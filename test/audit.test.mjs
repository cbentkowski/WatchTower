import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { appendFile, mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

async function freePort() {
  const socket = createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  return port;
}

test('application, workspace, and settings edits appear in audit logs', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-audit-'));
  const data = path.join(directory, 'data');
  await mkdir(data);
  await writeFile(path.join(directory, 'applications.yaml'), 'applications:\n');
  await writeFile(path.join(directory, 'workspaces.yaml'), 'workspaces:\n');
  const port = await freePort();
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: directory, DATA_DIR: data, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', YAML_CHECK_INTERVAL_MS: '100', OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '', OIDC_REQUIRED_ROLE: '' },
    stdio: 'ignore',
  });
  const origin = `http://127.0.0.1:${port}`;
  const post = async (route, body, method = 'POST') => fetch(`${origin}${route}`, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  try {
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { ready = (await fetch(`${origin}/api/session`)).ok; if (ready) break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.equal(ready, true);
    const settings = await (await fetch(`${origin}/api/settings`)).json();
    assert.equal(settings.version, '0.7.0');

    const app = { name: 'Test App', version: '1.0', cpeVendor: 'example', cpeProduct: 'testapp', eolDate: '2030-01-01' };
    const appResponse = await post('/api/applications', app);
    assert.equal(appResponse.status, 201);
    const appId = (await appResponse.json()).id;
    assert.equal((await post(`/api/applications/${appId}`, { ...app, id: 'ignored', name: 'Renamed App', version: '1.1' }, 'PUT')).status, 200);
    const workspaceResponse = await post('/api/workspaces', { name: 'Team', applications: [appId], notificationEmails: 'team@example.com' });
    assert.equal(workspaceResponse.status, 201);
    const workspaceId = (await workspaceResponse.json()).id;
    assert.equal((await post(`/api/workspaces/${workspaceId}`, { id: 'ignored', name: 'Operations', applications: [], notificationEmails: '' }, 'PUT')).status, 200);
    assert.equal((await post('/api/settings', { smtp: { enabled: false }, general: { protocol: 'https', host: 'home.example.com', port: 443 } })).status, 200);
    const feedResponse = await post('/api/feeds', { name: 'Vendor advisories', url: 'https://example.com/security.xml', format: 'rss', enabled: true, categories: ['security'], productAliases: ['Test App'], applicationIds: [appId] });
    assert.equal(feedResponse.status, 201);
    const feed = await feedResponse.json();
    assert.equal((await post(`/api/feeds/${feed.id}`, { ...feed, name: 'Vendor security advisories', enabled: false }, 'PUT')).status, 200);
    assert.equal((await post(`/api/applications/${appId}/feeds`, { feedIds: [feed.id] }, 'PUT')).status, 200);

    const { entries } = await (await fetch(`${origin}/api/logs`)).json();
    const audits = entries.filter(entry => entry.level === 'audit');
    assert.deepEqual(audits.map(entry => entry.message).sort(), ['Application added', 'Application updated', 'Feed added', 'Feed updated', 'Settings updated', 'Workspace added', 'Workspace updated'].sort());
    assert.ok(audits.every(entry => entry.actor.username === 'local'));
    assert.deepEqual(audits.find(entry => entry.message === 'Application updated').changes.version, { from: '1.0', to: '1.1' });
    assert.deepEqual(audits.find(entry => entry.message === 'Workspace updated').changes.removedApplications, [appId]);
    assert.equal(audits.find(entry => entry.message === 'Workspace updated').changes.notificationRecipientsChanged, true);
    assert.ok(!JSON.stringify(audits).includes('team@example.com'));
    const feedList = await (await fetch(`${origin}/api/feeds`)).json();
    assert.equal(feedList.feeds[0].name, 'Vendor security advisories');
    assert.equal(feedList.feeds[0].state.status, 'not-checked');

    assert.equal((await post(`/api/workspaces/${workspaceId}`, { id: 'renamed-workspace', name: 'Operations', applications: [appId], notificationEmails: '' }, 'PUT')).status, 200);
    assert.equal((await post(`/api/applications/${appId}`, { ...app, id: 'renamed-app', name: 'Renamed App', version: '1.1' }, 'PUT')).status, 200);
    const immutableConfig = await (await fetch(`${origin}/api/config`)).json();
    assert.equal(immutableConfig.applications.some(item => item.id === appId), true);
    assert.equal(immutableConfig.workspaces.some(group => group.id === workspaceId), true);

    await new Promise(resolve => setTimeout(resolve, 250));
    const afterWebEdits = (await (await fetch(`${origin}/api/logs`)).json()).entries;
    assert.equal(afterWebEdits.some(entry => entry.message === 'YAML file changed outside web interface'), false);
    await appendFile(path.join(directory, 'applications.yaml'), '# edited outside the dashboard\n');
    let filesystemEntry;
    for (let attempt = 0; attempt < 30; attempt++) {
      const current = (await (await fetch(`${origin}/api/logs`)).json()).entries;
      filesystemEntry = current.find(entry => entry.message === 'YAML file changed outside web interface');
      if (filesystemEntry) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(filesystemEntry, 'direct YAML edit was logged');
    assert.equal(filesystemEntry.target.id, 'applications.yaml');
    assert.equal(filesystemEntry.actor.subject, 'unknown');
    assert.equal(filesystemEntry.changes.kind, 'modified');
    assert.ok(!JSON.stringify(filesystemEntry).includes('edited outside the dashboard'));
  } finally {
    child.kill();
    await rm(directory, { recursive: true, force: true });
  }
});
