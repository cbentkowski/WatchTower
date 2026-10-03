import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

async function freePort() {
  const socket = createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  return port;
}

test('Permission Preview enforces selected access, blocks mutations, and preserves a reliable exit', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-vantage-'));
  const data = path.join(directory, 'data');
  await mkdir(data);
  const appA = '11111111-1111-4111-8111-111111111111';
  const appB = '22222222-2222-4222-8222-222222222222';
  const workspace = '33333333-3333-4333-8333-333333333333';
  const mapping = '44444444-4444-4444-8444-444444444444';
  const grant = '55555555-5555-4555-8555-555555555555';
  await writeFile(path.join(directory, 'applications.yaml'), `applications:\n  - id: ${appA}\n    name: "Visible App"\n    vendor: "Example"\n    version: "1.0"\n    cpeVendor: "example"\n    cpeProduct: "visible"\n    eolDate: "2030-01-01"\n    enabled: true\n  - id: ${appB}\n    name: "Hidden App"\n    vendor: "Example"\n    version: "1.0"\n    cpeVendor: "example"\n    cpeProduct: "hidden"\n    eolDate: "2030-01-01"\n    enabled: true\n`);
  await writeFile(path.join(directory, 'workspaces.yaml'), `workspaces:\n  - id: ${workspace}\n    name: "Visible Workspace"\n    applications:\n      - ${appA}\n`);
  await writeFile(path.join(directory, 'feeds.yaml'), 'feeds:\n');
  await writeFile(path.join(directory, 'smtp.yaml'), 'enabled: false\n');
  await writeFile(path.join(directory, 'general.yaml'), 'general:\n  protocol: "http"\n  host: "127.0.0.1"\n  port: 4173\n');
  const port = await freePort();
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: directory, DATA_DIR: data, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let errors = '';
  child.stderr.on('data', chunk => { errors += chunk; });
  const origin = `http://127.0.0.1:${port}`;
  const config = {
    groups: [{ id: mapping, name: 'Workspace Readers', claimSource: 'groups', claimValue: 'readers', enabled: true }],
    grants: [{ id: grant, groupId: mapping, scopeType: 'workspace', roles: ['workspace-viewer'], resourceIds: [workspace] }],
  };
  try {
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { ready = (await fetch(`${origin}/api/session`)).ok; if (ready) break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.equal(ready, true, errors);

    const noGrants = await fetch(`${origin}/api/rbac/evaluate`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config, mappingIds: [mapping], grantIds: [] }) });
    assert.equal(noGrants.status, 200);
    assert.deepEqual((await noGrants.json()).effective.applications.view, []);
    const evaluation = await fetch(`${origin}/api/rbac/evaluate`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config, mappingIds: [mapping], grantIds: [grant] }) });
    assert.equal(evaluation.status, 200);
    const explanation = await evaluation.json();
    assert.deepEqual(explanation.effective.applications.view.map(item => item.id), [appA]);

    const started = await fetch(`${origin}/api/rbac/preview`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config, mappingIds: [mapping], grantIds: [grant], name: 'Workspace Readers' }) });
    assert.equal(started.status, 201);
    const cookie = started.headers.get('set-cookie').split(';')[0];
    const session = await (await fetch(`${origin}/api/session`, { headers: { cookie } })).json();
    assert.equal(session.isAdmin, false);
    assert.equal(session.preview.name, 'Workspace Readers');

    const visible = await (await fetch(`${origin}/api/config`, { headers: { cookie } })).json();
    assert.deepEqual(visible.applications.map(item => item.id), [appA]);
    assert.deepEqual(visible.workspaces.map(item => item.id), [workspace]);

    const mutation = await fetch(`${origin}/api/settings`, { method: 'POST', headers: { cookie, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(mutation.status, 403);
    assert.match((await mutation.json()).error, /read-only/);
    assert.equal((await fetch(`${origin}/api/applications/${appA}/inventory`, { headers: { cookie } })).status, 200);
    assert.equal((await fetch(`${origin}/api/applications/${appB}/inventory`, { headers: { cookie } })).status, 403);
    const demo = await (await fetch(`${origin}/api/sboms/demo-before`)).json();
    const imported = await (await fetch(`${origin}/api/applications/${appA}/sboms`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sbom: JSON.stringify(demo), imageId: null }) })).json();
    assert.ok(imported.id);
    const componentPath = `/inventory/revisions/${imported.id}/components`;
    assert.equal((await fetch(`${origin}/api/applications/${appA}${componentPath}`, { headers: { cookie } })).status, 200);
    assert.equal((await fetch(`${origin}/api/applications/${appB}${componentPath}`, { headers: { cookie } })).status, 403);
    assert.equal((await fetch(`${origin}/api/applications/${appA}/images`, { method: 'PUT', headers: { cookie, 'Content-Type': 'application/json' }, body: '{"images":[]}' })).status, 403);
    for (const suffix of ['sboms', 'refresh']) {
      const response = await fetch(`${origin}/api/applications/${appA}/${suffix}`, { method: 'POST', headers: { cookie, 'Content-Type': 'application/json' }, body: '{}' });
      assert.equal(response.status, 403);
      assert.match((await response.json()).error, /read-only/);
    }

    const exited = await fetch(`${origin}/api/rbac/preview`, { method: 'DELETE', headers: { cookie } });
    assert.equal(exited.status, 200);
    assert.match(exited.headers.get('set-cookie'), /Max-Age=0/);
    const restored = await (await fetch(`${origin}/api/session`)).json();
    assert.equal(restored.isAdmin, true);
    assert.equal(restored.preview, null);
    const logs = await (await fetch(`${origin}/api/logs?type=audit`)).json();
    assert.ok(logs.entries.some(entry => entry.message === 'Permission Preview started'));
    assert.ok(logs.entries.some(entry => entry.message === 'Permission Preview exited'));
  } finally {
    child.kill();
    await rm(directory, { recursive: true, force: true });
  }
});
