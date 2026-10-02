import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

async function freePort() {
  const socket = createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  return port;
}

test('notification policy API migrates defaults, previews drafts, and persists replacements', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-policy-api-'));
  const data = path.join(directory, 'data');
  await mkdir(data);
  await writeFile(path.join(directory, 'applications.yaml'), 'applications:\n');
  await writeFile(path.join(directory, 'workspaces.yaml'), 'workspaces:\n');
  await writeFile(path.join(directory, 'owners.yaml'), 'owners:\n');
  const port = await freePort();
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: directory, DATA_DIR: data, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', YAML_CHECK_INTERVAL_MS: '100', OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '', OIDC_REQUIRED_ROLE: '' },
    stdio: 'ignore',
  });
  const origin = `http://127.0.0.1:${port}`;
  try {
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { ready = (await fetch(`${origin}/api/session`)).ok; if (ready) break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.equal(ready, true);
    const initial = await (await fetch(`${origin}/api/notification-policies`)).json();
    assert.deepEqual(initial.policies.map(policy => policy.name), ['High and Critical findings', 'Known-exploited findings']);

    const draft = { id: 'critical-only', name: 'Critical only', enabled: true, conditions: { severities: ['critical'] } };
    const previewResponse = await fetch(`${origin}/api/notification-policies/preview`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ policy: draft }) });
    assert.equal(previewResponse.status, 200);
    const preview = await previewResponse.json();
    assert.deepEqual(preview.matches, []);
    assert.deepEqual(preview.routes, []);
    assert.equal(preview.delivery.cadence, 'adaptive');

    const saveResponse = await fetch(`${origin}/api/notification-policies`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ policies: [draft] }) });
    assert.equal(saveResponse.status, 200);
    const saved = (await saveResponse.json()).policies;
    assert.equal(saved[0].delivery.cadence, 'adaptive');
    assert.deepEqual((JSON.parse(await readFile(path.join(directory, 'notification-policies.json'), 'utf8'))).policies, saved);

    const updated = { ...saved[0], name: 'Critical production', enabled: false, conditions: { ...saved[0].conditions, environments: ['production'] }, delivery: { ...saved[0].delivery, cadence: 'daily', sendHour: 9 } };
    const updateResponse = await fetch(`${origin}/api/notification-policies`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ policies: [updated] }) });
    assert.equal(updateResponse.status, 200);
    const audits = (await (await fetch(`${origin}/api/logs?type=audit`)).json()).entries;
    const changed = audits.find(entry => entry.message === 'Notification policy updated');
    assert.equal(changed.target.name, 'Critical production');
    assert.deepEqual(changed.changes.name, { from: 'Critical only', to: 'Critical production' });
    assert.deepEqual(changed.changes.enabled, { from: 'Yes', to: 'No' });
    assert.deepEqual(changed.changes.environments, { from: 'Any', to: 'Production' });
    assert.deepEqual(changed.changes.cadence, { from: 'Adaptive', to: 'Daily' });
    assert.deepEqual(changed.changes.sendHour, { from: 'Global', to: '09:00' });
    assert.match(changed.detail, /Critical production; Name: Critical only → Critical production/);
    assert.equal(audits.filter(entry => entry.message === 'Notification policy added').length, 1);
    assert.equal(audits.filter(entry => entry.message === 'Notification policy removed').length, 2);
  } finally {
    child.kill('SIGTERM');
    await new Promise(resolve => child.once('exit', resolve));
    await rm(directory, { recursive: true, force: true });
  }
});
