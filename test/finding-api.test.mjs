import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
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

test('finding workflow API persists the update, history, snapshot, and audit event', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-finding-api-'));
  const data = path.join(directory, 'data');
  const applicationId = '11111111-1111-4111-8111-111111111111';
  const findingId = 'CVE-2026-1234';
  const finding = { id: findingId, score: 9.8, label: 'Critical', description: 'Evidence', knownExploited: false, url: `https://example.com/${findingId}`, advisories: [] };
  await mkdir(data);
  await writeFile(path.join(directory, 'applications.yaml'), `applications:\n  - id: ${applicationId}\n    name: "Test App"\n    version: "1.0.0"\n    cpeVendor: "example"\n    cpeProduct: "test"\n    cpeName: "cpe:2.3:a:example:test:*:*:*:*:*:*:*:*"\n    cpeMode: "product"\n    cpeTitle: "Test App"\n    eolDate: "2030-01-01"\n    criticality: "unspecified"\n    environment: "unspecified"\n    exposure: "unknown"\n    ownerIds:\n    tags:\n`);
  await writeFile(path.join(directory, 'workspaces.yaml'), 'workspaces:\n');
  await writeFile(path.join(data, 'status.json'), `${JSON.stringify({ checkedAt: new Date().toISOString(), results: [{ id: applicationId, name: 'Test App', version: '1.0.0', vulnerabilities: [finding] }], workspaces: [] })}\n`);
  const port = await freePort();
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: directory, DATA_DIR: data, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let serverError = '';
  child.stderr.on('data', chunk => { serverError += chunk; });
  const origin = `http://127.0.0.1:${port}`;
  try {
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { ready = (await fetch(`${origin}/api/session`)).ok; if (ready) break; } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.equal(ready, true, serverError);
    const status = await (await fetch(`${origin}/api/status`)).json();
    assert.equal(status.results[0]?.vulnerabilities[0]?.id, findingId, JSON.stringify(status));
    const updated = await fetch(`${origin}/api/applications/${applicationId}/findings/${findingId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ state: 'remediation-planned', assignee: 'Platform', dueDate: '2026-03-01', ticketReference: 'INC0001234', notes: 'Upgrade scheduled' }) });
    const updatedBody = await updated.json();
    assert.equal(updated.status, 200, updatedBody.error);
    assert.equal(updatedBody.state, 'remediation-planned');
    const history = await (await fetch(`${origin}/api/applications/${applicationId}/findings/${findingId}/history`)).json();
    assert.deepEqual(history.entries.map(entry => entry.type), ['finding-workflow-updated', 'finding-discovered']);
    assert.equal(history.entries[0].actor.username, 'local');
    const store = JSON.parse(await readFile(path.join(data, 'finding-workflows.json'), 'utf8'));
    assert.equal(store.records[`${applicationId}:${findingId}`].assignee, 'Platform');
    assert.equal(store.records[`${applicationId}:${findingId}`].ticketReference, 'INC0001234');
    const snapshot = JSON.parse(await readFile(path.join(data, 'status.json'), 'utf8'));
    assert.equal(snapshot.results[0].vulnerabilities[0].workflow.state, 'remediation-planned');
    assert.match(await readFile(path.join(data, 'audit.jsonl'), 'utf8'), /Finding workflow updated/);
  } finally {
    if (child.exitCode === null && child.signalCode === null) { child.kill(); await once(child, 'exit'); }
    await rm(directory, { recursive: true, force: true });
  }
});
