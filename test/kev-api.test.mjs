import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

test('full and scoped scans preserve KEV evidence through outage/restart and record verified status transitions', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-kev-'));
  const data = path.join(directory, 'data'), mode = path.join(directory, 'osv.txt'), feed = path.join(directory, 'kev.json');
  await mkdir(data); await writeFile(mode, 'active');
  await writeFile(feed, JSON.stringify({ vulnerabilities: [] }));
  for (const name of ['applications', 'workspaces', 'feeds']) await writeFile(path.join(directory, name + '.yaml'), name + ':\n');
  const socket = createServer(); await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port; await new Promise(resolve => socket.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  let child;
  const request = async (route, method = 'GET', body) => {
    const response = await fetch(origin + route, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    assert.ok(response.ok, await response.clone().text()); return response.json();
  };
  async function start() {
    child = spawn(process.execPath, ['--import', pathToFileURL(path.resolve('test-support/mock-sources.mjs')).href, 'src/server.mjs'], { env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: directory, DATA_DIR: data, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', WATCHTOWER_TEST_OSV_MODE_FILE: mode, WATCHTOWER_TEST_KEV_FILE: feed, OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' }, stdio: ['ignore', 'ignore', 'pipe'] });
    let errors = ''; child.stderr.on('data', chunk => { errors += chunk; });
    for (let i = 0; i < 80; i++) { try { if ((await fetch(origin + '/api/session')).ok) return; } catch {} await new Promise(resolve => setTimeout(resolve, 100)); }
    assert.fail(errors);
  }
  async function stop() { if (child?.exitCode === null && child?.signalCode === null) { child.kill(); await once(child, 'exit'); } }
  try {
    await start();
    const app = await request('/api/applications', 'POST', { name: 'KEV test', version: '1', assessmentMode: 'inventory', eolDate: '2030-01-01' });
    const base = '/api/applications/' + app.id;
    await request(base + '/sboms', 'POST', { sbom: JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [{ type: 'library', name: 'example', version: '1.0.0', purl: 'pkg:npm/example@1.0.0', 'bom-ref': 'example' }] }), imageId: null });
    const refresh = async () => (await request(base + '/refresh', 'POST')).results.find(item => item.id === app.id).vulnerabilities[0];
    const initial = await refresh(); assert.equal(initial.knownExploited, false);
    await writeFile(feed, JSON.stringify({ dateReleased: '2026-10-01T12:00:00Z', vulnerabilities: [{ cveID: 'CVE-2026-1234', dateAdded: '2026-10-01', dueDate: '2026-10-22', requiredAction: 'Apply updates.' }] }));
    const found = (await request('/api/status?refresh=1')).results.find(item => item.id === app.id).vulnerabilities[0];
    assert.equal(found.id, initial.id); assert.equal(found.knownExploited, true);
    assert.equal(found.kev.entries[0].dueDate, '2026-10-22');
    await writeFile(feed, 'offline'); await stop(); await start();
    const stale = await refresh(); assert.equal(stale.knownExploited, true); assert.equal(stale.kev.state, 'stale');
    assert.equal(stale.kev.lastSuccessfulCheckAt, found.kev.lastSuccessfulCheckAt);
    assert.equal(stale.kev.entries[0].requiredAction, 'Apply updates.');
    await writeFile(feed, '{"vulnerabilities":[{"cveID":"invalid"}]}');
    assert.equal((await refresh()).knownExploited, true);
    await writeFile(feed, '{"vulnerabilities":[]}');
    assert.equal((await refresh()).knownExploited, false);
    const history = await request(base + '/findings/' + initial.id + '/history');
    const changes = history.entries.filter(event => event.type === 'finding-kev-status-changed');
    assert.equal(changes.length, 2);
    assert.deepEqual(changes.map(event => event.to).sort(), [false, true]);
  } finally { await stop(); await rm(directory, { recursive: true, force: true }); }
});
