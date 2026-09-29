import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

async function freePort() {
  const socket = createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  return port;
}

test('new application refresh collects only associated feeds and preserves existing results', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-application-refresh-'));
  const data = path.join(directory, 'data');
  const fetchLog = path.join(directory, 'fetch.log');
  const existingId = '11111111-1111-4111-8111-111111111111';
  const existingFeedId = '22222222-2222-4222-8222-222222222222';
  const newFeedId = '33333333-3333-4333-8333-333333333333';
  const existingResult = { id: existingId, name: 'Existing App', version: '1.0.0', status: 'green', reasons: ['Preserve me'], vulnerabilities: [], ownerIds: [], tags: [] };
  await mkdir(data);
  await writeFile(path.join(directory, 'applications.yaml'), `applications:\n  - id: ${existingId}\n    name: "Existing App"\n    version: "1.0.0"\n    cpeVendor: "example"\n    cpeProduct: "existing"\n    cpeName: "cpe:2.3:a:example:existing:*:*:*:*:*:*:*:*"\n    cpeMode: "product"\n    eolDate: "2030-01-01"\n    criticality: "unspecified"\n    environment: "unspecified"\n    exposure: "unknown"\n    ownerIds:\n    tags:\n`);
  await writeFile(path.join(directory, 'workspaces.yaml'), 'workspaces:\n');
  await writeFile(path.join(directory, 'feeds.yaml'), `version: 1\nfeeds:\n  - id: ${existingFeedId}\n    name: "Existing application feed"\n    url: "https://93.184.216.34/existing.xml"\n    format: "rss"\n    enabled: true\n    categories:\n      - "release"\n    productAliases:\n      - "Existing App"\n    applicationIds:\n      - ${existingId}\n  - id: ${newFeedId}\n    name: "New application feed"\n    url: "https://93.184.216.35/new.xml"\n    format: "rss"\n    enabled: true\n    categories:\n      - "release"\n    productAliases:\n      - "New App"\n    applicationIds:\n`);
  await writeFile(path.join(data, 'status.json'), `${JSON.stringify({ checkedAt: new Date().toISOString(), results: [existingResult], workspaces: [], owners: [], feedSummary: { total: 2, errors: 0 }, warning: null, inventoryCount: 1 })}\n`);
  const port = await freePort();
  const fixture = pathToFileURL(path.resolve(import.meta.dirname, '..', 'test-support', 'mock-sources.mjs')).href;
  const child = spawn(process.execPath, ['--import', fixture, 'server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: directory, DATA_DIR: data, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', WATCHTOWER_TEST_FETCH_LOG: fetchLog, OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let serverError = '';
  child.stderr.on('data', chunk => { serverError += chunk; });
  const origin = `http://127.0.0.1:${port}`;
  try {
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { ready = (await fetch(`${origin}/api/session`)).ok; if (ready) break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.equal(ready, true, serverError);
    const created = await fetch(`${origin}/api/applications`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'New App', version: '1.0.0', cpeVendor: 'example', cpeProduct: 'new', eolDate: '2030-01-01' }) });
    assert.equal(created.status, 201);
    const { id: newId } = await created.json();
    const association = await fetch(`${origin}/api/applications/${newId}/feeds`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ feedIds: [newFeedId] }) });
    assert.equal(association.status, 200);
    const refreshed = await fetch(`${origin}/api/applications/${newId}/refresh`, { method: 'POST' });
    assert.equal(refreshed.status, 200);
    const snapshot = await refreshed.json();
    assert.deepEqual(snapshot.results.find(result => result.id === existingId), existingResult);
    assert.equal(snapshot.results.some(result => result.id === newId), true);
    const requests = await readFile(fetchLog, 'utf8');
    assert.match(requests, /93\.184\.216\.35\/new\.xml/);
    assert.doesNotMatch(requests, /93\.184\.216\.34\/existing\.xml/);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill();
      await once(child, 'exit');
    }
    await rm(directory, { recursive: true, force: true });
  }
});
