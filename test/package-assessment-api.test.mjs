import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

test('CPE-less imports reassess new advisories, persist workflow, retain failures and isolate package sources', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-osv-api-'));
  const data = path.join(directory, 'data'), modeFile = path.join(directory, 'mode.txt'), fetchLog = path.join(directory, 'fetch.log');
  await mkdir(data);
  await writeFile(modeFile, 'empty');
  for (const [name, contents] of [['applications.yaml', 'applications:\n'], ['workspaces.yaml', 'workspaces:\n'], ['feeds.yaml', 'feeds:\n']]) await writeFile(path.join(directory, name), contents);
  const socket = createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  const child = spawn(process.execPath, ['--import', pathToFileURL(path.resolve('test-support/mock-sources.mjs')).href, 'src/server.mjs'], { env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: directory, DATA_DIR: data, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', WATCHTOWER_TEST_OSV_MODE_FILE: modeFile, WATCHTOWER_TEST_FETCH_LOG: fetchLog, OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' }, stdio: ['ignore', 'ignore', 'pipe'] });
  let errors = ''; child.stderr.on('data', chunk => { errors += chunk; });
  const origin = `http://127.0.0.1:${port}`;
  const request = async (route, method = 'GET', body) => fetch(`${origin}${route}`, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  try {
    let ready = false;
    for (let attempt = 0; attempt < 50; attempt++) { try { ready = (await request('/api/session')).ok; if (ready) break; } catch { await new Promise(resolve => setTimeout(resolve, 100)); } }
    assert.equal(ready, true, errors);
    const demoResponse = await request('/api/sboms/demo');
    assert.equal(demoResponse.status, 200);
    assert.match(demoResponse.headers.get('content-disposition'), /attachment/);
    assert.deepEqual(await demoResponse.json(), JSON.parse(await readFile('test/fixtures/package-assessment-demo.cdx.json', 'utf8')));
    const created = await request('/api/applications', 'POST', { name: 'Inventory App', version: '1.0.0', assessmentMode: 'inventory', eolDate: '2030-01-01' });
    assert.equal(created.status, 201, await created.clone().text());
    const { id } = await created.json();
    const refresh = async () => { const response = await request(`/api/applications/${id}/refresh`, 'POST'); assert.equal(response.status, 200, await response.clone().text()); return (await response.json()).results.find(app => app.id === id); };
    assert.equal((await refresh()).status, 'unknown');
    const document = { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [{ type: 'library', name: 'example', version: '1.0.0', purl: 'pkg:npm/example@1.0.0', 'bom-ref': 'example' }] };
    assert.equal((await request(`/api/applications/${id}/sboms`, 'POST', { sbom: JSON.stringify(document), imageId: null })).status, 201);
    const clean = await refresh();
    assert.equal(clean.packageAssessment.state, 'assessed');
    assert.equal(clean.status, 'green');
    await writeFile(modeFile, 'new-advisory');
    const affected = await refresh();
    assert.equal(affected.status, 'red');
    const finding = affected.vulnerabilities[0];
    assert.equal(finding.advisoryId, 'GHSA-xxxx-yyyy-zzzz');
    assert.equal(finding.package.purl, 'pkg:npm/example@1.0.0');
    assert.equal(finding.sourceRecords[0].affected[0].ranges[0].events[1].fixed, '2.0.0');
    const updated = await request(`/api/applications/${id}/findings/${finding.id}`, 'PUT', { state: 'investigating', assignee: 'Team', notes: 'Reviewing', ticketReference: 'SEC-123' });
    assert.equal(updated.status, 200, await updated.clone().text());
    const repeated = await refresh();
    assert.equal(repeated.vulnerabilities[0].id, finding.id);
    assert.equal(repeated.vulnerabilities[0].workflow.notes, 'Reviewing');
    await writeFile(modeFile, 'offline');
    const failed = await refresh();
    assert.equal(failed.packageAssessment.state, 'incomplete');
    assert.equal(failed.vulnerabilities[0].id, finding.id);
    assert.equal(failed.vulnerabilities[0].evidenceState, 'unverified');
    assert.equal(failed.vulnerabilities[0].workflow.state, 'investigating');
    const metadata = await (await request(`/api/applications/${id}/inventory`)).json();
    assert.equal(metadata.revisions[0].assessment.state, 'incomplete');
    const log = await readFile(fetchLog, 'utf8');
    assert.match(log, /api\.osv\.dev\/v1\/querybatch/);
    assert.doesNotMatch(log, /services\.nvd\.nist/);
    const full = await (await request('/api/status?refresh=1')).json();
    assert.equal(full.results[0].packageAssessment.state, 'incomplete');
  } finally {
    if (child.exitCode === null && child.signalCode === null) { child.kill(); await once(child, 'exit'); }
    await rm(directory, { recursive: true, force: true });
  }
});
