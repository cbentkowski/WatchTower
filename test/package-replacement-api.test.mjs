import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

test('replacement demos preserve responses across failure, upgrade, rollback, retirement and restart', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-replacement-'));
  const modeFile = path.join(directory, 'mode.txt');
  await mkdir(path.join(directory, 'data'));
  await writeFile(modeFile, 'replacement');
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
    child = spawn(process.execPath, ['--import', pathToFileURL(path.resolve('test-support/mock-sources.mjs')).href, 'src/server.mjs'], { env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: directory, DATA_DIR: path.join(directory, 'data'), AUTO_SCAN: 'false', AUTH_DISABLED: 'true', WATCHTOWER_TEST_OSV_MODE_FILE: modeFile, OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' }, stdio: ['ignore', 'ignore', 'pipe'] });
    let errors = ''; child.stderr.on('data', chunk => { errors += chunk; });
    for (let i = 0; i < 80; i++) { try { if ((await fetch(origin + '/api/session')).ok) return; } catch {} await new Promise(resolve => setTimeout(resolve, 100)); }
    assert.fail(errors);
  }
  async function stop() { if (child?.exitCode === null && child?.signalCode === null) { child.kill(); await once(child, 'exit'); } }
  try {
    await start();
    const app = await request('/api/applications', 'POST', { name: 'Replacement test', version: '1', assessmentMode: 'inventory', eolDate: '2030-01-01' });
    const base = '/api/applications/' + app.id;
    const before = await request('/api/sboms/demo-before'), after = await request('/api/sboms/demo-after');
    const upload = (doc, imageId = null) => request(base + '/sboms', 'POST', { sbom: JSON.stringify(doc), imageId });
    const refresh = async () => (await request(base + '/refresh', 'POST')).results.find(item => item.id === app.id);
    const firstImport = await upload(before);
    const initial = await refresh(); assert.equal(initial.vulnerabilities.length, 2);
    const lodash = initial.vulnerabilities.find(item => item.package.name === 'lodash');
    const minimist = initial.vulnerabilities.find(item => item.package.name === 'minimist');
    for (const finding of [lodash, minimist]) await request(base + '/findings/' + finding.id, 'PUT', { state: 'investigating', notes: 'Keep response', assignee: 'Security', ticketReference: 'SEC-1' });
    // Serialize workflow writes with assessment persistence so notes cannot be lost.
    await Promise.all([refresh(), request(base + '/findings/' + minimist.id, 'PUT', { state: 'investigating', notes: 'Concurrent note', assignee: 'Security', ticketReference: 'SEC-1' })]);
    await writeFile(modeFile, 'offline'); await upload(after);
    const failed = await refresh();
    assert.equal(failed.vulnerabilities.length, 2); assert.ok(failed.vulnerabilities.every(item => item.evidenceState === 'unverified'));
    assert.equal(failed.resolvedPackageFindings.length, 0);
    await writeFile(modeFile, 'replacement');
    const upgraded = await refresh();
    assert.equal(upgraded.vulnerabilities.length, 1); assert.equal(upgraded.vulnerabilities[0].id, minimist.id);
    assert.equal(upgraded.vulnerabilities[0].workflow.notes, 'Concurrent note');
    assert.equal(upgraded.resolvedPackageFindings[0].id, lodash.id);
    assert.equal(upgraded.resolvedPackageFindings[0].resolution.reason, 'version-changed');
    assert.equal(upgraded.resolvedPackageFindings[0].workflow.notes, 'Keep response');
    const metadata = await request(base + '/inventory');
    assert.equal(metadata.revisions[0].id, firstImport.id); assert.equal(metadata.revisions[0].supersededBy, metadata.revisions[1].id);
    const history = await request(base + '/findings/' + lodash.id + '/history');
    assert.ok(history.entries.some(event => event.type === 'finding-inventory-resolved'));
    await stop(); await start();
    const restarted = (await request('/api/status')).results.find(item => item.id === app.id);
    assert.equal(restarted.resolvedPackageFindings[0].id, lodash.id);
    assert.equal(restarted.vulnerabilities[0].workflow.notes, 'Concurrent note');
    await upload(before);
    const restored = await refresh();
    const reopened = restored.vulnerabilities.find(item => item.id === lodash.id);
    assert.equal(reopened.workflow.state, 'new'); assert.equal(reopened.workflow.notes, 'Keep response');
    const imageState = await request(base + '/images', 'PUT', { images: [{ reference: 'docker.io/test/app:1', label: 'Web' }] });
    const image = imageState.images[0]; await upload(before, image.id);
    const scoped = await refresh(); assert.equal(scoped.vulnerabilities.length, 4);
    const imageRevision = (await request(base + '/inventory')).revisions.find(revision => revision.active && revision.scope.imageId === image.id);
    assert.equal(imageRevision.imageReferenceAtImport, image.reference);
    const componentPage = await request(base + '/inventory/revisions/' + imageRevision.id + '/components?q=lodash');
    assert.equal(componentPage.total, 1); assert.equal(componentPage.components[0].name, 'lodash');
    await request(base + '/images', 'PUT', { images: [{ ...image, reference: 'docker.io/test/app:2' }] });
    const mismatch = await refresh();
    assert.equal(mismatch.packageAssessment.state, 'incomplete');
    assert.ok(mismatch.vulnerabilities.filter(item => item.package.imageId === image.id).every(item => item.evidenceState === 'unverified'));
    assert.ok(mismatch.reasons.some(reason => reason.includes('package entries checked')));
    await request(base + '/images', 'PUT', { images: [{ ...image, enabled: false }] });
    assert.ok((await refresh()).vulnerabilities.some(item => item.package.imageId === image.id && item.evidenceState === 'unverified'));
    await request(base + '/images', 'PUT', { images: [image] });
    assert.ok((await refresh()).vulnerabilities.filter(item => item.package.imageId === image.id).every(item => item.evidenceState === 'current'));
    const retiredState = await request(base + '/images', 'PUT', { images: [{ ...image, retired: true }] });
    assert.ok(retiredState.images[0].retiredAt); assert.ok(retiredState.images[0].retiredBy);
    const retired = await refresh();
    assert.equal(retired.vulnerabilities.length, 2);
    assert.equal(retired.resolvedPackageFindings.filter(item => item.resolution.reason === 'image-retired').length, 2);
    assert.ok(retired.vulnerabilities.every(item => item.package.imageId === null));
    const rejection = await fetch(origin + base + '/images', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ images: [{ ...image, retired: false }] }) });
    assert.equal(rejection.status, 400);
    const otherApp = await request('/api/applications', 'POST', { name: 'Browse inventory', version: '1', assessmentMode: 'inventory', eolDate: '2030-01-01' });
    const many = { ...before, components: Array.from({ length: 70 }, (_, index) => ({ type: 'library', name: 'component-' + index, version: '1', purl: 'pkg:npm/component-' + index + '@1', 'bom-ref': 'ref-' + index })) };
    const manyRevision = await request('/api/applications/' + otherApp.id + '/sboms', 'POST', { sbom: JSON.stringify(many), imageId: null });
    const browseRoute = '/api/applications/' + otherApp.id + '/inventory/revisions/' + manyRevision.id + '/components';
    assert.equal((await request(browseRoute)).components.length, 50);
    assert.equal((await request(browseRoute + '?offset=50')).components.length, 20);
    assert.equal((await request(browseRoute + '?q=component-69')).total, 1);
    const foreign = await fetch(origin + base + '/inventory/revisions/' + manyRevision.id + '/components');
    assert.equal(foreign.status, 404);
    assert.equal((await fetch(origin + browseRoute + '?offset=-1')).status, 400);
  } finally { await stop(); await rm(directory, { recursive: true, force: true }); }
});
