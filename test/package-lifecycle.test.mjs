import test from 'node:test';
import assert from 'node:assert/strict';
import { reconcileFindingWorkflows, updateFindingWorkflow, findingKey, writeFindingStore, readFindingStore } from '../src/findings.mjs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
const appId = '11111111-1111-4111-8111-111111111111';
const image = '22222222-2222-4222-8222-222222222222';
const actor = { name: 'Test assessment' };
const component = (name, version) => ({ name, version, purl: `pkg:npm/${name}@${version}`, location: '' });
const finding = (name, version, imageId = null) => ({ advisoryId: `GHSA-${name}`, aliases: [`GHSA-${name}`], severity: 'HIGH', score: null, evidenceState: 'current', sourceRecords: [], package: { ...component(name, version), imageId, revisionId: 'before' } });
const result = (findings, components, { revision = 'after', complete = true, images = [], imageId = null } = {}) => [{ id: appId, status: findings.length ? 'red' : 'green', reasons: [], vulnerabilities: findings, inventoryLifecycle: { images, inventories: [{ imageId, revisionId: revision, complete, components }] } }];
function initial(imageId = null) {
  const store = { records: {} };
  const apps = result([finding('lodash', '4.17.20', imageId), finding('minimist', '1.2.5', imageId)], [component('lodash', '4.17.20'), component('minimist', '1.2.5')], { revision: 'before', imageId });
  reconcileFindingWorkflows(store, apps, actor);
  const lodash = apps[0].vulnerabilities[0].id, minimist = apps[0].vulnerabilities[1].id;
  for (const id of [lodash, minimist]) updateFindingWorkflow(store, appId, id, { state: 'investigating', assignee: 'Security', notes: 'Preserve notes', ticketReference: 'SEC-1' }, { name: 'Analyst' });
  return { store, lodash, minimist };
}

test('replacement resolves changed versions and preserves unchanged identities, responses and restart history', async () => {
  const { store, lodash, minimist } = initial();
  const apps = result([{ ...finding('minimist', '1.2.5'), package: { ...finding('minimist', '1.2.5').package, revisionId: 'after' } }], [component('lodash', '4.18.1'), component('minimist', '1.2.5')]);
  const change = reconcileFindingWorkflows(store, apps, actor);
  assert.equal(apps[0].vulnerabilities[0].id, minimist);
  assert.equal(apps[0].vulnerabilities[0].workflow.state, 'investigating');
  assert.equal(apps[0].resolvedPackageFindings[0].id, lodash);
  assert.equal(apps[0].resolvedPackageFindings[0].workflow.notes, 'Preserve notes');
  assert.equal(apps[0].resolvedPackageFindings[0].resolution.reason, 'version-changed');
  assert.equal(change.events.filter(event => event.type === 'finding-inventory-resolved').length, 1);
  assert.equal(reconcileFindingWorkflows(store, apps, actor).events.length, 0);
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-lifecycle-'));
  try {
    const file = path.join(directory, 'workflows.json'); await writeFindingStore(file, store);
    const restored = await readFindingStore(file);
    assert.equal(restored.records[findingKey(appId, lodash)].inventoryResolution.reason, 'version-changed');
    assert.equal(restored.records[findingKey(appId, lodash)].notes, 'Preserve notes');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('failed, stale, unsupported and uncommitted replacements keep prior findings unverified until complete evidence', () => {
  const { store, lodash } = initial();
  for (const components of [[component('lodash', '4.18.1')], [], [{ name: 'incomplete' }]]) {
    const apps = result([], components, { complete: false });
    const change = reconcileFindingWorkflows(store, apps, actor);
    assert.equal(change.events.some(event => event.type === 'finding-inventory-resolved'), false);
    assert.equal(apps[0].status, 'red');
    assert.ok(apps[0].vulnerabilities.every(item => item.evidenceState === 'unverified'));
    assert.equal(store.records[findingKey(appId, lodash)].state, 'investigating');
  }
  const removed = result([finding('minimist', '1.2.5')], [component('minimist', '1.2.5')]);
  reconcileFindingWorkflows(store, removed, actor);
  assert.equal(removed[0].resolvedPackageFindings[0].resolution.reason, 'package-removed');
});

test('retirement resolves the explicit image scope and preserves its history', () => {
  const { store } = initial(image);
  const apps = [{ id: appId, status: 'unknown', reasons: [], vulnerabilities: [], inventoryLifecycle: { images: [{ id: image, retired: true, reference: 'docker.io/test/image:1' }], inventories: [] } }];
  reconcileFindingWorkflows(store, apps, actor);
  assert.equal(apps[0].vulnerabilities.length, 0);
  assert.ok(apps[0].resolvedPackageFindings.every(item => item.resolution.reason === 'image-retired'));
});

test('successful unchanged-package lookups resolve missing advisories without reopening from cached evidence', () => {
  const { store, lodash } = initial();
  const apps = result([], [component('lodash', '4.17.20'), component('minimist', '1.2.5')], { revision: 'before' });
  reconcileFindingWorkflows(store, apps, actor);
  assert.equal(apps[0].resolvedPackageFindings.find(item => item.id === lodash).resolution.reason, 'no-longer-reported');
  const cached = [{ id: appId, vulnerabilities: [finding('lodash', '4.17.20')], status: 'red', reasons: [] }];
  assert.equal(reconcileFindingWorkflows(store, cached, actor).events.some(event => event.type === 'finding-reopened'), false);
  assert.ok(store.records[findingKey(appId, lodash)].inventoryResolution);
  const fresh = result([finding('lodash', '4.17.20')], [component('lodash', '4.17.20')]);
  assert.equal(reconcileFindingWorkflows(store, fresh, actor).events.some(event => event.type === 'finding-reopened'), true);
  assert.equal(fresh[0].vulnerabilities[0].id, lodash);
  assert.equal(fresh[0].vulnerabilities[0].workflow.notes, 'Preserve notes');
});

test('one image replacement cannot resolve another image or application-level occurrence', () => {
  const { store, lodash } = initial(image);
  const apps = result([], [component('lodash', '4.18.1')], { imageId: null });
  reconcileFindingWorkflows(store, apps, actor);
  assert.equal(apps[0].resolvedPackageFindings.length, 0);
  assert.ok(apps[0].vulnerabilities.some(item => item.id === lodash && item.evidenceState === 'unverified'));
});
