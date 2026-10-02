import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalImageReference, reconcileImages, packageIdentity, createInventoryRevision } from '../src/inventory.mjs';
import { reconcilePackageFinding } from '../src/package-findings.mjs';
import { reconcileFindingWorkflows, updateFindingWorkflow, readFindingStore, writeFindingStore } from '../src/findings.mjs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const app = '11111111-1111-4111-8111-111111111111';
const image = '22222222-2222-4222-8222-222222222222';
const evidence = (extra = {}) => ({ applicationId: app, purl: 'pkg:npm/example@1.2.3', advisoryId: 'GHSA-xxxx-yyyy-zzzz', ...extra });

test('OCI references require explicit registry and selector, preserve tags, reject unsafe input', () => {
  assert.equal(canonicalImageReference('REGISTRY.example/team/app:Release'), 'registry.example/team/app:Release');
  assert.equal(canonicalImageReference(`localhost:5000/app:tag@sha256:${'A'.repeat(64)}`), `localhost:5000/app:tag@sha256:${'a'.repeat(64)}`);
  for (const value of ['https://example.com/app:v1', 'user:secret@example.com/app:v1', 'example.com/app', 'team/app:v1', 'example.com/App:v1', 'example.com/app:v1 ', 'example.com:70000/app:v1', 'example.com/app@sha256:abc']) assert.throws(() => canonicalImageReference(value));
});

test('images retain managed IDs and must be retired rather than removed', () => {
  const first = reconcileImages([{ reference: 'docker.io/team/web:1' }, { reference: 'docker.io/team/worker:1' }]);
  assert.notEqual(first[0].id, first[1].id);
  const edited = reconcileImages(first.map(entry => ({ ...entry, label: 'Updated' })), first);
  assert.equal(edited[0].id, first[0].id);
  assert.throws(() => reconcileImages([first[0]], first), /Retire/);
  assert.throws(() => reconcileImages([{ id: image, reference: 'docker.io/team/web:1' }]), /managed/);
  assert.throws(() => reconcileImages([{ reference: 'DOCKER.io/team/web:1' }, { reference: 'docker.io/team/web:1' }]), /Duplicate/);
  const retired = reconcileImages(first.map(entry => ({ ...entry, retired: true })), first);
  assert.equal(retired[0].enabled, false);
});

test('PURL normalization retains version, qualifiers, subpath, and location distinctions', () => {
  assert.deepEqual(packageIdentity({ purl: 'pkg:deb/debian/example@1?distro=bookworm&arch=amd64' }), packageIdentity({ purl: 'pkg:deb/debian/example@1?arch=amd64&distro=bookworm' }));
  assert.throws(() => packageIdentity({ purl: 'pkg:npm/example' }), /installed version/);
  assert.throws(() => packageIdentity({ purl: 'pkg:npm/example@1', version: '2' }), /disagrees/);
});

test('revisions and added aliases do not change finding identity; scopes and versions do', () => {
  const store = {};
  const first = reconcilePackageFinding(store, evidence());
  const second = reconcilePackageFinding(store, evidence({ advisoryId: 'CVE-2026-1234', aliases: ['GHSA-xxxx-yyyy-zzzz'] }));
  assert.equal(second.findingId, first.findingId);
  assert.equal(reconcilePackageFinding(store, evidence({ advisoryId: 'CVE-2026-1234' })).findingId, first.findingId);
  for (const extra of [{ imageId: image }, { purl: 'pkg:npm/example@1.2.4' }, { location: '/other' }]) assert.notEqual(reconcilePackageFinding(store, evidence(extra)).findingId, first.findingId);
  const scope = { applicationId: app, imageId: null };
  assert.notEqual(createInventoryRevision(scope, { checksum: 'a'.repeat(64) }).id, createInventoryRevision(scope, { checksum: 'a'.repeat(64) }).id);
});

test('alias bridges report ambiguity without destroying either identity', () => {
  const store = {};
  reconcilePackageFinding(store, evidence());
  reconcilePackageFinding(store, evidence({ advisoryId: 'CVE-2026-1234' }));
  const before = structuredClone(store);
  assert.equal(reconcilePackageFinding(store, evidence({ aliases: ['CVE-2026-1234'] })).status, 'ambiguous');
  assert.deepEqual(store, before);
});

test('qualifier ordering matches while package qualifiers and subpaths remain distinct', () => {
  const store = {};
  const first = reconcilePackageFinding(store, evidence({ purl: 'pkg:deb/debian/example@1?distro=bookworm&arch=amd64' }));
  assert.equal(reconcilePackageFinding(store, evidence({ purl: 'pkg:deb/debian/example@1?arch=amd64&distro=bookworm' })).findingId, first.findingId);
  assert.notEqual(reconcilePackageFinding(store, evidence({ purl: 'pkg:deb/debian/example@1?arch=arm64&distro=bookworm' })).findingId, first.findingId);
  assert.notEqual(reconcilePackageFinding(store, evidence({ purl: 'pkg:deb/debian/example@1?arch=amd64&distro=bookworm#other' })).findingId, first.findingId);
});

test('ambiguous package evidence cannot acquire either existing response workflow', () => {
  const store = { records: {} };
  const results = [{ id: app, vulnerabilities: ['GHSA-xxxx-yyyy-zzzz', 'CVE-2026-1234'].map(advisoryId => ({ advisoryId, package: { purl: 'pkg:npm/example@1.2.3' } })) }];
  reconcileFindingWorkflows(store, results);
  const before = structuredClone(store);
  const bridge = [{ id: app, vulnerabilities: [{ advisoryId: 'CVE-2026-1234', aliases: ['GHSA-xxxx-yyyy-zzzz'], package: { purl: 'pkg:npm/example@1.2.3' }, workflow: { state: 'resolved' } }] }];
  reconcileFindingWorkflows(store, bridge);
  assert.equal(bridge[0].vulnerabilities[0].identity.status, 'ambiguous');
  assert.equal(bridge[0].vulnerabilities[0].workflow, undefined);
  assert.deepEqual(store, before);
});

test('workflow and persisted UUID survive alias expansion and process restart', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-identity-'));
  try {
    let store = { version: 1, records: {} };
    const results = aliases => [{ id: app, vulnerabilities: [{ package: { purl: 'pkg:npm/example@1.2.3' }, advisoryId: 'GHSA-xxxx-yyyy-zzzz', aliases, score: 5 }] }];
    const first = results([]);
    reconcileFindingWorkflows(store, first);
    const id = first[0].vulnerabilities[0].id;
    updateFindingWorkflow(store, app, id, { state: 'risk-accepted', notes: 'Reviewed', ticketReference: 'SEC-1' }, {});
    await writeFindingStore(path.join(directory, 'findings.json'), store);
    store = await readFindingStore(path.join(directory, 'findings.json'));
    const next = results(['CVE-2026-1234']);
    reconcileFindingWorkflows(store, next);
    assert.equal(next[0].vulnerabilities[0].id, id);
    assert.equal(next[0].vulnerabilities[0].workflow.state, 'risk-accepted');
    assert.equal(next[0].vulnerabilities[0].workflow.notes, 'Reviewed');
    assert.equal(next[0].vulnerabilities[0].workflow.ticketReference, 'SEC-1');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
