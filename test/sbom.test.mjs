import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { normalizeSbom, selectInventoryImage, sbomLimits } from '../src/sbom.mjs';
import { createInventoryStore } from '../src/inventory-store.mjs';

const app = '11111111-1111-4111-8111-111111111111';
const cdx = () => ({ bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, serialNumber: 'urn:uuid:11111111-1111-4111-8111-111111111111', components: [{ type: 'library', name: 'example', version: '1.0.0', 'bom-ref': 'example', purl: 'pkg:npm/example@1.0.0', hashes: [{ alg: 'SHA-256', content: 'a'.repeat(64) }], licenses: [{ license: { id: 'MIT' } }] }], dependencies: [{ ref: 'example', dependsOn: ['missing'] }] });
const spdx = () => ({ spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', SPDXID: 'SPDXRef-DOCUMENT', name: 'Example', documentNamespace: 'https://example.com/sbom/1', creationInfo: { creators: ['Tool: Example-1'], created: '2026-10-02T12:00:00Z' }, packages: [{ SPDXID: 'SPDXRef-example', name: 'example', versionInfo: '1.0.0', downloadLocation: 'NOASSERTION', externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/example@1.0.0' }], filesAnalyzed: false, licenseConcluded: 'MIT', licenseDeclared: 'MIT', copyrightText: 'NOASSERTION' }], relationships: [{ spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-example' }] });

test('both official schemas normalize equivalent package identities and provenance', () => {
  const first = normalizeSbom(JSON.stringify(cdx()));
  const second = normalizeSbom(JSON.stringify(spdx()));
  assert.equal(first.components[0].purl, second.components[0].purl);
  assert.equal(first.components[0].version, second.components[0].version);
  assert.equal(first.dependencies[0].to, 'missing');
  assert.equal(second.generator[0], 'Tool: Example-1');
  assert.equal(first.components[0].hashes[0].value, 'a'.repeat(64));
  assert.equal(first.assessmentState, 'awaiting-assessment');
});

test('incomplete and mismatched identities remain visible; nested components are retained', () => {
  const document = cdx();
  document.components[0].components = [{ type: 'library', name: 'internal', 'bom-ref': 'internal' }];
  document.components[0].version = '2';
  const inventory = normalizeSbom(JSON.stringify(document));
  assert.equal(inventory.componentCount, 2);
  assert.equal(inventory.incompleteComponentCount, 2);
  assert.ok(inventory.components.some(item => item.identityIssue === 'version-mismatch'));
});

test('supplier VEX is attributed and cannot become authoritative assessment', () => {
  const document = cdx();
  document.vulnerabilities = [{ id: 'CVE-2026-1234', affects: [{ ref: 'example' }], analysis: { state: 'not_affected', detail: '<script>untrusted</script>' } }];
  const inventory = normalizeSbom(JSON.stringify(document));
  assert.equal(inventory.supplierEvidence[0].trustedForAssessment, false);
  assert.equal(inventory.supplierEvidence[0].analysis.state, 'not_affected');
  assert.equal(inventory.assessmentState, 'awaiting-assessment');
});

test('malformed schemas, formats, duplicate references, hostile properties and limits fail', () => {
  const invalid = cdx(); invalid.components[0].type = 'invalid';
  assert.throws(() => normalizeSbom(JSON.stringify(invalid)), /Invalid CycloneDX/);
  assert.throws(() => normalizeSbom('{"bomFormat":"CycloneDX","specVersion":"1.6","__proto__":{}}'), /Unsafe/);
  assert.throws(() => normalizeSbom('{}'), /Supported/);
  assert.throws(() => normalizeSbom('a'.repeat(sbomLimits.bytes + 1)), /size/);
  const duplicate = cdx(); duplicate.components.push(duplicate.components[0]);
  assert.throws(() => normalizeSbom(JSON.stringify(duplicate)), /duplicate/i);
  const deep = cdx(); let current = deep;
  for (let index = 0; index < 40; index++) { current.nested = {}; current = current.nested; }
  assert.throws(() => normalizeSbom(JSON.stringify(deep)), /processing/);
  const many = cdx(); many.components = Array.from({ length: 10001 }, (_, index) => ({ type: 'library', name: 'a', 'bom-ref': `ref-${index}` }));
  assert.throws(() => normalizeSbom(JSON.stringify(many)), /component count/);
});

test('image matching requires unambiguous configured scope and rejects mismatches', () => {
  const images = [{ id: 'one', reference: 'docker.io/team/app:1', enabled: true }, { id: 'two', reference: 'docker.io/team/worker:1', enabled: true }];
  assert.equal(selectInventoryImage({ reportedImages: [images[0].reference] }, images), 'one');
  assert.throws(() => selectInventoryImage({ reportedImages: [images[0].reference] }, images, 'two'), /does not match/);
  assert.throws(() => selectInventoryImage({ reportedImages: [] }, images), /explicitly/);
  assert.equal(selectInventoryImage({ reportedImages: [] }, images, null), null);
});

test('concurrent imports preserve revisions, scopes, attribution and restart state without raw content', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-inventory-'));
  try {
    const store = createInventoryStore(directory);
    const state = await store.setImages(app, [{ reference: 'docker.io/team/app:1' }, { reference: 'docker.io/team/worker:1' }]);
    const actor = { name: 'Uploader' };
    const imported = await Promise.all([store.import(app, JSON.stringify(cdx()), null, actor), store.import(app, JSON.stringify(spdx()), state.images[0].id, actor), store.import(app, JSON.stringify(cdx()), state.images[1].id, actor), store.import(app, JSON.stringify(spdx()), null, actor)]);
    const restarted = await createInventoryStore(directory).read(app);
    assert.equal(restarted.revisions.length, 4);
    assert.equal(restarted.revisions.filter(revision => revision.active).length, 3);
    assert.equal(restarted.revisions[0].active, false);
    const revision = JSON.parse(await readFile(path.join(directory, app, `${imported[0].id}.json`), 'utf8'));
    assert.equal(revision.uploader.name, 'Uploader');
    assert.equal(revision.components[0].purl, 'pkg:npm/example@1.0.0');
    assert.equal(revision.raw, undefined);
    await assert.rejects(() => createInventoryStore(directory).read('../escape'));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
