import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { normalizeSbom } from '../src/sbom.mjs';
import { createInventoryStore } from '../src/inventory-store.mjs';
import { createOsvClient } from '../src/osv.mjs';
import { reconcileFindingWorkflows } from '../src/findings.mjs';

const base = 'https://example.com/sbom/';
const element = (type, name, properties = {}) => ({ type, spdxId: base + name, creationInfo: '_:creation', ...properties });
function document(version = '3.0.1') {
  return { '@context': `https://spdx.org/rdf/${version === '3.0' ? '3.0.0' : version}/spdx-context.jsonld`, '@graph': [
    { type: 'CreationInfo', '@id': '_:creation', specVersion: version === '3.0' ? '3.0.0' : version, created: '2026-10-02T12:00:00Z', createdBy: [base + 'supplier'], createdUsing: [base + 'tool'] },
    element('Organization', 'supplier', { name: 'Example supplier' }),
    element('Tool', 'tool', { name: 'Example generator' }),
    element('SpdxDocument', 'document', { rootElement: [base + 'package'] }),
    element('software_Package', 'package', { name: 'example', software_packageVersion: '1.0.0', software_packageUrl: 'pkg:npm/example@1.0.0', suppliedBy: base + 'supplier', verifiedUsing: [{ type: 'Hash', algorithm: 'sha256', hashValue: 'a'.repeat(64) }] }),
    element('simplelicensing_LicenseExpression', 'license', { simplelicensing_licenseExpression: 'MIT' }),
    element('Relationship', 'license-relation', { from: base + 'package', to: [base + 'license'], relationshipType: 'hasDeclaredLicense' }),
    element('Relationship', 'dependency', { from: base + 'package', to: [base + 'external'], relationshipType: 'dependsOn' }),
    element('security_Vulnerability', 'vulnerability', { name: 'CVE-2026-1234' }),
    element('Relationship', 'supplier-assertion', { from: base + 'vulnerability', to: [base + 'package'], relationshipType: 'doesNotAffect' })
  ] };
}

for (const version of ['3.0', '3.0.1']) test(`SPDX ${version} normalizes graph references, provenance and supplier assertions`, () => {
  const result = normalizeSbom(JSON.stringify(document(version)));
  assert.equal(result.specificationVersion, version);
  assert.equal(result.componentCount, 1);
  assert.equal(result.components[0].purl, 'pkg:npm/example@1.0.0');
  assert.equal(result.components[0].supplier, 'Example supplier');
  assert.deepEqual(result.components[0].licenses, ['MIT']);
  assert.equal(result.components[0].hashes[0].value, 'a'.repeat(64));
  assert.deepEqual(result.generator, ['Example generator']);
  assert.equal(result.generatedAt, '2026-10-02T12:00:00Z');
  assert.ok(result.dependencies.some(edge => edge.relationship === 'DEPENDS_ON' && edge.to === base + 'external'));
  assert.equal(result.supplierEvidence.length, 2);
  assert.ok(result.supplierEvidence.every(item => item.trustedForAssessment === false));
  assert.equal(result.assessmentState, 'awaiting-assessment');
});

test('SPDX JSON-LD rejects unknown contexts, malformed graphs, duplicate IDs and unresolved creation info', () => {
  for (const context of ['https://example.com/context', 'https://spdx.org/rdf/3.1/spdx-context.jsonld']) {
    const value = document(); value['@context'] = context;
    assert.throws(() => normalizeSbom(JSON.stringify(value)), /Unsupported SPDX JSON-LD context/);
  }
  const malformed = document(); delete malformed['@graph'][0].created;
  assert.throws(() => normalizeSbom(JSON.stringify(malformed)), /Invalid SPDX/);
  const duplicate = document(); duplicate['@graph'].push(duplicate['@graph'][4]);
  assert.throws(() => normalizeSbom(JSON.stringify(duplicate)), /Duplicate SPDX/);
  const unresolved = document(); unresolved['@graph'][4].creationInfo = '_:missing';
  assert.throws(() => normalizeSbom(JSON.stringify(unresolved)), /Unresolved SPDX creation/);
  const future = document(); future['@graph'][0].specVersion = '3.1.0';
  assert.throws(() => normalizeSbom(JSON.stringify(future)), /Unsupported SPDX creation/);
});

test('SPDX JSON-LD conflicting identities cannot become assessable packages', () => {
  const value = document(); value['@graph'][4].externalIdentifier = [{ type: 'ExternalIdentifier', externalIdentifierType: 'packageUrl', identifier: 'pkg:npm/other@1.0.0' }];
  const result = normalizeSbom(JSON.stringify(value));
  assert.equal(result.components[0].identityIssue, 'conflicting-purls');
  assert.equal(result.components[0].purl, '');
});

test('SPDX 3 imports run within the bounded worker and retain revision metadata after restart', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-spdx3-'));
  const app = '11111111-1111-4111-8111-111111111111';
  try {
    for (const version of ['3.0', '3.0.1']) {
      await createInventoryStore(directory).import(app, JSON.stringify(document(version)), null, { name: 'Uploader' });
      const stored = await createInventoryStore(directory).loadActive(app);
      assert.equal(stored.inventories[0].specificationVersion, version);
      assert.equal(stored.inventories[0].components[0].purl, 'pkg:npm/example@1.0.0');
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('SPDX 3 supplier VEX does not suppress OSV findings and cross-format package identity is stable', async () => {
  const cdx = { bomFormat: 'CycloneDX', specVersion: '1.7', version: 1, components: [{ type: 'library', name: 'example', version: '1.0.0', purl: 'pkg:npm/example@1.0.0' }] };
  const api = createOsvClient({ pause: async () => {}, fetchImpl: async url => new Response(JSON.stringify(url.endsWith('querybatch') ? { results: [{ vulns: [{ id: 'CVE-2026-1234' }] }] } : { id: 'CVE-2026-1234', affected: [{ package: { ecosystem: 'npm', name: 'example' } }] })) });
  const store = { records: {} }; let previous;
  for (const raw of [cdx, document('3.0'), document('3.0.1')]) {
    const inventory = { ...normalizeSbom(JSON.stringify(raw)), id: 'revision', scope: { applicationId: '11111111-1111-4111-8111-111111111111', imageId: null } };
    const result = await api.assess(inventory);
    const apps = [{ id: '11111111-1111-4111-8111-111111111111', vulnerabilities: result.findings }];
    reconcileFindingWorkflows(store, apps);
    assert.equal(apps[0].vulnerabilities.length, 1);
    const id = apps[0].vulnerabilities[0].id;
    if (previous) assert.equal(id, previous);
    previous = id;
  }
});
