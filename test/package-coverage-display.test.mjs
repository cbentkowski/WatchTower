import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
const source = await readFile(new URL('../src/web/app.js', import.meta.url), 'utf8');
const code = source.slice(source.indexOf('function packageCoverageMarkup('), source.indexOf('let inventoryApplicationId = null;'));
const context = vm.createContext({ escape: value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;') });
vm.runInContext(code, context);

test('coverage explains partial success, skipped identities, retained findings and source errors safely', () => {
  const html = context.packageCoverageMarkup({ inventories: [{ state: 'incomplete', assessedComponentCount: 2, packageComponentCount: 4, findingCount: 2, retainedFindingCount: 1, unsupportedComponentCount: 1, ignoredComponentCount: 3179,
    lookups: [{ purl: 'pkg:npm/clear@1', state: 'no-known-matches' }, { purl: 'pkg:npm/affected@1', state: 'findings', findingCount: 1 }, { purl: 'pkg:npm/offline@1', state: 'incomplete' }],
    unsupported: [{ name: '<script>alert(1)</script>', reason: 'unsupported-ecosystem', ecosystem: 'deb' }], errors: [{ purl: 'pkg:npm/offline@1', message: 'OSV HTTP 503' }], typeMetadataMissing: true, stale: true }] });
  for (const expected of ['2 of 4 package entries checked', '3179 non-package entries', 'Lookup succeeded; no known vulnerabilities returned', '1 finding occurrence(s)', 'Lookup incomplete', 'No assessment adapter for this package ecosystem', 'OSV HTTP 503', '1 finding(s) retained', 'Reimport this SBOM', 'inventory is stale', 'Coverage is incomplete']) assert.ok(html.includes(expected), expected);
  assert.ok(html.includes('&lt;script&gt;'));
  assert.equal(html.includes('<script>'), false);
});

test('coverage bounds long visible lists without hiding their total or claiming complete coverage', () => {
  const html = context.packageCoverageMarkup({ inventories: [{ state: 'incomplete', unsupported: Array.from({ length: 150 }, (_, i) => ({ name: `package-${i}`, reason: 'missing-purl' })) }] });
  assert.ok(html.includes('Showing the first 100 of 150 entries'));
  assert.ok(html.includes('Skipped packages and reasons (150)'));
  assert.equal(html.includes('package-149'), false);
  assert.equal(context.packageCoverageMarkup(undefined), '');
});
