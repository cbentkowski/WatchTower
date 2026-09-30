import test from 'node:test';
import assert from 'node:assert/strict';
import { cpeSearchMatch, effectiveCpe, legacyCpe, mappingFromApp, mappingWarnings, parseCpe23, productCpe } from '../src/cpe.mjs';

const exact = 'cpe:2.3:a:atlassian:jira_service_management:5.17.3:*:enterprise:*:*:*:*:*';

test('CPE 2.3 parsing returns named components and rejects malformed names', () => {
  const parsed = parseCpe23(exact);
  assert.equal(parsed.vendor, 'atlassian');
  assert.equal(parsed.product, 'jira_service_management');
  assert.equal(parsed.version, '5.17.3');
  assert.equal(parsed.edition, 'enterprise');
  assert.throws(() => parseCpe23('cpe:2.3:a:vendor:product'), /11 components/);
  assert.throws(() => parseCpe23('cpe:2.3:*:*:*:*:*:*:*:*:*:*:*'), /part/);
});

test('product and exact mapping modes produce their intended query CPE', () => {
  const parsed = parseCpe23(exact);
  assert.equal(productCpe(parsed), 'cpe:2.3:a:atlassian:jira_service_management:*:*:*:*:*:*:*:*');
  assert.equal(effectiveCpe(parsed, 'exact'), exact);
  assert.equal(effectiveCpe(parsed, 'product'), productCpe(parsed));
});

test('legacy fields become a compatible mapping without changing identity or qualifiers', () => {
  const app = { cpeVendor: 'gitlab', cpeProduct: 'gitlab', cpeEdition: 'enterprise' };
  assert.equal(legacyCpe(app), 'cpe:2.3:a:gitlab:gitlab:*:*:enterprise:*:*:*:*:*');
  const mapping = mappingFromApp(app);
  assert.equal(mapping.vendor, 'gitlab');
  assert.equal(mapping.product, 'gitlab');
  assert.equal(mapping.mode, 'exact');
});

test('mapping warnings identify deprecated, conflicting, and ignored qualifiers', () => {
  const mapping = { ...parseCpe23(exact), mode: 'exact', deprecated: true };
  assert.deepEqual(mappingWarnings(mapping, '5.18.0').map(item => item.code), ['deprecated', 'version-conflict']);
  assert.ok(mappingWarnings({ ...mapping, mode: 'product' }, '5.17.3').some(item => item.code === 'qualifiers-ignored'));
});

test('advanced search filters any text and individual fields', () => {
  const item = { ...parseCpe23(exact), title: 'Jira Service Management' };
  assert.equal(cpeSearchMatch(item, { any: 'service', vendor: 'atlas' }), true);
  assert.equal(cpeSearchMatch(item, { any: 'service', vendor: 'microsoft' }), false);
});
