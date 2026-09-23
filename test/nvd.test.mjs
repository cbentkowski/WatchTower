import test from 'node:test';
import assert from 'node:assert/strict';
import { cpeMatchAffectsVersion, cveAffectsApplication, wildcardApplicationCpe } from '../nvd.mjs';

const app = { version: '5.17.3', cpeVendor: 'atlassian', cpeProduct: 'jira_service_management', cpeEdition: '' };
const ranged = { vulnerable: true, criteria: 'cpe:2.3:a:atlassian:jira_service_management:*:*:*:*:*:*:*:*', versionStartIncluding: '5.16.0', versionEndExcluding: '5.17.4' };

test('wildcard NVD CPE keeps product identity and omits the installed version', () => {
  assert.equal(wildcardApplicationCpe(app), 'cpe:2.3:a:atlassian:jira_service_management:*:*:*:*:*:*:*:*');
});

test('NVD range matching includes only affected installed versions', () => {
  assert.equal(cpeMatchAffectsVersion(ranged, app), true);
  assert.equal(cpeMatchAffectsVersion(ranged, { ...app, version: '5.17.4' }), false);
  assert.equal(cpeMatchAffectsVersion(ranged, { ...app, version: '5.15.9' }), false);
  assert.equal(cpeMatchAffectsVersion({ ...ranged, vulnerable: false }, app), false);
  assert.equal(cpeMatchAffectsVersion({ ...ranged, criteria: 'cpe:2.3:a:other:product:*:*:*:*:*:*:*:*' }, app), false);
});

test('CVE applicability finds matching ranges inside NVD configuration nodes', () => {
  const cve = { configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [{ ...ranged, versionEndExcluding: '5.17.3' }, ranged] }] }] };
  assert.equal(cveAffectsApplication(cve, app), true);
  assert.equal(cveAffectsApplication(cve, { ...app, version: '5.18.0' }), false);
});
