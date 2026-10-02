import test from 'node:test';
import assert from 'node:assert/strict';
import { createOsvClient, osvPackage, osvLimits } from '../src/osv.mjs';
import { assessApplicationInventory } from '../src/package-assessment.mjs';
import { reconcileFindingWorkflows, updateFindingWorkflow } from '../src/findings.mjs';

const app = '11111111-1111-4111-8111-111111111111';
const scope = { applicationId: app, imageId: null };
const component = (name = 'example', version = '1.0.0') => ({ componentRef: name, name, version, purl: `pkg:npm/${name}@${version}`, identityIssue: '', location: '' });
const inventory = (components = [component()]) => ({ id: '22222222-2222-4222-8222-222222222222', scope, importedAt: '2026-10-02T12:00:00Z', generatedAt: '', componentCount: components.length, components, dependencies: [] });
const record = (id = 'GHSA-xxxx-yyyy-zzzz', name = 'example', aliases = ['CVE-2026-1234']) => ({ id, modified: '2026-10-02T12:00:00Z', aliases, summary: 'Affected package', database_specific: { severity: 'HIGH' }, affected: [{ package: { ecosystem: 'npm', name }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.1.0' }] }] }], references: [{ type: 'ADVISORY', url: 'https://example.com/advisory' }, { type: 'WEB', url: 'javascript:alert(1)' }] });
const json = data => new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
function client(handler) { return createOsvClient({ fetchImpl: handler, now: () => Date.parse('2026-10-02T12:00:00Z'), pause: async () => {} }); }

test('OSV supports explicit language ecosystems; qualified/distribution/incomplete identities stay unknown', () => {
  assert.equal(osvPackage(component()).queryPurl, 'pkg:npm/example@1.0.0');
  for (const value of [{ ...component(), purl: 'pkg:deb/debian/example@1.0.0' }, { ...component(), purl: 'pkg:npm/example@1.0.0?repository_url=other' }, { ...component(), identityIssue: 'version-mismatch' }]) assert.ok(osvPackage(value).reason);
});

test('pagination follows tokens only for incomplete packages, fetches full records and correlates aliases', async () => {
  const requests = [];
  const api = client(async (url, options) => {
    requests.push({ url, body: options.body && JSON.parse(options.body) });
    if (url.endsWith('querybatch')) {
      const queries = JSON.parse(options.body).queries;
      assert.equal(queries[0].version, undefined);
      if (queries[0].page_token) { assert.equal(queries.length, 1); return json({ results: [{ vulns: [{ id: 'CVE-2026-1234', modified: 'v1' }] }] }); }
      return json({ results: [{ vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz', modified: 'v1' }], next_page_token: 'more' }, {}] });
    }
    return json(url.includes('GHSA') ? record() : record('CVE-2026-1234', 'example', ['GHSA-xxxx-yyyy-zzzz']));
  });
  const result = await api.assess(inventory([component(), component('other')]), new Set(['CVE-2026-1234']));
  assert.equal(result.state, 'assessed');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].sourceRecords.length, 2);
  assert.deepEqual(result.findings[0].fixedVersions, ['1.1.0']);
  assert.equal(result.findings[0].knownExploited, true);
  assert.equal(result.findings[0].score, null);
  assert.equal(result.findings[0].advisories.some(url => url.startsWith('javascript:')), false);
  assert.equal(requests.filter(request => request.url.endsWith('querybatch')).length, 2);
});

test('batches and repeated pagination are bounded; malformed and failed results never become assessed', async () => {
  const sizes = [];
  const batched = await client(async (url, options) => { const queries = JSON.parse(options.body).queries; sizes.push(queries.length); return json({ results: queries.map(() => ({})) }); }).assess(inventory(Array.from({ length: 205 }, (_, index) => component(`package${index}`))));
  assert.deepEqual(sizes, [100, 100, 5]);
  assert.equal(batched.assessedComponentCount, 205);
  for (const response of [{ results: [] }, { results: [{ next_page_token: 'repeat' }] }, { results: [{ error: 'lookup failed' }] }, { results: [{ vulns: null }] }]) {
    const result = await client(async () => json(response)).assess(inventory());
    assert.equal(result.state, 'incomplete');
    assert.ok(result.errors.length);
  }
  let attempts = 0;
  const retry = await client(async () => { attempts++; return attempts < 3 ? new Response('', { status: 429, headers: { 'retry-after': '0' } }) : json({ results: [{}] }); }).assess(inventory());
  assert.equal(attempts, 3);
  assert.equal(retry.state, 'assessed');
  const oversized = await client(async () => new Response('{}', { headers: { 'content-length': String(osvLimits.bytes + 1) } })).assess(inventory());
  assert.equal(oversized.state, 'incomplete');
});

test('fresh queries observe new advisories while detail caching respects modified timestamps', async () => {
  let revision = 'first', detailCalls = 0;
  const api = client(async (url) => {
    if (url.endsWith('querybatch')) return json({ results: [{ vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz', modified: revision }] }] });
    detailCalls++; return json(record());
  });
  await api.assess(inventory()); await api.assess(inventory());
  assert.equal(detailCalls, 1);
  revision = 'second'; await api.assess(inventory());
  assert.equal(detailCalls, 2);
});

test('package mismatch and related identifiers cannot silently merge applicability', async () => {
  const api = client(async url => url.endsWith('querybatch') ? json({ results: [{ vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz' }] }] }) : json(record('GHSA-xxxx-yyyy-zzzz', 'different')));
  const result = await api.assess(inventory());
  assert.equal(result.state, 'incomplete');
  assert.equal(result.findings.length, 0);
});

test('advisory aliases preserve UUID and disposition while scopes and locations remain independent', async () => {
  let aliases = [], id = 'GHSA-xxxx-yyyy-zzzz';
  const api = client(async url => url.endsWith('querybatch') ? json({ results: [{ vulns: [{ id, modified: id }] }] }) : json(record(id, 'example', aliases)));
  const store = { records: {} };
  const first = [{ id: app, vulnerabilities: (await api.assess(inventory())).findings }];
  reconcileFindingWorkflows(store, first);
  const uuid = first[0].vulnerabilities[0].id;
  updateFindingWorkflow(store, app, uuid, { state: 'risk-accepted', notes: 'Keep response' }, {});
  aliases = ['GHSA-xxxx-yyyy-zzzz']; id = 'CVE-2026-1234';
  const next = [{ id: app, vulnerabilities: (await api.assess(inventory())).findings }];
  reconcileFindingWorkflows(store, next);
  assert.equal(next[0].vulnerabilities[0].id, uuid);
  assert.equal(next[0].vulnerabilities[0].workflow.state, 'risk-accepted');
  const other = inventory([{ ...component(), locations: ['/one', '/two'] }]); other.scope = { applicationId: app, imageId: '33333333-3333-4333-8333-333333333333' };
  const distinct = [{ id: app, vulnerabilities: (await api.assess(other)).findings }];
  reconcileFindingWorkflows(store, distinct);
  assert.equal(new Set(distinct[0].vulnerabilities.map(finding => finding.id)).size, 2);
  assert.ok(distinct[0].vulnerabilities.every(finding => finding.id !== uuid));
});

test('missing, stale, partial and failed inventory evidence stays incomplete and retains prior findings', async () => {
  const stored = [];
  const item = inventory();
  const api = client(async url => url.endsWith('querybatch') ? json({ results: [{ vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz' }] }] }) : json(record()));
  const store = { loadActive: async () => ({ images: [], inventories: [item] }), recordAssessment: async (_, __, result) => { stored.push(result); return true; } };
  const first = await assessApplicationInventory({ id: app, assessmentMode: 'inventory' }, store, api, new Set(), { now: new Date('2026-10-02T12:00:00Z') });
  assert.equal(first.state, 'assessed');
  item.previousAssessment = stored[0];
  const failed = await assessApplicationInventory({ id: app }, store, { assess: async () => { throw new Error('offline'); } }, new Set(), { now: new Date('2026-10-02T12:00:00Z') });
  assert.equal(failed.state, 'incomplete');
  assert.equal(failed.findings[0].evidenceState, 'unverified');
  item.generatedAt = '2020-01-01T00:00:00Z';
  assert.equal((await assessApplicationInventory({ id: app }, store, api, new Set(), { now: new Date('2026-10-02T12:00:00Z') })).state, 'incomplete');
  const empty = { ...store, loadActive: async () => ({ images: [], inventories: [] }) };
  assert.equal((await assessApplicationInventory({ id: app, assessmentMode: 'inventory' }, empty, api, new Set())).state, 'incomplete');
});
