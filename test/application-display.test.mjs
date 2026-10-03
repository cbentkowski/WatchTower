import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../src/web/app.js', import.meta.url), 'utf8');
const detailCode = source.slice(source.indexOf('function showDetails(a)'), source.indexOf('async function openFindingEditor'));
const application = { id: 'app', name: 'Example', version: '1', status: 'green', vulnerabilities: [], reasons: [], sources: [], ownerIds: [], tags: [] };
const escapeCode = source.slice(source.indexOf('const escape ='), source.indexOf('const safeUrl ='));
const archiveCode = source.slice(source.indexOf('function resolvedPackagesMarkup('));
test('resolved history preserves responses, escapes source text and reports read failures safely', async () => {
  const elements = new Map();
  const element = id => { if (!elements.has(id)) elements.set(id, { addEventListener() {}, showModal() {}, close() {} }); return elements.get(id); };
  const context = vm.createContext({ $: element, detailAppId: 'app', encodeURIComponent, Date, fetch: async () => ({ ok: false, json: async () => ({ error: '<upload failed>' }) }) });
  vm.runInContext(escapeCode + archiveCode, context);
  const markup = context.resolvedPackagesMarkup([{ id: 'uuid', advisoryId: 'GHSA-demo', package: { name: '<ScRiPt>alert(1)</sCrIpT>', version: '1' }, resolution: { reason: 'version-changed', at: '2026-10-02' }, workflow: { notes: '<IMG src=x onerror=alert(1)> & \"quoted\"', assignee: '<SCRIPT>', ticketReference: "SEC-'1'" } }]);
  assert.match(markup, /version changed/);
  assert.ok(markup.includes('&lt;ScRiPt&gt;alert(1)&lt;/sCrIpT&gt;'));
  assert.ok(markup.includes('&lt;SCRIPT&gt;'));
  assert.ok(markup.includes('&amp; &quot;quoted&quot;'));
  assert.ok(markup.includes('SEC-&#39;1&#39;'));
  assert.ok(markup.includes('&lt;IMG src=x onerror=alert(1)&gt;'));
  assert.match(markup, /View history/);
  assert.doesNotMatch(markup, /Update response/);
  assert.doesNotMatch(markup, /<\s*(?:script|img)\b/i);
  await context.openResolvedHistory('uuid');
  assert.equal(element('resolved-history-body').textContent, '<upload failed>');
});
function displayContext(permissions) {
  const elements = new Map();
  const element = id => { if (!elements.has(id)) elements.set(id, { addEventListener() {}, hidden: false, scrollTop: 0, open: false, showModal() { this.open = true; this.scrollTop = 900; } }); return elements.get(id); };
  const context = vm.createContext({ $: element, requestAnimationFrame: callback => callback(), detailAppId: null, isAdmin: false, permissions, openInventory() {}, packageContext: () => '', packageCoverageMarkup: () => '', resolvedPackagesMarkup: () => '', labels: { green: 'Clear' }, escape: value => String(value), safeUrl: value => value, workspaces: [], owners: [], allResults: [application], encodeURIComponent, render(data) { context.allResults = data.results; } });
  context.kevMarkup = () => '';
  vm.runInContext(detailCode, context);
  return { context, element };
}
test('application opens at the top but an open-dialog repaint retains scroll position', () => {
  const { context, element } = displayContext({ scan: false, applications: { view: ['app'], edit: [] } });
  context.showDetails(application);
  assert.equal(element('details').scrollTop, 0);
  element('details').scrollTop = 450;
  element('detail-body').scrollTop = 700;
  context.showDetails(application);
  assert.equal(element('details').scrollTop, 450);
  assert.equal(element('detail-body').scrollTop, 700);
  element('details').open = false;
  context.showDetails(application);
  assert.equal(element('details').scrollTop, 0);
  assert.equal(element('detail-body').scrollTop, 0);
  element('detail-body').scrollTop = 800;
  context.showDetails({ ...application, id: 'another-app' });
  assert.equal(element('detail-body').scrollTop, 0);
  assert.equal(element('refresh-app').hidden, true);
});
test('scan operator can refresh without edit, posts the selected ID, and preserves dialog position', async () => {
  const { context, element } = displayContext({ scan: true, applications: { view: ['app'], edit: [] } });
  context.showDetails(application);
  assert.equal(element('refresh-app').hidden, false);
  assert.equal(element('edit-app').hidden, true);
  element('details').scrollTop = 320;
  element('detail-body').scrollTop = 600;
  const requests = [];
  context.fetch = async (url, options) => { requests.push({ url, options }); return { ok: true, json: async () => ({ results: [application] }) }; };
  await context.refreshDisplayedApplication();
  assert.equal(requests[0].url, '/api/applications/app/refresh');
  assert.equal(requests[0].options.method, 'POST');
  assert.equal(element('details').scrollTop, 320);
  assert.equal(element('detail-body').scrollTop, 600);
  assert.equal(element('refresh-app').disabled, false);
  assert.match(element('detail-refresh-message').textContent, /complete/);
});

test('package finding response controls retain the finding UUID while displaying the advisory', () => {
  const { context, element } = displayContext({ scan: false, applications: { view: ['app'], edit: ['app'] } });
  context.showDetails({ ...application, vulnerabilities: [{ id: 'finding-uuid', advisoryId: 'GHSA-package-advisory', label: 'HIGH', package: { name: 'lodash' }, workflow: { state: 'new' } }] });
  assert.match(element('detail-body').innerHTML, /data-finding-id="finding-uuid"/);
  assert.match(element('detail-body').innerHTML, /GHSA-package-advisory/);
  assert.match(element('detail-body').innerHTML, /Update response/);
});

const statusCode = source.slice(source.indexOf('function dashboardStatus('), source.indexOf('function setTheme('));
test('dashboard distinguishes checked no-findings from unknown without promoting partial evidence or findings', () => {
  const context = vm.createContext({ labels: { unknown: 'Unknown', red: 'Needs action', yellow: 'Approaching EOL', green: 'Clear' }, escape: String });
  vm.runInContext(statusCode, context);
  const app = { status: 'unknown', vulnerabilities: [], packageAssessment: { state: 'incomplete', inventories: [{ assessedComponentCount: 5 }] } };
  assert.match(context.dashboardStatus(app), /badge unknown.*No findings.*Partial coverage/);
  assert.match(context.dashboardStatus({ ...app, packageAssessment: { state: 'incomplete', inventories: [{ assessedComponentCount: 0 }] } }), />Unknown</);
  assert.match(context.dashboardStatus({ ...app, packageAssessment: { state: 'assessed', inventories: [{ assessedComponentCount: 5 }] } }), /No findings.*Assessment incomplete/);
  assert.doesNotMatch(context.dashboardStatus({ ...app, vulnerabilities: [{ id: 'finding' }] }), /No findings/);
  assert.match(context.dashboardStatus({ ...app, status: 'red' }), /Needs action/);
  assert.match(context.dashboardStatus({ ...app, status: 'yellow' }), /Approaching EOL/);
});
