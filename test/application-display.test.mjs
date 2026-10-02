import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../src/web/app.js', import.meta.url), 'utf8');
const detailCode = source.slice(source.indexOf('function showDetails(a)'), source.indexOf('async function openFindingEditor'));
const application = { id: 'app', name: 'Example', version: '1', status: 'green', vulnerabilities: [], reasons: [], sources: [], ownerIds: [], tags: [] };
function displayContext(permissions) {
  const elements = new Map();
  const element = id => { if (!elements.has(id)) elements.set(id, { hidden: false, scrollTop: 0, open: false, showModal() { this.open = true; this.scrollTop = 900; } }); return elements.get(id); };
  const context = vm.createContext({ $: element, requestAnimationFrame: callback => callback(), detailAppId: null, isAdmin: false, permissions, labels: { green: 'Clear' }, escape: value => String(value), safeUrl: value => value, workspaces: [], owners: [], allResults: [application], encodeURIComponent, render(data) { context.allResults = data.results; } });
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
