import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
const source = await readFile(new URL('../src/web/app.js', import.meta.url), 'utf8');
const escapeCode = source.slice(source.indexOf('const escape ='), source.indexOf('const safeUrl ='));
const image = { id: 'image-one', reference: 'docker.io/test/app:1', label: '<SCRIPT>', enabled: true, retired: false };
const revision = { id: 'revision', scope: { imageId: image.id }, active: true, imageReferenceAtImport: image.reference, format: 'CycloneDX', specificationVersion: '1.7', generator: ['<IMG>'], generatedAt: '', importedAt: '2026-10-02', checksum: 'hash', componentCount: 2, assessmentState: 'assessed', assessment: { assessedComponentCount: 2, unsupportedComponentCount: 0, lastSuccessfulLookup: '2026-10-02' } };
test('late inventory responses cannot overwrite a different application dialog', async () => {
  let finish;
  const data = new Promise(resolve => { finish = resolve; });
  const context = vm.createContext({ inventoryApplicationId: 'first', encodeURIComponent, fetch: async () => ({ ok: true, json: () => data }), renderInventory: () => assert.fail('A stale response must not repaint the new application') });
  vm.runInContext(source.slice(source.indexOf('async function readInventory()'), source.indexOf('async function openInventory(')), context);
  const pending = context.readInventory();
  context.inventoryApplicationId = 'second';
  finish({ images: [], revisions: [] });
  await pending;
});
function setup({ admin = true, preview = null, fetch = async () => ({ ok: true, json: async () => ({ images: [image], revisions: [revision] }) }) } = {}) {
  const elements = new Map();
  const element = id => { if (!elements.has(id)) elements.set(id, { value: '', checked: false, hidden: false, disabled: false, textContent: '', innerHTML: '', listeners: {}, addEventListener(type, handler) { this.listeners[type] = handler; }, focus() {}, querySelectorAll() { return []; }, classList: { toggle() {} }, setAttribute() {} }); return elements.get(id); };
  const context = vm.createContext({ $: element, activePreview: preview, isAdmin: admin, permissions: { applications: { edit: [] } }, inventoryApplicationId: 'app', packageCoverageMarkup: () => '', readInventory: async () => {}, fetch, encodeURIComponent, Date });
  vm.runInContext(escapeCode + source.slice(source.indexOf('let inventoryData =')), context);
  vm.runInContext('inventoryData = ' + JSON.stringify({ images: [image], revisions: [revision] }), context);
  return { context, element };
}
test('inventory rendering escapes provenance and hides mutations for viewers and Permission Preview', () => {
  for (const options of [{}, { admin: false }, { preview: {} }]) {
    const { context, element } = setup(options); context.renderInventory();
    assert.match(element('inventory-images').innerHTML, /&lt;SCRIPT&gt;/);
    assert.match(element('inventory-summary').innerHTML, /&lt;IMG&gt;/);
    assert.doesNotMatch(element('inventory-summary').innerHTML, /<\s*(?:script|img)\b/i);
    assert.match(element('inventory-summary').innerHTML, /Last successful lookup|Browse components/);
    if (options.admin === false || options.preview) { assert.equal(element('image-add').hidden, true); assert.doesNotMatch(element('inventory-images').innerHTML, /data-image-edit|data-image-retire/); }
  }
});
test('retirement requires an exact reference and image saves retain all managed IDs', async () => {
  const requests = [];
  const { context, element } = setup({ fetch: async (url, options) => { requests.push(JSON.parse(options.body)); return { ok: true, json: async () => ({}) }; } });
  context.beginImageRetirement(image.id);
  element('image-retire-confirm').value = 'wrong';
  element('image-retire-form').listeners.submit({ preventDefault() {} });
  assert.equal(requests.length, 0); assert.match(element('image-message').textContent, /exactly/);
  await context.saveInventoryImages([{ ...image, retired: true }]);
  assert.equal(requests[0].images[0].id, image.id); assert.equal(requests[0].images[0].retired, true);
  assert.match(element('image-message').textContent, /Refresh the application/);
});
test('component browser escapes package evidence and applies server paging bounds', async () => {
  const { context, element } = setup({ fetch: async () => ({ ok: true, json: async () => ({ total: 70, offset: 0, components: [{ name: '<SCRIPT>', supplier: '<IMG>', licenses: ['<SVG>'], hashes: [], cpes: [], locations: [], componentRef: 'id' }], dependencies: [{ from: '<SCRIPT>', to: 'id', relationship: 'DEPENDS_ON' }], dependencyCount: 1 }) }) });
  await context.loadComponents();
  assert.match(element('components-body').innerHTML, /&lt;SCRIPT&gt;/);
  assert.match(element('components-body').innerHTML, /&lt;IMG&gt;/);
  assert.doesNotMatch(element('components-body').innerHTML, /<\s*(?:script|img|svg)\b/i);
  assert.equal(element('components-prev').disabled, true); assert.equal(element('components-next').disabled, false);
});
