import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../src/web/app.js', import.meta.url), 'utf8');
const code = source.slice(source.indexOf('function packageCoverageMarkup('));
function contextFor(file, fetch) {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      textContent: '', innerHTML: 'previous active inventory', hidden: false, disabled: false,
      value: '', files: [], classes: new Set(), attributes: {},
      classList: { toggle(name, enabled) { enabled ? elements.get(id).classes.add(name) : elements.get(id).classes.delete(name); } },
      setAttribute(name, value) { this.attributes[name] = value; },
      scrollIntoView() { this.scrolled = true; }, addEventListener() {}
    });
    return elements.get(id);
  };
  element('sbom-file').files = [file]; element('sbom-file').value = 'chosen.json';
  const context = vm.createContext({ $: element, fetch, encodeURIComponent, escape: String });
  vm.runInContext(code, context); vm.runInContext("inventoryApplicationId = 'app';", context);
  return { context, element, submit: () => context.importSbom({ preventDefault() {} }) };
}
const file = { size: 12, text: async () => '{not json}' };

test('oversized uploads show an alert before sending and preserve the active inventory', async () => {
  const { element, submit } = contextFor({ ...file, size: 6 * 1024 * 1024 }, () => assert.fail('Must not upload'));
  await submit();
  assert.match(element('sbom-message').textContent, /SBOM upload failed:.*6.00 MiB.*5 MiB/);
  assert.equal(element('sbom-message').attributes.role, 'alert');
  assert.ok(element('sbom-message').classes.has('form-error'));
  assert.equal(element('inventory-summary').innerHTML, 'previous active inventory');
});

test('server parsing errors remain prominent, keep the selected file, and a successful retry clears the alert', async () => {
  let reject = true;
  const { element, submit } = contextFor(file, async url => url.endsWith('/sboms') ? { ok: !reject, json: async () => reject ? { error: 'SBOM must be uncompressed JSON' } : {} } : { ok: true, json: async () => ({ images: [], revisions: [] }) });
  await submit();
  assert.match(element('sbom-message').textContent, /SBOM upload failed: SBOM must be uncompressed JSON/);
  assert.ok(element('sbom-message').classes.has('form-error'));
  assert.equal(element('sbom-file').value, 'chosen.json');
  assert.equal(element('sbom-submit').disabled, false);
  assert.equal(element('sbom-scope').disabled, false);
  assert.equal(element('inventory-summary').innerHTML, 'previous active inventory');
  reject = false; await submit();
  assert.match(element('sbom-message').textContent, /^SBOM imported/);
  assert.doesNotMatch(element('sbom-message').textContent, /metadata.*unavailable/);
  assert.match(element('inventory-summary').innerHTML, /No SBOM imported/);
  assert.equal(element('sbom-message').classes.has('form-error'), false);
  assert.equal(element('sbom-message').attributes.role, 'status');
  assert.equal(element('sbom-file').value, '');
});

test('non-JSON proxy failures identify their HTTP status and metadata failures do not falsely report failed imports', async () => {
  const failed = contextFor(file, async () => ({ ok: false, status: 413, json: async () => { throw new Error('Unexpected token'); } }));
  await failed.submit();
  assert.match(failed.element('sbom-message').textContent, /SBOM upload failed:.*HTTP 413.*upload limit/);
  const saved = contextFor(file, async url => { if (url.endsWith('/sboms')) return { ok: true, json: async () => ({}) }; throw new Error('offline'); });
  await saved.submit();
  assert.match(saved.element('sbom-message').textContent, /^SBOM imported, but inventory metadata/);
  assert.equal(saved.element('sbom-message').classes.has('form-error'), false);
});
