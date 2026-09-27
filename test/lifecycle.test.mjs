import test from 'node:test';
import assert from 'node:assert/strict';
import { matchLifecycleRelease, normalizeLifecycleProduct, searchLifecycleProducts } from '../lifecycle.mjs';

const products = [
  { name: 'chrome', label: 'Google Chrome', aliases: ['google-chrome'], category: 'app', tags: ['google', 'web-browser'] },
  { name: 'chromium', label: 'Chromium', aliases: [], category: 'app', tags: ['google', 'web-browser'] },
  { name: 'postgresql', label: 'PostgreSQL', aliases: ['postgres'], category: 'database', tags: ['database'] },
];

test('lifecycle search uses text, category, vendor, and CPE hints', () => {
  assert.equal(searchLifecycleProducts(products, { query: 'chrome' })[0].name, 'chrome');
  assert.equal(searchLifecycleProducts(products, { vendor: 'google', cpe: 'cpe:2.3:a:google:chrome' })[0].name, 'chrome');
  assert.deepEqual(searchLifecycleProducts(products, { query: 'postgres', category: 'database' }).map(item => item.name), ['postgresql']);
});

test('lifecycle products and releases normalize and match installed versions', () => {
  const product = normalizeLifecycleProduct({ name: 'postgresql', releases: [{ name: '16', label: '16', isEol: false, isMaintained: true, latest: { name: '16.10', date: '2026-08-10' } }] });
  assert.equal(product.releases[0].eol, false);
  assert.equal(product.releases[0].latest, '16.10');
  assert.equal(matchLifecycleRelease(product.releases, '16.4').cycle, '16');
  assert.equal(matchLifecycleRelease(product.releases, '15.1'), null);
});
