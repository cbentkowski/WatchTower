import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { normalizeKevCatalog, kevIndex, enrichKevFindings } from '../src/kev.mjs';
import { reconcileFindingWorkflows } from '../src/findings.mjs';

const entry = { cveID: 'CVE-2026-1234', dateAdded: '2026-10-01', dueDate: '2026-10-22', requiredAction: 'Apply updates.' };
const catalog = () => normalizeKevCatalog({ vulnerabilities: [entry], dateReleased: '2026-10-01T12:00:00Z' }, '2026-10-03T01:00:00Z');

test('KEV details match product CVEs and all package aliases without losing missing fields', () => {
  const findings = [{ id: entry.cveID }, { id: 'uuid', advisoryId: 'GHSA-test', aliases: [entry.cveID.toLowerCase()], package: { purl: 'pkg:npm/test@1' } }, { id: 'CVE-2026-9999' }];
  enrichKevFindings(findings, kevIndex(catalog()));
  assert.ok(findings[0].knownExploited && findings[1].knownExploited);
  assert.equal(findings[1].kev.entries[0].requiredAction, 'Apply updates.');
  assert.equal(findings[2].knownExploited, false);
  const incomplete = normalizeKevCatalog({ vulnerabilities: [{ cveID: entry.cveID, dueDate: '2026-99-99' }] });
  enrichKevFindings(findings, kevIndex(incomplete));
  assert.equal(findings[0].knownExploited, true);
  assert.equal(findings[0].kev.entries[0].dueDate, '');
  assert.throws(() => normalizeKevCatalog({ vulnerabilities: [{ cveID: 'not-a-cve' }] }), /identifier/);
  assert.throws(() => normalizeKevCatalog({ vulnerabilities: [entry, entry] }), /Duplicate/);
});

test('outages retain confirmed evidence and only successful status changes produce assessment events', () => {
  const store = { records: {} };
  const assess = index => { const result = { id: 'app', vulnerabilities: [{ id: entry.cveID, score: 8, label: 'High' }] }; enrichKevFindings(result.vulnerabilities, index); return { result, update: reconcileFindingWorkflows(store, [result]) }; };
  assess(kevIndex(normalizeKevCatalog({ vulnerabilities: [] })));
  const confirmed = assess(kevIndex(catalog()));
  assert.deepEqual(confirmed.update.events.find(e => e.type === 'finding-kev-status-changed')?.to, true);
  assert.equal(assess(kevIndex(catalog())).update.events.length, 0);
  const stale = [{ id: entry.cveID }];
  enrichKevFindings(stale, kevIndex(null, 'unavailable'), confirmed.result.vulnerabilities);
  assert.equal(stale[0].knownExploited, true);
  assert.equal(stale[0].kev.entries[0].dateAdded, entry.dateAdded);
  assert.equal(reconcileFindingWorkflows(store, [{ id: 'app', vulnerabilities: stale }]).events.filter(e => e.type === 'finding-kev-status-changed').length, 0);
  assert.equal(assess(kevIndex(normalizeKevCatalog({ vulnerabilities: [] }))).update.events.find(e => e.type === 'finding-kev-status-changed')?.to, false);
});

test('KEV display escapes actions, labels CISA deadlines separately and explains stale evidence', async () => {
  const source = await readFile('src/web/app.js', 'utf8');
  const context = vm.createContext({ URL, Date });
  vm.runInContext(source.slice(source.indexOf('const escape ='), source.indexOf('const ticketReferenceMarkup')), context);
  const finding = { knownExploited: true, kev: { state: 'stale', entries: [{ ...entry, requiredAction: '<img src=x onerror=alert(1)>' }], sourceUrl: 'javascript:alert(1)' } };
  const markup = context.kevMarkup(finding);
  assert.match(markup, /Stale catalog/);
  assert.match(markup, /CISA remediation due date/);
  assert.match(markup, /&lt;img/);
  assert.doesNotMatch(markup, /<img|href="javascript:/);
});
