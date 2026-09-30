import test from 'node:test';
import assert from 'node:assert/strict';
import { appendFindingEvents, readFindingEvents, reconcileFindingWorkflows, updateFindingWorkflow, validateFindingUpdate } from '../src/findings.mjs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const result = (description = 'Original evidence') => [{ id: '11111111-1111-4111-8111-111111111111', vulnerabilities: [{ id: 'CVE-2026-1234', score: 9.8, severity: 'CRITICAL', description, url: 'https://example.com/CVE-2026-1234', advisories: [] }] }];

test('finding workflows persist decisions and attributable changes', () => {
  const store = { version: 1, records: {} };
  const first = result();
  const discovered = reconcileFindingWorkflows(store, first, { issuer: 'scanner', name: 'Scanner' }, new Date('2026-01-01T00:00:00Z'));
  assert.equal(discovered.events[0].type, 'finding-discovered');
  assert.equal(first[0].vulnerabilities[0].workflow.state, 'new');
  const actor = { issuer: 'https://login.example', username: 'analyst@example.com', name: 'Analyst' };
  const updated = updateFindingWorkflow(store, first[0].id, 'CVE-2026-1234', { state: 'risk-accepted', assignee: 'Security', dueDate: '2026-06-01', ticketReference: 'INC0001234', notes: 'Compensating control', riskExpiration: '2026-05-01' }, actor, new Date('2026-01-02T00:00:00Z'));
  assert.equal(updated.record.state, 'risk-accepted');
  assert.equal(updated.event.actor.username, 'analyst@example.com');
  assert.deepEqual(updated.changes.state, { from: 'new', to: 'risk-accepted' });
  assert.equal(updated.record.ticketReference, 'INC0001234');
});

test('expired risk acceptance and material evidence changes reopen dispositions', () => {
  const store = { version: 1, records: {} };
  reconcileFindingWorkflows(store, result(), undefined, new Date('2026-01-01T00:00:00Z'));
  const appId = '11111111-1111-4111-8111-111111111111';
  updateFindingWorkflow(store, appId, 'CVE-2026-1234', { state: 'risk-accepted', riskExpiration: '2026-01-05' }, {}, new Date('2026-01-02T00:00:00Z'));
  const expired = result();
  const expiration = reconcileFindingWorkflows(store, expired, undefined, new Date('2026-01-06T00:00:00Z'));
  assert.equal(expired[0].vulnerabilities[0].workflow.state, 'new');
  assert.equal(expiration.events[0].reason, 'Risk acceptance expired');
  updateFindingWorkflow(store, appId, 'CVE-2026-1234', { state: 'resolved' }, {}, new Date('2026-01-07T00:00:00Z'));
  const changed = result('Changed evidence');
  changed[0].vulnerabilities[0].score = 10;
  const evidence = reconcileFindingWorkflows(store, changed, undefined, new Date('2026-01-08T00:00:00Z'));
  assert.equal(changed[0].vulnerabilities[0].workflow.state, 'new');
  assert.equal(evidence.events[0].reason, 'Finding evidence changed');
});

test('description-only evidence changes do not reopen dispositions', () => {
  const store = { version: 1, records: {} };
  reconcileFindingWorkflows(store, result(), undefined, new Date('2026-01-01T00:00:00Z'));
  updateFindingWorkflow(store, result()[0].id, 'CVE-2026-1234', { state: 'resolved' }, {}, new Date('2026-01-02T00:00:00Z'));
  const refreshed = result('Reworded description from the same source');
  const reconciliation = reconcileFindingWorkflows(store, refreshed, undefined, new Date('2026-01-03T00:00:00Z'));
  assert.equal(refreshed[0].vulnerabilities[0].workflow.state, 'resolved');
  assert.equal(reconciliation.events.length, 0);
});

test('finding history is returned newest first and scoped to the finding', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-finding-history-'));
  const file = path.join(directory, 'history.jsonl');
  try {
    await appendFindingEvents(file, [
      { at: '2026-01-01T00:00:00Z', applicationId: 'app-1', findingId: 'CVE-1', type: 'finding-discovered' },
      { at: '2026-01-02T00:00:00Z', applicationId: 'app-1', findingId: 'CVE-2', type: 'finding-discovered' },
      { at: '2026-01-03T00:00:00Z', applicationId: 'app-1', findingId: 'CVE-1', type: 'finding-workflow-updated' },
    ]);
    const history = await readFindingEvents(file, 'app-1', 'CVE-1');
    assert.deepEqual(history.map(event => event.at), ['2026-01-03T00:00:00Z', '2026-01-01T00:00:00Z']);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('finding workflow input validates state, dates, and risk expiration scope', () => {
  assert.throws(() => validateFindingUpdate({ state: 'closed' }), /valid finding state/);
  assert.throws(() => validateFindingUpdate({ state: 'resolved', riskExpiration: '2027-01-01' }), /only valid/);
  assert.throws(() => validateFindingUpdate({ state: 'investigating', dueDate: 'tomorrow' }), /YYYY-MM-DD/);
  assert.equal(validateFindingUpdate({ state: 'investigating', ticketReference: 'Remedy INC0001234' }).ticketReference, 'Remedy INC0001234');
  assert.equal(validateFindingUpdate({ state: 'investigating', ticketReference: 'https://tickets.example.com/SEC-123' }).ticketReference, 'https://tickets.example.com/SEC-123');
  assert.throws(() => validateFindingUpdate({ state: 'investigating', ticketReference: 'http://tickets.example.com/SEC-123' }), /valid HTTPS URL/);
  assert.throws(() => validateFindingUpdate({ state: 'investigating', ticketReference: 'https://user:secret@tickets.example.com/SEC-123' }), /without credentials/);
});
