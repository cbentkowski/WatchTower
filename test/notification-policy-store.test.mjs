import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ensureNotificationPolicies, previewNotificationPolicy, readNotificationPolicies, validateNotificationPolicies, validateNotificationPolicy, writeNotificationPolicies } from '../src/notification-policy-store.mjs';

const resources = { workspaces: [{ id: 'workspace-1', name: 'Operations' }], owners: [{ id: 'owner-1', name: 'Security' }] };

test('missing policy configuration migrates to persisted equivalent defaults', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-policies-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'notification-policies.json');
  const policies = await ensureNotificationPolicies(file);
  assert.deepEqual(policies.map(policy => policy.name), ['High and Critical findings', 'Known-exploited findings']);
  assert.deepEqual((JSON.parse(await readFile(file, 'utf8'))).policies, policies);
});

test('policies validate, persist, and reload deterministically', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-policies-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'notification-policies.json');
  const policies = validateNotificationPolicies([{ id: 'production-critical', name: 'Production critical', enabled: true, conditions: { severities: ['critical'], environments: ['production'], workspaceIds: ['workspace-1'], ownerIds: ['owner-1'], minimumAgeDays: 2 } }], resources);
  await writeNotificationPolicies(file, policies);
  assert.deepEqual(await readNotificationPolicies(file), policies);
});

test('empty multi-select values mean any and are omitted from stored conditions', () => {
  const policy = validateNotificationPolicy({ name: 'Critical in any environment', conditions: { severities: ['critical'], environments: [], workspaceIds: [], ownerIds: [] } }, resources);
  assert.deepEqual(policy.conditions, { severities: ['critical'] });
});

test('policy validation rejects empty, duplicate, invalid-resource, and inverted age conditions', () => {
  assert.throws(() => validateNotificationPolicy({ name: 'Empty', conditions: {} }), /at least one/);
  assert.throws(() => validateNotificationPolicy({ name: 'Missing workspace', conditions: { workspaceIds: ['missing'] } }, resources), /valid workspaces/);
  assert.throws(() => validateNotificationPolicy({ name: 'Age', conditions: { minimumAgeDays: 10, maximumAgeDays: 2 } }), /Minimum age/);
  assert.throws(() => validateNotificationPolicies([{ id: 'one', name: 'Same', conditions: { knownExploited: true } }, { id: 'two', name: 'same', conditions: { severities: ['high'] } }]), /names must be unique/);
});

test('policy preview returns human-readable matches and explanations without saving', () => {
  const policy = validateNotificationPolicy({ id: 'production-critical', name: 'Production critical', conditions: { severities: ['critical'], environments: ['production'] } });
  const preview = previewNotificationPolicy(policy, {
    workspaces: [{ id: 'workspace-1', name: 'Operations', applications: ['app-1'] }],
    results: [{ id: 'app-1', name: 'Payments', environment: 'production', vulnerabilities: [{ id: 'CVE-2026-1234', score: 9.8 }] }],
  });
  assert.equal(preview.evaluatedFindings, 1);
  assert.deepEqual(preview.matches.map(({ workspace, application, finding }) => ({ workspace, application, finding })), [{ workspace: 'Operations', application: 'Payments', finding: 'CVE-2026-1234' }]);
  assert.ok(preview.matches[0].explanation.every(item => item.matched));
});
