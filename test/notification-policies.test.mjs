import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePolicies, evaluatePolicy, findingAgeDays } from '../src/notification-policies.mjs';

const context = {
  finding: { id: 'CVE-2026-1234', score: 9.8, knownExploited: true, workflow: { state: 'investigating', discoveredAt: '2026-09-20T15:30:00.000Z' } },
  application: { id: 'app-1', criticality: 'critical', environment: 'production', exposure: 'internet', ownerIds: ['application-owner'] },
  workspace: { id: 'workspace-1', ownerIds: ['workspace-owner'] },
};

test('conditions use AND semantics and return an explanation in stable order', () => {
  const result = evaluatePolicy({
    id: 'internet-critical',
    name: 'Internet-facing critical findings',
    conditions: {
      ownerIds: ['workspace-owner'],
      workspaceIds: ['workspace-1'],
      severities: ['critical'],
      knownExploited: true,
      criticalities: ['critical'],
      environments: ['production'],
      exposures: ['internet'],
      findingStates: ['new', 'investigating'],
      minimumAgeDays: 5,
      maximumAgeDays: 30,
    },
  }, context, new Date('2026-09-30T01:00:00.000Z'));

  assert.equal(result.matched, true);
  assert.deepEqual(result.explanation.map(item => item.condition), [
    'severities', 'knownExploited', 'criticalities', 'environments', 'exposures',
    'workspaceIds', 'ownerIds', 'findingStates', 'minimumAgeDays', 'maximumAgeDays',
  ]);
  assert.ok(result.explanation.every(item => item.matched));
});

test('one failed condition prevents a policy match and identifies why', () => {
  const result = evaluatePolicy({
    id: 'internal-only',
    name: 'Internal findings',
    conditions: { severities: ['critical'], environments: ['production'], exposures: ['internal'] },
  }, context);

  assert.equal(result.matched, false);
  assert.deepEqual(result.explanation.find(item => !item.matched), {
    condition: 'exposures', expected: ['internal'], actual: 'internet', matched: false,
  });
});

test('multiple enabled policies match independently', () => {
  const results = evaluatePolicies([
    { id: 'critical', name: 'Critical', conditions: { severities: ['critical'] } },
    { id: 'kev', name: 'Known exploited', conditions: { knownExploited: true } },
    { id: 'disabled', name: 'Disabled', enabled: false, conditions: {} },
    { id: 'development', name: 'Development', conditions: { environments: ['development'] } },
  ], context);

  assert.deepEqual(results.map(result => [result.policyId, result.matched]), [
    ['critical', true], ['kev', true], ['development', false],
  ]);
});

test('finding age is measured in whole UTC calendar days', () => {
  assert.equal(findingAgeDays(context.finding, new Date('2026-09-30T01:00:00.000Z')), 10);
  assert.equal(findingAgeDays({ workflow: {} }), null);
});

test('unknown conditions are rejected instead of silently ignored', () => {
  assert.throws(
    () => evaluatePolicy({ id: 'typo', conditions: { severty: ['critical'] } }, context),
    /Unsupported notification policy condition: severty/,
  );
});
