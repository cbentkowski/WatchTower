const conditionOrder = Object.freeze([
  'severities',
  'knownExploited',
  'criticalities',
  'environments',
  'exposures',
  'workspaceIds',
  'ownerIds',
  'findingStates',
  'minimumAgeDays',
  'maximumAgeDays',
]);

export const defaultNotificationPolicies = Object.freeze([
  Object.freeze({
    id: 'default-high-severity',
    name: 'High and Critical findings',
    enabled: true,
    conditions: Object.freeze({ severities: Object.freeze(['high', 'critical']) }),
  }),
  Object.freeze({
    id: 'default-known-exploited',
    name: 'Known-exploited findings',
    enabled: true,
    conditions: Object.freeze({ knownExploited: true }),
  }),
]);

const severityFor = finding => {
  const supplied = String(finding.severity || finding.label || '').trim().toLowerCase();
  if (supplied) return supplied;
  const score = Number(finding.score);
  if (!Number.isFinite(score)) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'none';
};

const values = value => [...new Set((Array.isArray(value) ? value : [value]).map(item => String(item).trim()).filter(Boolean))].sort();
const intersects = (left, right) => left.some(value => right.includes(value));
const dayNumber = value => {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? Math.floor(parsed / 86_400_000) : null;
};

export function findingAgeDays(finding, now = new Date()) {
  const discovered = dayNumber(finding.workflow?.discoveredAt);
  const today = dayNumber(now);
  return discovered === null || today === null ? null : Math.max(0, today - discovered);
}

export function evaluatePolicy(policy, { finding, application, workspace }, now = new Date()) {
  const conditions = policy?.conditions || {};
  const unknown = Object.keys(conditions).filter(name => !conditionOrder.includes(name)).sort();
  if (unknown.length) throw new Error(`Unsupported notification policy condition: ${unknown.join(', ')}`);

  const ownerIds = values([...(application.ownerIds || []), ...(workspace.ownerIds || [])]);
  const actual = {
    severities: severityFor(finding),
    knownExploited: Boolean(finding.knownExploited),
    criticalities: String(application.criticality || 'unspecified'),
    environments: String(application.environment || 'unspecified'),
    exposures: String(application.exposure || 'unknown'),
    workspaceIds: String(workspace.id || ''),
    ownerIds,
    findingStates: String(finding.workflow?.state || 'new'),
    minimumAgeDays: findingAgeDays(finding, now),
    maximumAgeDays: findingAgeDays(finding, now),
  };

  const explanation = [];
  for (const name of conditionOrder) {
    if (!Object.hasOwn(conditions, name)) continue;
    const expected = conditions[name];
    let matched;
    if (name === 'knownExploited') matched = actual[name] === Boolean(expected);
    else if (name === 'minimumAgeDays') matched = actual[name] !== null && actual[name] >= Number(expected);
    else if (name === 'maximumAgeDays') matched = actual[name] !== null && actual[name] <= Number(expected);
    else if (name === 'ownerIds') matched = intersects(values(expected), actual[name]);
    else matched = values(expected).includes(actual[name]);
    explanation.push({ condition: name, expected, actual: actual[name], matched });
  }

  return {
    policyId: String(policy?.id || ''),
    policyName: String(policy?.name || ''),
    matched: explanation.every(item => item.matched),
    explanation,
  };
}

export function evaluatePolicies(policies, context, now = new Date()) {
  return policies.filter(policy => policy.enabled !== false).map(policy => evaluatePolicy(policy, context, now));
}

export function matchingPolicies(policies, context, now = new Date()) {
  return evaluatePolicies(policies, context, now).filter(result => result.matched);
}
