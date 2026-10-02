import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { defaultNotificationPolicies, evaluatePolicies } from './notification-policies.mjs';
import { findingStates } from './findings.mjs';

export const notificationPolicyOptions = Object.freeze({
  severities: Object.freeze(['critical', 'high', 'medium', 'low', 'none', 'unknown']),
  criticalities: Object.freeze(['critical', 'high', 'medium', 'low', 'unspecified']),
  environments: Object.freeze(['production', 'staging', 'development', 'test', 'disaster-recovery', 'unspecified']),
  exposures: Object.freeze(['internet', 'external', 'internal', 'unknown']),
  findingStates,
});

const listFields = ['severities', 'criticalities', 'environments', 'exposures', 'workspaceIds', 'ownerIds', 'findingStates'];
const allowedConditions = new Set([...listFields, 'knownExploited', 'minimumAgeDays', 'maximumAgeDays']);
const deliveryCadences = new Set(['adaptive', 'immediate', 'daily', 'weekly']);
const oneLine = (value, label, limit = 120) => {
  const text = String(value || '').trim();
  if (!text) throw new Error(`${label} is required`);
  if (text.length > limit || /[\r\n]/.test(text)) throw new Error(`${label} must be one line with at most ${limit} characters`);
  return text;
};
const uniqueStrings = value => [...new Set((Array.isArray(value) ? value : []).map(item => String(item).trim()).filter(Boolean))].sort();
const optionalHour = (value, label) => {
  if (value === '' || value === undefined || value === null) return null;
  const hour = Number(value);
  if (!Number.isInteger(hour) || hour < 0 || hour > 23) throw new Error(`${label} must be a whole hour from 0 to 23`);
  return hour;
};

function validateDelivery(input = {}, resources = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Policy delivery settings must be an object');
  const cadence = String(input.cadence || 'adaptive');
  if (!deliveryCadences.has(cadence)) throw new Error('Select a valid delivery cadence');
  const reminderDays = input.reminderDays === '' || input.reminderDays === undefined || input.reminderDays === null ? 7 : Number(input.reminderDays);
  if (!Number.isInteger(reminderDays) || reminderDays < 1 || reminderDays > 365) throw new Error('Reminder interval must be from 1 to 365 days');
  const weeklyDay = input.weeklyDay === '' || input.weeklyDay === undefined || input.weeklyDay === null ? 1 : Number(input.weeklyDay);
  if (!Number.isInteger(weeklyDay) || weeklyDay < 0 || weeklyDay > 6) throw new Error('Select a valid weekly delivery day');
  const escalationAfterDays = input.escalationAfterDays === '' || input.escalationAfterDays === undefined || input.escalationAfterDays === null ? null : Number(input.escalationAfterDays);
  if (escalationAfterDays !== null && (!Number.isInteger(escalationAfterDays) || escalationAfterDays < 1 || escalationAfterDays > 365)) throw new Error('Escalation age must be from 1 to 365 days');
  const recipientOwnerIds = uniqueStrings(input.recipientOwnerIds);
  if (resources.owners && recipientOwnerIds.some(value => !resources.owners.some(item => item.id === value))) throw new Error('Select valid delivery owners');
  const workspaceRecipients = input.workspaceRecipients !== false;
  if (!workspaceRecipients && !recipientOwnerIds.length) throw new Error('Select workspace recipients or at least one delivery owner');
  if (input.includeEscalationContacts === true && escalationAfterDays === null) throw new Error('Enter an escalation age when escalation contacts are enabled');
  return {
    cadence,
    sendHour: optionalHour(input.sendHour, 'Delivery hour'),
    weeklyDay,
    windowStartHour: optionalHour(input.windowStartHour ?? 0, 'Delivery window start'),
    windowEndHour: optionalHour(input.windowEndHour ?? 23, 'Delivery window end'),
    reminderDays,
    workspaceRecipients,
    recipientOwnerIds,
    includeEscalationContacts: input.includeEscalationContacts === true,
    escalationAfterDays,
  };
}

export function validateNotificationPolicy(input, resources = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Notification policy details are required');
  const id = input.id ? oneLine(input.id, 'Policy ID', 120) : randomUUID();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(id)) throw new Error('Policy ID contains unsupported characters');
  const conditions = input.conditions && typeof input.conditions === 'object' && !Array.isArray(input.conditions) ? input.conditions : {};
  const unknown = Object.keys(conditions).filter(name => !allowedConditions.has(name)).sort();
  if (unknown.length) throw new Error(`Unsupported notification policy condition: ${unknown.join(', ')}`);
  const normalized = {};
  for (const field of listFields) {
    const selected = uniqueStrings(conditions[field]);
    if (!selected.length) continue;
    const allowed = notificationPolicyOptions[field];
    if (allowed && selected.some(value => !allowed.includes(value))) throw new Error(`Select valid ${field}`);
    const resourceValues = field === 'workspaceIds' ? resources.workspaces : field === 'ownerIds' ? resources.owners : null;
    if (resourceValues && selected.some(value => !resourceValues.some(item => item.id === value))) throw new Error(`Select valid ${field === 'workspaceIds' ? 'workspaces' : 'owners'}`);
    normalized[field] = selected;
  }
  if (conditions.knownExploited === true || conditions.knownExploited === false) normalized.knownExploited = conditions.knownExploited;
  for (const field of ['minimumAgeDays', 'maximumAgeDays']) {
    if (conditions[field] === '' || conditions[field] === undefined || conditions[field] === null) continue;
    const value = Number(conditions[field]);
    if (!Number.isInteger(value) || value < 0 || value > 36_500) throw new Error(`${field === 'minimumAgeDays' ? 'Minimum' : 'Maximum'} age must be a whole number from 0 to 36500 days`);
    normalized[field] = value;
  }
  if (normalized.minimumAgeDays !== undefined && normalized.maximumAgeDays !== undefined && normalized.minimumAgeDays > normalized.maximumAgeDays) throw new Error('Minimum age cannot exceed maximum age');
  if (!Object.keys(normalized).length) throw new Error('Select at least one policy condition');
  return { id, name: oneLine(input.name, 'Policy name'), enabled: input.enabled !== false, conditions: normalized, delivery: validateDelivery(input.delivery, resources) };
}

export function validateNotificationPolicies(input, resources = {}) {
  if (!Array.isArray(input)) throw new Error('Notification policies must be a list');
  const policies = input.map(policy => validateNotificationPolicy(policy, resources));
  if (new Set(policies.map(policy => policy.id)).size !== policies.length) throw new Error('Policy IDs must be unique');
  if (new Set(policies.map(policy => policy.name.toLowerCase())).size !== policies.length) throw new Error('Policy names must be unique');
  return policies;
}

export async function readNotificationPolicies(file) {
  try {
    const parsed = JSON.parse(await readFile(file, 'utf8'));
    return validateNotificationPolicies(parsed?.policies || parsed);
  } catch (error) {
    if (error.code === 'ENOENT') return structuredClone(defaultNotificationPolicies);
    throw error;
  }
}

export async function writeNotificationPolicies(file, policies) {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp`;
  await writeFile(temporary, `${JSON.stringify({ version: 1, policies }, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, file);
  return policies;
}

export async function ensureNotificationPolicies(file) {
  try { await readFile(file); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await writeNotificationPolicies(file, validateNotificationPolicies(structuredClone(defaultNotificationPolicies)));
  }
  return readNotificationPolicies(file);
}

export function previewNotificationPolicy(policy, snapshot, now = new Date()) {
  const matches = [];
  const routes = new Map();
  const ownerById = new Map((snapshot?.owners || []).map(owner => [owner.id, owner]));
  let evaluatedFindings = 0;
  for (const workspace of snapshot?.workspaces || []) {
    for (const application of (snapshot?.results || []).filter(item => workspace.applications.includes(item.id))) {
      for (const finding of application.vulnerabilities || []) {
        evaluatedFindings++;
        const result = evaluatePolicies([policy], { finding, application, workspace }, now)[0];
        if (result?.matched) {
          matches.push({ workspace: workspace.name, application: application.name, finding: finding.id || 'Unknown finding', explanation: result.explanation });
          const ownerIds = [...new Set([...(policy.delivery.workspaceRecipients ? workspace.ownerIds || [] : []), ...policy.delivery.recipientOwnerIds])];
          const recipients = ownerIds.map(id => ownerById.get(id)).filter(Boolean);
          routes.set(workspace.id, { workspace: workspace.name, recipients: recipients.map(owner => ({ name: owner.name, email: owner.email })), escalationRecipients: policy.delivery.includeEscalationContacts ? recipients.filter(owner => owner.escalationEmail).map(owner => ({ name: owner.name, email: owner.escalationEmail })) : [] });
        }
      }
    }
  }
  return { evaluatedFindings, matches, delivery: policy.delivery, routes: [...routes.values()] };
}
