import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

export const findingStates = Object.freeze(['new', 'investigating', 'remediation-planned', 'mitigated', 'resolved', 'risk-accepted', 'not-affected', 'false-positive']);
export const findingStateLabels = Object.freeze({ new: 'New', investigating: 'Investigating', 'remediation-planned': 'Remediation planned', mitigated: 'Mitigated', resolved: 'Resolved', 'risk-accepted': 'Risk accepted', 'not-affected': 'Not affected', 'false-positive': 'False positive' });
const dispositions = new Set(['mitigated', 'resolved', 'risk-accepted', 'not-affected', 'false-positive']);
const datePattern = /^\d{4}-\d{2}-\d{2}$/;
const oneLine = (value, name, limit) => {
  const text = String(value || '').trim();
  if (text.length > limit || /[\r\n]/.test(text)) throw new Error(`${name} must be one line with at most ${limit} characters`);
  return text;
};
const date = (value, name) => {
  const text = String(value || '').trim();
  if (text && (!datePattern.test(text) || !Number.isFinite(Date.parse(`${text}T00:00:00Z`)))) throw new Error(`${name} must be YYYY-MM-DD`);
  return text;
};
const httpsUrl = value => {
  const text = String(value || '').trim();
  if (!text) return '';
  if (text.length > 2048) throw new Error('Ticket URL must be at most 2048 characters');
  try {
    const parsed = new URL(text);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) throw new Error();
    return parsed.href;
  } catch { throw new Error('Ticket URL must be a valid HTTPS URL without credentials'); }
};
export const findingKey = (applicationId, findingId) => `${applicationId}:${findingId}`;
export function evidenceFingerprint(finding) {
  const evidence = { id: finding.id, score: Number(finding.score) || 0, severity: finding.severity || finding.label || '', knownExploited: Boolean(finding.knownExploited), url: finding.url || '', advisories: [...(finding.advisories || [])].sort() };
  return createHash('sha256').update(JSON.stringify(evidence)).digest('hex');
}
export function validateFindingUpdate(input = {}) {
  const state = String(input.state || '').trim();
  if (!findingStates.includes(state)) throw new Error('Select a valid finding state');
  const notes = String(input.notes || '').trim();
  if (notes.length > 4000) throw new Error('Finding notes must be at most 4000 characters');
  const riskExpiration = date(input.riskExpiration, 'Risk-acceptance expiration');
  if (riskExpiration && state !== 'risk-accepted') throw new Error('Risk-acceptance expiration is only valid for Risk accepted findings');
  return { state, assignee: oneLine(input.assignee, 'Assignee', 120), dueDate: date(input.dueDate, 'Due date'), ticketUrl: httpsUrl(input.ticketUrl), notes, riskExpiration };
}
export async function readFindingStore(file) {
  try {
    const parsed = JSON.parse(await readFile(file, 'utf8'));
    return { version: 1, records: parsed?.records && typeof parsed.records === 'object' ? parsed.records : {} };
  } catch (error) { if (error.code === 'ENOENT') return { version: 1, records: {} }; throw error; }
}
export async function writeFindingStore(file, store) {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp`;
  await writeFile(temporary, `${JSON.stringify(store, null, 2)}\n`, 'utf8');
  await rename(temporary, file);
}
export async function appendFindingEvents(file, events) {
  if (!events.length) return;
  await mkdir(path.dirname(file), { recursive: true });
  await appendFile(file, events.map(event => `${JSON.stringify(event)}\n`).join(''), 'utf8');
}
export async function readFindingEvents(file, applicationId, findingId, limit = 50) {
  try {
    const lines = (await readFile(file, 'utf8')).trim().split('\n').filter(Boolean);
    const events = [];
    for (let index = lines.length - 1; index >= 0 && events.length < limit; index--) {
      try {
        const event = JSON.parse(lines[index]);
        if (event.applicationId === applicationId && event.findingId === findingId) events.push(event);
      } catch {}
    }
    return events;
  } catch (error) { if (error.code === 'ENOENT') return []; throw error; }
}
function publicWorkflow(record) {
  return { state: record.state, stateLabel: findingStateLabels[record.state], assignee: record.assignee, dueDate: record.dueDate, ticketUrl: record.ticketUrl || '', notes: record.notes, riskExpiration: record.riskExpiration, discoveredAt: record.discoveredAt, updatedAt: record.updatedAt, updatedBy: record.updatedBy, reopenedAt: record.reopenedAt || '', reopenedReason: record.reopenedReason || '' };
}
export function reconcileFindingWorkflows(store, results, actor = { issuer: 'scanner', name: 'Automated assessment' }, now = new Date()) {
  const at = now.toISOString();
  const today = at.slice(0, 10);
  const events = [];
  let changed = false;
  for (const application of results) for (const finding of application.vulnerabilities || []) {
    const key = findingKey(application.id, finding.id);
    const fingerprint = evidenceFingerprint(finding);
    let record = store.records[key];
    if (!record) {
      record = store.records[key] = { applicationId: application.id, findingId: finding.id, state: 'new', assignee: '', dueDate: '', ticketUrl: '', notes: '', riskExpiration: '', discoveredAt: at, updatedAt: at, updatedBy: actor, evidenceFingerprint: fingerprint };
      events.push({ at, type: 'finding-discovered', applicationId: application.id, findingId: finding.id, actor, state: 'new' });
      changed = true;
    } else {
      const evidenceChanged = Boolean(record.evidenceFingerprint && record.evidenceFingerprint !== fingerprint);
      const expired = record.state === 'risk-accepted' && record.riskExpiration && record.riskExpiration < today;
      if ((evidenceChanged && dispositions.has(record.state)) || expired) {
        const from = record.state;
        record.state = 'new';
        record.riskExpiration = '';
        record.reopenedAt = at;
        record.reopenedReason = expired ? 'Risk acceptance expired' : 'Finding evidence changed';
        record.updatedAt = at;
        record.updatedBy = actor;
        events.push({ at, type: 'finding-reopened', applicationId: application.id, findingId: finding.id, actor, from, to: 'new', reason: record.reopenedReason });
        changed = true;
      }
      if (record.evidenceFingerprint !== fingerprint) { record.evidenceFingerprint = fingerprint; changed = true; }
    }
    finding.workflow = publicWorkflow(record);
  }
  return { changed, events };
}
export function updateFindingWorkflow(store, applicationId, findingId, input, actor, now = new Date()) {
  const key = findingKey(applicationId, findingId);
  const previous = store.records[key];
  if (!previous) throw new Error('Finding workflow is unavailable until the finding has been assessed');
  const update = validateFindingUpdate(input);
  const at = now.toISOString();
  const changes = Object.fromEntries(Object.keys(update).filter(field => previous[field] !== update[field]).map(field => [field, { from: previous[field] || '', to: update[field] || '' }]));
  if (!Object.keys(changes).length) return { record: publicWorkflow(previous), event: null, changes };
  Object.assign(previous, update, { updatedAt: at, updatedBy: actor, reopenedAt: '', reopenedReason: '' });
  return { record: publicWorkflow(previous), changes, event: { at, type: 'finding-workflow-updated', applicationId, findingId, actor, changes, state: previous.state } };
}
