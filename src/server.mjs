import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile, writeFile, rename, mkdir, rm, access, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import path from 'node:path';
import { createNotifier, sendTestEmail } from './notifications.mjs';
import { readSmtpSettings, smtpPasswordState, writeSmtpSettings, validateSmtpSettings } from './settings.mjs';
import { readGeneralSettings, writeGeneralSettings, validateGeneralSettings, generalUrl } from './general.mjs';
import { createLogger, logTypes } from './logger.mjs';
import { administratorRole, createAuth } from './auth.mjs';
import { createYamlMonitor } from './yaml-monitor.mjs';
import { readRbac, writeRbac, validateRbacInput, calculateAccess, accessJson, canCreateOwner, canDeleteApplication, claimsForIdentityMappings, describeIdentityClaims, explainAccess, protectedRoleState, standardRoles, canRefreshApplication } from './rbac.mjs';
import { collectFeeds, eventAffectsVersion, feedRequestUrl, normalizeEntries, readFeeds, secureFetchText, serializeFeeds, validateFeedInput, writeFeeds } from './feeds.mjs';
import { readOwners, validateOwner, writeOwners } from './owners.mjs';
import { cveAffectsApplication, wildcardApplicationCpe } from './nvd.mjs';
import { loadTlsConfiguration } from './tls.mjs';
import { cpeSearchMatch, effectiveCpe, legacyCpe, mappingFromApp, mappingWarnings, parseCpe23, productCpe } from './cpe.mjs';
import { matchLifecycleRelease, normalizeLifecycleProduct, searchLifecycleProducts } from './lifecycle.mjs';
import { appendFindingEvents, readFindingEvents, readFindingStore, reconcileFindingWorkflows, updateFindingWorkflow, writeFindingStore } from './findings.mjs';
import { ensureNotificationPolicies, notificationPolicyOptions, previewNotificationPolicy, readNotificationPolicies, validateNotificationPolicies, validateNotificationPolicy, writeNotificationPolicies } from './notification-policy-store.mjs';
import { createInventoryStore } from './inventory-store.mjs';
import { sbomLimits } from './sbom.mjs';
import { createOsvClient } from './osv.mjs';
import { assessApplicationInventory } from './package-assessment.mjs';
import { replacementDemo } from './sbom-demo.mjs';

const sourceDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectDirectory = path.dirname(sourceDirectory);
const applicationVersion = JSON.parse(await readFile(path.join(projectDirectory, 'package.json'), 'utf8')).version;
const configDirectory = process.env.CONFIG_DIR || path.join(projectDirectory, 'config');
const defaultConfigDirectory = process.env.DEFAULT_CONFIG_DIR || path.join(projectDirectory, 'defaults');
const PORT = Number(process.env.SERVER_PORT || process.env.PORT || 4173);
const HOST = process.env.HOST || '127.0.0.1';
const tlsConfiguration = await loadTlsConfiguration();
const dataDirectory = process.env.DATA_DIR || path.join(projectDirectory, 'data');
const inventoryStore = createInventoryStore(path.join(dataDirectory, 'inventories'));
const osvClient = createOsvClient();
const sbomMaxAgeDays = Number(process.env.SBOM_MAX_AGE_DAYS || 30);
if (!Number.isInteger(sbomMaxAgeDays) || sbomMaxAgeDays < 1 || sbomMaxAgeDays > 3650) throw new Error('SBOM_MAX_AGE_DAYS must be an integer from 1 to 3650');
const configFiles = ['applications.yaml', 'workspaces.yaml', 'feeds.yaml', 'owners.yaml', 'smtp.yaml', 'general.yaml'];
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exists = file => access(file).then(() => true, () => false);
async function ensureConfiguration() {
  await mkdir(configDirectory, { recursive: true });
  for (const name of configFiles) {
    const destination = path.join(configDirectory, name);
    if (await exists(destination)) continue;
    const legacy = path.join(path.dirname(configDirectory), name);
    if (legacy !== destination && await exists(legacy)) await rename(legacy, destination);
    else {
      const bundledDefault = path.join(defaultConfigDirectory, name);
      if (await exists(bundledDefault)) await copyFile(bundledDefault, destination);
    }
  }
}
await ensureConfiguration();
const rbacFile = path.join(configDirectory, 'rbac.yaml');
const feedFile = path.join(configDirectory, 'feeds.yaml');
const ownerFile = path.join(configDirectory, 'owners.yaml');
if (!await exists(rbacFile)) await writeRbac(rbacFile, { groups: [], grants: [] });
const resourceMigration = await migrateResourceIds();
const logger = createLogger(dataDirectory);
const auth = createAuth(undefined, undefined, recordAuthenticationEvent);
if (!auth && process.env.AUTH_DISABLED !== 'true') throw new Error('OIDC is required. Configure OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_BASE_URL, and either OIDC_CLIENT_SECRET or OIDC_CLIENT_SECRET_FILE, or set AUTH_DISABLED=true for a private development instance.');
const snapshotFile = path.join(dataDirectory, 'status.json');
const feedCacheFile = path.join(dataDirectory, 'feeds.json');
const smtpFile = path.join(configDirectory, 'smtp.yaml');
const generalFile = path.join(configDirectory, 'general.yaml');
const notificationPolicyFile = path.join(configDirectory, 'notification-policies.json');
const findingStoreFile = path.join(dataDirectory, 'finding-workflows.json');
const findingHistoryFile = path.join(dataDirectory, 'finding-history.jsonl');
await ensureNotificationPolicies(notificationPolicyFile);

async function recordAuthenticationEvent(action, actor, context = {}) {
  const { claims = {}, protectedAdminClaim = '', ...event } = context;
  let config = { groups: [], grants: [] };
  try { config = await readRbac(rbacFile); }
  catch (error) { logger.log('error', 'Authentication claims could not be matched to access control', error.message); }
  await logger.authentication(action, actor, {
    ...event,
    ...describeIdentityClaims(config, claims, { administratorRole, protectedAdminClaim }),
  });
}
const notifier = createNotifier({ dataDirectory, settingsLoader: async () => ({ ...await readSmtpSettings(smtpFile), baseUrl: generalUrl(await readGeneralSettings(generalFile)) }), policyLoader: () => readNotificationPolicies(notificationPolicyFile), deliveryLogger: entry => logger.notification(entry) });
for (const [from, to] of resourceMigration.applications) await notifier.renameIdentifiers({ appFrom: from, appTo: to });
for (const [from, to] of resourceMigration.workspaces) await notifier.renameIdentifiers({ workspaceFrom: from, workspaceTo: to });
function detectedGeneral(req) {
  const hostHeader = String(req.headers['x-forwarded-host'] || req.headers.host || `${HOST}:${PORT}`).split(',')[0].trim();
  const forwardedProtocol = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  const protocol = forwardedProtocol === 'https' || req.socket.encrypted ? 'https' : 'http';
  try {
    const address = new URL(`${protocol}://${hostHeader}`);
    return { protocol, host: address.hostname, port: Number(address.port) || (protocol === 'https' ? 443 : 80) };
  } catch { return { protocol: 'http', host: HOST, port: PORT }; }
}
const refreshMs = 60 * 60 * 1000;
const intervalMinutes = Number(process.env.SCAN_INTERVAL_MINUTES || 60);
const scanIntervalMs = Number.isFinite(intervalMinutes) && intervalMinutes > 0 ? intervalMinutes * 60_000 : refreshMs;
let snapshot = null;
let refreshPromise = null;
let nvdLastRequest = 0;
let lifecycleCatalogCache = null;
const permissionPreviews = new Map();
const previewLifetime = 8 * 60 * 60 * 1000;
let findingWriteQueue = Promise.resolve();
function withFindingWrite(operation) {
  const task = findingWriteQueue.catch(() => {}).then(operation);
  findingWriteQueue = task;
  return task;
}
const snapshotReady = readFile(snapshotFile, 'utf8').then(async raw => {
  const saved = JSON.parse(raw);
  if (saved.checkedAt && Array.isArray(saved.results) && Array.isArray(saved.workspaces)) {
    await withFindingWrite(async () => {
      const findingStore = await readFindingStore(findingStoreFile);
      const reconciliation = reconcileFindingWorkflows(findingStore, saved.results);
      if (reconciliation.changed) await writeFindingStore(findingStoreFile, findingStore);
      await appendFindingEvents(findingHistoryFile, reconciliation.events);
      snapshot = saved;
    });
  }
}).catch(error => { if (error.code !== 'ENOENT') console.warn(`Could not load saved scan: ${error.message}`); });
const yamlCheckInterval = Number(process.env.YAML_CHECK_INTERVAL_MS || 30_000);
const yamlMonitor = createYamlMonitor({
  files: {
    'applications.yaml': path.join(configDirectory, 'applications.yaml'),
    'workspaces.yaml': path.join(configDirectory, 'workspaces.yaml'),
    'feeds.yaml': feedFile,
    'owners.yaml': ownerFile,
    'smtp.yaml': smtpFile,
    'general.yaml': generalFile,
    'rbac.yaml': rbacFile,
  },
  intervalMs: Number.isFinite(yamlCheckInterval) && yamlCheckInterval > 0 ? yamlCheckInterval : 30_000,
  onChange: async changes => {
    const actor = { issuer: 'filesystem', subject: 'unknown', name: 'Filesystem change (unattributed)' };
    for (const change of changes) await logger.audit('YAML file changed outside web interface', actor, { type: 'yaml', id: change.name }, { kind: change.kind }, `${change.name} ${change.kind}`);
    if (changes.some(change => ['applications.yaml', 'workspaces.yaml', 'feeds.yaml', 'owners.yaml'].includes(change.name))) {
      await invalidateSnapshot();
      if (process.env.AUTO_SCAN !== 'false') {
        if (refreshPromise) await refreshPromise.catch(() => {});
        await refresh().catch(error => logger.log('error', 'Scan after YAML change failed', error.message));
      }
    } else if (snapshot && !changes.some(change => change.name === 'rbac.yaml')) notifier.onScan(snapshot).catch(error => logger.log('error', 'Notification check after YAML change failed', error.message));
  },
});
await yamlMonitor.start();

async function storeSnapshot(data) {
  return withFindingWrite(async () => {
    await mkdir(dataDirectory, { recursive: true });
    const findingStore = await readFindingStore(findingStoreFile);
    const reconciliation = reconcileFindingWorkflows(findingStore, data.results || []);
    for (const application of data.results || []) delete application.inventoryLifecycle;
    if (reconciliation.changed) await writeFindingStore(findingStoreFile, findingStore);
    await appendFindingEvents(findingHistoryFile, reconciliation.events);
    for (const event of reconciliation.events.filter(event => event.type === 'finding-inventory-resolved' || (event.type === 'finding-reopened' && event.previousResolution))) {
      await logger.audit(event.type === 'finding-inventory-resolved' ? 'Package finding resolved by inventory assessment' : 'Package finding reopened', event.actor, { type: 'finding', id: event.findingId, applicationId: event.applicationId }, { reason: event.reason, inventory: event.inventory || event.previousResolution }, event.reason);
    }
    await saveAtomic(snapshotFile, `${JSON.stringify(data)}\n`);
    snapshot = data;
    notifier.onScan(data).catch(error => { console.error(`Notification check failed: ${error.message}`); logger.log('error', 'Notification check failed', error.message); });
    return data;
  });
}

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
function acknowledgePage(entry, confirmed = false) {
  const heading = confirmed || entry.acknowledgedAt ? 'Alert acknowledged' : 'Acknowledge this alert?';
  const details = `${escapeHtml(entry.appName || 'Application')} · ${escapeHtml(entry.version || '')} in ${escapeHtml(entry.workspaceName || 'workspace')}`;
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${heading} · WatchTower</title><body style="margin:0;background:#f4f8fa;color:#203646;font:16px Arial,sans-serif"><main style="max-width:560px;margin:10vh auto;padding:32px;background:white;border:1px solid #dce6eb;border-radius:12px"><h1>${heading}</h1><p>${details}</p><p>Confirming stops reminders for this application in this workspace until the alert clears or its version changes.</p>${confirmed || entry.acknowledgedAt ? '<p>You can close this page.</p>' : `<form method="post"><button style="padding:12px 18px;border:0;border-radius:7px;background:#147d69;color:white;font:inherit;cursor:pointer">Acknowledge alert</button></form>`}</main></body></html>`;
}

async function invalidateSnapshot() {
  snapshot = null;
  await rm(snapshotFile, { force: true });
}

function scalar(value) {
  const raw = value.trim();
  if (raw.startsWith('"')) { try { return JSON.parse(raw); } catch { throw new Error('Invalid quoted YAML value'); } }
  const v = raw.replace(/\s+#.*$/, '');
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (/^['"].*['"]$/.test(v)) return v.slice(1, -1);
  return v;
}

function parseInventory(source, includeDisabled = false, allowLegacyIds = false) {
  const apps = [];
  let current = null;
  let listField = '';
  for (const line of source.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#') || line.trim() === 'applications:') continue;
    const entry = line.match(/^  - ([A-Za-z][\w]*):\s*(.*)$/);
    const field = line.match(/^    ([A-Za-z][\w]*):\s*(.*)$/);
    const listItem = line.match(/^      -\s*(.*)$/);
    if (entry) { current = {}; apps.push(current); current[entry[1]] = scalar(entry[2]); listField = ''; }
    else if (field && current && ['ownerIds', 'tags'].includes(field[1]) && !field[2].trim()) { listField = field[1]; current[listField] = []; }
    else if (field && current) { current[field[1]] = scalar(field[2]); listField = ''; }
    else if (listItem && current && listField) current[listField].push(scalar(listItem[1]));
    else throw new Error(`Unsupported inventory YAML line: ${line}`);
  }
  for (const app of apps) {
    const hadContext = ['criticality', 'environment', 'exposure', 'ownerIds', 'tags'].every(key => Object.hasOwn(app, key));
    for (const key of ['id', 'name', 'version']) {
      if (!app[key] || typeof app[key] !== 'string') throw new Error(`Application is missing ${key}`);
    }
    if (!allowLegacyIds && !uuidPattern.test(app.id)) throw new Error(`Invalid immutable application ID for ${app.name}`);
    for (const key of ['version']) {
      if (!/^[A-Za-z0-9._-]+$/.test(app[key])) throw new Error(`Invalid ${key} for ${app.name}`);
    }
    if (app.cpeMode && !['product', 'exact'].includes(app.cpeMode)) throw new Error(`Invalid cpeMode for ${app.name}`);
    const hadCanonicalCpe = Boolean(app.cpeName);
    app.assessmentMode ||= 'cpe';
    if (!['cpe', 'inventory'].includes(app.assessmentMode)) throw new Error('Invalid assessmentMode');
    if (app.cpeName || app.cpeVendor && app.cpeProduct || app.assessmentMode === 'cpe') {
      const mapping = mappingFromApp(app);
      app.cpeName = mapping.cpeName;
      app.cpeMode = mapping.mode;
    }
    app.cpeTitle ||= app.name;
    app.criticality ||= 'unspecified';
    app.environment ||= 'unspecified';
    app.exposure ||= 'unknown';
    app.ownerIds = [...new Set(Array.isArray(app.ownerIds) ? app.ownerIds.map(String) : [])];
    app.tags = [...new Set(Array.isArray(app.tags) ? app.tags.map(String) : [])];
    if (app.ownerIds.some(id => !uuidPattern.test(id))) throw new Error(`Invalid owner reference for ${app.name}`);
    if (app.tags.length > 25 || app.tags.some(tag => tag.length > 40 || !/^[a-z0-9][a-z0-9._-]*$/.test(tag))) throw new Error(`Invalid tags for ${app.name}`);
    if (!['unspecified', 'low', 'medium', 'high', 'critical'].includes(app.criticality)) throw new Error(`Invalid criticality for ${app.name}`);
    if (!['unspecified', 'production', 'staging', 'development', 'test', 'disaster-recovery'].includes(app.environment)) throw new Error(`Invalid environment for ${app.name}`);
    if (!['unknown', 'internal', 'external', 'internet'].includes(app.exposure)) throw new Error(`Invalid exposure for ${app.name}`);
    Object.defineProperty(app, '_needsCpeMigration', { value: !hadCanonicalCpe && Boolean(app.cpeName), enumerable: false });
    Object.defineProperty(app, '_needsContextMigration', { value: !hadContext, enumerable: false });
  }
  if (new Set(apps.map(a => a.id)).size !== apps.length) throw new Error('Application IDs must be unique');
  return includeDisabled ? apps : apps.filter(a => a.enabled !== false);
}

const appFields = ['assessmentMode', 'id', 'legacyId', 'name', 'vendor', 'version', 'cpeName', 'cpeMode', 'cpeTitle', 'cpeDeprecated', 'cpeLastTestedAt', 'cpeTestCandidateCount', 'cpeTestApplicableCount', 'cpeVendor', 'cpeProduct', 'cpeEdition', 'lifecycleProduct', 'eolDate', 'lifecycleUrl', 'vendorBulletinUrl', 'releaseUrl', 'latestVersion', 'latestBranchVersion', 'latestLtsVersion', 'criticality', 'environment', 'exposure', 'ownerIds', 'tags'];
const scalarAppFields = appFields.filter(key => !['ownerIds', 'tags'].includes(key));
const idPattern = /^[A-Za-z0-9._-]+$/;
function cleanApp(input, existingId = '') {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Application details are required');
  const app = Object.fromEntries(scalarAppFields.map(key => [key, String(key === 'id' && existingId ? existingId : input[key] ?? '').trim()]));
  app.criticality ||= 'unspecified';
  app.environment ||= 'unspecified';
  app.exposure ||= 'unknown';
  app.ownerIds = [...new Set((Array.isArray(input.ownerIds) ? input.ownerIds : []).map(value => String(value).trim()).filter(Boolean))];
  app.tags = [...new Set((Array.isArray(input.tags) ? input.tags : String(input.tags || '').split(',')).map(value => String(value).trim().toLowerCase()).filter(Boolean))];
  if (!app.cpeName && app.cpeVendor && app.cpeProduct) {
    app.cpeName = legacyCpe(app);
    app.cpeMode = app.cpeEdition ? 'exact' : 'product';
    app.cpeTitle ||= app.name;
  }
  app.assessmentMode ||= 'cpe';
  if (!['cpe', 'inventory'].includes(app.assessmentMode)) throw new Error('Invalid assessmentMode');
  for (const key of ['id', 'name', 'version']) if (!app[key]) throw new Error(`${key} is required`);
  if (!app.cpeName && app.assessmentMode !== 'inventory') throw new Error('cpeName is required');
  if (!uuidPattern.test(app.id)) throw new Error('Application ID must be an immutable UUID');
  if (app.cpeName) {
  if (!['product', 'exact'].includes(app.cpeMode)) throw new Error('cpeMode must be product or exact');
  const mapping = parseCpe23(app.cpeName);
  app.cpeVendor = mapping.vendor;
  app.cpeProduct = mapping.product;
  app.cpeEdition = mapping.edition === '*' || mapping.edition === '-' ? '' : mapping.edition;
  const blocking = mappingWarnings({ ...mapping, mode: app.cpeMode, deprecated: app.cpeDeprecated === 'true' }, app.version).filter(item => item.code === 'version-conflict');
  if (blocking.length) throw new Error(blocking[0].message);
  }
  // CPE-derived fields have already been validated as part of the canonical CPE.
  // They may legitimately contain escaped punctuation such as Notepad++'s `notepad\+\+`.
  for (const key of ['version', 'lifecycleProduct']) if (app[key] && !idPattern.test(app[key])) throw new Error(`${key} may contain only letters, numbers, dots, underscores, and hyphens`);
  if (!app.lifecycleProduct && !app.eolDate) throw new Error('A lifecycle product or end-of-life date is required');
  if (app.eolDate && (!/^\d{4}-\d{2}-\d{2}$/.test(app.eolDate) || !Number.isFinite(Date.parse(`${app.eolDate}T00:00:00Z`)))) throw new Error('End-of-life date must be YYYY-MM-DD');
  for (const key of ['lifecycleUrl', 'vendorBulletinUrl', 'releaseUrl']) if (app[key]) { try { if (new URL(app[key]).protocol !== 'https:') throw new Error(); } catch { throw new Error(`${key} must be an HTTPS URL`); } }
  for (const key of ['name', 'vendor']) if (/[\r\n]/.test(app[key])) throw new Error(`${key} must be one line`);
  if (!['unspecified', 'low', 'medium', 'high', 'critical'].includes(app.criticality)) throw new Error('Select a valid criticality');
  if (!['unspecified', 'production', 'staging', 'development', 'test', 'disaster-recovery'].includes(app.environment)) throw new Error('Select a valid environment');
  if (!['unknown', 'internal', 'external', 'internet'].includes(app.exposure)) throw new Error('Select a valid exposure');
  if (app.tags.length > 25 || app.tags.some(tag => tag.length > 40 || !/^[a-z0-9][a-z0-9._-]*$/.test(tag))) throw new Error('Tags must be comma-separated lowercase words using letters, numbers, dots, underscores, or hyphens');
  return app;
}
function yamlValue(value) { return JSON.stringify(String(value)); }
function serializeApp(app) {
  return `  - id: ${app.id}\n${Object.entries(app).filter(([key, value]) => key !== 'id' && value !== '' && value != null && !Array.isArray(value)).map(([key, value]) => `    ${key}: ${typeof value === 'boolean' ? value : yamlValue(value)}\n`).join('')}    ownerIds:\n${(app.ownerIds || []).map(id => `      - ${id}\n`).join('')}    tags:\n${(app.tags || []).map(tag => `      - ${yamlValue(tag)}\n`).join('')}`;
}
function serializeWorkspaces(groups) {
  return `# Workspace names are free text. Applications and owners are referenced by immutable ID.\nworkspaces:\n${groups.map(group => `  - id: ${group.id}\n${group.legacyId ? `    legacyId: ${yamlValue(group.legacyId)}\n` : ''}    name: ${yamlValue(group.name)}\n    ownerIds:\n${(group.ownerIds || []).map(id => `      - ${id}\n`).join('')}    applications:\n${group.applications.map(id => `      - ${id}\n`).join('')}`).join('')}`;
}
function auditActor(req) {
  if (!req.authUser) return { issuer: 'local', username: 'local', name: 'Local development session' };
  return { issuer: req.authUser.issuer, username: req.authUser.username || req.authUser.subject, name: req.authUser.name };
}
function changedFields(before, after, fields) {
  return Object.fromEntries(fields.filter(field => JSON.stringify(before[field] ?? '') !== JSON.stringify(after[field] ?? '')).map(field => [field, { from: before[field] ?? '', to: after[field] ?? '' }]));
}
function describeFields(changes) {
  return Object.entries(changes).map(([field, value]) => `${field}: ${JSON.stringify(value.from)} → ${JSON.stringify(value.to)}`).join('; ') || 'No values changed';
}
const policyAuditLabels = Object.freeze({
  name: 'Name', enabled: 'Enabled', severities: 'Severities', knownExploited: 'Known exploitation', criticalities: 'Application criticalities', environments: 'Environments', exposures: 'Exposures', findingStates: 'Finding states', workspaceIds: 'Workspaces', ownerIds: 'Owners', minimumAgeDays: 'Minimum finding age', maximumAgeDays: 'Maximum finding age', cadence: 'Cadence', sendHour: 'Delivery hour', weeklyDay: 'Weekly delivery day', windowStartHour: 'Allowed window start', windowEndHour: 'Allowed window end', reminderDays: 'Reminder interval', workspaceRecipients: 'Include workspace owners', recipientOwnerIds: 'Additional delivery owners', includeEscalationContacts: 'Include escalation contacts', escalationAfterDays: 'Escalation age',
});
const policyAuditDays = Object.freeze(['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']);
function policyAuditView(policy, { workspaces = [], owners = [] } = {}) {
  const conditions = policy.conditions || {};
  const delivery = policy.delivery || {};
  const workspaceNames = new Map(workspaces.map(item => [item.id, item.name]));
  const ownerNames = new Map(owners.map(item => [item.id, `${item.name}${item.email ? ` <${item.email}>` : ''}`]));
  const title = value => String(value).split('-').map(part => part ? part[0].toUpperCase() + part.slice(1) : part).join(' ');
  const list = (values, names) => (values || []).map(value => names?.get(value) || title(value)).join(', ') || 'Any';
  const hour = value => value === null || value === undefined ? 'Global' : `${String(value).padStart(2, '0')}:00`;
  return {
    name: policy.name,
    enabled: policy.enabled === false ? 'No' : 'Yes',
    severities: list(conditions.severities),
    knownExploited: conditions.knownExploited === undefined ? 'Any' : conditions.knownExploited ? 'Yes' : 'No',
    criticalities: list(conditions.criticalities),
    environments: list(conditions.environments),
    exposures: list(conditions.exposures),
    findingStates: list(conditions.findingStates),
    workspaceIds: list(conditions.workspaceIds, workspaceNames),
    ownerIds: list(conditions.ownerIds, ownerNames),
    minimumAgeDays: conditions.minimumAgeDays === undefined ? 'Any' : `${conditions.minimumAgeDays} days`,
    maximumAgeDays: conditions.maximumAgeDays === undefined ? 'Any' : `${conditions.maximumAgeDays} days`,
    cadence: title(delivery.cadence || 'adaptive'),
    sendHour: hour(delivery.sendHour),
    weeklyDay: policyAuditDays[delivery.weeklyDay ?? 1],
    windowStartHour: hour(delivery.windowStartHour ?? 0),
    windowEndHour: hour(delivery.windowEndHour ?? 23),
    reminderDays: `${delivery.reminderDays ?? 7} days`,
    workspaceRecipients: delivery.workspaceRecipients === false ? 'No' : 'Yes',
    recipientOwnerIds: list(delivery.recipientOwnerIds, ownerNames).replace(/^Any$/, 'None'),
    includeEscalationContacts: delivery.includeEscalationContacts === true ? 'Yes' : 'No',
    escalationAfterDays: delivery.escalationAfterDays == null ? 'Not configured' : `${delivery.escalationAfterDays} days`,
  };
}
function policyAuditChanges(before, after, resources) {
  const previous = policyAuditView(before, resources);
  const current = policyAuditView(after, resources);
  return changedFields(previous, current, Object.keys(policyAuditLabels));
}
function describePolicyAuditChanges(changes) {
  return Object.entries(changes).map(([field, value]) => `${policyAuditLabels[field]}: ${value.from || 'empty'} → ${value.to || 'empty'}`).join('; ');
}
async function saveAtomic(file, content) {
  const temporary = `${file}.tmp`;
  await writeFile(temporary, content, 'utf8');
  await rename(temporary, file);
}
async function saveRelatedFiles(updates) {
  const originals = await Promise.all(updates.map(async update => ({ ...update, original: await readFile(update.file, 'utf8') })));
  try {
    for (const update of originals) await yamlMonitor.webWrite(update.file, () => saveAtomic(update.file, update.content));
  } catch (error) {
    for (const update of originals) await yamlMonitor.webWrite(update.file, () => saveAtomic(update.file, update.original)).catch(() => {});
    throw error;
  }
}
async function readBody(req, limit = 50000) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > limit) throw new Error('Request is too large');
    chunks.push(chunk);
  }
  const body = Buffer.concat(chunks).toString('utf8');
  try { return JSON.parse(body); } catch { throw new Error('Invalid JSON'); }
}

function requestCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').map(part => part.trim().split(/=(.*)/s, 2)).filter(([name, value]) => name && value !== undefined));
}

function previewActorKey(req) {
  return req.authUser ? `${req.authUser.issuer}|${req.authUser.subject}` : 'local-development';
}

function previewCookie(req, value, seconds) {
  const secure = detectedGeneral(req).protocol === 'https' ? '; Secure' : '';
  return `watchtower_preview=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${seconds}${secure}`;
}

function attachPermissionPreview(req) {
  for (const [id, item] of permissionPreviews) if (item.expires <= Date.now()) permissionPreviews.delete(id);
  const token = requestCookies(req).watchtower_preview;
  const preview = permissionPreviews.get(token);
  if (!preview) return;
  if (preview.expires <= Date.now() || preview.actorKey !== previewActorKey(req)) {
    permissionPreviews.delete(token);
    return;
  }
  req.permissionPreview = preview;
  req.permissionPreviewToken = token;
}

async function readFeedCache() {
  try { return JSON.parse(await readFile(feedCacheFile, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return { checkedAt: null, feeds: {} }; throw error; }
}

function parseWorkspaces(source, apps, owners = [], allowLegacyIds = false) {
  const groups = [];
  let current = null;
  let listField = '';
  for (const line of source.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#') || line.trim() === 'workspaces:') continue;
    const entry = line.match(/^  - id:\s*(.*)$/);
    const name = line.match(/^    name:\s*(.*)$/);
    const legacyId = line.match(/^    legacyId:\s*(.*)$/);
    const notificationEmails = line.match(/^    notificationEmails:\s*(.*)$/);
    const item = line.match(/^      - ([A-Za-z0-9._-]+)\s*$/);
    if (entry) { current = { id: scalar(entry[1]), ownerIds: [], applications: [] }; groups.push(current); listField = ''; }
    else if (legacyId && current) current.legacyId = scalar(legacyId[1]);
    else if (name && current) current.name = scalar(name[1]);
    else if (notificationEmails && current) current.notificationEmails = scalar(notificationEmails[1]);
    else if (line === '    ownerIds:' && current) listField = 'ownerIds';
    else if (line === '    applications:' && current) listField = 'applications';
    else if (item && current && listField) current[listField].push(item[1]);
    else throw new Error(`Unsupported workspace YAML line: ${line}`);
  }
  const known = new Set(apps.map(app => app.id));
  const knownOwners = new Set(owners.map(owner => owner.id));
  for (const group of groups) {
    if ((!allowLegacyIds && !uuidPattern.test(group.id || '')) || !group.name) throw new Error('Workspace needs an immutable UUID and name');
    group.notificationEmails ||= '';
    group.ownerIds = [...new Set(group.ownerIds || [])];
    if (!allowLegacyIds) for (const id of group.ownerIds) if (!knownOwners.has(id)) throw new Error(`Workspace ${group.name} references an unavailable owner: ${id}`);
    for (const id of group.applications) if (!known.has(id)) throw new Error(`Workspace ${group.name} references an unavailable application: ${id}`);
    group.applications = [...new Set(group.applications)];
  }
  if (new Set(groups.map(group => group.id)).size !== groups.length) throw new Error('Workspace IDs must be unique');
  return groups;
}

async function authorizationResources(includeDisabled = true) {
  const apps = parseInventory(await readFile(path.join(configDirectory, 'applications.yaml'), 'utf8'), includeDisabled);
  const owners = await readOwners(ownerFile);
  const workspaces = parseWorkspaces(await readFile(path.join(configDirectory, 'workspaces.yaml'), 'utf8'), apps.filter(app => app.enabled !== false), owners);
  const feeds = await readFeeds(feedFile);
  const ownerIds = new Set(owners.map(owner => owner.id));
  for (const app of apps) for (const ownerId of app.ownerIds) if (!ownerIds.has(ownerId)) throw new Error(`Application ${app.name} references an unavailable owner: ${ownerId}`);
  return { apps, workspaces, feeds, owners };
}

async function authorization(req, includeDisabled = true) {
  const { apps, workspaces, feeds, owners } = await authorizationResources(includeDisabled);
  const config = req.permissionPreview?.config || await readRbac(rbacFile);
  const user = req.permissionPreview ? { issuer: 'permission-preview', claims: req.permissionPreview.claims } : req.authUser || { issuer: 'local', isAdmin: true };
  const access = calculateAccess(user, config, apps, workspaces, feeds);
  return { apps, workspaces, feeds, owners, access };
}

async function realAuthorization(req, includeDisabled = true) {
  const { apps, workspaces, feeds, owners } = await authorizationResources(includeDisabled);
  const access = calculateAccess(req.authUser || { issuer: 'local', isAdmin: true }, await readRbac(rbacFile), apps, workspaces, feeds);
  return { apps, workspaces, feeds, owners, access };
}

function forbidden(res, message = 'You do not have permission to perform this action') {
  res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ error: message }));
}

function visibleSnapshot(data, owners, access, req) {
  const results = (data.results || []).filter(app => access.appView.has(app.id));
  const workspaces = (data.workspaces || []).filter(group => access.workspaceView.has(group.id)).map(group => ({ ...group, applications: group.applications.filter(id => access.appView.has(id)) }));
  const assignedOwnerIds = new Set(results.flatMap(app => app.ownerIds || []));
  const visibleOwners = owners.filter(owner => assignedOwnerIds.has(owner.id));
  return { ...data, results, workspaces, owners: visibleOwners, access: accessJson(access), groupOverage: req.permissionPreview ? false : Boolean(req.authUser?.groupOverage) };
}

function selectedPreviewConfig(config, grantIds) {
  if (grantIds === undefined) return config;
  if (!Array.isArray(grantIds)) throw new Error('Permission verification grant selection must be an array');
  const selected = new Set(grantIds.map(String));
  if ([...selected].some(id => !config.grants.some(grant => grant.id === id))) throw new Error('Permission verification references an unknown grant');
  return { groups: config.groups, grants: config.grants.filter(grant => selected.has(grant.id)) };
}

async function migrateResourceIds() {
  const applicationFile = path.join(configDirectory, 'applications.yaml');
  const workspaceFile = path.join(configDirectory, 'workspaces.yaml');
  const applicationSource = await readFile(applicationFile, 'utf8');
  const workspaceSource = await readFile(workspaceFile, 'utf8');
  const applications = parseInventory(applicationSource, true, true);
  const owners = await readOwners(ownerFile);
  const workspaces = parseWorkspaces(workspaceSource, applications.filter(app => app.enabled !== false), owners, true);
  const knownOwnerIds = new Set(owners.map(owner => owner.id));
  for (const app of applications) for (const ownerId of app.ownerIds) if (!knownOwnerIds.has(ownerId)) throw new Error(`Application ${app.name} references an unavailable owner: ${ownerId}`);
  const applicationIds = new Map();
  const workspaceIds = new Map();
  for (const app of applications) if (!uuidPattern.test(app.id)) { const previous = app.id; app.id = randomUUID(); app.legacyId ||= previous; applicationIds.set(previous, app.id); }
  for (const workspace of workspaces) {
    workspace.applications = workspace.applications.map(id => applicationIds.get(id) || id);
    if (!uuidPattern.test(workspace.id)) { const previous = workspace.id; workspace.id = randomUUID(); workspace.legacyId ||= previous; workspaceIds.set(previous, workspace.id); }
  }
  let workspaceOwnersMigrated = false;
  for (const workspace of workspaces) {
    const recipients = [...new Set(String(workspace.notificationEmails || '').split(/[;,]/).map(value => value.trim()).filter(Boolean))];
    for (const email of recipients) {
      let owner = owners.find(item => item.email.toLowerCase() === email.toLowerCase());
      if (!owner) {
        const baseName = `Notification recipient ${email}`;
        let name = baseName;
        for (let suffix = 2; owners.some(item => item.name.toLowerCase() === name.toLowerCase()); suffix += 1) name = `${baseName} ${suffix}`;
        owner = validateOwner({ name, email });
        owners.push(owner);
      }
      if (!workspace.ownerIds.includes(owner.id)) workspace.ownerIds.push(owner.id);
    }
    if (recipients.length) workspaceOwnersMigrated = true;
    delete workspace.notificationEmails;
  }
  const cpeMappingsMigrated = applications.some(app => app._needsCpeMigration);
  const applicationContextMigrated = applications.some(app => app._needsContextMigration);
  if (applicationIds.size || cpeMappingsMigrated || applicationContextMigrated) await saveAtomic(applicationFile, `# Application IDs, canonical CPE mappings, ownership, and risk context are managed by WatchTower.\napplications:\n${applications.map(serializeApp).join('')}`);
  if (workspaceOwnersMigrated) await writeOwners(ownerFile, owners);
  if (applicationIds.size || workspaceIds.size || workspaceOwnersMigrated) await saveAtomic(workspaceFile, serializeWorkspaces(workspaces));
  if (applicationIds.size || workspaceIds.size || workspaceOwnersMigrated || cpeMappingsMigrated || applicationContextMigrated) await rm(path.join(dataDirectory, 'status.json'), { force: true });
  return { applications: applicationIds, workspaces: workspaceIds };
}

async function fetchJson(url, timeout = 15000, headers = {}) {
  try {
    const response = await fetch(url, { headers: { 'User-Agent': 'VulnerabilityDashboard/1.0', Accept: 'application/json', ...headers }, signal: AbortSignal.timeout(timeout) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    logger.feed('info', 'Source request succeeded', String(url));
    return data;
  } catch (error) {
    logger.feed('error', 'Source request failed', `${url}: ${error.cause?.code || error.name || 'Error'}: ${error.message}`);
    throw error;
  }
}

async function fetchText(url, timeout = 15000) {
  try {
    const response = await fetch(url, { headers: { 'User-Agent': 'VulnerabilityDashboard/1.0' }, signal: AbortSignal.timeout(timeout) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.text();
    logger.feed('info', 'Source request succeeded', String(url));
    return data;
  } catch (error) {
    logger.feed('error', 'Source request failed', `${url}: ${error.cause?.code || error.name || 'Error'}: ${error.message}`);
    throw error;
  }
}

async function fetchNvdJson(url) {
  const interval = process.env.NVD_API_KEY ? 700 : 6500;
  const wait = Math.max(0, interval - (Date.now() - nvdLastRequest));
  if (wait) await new Promise(resolve => setTimeout(resolve, wait));
  nvdLastRequest = Date.now();
  return fetchJson(url, 20000, process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {});
}

async function lifecycleCatalog() {
  if (lifecycleCatalogCache && Date.now() - lifecycleCatalogCache.loadedAt < 60 * 60 * 1000) return lifecycleCatalogCache.products;
  const data = await fetchJson('https://endoflife.date/api/v1/products/', 20000);
  if (!Array.isArray(data.result)) throw new Error('endoflife.date returned an invalid product catalog');
  lifecycleCatalogCache = { loadedAt: Date.now(), products: data.result };
  return lifecycleCatalogCache.products;
}

async function lifecycleProduct(name) {
  if (!idPattern.test(name)) throw new Error('Invalid lifecycle product identifier');
  const data = await fetchJson(`https://endoflife.date/api/v1/products/${encodeURIComponent(name)}/`, 20000);
  if (!data.result || typeof data.result !== 'object') throw new Error('endoflife.date returned an invalid product record');
  return normalizeLifecycleProduct(data.result);
}

function severity(cve) {
  const metrics = cve.metrics || {};
  const scores = [...(metrics.cvssMetricV40 || []), ...(metrics.cvssMetricV31 || []), ...(metrics.cvssMetricV30 || []), ...(metrics.cvssMetricV2 || [])];
  const highest = scores.map(m => m.cvssData?.baseScore || 0).reduce((a, b) => Math.max(a, b), 0);
  return { score: highest, label: highest >= 9 ? 'Critical' : highest >= 7 ? 'High' : highest >= 4 ? 'Medium' : highest > 0 ? 'Low' : 'Unrated' };
}

function lifecycleStatus(cycle, version) {
  if (!cycle) return { state: 'unknown', note: 'Lifecycle version not matched' };
  const raw = cycle.eol;
  if (raw === false) return { state: 'supported', note: 'Supported release' };
  if (raw === true) return { state: 'expired', note: 'Past end of life' };
  if (typeof raw !== 'string' || !/^\d{4}-\d\d-\d\d$/.test(raw)) return { state: 'unknown', note: 'End-of-life date unavailable' };
  const days = Math.ceil((new Date(`${raw}T00:00:00Z`).getTime() - Date.now()) / 86400000);
  return { state: days < 0 ? 'expired' : days <= 90 ? 'approaching' : 'supported', note: days < 0 ? `End of life ${raw}` : `End of life ${raw}`, eol: raw, daysRemaining: days };
}

function compareVersions(a, b) {
  const left = String(a).split('.').map(Number);
  const right = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const diff = (left[i] || 0) - (right[i] || 0);
    if (diff) return diff;
  }
  return 0;
}

function releaseTargets(cycles, currentCycle, sourceUrl) {
  const released = cycles.filter(c => /^\d+(?:\.\d+)*$/.test(String(c.latest || '')));
  const newest = [...released].sort((a, b) => compareVersions(b.latest, a.latest))[0];
  const supportedLts = released.filter(c => c.lts === true && (c.eol === false || typeof c.eol === 'string' && new Date(`${c.eol}T00:00:00Z`).getTime() >= Date.now()));
  const latestLts = supportedLts.sort((a, b) => compareVersions(b.latest, a.latest))[0];
  return { latest: newest?.latest || null, currentLine: currentCycle?.latest || null, latestLts: latestLts?.latest || null, sourceUrl };
}

async function checkAtlassian(app, kev) {
  const product = app.cpeProduct === 'jira_software_data_center' ? 'JIRA Software Data Center' : app.cpeProduct === 'confluence_data_center' ? 'Confluence Data Center' : null;
  if (!product) return null;
  const api = new URL('https://api.atlassian.com/vuln-transparency/v1/products');
  api.searchParams.set('products', product);
  api.searchParams.set('version', app.version);
  const data = await fetchJson(api);
  const key = Object.keys(data.products || {}).find(p => p.toLowerCase() === product.toLowerCase());
  const records = data.products?.[key]?.versions?.[app.version];
  if (!Array.isArray(records)) throw new Error('Exact version not covered by Atlassian API');
  const vulnerabilities = records.flatMap(record => Object.entries(record)).filter(([, state]) => state === 'AFFECTED').map(([id]) => {
    const meta = data.cve_metadata?.[id] || {};
    const score = Number(meta.cve_severity || 0);
    return { id, score, label: score >= 9 ? 'Critical' : score >= 7 ? 'High' : score >= 4 ? 'Medium' : 'Unrated', description: meta.cve_description || meta.cve_summary || '', published: meta.cve_publish_date || '', knownExploited: kev.has(id), url: meta.atl_tracking_url || `https://nvd.nist.gov/vuln/detail/${id}`, advisories: [meta.advisory_url].filter(Boolean), source: 'Atlassian' };
  }).filter(v => v.score >= 7 || v.knownExploited).sort((a,b) => Number(b.knownExploited)-Number(a.knownExploited) || b.score-a.score);
  return { vulnerabilities, source: { name: 'Atlassian vulnerability API', url: api.toString() } };
}

async function checkGitlab(app, kev) {
  if (app.cpeVendor !== 'gitlab' || app.cpeProduct !== 'gitlab') return null;
  const feedUrl = 'https://docs.gitlab.com/releases/patch-releases.xml';
  const xml = await fetchText(feedUrl, 20000);
  const [major, minor, patch] = app.version.split('.').map(Number);
  const entries = [...xml.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].map(([, body]) => ({
    title: body.match(/<title>(.*?)<\/title>/)?.[1] || '',
    url: body.match(/<link href="([^"]+)"/)?.[1] || feedUrl,
    body,
  }));
  const relevant = entries.filter(e => new RegExp(`\\b${major}\\.${minor}\\.\\d+\\b`).test(e.title));
  if (!relevant.length) throw new Error('Installed release cycle not in GitLab patch feed');
  const newer = relevant.filter(e => [...e.title.matchAll(new RegExp(`\\b${major}\\.${minor}\\.(\\d+)\\b`, 'g'))].some(m => Number(m[1]) > patch));
  if (!newer.length) return { vulnerabilities: [], source: { name: 'GitLab patch releases', url: feedUrl } };
  const vulnerabilities = [];
  for (const entry of newer) {
    for (const [, section] of entry.body.matchAll(/<h3[^>]*id="cve-[^"]*"[^>]*>([\s\S]*?)(?=<h3|<h2|<\/entry>)/g)) {
      const id = section.match(/CVE-\d{4}-\d{4,}/)?.[0];
      const impacted = section.match(/Impacted Versions:<\/strong>([\s\S]*?)<\/p>/i)?.[1] || '';
      const fix = impacted.match(new RegExp(`\\b${major}\\.${minor}\\s+before\\s+${major}\\.${minor}\\.(\\d+)`, 'i'));
      const score = Number(section.match(/<strong>CVSS<\/strong>\s*([0-9]+(?:\.[0-9]+)?)/i)?.[1] || 0);
      if (!id || !fix || patch >= Number(fix[1]) || score < 7) continue;
      vulnerabilities.push({ id, score, label: score >= 9 ? 'Critical' : 'High', description: section.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 650), knownExploited: kev.has(id), url: entry.url, advisories: [entry.url], source: 'GitLab' });
    }
  }
  if (!vulnerabilities.length) throw new Error('Newer GitLab patch exists; affected versions could not be confirmed from feed');
  return { vulnerabilities: [...new Map(vulnerabilities.map(v => [v.id, v])).values()].sort((a,b) => b.score-a.score), source: { name: 'GitLab patch releases', url: feedUrl } };
}

async function scanApp(app, kev, feedRecords = [], feedErrors = []) {
  const mapping = app.cpeName ? mappingFromApp(app) : null;
  const cpe = mapping ? mapping.mode === 'exact' ? mapping.cpeName : `cpe:2.3:${mapping.part}:${mapping.vendor}:${mapping.product}:${app.version}:*:*:*:*:*:*:*` : '';
  const result = { ...app, cpe, status: 'unknown', reasons: [], vulnerabilities: [], sources: [], checkedAt: new Date().toISOString() };
  let sourceOk = false;
  let sourceLabel = mapping ? 'NVD' : 'Package inventory';
  if (mapping) try {
    const vendor = app.cpeVendor === 'atlassian' ? await checkAtlassian(app, kev) : await checkGitlab(app, kev);
    if (vendor) {
      result.vulnerabilities = vendor.vulnerabilities;
      result.sources.push(vendor.source);
      sourceOk = true;
      sourceLabel = vendor.source.name;
      result.vendorConfirmed = true;
    }
  } catch (error) { logger.feed('warn', 'Vendor assessment unavailable', `${app.name}: ${error.message}; using NVD fallback`); result.reasons.push(`Vendor check unavailable: ${error.message}; using NVD fallback`); }
  if (mapping && !sourceOk) try {
    const api = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
    api.searchParams.set('virtualMatchString', wildcardApplicationCpe(app));
    api.searchParams.set('resultsPerPage', '2000');
    const data = await fetchNvdJson(api);
    result.vulnerabilities = (data.vulnerabilities || []).filter(({ cve }) => cveAffectsApplication(cve, app)).map(({ cve }) => {
      const level = severity(cve);
      return { id: cve.id, ...level, published: cve.published, description: cve.descriptions?.find(d => d.lang === 'en')?.value || '', knownExploited: kev.has(cve.id), url: `https://nvd.nist.gov/vuln/detail/${cve.id}`, advisories: (cve.references || []).filter(r => /vendor advisory|patch/i.test((r.tags || []).join(' '))).slice(0, 3).map(r => r.url) };
    }).filter(v => v.score >= 7 || v.knownExploited).sort((a,b) => Number(b.knownExploited) - Number(a.knownExploited) || b.score - a.score);
    sourceOk = data.totalResults <= 2000;
    if (!sourceOk) result.reasons.push('NVD result limit reached; review required');
    result.sources.push({ name: 'NVD', url: api.toString() });
  } catch (error) { logger.feed('error', 'NVD assessment unavailable', `${app.name}: ${error.message}`); result.reasons.push(`NVD check unavailable: ${error.message}`); }
  let life = { state: 'unknown', note: 'Lifecycle source not configured' };
  result.upgrades = { latest: app.latestVersion || null, currentLine: app.latestBranchVersion || null, latestLts: app.latestLtsVersion || null, sourceUrl: app.releaseUrl || app.lifecycleUrl || null };
  if (app.eolDate) {
    life = lifecycleStatus({ eol: app.eolDate }, app.version);
    if (app.lifecycleUrl) result.sources.push({ name: 'Vendor lifecycle', url: app.lifecycleUrl });
  } else if (app.lifecycleProduct) {
    try {
      const url = `https://endoflife.date/api/${encodeURIComponent(app.lifecycleProduct)}.json`;
      const cycles = await fetchJson(url);
      const cycle = cycles.find(c => app.version === c.cycle || app.version.startsWith(`${c.cycle}.`));
      life = lifecycleStatus(cycle, app.version);
      result.upgrades = releaseTargets(cycles, cycle, app.releaseUrl || url);
      if (app.latestVersion) result.upgrades.latest = app.latestVersion;
      if (app.latestBranchVersion) result.upgrades.currentLine = app.latestBranchVersion;
      if (app.latestLtsVersion) result.upgrades.latestLts = app.latestLtsVersion;
      result.sources.push({ name: 'endoflife.date', url });
    } catch (error) { logger.feed('error', 'Lifecycle assessment unavailable', `${app.name}: ${error.message}`); life = { state: 'unknown', note: `Lifecycle check unavailable: ${error.message}` }; }
  }
  result.lifecycle = life;
  result.assessmentSource = sourceLabel;
  if (app.vendorBulletinUrl) result.sources.push({ name: 'Vendor security bulletins', url: app.vendorBulletinUrl });
  const feedSecurity = feedRecords.filter(event => event.type === 'security');
  if (feedSecurity.some(event => event.confidence === 'high')) { sourceOk = true; sourceLabel = 'Vendor feeds'; result.vendorConfirmed = true; }
  const versionLine = app.version.split('.').slice(0, 2).join('.');
  const reviewAdvisories = [];
  for (const event of feedSecurity) {
    if (event.confidence === 'high' && eventAffectsVersion(event, app.version)) {
      result.vulnerabilities.push({ id: event.cves[0] || event.title, score: event.score || (event.severity === 'CRITICAL' ? 9 : event.severity === 'HIGH' ? 7 : 0), label: event.severity, severity: event.severity, published: event.published, description: event.summary, knownExploited: event.cves.some(cve => kev.has(cve)), url: event.url, advisories: [event.url], vendorFeed: true });
      result.vendorConfirmed = true;
    } else if (event.confidence === 'medium' && ((event.versions || []).some(version => version === versionLine || version.startsWith(`${versionLine}.`)) || /\ball (?:supported )?versions\b/i.test(`${event.title} ${event.summary}`))) {
      reviewAdvisories.push(event);
      sourceOk = false;
    }
  }
  if (reviewAdvisories.length) result.reasons.push(`${reviewAdvisories.length} vendor feed advisor${reviewAdvisories.length === 1 ? 'y requires' : 'ies require'} manual applicability review`);
  const feedVersions = feedRecords.filter(event => event.type === 'release').flatMap(event => event.versions || []).filter(version => /^\d+\.\d+/.test(version));
  if (feedVersions.length) {
    result.upgrades.latest = feedVersions.sort((a, b) => compareVersions(b, a))[0];
    result.upgrades.currentLine = feedVersions.filter(version => version === versionLine || version.startsWith(`${versionLine}.`)).sort((a, b) => compareVersions(b, a))[0] || result.upgrades.currentLine;
  }
  const lifecycleEvent = feedRecords.filter(event => event.type === 'lifecycle' && event.endDate && (event.versions || []).some(version => app.version === version || app.version.startsWith(`${version}.`) || version.startsWith(`${app.version.split('.').slice(0, 2).join('.')}.`))).sort((a, b) => b.endDate.localeCompare(a.endDate))[0];
  if (lifecycleEvent) { life = lifecycleStatus({ eol: lifecycleEvent.endDate }, app.version); result.lifecycle = life; sourceLabel = 'Vendor feeds'; sourceOk = true; }
  const affectingSecurity = feedSecurity.filter(event => event.confidence === 'high' && eventAffectsVersion(event, app.version));
  const releaseEvidence = feedRecords.filter(event => event.type === 'release' && (event.versions || []).includes(result.upgrades.latest)).slice(0, 3);
  const evidence = [...new Map([...affectingSecurity, ...reviewAdvisories, ...releaseEvidence, ...(lifecycleEvent ? [lifecycleEvent] : [])].map(event => [event.id, event])).values()].slice(0, 25);
  result.feedEvents = evidence.map(event => ({ type: event.type, title: event.title, published: event.published, url: event.url, confidence: event.confidence, severity: event.severity, cves: event.cves }));
  for (const record of evidence) if (record.url && !result.sources.some(source => source.url === record.url)) result.sources.push({ name: `${record.feedName} · ${record.type}`, url: record.url });
  for (const error of feedErrors) result.reasons.push(`Vendor feed unavailable: ${error}`);
  if (feedErrors.length) sourceOk = false;
  result.vulnerabilities = [...new Map(result.vulnerabilities.map(item => [`${item.id}:${item.url}`, item])).values()].sort((a, b) => (b.score || 0) - (a.score || 0));
  try {
    const packages = await assessApplicationInventory(app, inventoryStore, osvClient, kev, { maxAgeDays: sbomMaxAgeDays, onEvent: logger.feed });
    result.packageAssessment = { configured: packages.configured, state: packages.state, inventories: packages.inventories };
    result.inventoryLifecycle = packages.lifecycle;
    result.vulnerabilities.push(...packages.findings);
    result.reasons.push(...packages.reasons);
    if (packages.configured) {
      result.sources.push({ name: 'OSV package assessment', url: 'https://osv.dev/' });
      if (packages.state !== 'assessed') sourceOk = false;
      else if (!mapping && !feedErrors.length && !reviewAdvisories.length) { sourceOk = true; sourceLabel = 'OSV'; }
    }
  } catch (error) { sourceOk = false; result.packageAssessment = { configured: true, state: 'incomplete', inventories: [] }; result.reasons.push(`Package assessment unavailable: ${error.message}`); }
  const urgent = result.vulnerabilities.some(v => v.score >= 7 || v.knownExploited || ['HIGH', 'CRITICAL'].includes(v.severity));
  result.status = urgent || life.state === 'expired' ? 'red' : !sourceOk || life.state === 'unknown' ? 'unknown' : life.state === 'approaching' ? 'yellow' : 'green';
  if (result.status === 'green' && result.vulnerabilities.some(finding => finding.package)) result.status = result.vulnerabilities.some(finding => finding.package && finding.severity === 'UNKNOWN') ? 'unknown' : 'yellow';
  const unknownSeverity = result.vulnerabilities.filter(finding => finding.package && finding.severity === 'UNKNOWN').length;
  if (unknownSeverity) result.reasons.push(`${unknownSeverity} package findings have no interpreted severity label; review retained source severity evidence`);
  if (urgent) result.reasons.push(`${result.vulnerabilities.filter(v => v.score >= 7 || v.knownExploited || ['HIGH', 'CRITICAL'].includes(v.severity)).length} high/critical or known-exploited findings; review linked applicability evidence`);
  if (life.state !== 'supported') result.reasons.push(life.note);
  if (result.status === 'green') result.reasons.push(`Supported; no high or critical CVEs found in ${sourceLabel}`);
  result.assessmentSource = sourceLabel;
  return result;
}

async function refresh() {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    logger.log('info', 'Scan started');
    const apps = parseInventory(await readFile(path.join(configDirectory, 'applications.yaml'), 'utf8'));
    const owners = await readOwners(ownerFile);
    const workspaces = parseWorkspaces(await readFile(path.join(configDirectory, 'workspaces.yaml'), 'utf8'), apps, owners);
    const feeds = await readFeeds(feedFile);
    const feedCache = await collectFeeds(feeds, feedCacheFile, { onEvent: logger.feed });
    let kev = new Set();
    let kevError = null;
    try {
      if (!apps.length) return storeSnapshot({ checkedAt: new Date().toISOString(), results: [], workspaces, owners, warning: null, inventoryCount: 0 });
      const data = await fetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      kev = new Set(data.vulnerabilities.map(v => v.cveID));
    } catch (error) { logger.feed('error', 'CISA KEV unavailable', error.message); kevError = `CISA KEV unavailable: ${error.message}`; }
    const results = [];
    for (const app of apps) {
      const associatedFeeds = feeds.filter(feed => feed.enabled && feed.applicationIds.includes(app.id));
      const associated = associatedFeeds.flatMap(feed => feedCache.feeds[feed.id]?.entries || []);
      const feedErrors = associatedFeeds.filter(feed => feedCache.feeds[feed.id]?.status === 'error').map(feed => `${feed.name}: ${feedCache.feeds[feed.id].error}`);
      results.push(await scanApp(app, kev, associated, feedErrors));
    }
    for (const app of results) {
      if (kevError) { app.reasons.push(kevError); if (app.status !== 'red') app.status = 'unknown'; }
      else app.sources.push({ name: 'CISA Known Exploited Vulnerabilities', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' });
    }
    const saved = await storeSnapshot({ checkedAt: new Date().toISOString(), results, workspaces, owners, feedSummary: { total: feeds.length, errors: Object.values(feedCache.feeds).filter(item => item.status === 'error').length }, warning: kevError, inventoryCount: apps.length });
    logger.log('info', 'Scan completed', `${results.length} applications; ${results.filter(app => app.status === 'unknown').length} unknown`);
    return saved;
  })().catch(error => { logger.log('error', 'Scan failed', error.message); throw error; }).finally(() => { refreshPromise = null; });
  return refreshPromise;
}

async function refreshApplication(appId) {
  if (refreshPromise) await refreshPromise;
  if (!snapshot) snapshot = { results: [], checkedAt: new Date().toISOString(), workspaces: [], owners: [], inventoryCount: 0 };
  refreshPromise = (async () => {
    const apps = parseInventory(await readFile(path.join(configDirectory, 'applications.yaml'), 'utf8'));
    const owners = await readOwners(ownerFile);
    const workspaces = parseWorkspaces(await readFile(path.join(configDirectory, 'workspaces.yaml'), 'utf8'), apps, owners);
    const app = apps.find(item => item.id === appId);
    if (!app) {
      const saved = await storeSnapshot({ ...snapshot, checkedAt: new Date().toISOString(), results: (snapshot.results || []).filter(item => item.id !== appId), workspaces, owners, inventoryCount: apps.length });
      return saved;
    }
    logger.log('info', 'Application scan started', app.name);
    const feeds = await readFeeds(feedFile);
    const associatedFeeds = feeds.filter(feed => feed.enabled && feed.applicationIds.includes(app.id));
    const feedCache = associatedFeeds.length ? await collectFeeds(associatedFeeds, feedCacheFile, { preserveUnlisted: true, onEvent: logger.feed }) : await readFeedCache();
    const associated = associatedFeeds.flatMap(feed => feedCache.feeds?.[feed.id]?.entries || []);
    const feedErrors = associatedFeeds.filter(feed => feedCache.feeds?.[feed.id]?.status === 'error').map(feed => `${feed.name}: ${feedCache.feeds[feed.id].error}`);
    let kev = new Set();
    let kevError = null;
    try {
      const data = await fetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      kev = new Set(data.vulnerabilities.map(item => item.cveID));
    } catch (error) { logger.feed('error', 'CISA KEV unavailable', error.message); kevError = `CISA KEV unavailable: ${error.message}`; }
    const result = await scanApp(app, kev, associated, feedErrors);
    if (kevError) { result.reasons.push(kevError); if (result.status !== 'red') result.status = 'unknown'; }
    else result.sources.push({ name: 'CISA Known Exploited Vulnerabilities', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' });
    const previousResults = snapshot.results || [];
    const results = previousResults.some(item => item.id === app.id) ? previousResults.map(item => item.id === app.id ? result : item) : [...previousResults, result];
    const saved = await storeSnapshot({ ...snapshot, checkedAt: new Date().toISOString(), results, workspaces, owners, inventoryCount: apps.length, feedSummary: { total: feeds.length, errors: Object.values(feedCache.feeds || {}).filter(item => item.status === 'error').length } });
    logger.log('info', 'Application scan completed', app.name);
    return saved;
  })().catch(error => { logger.log('error', 'Application scan failed', `${appId}: ${error.message}`); throw error; }).finally(() => { refreshPromise = null; });
  return refreshPromise;
}

const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
const requestHandler = async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=(), payment=(), usb=()');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname === '/healthz' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end('{"status":"ok"}'); return;
    }
    const acknowledgement = url.pathname.match(/^\/ack\/([A-Za-z0-9_-]{43})$/);
    if (acknowledgement && ['GET', 'POST'].includes(req.method)) {
      const token = acknowledgement[1];
      const entry = await notifier.lookup(token);
      if (!entry) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }); res.end('Alert link is no longer active.'); return; }
      const confirmed = req.method === 'POST' ? await notifier.acknowledge(token) : false;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' }); res.end(acknowledgePage(entry, confirmed)); return;
    }
    if (auth && await auth.handle(req, res, url)) return;
    attachPermissionPreview(req);
    const previewExit = url.pathname === '/api/rbac/preview' && req.method === 'DELETE';
    if (req.permissionPreview && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !previewExit) {
      forbidden(res, 'Permission Preview is read-only. Exit preview to make changes.'); return;
    }
    if (url.pathname === '/api/session' && req.method === 'GET') {
      const { access } = await authorization(req);
      const real = await realAuthorization(req);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ enabled: Boolean(auth), user: req.authUser?.name || 'Local development session', isAdmin: access.isAdmin, canManageAccess: access.accessManage, claims: real.access.isAdmin ? req.authUser?.claims : undefined, groupOverage: Boolean(req.authUser?.groupOverage), preview: req.permissionPreview ? { name: req.permissionPreview.name, mappingIds: req.permissionPreview.mappingIds, expires: new Date(req.permissionPreview.expires).toISOString() } : null })); return;
    }
    if ((url.pathname.startsWith('/api/settings') || url.pathname.startsWith('/api/notification-policies') || url.pathname === '/api/logs') && !(await authorization(req)).access.isAdmin) { forbidden(res, 'Administrator role required'); return; }
    if (url.pathname === '/api/rbac/preview' && req.method === 'DELETE') {
      const preview = req.permissionPreview;
      if (req.permissionPreviewToken) permissionPreviews.delete(req.permissionPreviewToken);
      if (preview) await logger.audit('Permission Preview exited', auditActor(req), { type: 'rbac-preview', id: preview.id }, { identityMappings: preview.mappingIds }, preview.name);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Set-Cookie': previewCookie(req, '', 0) }); res.end(JSON.stringify({ preview: null })); return;
    }
    if (url.pathname === '/api/settings' && req.method === 'GET') {
      const smtp = await readSmtpSettings(smtpFile);
      const configuredGeneral = await readGeneralSettings(generalFile);
      const general = configuredGeneral.host ? configuredGeneral : detectedGeneral(req);
      const password = await smtpPasswordState(process.env);
      const envStatus = { usernamePresent: Boolean(smtp.usernameEnv && process.env[smtp.usernameEnv]), passwordFileConfigured: password.configured, passwordPresent: password.present };
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ version: applicationVersion, smtp, general, generalConfigured: Boolean(configuredGeneral.host), envStatus })); return;
    }
    if (url.pathname === '/api/logs' && req.method === 'GET') {
      const type = url.searchParams.get('type') || 'system';
      if (!logTypes.includes(type)) { res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify({ error: 'Unknown log type' })); return; }
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ type, entries: await logger.recent(type) })); return;
    }
    if (url.pathname === '/api/settings' && req.method === 'POST') {
      const body = await readBody(req);
      const smtpInput = validateSmtpSettings(body.smtp);
      if (smtpInput.enabled && !smtpInput.unauthenticated && !(await smtpPasswordState(process.env)).present) throw new Error('Authenticated email requires SMTP_PASSWORD_FILE to reference a readable, nonempty secret file');
      const generalInput = validateGeneralSettings(body.general);
      if (!generalInput.host) throw new Error('General hostname and web port are required');
      const previousSmtp = await readSmtpSettings(smtpFile);
      const previousGeneral = await readGeneralSettings(generalFile);
      const smtp = await yamlMonitor.webWrite(smtpFile, () => writeSmtpSettings(smtpFile, smtpInput));
      const general = await yamlMonitor.webWrite(generalFile, () => writeGeneralSettings(generalFile, generalInput));
      const smtpFieldsChanged = Object.keys(changedFields(previousSmtp, smtp, Object.keys(smtp)));
      const publicAddress = changedFields({ url: generalUrl(previousGeneral) }, { url: generalUrl(general) }, ['url']);
      if (smtpFieldsChanged.length || Object.keys(publicAddress).length) {
        const changes = { publicAddress, smtpFieldsChanged, emailDelivery: { from: previousSmtp.enabled, to: smtp.enabled } };
        const detail = [Object.keys(publicAddress).length ? `Public address: ${describeFields(publicAddress)}` : '', smtpFieldsChanged.length ? `Email fields changed: ${smtpFieldsChanged.join(', ')}` : ''].filter(Boolean).join('; ');
        await logger.audit('Settings updated', auditActor(req), { type: 'settings', id: 'general-and-email' }, changes, detail);
      }
      if (snapshot) notifier.onScan(snapshot).catch(error => console.error(`Notification check failed: ${error.message}`));
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify({ smtp, general })); return;
    }
    if (url.pathname === '/api/settings/test-email' && req.method === 'POST') {
      const body = await readBody(req);
      const smtp = validateSmtpSettings({ ...(body.smtp || {}), enabled: true });
      let result;
      try {
        result = await sendTestEmail(smtp, body.recipient);
        await logger.notification({ outcome: 'accepted', message: 'Test email accepted', deliveryType: 'test', workspace: '', applications: [], policies: [], reasons: ['SMTP configuration test'], recipients: [{ name: 'Test recipient', email: String(body.recipient), route: 'test' }], accepted: result.accepted, rejected: [], messageId: result.messageId });
      } catch (error) {
        await logger.notification({ outcome: 'failed', message: 'Test email failed', deliveryType: 'test', workspace: '', applications: [], policies: [], reasons: ['SMTP configuration test'], recipients: [{ name: 'Test recipient', email: String(body.recipient || ''), route: 'test' }], accepted: [], rejected: [], error: String(error.message || 'Delivery failed').slice(0, 500) });
        throw error;
      }
      await logger.audit('Test email sent', auditActor(req), { type: 'settings', id: 'email-delivery' }, { transportSecurity: smtp.secure ? 'tls' : smtp.requireTls ? 'starttls' : 'none', unauthenticated: smtp.unauthenticated }, 'SMTP test completed successfully; settings were not saved');
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ sent: true, accepted: result.accepted })); return;
    }
    if (url.pathname === '/api/notification-policies' && req.method === 'GET') {
      const { apps, workspaces, owners } = await authorizationResources();
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ policies: await readNotificationPolicies(notificationPolicyFile), options: notificationPolicyOptions, workspaces: workspaces.map(({ id, name }) => ({ id, name })), owners: owners.map(({ id, name, email }) => ({ id, name, email })), applications: apps.map(({ id, name }) => ({ id, name })) })); return;
    }
    if (url.pathname === '/api/notification-policies/preview' && req.method === 'POST') {
      const body = await readBody(req);
      const { workspaces, owners } = await authorizationResources();
      const policy = validateNotificationPolicy(body.policy, { workspaces, owners });
      const preview = previewNotificationPolicy(policy, snapshot);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ policy, ...preview })); return;
    }
    if (url.pathname === '/api/notification-policies' && req.method === 'PUT') {
      const body = await readBody(req);
      const { workspaces, owners } = await authorizationResources();
      const previous = await readNotificationPolicies(notificationPolicyFile);
      const policies = validateNotificationPolicies(body.policies, { workspaces, owners });
      await writeNotificationPolicies(notificationPolicyFile, policies);
      const actor = auditActor(req);
      const resources = { workspaces, owners };
      const previousById = new Map(previous.map(policy => [policy.id, policy]));
      const currentById = new Map(policies.map(policy => [policy.id, policy]));
      for (const policy of policies) {
        const oldPolicy = previousById.get(policy.id);
        if (!oldPolicy) {
          const configured = policyAuditView(policy, resources);
          await logger.audit('Notification policy added', actor, { type: 'notification-policy', id: policy.id, name: policy.name }, configured, `${policy.name}; ${Object.entries(configured).filter(([field]) => field !== 'name').map(([field, value]) => `${policyAuditLabels[field]}: ${value}`).join('; ')}`);
          continue;
        }
        const changes = policyAuditChanges(oldPolicy, policy, resources);
        if (Object.keys(changes).length) await logger.audit('Notification policy updated', actor, { type: 'notification-policy', id: policy.id, name: policy.name }, changes, `${policy.name}; ${describePolicyAuditChanges(changes)}`);
      }
      for (const policy of previous) {
        if (currentById.has(policy.id)) continue;
        const configured = policyAuditView(policy, resources);
        await logger.audit('Notification policy removed', actor, { type: 'notification-policy', id: policy.id, name: policy.name }, configured, `${policy.name}; removed policy configuration: ${Object.entries(configured).filter(([field]) => field !== 'name').map(([field, value]) => `${policyAuditLabels[field]}: ${value}`).join('; ')}`);
      }
      if (snapshot) notifier.onScan(snapshot).catch(error => logger.log('error', 'Notification check after policy update failed', error.message));
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify({ policies })); return;
    }
    if (url.pathname === '/api/config' && req.method === 'GET') {
      const { apps, workspaces, feeds, owners, access } = await authorization(req);
      const visibleApps = apps.filter(app => access.appView.has(app.id) || access.appEdit.has(app.id));
      const visibleWorkspaces = workspaces.filter(group => access.workspaceView.has(group.id) || access.workspaceEdit.has(group.id) || access.workspaceMembership.has(group.id) || access.workspaceNotifications.has(group.id));
      const visibleFeeds = feeds.filter(feed => access.feedView.has(feed.id));
      const assignedOwnerIds = new Set(visibleApps.flatMap(app => app.ownerIds));
      const visibleOwners = owners.filter(owner => assignedOwnerIds.has(owner.id) || access.isAdmin || access.appEdit.size || access.workspaceNotifications.size);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ applications: visibleApps, workspaces: visibleWorkspaces, feeds: visibleFeeds, owners: visibleOwners, access: accessJson(access) })); return;
    }
    if (url.pathname === '/api/owners' && req.method === 'GET') {
      if (!req.authUser?.isAdmin && auth) { forbidden(res, 'Administrator role required to manage owners'); return; }
      const owners = await readOwners(ownerFile);
      const apps = parseInventory(await readFile(path.join(configDirectory, 'applications.yaml'), 'utf8'), true);
      const workspaces = parseWorkspaces(await readFile(path.join(configDirectory, 'workspaces.yaml'), 'utf8'), apps.filter(app => app.enabled !== false), owners);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ owners: owners.map(owner => ({ ...owner, applicationCount: apps.filter(app => app.ownerIds.includes(owner.id)).length, workspaceCount: workspaces.filter(group => group.ownerIds.includes(owner.id)).length })) })); return;
    }
    if (url.pathname === '/api/owners' && req.method === 'POST') {
      const { access } = await authorization(req);
      if (!canCreateOwner(access)) { forbidden(res, 'Application Editor or Notification Manager role required to add owners'); return; }
      const owners = await readOwners(ownerFile);
      const owner = validateOwner(await readBody(req));
      if (owners.some(item => item.name.toLowerCase() === owner.name.toLowerCase())) throw new Error('Owner name already exists');
      if (owners.some(item => item.email.toLowerCase() === owner.email.toLowerCase())) throw new Error('An owner with this email already exists. Select the existing owner instead.');
      await yamlMonitor.webWrite(ownerFile, () => writeOwners(ownerFile, [...owners, owner]));
      await logger.audit('Owner added', auditActor(req), { type: 'owner', id: owner.id, name: owner.name }, { name: owner.name, emailConfigured: true, escalationEmailConfigured: Boolean(owner.escalationEmail) }, `${owner.name} (${owner.id})`);
      res.writeHead(201, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(owner)); return;
    }
    const ownerRoute = url.pathname.match(/^\/api\/owners\/([0-9a-f-]+)$/i);
    if (ownerRoute && req.method === 'PUT') {
      if (!req.authUser?.isAdmin && auth) { forbidden(res, 'Administrator role required to update owners'); return; }
      const owners = await readOwners(ownerFile);
      const index = owners.findIndex(owner => owner.id === ownerRoute[1]);
      if (index < 0) throw new Error('Owner not found');
      const previous = owners[index];
      const owner = validateOwner(await readBody(req), previous.id);
      if (owners.some((item, ownerIndex) => ownerIndex !== index && item.name.toLowerCase() === owner.name.toLowerCase())) throw new Error('Owner name already exists');
      if (owners.some((item, ownerIndex) => ownerIndex !== index && item.email.toLowerCase() === owner.email.toLowerCase())) throw new Error('An owner with this email already exists. Select the existing owner instead.');
      owners[index] = owner;
      await yamlMonitor.webWrite(ownerFile, () => writeOwners(ownerFile, owners));
      const changes = changedFields(previous, owner, ['name']);
      if (previous.email !== owner.email) changes.emailChanged = true;
      if (previous.escalationEmail !== owner.escalationEmail) changes.escalationEmailChanged = true;
      if (Object.keys(changes).length) await logger.audit('Owner updated', auditActor(req), { type: 'owner', id: owner.id, name: owner.name }, changes, `${owner.name} (${owner.id}); ${describeFields(changes)}`);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(owner)); return;
    }
    if (ownerRoute && req.method === 'DELETE') {
      if (!req.authUser?.isAdmin && auth) { forbidden(res, 'Administrator role required to remove owners'); return; }
      const owners = await readOwners(ownerFile);
      const owner = owners.find(item => item.id === ownerRoute[1]);
      if (!owner) throw new Error('Owner not found');
      const apps = parseInventory(await readFile(path.join(configDirectory, 'applications.yaml'), 'utf8'), true);
      const workspaces = parseWorkspaces(await readFile(path.join(configDirectory, 'workspaces.yaml'), 'utf8'), apps, owners);
      const assigned = apps.filter(app => app.ownerIds.includes(owner.id));
      const assignedWorkspaces = workspaces.filter(group => group.ownerIds.includes(owner.id));
      if (assigned.length || assignedWorkspaces.length) throw new Error(`Owner is assigned to ${assigned.length} application${assigned.length === 1 ? '' : 's'} and ${assignedWorkspaces.length} workspace${assignedWorkspaces.length === 1 ? '' : 's'} and cannot be removed`);
      await yamlMonitor.webWrite(ownerFile, () => writeOwners(ownerFile, owners.filter(item => item.id !== owner.id)));
      await logger.audit('Owner removed', auditActor(req), { type: 'owner', id: owner.id, name: owner.name }, { name: owner.name }, `${owner.name} (${owner.id})`);
      res.writeHead(204); res.end(); return;
    }
    if (url.pathname === '/api/rbac' && req.method === 'GET') {
      const { apps, workspaces, feeds, access } = await authorization(req);
      if (!access.accessManage) { forbidden(res, 'Access Administrator role required'); return; }
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ ...await readRbac(rbacFile), roles: standardRoles, applications: apps, workspaces, feeds, session: { name: req.permissionPreview?.name || req.authUser?.name || 'Local development session', claims: req.permissionPreview?.claims || req.authUser?.claims || {}, groupOverage: req.permissionPreview ? false : Boolean(req.authUser?.groupOverage) } })); return;
    }
    if (url.pathname === '/api/rbac/evaluate' && req.method === 'POST') {
      const { apps, workspaces, feeds, access } = await realAuthorization(req);
      if (!access.accessManage) { forbidden(res, 'Access Administrator role required'); return; }
      const body = await readBody(req);
      const config = selectedPreviewConfig(validateRbacInput(body.config, apps, workspaces, feeds), body.grantIds);
      const explanation = explainAccess(config, body.mappingIds, apps, workspaces, feeds);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(explanation)); return;
    }
    if (url.pathname === '/api/rbac/preview' && req.method === 'POST') {
      const { apps, workspaces, feeds, access } = await realAuthorization(req);
      if (!access.accessManage) { forbidden(res, 'Access Administrator role required'); return; }
      const body = await readBody(req);
      const config = selectedPreviewConfig(validateRbacInput(body.config, apps, workspaces, feeds), body.grantIds);
      const explanation = explainAccess(config, body.mappingIds, apps, workspaces, feeds);
      const name = String(body.name || explanation.selectedMappings.map(item => item.name).join(' + ') || 'No matched identity').trim().slice(0, 160);
      const token = randomBytes(32).toString('base64url');
      const preview = { id: randomUUID(), actorKey: previewActorKey(req), name, mappingIds: explanation.selectedMappings.map(item => item.id), claims: claimsForIdentityMappings(config, body.mappingIds), config, expires: Date.now() + previewLifetime };
      permissionPreviews.set(token, preview);
      await logger.audit('Permission Preview started', auditActor(req), { type: 'rbac-preview', id: preview.id }, { identityMappings: preview.mappingIds }, name);
      res.writeHead(201, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Set-Cookie': previewCookie(req, token, previewLifetime / 1000) }); res.end(JSON.stringify({ preview: { name, mappingIds: preview.mappingIds, expires: new Date(preview.expires).toISOString() }, explanation })); return;
    }
    if (url.pathname === '/api/rbac' && req.method === 'POST') {
      const { apps, workspaces, feeds, access } = await realAuthorization(req);
      if (!access.accessManage) { forbidden(res, 'Access Administrator role required'); return; }
      const previous = await readRbac(rbacFile);
      const config = validateRbacInput(await readBody(req), apps, workspaces, feeds);
      if (!access.isAdmin && protectedRoleState(previous, 'access-administrator') !== protectedRoleState(config, 'access-administrator')) { forbidden(res, 'Only a protected administrator can change Access Administrator assignments'); return; }
      await yamlMonitor.webWrite(rbacFile, () => writeRbac(rbacFile, config));
      await logger.audit('Access control updated', auditActor(req), { type: 'rbac', id: 'access-control' }, { groups: { from: previous.groups.length, to: config.groups.length }, grants: { from: previous.grants.length, to: config.grants.length } }, `${config.groups.length} identity mappings; ${config.grants.length} grants`);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(config)); return;
    }
    if (url.pathname === '/api/cpes' && req.method === 'GET') {
      const { access } = await authorization(req);
      if (!access.isAdmin && !access.appEdit.size) { forbidden(res, 'Application Editor role required'); return; }
      const allowed = ['any', 'part', 'vendor', 'product', 'version', 'edition'];
      const filters = Object.fromEntries(allowed.map(name => [name, String(url.searchParams.get(name) || (name === 'any' ? url.searchParams.get('q') || '' : '')).trim()]));
      if (!Object.values(filters).some(Boolean)) throw new Error('Enter at least one CPE search field');
      for (const value of Object.values(filters)) if (value.length > 100 || /[\u0000-\u001f]/.test(value)) throw new Error('CPE search fields must contain at most 100 printable characters');
      if (filters.part && !['a', 'o', 'h'].includes(filters.part)) throw new Error('CPE part must be a, o, or h');
      const startIndex = Math.max(0, Number.parseInt(url.searchParams.get('startIndex') || '0', 10) || 0);
      const pageSize = 50;
      const api = new URL('https://services.nvd.nist.gov/rest/json/cpes/2.0');
      const keywords = [filters.any, filters.vendor, filters.product, filters.version, filters.edition].filter(value => value.length >= 2).join(' ');
      if (keywords) api.searchParams.set('keywordSearch', keywords);
      api.searchParams.set('resultsPerPage', String(pageSize));
      api.searchParams.set('startIndex', String(startIndex));
      const data = await fetchNvdJson(api);
      const results = (data.products || []).map(product => {
        const name = product.cpe?.cpeName || '';
        let parsed;
        try { parsed = parseCpe23(name); } catch { return null; }
        const replacements = (product.cpe?.deprecatedBy || []).map(item => typeof item === 'string' ? item : item.cpeName).filter(Boolean);
        return { ...parsed, title: product.cpe?.titles?.find(item => item.lang === 'en')?.title || name, deprecated: Boolean(product.cpe?.deprecated), replacements };
      }).filter(Boolean).filter(item => cpeSearchMatch(item, filters)).filter(item => url.searchParams.get('includeDeprecated') === 'true' || !item.deprecated);
      const rawEnd = startIndex + (data.products || []).length;
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ results, startIndex, resultsPerPage: pageSize, totalResults: data.totalResults || 0, nextIndex: rawEnd < (data.totalResults || 0) ? rawEnd : null, previousIndex: startIndex > 0 ? Math.max(0, startIndex - pageSize) : null })); return;
    }
    if (url.pathname === '/api/cpes/parse' && req.method === 'POST') {
      const { access } = await authorization(req);
      if (!access.isAdmin && !access.appEdit.size) { forbidden(res, 'Application Editor role required'); return; }
      const body = await readBody(req);
      const mapping = { ...parseCpe23(body.cpeName), mode: body.mode === 'exact' ? 'exact' : 'product', deprecated: false };
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ mapping, effectiveCpe: effectiveCpe(mapping, mapping.mode), warnings: mappingWarnings(mapping, String(body.version || '')) })); return;
    }
    if (url.pathname === '/api/cpes/test' && req.method === 'POST') {
      const { access } = await authorization(req);
      if (!access.isAdmin && !access.appEdit.size) { forbidden(res, 'Application Editor role required'); return; }
      const body = await readBody(req);
      const mapping = { ...parseCpe23(body.cpeName), mode: body.mode === 'exact' ? 'exact' : 'product', deprecated: body.deprecated === true };
      const version = String(body.version || '').trim();
      if (!version || !idPattern.test(version)) throw new Error('Enter a valid installed version before testing the mapping');
      const app = { version, cpeName: mapping.cpeName, cpeMode: mapping.mode, cpeVendor: mapping.vendor, cpeProduct: mapping.product, cpeEdition: mapping.edition === '*' || mapping.edition === '-' ? '' : mapping.edition };
      const queryCpe = effectiveCpe(mapping, mapping.mode);
      const api = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
      api.searchParams.set('virtualMatchString', queryCpe);
      api.searchParams.set('resultsPerPage', '200');
      const data = await fetchNvdJson(api);
      const candidates = data.vulnerabilities || [];
      const applicable = candidates.filter(({ cve }) => cveAffectsApplication(cve, app));
      const sample = applicable.slice(0, 10).map(({ cve }) => ({ id: cve.id, published: cve.published, description: cve.descriptions?.find(item => item.lang === 'en')?.value || '', url: `https://nvd.nist.gov/vuln/detail/${cve.id}` }));
      const warnings = mappingWarnings(mapping, version);
      if (!data.totalResults) warnings.push({ code: 'no-candidates', level: 'warning', message: 'NVD returned no vulnerability candidates. This is inconclusive; verify the product mapping before saving.' });
      if ((data.totalResults || 0) > candidates.length) warnings.push({ code: 'sampled-results', level: 'info', message: `NVD returned ${data.totalResults} candidates; applicability was previewed against the first ${candidates.length}.` });
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ testedAt: new Date().toISOString(), queryCpe, candidateCount: data.totalResults || 0, testedCandidateCount: candidates.length, applicableCount: applicable.length, sample, warnings })); return;
    }
    if (url.pathname === '/api/lifecycle-products' && req.method === 'GET') {
      const { access } = await authorization(req);
      if (!access.isAdmin && !access.appEdit.size) { forbidden(res, 'Application Editor role required'); return; }
      const query = String(url.searchParams.get('q') || '').trim();
      const vendor = String(url.searchParams.get('vendor') || '').trim();
      const cpe = String(url.searchParams.get('cpe') || '').trim();
      const category = String(url.searchParams.get('category') || '').trim();
      for (const value of [query, vendor, cpe, category]) if (value.length > 200 || /[\u0000-\u001f]/.test(value)) throw new Error('Lifecycle search fields must contain at most 200 printable characters');
      const catalog = await lifecycleCatalog();
      const products = searchLifecycleProducts(catalog, { query, vendor, cpe, category }).slice(0, 50);
      const categories = [...new Set(catalog.map(item => String(item.category || '')).filter(Boolean))].sort();
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ products, categories })); return;
    }
    const lifecycleRoute = url.pathname.match(/^\/api\/lifecycle-products\/([A-Za-z0-9._-]+)$/);
    if (lifecycleRoute && req.method === 'GET') {
      const { access } = await authorization(req);
      if (!access.isAdmin && !access.appEdit.size) { forbidden(res, 'Application Editor role required'); return; }
      const product = await lifecycleProduct(lifecycleRoute[1]);
      const version = String(url.searchParams.get('version') || '').trim();
      const matchedRelease = matchLifecycleRelease(product.releases, version);
      const selectedCpe = String(url.searchParams.get('cpe') || '');
      const cpeIdentifiers = product.identifiers.filter(item => item.type === 'cpe').map(item => item.id);
      const cpeIdentity = selectedCpe ? cpeIdentifiers.some(item => selectedCpe.startsWith(`${item}:`) || selectedCpe === item) : null;
      const warnings = [];
      if (version && !matchedRelease) warnings.push({ level: 'warning', message: `Installed version ${version} did not match a known ${product.label} release cycle.` });
      if (selectedCpe && cpeIdentifiers.length && !cpeIdentity) warnings.push({ level: 'warning', message: 'The selected CPE does not match the CPE identifiers published for this lifecycle product.' });
      if (cpeIdentity) warnings.push({ level: 'info', message: 'The lifecycle product publishes an identifier matching the selected CPE.' });
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ product, matchedRelease, cpeIdentity, warnings, testedAt: new Date().toISOString(), sourceUrl: product.links.html || `https://endoflife.date/${product.name}` })); return;
    }
    if (url.pathname === '/api/feeds' && req.method === 'GET') {
      const { apps, feeds, access } = await authorization(req);
      const cache = await readFeedCache();
      const visible = feeds.filter(feed => access.feedView.has(feed.id)).map(feed => ({ ...feed, state: cache.feeds?.[feed.id] || { status: 'not-checked', entries: [] }, canEdit: access.feedEdit.has(feed.id) }));
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ feeds: visible, applications: apps.filter(app => access.appView.has(app.id) || access.appEdit.has(app.id)), canManage: access.feedManage })); return;
    }
    if (url.pathname === '/api/feeds' && req.method === 'POST') {
      const { apps, feeds, access } = await authorization(req);
      if (!access.feedManage) { forbidden(res, 'Feed Manager role required to add feeds'); return; }
      const feed = validateFeedInput(await readBody(req), apps);
      const updated = [...feeds, feed];
      await yamlMonitor.webWrite(feedFile, () => writeFeeds(feedFile, updated));
      await invalidateSnapshot();
      await logger.audit('Feed added', auditActor(req), { type: 'feed', id: feed.id, name: feed.name }, { categories: feed.categories, applicationIds: feed.applicationIds }, `${feed.name} (${feed.id})`);
      res.writeHead(201, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(feed)); return;
    }
    const feedRoute = url.pathname.match(/^\/api\/feeds\/([0-9a-f-]+)(?:\/(test|refresh))?$/i);
    if (feedRoute && req.method === 'POST' && feedRoute[2] === 'test') {
      const { feeds, access } = await authorization(req);
      const feed = feeds.find(item => item.id === feedRoute[1]);
      if (!feed) throw new Error('Feed not found');
      if (!access.feedEdit.has(feed.id)) { forbidden(res, 'Feed Editor role required'); return; }
      try {
        const response = await secureFetchText(feedRequestUrl(feed), { headers: feed.format === 'github' ? { Accept: 'application/vnd.github+json' } : {} });
        const entries = normalizeEntries(feed, response);
        await logger.feed('info', 'Feed test succeeded', `${feed.name}: ${entries.length} normalized entries`);
        await logger.audit('Feed tested', auditActor(req), { type: 'feed', id: feed.id, name: feed.name }, { entries: entries.length }, `${feed.name}; ${entries.length} normalized entries`);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ sourceUrl: response.url, entries: entries.slice(0, 25) })); return;
      } catch (error) {
        await logger.feed('error', 'Feed test failed', `${feed.name}: ${error.message}`);
        throw error;
      }
    }
    if (feedRoute && req.method === 'POST' && feedRoute[2] === 'refresh') {
      const { feeds, access } = await authorization(req);
      const feed = feeds.find(item => item.id === feedRoute[1]);
      if (!feed) throw new Error('Feed not found');
      if (!access.feedEdit.has(feed.id)) { forbidden(res, 'Feed Editor role required'); return; }
      if (refreshPromise) await refreshPromise;
      const cache = await collectFeeds([feed], feedCacheFile, { preserveUnlisted: true, onEvent: logger.feed });
      const state = cache.feeds[feed.id];
      await invalidateSnapshot();
      await logger.audit('Feed collected', auditActor(req), { type: 'feed', id: feed.id, name: feed.name }, { status: state.status, entries: state.entries?.length || 0 }, `${feed.name}; ${state.status}; ${state.entries?.length || 0} cached entries`);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ state })); return;
    }
    if (feedRoute && !feedRoute[2] && req.method === 'PUT') {
      const { apps, feeds, access } = await authorization(req);
      const index = feeds.findIndex(item => item.id === feedRoute[1]);
      if (index < 0) throw new Error('Feed not found');
      if (!access.feedEdit.has(feedRoute[1])) { forbidden(res, 'Feed Editor role required'); return; }
      const previous = feeds[index];
      const feed = validateFeedInput(await readBody(req), apps, previous.id);
      if (!access.feedManage && JSON.stringify(feed.applicationIds) !== JSON.stringify(previous.applicationIds)) { forbidden(res, 'Feed Manager role required to change associations from the feed editor'); return; }
      feeds[index] = feed;
      await yamlMonitor.webWrite(feedFile, () => writeFeeds(feedFile, feeds));
      await invalidateSnapshot();
      const changes = changedFields(previous, feed, ['name', 'url', 'format', 'enabled', 'categories', 'productAliases', 'applicationIds']);
      await logger.audit('Feed updated', auditActor(req), { type: 'feed', id: feed.id, name: feed.name }, changes, `${feed.name} (${feed.id}); ${Object.keys(changes).join(', ') || 'no fields changed'}`);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(feed)); return;
    }
    if (feedRoute && !feedRoute[2] && req.method === 'DELETE') {
      const { feeds, access } = await authorization(req);
      if (!access.feedManage) { forbidden(res, 'Feed Manager role required to remove feeds'); return; }
      const feed = feeds.find(item => item.id === feedRoute[1]);
      if (!feed) throw new Error('Feed not found');
      const rbac = await readRbac(rbacFile);
      if (rbac.grants.some(grant => grant.scopeType === 'feed' && grant.resourceIds.includes(feed.id))) throw new Error('Remove feed grants before deleting this feed');
      await yamlMonitor.webWrite(feedFile, () => writeFeeds(feedFile, feeds.filter(item => item.id !== feed.id)));
      await invalidateSnapshot();
      await logger.audit('Feed removed', auditActor(req), { type: 'feed', id: feed.id, name: feed.name }, { applicationIds: feed.applicationIds }, `${feed.name} (${feed.id})`);
      res.writeHead(204); res.end(); return;
    }
    const findingHistoryRoute = url.pathname.match(/^\/api\/applications\/([0-9a-f-]+)\/findings\/(.+)\/history$/i);
    if (findingHistoryRoute && req.method === 'GET') {
      const applicationId = findingHistoryRoute[1];
      const findingId = decodeURIComponent(findingHistoryRoute[2]);
      const { apps, access } = await authorization(req);
      if (!access.appView.has(applicationId)) { forbidden(res); return; }
      if (!apps.some(item => item.id === applicationId)) throw new Error('Application not found');
      const entries = await readFindingEvents(findingHistoryFile, applicationId, findingId);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ entries })); return;
    }
    const findingRoute = url.pathname.match(/^\/api\/applications\/([0-9a-f-]+)\/findings\/(.+)$/i);
    if (findingRoute && req.method === 'PUT') {
      await snapshotReady;
      const applicationId = findingRoute[1];
      const findingId = decodeURIComponent(findingRoute[2]);
      const { apps, access } = await authorization(req);
      if (!access.appEdit.has(applicationId)) { forbidden(res, 'Application Editor role required'); return; }
      const application = apps.find(item => item.id === applicationId);
      if (refreshPromise) await refreshPromise;
      await withFindingWrite(async () => {
        const liveApplication = snapshot?.results?.find(item => item.id === applicationId);
        const finding = liveApplication?.vulnerabilities?.find(item => item.id === findingId);
        if (!application || !finding) throw new Error('Active finding not found');
        const actor = auditActor(req);
        const store = await readFindingStore(findingStoreFile);
        const updated = updateFindingWorkflow(store, applicationId, findingId, await readBody(req), actor);
        if (updated.event) {
          await writeFindingStore(findingStoreFile, store);
          await appendFindingEvents(findingHistoryFile, [updated.event]);
          finding.workflow = updated.record;
          await saveAtomic(snapshotFile, `${JSON.stringify(snapshot)}\n`);
          await logger.audit('Finding workflow updated', actor, { type: 'finding', id: findingId, applicationId, applicationName: application.name }, updated.changes, `${application.name}: ${findingId} → ${updated.record.stateLabel}`);
        }
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(updated.record));
      }); return;
    }
    const appFeeds = url.pathname.match(/^\/api\/applications\/([0-9a-f-]+)\/feeds$/i);
    if (appFeeds && req.method === 'PUT') {
      const { feeds, access } = await authorization(req);
      if (!access.appEdit.has(appFeeds[1])) { forbidden(res, 'Application Editor role required'); return; }
      const body = await readBody(req);
      if (!Array.isArray(body.feedIds)) throw new Error('feedIds must be an array');
      const selected = [...new Set(body.feedIds.map(String))];
      if (selected.some(id => !access.feedView.has(id))) { forbidden(res, 'Feed Viewer role required for every selected feed'); return; }
      const changed = [];
      for (const feed of feeds) {
        if (!access.feedView.has(feed.id)) continue;
        const had = feed.applicationIds.includes(appFeeds[1]);
        const has = selected.includes(feed.id);
        if (had === has) continue;
        feed.applicationIds = has ? [...feed.applicationIds, appFeeds[1]] : feed.applicationIds.filter(id => id !== appFeeds[1]);
        changed.push(feed.id);
      }
      if (changed.length) {
        await yamlMonitor.webWrite(feedFile, () => writeFeeds(feedFile, feeds));
        await logger.audit('Application feed associations updated', auditActor(req), { type: 'application', id: appFeeds[1] }, { feedIds: selected }, `${changed.length} feed associations changed`);
      }
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify({ feedIds: selected })); return;
    }
    if (url.pathname === '/api/applications' && req.method === 'POST') {
      if (auth && !req.authUser?.isAdmin) { forbidden(res, 'Administrator role required to add applications'); return; }
      const app = cleanApp({ ...await readBody(req), id: randomUUID() });
      const owners = await readOwners(ownerFile);
      if (app.ownerIds.some(id => !owners.some(owner => owner.id === id))) throw new Error('Application references an unknown owner');
      if (refreshPromise) await refreshPromise;
      const file = path.join(configDirectory, 'applications.yaml');
      const current = await readFile(file, 'utf8');
      if (parseInventory(current, true).some(existing => existing.id === app.id)) throw new Error('Application ID already exists');
      await yamlMonitor.webWrite(file, () => saveAtomic(file, `${current.trimEnd()}\n${serializeApp({ ...app, enabled: true })}`));
      // Keep prior results available so the following application refresh can merge one scoped assessment.
      await logger.audit('Application added', auditActor(req), { type: 'application', id: app.id, name: app.name }, { name: app.name, version: app.version }, `${app.name} (${app.id}); installed version ${app.version}`);
      res.writeHead(201, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify({ id: app.id })); return;
    }
    const appEdit = url.pathname.match(/^\/api\/applications\/([A-Za-z0-9._-]+)$/);
    if (appEdit && req.method === 'PUT') {
      const previousId = appEdit[1];
      const { access } = await authorization(req);
      if (!access.appEdit.has(previousId)) { forbidden(res); return; }
      const app = cleanApp(await readBody(req), previousId);
      const owners = await readOwners(ownerFile);
      if (app.ownerIds.some(id => !owners.some(owner => owner.id === id))) throw new Error('Application references an unknown owner');
      if (refreshPromise) await refreshPromise;
      const file = path.join(configDirectory, 'applications.yaml');
      const current = await readFile(file, 'utf8');
      const inventory = parseInventory(current, true);
      const existing = inventory.find(item => item.id === previousId);
      if (!existing) throw new Error('Application not found');
      const lines = current.split(/\r?\n/);
      const start = lines.findIndex(line => { const match = line.match(/^  - id:\s*(.*)$/); return match && scalar(match[1]) === previousId; });
      if (start < 0) throw new Error('Application entry not found in YAML');
      let end = start + 1;
      while (end < lines.length && !/^  - [A-Za-z][\w]*:/.test(lines[end])) end++;
      const updated = { ...existing, ...app, legacyId: existing.legacyId || app.legacyId };
      lines.splice(start, end - start, ...serializeApp(updated).trimEnd().split('\n'));
      await yamlMonitor.webWrite(file, () => saveAtomic(file, `${lines.join('\n').trimEnd()}\n`));
      const changes = changedFields(existing, updated, appFields);
      if (Object.keys(changes).length) await logger.audit('Application updated', auditActor(req), { type: 'application', id: app.id, name: updated.name }, changes, `${updated.name} (${app.id}); ${describeFields(changes)}`);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify({ id: app.id, previousId })); return;
    }
    if (appEdit && req.method === 'DELETE') {
      const appId = appEdit[1];
      const { apps, workspaces, feeds, access } = await authorization(req);
      if (!canDeleteApplication(access)) { forbidden(res, 'Administrator role required to remove applications'); return; }
      const app = apps.find(item => item.id === appId);
      if (!app) throw new Error('Application not found');
      const body = await readBody(req);
      if (body.confirmation !== app.name) throw new Error(`Type the application name exactly to confirm deletion: ${app.name}`);
      const rbac = await readRbac(rbacFile);
      if (rbac.grants.some(grant => grant.scopeType === 'application' && grant.resourceIds.includes(app.id))) throw new Error('Remove application grants before deleting this application');
      if (refreshPromise) await refreshPromise;
      const remainingApps = apps.filter(item => item.id !== app.id);
      const affectedWorkspaces = workspaces.filter(group => group.applications.includes(app.id)).map(group => group.id);
      const affectedFeeds = feeds.filter(feed => feed.applicationIds.includes(app.id)).map(feed => feed.id);
      const updatedWorkspaces = workspaces.map(group => ({ ...group, applications: group.applications.filter(id => id !== app.id) }));
      const updatedFeeds = feeds.map(feed => ({ ...feed, applicationIds: feed.applicationIds.filter(id => id !== app.id) }));
      await saveRelatedFiles([
        { file: path.join(configDirectory, 'applications.yaml'), content: `# Application IDs, canonical CPE mappings, ownership, and risk context are managed by WatchTower.\napplications:\n${remainingApps.map(serializeApp).join('')}` },
        { file: path.join(configDirectory, 'workspaces.yaml'), content: serializeWorkspaces(updatedWorkspaces) },
        { file: feedFile, content: serializeFeeds(updatedFeeds) },
      ]);
      if (snapshot) {
        snapshot = { ...snapshot, results: (snapshot.results || []).filter(item => item.id !== app.id), workspaces: updatedWorkspaces, inventoryCount: remainingApps.filter(item => item.enabled !== false).length, feedSummary: { ...(snapshot.feedSummary || {}), total: updatedFeeds.length } };
        await saveAtomic(snapshotFile, `${JSON.stringify(snapshot)}\n`);
      }
      const changes = { workspaceIds: affectedWorkspaces, feedIds: affectedFeeds, workflowRecords: 'preserved' };
      await logger.audit('Application removed', auditActor(req), { type: 'application', id: app.id, name: app.name }, changes, `${app.name} (${app.id}); removed from ${affectedWorkspaces.length} workspaces and ${affectedFeeds.length} feeds; finding workflow records preserved`);
      res.writeHead(204); res.end(); return;
    }
    const inventoryRoute = url.pathname.match(/^\/api\/applications\/([0-9a-f-]+)\/(inventory|images|sboms)$/i);
    if (inventoryRoute && ['GET', 'PUT', 'POST'].includes(req.method)) {
      const applicationId = inventoryRoute[1];
      const { access, apps } = await authorization(req);
      if (!access.appView.has(applicationId) || (req.method !== 'GET' && !access.appEdit.has(applicationId))) { forbidden(res, 'Application access required'); return; }
      if (!apps.some(app => app.id === applicationId)) throw new Error('Application not found');
      let result;
      if (req.method !== 'GET' && refreshPromise) await refreshPromise;
      if (req.method === 'GET' && inventoryRoute[2] === 'inventory') result = await inventoryStore.read(applicationId);
      else if (req.method === 'PUT' && inventoryRoute[2] === 'images') {
        result = await inventoryStore.setImages(applicationId, (await readBody(req)).images, auditActor(req));
        await logger.audit('Application images updated', auditActor(req), { type: 'application', id: applicationId }, { images: result.images });
      } else if (req.method === 'POST' && inventoryRoute[2] === 'sboms') {
        if (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity') throw new Error('Compressed SBOM uploads are unsupported');
        const body = await readBody(req, sbomLimits.bytes + 100000);
        result = await inventoryStore.import(applicationId, body.sbom, body.imageId, auditActor(req));
        await logger.audit('SBOM imported', auditActor(req), { type: 'application', id: applicationId }, result, 'Inventory awaiting vulnerability assessment');
      } else { res.writeHead(405); res.end(); return; }
      res.writeHead(req.method === 'POST' ? 201 : 200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(result)); return;
    }
    const appRefresh = url.pathname.match(/^\/api\/applications\/([0-9a-f-]+)\/refresh$/i);
    if (appRefresh && req.method === 'POST') {
      await snapshotReady;
      const { access, owners } = await authorization(req);
      if (!canRefreshApplication(access, appRefresh[1])) { forbidden(res, 'Application Editor or Scan Operator access required'); return; }
      const data = await refreshApplication(appRefresh[1]);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(visibleSnapshot(data, owners, access, req))); return;
    }
    const workspaceEdit = url.pathname.match(/^\/api\/workspaces\/([A-Za-z0-9._-]+)$/);
    if ((url.pathname === '/api/workspaces' && req.method === 'POST') || (workspaceEdit && req.method === 'PUT')) {
      const body = await readBody(req);
      const previousId = workspaceEdit?.[1] || null;
      if (!previousId && auth && !req.authUser?.isAdmin) { forbidden(res, 'Administrator role required to add workspaces'); return; }
      const { access, owners } = await authorization(req);
      const id = previousId || randomUUID();
      const name = String(body.name ?? '').trim();
      if (!uuidPattern.test(id)) throw new Error('Workspace ID must be an immutable UUID');
      if (!name || /[\r\n]/.test(name)) throw new Error('Workspace name is required on one line');
      if (!Array.isArray(body.ownerIds)) throw new Error('Select owners for the workspace');
      const ownerIds = [...new Set(body.ownerIds.map(value => String(value)))];
      if (ownerIds.some(ownerId => !owners.some(owner => owner.id === ownerId))) throw new Error('Workspace contains an unknown owner');
      if (!Array.isArray(body.applications)) throw new Error('Select applications for the workspace');
      const membership = [...new Set(body.applications.map(value => String(value)))];
      const apps = parseInventory(await readFile(path.join(configDirectory, 'applications.yaml'), 'utf8'));
      if (membership.some(appId => !apps.some(app => app.id === appId))) throw new Error('Workspace contains an unknown application');
      if (refreshPromise) await refreshPromise;
      const file = path.join(configDirectory, 'workspaces.yaml');
      const groups = parseWorkspaces(await readFile(file, 'utf8'), apps, owners);
      const index = previousId ? groups.findIndex(group => group.id === previousId) : groups.findIndex(group => group.id === id);
      if (previousId && index < 0) throw new Error('Workspace not found');
      const previous = index < 0 ? null : groups[index];
      if (previous) {
        if (name !== previous.name && !access.workspaceEdit.has(id)) { forbidden(res, 'Workspace Manager role required to rename this workspace'); return; }
        if (JSON.stringify(membership) !== JSON.stringify(previous.applications) && !access.workspaceMembership.has(id)) { forbidden(res, 'Workspace Membership Manager role required'); return; }
        if (JSON.stringify(ownerIds) !== JSON.stringify(previous.ownerIds) && !access.workspaceNotifications.has(id)) { forbidden(res, 'Notification Manager role required'); return; }
      }
      const group = { id, legacyId: previous?.legacyId || '', name, ownerIds, applications: membership };
      if (index < 0) groups.push(group); else groups[index] = group;
      await yamlMonitor.webWrite(file, () => saveAtomic(file, serializeWorkspaces(groups)));
      if (snapshot) {
        snapshot = { ...snapshot, workspaces: groups, owners };
        await saveAtomic(snapshotFile, `${JSON.stringify(snapshot)}\n`);
      }
      if (previous) {
        const addedApplications = membership.filter(appId => !previous.applications.includes(appId));
        const removedApplications = previous.applications.filter(appId => !membership.includes(appId));
        const changes = { ...changedFields(previous, group, ['id', 'name']), addedApplications, removedApplications, ownerAssignmentsChanged: JSON.stringify(previous.ownerIds) !== JSON.stringify(group.ownerIds) };
        if (changes.name || addedApplications.length || removedApplications.length || changes.ownerAssignmentsChanged) {
          const detail = [changes.id || changes.name ? describeFields(Object.fromEntries(Object.entries({ id: changes.id, name: changes.name }).filter(([, value]) => value))) : '', addedApplications.length ? `Applications added: ${addedApplications.join(', ')}` : '', removedApplications.length ? `Applications removed: ${removedApplications.join(', ')}` : '', changes.ownerAssignmentsChanged ? 'Workspace owners changed' : ''].filter(Boolean).join('; ');
          await logger.audit('Workspace updated', auditActor(req), { type: 'workspace', id, name }, changes, `${name} (${id}); ${detail}`);
        }
      } else {
        await logger.audit('Workspace added', auditActor(req), { type: 'workspace', id, name }, { name, applications: membership, ownerIds }, `${name} (${id}); applications: ${membership.join(', ') || 'none'}; owners: ${ownerIds.length}`);
      }
      res.writeHead(index < 0 ? 201 : 200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify({ ...group, previousId: previousId || id })); return;
    }
    if (workspaceEdit && req.method === 'DELETE') {
      const workspaceId = workspaceEdit[1];
      const { workspaces, access } = await authorization(req);
      if (!access.workspaceEdit.has(workspaceId)) { forbidden(res, 'Workspace Manager role required to remove this workspace'); return; }
      const workspace = workspaces.find(item => item.id === workspaceId);
      if (!workspace) throw new Error('Workspace not found');
      const body = await readBody(req);
      if (body.confirmation !== workspace.name) throw new Error(`Type the workspace name exactly to confirm deletion: ${workspace.name}`);
      const rbac = await readRbac(rbacFile);
      if (rbac.grants.some(grant => grant.scopeType === 'workspace' && grant.resourceIds.includes(workspace.id))) throw new Error('Remove workspace grants before deleting this workspace');
      if (refreshPromise) await refreshPromise;
      const remainingWorkspaces = workspaces.filter(item => item.id !== workspace.id);
      const workspaceFile = path.join(configDirectory, 'workspaces.yaml');
      await yamlMonitor.webWrite(workspaceFile, () => saveAtomic(workspaceFile, serializeWorkspaces(remainingWorkspaces)));
      if (snapshot) {
        snapshot = { ...snapshot, workspaces: remainingWorkspaces };
        await saveAtomic(snapshotFile, `${JSON.stringify(snapshot)}\n`);
      }
      const changes = { applicationIds: workspace.applications, ownerIds: workspace.ownerIds, applicationsPreserved: true, workflowRecords: 'preserved' };
      await logger.audit('Workspace removed', auditActor(req), { type: 'workspace', id: workspace.id, name: workspace.name }, changes, `${workspace.name} (${workspace.id}); ${workspace.applications.length} applications preserved; finding workflow records preserved`);
      res.writeHead(204); res.end(); return;
    }
    if (url.pathname === '/api/status') {
      await snapshotReady;
      const { owners, access } = await authorization(req);
      if (url.searchParams.has('refresh') && !access.scan) { forbidden(res, 'Scan Operator role required'); return; }
      const data = !snapshot || Date.now() - new Date(snapshot.checkedAt).getTime() > refreshMs || url.searchParams.has('refresh') ? await refresh() : snapshot;
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(visibleSnapshot(data, owners, access, req))); return;
    }
    const replacementDownload = url.pathname.match(/^\/api\/sboms\/demo-(before|after)$/);
    if (replacementDownload && req.method === 'GET') {
      const stage = replacementDownload[1];
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': `attachment; filename="replacement-${stage}.cdx.json"`, 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(replacementDemo(stage), null, 2)); return;
    }
    if (url.pathname === '/api/sboms/demo' && req.method === 'GET') {
      const demo = { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [{ type: 'library', 'bom-ref': 'lodash', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' }] };
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="demo-sbom.cdx.json"', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(demo, null, 2)); return;
    }
    const files = { '/': 'index.html', '/styles.css': 'styles.css', '/theme-init.js': 'theme-init.js', '/app.js': 'app.js', '/favicon.svg': 'favicon.svg' };
    const file = files[url.pathname];
    if (!file) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': mime[path.extname(file)] }); res.end(await readFile(path.join(sourceDirectory, 'web', file)));
  } catch (error) { res.writeHead(['POST', 'PUT', 'DELETE'].includes(req.method) ? 400 : 500, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: error.message })); }
};

let server;
try {
  server = tlsConfiguration.enabled ? createHttpsServer(tlsConfiguration.options, requestHandler) : createHttpServer(requestHandler);
} catch (error) {
  throw new Error(`Native TLS initialization failed: ${error.code || error.message}`);
}
server.listen(PORT, HOST, () => {
  const listener = `${tlsConfiguration.protocol}://${HOST}:${PORT}`;
  console.log(`Vulnerability dashboard: ${listener}`);
  logger.log('info', 'Server started', `Listening on ${listener}`);
});

createInterface({ input: process.stdin }).on('line', line => {
  if (line.trim().toLowerCase() !== 'scan') return;
  refresh().then(data => console.log(`Scheduled scan complete: ${data.checkedAt}`)).catch(error => console.error(`Scheduled scan failed: ${error.message}`));
});

function scheduleNextHourlyScan() {
  const next = Math.floor(Date.now() / scanIntervalMs + 1) * scanIntervalMs;
  setTimeout(() => {
    scheduleNextHourlyScan();
    refresh().then(data => console.log(`Hourly scan complete: ${data.checkedAt}`)).catch(error => console.error(`Hourly scan failed: ${error.message}`));
  }, next - Date.now());
}

snapshotReady.then(() => {
  if (snapshot) notifier.onScan(snapshot).catch(error => console.error(`Notification check failed: ${error.message}`));
  if (process.env.AUTO_SCAN === 'false') return;
  scheduleNextHourlyScan();
  if (!snapshot || Date.now() - new Date(snapshot.checkedAt).getTime() >= refreshMs) {
    refresh().then(data => console.log(`Startup scan complete: ${data.checkedAt}`)).catch(error => console.error(`Startup scan failed: ${error.message}`));
  }
});
