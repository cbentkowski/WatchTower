import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { readFile, writeFile, rename, mkdir, rm, access, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import path from 'node:path';
import { createNotifier, sendTestEmail } from './notifications.mjs';
import { readSmtpSettings, writeSmtpSettings, validateSmtpSettings } from './settings.mjs';
import { readGeneralSettings, writeGeneralSettings, validateGeneralSettings, generalUrl } from './general.mjs';
import { createLogger } from './logger.mjs';
import { createAuth } from './auth.mjs';
import { createYamlMonitor } from './yaml-monitor.mjs';
import { readRbac, writeRbac, validateRbacInput, calculateAccess, accessJson, standardRoles } from './rbac.mjs';
import { collectFeeds, eventAffectsVersion, feedRequestUrl, normalizeEntries, readFeeds, secureFetchText, validateFeedInput, writeFeeds } from './feeds.mjs';
import { cveAffectsApplication, wildcardApplicationCpe } from './nvd.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const configDirectory = process.env.CONFIG_DIR || path.join(root, 'config');
const defaultConfigDirectory = process.env.DEFAULT_CONFIG_DIR || path.join(root, 'defaults');
const PORT = Number(process.env.SERVER_PORT || process.env.PORT || 4173);
const HOST = process.env.HOST || '127.0.0.1';
const dataDirectory = process.env.DATA_DIR || path.join(root, 'data');
const configFiles = ['applications.yaml', 'workspaces.yaml', 'feeds.yaml', 'smtp.yaml', 'general.yaml'];
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
if (!await exists(rbacFile)) await writeRbac(rbacFile, { groups: [], grants: [] });
const resourceMigration = await migrateResourceIds();
const logger = createLogger(dataDirectory);
const auth = createAuth();
if (!auth && process.env.AUTH_DISABLED !== 'true') throw new Error('OIDC is required. Configure OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_BASE_URL, and either OIDC_CLIENT_SECRET or OIDC_CLIENT_SECRET_FILE, or set AUTH_DISABLED=true for a private development instance.');
const snapshotFile = path.join(dataDirectory, 'status.json');
const feedCacheFile = path.join(dataDirectory, 'feeds.json');
const smtpFile = path.join(configDirectory, 'smtp.yaml');
const generalFile = path.join(configDirectory, 'general.yaml');
const notifier = createNotifier({ dataDirectory, settingsLoader: async () => ({ ...await readSmtpSettings(smtpFile), baseUrl: generalUrl(await readGeneralSettings(generalFile)) }) });
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
const snapshotReady = readFile(snapshotFile, 'utf8').then(raw => {
  const saved = JSON.parse(raw);
  if (saved.checkedAt && Array.isArray(saved.results) && Array.isArray(saved.workspaces)) snapshot = saved;
}).catch(error => { if (error.code !== 'ENOENT') console.warn(`Could not load saved scan: ${error.message}`); });
const yamlCheckInterval = Number(process.env.YAML_CHECK_INTERVAL_MS || 30_000);
const yamlMonitor = createYamlMonitor({
  files: {
    'applications.yaml': path.join(configDirectory, 'applications.yaml'),
    'workspaces.yaml': path.join(configDirectory, 'workspaces.yaml'),
    'feeds.yaml': feedFile,
    'smtp.yaml': smtpFile,
    'general.yaml': generalFile,
    'rbac.yaml': rbacFile,
  },
  intervalMs: Number.isFinite(yamlCheckInterval) && yamlCheckInterval > 0 ? yamlCheckInterval : 30_000,
  onChange: async changes => {
    const actor = { issuer: 'filesystem', subject: 'unknown', name: 'Filesystem change (unattributed)' };
    for (const change of changes) await logger.audit('YAML file changed outside web interface', actor, { type: 'yaml', id: change.name }, { kind: change.kind }, `${change.name} ${change.kind}`);
    if (changes.some(change => ['applications.yaml', 'workspaces.yaml', 'feeds.yaml'].includes(change.name))) {
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
  await mkdir(dataDirectory, { recursive: true });
  await saveAtomic(snapshotFile, `${JSON.stringify(data)}\n`);
  snapshot = data;
  notifier.onScan(data).catch(error => { console.error(`Notification check failed: ${error.message}`); logger.log('error', 'Notification check failed', error.message); });
  return data;
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
  for (const line of source.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#') || line.trim() === 'applications:') continue;
    const entry = line.match(/^  - ([A-Za-z][\w]*):\s*(.*)$/);
    const field = line.match(/^    ([A-Za-z][\w]*):\s*(.*)$/);
    if (entry) { current = {}; apps.push(current); current[entry[1]] = scalar(entry[2]); }
    else if (field && current) current[field[1]] = scalar(field[2]);
    else throw new Error(`Unsupported inventory YAML line: ${line}`);
  }
  for (const app of apps) {
    for (const key of ['id', 'name', 'version', 'cpeVendor', 'cpeProduct']) {
      if (!app[key] || typeof app[key] !== 'string') throw new Error(`Application is missing ${key}`);
    }
    if (!allowLegacyIds && !uuidPattern.test(app.id)) throw new Error(`Invalid immutable application ID for ${app.name}`);
    for (const key of ['version', 'cpeVendor', 'cpeProduct']) {
      if (!/^[A-Za-z0-9._-]+$/.test(app[key])) throw new Error(`Invalid ${key} for ${app.name}`);
    }
    if (app.cpeEdition && !/^[A-Za-z0-9._-]+$/.test(app.cpeEdition)) throw new Error(`Invalid cpeEdition for ${app.name}`);
  }
  if (new Set(apps.map(a => a.id)).size !== apps.length) throw new Error('Application IDs must be unique');
  return includeDisabled ? apps : apps.filter(a => a.enabled !== false);
}

const appFields = ['id', 'legacyId', 'name', 'vendor', 'version', 'cpeVendor', 'cpeProduct', 'cpeEdition', 'lifecycleProduct', 'eolDate', 'lifecycleUrl', 'vendorBulletinUrl', 'releaseUrl', 'latestVersion', 'latestBranchVersion', 'latestLtsVersion'];
const idPattern = /^[A-Za-z0-9._-]+$/;
function cleanApp(input, existingId = '') {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Application details are required');
  const app = Object.fromEntries(appFields.map(key => [key, String(key === 'id' && existingId ? existingId : input[key] ?? '').trim()]));
  for (const key of ['id', 'name', 'version', 'cpeVendor', 'cpeProduct']) if (!app[key]) throw new Error(`${key} is required`);
  if (!uuidPattern.test(app.id)) throw new Error('Application ID must be an immutable UUID');
  for (const key of ['version', 'cpeVendor', 'cpeProduct', 'cpeEdition', 'lifecycleProduct']) if (app[key] && !idPattern.test(app[key])) throw new Error(`${key} may contain only letters, numbers, dots, underscores, and hyphens`);
  if (!app.lifecycleProduct && !app.eolDate) throw new Error('A lifecycle product or end-of-life date is required');
  if (app.eolDate && (!/^\d{4}-\d{2}-\d{2}$/.test(app.eolDate) || !Number.isFinite(Date.parse(`${app.eolDate}T00:00:00Z`)))) throw new Error('End-of-life date must be YYYY-MM-DD');
  for (const key of ['lifecycleUrl', 'vendorBulletinUrl', 'releaseUrl']) if (app[key]) { try { if (new URL(app[key]).protocol !== 'https:') throw new Error(); } catch { throw new Error(`${key} must be an HTTPS URL`); } }
  for (const key of ['name', 'vendor']) if (/[\r\n]/.test(app[key])) throw new Error(`${key} must be one line`);
  return app;
}
function yamlValue(value) { return JSON.stringify(String(value)); }
function serializeApp(app) {
  return `  - id: ${app.id}\n${Object.entries(app).filter(([key, value]) => key !== 'id' && value !== '' && value != null).map(([key, value]) => `    ${key}: ${typeof value === 'boolean' ? value : yamlValue(value)}\n`).join('')}`;
}
function serializeWorkspaces(groups) {
  return `# Workspace names are free text. The same application may appear in multiple workspaces.\nworkspaces:\n${groups.map(group => `  - id: ${group.id}\n${group.legacyId ? `    legacyId: ${yamlValue(group.legacyId)}\n` : ''}    name: ${yamlValue(group.name)}\n${group.notificationEmails ? `    notificationEmails: ${yamlValue(group.notificationEmails)}\n` : ''}    applications:\n${group.applications.map(id => `      - ${id}\n`).join('')}`).join('')}`;
}
function auditActor(req) {
  if (!req.authUser) return { issuer: 'local', username: 'local', name: 'Local development session' };
  return { issuer: req.authUser.issuer, username: req.authUser.username || req.authUser.subject, name: req.authUser.name };
}
function changedFields(before, after, fields) {
  return Object.fromEntries(fields.filter(field => (before[field] ?? '') !== (after[field] ?? '')).map(field => [field, { from: before[field] ?? '', to: after[field] ?? '' }]));
}
function describeFields(changes) {
  return Object.entries(changes).map(([field, value]) => `${field}: ${JSON.stringify(value.from)} → ${JSON.stringify(value.to)}`).join('; ') || 'No values changed';
}
async function saveAtomic(file, content) {
  const temporary = `${file}.tmp`;
  await writeFile(temporary, content, 'utf8');
  await rename(temporary, file);
}
async function readBody(req) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 50000) throw new Error('Request is too large');
  }
  try { return JSON.parse(body); } catch { throw new Error('Invalid JSON'); }
}

async function readFeedCache() {
  try { return JSON.parse(await readFile(feedCacheFile, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return { checkedAt: null, feeds: {} }; throw error; }
}

function parseWorkspaces(source, apps, allowLegacyIds = false) {
  const groups = [];
  let current = null;
  let inApplications = false;
  for (const line of source.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#') || line.trim() === 'workspaces:') continue;
    const entry = line.match(/^  - id:\s*(.*)$/);
    const name = line.match(/^    name:\s*(.*)$/);
    const legacyId = line.match(/^    legacyId:\s*(.*)$/);
    const notificationEmails = line.match(/^    notificationEmails:\s*(.*)$/);
    const app = line.match(/^      - ([A-Za-z0-9._-]+)\s*$/);
    if (entry) { current = { id: scalar(entry[1]), applications: [] }; groups.push(current); inApplications = false; }
    else if (legacyId && current) current.legacyId = scalar(legacyId[1]);
    else if (name && current) current.name = scalar(name[1]);
    else if (notificationEmails && current) current.notificationEmails = scalar(notificationEmails[1]);
    else if (line === '    applications:' && current) inApplications = true;
    else if (app && current && inApplications) current.applications.push(app[1]);
    else throw new Error(`Unsupported workspace YAML line: ${line}`);
  }
  const known = new Set(apps.map(app => app.id));
  for (const group of groups) {
    if ((!allowLegacyIds && !uuidPattern.test(group.id || '')) || !group.name) throw new Error('Workspace needs an immutable UUID and name');
    group.notificationEmails ||= '';
    for (const id of group.applications) if (!known.has(id)) throw new Error(`Workspace ${group.name} references an unavailable application: ${id}`);
    group.applications = [...new Set(group.applications)];
  }
  if (new Set(groups.map(group => group.id)).size !== groups.length) throw new Error('Workspace IDs must be unique');
  return groups;
}

async function authorization(req, includeDisabled = true) {
  const apps = parseInventory(await readFile(path.join(configDirectory, 'applications.yaml'), 'utf8'), includeDisabled);
  const workspaces = parseWorkspaces(await readFile(path.join(configDirectory, 'workspaces.yaml'), 'utf8'), apps.filter(app => app.enabled !== false));
  const feeds = await readFeeds(feedFile);
  const access = calculateAccess(req.authUser || { issuer: 'local', isAdmin: true }, await readRbac(rbacFile), apps, workspaces, feeds);
  return { apps, workspaces, feeds, access };
}

function forbidden(res, message = 'You do not have permission to perform this action') {
  res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ error: message }));
}

async function migrateResourceIds() {
  const applicationFile = path.join(configDirectory, 'applications.yaml');
  const workspaceFile = path.join(configDirectory, 'workspaces.yaml');
  const applicationSource = await readFile(applicationFile, 'utf8');
  const workspaceSource = await readFile(workspaceFile, 'utf8');
  const applications = parseInventory(applicationSource, true, true);
  const workspaces = parseWorkspaces(workspaceSource, applications.filter(app => app.enabled !== false), true);
  const applicationIds = new Map();
  const workspaceIds = new Map();
  for (const app of applications) if (!uuidPattern.test(app.id)) { const previous = app.id; app.id = randomUUID(); app.legacyId ||= previous; applicationIds.set(previous, app.id); }
  for (const workspace of workspaces) {
    workspace.applications = workspace.applications.map(id => applicationIds.get(id) || id);
    if (!uuidPattern.test(workspace.id)) { const previous = workspace.id; workspace.id = randomUUID(); workspace.legacyId ||= previous; workspaceIds.set(previous, workspace.id); }
  }
  if (applicationIds.size) await saveAtomic(applicationFile, `# Application IDs are immutable UUIDs managed by WatchTower.\napplications:\n${applications.map(serializeApp).join('')}`);
  if (applicationIds.size || workspaceIds.size) await saveAtomic(workspaceFile, serializeWorkspaces(workspaces));
  if (applicationIds.size || workspaceIds.size) await rm(path.join(dataDirectory, 'status.json'), { force: true });
  return { applications: applicationIds, workspaces: workspaceIds };
}

async function fetchJson(url, timeout = 15000, headers = {}) {
  try {
    const response = await fetch(url, { headers: { 'User-Agent': 'VulnerabilityDashboard/1.0', Accept: 'application/json', ...headers }, signal: AbortSignal.timeout(timeout) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    logger.log('info', 'Feed request succeeded', String(url));
    return data;
  } catch (error) {
    logger.log('error', 'Feed request failed', `${url}: ${error.cause?.code || error.name || 'Error'}: ${error.message}`);
    throw error;
  }
}

async function fetchText(url, timeout = 15000) {
  try {
    const response = await fetch(url, { headers: { 'User-Agent': 'VulnerabilityDashboard/1.0' }, signal: AbortSignal.timeout(timeout) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.text();
    logger.log('info', 'Feed request succeeded', String(url));
    return data;
  } catch (error) {
    logger.log('error', 'Feed request failed', `${url}: ${error.cause?.code || error.name || 'Error'}: ${error.message}`);
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
  const cpe = `cpe:2.3:a:${app.cpeVendor}:${app.cpeProduct}:${app.version}:*:*:*:${app.cpeEdition || '*'}:*:*:*`;
  const result = { ...app, cpe, status: 'unknown', reasons: [], vulnerabilities: [], sources: [], checkedAt: new Date().toISOString() };
  let sourceOk = false;
  let sourceLabel = 'NVD';
  try {
    const vendor = app.cpeVendor === 'atlassian' ? await checkAtlassian(app, kev) : await checkGitlab(app, kev);
    if (vendor) {
      result.vulnerabilities = vendor.vulnerabilities;
      result.sources.push(vendor.source);
      sourceOk = true;
      sourceLabel = vendor.source.name;
      result.vendorConfirmed = true;
    }
  } catch (error) { logger.log('warn', 'Vendor assessment unavailable', `${app.name}: ${error.message}; using NVD fallback`); result.reasons.push(`Vendor check unavailable: ${error.message}; using NVD fallback`); }
  if (!sourceOk) try {
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
  } catch (error) { logger.log('error', 'NVD assessment unavailable', `${app.name}: ${error.message}`); result.reasons.push(`NVD check unavailable: ${error.message}`); }
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
    } catch (error) { logger.log('error', 'Lifecycle assessment unavailable', `${app.name}: ${error.message}`); life = { state: 'unknown', note: `Lifecycle check unavailable: ${error.message}` }; }
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
  const urgent = result.vulnerabilities.some(v => v.score >= 7 || v.knownExploited);
  result.status = urgent || life.state === 'expired' ? 'red' : !sourceOk || life.state === 'unknown' ? 'unknown' : life.state === 'approaching' ? 'yellow' : 'green';
  if (urgent) result.reasons.push(`${result.vulnerabilities.length} ${result.vendorConfirmed ? 'vendor-confirmed' : 'possible'} high/critical or known exploited CVE${result.vulnerabilities.length === 1 ? '' : 's'}${result.vendorConfirmed ? '' : '; confirm vendor applicability'}`);
  if (life.state !== 'supported') result.reasons.push(life.note);
  if (result.status === 'green') result.reasons.push(`Supported; no high or critical CVEs found in ${sourceLabel}`);
  return result;
}

async function refresh() {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    logger.log('info', 'Scan started');
    const apps = parseInventory(await readFile(path.join(configDirectory, 'applications.yaml'), 'utf8'));
    const workspaces = parseWorkspaces(await readFile(path.join(configDirectory, 'workspaces.yaml'), 'utf8'), apps);
    const feeds = await readFeeds(feedFile);
    const feedCache = await collectFeeds(feeds, feedCacheFile);
    let kev = new Set();
    let kevError = null;
    try {
      if (!apps.length) return storeSnapshot({ checkedAt: new Date().toISOString(), results: [], workspaces, warning: null, inventoryCount: 0 });
      const data = await fetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      kev = new Set(data.vulnerabilities.map(v => v.cveID));
    } catch (error) { logger.log('error', 'CISA KEV unavailable', error.message); kevError = `CISA KEV unavailable: ${error.message}`; }
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
    const saved = await storeSnapshot({ checkedAt: new Date().toISOString(), results, workspaces, feedSummary: { total: feeds.length, errors: Object.values(feedCache.feeds).filter(item => item.status === 'error').length }, warning: kevError, inventoryCount: apps.length });
    logger.log('info', 'Scan completed', `${results.length} applications; ${results.filter(app => app.status === 'unknown').length} unknown`);
    return saved;
  })().catch(error => { logger.log('error', 'Scan failed', error.message); throw error; }).finally(() => { refreshPromise = null; });
  return refreshPromise;
}

async function refreshApplication(appId) {
  if (refreshPromise) await refreshPromise;
  if (!snapshot) return refresh();
  refreshPromise = (async () => {
    const apps = parseInventory(await readFile(path.join(configDirectory, 'applications.yaml'), 'utf8'));
    const workspaces = parseWorkspaces(await readFile(path.join(configDirectory, 'workspaces.yaml'), 'utf8'), apps);
    const app = apps.find(item => item.id === appId);
    if (!app) {
      const saved = await storeSnapshot({ ...snapshot, checkedAt: new Date().toISOString(), results: (snapshot.results || []).filter(item => item.id !== appId), workspaces, inventoryCount: apps.length });
      return saved;
    }
    logger.log('info', 'Application scan started', app.name);
    const feeds = await readFeeds(feedFile);
    const associatedFeeds = feeds.filter(feed => feed.enabled && feed.applicationIds.includes(app.id));
    const feedCache = associatedFeeds.length ? await collectFeeds(associatedFeeds, feedCacheFile, { preserveUnlisted: true }) : await readFeedCache();
    const associated = associatedFeeds.flatMap(feed => feedCache.feeds?.[feed.id]?.entries || []);
    const feedErrors = associatedFeeds.filter(feed => feedCache.feeds?.[feed.id]?.status === 'error').map(feed => `${feed.name}: ${feedCache.feeds[feed.id].error}`);
    let kev = new Set();
    let kevError = null;
    try {
      const data = await fetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      kev = new Set(data.vulnerabilities.map(item => item.cveID));
    } catch (error) { kevError = `CISA KEV unavailable: ${error.message}`; }
    const result = await scanApp(app, kev, associated, feedErrors);
    if (kevError) { result.reasons.push(kevError); if (result.status !== 'red') result.status = 'unknown'; }
    else result.sources.push({ name: 'CISA Known Exploited Vulnerabilities', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' });
    const previousResults = snapshot.results || [];
    const results = previousResults.some(item => item.id === app.id) ? previousResults.map(item => item.id === app.id ? result : item) : [...previousResults, result];
    const saved = await storeSnapshot({ ...snapshot, checkedAt: new Date().toISOString(), results, workspaces, inventoryCount: apps.length, feedSummary: { total: feeds.length, errors: Object.values(feedCache.feeds || {}).filter(item => item.status === 'error').length } });
    logger.log('info', 'Application scan completed', app.name);
    return saved;
  })().catch(error => { logger.log('error', 'Application scan failed', `${appId}: ${error.message}`); throw error; }).finally(() => { refreshPromise = null; });
  return refreshPromise;
}

const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
createServer(async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    const url = new URL(req.url, `http://${req.headers.host}`);
    const acknowledgement = url.pathname.match(/^\/ack\/([A-Za-z0-9_-]{43})$/);
    if (acknowledgement && ['GET', 'POST'].includes(req.method)) {
      const token = acknowledgement[1];
      const entry = await notifier.lookup(token);
      if (!entry) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }); res.end('Alert link is no longer active.'); return; }
      const confirmed = req.method === 'POST' ? await notifier.acknowledge(token) : false;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' }); res.end(acknowledgePage(entry, confirmed)); return;
    }
    if (auth && await auth.handle(req, res, url)) return;
    if (url.pathname === '/api/session' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ enabled: false, user: 'Local development session', isAdmin: true })); return;
    }
    if ((url.pathname.startsWith('/api/settings') || ['/api/logs', '/api/rbac'].includes(url.pathname)) && auth && !req.authUser?.isAdmin) { forbidden(res, 'Administrator role required'); return; }
    if (url.pathname === '/api/settings' && req.method === 'GET') {
      const smtp = await readSmtpSettings(smtpFile);
      const configuredGeneral = await readGeneralSettings(generalFile);
      const general = configuredGeneral.host ? configuredGeneral : detectedGeneral(req);
      const envStatus = { usernamePresent: Boolean(smtp.usernameEnv && process.env[smtp.usernameEnv]), passwordPresent: Boolean(smtp.passwordEnv && process.env[smtp.passwordEnv]) };
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ smtp, general, generalConfigured: Boolean(configuredGeneral.host), envStatus })); return;
    }
    if (url.pathname === '/api/logs' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ entries: await logger.recent() })); return;
    }
    if (url.pathname === '/api/settings' && req.method === 'POST') {
      const body = await readBody(req);
      const smtpInput = validateSmtpSettings(body.smtp);
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
      const result = await sendTestEmail(smtp, body.recipient);
      await logger.audit('Test email sent', auditActor(req), { type: 'settings', id: 'email-delivery' }, { transportSecurity: smtp.secure ? 'tls' : smtp.requireTls ? 'starttls' : 'none', unauthenticated: smtp.unauthenticated }, 'SMTP test completed successfully; settings were not saved');
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ sent: true, accepted: result.accepted })); return;
    }
    if (url.pathname === '/api/config' && req.method === 'GET') {
      const { apps, workspaces, feeds, access } = await authorization(req);
      const visibleApps = apps.filter(app => access.appView.has(app.id) || access.appEdit.has(app.id));
      const visibleWorkspaces = workspaces.filter(group => access.workspaceView.has(group.id) || access.workspaceEdit.has(group.id) || access.workspaceMembership.has(group.id) || access.workspaceNotifications.has(group.id));
      const visibleFeeds = feeds.filter(feed => access.feedView.has(feed.id));
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ applications: visibleApps, workspaces: visibleWorkspaces, feeds: visibleFeeds, access: accessJson(access) })); return;
    }
    if (url.pathname === '/api/rbac' && req.method === 'GET') {
      const { apps, workspaces, feeds } = await authorization(req);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ ...await readRbac(rbacFile), roles: standardRoles, applications: apps, workspaces, feeds, session: { name: req.authUser?.name || 'Local development session', claims: req.authUser?.claims || {}, groupOverage: Boolean(req.authUser?.groupOverage) } })); return;
    }
    if (url.pathname === '/api/rbac' && req.method === 'POST') {
      const { apps, workspaces, feeds } = await authorization(req);
      const previous = await readRbac(rbacFile);
      const config = validateRbacInput(await readBody(req), apps, workspaces, feeds);
      await yamlMonitor.webWrite(rbacFile, () => writeRbac(rbacFile, config));
      await logger.audit('Access control updated', auditActor(req), { type: 'rbac', id: 'access-control' }, { groups: { from: previous.groups.length, to: config.groups.length }, grants: { from: previous.grants.length, to: config.grants.length } }, `${config.groups.length} identity mappings; ${config.grants.length} grants`);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(config)); return;
    }
    if (url.pathname === '/api/cpes' && req.method === 'GET') {
      const { access } = await authorization(req);
      if (!access.isAdmin && !access.appEdit.size) { forbidden(res, 'Application Editor role required'); return; }
      const query = String(url.searchParams.get('q') || '').trim();
      if (query.length < 2 || query.length > 100 || /[\u0000-\u001f]/.test(query)) throw new Error('CPE search requires 2 to 100 printable characters');
      const api = new URL('https://services.nvd.nist.gov/rest/json/cpes/2.0');
      api.searchParams.set('keywordSearch', query);
      api.searchParams.set('resultsPerPage', '50');
      const data = await fetchNvdJson(api);
      const results = (data.products || []).map(product => {
        const name = product.cpe?.cpeName || '';
        const parts = name.split(':');
        return { cpeName: name, part: parts[2], vendor: parts[3] || '', product: parts[4] || '', version: parts[5] || '', edition: parts[9] === '*' ? '' : parts[9] || '', title: product.cpe?.titles?.find(item => item.lang === 'en')?.title || name };
      }).filter(item => item.part === 'a');
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ results })); return;
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
      const response = await secureFetchText(feedRequestUrl(feed), { headers: feed.format === 'github' ? { Accept: 'application/vnd.github+json' } : {} });
      const entries = normalizeEntries(feed, response);
      await logger.audit('Feed tested', auditActor(req), { type: 'feed', id: feed.id, name: feed.name }, { entries: entries.length }, `${feed.name}; ${entries.length} normalized entries`);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ sourceUrl: response.url, entries: entries.slice(0, 25) })); return;
    }
    if (feedRoute && req.method === 'POST' && feedRoute[2] === 'refresh') {
      const { feeds, access } = await authorization(req);
      const feed = feeds.find(item => item.id === feedRoute[1]);
      if (!feed) throw new Error('Feed not found');
      if (!access.feedEdit.has(feed.id)) { forbidden(res, 'Feed Editor role required'); return; }
      if (refreshPromise) await refreshPromise;
      const cache = await collectFeeds([feed], feedCacheFile, { preserveUnlisted: true });
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
      if (refreshPromise) await refreshPromise;
      const file = path.join(configDirectory, 'applications.yaml');
      const current = await readFile(file, 'utf8');
      if (parseInventory(current, true).some(existing => existing.id === app.id)) throw new Error('Application ID already exists');
      await yamlMonitor.webWrite(file, () => saveAtomic(file, `${current.trimEnd()}\n${serializeApp({ ...app, enabled: true })}`));
      await invalidateSnapshot();
      await logger.audit('Application added', auditActor(req), { type: 'application', id: app.id, name: app.name }, { name: app.name, version: app.version }, `${app.name} (${app.id}); installed version ${app.version}`);
      res.writeHead(201, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify({ id: app.id })); return;
    }
    const appEdit = url.pathname.match(/^\/api\/applications\/([A-Za-z0-9._-]+)$/);
    if (appEdit && req.method === 'PUT') {
      const previousId = appEdit[1];
      const { access } = await authorization(req);
      if (!access.appEdit.has(previousId)) { forbidden(res); return; }
      const app = cleanApp(await readBody(req), previousId);
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
    const appRefresh = url.pathname.match(/^\/api\/applications\/([0-9a-f-]+)\/refresh$/i);
    if (appRefresh && req.method === 'POST') {
      const { access } = await authorization(req);
      if (!access.appEdit.has(appRefresh[1])) { forbidden(res, 'Application Editor role required'); return; }
      const data = await refreshApplication(appRefresh[1]);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(data)); return;
    }
    const workspaceEdit = url.pathname.match(/^\/api\/workspaces\/([A-Za-z0-9._-]+)$/);
    if ((url.pathname === '/api/workspaces' && req.method === 'POST') || (workspaceEdit && req.method === 'PUT')) {
      const body = await readBody(req);
      const previousId = workspaceEdit?.[1] || null;
      if (!previousId && auth && !req.authUser?.isAdmin) { forbidden(res, 'Administrator role required to add workspaces'); return; }
      const { access } = await authorization(req);
      const id = previousId || randomUUID();
      const name = String(body.name ?? '').trim();
      const notificationEmails = String(body.notificationEmails ?? '').trim();
      if (!uuidPattern.test(id)) throw new Error('Workspace ID must be an immutable UUID');
      if (!name || /[\r\n]/.test(name)) throw new Error('Workspace name is required on one line');
      const recipients = [...new Set(notificationEmails.split(/[;,]/).map(value => value.trim()).filter(Boolean))];
      if (recipients.some(value => !/^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(value))) throw new Error('Enter valid notification email addresses separated by commas');
      if (!Array.isArray(body.applications)) throw new Error('Select applications for the workspace');
      const membership = [...new Set(body.applications.map(value => String(value)))];
      const apps = parseInventory(await readFile(path.join(configDirectory, 'applications.yaml'), 'utf8'));
      if (membership.some(appId => !apps.some(app => app.id === appId))) throw new Error('Workspace contains an unknown application');
      if (refreshPromise) await refreshPromise;
      const file = path.join(configDirectory, 'workspaces.yaml');
      const groups = parseWorkspaces(await readFile(file, 'utf8'), apps);
      const index = previousId ? groups.findIndex(group => group.id === previousId) : groups.findIndex(group => group.id === id);
      if (previousId && index < 0) throw new Error('Workspace not found');
      const previous = index < 0 ? null : groups[index];
      if (previous) {
        if (name !== previous.name && !access.workspaceEdit.has(id)) { forbidden(res, 'Workspace Manager role required to rename this workspace'); return; }
        if (JSON.stringify(membership) !== JSON.stringify(previous.applications) && !access.workspaceMembership.has(id)) { forbidden(res, 'Workspace Membership Manager role required'); return; }
        if (recipients.join(', ') !== previous.notificationEmails && !access.workspaceNotifications.has(id)) { forbidden(res, 'Notification Manager role required'); return; }
      }
      const group = { id, legacyId: previous?.legacyId || '', name, notificationEmails: recipients.join(', '), applications: membership };
      if (index < 0) groups.push(group); else groups[index] = group;
      await yamlMonitor.webWrite(file, () => saveAtomic(file, serializeWorkspaces(groups)));
      if (snapshot) {
        snapshot = { ...snapshot, workspaces: groups };
        await saveAtomic(snapshotFile, `${JSON.stringify(snapshot)}\n`);
      }
      if (previous) {
        const addedApplications = membership.filter(appId => !previous.applications.includes(appId));
        const removedApplications = previous.applications.filter(appId => !membership.includes(appId));
        const changes = { ...changedFields(previous, group, ['id', 'name']), addedApplications, removedApplications, notificationRecipientsChanged: previous.notificationEmails !== group.notificationEmails };
        if (changes.name || addedApplications.length || removedApplications.length || changes.notificationRecipientsChanged) {
          const detail = [changes.id || changes.name ? describeFields(Object.fromEntries(Object.entries({ id: changes.id, name: changes.name }).filter(([, value]) => value))) : '', addedApplications.length ? `Applications added: ${addedApplications.join(', ')}` : '', removedApplications.length ? `Applications removed: ${removedApplications.join(', ')}` : '', changes.notificationRecipientsChanged ? 'Notification recipients changed' : ''].filter(Boolean).join('; ');
          await logger.audit('Workspace updated', auditActor(req), { type: 'workspace', id, name }, changes, `${name} (${id}); ${detail}`);
        }
      } else {
        await logger.audit('Workspace added', auditActor(req), { type: 'workspace', id, name }, { name, applications: membership, notificationRecipientCount: recipients.length }, `${name} (${id}); applications: ${membership.join(', ') || 'none'}; notification recipients: ${recipients.length}`);
      }
      res.writeHead(index < 0 ? 201 : 200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify({ ...group, previousId: previousId || id })); return;
    }
    if (url.pathname === '/api/status') {
      await snapshotReady;
      const { access } = await authorization(req);
      if (url.searchParams.has('refresh') && !access.scan) { forbidden(res, 'Scan Operator role required'); return; }
      const data = !snapshot || Date.now() - new Date(snapshot.checkedAt).getTime() > refreshMs || url.searchParams.has('refresh') ? await refresh() : snapshot;
      const results = (data.results || []).filter(app => access.appView.has(app.id));
      const workspaces = (data.workspaces || []).filter(group => access.workspaceView.has(group.id)).map(group => ({ ...group, applications: group.applications.filter(id => access.appView.has(id)) }));
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ ...data, results, workspaces, access: accessJson(access), groupOverage: Boolean(req.authUser?.groupOverage) })); return;
    }
    const files = { '/': 'index.html', '/styles.css': 'styles.css', '/theme-init.js': 'theme-init.js', '/app.js': 'app.js', '/favicon.svg': 'favicon.svg' };
    const file = files[url.pathname];
    if (!file) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': mime[path.extname(file)] }); res.end(await readFile(path.join(root, 'web', file)));
  } catch (error) { res.writeHead(['POST', 'PUT', 'DELETE'].includes(req.method) ? 400 : 500, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: error.message })); }
}).listen(PORT, HOST, () => { console.log(`Vulnerability dashboard: http://${HOST}:${PORT}`); logger.log('info', 'Server started', `Listening on ${HOST}:${PORT}`); });

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
