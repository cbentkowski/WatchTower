import { randomUUID } from 'node:crypto';
import { readFile, writeFile, rename } from 'node:fs/promises';

export const standardRoles = Object.freeze({
  'workspace-viewer': { name: 'Workspace Viewer', scopes: ['workspace'] },
  'workspace-manager': { name: 'Workspace Manager', scopes: ['workspace'] },
  'workspace-membership-manager': { name: 'Workspace Membership Manager', scopes: ['workspace'] },
  'workspace-application-editor': { name: 'Workspace Application Editor', scopes: ['workspace'] },
  'notification-manager': { name: 'Notification Manager', scopes: ['workspace'] },
  'application-viewer': { name: 'Application Viewer', scopes: ['application'] },
  'application-editor': { name: 'Application Editor', scopes: ['application'] },
  'feed-viewer': { name: 'Feed Viewer', scopes: ['feed'] },
  'feed-editor': { name: 'Feed Editor', scopes: ['feed'] },
  'feed-manager': { name: 'Feed Manager', scopes: ['global'] },
  'scan-operator': { name: 'Scan Operator', scopes: ['global'] },
});

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const scalar = value => { const raw = value.trim(); if (raw.startsWith('"')) return JSON.parse(raw); return raw === 'true' ? true : raw === 'false' ? false : raw; };

export function parseRbac(source) {
  const result = { groups: [], grants: [] };
  let section = null;
  let current = null;
  let list = null;
  for (const line of source.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed === 'version: 1') continue;
    if (trimmed === 'groups:') { section = 'groups'; current = null; continue; }
    if (trimmed === 'grants:') { section = 'grants'; current = null; continue; }
    const entry = line.match(/^  - id:\s*(.*)$/);
    const field = line.match(/^    ([A-Za-z][\w]*):\s*(.*)$/);
    const item = line.match(/^      -\s*(.*)$/);
    if (entry && section) { current = { id: scalar(entry[1]) }; result[section].push(current); list = null; }
    else if (field && current) {
      if (field[2] === '') { current[field[1]] = []; list = field[1]; }
      else { current[field[1]] = scalar(field[2]); list = null; }
    } else if (item && current && list) current[list].push(scalar(item[1]));
    else throw new Error(`Unsupported RBAC YAML line: ${line}`);
  }
  for (const group of result.groups) {
    if (!uuid.test(group.id || '')) throw new Error('Every identity mapping requires a UUID');
    if (!group.name || !group.claimSource || !group.claimValue) throw new Error('Identity mappings require name, claim source, and claim value');
    group.enabled = group.enabled !== false;
  }
  for (const grant of result.grants) {
    if (!uuid.test(grant.id || '') || !result.groups.some(group => group.id === grant.groupId)) throw new Error('Every grant requires a UUID and valid identity mapping');
    if (!['global', 'workspace', 'application', 'feed'].includes(grant.scopeType)) throw new Error('Grant has an invalid scope type');
    grant.roles ||= [];
    grant.resourceIds ||= [];
    if (!grant.roles.length || grant.roles.some(role => !standardRoles[role] || !standardRoles[role].scopes.includes(grant.scopeType))) throw new Error('Grant contains an invalid role for its scope');
    if (grant.scopeType !== 'global' && !grant.resourceIds.length) throw new Error('Scoped grant requires at least one resource');
  }
  return result;
}

const q = value => JSON.stringify(String(value));
export function serializeRbac(config) {
  const groups = config.groups.map(group => `  - id: ${group.id}\n    name: ${q(group.name)}\n    claimSource: ${q(group.claimSource)}\n    claimValue: ${q(group.claimValue)}\n    enabled: ${group.enabled !== false}\n`).join('');
  const grants = config.grants.map(grant => `  - id: ${grant.id}\n    groupId: ${grant.groupId}\n    scopeType: ${grant.scopeType}\n    roles:\n${grant.roles.map(role => `      - ${role}\n`).join('')}    resourceIds:\n${(grant.resourceIds || []).map(id => `      - ${id}\n`).join('')}`).join('');
  return `# Managed by WatchTower. Claim values are matched exactly and case-sensitively.\nversion: 1\ngroups:\n${groups}grants:\n${grants}`;
}

export async function readRbac(file) { try { return parseRbac(await readFile(file, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return { groups: [], grants: [] }; throw error; } }
export async function writeRbac(file, config) { const temp = `${file}.tmp`; await writeFile(temp, serializeRbac(config)); await rename(temp, file); return config; }

export function validateRbacInput(input, apps, workspaces, feeds = []) {
  if (!input || !Array.isArray(input.groups) || !Array.isArray(input.grants)) throw new Error('Groups and grants are required');
  const groups = input.groups.map(group => ({ id: uuid.test(group.id || '') ? group.id : randomUUID(), name: String(group.name || '').trim(), claimSource: String(group.claimSource || '').trim(), claimValue: String(group.claimValue || '').trim(), enabled: group.enabled !== false }));
  const groupIds = new Set(groups.map(group => group.id));
  if (groups.some(group => !group.name || !['groups', 'roles', 'realm_access.roles', 'resource_access.roles'].includes(group.claimSource) || !group.claimValue)) throw new Error('Each identity mapping needs a name, supported claim source, and claim value');
  const known = { workspace: new Set(workspaces.map(item => item.id)), application: new Set(apps.map(item => item.id)), feed: new Set(feeds.map(item => item.id)) };
  const grants = input.grants.map(grant => ({ id: uuid.test(grant.id || '') ? grant.id : randomUUID(), groupId: String(grant.groupId || ''), scopeType: String(grant.scopeType || ''), roles: [...new Set((grant.roles || []).map(String))], resourceIds: [...new Set((grant.resourceIds || []).map(String))] }));
  for (const grant of grants) {
    if (!groupIds.has(grant.groupId)) throw new Error('Grant references an unknown identity mapping');
    if (!['global', 'workspace', 'application', 'feed'].includes(grant.scopeType) || !grant.roles.length) throw new Error('Grant requires a valid scope and at least one role');
    if (grant.roles.some(role => !standardRoles[role]?.scopes.includes(grant.scopeType))) throw new Error('Grant contains a role that is invalid for its scope');
    if (grant.scopeType !== 'global' && (!grant.resourceIds.length || grant.resourceIds.some(id => !known[grant.scopeType].has(id)))) throw new Error('Grant references an unknown resource');
    if (grant.scopeType === 'global') grant.resourceIds = [];
  }
  return { groups, grants };
}

export function calculateAccess(user, config, apps, workspaces, feeds = []) {
  if (user?.isAdmin || user?.issuer === 'local') return { isAdmin: true, scan: true, feedManage: true, feedView: new Set(feeds.map(f => f.id)), feedEdit: new Set(feeds.map(f => f.id)), appView: new Set(apps.map(a => a.id)), appEdit: new Set(apps.map(a => a.id)), workspaceView: new Set(workspaces.map(w => w.id)), workspaceEdit: new Set(workspaces.map(w => w.id)), workspaceMembership: new Set(workspaces.map(w => w.id)), workspaceNotifications: new Set(workspaces.map(w => w.id)) };
  const claims = user?.claims || {};
  const matched = new Set(config.groups.filter(group => group.enabled && (claims[group.claimSource] || []).includes(group.claimValue)).map(group => group.id));
  const access = { isAdmin: false, scan: false, feedManage: false, feedView: new Set(), feedEdit: new Set(), appView: new Set(), appEdit: new Set(), workspaceView: new Set(), workspaceEdit: new Set(), workspaceMembership: new Set(), workspaceNotifications: new Set() };
  for (const grant of config.grants.filter(item => matched.has(item.groupId))) {
    if (grant.scopeType === 'global' && grant.roles.includes('scan-operator')) access.scan = true;
    if (grant.scopeType === 'global' && grant.roles.includes('feed-manager')) { access.feedManage = true; for (const feed of feeds) { access.feedView.add(feed.id); access.feedEdit.add(feed.id); } }
    if (grant.scopeType === 'feed') for (const id of grant.resourceIds) {
      if (grant.roles.some(role => ['feed-viewer', 'feed-editor'].includes(role))) access.feedView.add(id);
      if (grant.roles.includes('feed-editor')) access.feedEdit.add(id);
    }
    if (grant.scopeType === 'application') for (const id of grant.resourceIds) {
      if (grant.roles.some(role => ['application-viewer', 'application-editor'].includes(role))) access.appView.add(id);
      if (grant.roles.includes('application-editor')) access.appEdit.add(id);
    }
    if (grant.scopeType === 'workspace') for (const id of grant.resourceIds) {
      const workspace = workspaces.find(item => item.id === id);
      if (!workspace) continue;
      access.workspaceView.add(id);
      for (const appId of workspace.applications) access.appView.add(appId);
      if (grant.roles.includes('workspace-manager')) access.workspaceEdit.add(id);
      if (grant.roles.includes('workspace-membership-manager')) access.workspaceMembership.add(id);
      if (grant.roles.includes('notification-manager')) access.workspaceNotifications.add(id);
      if (grant.roles.includes('workspace-application-editor')) for (const appId of workspace.applications) access.appEdit.add(appId);
    }
  }
  for (const id of access.appEdit) access.appView.add(id);
  for (const id of access.feedEdit) access.feedView.add(id);
  return access;
}

export function accessJson(access) { return { isAdmin: access.isAdmin, scan: access.scan, feeds: { manage: access.feedManage, view: [...access.feedView], edit: [...access.feedEdit] }, applications: { view: [...access.appView], edit: [...access.appEdit] }, workspaces: { view: [...access.workspaceView], edit: [...access.workspaceEdit], membership: [...access.workspaceMembership], notifications: [...access.workspaceNotifications] } }; }
