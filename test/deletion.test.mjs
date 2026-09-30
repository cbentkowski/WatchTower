import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const appId = '11111111-1111-4111-8111-111111111111';
const workspaceId = '22222222-2222-4222-8222-222222222222';
const archiveWorkspaceId = '77777777-7777-4777-8777-777777777777';
const feedId = '33333333-3333-4333-8333-333333333333';
const groupId = '44444444-4444-4444-8444-444444444444';
const appGrantId = '55555555-5555-4555-8555-555555555555';
const workspaceGrantId = '66666666-6666-4666-8666-666666666666';

async function freePort() {
  const socket = createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  return port;
}

const rbac = grants => `version: 1\ngroups:\n  - id: ${groupId}\n    name: "Managers"\n    claimSource: "groups"\n    claimValue: "managers"\n    enabled: true\ngrants:\n${grants}`;
const workspaceGrant = `  - id: ${workspaceGrantId}\n    groupId: ${groupId}\n    scopeType: workspace\n    roles:\n      - workspace-manager\n    resourceIds:\n      - ${workspaceId}\n`;

test('safe deletion blocks RBAC references, cleans relationships, preserves applications, updates snapshot, and audits', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-delete-'));
  const data = path.join(directory, 'data');
  await mkdir(data);
  await writeFile(path.join(directory, 'applications.yaml'), `applications:\n  - id: ${appId}\n    name: "Test App"\n    version: "1.0"\n    cpeVendor: "example"\n    cpeProduct: "test"\n    cpeName: "cpe:2.3:a:example:test:*:*:*:*:*:*:*:*"\n    cpeMode: "product"\n    eolDate: "2030-01-01"\n    enabled: true\n    criticality: "high"\n    environment: "production"\n    exposure: "internal"\n    ownerIds:\n    tags:\n`);
  await writeFile(path.join(directory, 'workspaces.yaml'), `workspaces:\n  - id: ${workspaceId}\n    name: "Operations"\n    ownerIds:\n    applications:\n      - ${appId}\n  - id: ${archiveWorkspaceId}\n    name: "Archive"\n    ownerIds:\n    applications:\n      - ${appId}\n`);
  await writeFile(path.join(directory, 'feeds.yaml'), `version: 1\nfeeds:\n  - id: ${feedId}\n    name: "Vendor"\n    url: "https://example.com/feed"\n    format: "rss"\n    enabled: true\n    categories:\n      - "security"\n    productAliases:\n      - "Test App"\n    applicationIds:\n      - ${appId}\n`);
  await writeFile(path.join(directory, 'rbac.yaml'), rbac(`  - id: ${appGrantId}\n    groupId: ${groupId}\n    scopeType: application\n    roles:\n      - application-editor\n    resourceIds:\n      - ${appId}\n${workspaceGrant}`));
  await writeFile(path.join(data, 'status.json'), `${JSON.stringify({ checkedAt: new Date().toISOString(), results: [{ id: appId, name: 'Test App' }], workspaces: [{ id: workspaceId, name: 'Operations', ownerIds: [], applications: [appId] }, { id: archiveWorkspaceId, name: 'Archive', ownerIds: [], applications: [appId] }], owners: [], inventoryCount: 1, feedSummary: { total: 1, errors: 0 } })}\n`);
  const port = await freePort();
  const child = spawn(process.execPath, ['src/server.mjs'], { cwd: path.resolve(import.meta.dirname, '..'), env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: directory, DATA_DIR: data, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' }, stdio: 'ignore' });
  const origin = `http://127.0.0.1:${port}`;
  const remove = (route, confirmation) => fetch(`${origin}${route}`, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ confirmation }) });
  try {
    for (let attempt = 0; attempt < 30; attempt++) { try { if ((await fetch(`${origin}/api/session`)).ok) break; } catch {} await new Promise(resolve => setTimeout(resolve, 100)); }
    assert.equal((await remove(`/api/workspaces/${archiveWorkspaceId}`, 'Archive')).status, 204);
    assert.match(await readFile(path.join(directory, 'applications.yaml'), 'utf8'), new RegExp(appId));
    assert.doesNotMatch(await readFile(path.join(directory, 'workspaces.yaml'), 'utf8'), new RegExp(archiveWorkspaceId));
    assert.equal((await remove(`/api/applications/${appId}`, 'wrong')).status, 400);
    assert.equal((await remove(`/api/applications/${appId}`, 'Test App')).status, 400);
    await writeFile(path.join(directory, 'rbac.yaml'), rbac(workspaceGrant));
    assert.equal((await remove(`/api/applications/${appId}`, 'Test App')).status, 204);
    assert.doesNotMatch(await readFile(path.join(directory, 'applications.yaml'), 'utf8'), new RegExp(appId));
    assert.doesNotMatch(await readFile(path.join(directory, 'workspaces.yaml'), 'utf8'), new RegExp(appId));
    assert.doesNotMatch(await readFile(path.join(directory, 'feeds.yaml'), 'utf8'), new RegExp(appId));
    let saved = JSON.parse(await readFile(path.join(data, 'status.json'), 'utf8'));
    assert.deepEqual(saved.results, []);
    assert.deepEqual(saved.workspaces[0].applications, []);
    assert.equal((await remove(`/api/workspaces/${workspaceId}`, 'Operations')).status, 400);
    await writeFile(path.join(directory, 'rbac.yaml'), rbac(''));
    assert.equal((await remove(`/api/workspaces/${workspaceId}`, 'Operations')).status, 204);
    assert.match(await readFile(path.join(directory, 'applications.yaml'), 'utf8'), /applications:/);
    saved = JSON.parse(await readFile(path.join(data, 'status.json'), 'utf8'));
    assert.deepEqual(saved.workspaces, []);
    const audits = (await (await fetch(`${origin}/api/logs?type=audit`)).json()).entries;
    const appAudit = audits.find(entry => entry.message === 'Application removed');
    const workspaceAudit = audits.find(entry => entry.message === 'Workspace removed' && entry.target.id === archiveWorkspaceId);
    assert.deepEqual(appAudit.changes.workspaceIds, [workspaceId]);
    assert.deepEqual(appAudit.changes.feedIds, [feedId]);
    assert.equal(appAudit.changes.workflowRecords, 'preserved');
    assert.deepEqual(workspaceAudit.changes.applicationIds, [appId]);
    assert.equal(workspaceAudit.changes.applicationsPreserved, true);
  } finally {
    child.kill();
    await rm(directory, { recursive: true, force: true });
  }
});
