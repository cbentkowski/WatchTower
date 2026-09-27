import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateAccess, explainAccess, protectedRoleState, validateRbacInput } from '../rbac.mjs';

const appA = { id: '11111111-1111-4111-8111-111111111111', name: 'Jira' };
const appB = { id: '22222222-2222-4222-8222-222222222222', name: 'GitLab' };
const workspace = { id: '33333333-3333-4333-8333-333333333333', name: 'Infrastructure', applications: [appA.id, appB.id] };
const groupId = '44444444-4444-4444-8444-444444444444';
const grantId = '55555555-5555-4555-8555-555555555555';
const feed = { id: '66666666-6666-4666-8666-666666666666', name: 'Istio News' };

test('one workspace grant combines multiple roles and applies to every application in the workspace', () => {
  const config = validateRbacInput({
    groups: [{ id: groupId, name: 'Infrastructure Admins', claimSource: 'groups', claimValue: 'entra-group-id', enabled: true }],
    grants: [{ id: grantId, groupId, scopeType: 'workspace', roles: ['workspace-manager', 'workspace-application-editor'], resourceIds: [workspace.id] }],
  }, [appA, appB], [workspace]);
  const access = calculateAccess({ claims: { groups: ['entra-group-id'] } }, config, [appA, appB], [workspace]);
  assert.equal(access.workspaceEdit.has(workspace.id), true);
  assert.deepEqual([...access.appEdit].sort(), [appA.id, appB.id].sort());
  assert.equal(access.workspaceMembership.has(workspace.id), false);
});

test('unmatched authenticated users receive no access', () => {
  const access = calculateAccess({ claims: { groups: ['other-group'] } }, { groups: [], grants: [] }, [appA], [workspace]);
  assert.equal(access.isAdmin, false);
  assert.equal(access.appView.size, 0);
  assert.equal(access.workspaceView.size, 0);
});

test('feed roles separate scoped viewing and editing from global feed management', () => {
  const config = validateRbacInput({
    groups: [{ id: groupId, name: 'Feed Operators', claimSource: 'groups', claimValue: 'feed-team', enabled: true }],
    grants: [{ id: grantId, groupId, scopeType: 'feed', roles: ['feed-viewer', 'feed-editor'], resourceIds: [feed.id] }],
  }, [appA], [workspace], [feed]);
  const access = calculateAccess({ claims: { groups: ['feed-team'] } }, config, [appA], [workspace], [feed]);
  assert.equal(access.feedView.has(feed.id), true);
  assert.equal(access.feedEdit.has(feed.id), true);
  assert.equal(access.feedManage, false);

  const manager = validateRbacInput({ groups: config.groups, grants: [{ id: grantId, groupId, scopeType: 'global', roles: ['feed-manager'], resourceIds: [] }] }, [appA], [workspace], [feed]);
  assert.equal(calculateAccess({ claims: { groups: ['feed-team'] } }, manager, [appA], [workspace], [feed]).feedManage, true);
});

test('access administrator is global but does not imply resource or settings administration', () => {
  const config = validateRbacInput({
    groups: [{ id: groupId, name: 'Access Team', claimSource: 'roles', claimValue: 'WatchTower.Access', enabled: true }],
    grants: [{ id: grantId, groupId, scopeType: 'global', roles: ['access-administrator'], resourceIds: [] }],
  }, [appA], [workspace], [feed]);
  const access = calculateAccess({ claims: { roles: ['WatchTower.Access'] } }, config, [appA], [workspace], [feed]);
  assert.equal(access.accessManage, true);
  assert.equal(access.isAdmin, false);
  assert.equal(access.scan, false);
  assert.equal(access.feedManage, false);
  assert.equal(access.appView.size, 0);
  const renamed = structuredClone(config);
  renamed.groups[0].name = 'Renamed Access Team';
  assert.notEqual(protectedRoleState(config, 'access-administrator'), protectedRoleState(renamed, 'access-administrator'));
  const unrelated = structuredClone(config);
  unrelated.groups.push({ id: '99999999-9999-4999-8999-999999999999', name: 'Readers', claimSource: 'groups', claimValue: 'readers', enabled: true });
  assert.equal(protectedRoleState(config, 'access-administrator'), protectedRoleState(unrelated, 'access-administrator'));
});

test('effective access explanation combines selected mappings and names inherited workspace resources', () => {
  const secondGroupId = '77777777-7777-4777-8777-777777777777';
  const secondGrantId = '88888888-8888-4888-8888-888888888888';
  const config = validateRbacInput({
    groups: [
      { id: groupId, name: 'Workspace Readers', claimSource: 'groups', claimValue: 'readers', enabled: true },
      { id: secondGroupId, name: 'Application Editors', claimSource: 'roles', claimValue: 'editors', enabled: true },
    ],
    grants: [
      { id: grantId, groupId, scopeType: 'workspace', roles: ['workspace-viewer'], resourceIds: [workspace.id] },
      { id: secondGrantId, groupId: secondGroupId, scopeType: 'application', roles: ['application-editor'], resourceIds: [appA.id] },
    ],
  }, [appA, appB], [workspace], [feed]);
  const explanation = explainAccess(config, [groupId, secondGroupId], [appA, appB], [workspace], [feed]);
  assert.deepEqual(explanation.selectedMappings.map(item => item.name), ['Workspace Readers', 'Application Editors']);
  assert.deepEqual(explanation.effective.applications.view.map(item => item.name).sort(), ['GitLab', 'Jira']);
  assert.deepEqual(explanation.effective.applications.edit.map(item => item.name), ['Jira']);
  assert.equal(explanation.grants[0].resources[0].name, 'Infrastructure');
});
