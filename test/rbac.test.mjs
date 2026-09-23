import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateAccess, validateRbacInput } from '../rbac.mjs';

const appA = { id: '11111111-1111-4111-8111-111111111111', name: 'Jira' };
const appB = { id: '22222222-2222-4222-8222-222222222222', name: 'GitLab' };
const workspace = { id: '33333333-3333-4333-8333-333333333333', name: 'Infrastructure', applications: [appA.id, appB.id] };
const groupId = '44444444-4444-4444-8444-444444444444';
const grantId = '55555555-5555-4555-8555-555555555555';

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
