import test from 'node:test';
import assert from 'node:assert/strict';
import { parseOwners, serializeOwners, validateOwner } from '../owners.mjs';

test('owners round-trip with stable IDs and optional escalation contacts', () => {
  const owner = validateOwner({ name: 'Platform Engineering', primaryContact: 'platform@example.com', escalationContact: 'on-call@example.com' });
  const parsed = parseOwners(serializeOwners([owner]));
  assert.deepEqual(parsed, [owner]);
});

test('owner validation requires a name and primary contact', () => {
  assert.throws(() => validateOwner({ name: '', primaryContact: 'platform@example.com' }), /name is required/);
  assert.throws(() => validateOwner({ name: 'Platform Engineering', primaryContact: '' }), /Primary contact is required/);
  assert.throws(() => validateOwner({ name: 'Platform\nEngineering', primaryContact: 'platform@example.com' }), /one line/);
});
