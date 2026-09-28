import test from 'node:test';
import assert from 'node:assert/strict';
import { parseOwners, serializeOwners, validateOwner } from '../owners.mjs';

test('owners round-trip with stable IDs and optional escalation emails', () => {
  const owner = validateOwner({ name: 'Platform Engineering', email: 'platform@example.com', escalationEmail: 'on-call@example.com' });
  const parsed = parseOwners(serializeOwners([owner]));
  assert.deepEqual(parsed, [owner]);
});

test('owner validation requires a name and valid email', () => {
  assert.throws(() => validateOwner({ name: '', email: 'platform@example.com' }), /name is required/);
  assert.throws(() => validateOwner({ name: 'Platform Engineering', email: '' }), /email is required/);
  assert.throws(() => validateOwner({ name: 'Platform Engineering', email: 'not-an-email' }), /valid owner email/);
  assert.throws(() => validateOwner({ name: 'Platform\nEngineering', email: 'platform@example.com' }), /one line/);
});

test('owner YAML rejects duplicate email addresses case-insensitively', () => {
  const first = validateOwner({ name: 'Platform', email: 'platform@example.com' });
  const second = validateOwner({ name: 'Operations', email: 'PLATFORM@example.com' });
  assert.throws(() => parseOwners(serializeOwners([first, second])), /email addresses must be unique/);
});
