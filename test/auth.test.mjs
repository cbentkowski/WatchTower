import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createAuth, oidcSettings, requiresAdministrator } from '../auth.mjs';

const values = {
  OIDC_ISSUER: 'https://login.example.com/realms/watchtower',
  OIDC_CLIENT_ID: 'watchtower',
  OIDC_CLIENT_SECRET: 'test-secret',
  OIDC_BASE_URL: 'https://home.example.com',
};

function response() {
  return {
    writeHead(status, headers) { this.status = status; this.headers = headers; },
    end(body) { this.body = body; },
  };
}

test('OIDC configuration requires all fields and an HTTPS public address', () => {
  assert.equal(oidcSettings({}), null);
  assert.throws(() => oidcSettings({ OIDC_CLIENT_ID: 'watchtower' }), /OIDC_ISSUER is required/);
  assert.throws(() => oidcSettings({ ...values, OIDC_BASE_URL: 'http://home.example.com' }), /HTTPS/);
  assert.throws(() => oidcSettings({ ...values, OIDC_BASE_URL: 'https://home.example.com/path' }), /origin/);
  assert.throws(() => oidcSettings({ ...values, OIDC_ISSUER: 'http://login.example.com' }), /HTTPS/);
});

test('OIDC client secret can be loaded from a mounted file', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'watchtower-oidc-'));
  const secretFile = path.join(directory, 'client-secret');
  writeFileSync(secretFile, 'mounted-secret\n');
  try {
    const { OIDC_CLIENT_SECRET: _, ...withoutSecret } = values;
    assert.equal(oidcSettings({ ...withoutSecret, OIDC_CLIENT_SECRET_FILE: secretFile }).clientSecret, 'mounted-secret');
    assert.throws(() => oidcSettings({ ...values, OIDC_CLIENT_SECRET_FILE: secretFile }), /not both/);
    assert.throws(() => oidcSettings({ ...withoutSecret, OIDC_CLIENT_SECRET_FILE: path.join(directory, 'missing') }), /Could not read/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('unauthenticated requests cannot read APIs or the dashboard', async () => {
  const auth = createAuth(oidcSettings(values));
  const api = response();
  assert.equal(await auth.handle({ method: 'GET', headers: {} }, api, new URL('https://home.example.com/api/settings')), true);
  assert.equal(api.status, 401);
  assert.match(api.body, /Sign-in required/);
  assert.equal(api.headers['Cache-Control'], 'no-store');

  const page = response();
  assert.equal(await auth.handle({ method: 'GET', headers: {} }, page, new URL('https://home.example.com/')), true);
  assert.equal(page.status, 303);
  assert.equal(page.headers.Location, '/auth/login');
});

test('login binds the callback to a browser flow and creates a protected session', async () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'watchtower-admin-group-'));
  const adminGroupFile = path.join(directory, 'admin-group-id');
  writeFileSync(adminGroupFile, 'entra-admin-group-id\n');
  let parameters;
  const provider = {
    discovery: async () => ({}),
    randomState: () => 'expected-state',
    randomNonce: () => 'expected-nonce',
    randomPKCECodeVerifier: () => 'verifier',
    calculatePKCECodeChallenge: async () => 'challenge',
    buildAuthorizationUrl: (_config, input) => { parameters = input; return new URL('https://login.example.com/authorize'); },
    authorizationCodeGrant: async (_config, _url, checks) => {
      assert.equal(checks.expectedState, 'expected-state');
      assert.equal(checks.expectedNonce, 'expected-nonce');
      assert.equal(checks.pkceCodeVerifier, 'verifier');
      return { claims: () => ({ sub: 'user-123', name: 'Test User', preferred_username: 'test.user@example.com', groups: ['entra-admin-group-id'], roles: ['WatchTower.User'] }) };
    },
  };
  const auth = createAuth(oidcSettings({ ...values, OIDC_REQUIRED_ROLE: 'WatchTower.User', OIDC_ADMIN_GROUP_ID_FILE: adminGroupFile }), provider);
  const login = response();
  await auth.handle({ method: 'GET', headers: {} }, login, new URL('https://home.example.com/auth/login'));
  assert.equal(login.status, 302);
  assert.equal(parameters.redirect_uri, 'https://home.example.com/auth/callback');
  assert.equal(parameters.code_challenge_method, 'S256');
  const flowCookie = login.headers['Set-Cookie'].split(';')[0];
  assert.match(login.headers['Set-Cookie'], /HttpOnly.*SameSite=Lax.*Secure/);

  const invalid = response();
  await auth.handle({ method: 'GET', headers: {} }, invalid, new URL('https://home.example.com/auth/callback?state=expected-state&code=abc'));
  assert.equal(invalid.status, 400);

  const callback = response();
  await auth.handle({ method: 'GET', headers: { cookie: flowCookie } }, callback, new URL('https://home.example.com/auth/callback?state=expected-state&code=abc'));
  assert.equal(callback.status, 303);
  const sessionCookie = callback.headers['Set-Cookie'][1].split(';')[0];
  const sessionResponse = response();
  assert.equal(await auth.handle({ method: 'GET', headers: { cookie: sessionCookie } }, sessionResponse, new URL('https://home.example.com/api/session')), true);
  assert.equal(JSON.parse(sessionResponse.body).isAdmin, true);
  const api = response();
  const authenticated = { method: 'GET', headers: { cookie: sessionCookie } };
  assert.equal(await auth.handle(authenticated, api, new URL('https://home.example.com/api/settings')), false);
  assert.deepEqual(authenticated.authUser, { issuer: values.OIDC_ISSUER, subject: 'user-123', username: 'test.user@example.com', name: 'Test User', isAdmin: true, claims: { groups: ['entra-admin-group-id'], roles: ['WatchTower.User'], 'realm_access.roles': [], 'resource_access.roles': [] }, groupOverage: false });
  const mutation = response();
  await auth.handle({ method: 'POST', headers: { cookie: sessionCookie, origin: 'https://evil.example' } }, mutation, new URL('https://home.example.com/api/settings'));
  assert.equal(mutation.status, 403);
  rmSync(directory, { recursive: true, force: true });
});

test('administrator authorization covers every privileged API', () => {
  for (const route of ['/api/settings', '/api/logs', '/api/config', '/api/applications', '/api/applications/test', '/api/workspaces', '/api/status?refresh=1']) {
    assert.equal(requiresAdministrator(new URL(route, 'https://home.example.com')), true, route);
  }
  for (const route of ['/api/session', '/api/status', '/', '/app.js']) {
    assert.equal(requiresAdministrator(new URL(route, 'https://home.example.com')), false, route);
  }
});

test('OIDC client configuration reloads after mounted secret rotation', async () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'watchtower-oidc-rotation-'));
  const secretFile = path.join(directory, 'client-secret');
  writeFileSync(secretFile, 'first-secret\n');
  const discoveries = [];
  const provider = {
    discovery: async (_issuer, _clientId, secret) => { discoveries.push(secret); return {}; },
    randomState: () => 'state', randomNonce: () => 'nonce', randomPKCECodeVerifier: () => 'verifier',
    calculatePKCECodeChallenge: async () => 'challenge',
    buildAuthorizationUrl: () => new URL('https://login.example.com/authorize'),
  };
  try {
    const { OIDC_CLIENT_SECRET: _, ...withoutSecret } = values;
    const auth = createAuth(oidcSettings({ ...withoutSecret, OIDC_CLIENT_SECRET_FILE: secretFile }), provider);
    await auth.handle({ method: 'GET', headers: {} }, response(), new URL('https://home.example.com/auth/login'));
    writeFileSync(secretFile, 'second-secret\n');
    await auth.handle({ method: 'GET', headers: {} }, response(), new URL('https://home.example.com/auth/login'));
    assert.deepEqual(discoveries, ['first-secret', 'second-secret']);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
