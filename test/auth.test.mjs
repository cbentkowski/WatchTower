import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createAuth, oidcSettings, requiresAdministrator } from '../src/auth.mjs';

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
  assert.throws(() => oidcSettings({ ...values, OIDC_PROMPT: 'consent' }), /OIDC_PROMPT must be select_account or login/);
});

test('OIDC account selection is optional and validated', () => {
  assert.equal(oidcSettings(values).prompt, '');
  assert.equal(oidcSettings({ ...values, OIDC_PROMPT: 'select_account' }).prompt, 'select_account');
  assert.equal(oidcSettings({ ...values, OIDC_PROMPT: 'login' }).prompt, 'login');
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
  assert.equal(page.headers.Location, '/login');
  const loginPage = response();
  await auth.handle({ method: 'GET', headers: {} }, loginPage, new URL('https://home.example.com/login'));
  assert.equal(loginPage.status, 200);
  assert.match(loginPage.body, /WatchTower/);
  assert.match(loginPage.body, /href="\/auth\/login"/);
  assert.match(loginPage.body, /© 2026 Christopher Bentkowski/);
  assert.match(loginPage.body, /href="https:\/\/github\.com\/cbentkowski\/WatchTower"/);
});

test('stale sessions are cleared while preserving API and browser response semantics', async () => {
  const auth = createAuth(oidcSettings(values));
  const cookie = '__Host-watchtower=stale-session';
  const api = response();
  await auth.handle({ method: 'GET', headers: { cookie } }, api, new URL('https://home.example.com/api/session'));
  assert.equal(api.status, 401);
  assert.match(api.body, /Sign-in required/);
  assert.match(api.headers['Set-Cookie'], /__Host-watchtower=.*Max-Age=0.*Secure/);

  const page = response();
  await auth.handle({ method: 'GET', headers: { cookie } }, page, new URL('https://home.example.com/'));
  assert.equal(page.status, 303);
  assert.equal(page.headers.Location, '/login');
  assert.match(page.headers['Set-Cookie'], /__Host-watchtower=.*Max-Age=0.*Secure/);
});

test('login binds the callback to a browser flow and creates a protected session', async () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'watchtower-admin-group-'));
  const adminGroupFile = path.join(directory, 'admin-group-id');
  writeFileSync(adminGroupFile, 'entra-admin-group-id\n');
  let parameters;
  const events = [];
  const provider = {
    discovery: async () => ({}),
    randomState: () => 'expected-state',
    randomNonce: () => 'expected-nonce',
    randomPKCECodeVerifier: () => 'verifier',
    calculatePKCECodeChallenge: async () => 'challenge',
    buildAuthorizationUrl: (_config, input) => {
      parameters = input;
      const authorizationUrl = new URL('https://login.example.com/authorize');
      if (input.prompt) authorizationUrl.searchParams.set('prompt', input.prompt);
      return authorizationUrl;
    },
    authorizationCodeGrant: async (_config, _url, checks) => {
      assert.equal(checks.expectedState, 'expected-state');
      assert.equal(checks.expectedNonce, 'expected-nonce');
      assert.equal(checks.pkceCodeVerifier, 'verifier');
      return { claims: () => ({ sub: 'user-123', name: 'Test User', preferred_username: 'test.user@example.com', groups: ['entra-admin-group-id'], roles: ['WatchTower.User'] }) };
    },
  };
  const auth = createAuth(oidcSettings({ ...values, OIDC_REQUIRED_ROLE: 'WatchTower.User', OIDC_ADMIN_GROUP_ID_FILE: adminGroupFile }), provider, (...event) => events.push(event));
  const login = response();
  await auth.handle({ method: 'GET', headers: {} }, login, new URL('https://home.example.com/auth/login'));
  assert.equal(login.status, 302);
  assert.equal(parameters.redirect_uri, 'https://home.example.com/auth/callback');
  assert.equal(parameters.code_challenge_method, 'S256');
  assert.equal(parameters.prompt, undefined);
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
  const sessionRequest = { method: 'GET', headers: { cookie: sessionCookie } };
  assert.equal(await auth.handle(sessionRequest, sessionResponse, new URL('https://home.example.com/api/session')), false);
  assert.equal(sessionRequest.authUser.isAdmin, true);
  const api = response();
  const authenticated = { method: 'GET', headers: { cookie: sessionCookie } };
  assert.equal(await auth.handle(authenticated, api, new URL('https://home.example.com/api/settings')), false);
  assert.deepEqual(authenticated.authUser, { issuer: values.OIDC_ISSUER, subject: 'user-123', username: 'test.user@example.com', name: 'Test User', isAdmin: true, claims: { groups: ['entra-admin-group-id'], roles: ['WatchTower.User'], 'realm_access.roles': [], 'resource_access.roles': [] }, groupOverage: false });
  const signIn = events.find(([action]) => action === 'Sign-in succeeded');
  assert.deepEqual(signIn[1], { subject: 'user-123', username: 'test.user@example.com', name: 'Test User' });
  assert.deepEqual(signIn[2].claims.groups, ['entra-admin-group-id']);
  assert.equal(signIn[2].protectedAdminClaim, 'entra-admin-group-id');
  assert.ok(!JSON.stringify(events).includes('test-secret'));
  assert.ok(!JSON.stringify(events).includes('code=abc'));
  const mutation = response();
  await auth.handle({ method: 'POST', headers: { cookie: sessionCookie, origin: 'https://evil.example' } }, mutation, new URL('https://home.example.com/api/settings'));
  assert.equal(mutation.status, 403);
  const fetchMetadataMutation = { method: 'POST', headers: { cookie: sessionCookie, 'sec-fetch-site': 'same-origin' } };
  assert.equal(await auth.handle(fetchMetadataMutation, response(), new URL('https://home.example.com/api/settings')), false);
  assert.equal(fetchMetadataMutation.authUser.isAdmin, true);
  const proxiedMutation = { method: 'POST', headers: { cookie: sessionCookie, origin: 'http://watchtower:4173', 'sec-fetch-site': 'same-origin' } };
  assert.equal(await auth.handle(proxiedMutation, response(), new URL('https://home.example.com/api/settings')), false);
  assert.equal(proxiedMutation.authUser.isAdmin, true);
  const crossSiteLogout = response();
  await auth.handle({ method: 'POST', headers: { cookie: sessionCookie, referer: 'https://evil.example/page' } }, crossSiteLogout, new URL('https://home.example.com/auth/logout'));
  assert.equal(crossSiteLogout.status, 403);
  const logout = response();
  await auth.handle({ method: 'POST', headers: { cookie: sessionCookie, referer: 'https://home.example.com/settings' } }, logout, new URL('https://home.example.com/auth/logout'));
  assert.equal(logout.status, 303);
  assert.equal(logout.headers.Location, '/signed-out');
  assert.ok(events.some(([action]) => action === 'Signed out'));
  assert.equal(logout.headers['Set-Cookie'].length, 2);
  assert.match(logout.headers['Set-Cookie'][0], /watchtower=.*Max-Age=0/);
  assert.match(logout.headers['Set-Cookie'][1], /watchtower_flow=.*Max-Age=0/);
  const signedOut = response();
  await auth.handle({ method: 'GET', headers: {} }, signedOut, new URL('https://home.example.com/signed-out'));
  assert.equal(signedOut.status, 200);
  assert.match(signedOut.body, /successfully signed out/);
  assert.match(signedOut.body, /© 2026 Christopher Bentkowski/);
  assert.match(signedOut.body, /WatchTower on GitHub/);
  const proxiedLogout = response();
  await auth.handle({ method: 'POST', headers: { cookie: sessionCookie, origin: 'http://watchtower:4173', 'sec-fetch-site': 'same-origin' } }, proxiedLogout, new URL('https://home.example.com/auth/logout'));
  assert.equal(proxiedLogout.status, 303);
  assert.equal(proxiedLogout.headers.Location, '/signed-out');
  rmSync(directory, { recursive: true, force: true });
});

for (const prompt of ['select_account', 'login']) {
  test(`login sends the ${prompt} prompt when configured`, async () => {
    let parameters;
    const provider = {
      discovery: async () => ({}),
      randomState: () => 'state',
      randomNonce: () => 'nonce',
      randomPKCECodeVerifier: () => 'verifier',
      calculatePKCECodeChallenge: async () => 'challenge',
      buildAuthorizationUrl: (_config, input) => {
        parameters = input;
        const authorizationUrl = new URL('https://login.example.com/authorize');
        authorizationUrl.searchParams.set('prompt', input.prompt);
        return authorizationUrl;
      },
    };
    const auth = createAuth(oidcSettings({ ...values, OIDC_PROMPT: prompt }), provider);
    const loginResponse = response();
    await auth.handle({ method: 'GET', headers: {} }, loginResponse, new URL('https://home.example.com/auth/login'));
    assert.equal(loginResponse.status, 302);
    assert.equal(parameters.prompt, prompt);
    assert.equal(new URL(loginResponse.headers.Location).searchParams.get('prompt'), prompt);
  });
}

test('login redirects alternate hostnames to the configured OIDC origin', async () => {
  const auth = createAuth(oidcSettings(values), {});
  const alternate = response();
  await auth.handle({ method: 'GET', headers: { host: 'watchtower.example.com' }, socket: { encrypted: true } }, alternate, new URL('https://watchtower.example.com/auth/login'));
  assert.equal(alternate.status, 308);
  assert.equal(alternate.headers.Location, 'https://home.example.com/auth/login');

  const proxied = response();
  await auth.handle({ method: 'GET', headers: { host: 'watchtower:4173', 'x-forwarded-host': 'watchtower.example.com', 'x-forwarded-proto': 'https' } }, proxied, new URL('http://watchtower:4173/login'));
  assert.equal(proxied.status, 308);
  assert.equal(proxied.headers.Location, 'https://home.example.com/login');
});

test('administrator authorization covers every privileged API', () => {
  for (const route of ['/api/settings', '/api/settings/test-email', '/api/logs', '/api/config', '/api/applications', '/api/applications/test', '/api/workspaces', '/api/owners', '/api/owners/example', '/api/status?refresh=1']) {
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
