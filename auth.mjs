import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as oidc from 'openid-client';

const sessionLifetime = 8 * 60 * 60 * 1000;
const flowLifetime = 5 * 60 * 1000;
export const administratorRole = 'WatchTower.Administrator';
export function requiresAdministrator(url) {
  return url.pathname === '/api/settings' || url.pathname === '/api/logs' || url.pathname === '/api/config'
    || url.pathname === '/api/applications' || url.pathname.startsWith('/api/applications/') || url.pathname === '/api/workspaces' || url.pathname.startsWith('/api/workspaces/')
    || (url.pathname === '/api/status' && url.searchParams.has('refresh'));
}
const randomToken = () => randomBytes(32).toString('base64url');
function readProtectedFile(file, settingName) {
  let value;
  try { value = readFileSync(file, 'utf8').trim(); }
  catch (error) { throw new Error(`Could not read ${settingName}: ${error.code || error.message}`); }
  if (!value) throw new Error(`${settingName} is empty`);
  return value;
}
const readClientSecret = file => readProtectedFile(file, 'OIDC_CLIENT_SECRET_FILE');

export function oidcSettings(env = process.env) {
  const names = ['OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_BASE_URL'];
  if (![...names, 'OIDC_CLIENT_SECRET', 'OIDC_CLIENT_SECRET_FILE', 'OIDC_REQUIRED_ROLE'].some(name => env[name])) return null;
  for (const name of names) if (!env[name]) throw new Error(`${name} is required when OIDC is configured`);
  if (env.OIDC_CLIENT_SECRET && env.OIDC_CLIENT_SECRET_FILE) throw new Error('Set either OIDC_CLIENT_SECRET or OIDC_CLIENT_SECRET_FILE, not both');
  let clientSecret = env.OIDC_CLIENT_SECRET;
  if (!clientSecret && env.OIDC_CLIENT_SECRET_FILE) clientSecret = readClientSecret(env.OIDC_CLIENT_SECRET_FILE);
  if (!clientSecret) throw new Error('OIDC_CLIENT_SECRET or OIDC_CLIENT_SECRET_FILE is required when OIDC is configured');
  const issuer = new URL(env.OIDC_ISSUER);
  const base = new URL(env.OIDC_BASE_URL);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname);
  if (issuer.protocol !== 'https:') throw new Error('OIDC_ISSUER must use HTTPS');
  if (base.protocol !== 'https:' && !(base.protocol === 'http:' && local)) throw new Error('OIDC_BASE_URL must use HTTPS outside localhost');
  if (base.username || base.password || base.pathname !== '/' || base.search || base.hash) throw new Error('OIDC_BASE_URL must be an origin without a path or credentials');
  if (issuer.username || issuer.password || issuer.search || issuer.hash) throw new Error('OIDC_ISSUER must be an issuer URL without credentials, query, or fragment');
  if (env.OIDC_ADMIN_GROUP_ID_FILE) readProtectedFile(env.OIDC_ADMIN_GROUP_ID_FILE, 'OIDC_ADMIN_GROUP_ID_FILE');
  return { issuer, base, clientId: env.OIDC_CLIENT_ID, clientSecret, clientSecretFile: env.OIDC_CLIENT_SECRET_FILE || '', adminGroupIdFile: env.OIDC_ADMIN_GROUP_ID_FILE || '', requiredRole: env.OIDC_REQUIRED_ROLE || '' };
}

function cookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').map(part => part.trim().split(/=(.*)/s, 2)).filter(([name, value]) => name && value !== undefined));
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(body);
}

function hasValidRequestOrigin(req, expectedOrigin) {
  const origin = req.headers.origin;
  if (origin === expectedOrigin) return true;
  const referer = req.headers.referer;
  if (referer) { try { if (new URL(referer).origin === expectedOrigin) return true; } catch {} }
  return req.headers['sec-fetch-site'] === 'same-origin';
}

export function createAuth(settings = oidcSettings(), provider = oidc) {
  if (!settings) return null;
  const secure = settings.base.protocol === 'https:';
  const sessionName = secure ? '__Host-watchtower' : 'watchtower_session';
  const flowName = secure ? '__Host-watchtower_flow' : 'watchtower_flow';
  const cookie = (name, value, seconds) => `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${seconds}${secure ? '; Secure' : ''}`;
  const sessions = new Map();
  const flows = new Map();
  const redirectUri = new URL('/auth/callback', settings.base).href;
  let configuration;
  let activeClientSecret = settings.clientSecret;
  const client = () => {
    const currentClientSecret = settings.clientSecretFile ? readClientSecret(settings.clientSecretFile) : settings.clientSecret;
    if (currentClientSecret !== activeClientSecret) {
      activeClientSecret = currentClientSecret;
      configuration = null;
    }
    return configuration ||= provider.discovery(settings.issuer, settings.clientId, activeClientSecret).catch(error => { configuration = null; throw error; });
  };
  const prune = () => {
    const now = Date.now();
    for (const [key, value] of flows) if (value.expires <= now) flows.delete(key);
    for (const [key, value] of sessions) if (value.expires <= now) sessions.delete(key);
  };

  return {
    async handle(req, res, url) {
      prune();
      const values = cookies(req);
      const session = sessions.get(values[sessionName]);
      if (url.pathname === '/auth/login' && req.method === 'GET') {
        if (session) { send(res, 303, '', { Location: '/' }); return true; }
        const state = provider.randomState();
        const nonce = provider.randomNonce();
        const verifier = provider.randomPKCECodeVerifier();
        const challenge = await provider.calculatePKCECodeChallenge(verifier);
        const flowId = randomToken();
        flows.set(flowId, { state, nonce, verifier, expires: Date.now() + flowLifetime });
        let authorizationUrl;
        try {
          authorizationUrl = provider.buildAuthorizationUrl(await client(), {
            redirect_uri: redirectUri, scope: 'openid profile email', state, nonce,
            code_challenge: challenge, code_challenge_method: 'S256',
          });
        } catch (error) {
          flows.delete(flowId);
          console.error(`OIDC discovery failed: ${error.code || error.name}`);
          send(res, 503, 'Identity provider unavailable. Try signing in again later.', { 'Content-Type': 'text/plain; charset=utf-8' });
          return true;
        }
        send(res, 302, '', { Location: authorizationUrl.href, 'Set-Cookie': cookie(flowName, flowId, 300) });
        return true;
      }
      if (url.pathname === '/auth/callback' && req.method === 'GET') {
        const flow = flows.get(values[flowName]);
        flows.delete(values[flowName]);
        if (!flow || flow.expires <= Date.now() || url.searchParams.get('state') !== flow.state) {
          send(res, 400, 'Sign-in expired or invalid. Return to /auth/login to try again.', { 'Content-Type': 'text/plain; charset=utf-8', 'Set-Cookie': cookie(flowName, '', 0) });
          return true;
        }
        try {
          const callback = new URL(settings.base);
          callback.pathname = '/auth/callback';
          callback.search = url.search;
          const tokens = await provider.authorizationCodeGrant(await client(), callback, {
            pkceCodeVerifier: flow.verifier, expectedState: flow.state,
            expectedNonce: flow.nonce, idTokenExpected: true,
          });
          const claims = tokens.claims();
          if (!claims?.sub) throw new Error('OIDC ID token has no subject');
          const roles = [...new Set([...(Array.isArray(claims.roles) ? claims.roles : []), ...(Array.isArray(claims.realm_access?.roles) ? claims.realm_access.roles : []), ...(Array.isArray(claims.resource_access?.[settings.clientId]?.roles) ? claims.resource_access[settings.clientId].roles : [])].map(String))];
          if (settings.requiredRole && !roles.includes(settings.requiredRole)) {
            send(res, 403, 'Your account does not have the required WatchTower role.', { 'Content-Type': 'text/plain; charset=utf-8', 'Set-Cookie': cookie(flowName, '', 0) });
            return true;
          }
          const sessionId = randomToken();
          const claimValues = {
            groups: Array.isArray(claims.groups) ? claims.groups.map(String) : [],
            roles: Array.isArray(claims.roles) ? claims.roles.map(String) : [],
            'realm_access.roles': Array.isArray(claims.realm_access?.roles) ? claims.realm_access.roles.map(String) : [],
            'resource_access.roles': Array.isArray(claims.resource_access?.[settings.clientId]?.roles) ? claims.resource_access[settings.clientId].roles.map(String) : [],
          };
          const username = claims.preferred_username || claims.upn || claims.email || claims.sub;
          const protectedAdminGroup = settings.adminGroupIdFile ? readProtectedFile(settings.adminGroupIdFile, 'OIDC_ADMIN_GROUP_ID_FILE') : '';
          const isAdmin = Object.values(claimValues).some(values => values.includes(administratorRole)) || Boolean(protectedAdminGroup && claimValues.groups.includes(protectedAdminGroup));
          sessions.set(sessionId, { subject: claims.sub, username, name: claims.name || username, isAdmin, claims: claimValues, groupOverage: Boolean(claims._claim_names?.groups), expires: Date.now() + sessionLifetime });
          send(res, 303, '', { Location: '/', 'Set-Cookie': [cookie(flowName, '', 0), cookie(sessionName, sessionId, sessionLifetime / 1000)] });
        } catch (error) {
          console.warn(`OIDC callback rejected: ${error.code || error.name}`);
          send(res, 401, 'Sign-in failed. Return to /auth/login to try again.', { 'Content-Type': 'text/plain; charset=utf-8', 'Set-Cookie': cookie(flowName, '', 0) });
        }
        return true;
      }
      if (url.pathname === '/auth/logout' && req.method === 'POST') {
        if (!hasValidRequestOrigin(req, settings.base.origin)) { send(res, 403, 'Invalid request origin.'); return true; }
        sessions.delete(values[sessionName]);
        send(res, 303, '', { Location: '/auth/login', 'Set-Cookie': cookie(sessionName, '', 0) });
        return true;
      }
      if (!session) {
        if (url.pathname.startsWith('/api/')) send(res, 401, JSON.stringify({ error: 'Sign-in required' }), { 'Content-Type': 'application/json; charset=utf-8' });
        else send(res, 303, '', { Location: '/auth/login' });
        return true;
      }
      if (url.pathname === '/api/session' && req.method === 'GET') {
        send(res, 200, JSON.stringify({ enabled: true, user: session.name, isAdmin: session.isAdmin, claims: session.isAdmin ? session.claims : undefined, groupOverage: session.groupOverage }), { 'Content-Type': 'application/json; charset=utf-8' });
        return true;
      }
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !hasValidRequestOrigin(req, settings.base.origin)) {
        send(res, 403, JSON.stringify({ error: 'Invalid request origin' }), { 'Content-Type': 'application/json; charset=utf-8' });
        return true;
      }
      req.authUser = { issuer: settings.issuer.href, subject: session.subject, username: session.username, name: session.name, isAdmin: session.isAdmin, claims: session.claims, groupOverage: session.groupOverage };
      return false;
    },
  };
}
