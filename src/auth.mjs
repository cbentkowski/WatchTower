import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as oidc from 'openid-client';

const sessionLifetime = 8 * 60 * 60 * 1000;
const flowLifetime = 5 * 60 * 1000;
export const administratorRole = 'WatchTower.Administrator';
export function requiresAdministrator(url) {
  return url.pathname.startsWith('/api/settings') || url.pathname === '/api/logs' || url.pathname === '/api/config'
    || url.pathname === '/api/applications' || url.pathname.startsWith('/api/applications/') || url.pathname === '/api/workspaces' || url.pathname.startsWith('/api/workspaces/') || url.pathname === '/api/owners' || url.pathname.startsWith('/api/owners/')
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
  if (![...names, 'OIDC_CLIENT_SECRET', 'OIDC_CLIENT_SECRET_FILE', 'OIDC_REQUIRED_ROLE', 'OIDC_PROMPT'].some(name => env[name])) return null;
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
  const prompt = env.OIDC_PROMPT || '';
  if (prompt && !['select_account', 'login'].includes(prompt)) throw new Error('OIDC_PROMPT must be select_account or login when configured');
  if (env.OIDC_ADMIN_GROUP_ID_FILE) readProtectedFile(env.OIDC_ADMIN_GROUP_ID_FILE, 'OIDC_ADMIN_GROUP_ID_FILE');
  return { issuer, base, clientId: env.OIDC_CLIENT_ID, clientSecret, clientSecretFile: env.OIDC_CLIENT_SECRET_FILE || '', adminGroupIdFile: env.OIDC_ADMIN_GROUP_ID_FILE || '', requiredRole: env.OIDC_REQUIRED_ROLE || '', prompt };
}

function cookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').map(part => part.trim().split(/=(.*)/s, 2)).filter(([name, value]) => name && value !== undefined));
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(body);
}

function authPage(title, message, buttonLabel = 'Sign in') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>${title} · WatchTower</title><style>
    :root{font-family:Arial,sans-serif;color:#18283a;background:#eef3f6}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 50% 15%,#fff 0,#eef3f6 48%,#dce8ed 100%)}main{width:min(430px,100%);padding:42px;text-align:center;background:#fff;border:1px solid #dce6eb;border-radius:16px;box-shadow:0 20px 60px #1732461c}.logo{width:80px;height:80px;margin:0 auto 20px}h1{margin:0;font-size:31px;letter-spacing:-.04em;color:#122336}.sub{margin:6px 0 28px;color:#13987c;font-size:10px;font-weight:700;letter-spacing:.2em}.message{margin:0 0 28px;color:#607487;line-height:1.6}.auth-button{display:inline-block;padding:12px 20px;border-radius:8px;background:#147d69;color:#fff;text-decoration:none;font-weight:700}.auth-button:hover{background:#0f6b59}.auth-note{display:block;margin-top:28px;color:#8495a2}.auth-footer{display:flex;justify-content:center;gap:6px;flex-wrap:wrap;margin-top:22px;padding-top:18px;border-top:1px solid #e5ecef;color:#8495a2;font-size:11px}.auth-footer a{color:#147d69;font-weight:700;text-decoration:none}.auth-footer a:hover,.auth-footer a:focus{text-decoration:underline}@media(prefers-color-scheme:dark){:root{color:#d8e5ed;background:#09131d}body{background:radial-gradient(circle at 50% 15%,#193242 0,#0d1c29 50%,#08121b 100%)}main{background:#102434;border-color:#294353;box-shadow:0 20px 60px #0008}h1{color:#eefbf7}.message{color:#b2c5d0}.auth-note,.auth-footer{color:#7f98a9}.auth-footer{border-color:#294353}.auth-footer a{color:#74d9bf}}
  </style></head><body><main><svg class="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="WatchTower lighthouse"><rect width="64" height="64" rx="14" fill="#102434"/><path d="M34 24 61 10v32L34 31Z" fill="#4bd4b2" opacity=".52"/><path d="M35 25 61 19v14l-26-4Z" fill="#a1ffe0" opacity=".9"/><path d="M19 53h21M22 49l3-27h10l3 27Z" fill="#dffbf2" stroke="#4bd4b2" stroke-width="2.5" stroke-linejoin="round"/><path d="M21 22h18l-3-6H24Z" fill="#4bd4b2"/><path d="M25 16V9h10v7" fill="none" stroke="#dffbf2" stroke-width="2.5"/><path d="M17 54h26" stroke="#4bd4b2" stroke-width="3" stroke-linecap="round"/></svg><h1>WatchTower</h1><div class="sub">VULNERABILITY INTELLIGENCE</div><p class="message">${message}</p><a class="auth-button" href="/auth/login">${buttonLabel}</a><small class="auth-note">Authentication is provided by your configured identity provider.</small><footer class="auth-footer">© 2026 Christopher Bentkowski <span aria-hidden="true">·</span> <a href="https://github.com/cbentkowski/WatchTower" target="_blank" rel="noopener noreferrer">WatchTower on GitHub</a></footer></main></body></html>`;
}

function hasValidRequestOrigin(req, expectedOrigin) {
  const origin = req.headers.origin;
  if (origin === expectedOrigin) return true;
  const referer = req.headers.referer;
  if (referer) { try { if (new URL(referer).origin === expectedOrigin) return true; } catch {} }
  return req.headers['sec-fetch-site'] === 'same-origin';
}

function requestOrigin(req, url) {
  const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
  const host = forwardedHost || req.headers.host || url.host;
  const forwardedProtocol = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  const protocol = forwardedProtocol || (req.socket?.encrypted ? 'https' : url.protocol.replace(':', ''));
  try { return new URL(`${protocol}://${host}`).origin; }
  catch { return url.origin; }
}

export function createAuth(settings = oidcSettings(), provider = oidc, authEvent = () => {}) {
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
  const record = async (action, actor = null, context = {}) => {
    try { await authEvent(action, actor, context); }
    catch (error) { console.error(`Could not record authentication event: ${error.message}`); }
  };
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
      if (req.method === 'GET' && ['/login', '/auth/login', '/auth/callback'].includes(url.pathname) && requestOrigin(req, url) !== settings.base.origin) {
        const canonical = new URL(`${url.pathname}${url.search}`, settings.base);
        await record('Authentication request redirected', null, { outcome: 'info', issuer: settings.issuer.href, fromOrigin: requestOrigin(req, url), toOrigin: settings.base.origin, path: url.pathname });
        send(res, 308, '', { Location: canonical.href });
        return true;
      }
      if (url.pathname === '/login' && req.method === 'GET') {
        if (session) { send(res, 303, '', { Location: '/' }); return true; }
        send(res, 200, authPage('Sign in', 'Sign in to view application security and lifecycle status.'), { 'Content-Type': 'text/html; charset=utf-8' });
        return true;
      }
      if (url.pathname === '/signed-out' && req.method === 'GET') {
        send(res, 200, authPage('Signed out', 'You have successfully signed out of WatchTower.', 'Sign in again'), { 'Content-Type': 'text/html; charset=utf-8' });
        return true;
      }
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
            ...(settings.prompt ? { prompt: settings.prompt } : {}),
          });
        } catch (error) {
          flows.delete(flowId);
          console.error(`OIDC discovery failed: ${error.code || error.name}`);
          await record('Sign-in provider unavailable', null, { outcome: 'error', issuer: settings.issuer.href, reason: error.code || error.name || 'Error' });
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
          await record('Sign-in callback rejected', null, { outcome: 'warn', issuer: settings.issuer.href, reason: !flow ? 'missing-flow' : flow.expires <= Date.now() ? 'expired-flow' : 'state-mismatch' });
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
          const claimValues = {
            groups: Array.isArray(claims.groups) ? claims.groups.map(String) : [],
            roles: Array.isArray(claims.roles) ? claims.roles.map(String) : [],
            'realm_access.roles': Array.isArray(claims.realm_access?.roles) ? claims.realm_access.roles.map(String) : [],
            'resource_access.roles': Array.isArray(claims.resource_access?.[settings.clientId]?.roles) ? claims.resource_access[settings.clientId].roles.map(String) : [],
          };
          const username = claims.preferred_username || claims.upn || claims.email || claims.sub;
          const actor = { subject: String(claims.sub), username: String(username), name: String(claims.name || username) };
          const groupOverage = Boolean(claims._claim_names?.groups || claims.hasgroups);
          if (settings.requiredRole && !roles.includes(settings.requiredRole)) {
            await record('Sign-in denied', actor, { outcome: 'warn', issuer: settings.issuer.href, reason: 'required-role-missing', claims: claimValues, groupOverage });
            send(res, 403, 'Your account does not have the required WatchTower role.', { 'Content-Type': 'text/plain; charset=utf-8', 'Set-Cookie': cookie(flowName, '', 0) });
            return true;
          }
          const sessionId = randomToken();
          const protectedAdminGroup = settings.adminGroupIdFile ? readProtectedFile(settings.adminGroupIdFile, 'OIDC_ADMIN_GROUP_ID_FILE') : '';
          const isAdmin = Object.values(claimValues).some(values => values.includes(administratorRole)) || Boolean(protectedAdminGroup && claimValues.groups.includes(protectedAdminGroup));
          sessions.set(sessionId, { ...actor, isAdmin, claims: claimValues, groupOverage, expires: Date.now() + sessionLifetime });
          await record('Sign-in succeeded', actor, { outcome: 'success', issuer: settings.issuer.href, claims: claimValues, groupOverage, administrator: isAdmin, protectedAdminClaim: protectedAdminGroup && claimValues.groups.includes(protectedAdminGroup) ? protectedAdminGroup : '' });
          send(res, 303, '', { Location: '/', 'Set-Cookie': [cookie(flowName, '', 0), cookie(sessionName, sessionId, sessionLifetime / 1000)] });
        } catch (error) {
          console.warn(`OIDC callback rejected: ${error.code || error.name}`);
          await record('Sign-in callback rejected', null, { outcome: 'error', issuer: settings.issuer.href, reason: error.code || error.name || 'Error' });
          send(res, 401, 'Sign-in failed. Return to /auth/login to try again.', { 'Content-Type': 'text/plain; charset=utf-8', 'Set-Cookie': cookie(flowName, '', 0) });
        }
        return true;
      }
      if (url.pathname === '/auth/logout' && req.method === 'POST') {
        if (!hasValidRequestOrigin(req, settings.base.origin)) { send(res, 403, 'Invalid request origin.'); return true; }
        sessions.delete(values[sessionName]);
        flows.delete(values[flowName]);
        if (session) await record('Signed out', { subject: session.subject, username: session.username, name: session.name }, { outcome: 'success', issuer: settings.issuer.href });
        send(res, 303, '', { Location: '/signed-out', 'Set-Cookie': [cookie(sessionName, '', 0), cookie(flowName, '', 0)] });
        return true;
      }
      if (!session) {
        if (values[sessionName]) await record('Session rejected', null, { outcome: 'warn', issuer: settings.issuer.href, path: url.pathname.startsWith('/api/') ? '/api/*' : url.pathname });
        const rejectedSession = values[sessionName] ? { 'Set-Cookie': cookie(sessionName, '', 0) } : {};
        if (url.pathname.startsWith('/api/')) send(res, 401, JSON.stringify({ error: 'Sign-in required' }), { 'Content-Type': 'application/json; charset=utf-8', ...rejectedSession });
        else send(res, 303, '', { Location: '/login', ...rejectedSession });
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
