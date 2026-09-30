import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { request } from 'node:https';

async function freePort() {
  const socket = createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  return port;
}

function httpsGet(url, ca) {
  return new Promise((resolve, reject) => {
    const req = request(url, { ca }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('browser styles use local system fonts without external requests', async () => {
  const styles = await readFile(path.resolve(import.meta.dirname, '..', 'src', 'web', 'styles.css'), 'utf8');
  const html = await readFile(path.resolve(import.meta.dirname, '..', 'src', 'web', 'index.html'), 'utf8');
  assert.doesNotMatch(styles, /fonts\.googleapis\.com|@import\s+url\(https?:/i);
  assert.match(styles, /font-family:system-ui/);
  assert.match(html, /© 2026 Christopher Bentkowski/);
  assert.match(html, /href="https:\/\/github\.com\/cbentkowski\/WatchTower"/);
});

test('browser API requests return stale sessions to sign-in', async () => {
  const script = await readFile(path.resolve(import.meta.dirname, '..', 'src', 'web', 'app.js'), 'utf8');
  assert.match(script, /response\.status === 401/);
  assert.match(script, /request\.pathname\.startsWith\('\/api\/'\)/);
  assert.match(script, /location\.replace\('\/login'\)/);
});

test('server refuses to start without OIDC or an explicit private-development override', async () => {
  const env = { ...process.env, AUTO_SCAN: 'false' };
  for (const name of ['OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_CLIENT_SECRET_FILE', 'OIDC_BASE_URL', 'OIDC_REQUIRED_ROLE', 'OIDC_PROMPT', 'AUTH_DISABLED']) delete env[name];
  const child = spawn(process.execPath, ['src/server.mjs'], { cwd: path.resolve(import.meta.dirname, '..'), env, stdio: ['ignore', 'ignore', 'pipe'] });
  let errors = '';
  child.stderr.on('data', chunk => { errors += chunk; });
  const code = await new Promise(resolve => child.on('exit', resolve));
  assert.notEqual(code, 0);
  assert.match(errors, /OIDC is required/);
});

test('server fails closed when native TLS is enabled without certificate files', async () => {
  const env = { ...process.env, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', TLS_ENABLED: 'true' };
  for (const name of ['TLS_CERT_FILE', 'TLS_KEY_FILE']) delete env[name];
  const child = spawn(process.execPath, ['src/server.mjs'], { cwd: path.resolve(import.meta.dirname, '..'), env, stdio: ['ignore', 'ignore', 'pipe'] });
  let errors = '';
  child.stderr.on('data', chunk => { errors += chunk; });
  const code = await new Promise(resolve => child.on('exit', resolve));
  assert.notEqual(code, 0);
  assert.match(errors, /TLS_CERT_FILE and TLS_KEY_FILE are required/);
});

test('native HTTPS serves the health endpoint from mounted certificate files', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-tls-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const config = path.join(directory, 'config');
  await mkdir(config);
  await writeFile(path.join(config, 'general.yaml'), 'general:\n  protocol: "http"\n  host: "public.example"\n  port: 80\n');
  const cert = path.join(directory, 'certificate.pem');
  const key = path.join(directory, 'private-key.pem');
  const generated = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=localhost', '-keyout', key, '-out', cert], { encoding: 'utf8' });
  assert.equal(generated.status, 0, generated.stderr);
  const certificateAuthority = await readFile(cert);
  const port = await freePort();
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: config, DEFAULT_CONFIG_DIR: path.resolve(import.meta.dirname, '..', 'config'), DATA_DIR: path.join(directory, 'data'), AUTO_SCAN: 'false', AUTH_DISABLED: 'true', TLS_ENABLED: 'true', TLS_CERT_FILE: cert, TLS_KEY_FILE: key },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let errors = '';
  child.stderr.on('data', chunk => { errors += chunk; });
  try {
    let health;
    for (let attempt = 0; attempt < 40; attempt++) {
      try { health = await httpsGet(`https://localhost:${port}/healthz`, certificateAuthority); break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.ok(health, `HTTPS server started: ${errors}`);
    assert.equal(health.status, 200);
    assert.deepEqual(JSON.parse(health.body), { status: 'ok' });
    const settings = await httpsGet(`https://localhost:${port}/api/settings`, certificateAuthority);
    assert.equal(settings.status, 200);
    assert.deepEqual(JSON.parse(settings.body).general, { protocol: 'http', host: 'public.example', port: 80 });
  } finally { child.kill(); }
});

test('server fails closed when the native TLS private key does not match the certificate', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-tls-mismatch-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const cert = path.join(directory, 'certificate.pem');
  const firstKey = path.join(directory, 'first-key.pem');
  const secondCert = path.join(directory, 'second-certificate.pem');
  const secondKey = path.join(directory, 'second-key.pem');
  for (const [outputCert, outputKey, commonName] of [[cert, firstKey, 'first'], [secondCert, secondKey, 'second']]) {
    const generated = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', `/CN=${commonName}`, '-keyout', outputKey, '-out', outputCert], { encoding: 'utf8' });
    assert.equal(generated.status, 0, generated.stderr);
  }
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', TLS_ENABLED: 'true', TLS_CERT_FILE: cert, TLS_KEY_FILE: secondKey },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let errors = '';
  child.stderr.on('data', chunk => { errors += chunk; });
  const code = await new Promise(resolve => child.on('exit', resolve));
  assert.notEqual(code, 0);
  assert.match(errors, /Native TLS initialization failed/);
});

test('configured OIDC protects real HTTP routes before the API handler', async () => {
  const port = await freePort();
  const data = await mkdtemp(path.join(tmpdir(), 'watchtower-auth-'));
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), DATA_DIR: data, AUTO_SCAN: 'false',
      OIDC_ISSUER: 'https://login.example.com/realms/watchtower', OIDC_CLIENT_ID: 'watchtower',
      OIDC_CLIENT_SECRET: 'test-secret', OIDC_BASE_URL: 'https://home.example.com' },
    stdio: 'ignore',
  });
  try {
    let api;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { api = await fetch(`http://127.0.0.1:${port}/api/config`, { redirect: 'manual' }); break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.ok(api, 'server started');
    assert.equal(api.status, 401);
    assert.equal(api.headers.get('cache-control'), 'no-store');
    const settings = await fetch(`http://127.0.0.1:${port}/api/settings`, { redirect: 'manual' });
    assert.equal(settings.status, 401);
    const page = await fetch(`http://127.0.0.1:${port}/`, { redirect: 'manual' });
    assert.equal(page.status, 303);
    assert.equal(page.headers.get('location'), '/login');
    assert.match(page.headers.get('content-security-policy'), /script-src 'self'/);
    assert.equal(page.headers.get('cross-origin-opener-policy'), 'same-origin');
    assert.match(page.headers.get('permissions-policy'), /camera=\(\)/);
    const health = await fetch(`http://127.0.0.1:${port}/healthz`, { redirect: 'manual' });
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: 'ok' });
  } finally {
    child.kill();
    await rm(data, { recursive: true, force: true });
  }
});

test('direct server startup migrates legacy YAML files into the config directory', async () => {
  const port = await freePort();
  const home = await mkdtemp(path.join(tmpdir(), 'watchtower-config-'));
  const config = path.join(home, 'config');
  const data = path.join(home, 'data');
  const files = {
    'applications.yaml': 'applications:\n',
    'workspaces.yaml': 'workspaces:\n',
    'smtp.yaml': 'enabled: false\n',
    'general.yaml': 'protocol: "https"\nhost: "home.example.com"\nport: 443\n',
  };
  for (const [name, contents] of Object.entries(files)) await writeFile(path.join(home, name), contents);
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: config, DATA_DIR: data,
      AUTO_SCAN: 'false', AUTH_DISABLED: 'true', OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' },
    stdio: 'ignore',
  });
  try {
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { ready = (await fetch(`http://127.0.0.1:${port}/api/session`)).ok; if (ready) break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.equal(ready, true);
    for (const [name, contents] of Object.entries(files)) {
      assert.equal(await readFile(path.join(config, name), 'utf8'), contents);
      await assert.rejects(readFile(path.join(home, name), 'utf8'), { code: 'ENOENT' });
    }
  } finally {
    child.kill();
    await rm(home, { recursive: true, force: true });
  }
});

test('startup gives existing applications safe ownership and risk-context defaults', async () => {
  const port = await freePort();
  const home = await mkdtemp(path.join(tmpdir(), 'watchtower-context-migration-'));
  const config = path.join(home, 'config');
  const data = path.join(home, 'data');
  await mkdir(config);
  await writeFile(path.join(config, 'applications.yaml'), 'applications:\n  - id: 11111111-1111-4111-8111-111111111111\n    name: "Existing App"\n    version: "1.0"\n    cpeVendor: "example"\n    cpeProduct: "existing"\n    cpeName: "cpe:2.3:a:example:existing:*:*:*:*:*:*:*:*"\n    cpeMode: "product"\n    eolDate: "2030-01-01"\n');
  await writeFile(path.join(config, 'workspaces.yaml'), 'workspaces:\n');
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: config, DATA_DIR: data,
      AUTO_SCAN: 'false', AUTH_DISABLED: 'true', OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' },
    stdio: 'ignore',
  });
  try {
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { ready = (await fetch(`http://127.0.0.1:${port}/api/session`)).ok; if (ready) break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.equal(ready, true);
    const migrated = await readFile(path.join(config, 'applications.yaml'), 'utf8');
    assert.match(migrated, /criticality: "unspecified"/);
    assert.match(migrated, /environment: "unspecified"/);
    assert.match(migrated, /exposure: "unknown"/);
    assert.match(migrated, /ownerIds:\n\s+tags:/);
    const configured = await (await fetch(`http://127.0.0.1:${port}/api/config`)).json();
    assert.deepEqual(configured.applications[0].ownerIds, []);
    assert.deepEqual(configured.applications[0].tags, []);
  } finally {
    child.kill();
    await rm(home, { recursive: true, force: true });
  }
});

test('startup maps legacy workspace notification emails to unique owners', async () => {
  const port = await freePort();
  const home = await mkdtemp(path.join(tmpdir(), 'watchtower-workspace-owner-migration-'));
  const config = path.join(home, 'config');
  const data = path.join(home, 'data');
  await mkdir(config);
  await writeFile(path.join(config, 'applications.yaml'), 'applications:\n');
  await writeFile(path.join(config, 'owners.yaml'), 'owners:\n  - id: 11111111-1111-4111-8111-111111111111\n    name: "Existing owner"\n    email: "existing@example.com"\n');
  await writeFile(path.join(config, 'workspaces.yaml'), 'workspaces:\n  - id: 22222222-2222-4222-8222-222222222222\n    name: "Operations"\n    notificationEmails: "EXISTING@example.com, new@example.com"\n    applications:\n');
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: config, DATA_DIR: data, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' },
    stdio: 'ignore',
  });
  try {
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { ready = (await fetch(`http://127.0.0.1:${port}/api/session`)).ok; if (ready) break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.equal(ready, true);
    const configured = await (await fetch(`http://127.0.0.1:${port}/api/config`)).json();
    assert.equal(configured.owners.length, 2);
    assert.deepEqual(new Set(configured.owners.map(owner => owner.email.toLowerCase())), new Set(['existing@example.com', 'new@example.com']));
    assert.equal(configured.workspaces[0].ownerIds.length, 2);
    const migrated = await readFile(path.join(config, 'workspaces.yaml'), 'utf8');
    assert.doesNotMatch(migrated, /notificationEmails/);
    assert.match(migrated, /ownerIds:/);
  } finally {
    child.kill();
    await rm(home, { recursive: true, force: true });
  }
});
