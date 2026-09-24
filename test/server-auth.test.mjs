import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

async function freePort() {
  const socket = createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  return port;
}

test('server refuses to start without OIDC or an explicit private-development override', async () => {
  const env = { ...process.env, AUTO_SCAN: 'false' };
  for (const name of ['OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_CLIENT_SECRET_FILE', 'OIDC_BASE_URL', 'OIDC_REQUIRED_ROLE', 'AUTH_DISABLED']) delete env[name];
  const child = spawn(process.execPath, ['server.mjs'], { cwd: path.resolve(import.meta.dirname, '..'), env, stdio: ['ignore', 'ignore', 'pipe'] });
  let errors = '';
  child.stderr.on('data', chunk => { errors += chunk; });
  const code = await new Promise(resolve => child.on('exit', resolve));
  assert.notEqual(code, 0);
  assert.match(errors, /OIDC is required/);
});

test('configured OIDC protects real HTTP routes before the API handler', async () => {
  const port = await freePort();
  const data = await mkdtemp(path.join(tmpdir(), 'watchtower-auth-'));
  const child = spawn(process.execPath, ['server.mjs'], {
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
  const child = spawn(process.execPath, ['server.mjs'], {
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
