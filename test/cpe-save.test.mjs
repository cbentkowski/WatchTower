import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

async function freePort() {
  const socket = createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  return port;
}

test('application API saves a canonical CPE containing escaped punctuation', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-cpe-save-'));
  const data = path.join(directory, 'data');
  await mkdir(data);
  await writeFile(path.join(directory, 'applications.yaml'), 'applications:\n');
  await writeFile(path.join(directory, 'workspaces.yaml'), 'workspaces:\n');
  await writeFile(path.join(directory, 'feeds.yaml'), 'version: 1\nfeeds:\n');
  const port = await freePort();
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: directory, DATA_DIR: data, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let restartedChild;
  let serverError = '';
  child.stderr.on('data', chunk => { serverError += chunk; });
  const origin = `http://127.0.0.1:${port}`;
  try {
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { ready = (await fetch(`${origin}/api/session`)).ok; if (ready) break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.equal(ready, true, serverError);
    const cpeName = String.raw`cpe:2.3:a:notepad-plus-plus:notepad\+\+:*:*:*:*:*:*:*:*`;
    const response = await fetch(`${origin}/api/applications`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Notepad++', version: '8.8.5', cpeName, cpeMode: 'product', cpeTitle: 'Notepad++', eolDate: '2030-01-01' }),
    });
    assert.equal(response.status, 201, await response.text());
    assert.match(await readFile(path.join(directory, 'applications.yaml'), 'utf8'), /notepad\\\\\+\\\\\+/);
    child.kill();
    await once(child, 'exit');

    restartedChild = spawn(process.execPath, ['src/server.mjs'], {
      cwd: path.resolve(import.meta.dirname, '..'),
      env: { ...process.env, HOST: '127.0.0.1', SERVER_PORT: String(port), CONFIG_DIR: directory, DATA_DIR: data, AUTO_SCAN: 'false', AUTH_DISABLED: 'true', OIDC_ISSUER: '', OIDC_CLIENT_ID: '', OIDC_CLIENT_SECRET: '', OIDC_CLIENT_SECRET_FILE: '', OIDC_BASE_URL: '' },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let restartError = '';
    restartedChild.stderr.on('data', chunk => { restartError += chunk; });
    let restarted = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { restarted = (await fetch(`${origin}/api/session`)).ok; if (restarted) break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.equal(restarted, true, restartError);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill();
      await once(child, 'exit');
    }
    if (restartedChild?.exitCode === null && restartedChild.signalCode === null) {
      restartedChild.kill();
      await once(restartedChild, 'exit');
    }
    await rm(directory, { recursive: true, force: true });
  }
});
