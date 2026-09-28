import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createLogger } from '../logger.mjs';

test('system, feed, audit, and authentication events use independent files', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-logs-'));
  try {
    const logger = createLogger(directory);
    await logger.log('info', 'Scan completed');
    await logger.feed('error', 'Feed collection failed', 'Vendor feed');
    await logger.feed('warn', 'NVD assessment unavailable', 'Built-in source');
    await logger.audit('Settings updated', { subject: 'user-1', name: 'Admin' }, { type: 'settings', id: 'general' }, { host: true }, 'Host changed');
    await logger.authentication('Sign-in succeeded', { subject: 'user-1', name: 'Admin' }, { outcome: 'success', groupCount: 1, identities: [] });

    assert.equal((await logger.recent('system'))[0].message, 'Scan completed');
    assert.deepEqual((await logger.recent('feed')).map(entry => entry.message), ['NVD assessment unavailable', 'Feed collection failed']);
    assert.equal((await logger.recent('audit'))[0].message, 'Settings updated');
    assert.equal((await logger.recent('auth'))[0].message, 'Sign-in succeeded');
    for (const name of ['system', 'feed', 'audit', 'auth']) assert.match(await readFile(path.join(directory, `${name}.jsonl`), 'utf8'), new RegExp(name === 'auth' ? 'Sign-in succeeded' : name === 'audit' ? 'Settings updated' : name === 'feed' ? 'NVD assessment unavailable' : 'Scan completed'));
    assert.doesNotMatch(await readFile(path.join(directory, 'system.jsonl'), 'utf8'), /NVD assessment unavailable|Feed collection failed/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('each log stream rotates independently and legacy logs remain readable as system events', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'watchtower-log-rotation-'));
  try {
    await writeFile(path.join(directory, 'system.jsonl'), `${' '.repeat(5_000_001)}\n`);
    await writeFile(path.join(directory, 'logs.jsonl'), `${JSON.stringify({ at: '2020-01-01T00:00:00.000Z', level: 'info', message: 'Legacy event' })}\n`);
    const logger = createLogger(directory);
    await logger.log('info', 'Current event');
    assert.match(await readFile(path.join(directory, 'system.previous.jsonl'), 'utf8'), /^ +/);
    const entries = await logger.recent('system');
    assert.ok(entries.some(entry => entry.message === 'Legacy event'));
    assert.ok(entries.some(entry => entry.message === 'Current event'));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
