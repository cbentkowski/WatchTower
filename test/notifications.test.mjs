import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createNotifier } from '../notifications.mjs';
import { validateSmtpSettings } from '../settings.mjs';

const settings = { enabled: true, host: 'smtp.example.com', port: 587, secure: false, requireTls: true, from: 'alerts@example.com', baseUrl: 'https://watchtower.example.com', timeZone: 'UTC', sendHour: 8, usernameEnv: '', passwordEnv: '' };
const app = (version = '1.0') => ({ id: 'app', name: 'Test App', version, status: 'red', vulnerabilities: [{ id: 'CVE-2026-1234', score: 9 }], lifecycle: { state: 'supported' }, reasons: ['High risk finding'] });
const snapshot = current => ({ workspaces: [{ id: 'team', name: 'Team', notificationEmails: 'team@example.com', applications: ['app'] }], results: [current] });

test('needs-action alert is immediate, weekly thereafter, and stops after acknowledgment', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sent = [];
  let now = new Date('2026-09-20T09:00:00Z');
  const notifier = createNotifier({ dataDirectory: directory, settingsLoader: async () => settings, clock: () => now, transport: { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } } });
  await notifier.onScan(snapshot(app()));
  assert.equal(sent.length, 1);
  assert.match(sent[0].text, /Needs action/);
  now = new Date('2026-09-26T09:00:00Z');
  await notifier.onScan(snapshot(app()));
  assert.equal(sent.length, 1);
  now = new Date('2026-09-27T09:00:00Z');
  await notifier.onScan(snapshot(app()));
  assert.equal(sent.length, 2);
  const token = sent[1].text.match(/\/ack\/([A-Za-z0-9_-]{43})/)?.[1];
  assert.ok(token);
  assert.equal((await notifier.lookup(token)).acknowledgedAt, undefined);
  assert.equal(await notifier.acknowledge(token), true);
  now = new Date('2026-10-05T09:00:00Z');
  await notifier.onScan(snapshot(app()));
  assert.equal(sent.length, 2);
  await notifier.onScan(snapshot(app('1.1')));
  assert.equal(sent.length, 3);
});

test('EOL alert fires once within 30 days and weekly after expiration', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sent = [];
  let now = new Date('2026-09-20T09:00:00Z');
  const notifier = createNotifier({ dataDirectory: directory, settingsLoader: async () => settings, clock: () => now, transport: { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } } });
  const eolApp = days => ({ ...app(), status: days < 0 ? 'red' : 'yellow', vulnerabilities: [], lifecycle: { state: days < 0 ? 'expired' : 'approaching', daysRemaining: days, note: 'End of life 2026-10-20' } });
  await notifier.onScan(snapshot(eolApp(30)));
  assert.equal(sent.length, 1);
  assert.match(sent[0].text, /End of life in 30 days/);
  now = new Date('2026-10-01T09:00:00Z');
  await notifier.onScan(snapshot(eolApp(19)));
  assert.equal(sent.length, 1);
  now = new Date('2026-10-21T09:00:00Z');
  await notifier.onScan(snapshot(eolApp(-1)));
  assert.equal(sent.length, 2);
  assert.match(sent[1].text, /Past end of life/);
  now = new Date('2026-10-27T09:00:00Z');
  await notifier.onScan(snapshot(eolApp(-7)));
  assert.equal(sent.length, 2);
  now = new Date('2026-10-28T09:00:00Z');
  await notifier.onScan(snapshot(eolApp(-8)));
  assert.equal(sent.length, 3);
});

test('identifier renames preserve notification tokens and acknowledgements', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-rename-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sent = [];
  const notifier = createNotifier({ dataDirectory: directory, settingsLoader: async () => settings, clock: () => new Date('2026-09-20T09:00:00Z'), transport: { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } } });
  await notifier.onScan(snapshot(app()));
  const token = sent[0].text.match(/\/ack\/([A-Za-z0-9_-]{43})/)?.[1];
  assert.equal(await notifier.acknowledge(token), true);
  await notifier.renameIdentifiers({ appFrom: 'app', appTo: 'renamed-app', workspaceFrom: 'team', workspaceTo: 'renamed-team' });
  assert.ok((await notifier.lookup(token)).acknowledgedAt);
  const renamedApp = { ...app(), id: 'renamed-app' };
  await notifier.onScan({ workspaces: [{ id: 'renamed-team', name: 'Team', notificationEmails: 'team@example.com', applications: ['renamed-app'] }], results: [renamedApp] });
  assert.equal(sent.length, 1);
});

test('unauthenticated relay sends without credential variables', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-relay-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const relaySettings = validateSmtpSettings({ ...settings, unauthenticated: true, usernameEnv: 'MISSING_SMTP_USER', passwordEnv: 'MISSING_SMTP_PASSWORD' });
  let transportOptions;
  const sent = [];
  const notifier = createNotifier({ dataDirectory: directory, settingsLoader: async () => ({ ...relaySettings, baseUrl: settings.baseUrl }), env: {}, clock: () => new Date('2026-09-20T09:00:00Z'), transportFactory: options => { transportOptions = options; return { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } }; } });
  await notifier.onScan(snapshot(app()));
  assert.equal(transportOptions.auth, undefined);
  assert.equal(sent.length, 1);
});

test('disabled email permits blank delivery settings; enabling checks required fields', () => {
  const blank = validateSmtpSettings({ enabled: false, host: '', port: '', from: '', timeZone: '', sendHour: '', usernameEnv: '', passwordEnv: '', secure: false, requireTls: false });
  assert.equal(blank.port, '');
  assert.throws(() => validateSmtpSettings({ ...blank, enabled: true }), /SMTP host, port, and From address/);
  assert.throws(() => validateSmtpSettings({ ...settings, enabled: true, secure: false, requireTls: false, usernameEnv: 'USER', passwordEnv: 'PASS' }), /SSL\/TLS or STARTTLS/);
  assert.throws(() => validateSmtpSettings({ ...settings, enabled: true, usernameEnv: '', passwordEnv: '' }), /Username and password/);
});
