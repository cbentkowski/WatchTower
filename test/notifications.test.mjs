import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createNotifier, sendTestEmail } from '../src/notifications.mjs';
import { smtpPasswordState, validateSmtpSettings } from '../src/settings.mjs';

const settings = { enabled: true, host: 'smtp.example.com', port: 587, secure: false, requireTls: true, unauthenticated: true, from: 'alerts@example.com', baseUrl: 'https://watchtower.example.com', timeZone: 'UTC', sendHour: 9, usernameEnv: '' };
const app = (version = '1.0') => ({ id: 'app', name: 'Test App', version, status: 'red', vulnerabilities: [{ id: 'CVE-2026-1234', score: 9 }], lifecycle: { state: 'supported' }, reasons: ['High risk finding'] });
const snapshot = current => ({ owners: [{ id: 'owner', name: 'Team owner', email: 'team@example.com' }], workspaces: [{ id: 'team', name: 'Team', ownerIds: ['owner'], applications: ['app'] }], results: [current] });

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

test('alert messages include linked and plain external finding tickets', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-ticket-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sent = [];
  const ticketed = { ...app(), vulnerabilities: [{ id: 'CVE-2026-1234', score: 9, workflow: { ticketReference: 'https://tickets.example.com/SEC-123' } }, { id: 'CVE-2026-9999', score: 8, workflow: { ticketReference: 'Remedy INC0001234' } }] };
  const notifier = createNotifier({ dataDirectory: directory, settingsLoader: async () => settings, clock: () => new Date('2026-09-20T09:00:00Z'), transport: { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } } });
  await notifier.onScan(snapshot(ticketed));
  assert.match(sent[0].text, /Ticket \(CVE-2026-1234\): https:\/\/tickets\.example\.com\/SEC-123/);
  assert.match(sent[0].html, /href="https:\/\/tickets\.example\.com\/SEC-123"/);
  assert.match(sent[0].text, /Ticket \(CVE-2026-9999\): Remedy INC0001234/);
  assert.match(sent[0].html, /CVE-2026-9999 ticket: <strong>Remedy INC0001234<\/strong>/);
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

test('ordinary alerts wait for the configured local hour instead of sending on a later scan', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-window-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sent = [];
  let now = new Date('2026-09-20T20:00:00Z');
  const high = { ...app(), vulnerabilities: [{ id: 'CVE-2026-5678', score: 8 }] };
  const notifier = createNotifier({ dataDirectory: directory, settingsLoader: async () => ({ ...settings, sendHour: 8 }), clock: () => now, transport: { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } } });
  await notifier.onScan(snapshot(high));
  assert.equal(sent.length, 0);
  now = new Date('2026-09-21T08:00:00Z');
  await notifier.onScan(snapshot(high));
  assert.equal(sent.length, 1);
});

test('new Critical and known-exploited alerts send immediately but reminders use the scheduled window', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-urgent-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sent = [];
  let now = new Date('2026-09-20T20:00:00Z');
  const notifier = createNotifier({ dataDirectory: directory, settingsLoader: async () => ({ ...settings, sendHour: 8 }), clock: () => now, transport: { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } } });
  await notifier.onScan(snapshot(app()));
  await notifier.onScan(snapshot(app()));
  assert.equal(sent.length, 1);
  now = new Date('2026-09-27T20:00:00Z');
  await notifier.onScan(snapshot(app()));
  assert.equal(sent.length, 1);
  now = new Date('2026-09-28T08:00:00Z');
  await notifier.onScan(snapshot(app()));
  assert.equal(sent.length, 2);

  const kevDirectory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-kev-'));
  t.after(() => rm(kevDirectory, { recursive: true, force: true }));
  const kevSent = [];
  const kev = { ...app(), vulnerabilities: [{ id: 'CVE-2026-9999', score: 5, knownExploited: true }] };
  const kevNotifier = createNotifier({ dataDirectory: kevDirectory, settingsLoader: async () => ({ ...settings, sendHour: 8 }), clock: () => new Date('2026-09-20T20:00:00Z'), transport: { sendMail: async message => { kevSent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } } });
  await kevNotifier.onScan(snapshot(kev));
  assert.equal(kevSent.length, 1);
});

test('notification policies determine which vulnerable findings enter the existing delivery flow', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-policy-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sent = [];
  let policies = [{ id: 'production', name: 'Production only', conditions: { environments: ['production'] } }];
  const notifier = createNotifier({
    dataDirectory: directory,
    settingsLoader: async () => settings,
    policyLoader: async () => policies,
    clock: () => new Date('2026-09-20T09:00:00Z'),
    transport: { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } },
  });

  await notifier.onScan(snapshot({ ...app(), environment: 'development' }));
  assert.equal(sent.length, 0);
  policies = [{ id: 'development', name: 'Development', conditions: { environments: ['development'] } }];
  await notifier.onScan(snapshot({ ...app(), environment: 'development' }));
  assert.equal(sent.length, 1);
});

test('a new Critical finding sends immediately after an earlier High notification', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-escalation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sent = [];
  let now = new Date('2026-09-20T08:00:00Z');
  const high = { ...app(), vulnerabilities: [{ id: 'CVE-2026-7000', score: 8 }] };
  const critical = { ...app(), vulnerabilities: [...high.vulnerabilities, { id: 'CVE-2026-7001', score: 9.8 }] };
  const notifier = createNotifier({ dataDirectory: directory, settingsLoader: async () => ({ ...settings, sendHour: 8 }), clock: () => now, transport: { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } } });
  await notifier.onScan(snapshot(high));
  assert.equal(sent.length, 1);
  now = new Date('2026-09-20T20:00:00Z');
  await notifier.onScan(snapshot(critical));
  await notifier.onScan(snapshot(critical));
  assert.equal(sent.length, 2);
  assert.match(sent[1].text, /New Critical or known-exploited finding/);
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
  await notifier.onScan({ owners: [{ id: 'owner', name: 'Team owner', email: 'team@example.com' }], workspaces: [{ id: 'renamed-team', name: 'Team', ownerIds: ['owner'], applications: ['renamed-app'] }], results: [renamedApp] });
  assert.equal(sent.length, 1);
});

test('unauthenticated relay sends without credential variables', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-relay-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const relaySettings = validateSmtpSettings({ ...settings, unauthenticated: true, usernameEnv: 'MISSING_SMTP_USER' });
  let transportOptions;
  const sent = [];
  const notifier = createNotifier({ dataDirectory: directory, settingsLoader: async () => ({ ...relaySettings, baseUrl: settings.baseUrl }), env: {}, clock: () => new Date('2026-09-20T09:00:00Z'), transportFactory: options => { transportOptions = options; return { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } }; } });
  await notifier.onScan(snapshot(app()));
  assert.equal(transportOptions.auth, undefined);
  assert.equal(sent.length, 1);
});

test('disabled email permits blank delivery settings; enabling checks required fields', () => {
  const blank = validateSmtpSettings({ enabled: false, host: '', port: '', from: '', timeZone: '', sendHour: '', usernameEnv: '', secure: false, requireTls: false, unauthenticated: false });
  assert.equal(blank.port, '');
  assert.throws(() => validateSmtpSettings({ ...blank, enabled: true }), /SMTP host, port, and From address/);
  assert.throws(() => validateSmtpSettings({ ...settings, enabled: true, secure: false, requireTls: false, unauthenticated: false, usernameEnv: 'USER' }), /SSL\/TLS or STARTTLS/);
  assert.throws(() => validateSmtpSettings({ ...settings, enabled: true, unauthenticated: false, usernameEnv: '' }), /username environment variable/);
});

test('SMTP password secret state requires a readable nonempty mounted file', async () => {
  assert.deepEqual(await smtpPasswordState({}), { configured: false, present: false });
  assert.deepEqual(await smtpPasswordState({ SMTP_PASSWORD_FILE: '/run/watchtower-secrets/smtp-password' }, async () => 'secret\n'), { configured: true, present: true });
  assert.deepEqual(await smtpPasswordState({ SMTP_PASSWORD_FILE: '/run/watchtower-secrets/smtp-password' }, async () => '  '), { configured: true, present: false });
  assert.deepEqual(await smtpPasswordState({ SMTP_PASSWORD_FILE: '/missing' }, async () => { throw new Error('missing'); }), { configured: true, present: false });
});

test('test email uses an environment username and rereads the mounted password secret', async () => {
  let options;
  let message;
  let password = 'first-secret';
  const smtp = validateSmtpSettings({ ...settings, unauthenticated: false, usernameEnv: 'SMTP_USER' });
  const result = await sendTestEmail(smtp, 'operator@example.com', {
    env: { SMTP_USER: 'service-account', SMTP_PASSWORD_FILE: '/run/watchtower-secrets/smtp-password' },
    secretLoader: async file => { assert.equal(file, '/run/watchtower-secrets/smtp-password'); return password; },
    transportFactory: input => { options = input; return { sendMail: async value => { message = value; return { accepted: ['operator@example.com'], rejected: [], messageId: 'test-id' }; } }; },
  });
  assert.deepEqual(options.auth, { user: 'service-account', pass: 'first-secret' });
  assert.equal(message.to, 'operator@example.com');
  assert.match(message.subject, /Test email/);
  assert.deepEqual(result.accepted, ['operator@example.com']);
  password = 'rotated-secret';
  await sendTestEmail(smtp, 'operator@example.com', { env: { SMTP_USER: 'service-account', SMTP_PASSWORD_FILE: '/run/watchtower-secrets/smtp-password' }, secretLoader: async () => password, transportFactory: input => { options = input; return { sendMail: async () => ({ accepted: ['operator@example.com'], rejected: [] }) }; } });
  assert.equal(options.auth.pass, 'rotated-secret');
  await assert.rejects(() => sendTestEmail(smtp, 'invalid', { env: {} }), /valid test recipient/);
  await assert.rejects(() => sendTestEmail(smtp, 'operator@example.com', { env: { SMTP_USER: 'service-account' } }), /SMTP_PASSWORD_FILE is required/);
  await assert.rejects(() => sendTestEmail(smtp, 'operator@example.com', { env: { SMTP_USER: 'service-account', SMTP_PASSWORD_FILE: '/missing' }, secretLoader: async () => { const error = new Error('missing'); error.code = 'ENOENT'; throw error; } }), /Could not read SMTP_PASSWORD_FILE: ENOENT/);
});
