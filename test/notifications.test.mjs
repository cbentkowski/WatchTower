import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
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

test('policy cadence and delivery windows control daily and weekly digests', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-cadence-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sent = [];
  let now = new Date('2026-09-21T08:00:00Z'); // Monday
  let policies = [{ id: 'daily', name: 'Daily', conditions: { severities: ['critical'] }, delivery: { cadence: 'daily', sendHour: 10, windowStartHour: 9, windowEndHour: 17, reminderDays: 7, workspaceRecipients: true, recipientOwnerIds: [] } }];
  const notifier = createNotifier({ dataDirectory: directory, settingsLoader: async () => settings, policyLoader: async () => policies, clock: () => now, transport: { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } } });
  await notifier.onScan(snapshot(app()));
  assert.equal(sent.length, 0);
  now = new Date('2026-09-21T10:00:00Z');
  await notifier.onScan(snapshot(app()));
  assert.equal(sent.length, 1);

  const weeklyDirectory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-weekly-'));
  t.after(() => rm(weeklyDirectory, { recursive: true, force: true }));
  const weeklySent = [];
  policies = [{ id: 'weekly', name: 'Weekly', conditions: { severities: ['critical'] }, delivery: { cadence: 'weekly', sendHour: 10, weeklyDay: 2, windowStartHour: 0, windowEndHour: 23, reminderDays: 7, workspaceRecipients: true, recipientOwnerIds: [] } }];
  const weeklyNotifier = createNotifier({ dataDirectory: weeklyDirectory, settingsLoader: async () => settings, policyLoader: async () => policies, clock: () => now, transport: { sendMail: async message => { weeklySent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } } });
  await weeklyNotifier.onScan(snapshot(app()));
  assert.equal(weeklySent.length, 0);
  now = new Date('2026-09-22T10:00:00Z'); // Tuesday
  await weeklyNotifier.onScan(snapshot(app()));
  assert.equal(weeklySent.length, 1);
});

test('policy routing adds selected owners and later escalation contacts without losing restart deduplication', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-routing-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sent = [];
  let now = new Date('2026-09-20T09:00:00Z');
  const policy = { id: 'route', name: 'Route', conditions: { severities: ['critical'] }, delivery: { cadence: 'immediate', windowStartHour: 0, windowEndHour: 23, reminderDays: 1, workspaceRecipients: true, recipientOwnerIds: ['security'], includeEscalationContacts: true, escalationAfterDays: 2 } };
  const routedSnapshot = { owners: [{ id: 'owner', name: 'Team owner', email: 'team@example.com', escalationEmail: 'team-lead@example.com' }, { id: 'security', name: 'Security', email: 'security@example.com', escalationEmail: 'security-lead@example.com' }], workspaces: [{ id: 'team', name: 'Team', ownerIds: ['owner'], applications: ['app'] }], results: [app()] };
  const makeNotifier = () => createNotifier({ dataDirectory: directory, settingsLoader: async () => settings, policyLoader: async () => [policy], clock: () => now, transport: { sendMail: async message => { sent.push(message); return { accepted: String(message.to).split(', '), rejected: [] }; } } });
  await makeNotifier().onScan(routedSnapshot);
  assert.equal(sent.length, 1);
  assert.match(sent[0].to, /team@example.com/);
  assert.match(sent[0].to, /security@example.com/);
  await makeNotifier().onScan(routedSnapshot);
  assert.equal(sent.length, 1);
  now = new Date('2026-09-22T09:00:00Z');
  await makeNotifier().onScan(routedSnapshot);
  assert.equal(sent.length, 2);
  assert.match(sent[1].to, /team-lead@example.com/);
  assert.match(sent[1].to, /security-lead@example.com/);
});

test('legacy notification state migrates without resending an already delivered match', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-state-migration-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, 'notifications.json'), JSON.stringify({ entries: { [JSON.stringify(['team', 'app', '1.0'])]: { token: 'legacy-token', redLastSentOn: '2026-09-20', urgentFingerprint: 'CVE-2026-1234:9:false' } } }));
  const sent = [];
  const notifier = createNotifier({ dataDirectory: directory, settingsLoader: async () => settings, clock: () => new Date('2026-09-20T09:00:00Z'), transport: { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } } });
  await notifier.onScan(snapshot(app()));
  assert.equal(sent.length, 0);
});

test('unmatched findings do not affect urgency or appear in policy-routed messages', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-notify-policy-scope-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sent = [];
  let now = new Date('2026-09-20T08:00:00Z');
  const high = { id: 'CVE-2026-8000', score: 8, workflow: { ticketReference: 'HIGH-1' } };
  const critical = { id: 'CVE-2026-9000', score: 9.8, workflow: { ticketReference: 'CRITICAL-1' } };
  const notifier = createNotifier({
    dataDirectory: directory,
    settingsLoader: async () => ({ ...settings, sendHour: 8 }),
    policyLoader: async () => [{ id: 'high-only', name: 'High only', conditions: { severities: ['high'] } }],
    clock: () => now,
    transport: { sendMail: async message => { sent.push(message); return { accepted: ['team@example.com'], rejected: [] }; } },
  });

  await notifier.onScan(snapshot({ ...app(), vulnerabilities: [high, critical] }));
  assert.equal(sent.length, 1);
  assert.match(sent[0].text, /HIGH-1/);
  assert.doesNotMatch(sent[0].text, /CRITICAL-1/);

  now = new Date('2026-09-20T20:00:00Z');
  await notifier.onScan(snapshot({ ...app(), vulnerabilities: [high, critical, { id: 'CVE-2026-9001', score: 10 }] }));
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
