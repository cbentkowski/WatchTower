import { createTransport } from 'nodemailer';
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

const escape = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
const daysSince = (previous, today) => previous ? Math.round((Date.parse(`${today}T00:00:00Z`) - Date.parse(`${previous}T00:00:00Z`)) / 86_400_000) : Infinity;
const entryKey = (workspaceId, app) => JSON.stringify([workspaceId, app.id, app.version]);

export async function sendTestEmail(settings, recipient, { env = process.env, transportFactory = createTransport } = {}) {
  const to = String(recipient || '').trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) throw new Error('Enter a valid test recipient email address');
  const username = settings.usernameEnv ? env[settings.usernameEnv] : '';
  const password = settings.passwordEnv ? env[settings.passwordEnv] : '';
  if (!settings.unauthenticated && (!username || !password)) throw new Error('The configured SMTP credential environment variables are not both present');
  const mailer = transportFactory({ host: settings.host, port: settings.port, secure: settings.secure, requireTLS: settings.requireTls, auth: settings.unauthenticated ? undefined : { user: username, pass: password }, connectionTimeout: 15_000, greetingTimeout: 15_000, socketTimeout: 30_000 });
  const response = await mailer.sendMail({
    from: settings.from, to, subject: '[WatchTower] Test email',
    text: 'WatchTower successfully connected to your SMTP server and sent this test message. These settings have not been saved.',
    html: '<main style="font-family:Arial,sans-serif;max-width:620px;margin:auto;color:#203646"><h1>WatchTower test email</h1><p>WatchTower successfully connected to your SMTP server and sent this test message.</p><p><strong>These settings have not been saved.</strong></p></main>',
  });
  if (response?.rejected?.length) throw new Error(`Recipient rejected: ${response.rejected.join(', ')}`);
  return { accepted: response?.accepted?.map(String) || [to], messageId: String(response?.messageId || '') };
}

function localTime(date, timeZone) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', hourCycle: 'h23' }).formatToParts(date).map(part => [part.type, part.value]));
  return { day: `${parts.year}-${parts.month}-${parts.day}`, hour: Number(parts.hour) };
}

function classify(app) {
  const vulnerable = app.status === 'red' && (app.vulnerabilities || []).some(item => Number(item.score) >= 7 || item.knownExploited);
  const days = Number(app.lifecycle?.daysRemaining);
  const approaching = app.lifecycle?.state === 'approaching' && Number.isFinite(days) && days >= 0 && days <= 30;
  const expired = app.lifecycle?.state === 'expired';
  return { vulnerable, approaching, expired, days };
}

function dueReasons(entry, flags, today) {
  const reasons = [];
  if (flags.vulnerable && daysSince(entry.redLastSentOn, today) >= 7) reasons.push(entry.redLastSentOn ? 'Needs action reminder' : 'Needs action');
  if (flags.approaching && !entry.eol30SentOn) reasons.push(flags.days === 0 ? 'End of life today' : `End of life in ${flags.days} days`);
  if (flags.expired && daysSince(entry.expiredLastSentOn, today) >= 7) reasons.push(entry.expiredLastSentOn ? 'Past end of life reminder' : 'Past end of life');
  return reasons;
}

function messageFor(group, alerts, baseUrl) {
  const subject = `[WatchTower] ${group.name}: ${alerts.length} application alert${alerts.length === 1 ? '' : 's'}`;
  const lines = [`WatchTower alerts for ${group.name}`, ''];
  const cards = alerts.map(({ app, reasons, token }) => {
    const acknowledgementUrl = new URL(`/ack/${token}`, baseUrl).href;
    const workspaceUrl = new URL(`/#workspace=${encodeURIComponent(group.id)}`, baseUrl).href;
    const note = (app.reasons || []).filter(Boolean).slice(0, 2).join('; ');
    lines.push(`${app.name} (${app.version})`, reasons.join(' · '), note, `Workspace: ${workspaceUrl}`, `Acknowledge: ${acknowledgementUrl}`, '');
    return `<section style="padding:16px;margin:14px 0;border:1px solid #dce6eb;border-radius:8px"><h2 style="margin:0 0 8px;font-size:18px">${escape(app.name)} <small style="color:#647987">${escape(app.version)}</small></h2><strong>${escape(reasons.join(' · '))}</strong><p>${escape(note)}</p><a href="${escape(workspaceUrl)}">Open workspace</a> &nbsp;·&nbsp; <a href="${escape(acknowledgementUrl)}">Acknowledge alerts for this application</a></section>`;
  }).join('');
  return { subject, text: lines.join('\n'), html: `<main style="font-family:Arial,sans-serif;max-width:680px;margin:auto;color:#203646"><h1>WatchTower · ${escape(group.name)}</h1><p>${alerts.length} application${alerts.length === 1 ? '' : 's'} need your attention.</p>${cards}<p style="font-size:12px;color:#647987">The acknowledgment link opens a confirmation page. Confirming stops reminders for that application in this workspace until the alert clears or its version changes.</p></main>` };
}

export function createNotifier({ dataDirectory, settingsLoader, env = process.env, clock = () => new Date(), transport = null, transportFactory = createTransport }) {
  const file = path.join(dataDirectory, 'notifications.json');
  let state = null;
  let pending = Promise.resolve();

  async function load() {
    if (state) return state;
    try {
      const parsed = JSON.parse(await readFile(file, 'utf8'));
      state = parsed && typeof parsed === 'object' && parsed.entries && typeof parsed.entries === 'object' ? parsed : { entries: {} };
    } catch (error) {
      if (error.code !== 'ENOENT') console.warn(`Could not load notification state: ${error.message}`);
      state = { entries: {} };
    }
    return state;
  }
  async function save() {
    await mkdir(dataDirectory, { recursive: true });
    const temporary = `${file}.tmp`;
    await writeFile(temporary, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    await rename(temporary, file);
  }
  function serialize(action) {
    const result = pending.then(action);
    pending = result.catch(() => {});
    return result;
  }

  async function evaluate(snapshot) {
    await load();
    const settings = await settingsLoader();
    if (!settings.enabled) return;
    const { day, hour: currentHour } = localTime(clock(), settings.timeZone);
    let baseUrl = null;
    try { if (settings.baseUrl) baseUrl = new URL(settings.baseUrl); } catch {}
    const username = settings.usernameEnv ? env[settings.usernameEnv] : '';
    const password = settings.passwordEnv ? env[settings.passwordEnv] : '';
    const credentialsReady = settings.unauthenticated || ((!settings.usernameEnv || Boolean(username)) && (!settings.passwordEnv || Boolean(password)));
    const mailer = transport || (settings.host && settings.from && credentialsReady ? transportFactory({ host: settings.host, port: settings.port, secure: settings.secure, requireTLS: settings.requireTls, auth: settings.unauthenticated ? undefined : username ? { user: username, pass: password || '' } : undefined, connectionTimeout: 15_000, greetingTimeout: 15_000, socketTimeout: 30_000 }) : null);
    const active = new Set();
    const groups = snapshot.workspaces || [];
    const apps = snapshot.results || [];
    for (const group of groups) {
      const recipients = String(group.notificationEmails || '').split(',').map(value => value.trim()).filter(Boolean);
      if (!recipients.length) continue;
      const alerts = [];
      for (const app of apps.filter(item => group.applications.includes(item.id))) {
        const flags = classify(app);
        if (!flags.vulnerable && !flags.approaching && !flags.expired) continue;
        const key = entryKey(group.id, app);
        active.add(key);
        const entry = state.entries[key] ||= { token: randomBytes(32).toString('base64url') };
        entry.appName = app.name;
        entry.workspaceName = group.name;
        entry.version = app.version;
        if (!flags.vulnerable) entry.redLastSentOn = null;
        if (!flags.approaching && !flags.expired) entry.eol30SentOn = null;
        if (!flags.expired) entry.expiredLastSentOn = null;
        if (entry.acknowledgedAt || currentHour < settings.sendHour) continue;
        const reasons = dueReasons(entry, flags, day);
        if (reasons.length) alerts.push({ app, entry, flags, reasons, token: entry.token });
      }
      if (!alerts.length || !mailer || !baseUrl) continue;
      await save(); // Persist acknowledgment tokens before sending their links.
      const message = messageFor(group, alerts, baseUrl);
      try {
        const response = await mailer.sendMail({ from: settings.from || 'WatchTower <watchtower@localhost>', to: recipients.join(', '), ...message });
        if (response?.rejected?.length) throw new Error(`Recipients rejected: ${response.rejected.join(', ')}`);
        for (const { entry, flags, reasons } of alerts) {
          if (flags.vulnerable && reasons.some(reason => reason.startsWith('Needs action'))) entry.redLastSentOn = day;
          if (flags.approaching && reasons.some(reason => reason.startsWith('End of life'))) entry.eol30SentOn = day;
          if (flags.expired && reasons.some(reason => reason.startsWith('Past end of life'))) entry.expiredLastSentOn = day;
        }
        await save();
        console.log(`Sent ${alerts.length} notification(s) for workspace ${group.id}`);
      } catch (error) { console.error(`Could not email workspace ${group.id}: ${error.message}`); }
    }
    let changed = false;
    for (const key of Object.keys(state.entries)) if (!active.has(key)) { delete state.entries[key]; changed = true; }
    if (changed) await save();
  }

  return {
    onScan: snapshot => serialize(() => evaluate(snapshot)),
    lookup: token => serialize(async () => { await load(); const found = Object.entries(state.entries).find(([, entry]) => entry.token === token); return found ? { key: found[0], ...found[1] } : null; }),
    acknowledge: token => serialize(async () => { await load(); const found = Object.entries(state.entries).find(([, entry]) => entry.token === token); if (!found) return false; found[1].acknowledgedAt ||= clock().toISOString(); await save(); return true; }),
    renameIdentifiers: changes => serialize(async () => {
      await load();
      let changed = false;
      const entries = {};
      for (const [key, entry] of Object.entries(state.entries)) {
        let nextKey = key;
        try {
          const [workspaceId, appId, version] = JSON.parse(key);
          const nextWorkspaceId = changes.workspaceFrom === workspaceId ? changes.workspaceTo : workspaceId;
          const nextAppId = changes.appFrom === appId ? changes.appTo : appId;
          nextKey = JSON.stringify([nextWorkspaceId, nextAppId, version]);
        } catch {}
        if (nextKey !== key) changed = true;
        if (entries[nextKey]) throw new Error('Notification state collision while renaming an identifier');
        entries[nextKey] = entry;
      }
      if (changed) { state.entries = entries; await save(); }
    }),
  };
}
