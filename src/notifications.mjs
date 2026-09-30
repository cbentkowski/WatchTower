import { createTransport } from 'nodemailer';
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

const escape = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
const safeTicketUrl = value => { try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.href : ''; } catch { return ''; } };
const daysSince = (previous, today) => previous ? Math.round((Date.parse(`${today}T00:00:00Z`) - Date.parse(`${previous}T00:00:00Z`)) / 86_400_000) : Infinity;
const entryKey = (workspaceId, app) => JSON.stringify([workspaceId, app.id, app.version]);

async function smtpAuthentication(settings, env, secretLoader) {
  if (settings.unauthenticated) return undefined;
  const username = settings.usernameEnv ? env[settings.usernameEnv] : '';
  const secretFile = String(env.SMTP_PASSWORD_FILE || '').trim();
  if (!username) throw new Error('The configured SMTP username environment variable is not present');
  if (!secretFile) throw new Error('SMTP_PASSWORD_FILE is required for authenticated SMTP');
  let password;
  try { password = String(await secretLoader(secretFile, 'utf8')).trim(); }
  catch (error) { throw new Error(`Could not read SMTP_PASSWORD_FILE: ${error.code || error.message}`); }
  if (!password) throw new Error('SMTP_PASSWORD_FILE is empty');
  return { user: username, pass: password };
}

export async function sendTestEmail(settings, recipient, { env = process.env, transportFactory = createTransport, secretLoader = readFile } = {}) {
  const to = String(recipient || '').trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) throw new Error('Enter a valid test recipient email address');
  const auth = await smtpAuthentication(settings, env, secretLoader);
  const mailer = transportFactory({ host: settings.host, port: settings.port, secure: settings.secure, requireTLS: settings.requireTls, auth, connectionTimeout: 15_000, greetingTimeout: 15_000, socketTimeout: 30_000 });
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
  const findings = app.vulnerabilities || [];
  const vulnerable = app.status === 'red' && findings.some(item => Number(item.score) >= 7 || item.knownExploited);
  const urgentFindings = app.status === 'red' ? findings.filter(item => Number(item.score) >= 9 || item.knownExploited) : [];
  const urgentFingerprint = urgentFindings.map(item => `${item.id || 'unknown'}:${Number(item.score) || 0}:${Boolean(item.knownExploited)}`).sort().join('|');
  const days = Number(app.lifecycle?.daysRemaining);
  const approaching = app.lifecycle?.state === 'approaching' && Number.isFinite(days) && days >= 0 && days <= 30;
  const expired = app.lifecycle?.state === 'expired';
  return { vulnerable, urgent: Boolean(urgentFingerprint), urgentFingerprint, approaching, expired, days };
}

function dueReasons(entry, flags, today, urgentChanged) {
  const reasons = [];
  if (urgentChanged) reasons.push(entry.redLastSentOn ? 'New Critical or known-exploited finding' : 'Needs action');
  else if (flags.vulnerable && daysSince(entry.redLastSentOn, today) >= 7) reasons.push(entry.redLastSentOn ? 'Needs action reminder' : 'Needs action');
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
    const tickets = (app.vulnerabilities || []).map(finding => ({ id: finding.id || 'Finding', url: safeTicketUrl(finding.workflow?.ticketUrl) })).filter(ticket => ticket.url);
    lines.push(`${app.name} (${app.version})`, reasons.join(' · '), note, ...tickets.map(ticket => `Ticket (${ticket.id}): ${ticket.url}`), `Workspace: ${workspaceUrl}`, `Acknowledge: ${acknowledgementUrl}`, '');
    const ticketLinks = tickets.length ? `<p>${tickets.map(ticket => `<a href="${escape(ticket.url)}">${escape(ticket.id)} ticket</a>`).join(' &nbsp;·&nbsp; ')}</p>` : '';
    return `<section style="padding:16px;margin:14px 0;border:1px solid #dce6eb;border-radius:8px"><h2 style="margin:0 0 8px;font-size:18px">${escape(app.name)} <small style="color:#647987">${escape(app.version)}</small></h2><strong>${escape(reasons.join(' · '))}</strong><p>${escape(note)}</p>${ticketLinks}<a href="${escape(workspaceUrl)}">Open workspace</a> &nbsp;·&nbsp; <a href="${escape(acknowledgementUrl)}">Acknowledge alerts for this application</a></section>`;
  }).join('');
  return { subject, text: lines.join('\n'), html: `<main style="font-family:Arial,sans-serif;max-width:680px;margin:auto;color:#203646"><h1>WatchTower · ${escape(group.name)}</h1><p>${alerts.length} application${alerts.length === 1 ? '' : 's'} need your attention.</p>${cards}<p style="font-size:12px;color:#647987">The acknowledgment link opens a confirmation page. Confirming stops reminders for that application in this workspace until the alert clears or its version changes.</p></main>` };
}

export function createNotifier({ dataDirectory, settingsLoader, env = process.env, clock = () => new Date(), transport = null, transportFactory = createTransport, secretLoader = readFile }) {
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
    let auth;
    try { auth = await smtpAuthentication(settings, env, secretLoader); }
    catch (error) { console.error(`SMTP credentials unavailable: ${error.message}`); return; }
    const mailer = transport || (settings.host && settings.from ? transportFactory({ host: settings.host, port: settings.port, secure: settings.secure, requireTLS: settings.requireTls, auth, connectionTimeout: 15_000, greetingTimeout: 15_000, socketTimeout: 30_000 }) : null);
    const active = new Set();
    let changed = false;
    const groups = snapshot.workspaces || [];
    const apps = snapshot.results || [];
    const ownerById = new Map((snapshot.owners || []).map(owner => [owner.id, owner]));
    for (const group of groups) {
      const recipients = [...new Set((group.ownerIds || []).map(id => ownerById.get(id)?.email).filter(Boolean))];
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
        if (!flags.urgent && entry.urgentFingerprint) { delete entry.urgentFingerprint; changed = true; }
        if (!flags.approaching && !flags.expired) entry.eol30SentOn = null;
        if (!flags.expired) entry.expiredLastSentOn = null;
        const urgentChanged = flags.urgent && entry.urgentFingerprint !== flags.urgentFingerprint;
        if (entry.acknowledgedAt || (!urgentChanged && currentHour !== settings.sendHour)) continue;
        const reasons = dueReasons(entry, flags, day, urgentChanged);
        if (reasons.length) alerts.push({ app, entry, flags, urgentChanged, reasons, token: entry.token });
      }
      if (!alerts.length || !mailer || !baseUrl) continue;
      await save(); // Persist acknowledgment tokens before sending their links.
      const message = messageFor(group, alerts, baseUrl);
      try {
        const response = await mailer.sendMail({ from: settings.from || 'WatchTower <watchtower@localhost>', to: recipients.join(', '), ...message });
        if (response?.rejected?.length) throw new Error(`Recipients rejected: ${response.rejected.join(', ')}`);
        for (const { entry, flags, urgentChanged, reasons } of alerts) {
          if (flags.vulnerable && (urgentChanged || reasons.some(reason => reason.startsWith('Needs action')))) entry.redLastSentOn = day;
          if (urgentChanged) entry.urgentFingerprint = flags.urgentFingerprint;
          if (flags.approaching && reasons.some(reason => reason.startsWith('End of life'))) entry.eol30SentOn = day;
          if (flags.expired && reasons.some(reason => reason.startsWith('Past end of life'))) entry.expiredLastSentOn = day;
        }
        await save();
        console.log(`Sent ${alerts.length} notification(s) for workspace ${group.id}`);
      } catch (error) { console.error(`Could not email workspace ${group.id}: ${error.message}`); }
    }
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
