import { createTransport } from 'nodemailer';
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { defaultNotificationPolicies, matchingPolicies } from './notification-policies.mjs';

const escape = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
const safeTicketUrl = value => { try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.href : ''; } catch { return ''; } };
const daysSince = (previous, today) => previous ? Math.round((Date.parse(`${today}T00:00:00Z`) - Date.parse(`${previous}T00:00:00Z`)) / 86_400_000) : Infinity;
const entryKey = (workspaceId, app, policyId = 'lifecycle') => JSON.stringify([workspaceId, app.id, app.version, policyId]);

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
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', hourCycle: 'h23', weekday: 'short' }).formatToParts(date).map(part => [part.type, part.value]));
  return { day: `${parts.year}-${parts.month}-${parts.day}`, hour: Number(parts.hour), weekday: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(parts.weekday) };
}

function classify(app, workspace, policies, now) {
  const findings = app.vulnerabilities || [];
  const matchedFindings = [];
  const policyMatches = findings.flatMap(finding => {
    const matches = matchingPolicies(policies, { finding, application: app, workspace }, now);
    if (matches.length) matchedFindings.push(finding);
    return matches.map(policy => ({ findingId: finding.id, ...policy }));
  });
  const vulnerable = app.status === 'red' && policyMatches.length > 0;
  const urgentFindings = vulnerable ? matchedFindings.filter(item => Number(item.score) >= 9 || String(item.severity || item.label).toUpperCase() === 'CRITICAL' || item.knownExploited) : [];
  const urgentFingerprint = urgentFindings.map(item => `${item.id || 'unknown'}:${Number(item.score) || 0}:${Boolean(item.knownExploited)}`).sort().join('|');
  const days = Number(app.lifecycle?.daysRemaining);
  const approaching = app.lifecycle?.state === 'approaching' && Number.isFinite(days) && days >= 0 && days <= 30;
  const expired = app.lifecycle?.state === 'expired';
  return { vulnerable, matchedFindings, policyMatches, urgent: Boolean(urgentFingerprint), urgentFingerprint, approaching, expired, days };
}

function dueReasons(entry, flags, today, urgentChanged, reminderDays = 7) {
  const reasons = [];
  if (urgentChanged) reasons.push(entry.redLastSentOn ? 'New Critical or known-exploited finding' : 'Needs action');
  else if (flags.vulnerable && daysSince(entry.redLastSentOn, today) >= reminderDays) reasons.push(entry.redLastSentOn ? 'Needs action reminder' : 'Needs action');
  if (flags.approaching && !entry.eol30SentOn) reasons.push(flags.days === 0 ? 'End of life today' : `End of life in ${flags.days} days`);
  if (flags.expired && daysSince(entry.expiredLastSentOn, today) >= 7) reasons.push(entry.expiredLastSentOn ? 'Past end of life reminder' : 'Past end of life');
  return reasons;
}

const hourInWindow = (hour, start, end) => start <= end ? hour >= start && hour <= end : hour >= start || hour <= end;
function deliveryDue(delivery, local, urgentChanged, fallbackHour) {
  const start = delivery.windowStartHour ?? 0;
  const end = delivery.windowEndHour ?? 23;
  if (!hourInWindow(local.hour, start, end)) return false;
  const sendHour = delivery.sendHour ?? fallbackHour;
  if (delivery.cadence === 'immediate') return true;
  if (delivery.cadence === 'weekly') return local.weekday === delivery.weeklyDay && local.hour === sendHour;
  if (delivery.cadence === 'daily') return local.hour === sendHour;
  return urgentChanged || local.hour === sendHour;
}

function messageFor(group, alerts, baseUrl) {
  const subject = `[WatchTower] ${group.name}: ${alerts.length} application alert${alerts.length === 1 ? '' : 's'}`;
  const lines = [`WatchTower alerts for ${group.name}`, ''];
  const cards = alerts.map(({ app, flags, reasons, token }) => {
    const acknowledgementUrl = new URL(`/ack/${token}`, baseUrl).href;
    const workspaceUrl = new URL(`/#workspace=${encodeURIComponent(group.id)}`, baseUrl).href;
    const note = (app.reasons || []).filter(Boolean).slice(0, 2).join('; ');
    const messageFindings = flags.vulnerable ? flags.matchedFindings : (app.vulnerabilities || []);
    const tickets = messageFindings.map(finding => { const reference = String(finding.workflow?.ticketReference || finding.workflow?.ticketUrl || '').trim(); return { id: finding.id || 'Finding', reference, url: safeTicketUrl(reference) }; }).filter(ticket => ticket.reference);
    lines.push(`${app.name} (${app.version})`, reasons.join(' · '), note, ...tickets.map(ticket => `Ticket (${ticket.id}): ${ticket.reference}`), `Workspace: ${workspaceUrl}`, `Acknowledge: ${acknowledgementUrl}`, '');
    const ticketLinks = tickets.length ? `<p>${tickets.map(ticket => ticket.url ? `<a href="${escape(ticket.url)}">${escape(ticket.id)} ticket</a>` : `${escape(ticket.id)} ticket: <strong>${escape(ticket.reference)}</strong>`).join(' &nbsp;·&nbsp; ')}</p>` : '';
    return `<section style="padding:16px;margin:14px 0;border:1px solid #dce6eb;border-radius:8px"><h2 style="margin:0 0 8px;font-size:18px">${escape(app.name)} <small style="color:#647987">${escape(app.version)}</small></h2><strong>${escape(reasons.join(' · '))}</strong><p>${escape(note)}</p>${ticketLinks}<a href="${escape(workspaceUrl)}">Open workspace</a> &nbsp;·&nbsp; <a href="${escape(acknowledgementUrl)}">Acknowledge alerts for this application</a></section>`;
  }).join('');
  return { subject, text: lines.join('\n'), html: `<main style="font-family:Arial,sans-serif;max-width:680px;margin:auto;color:#203646"><h1>WatchTower · ${escape(group.name)}</h1><p>${alerts.length} application${alerts.length === 1 ? '' : 's'} need your attention.</p>${cards}<p style="font-size:12px;color:#647987">The acknowledgment link opens a confirmation page. Confirming stops reminders for that application in this workspace until the alert clears or its version changes.</p></main>` };
}

export function createNotifier({ dataDirectory, settingsLoader, policyLoader = async () => defaultNotificationPolicies, deliveryLogger = null, env = process.env, clock = () => new Date(), transport = null, transportFactory = createTransport, secretLoader = readFile }) {
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
    const now = clock();
    const local = localTime(now, settings.timeZone);
    const { day } = local;
    const policies = await policyLoader();
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
      const routes = policies.filter(policy => policy.enabled !== false).map(policy => ({ policy, delivery: policy.delivery || { cadence: 'adaptive', sendHour: null, weeklyDay: 1, windowStartHour: 0, windowEndHour: 23, reminderDays: 7, workspaceRecipients: true, recipientOwnerIds: [], includeEscalationContacts: false, escalationAfterDays: null } }));
      routes.push({ policy: null, delivery: { cadence: 'daily', sendHour: null, weeklyDay: 1, windowStartHour: 0, windowEndHour: 23, reminderDays: 7, workspaceRecipients: true, recipientOwnerIds: [], includeEscalationContacts: false, escalationAfterDays: null } });
      for (const { policy, delivery } of routes) {
        const ownerIds = [...new Set([...(delivery.workspaceRecipients ? group.ownerIds || [] : []), ...(delivery.recipientOwnerIds || [])])];
        const routeOwners = ownerIds.map(id => ownerById.get(id)).filter(Boolean);
        const alerts = [];
        for (const app of apps.filter(item => group.applications.includes(item.id))) {
          let flags = classify(app, group, policy ? [policy] : [], now);
          flags = policy ? { ...flags, approaching: false, expired: false } : { ...flags, vulnerable: false, urgent: false, urgentFingerprint: '', matchedFindings: [], policyMatches: [] };
          if (!flags.vulnerable && !flags.approaching && !flags.expired) continue;
          const key = entryKey(group.id, app, policy?.id);
          const legacyKey = JSON.stringify([group.id, app.id, app.version]);
          active.add(key);
          const entry = state.entries[key] ||= structuredClone(state.entries[legacyKey] || { token: randomBytes(32).toString('base64url') });
          entry.firstMatchedOn ||= day;
          entry.appName = app.name;
          entry.workspaceName = group.name;
          entry.version = app.version;
          if (!flags.vulnerable) entry.redLastSentOn = null;
          if (!flags.urgent && entry.urgentFingerprint) { delete entry.urgentFingerprint; changed = true; }
          if (!flags.approaching && !flags.expired) entry.eol30SentOn = null;
          if (!flags.expired) entry.expiredLastSentOn = null;
          const urgentChanged = flags.urgent && entry.urgentFingerprint !== flags.urgentFingerprint;
          if (entry.acknowledgedAt || !deliveryDue(delivery, local, urgentChanged, settings.sendHour)) continue;
          const reasons = dueReasons(entry, flags, day, urgentChanged, delivery.reminderDays);
          if (reasons.length) alerts.push({ app, entry, flags, urgentChanged, reasons, token: entry.token });
        }
        const escalationDue = delivery.includeEscalationContacts && delivery.escalationAfterDays !== null && alerts.some(({ entry }) => daysSince(entry.firstMatchedOn, day) >= delivery.escalationAfterDays);
        const recipientDetails = [...new Map([...routeOwners.map(owner => ({ name: owner.name, email: owner.email, route: 'primary' })), ...(escalationDue ? routeOwners.filter(owner => owner.escalationEmail).map(owner => ({ name: owner.name, email: owner.escalationEmail, route: 'escalation' })) : [])].map(item => [item.email, item])).values()];
        const recipients = recipientDetails.map(item => item.email);
        if (!alerts.length || !recipients.length || !mailer || !baseUrl) continue;
        await save(); // Persist acknowledgment tokens before sending their links.
        const message = messageFor(group, alerts, baseUrl);
        if (policy) message.subject = `${message.subject} · ${policy.name}`;
        try {
          const response = await mailer.sendMail({ from: settings.from || 'WatchTower <watchtower@localhost>', to: recipients.join(', '), ...message });
          const accepted = (response?.accepted || []).map(String);
          const rejected = (response?.rejected || []).map(String);
          const outcome = rejected.length ? accepted.length ? 'partial' : 'rejected' : 'accepted';
          await deliveryLogger?.({ outcome, message: `${policy ? policy.name : 'Lifecycle'} ${delivery.cadence === 'immediate' ? 'notification' : 'digest'} ${outcome}`, deliveryType: policy ? delivery.cadence : 'lifecycle', workspace: group.name, applications: alerts.map(item => item.app.name), policies: policy ? [policy.name] : [], reasons: [...new Set(alerts.flatMap(item => item.reasons))], recipients: recipientDetails, accepted, rejected, messageId: String(response?.messageId || '') });
          if (rejected.length) throw new Error(`Recipients rejected: ${rejected.join(', ')}`);
          for (const { entry, flags, urgentChanged, reasons } of alerts) {
            if (flags.vulnerable && (urgentChanged || reasons.some(reason => reason.startsWith('Needs action')))) entry.redLastSentOn = day;
            if (urgentChanged) entry.urgentFingerprint = flags.urgentFingerprint;
            if (flags.approaching && reasons.some(reason => reason.startsWith('End of life'))) entry.eol30SentOn = day;
            if (flags.expired && reasons.some(reason => reason.startsWith('Past end of life'))) entry.expiredLastSentOn = day;
          }
          await save();
          console.log(`Sent ${alerts.length} notification(s) for workspace ${group.id}${policy ? ` using policy ${policy.id}` : ''}`);
        } catch (error) {
          if (!String(error.message).startsWith('Recipients rejected:')) await deliveryLogger?.({ outcome: 'failed', message: `${policy ? policy.name : 'Lifecycle'} delivery failed`, deliveryType: policy ? delivery.cadence : 'lifecycle', workspace: group.name, applications: alerts.map(item => item.app.name), policies: policy ? [policy.name] : [], reasons: [...new Set(alerts.flatMap(item => item.reasons))], recipients: recipientDetails, accepted: [], rejected: [], error: String(error.message || 'Delivery failed').slice(0, 500) });
          console.error(`Could not email workspace ${group.id}: ${error.message}`);
        }
      }
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
          const [workspaceId, appId, version, policyId] = JSON.parse(key);
          const nextWorkspaceId = changes.workspaceFrom === workspaceId ? changes.workspaceTo : workspaceId;
          const nextAppId = changes.appFrom === appId ? changes.appTo : appId;
          nextKey = JSON.stringify([nextWorkspaceId, nextAppId, version, policyId].filter(value => value !== undefined));
        } catch {}
        if (nextKey !== key) changed = true;
        if (entries[nextKey]) throw new Error('Notification state collision while renaming an identifier');
        entries[nextKey] = entry;
      }
      if (changed) { state.entries = entries; await save(); }
    }),
  };
}
