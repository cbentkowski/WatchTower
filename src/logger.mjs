import { appendFile, mkdir, readFile, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';

export const logTypes = Object.freeze(['system', 'feed', 'audit', 'auth', 'notification']);
const fileNames = Object.freeze({ system: 'system.jsonl', feed: 'feed.jsonl', audit: 'audit.jsonl', auth: 'auth.jsonl', notification: 'notification.jsonl' });
const maxSize = 5_000_000;

export function createLogger(dataDirectory) {
  const pending = new Map(logTypes.map(type => [type, Promise.resolve()]));
  const fileFor = type => path.join(dataDirectory, fileNames[type]);

  function append(type, entry) {
    const file = fileFor(type);
    const write = pending.get(type).then(async () => {
      await mkdir(dataDirectory, { recursive: true });
      if ((await stat(file).catch(() => ({ size: 0 }))).size > maxSize) {
        const previous = path.join(dataDirectory, `${path.parse(file).name}.previous.jsonl`);
        await rm(previous, { force: true });
        await rename(file, previous);
      }
      await appendFile(file, `${JSON.stringify(entry)}\n`);
    }).catch(error => console.error(`Could not write ${type} log: ${error.message}`));
    pending.set(type, write);
    return write;
  }

  function log(level, message, detail = '') {
    return append('system', { at: new Date().toISOString(), level, message, detail: String(detail || '') });
  }

  function feed(level, message, detail = '') {
    return append('feed', { at: new Date().toISOString(), level, message, detail: String(detail || '') });
  }

  function audit(action, actor, target, changes, detail) {
    return append('audit', { at: new Date().toISOString(), level: 'audit', message: action, detail, actor, target, changes });
  }

  function authentication(action, actor, context = {}) {
    return append('auth', { at: new Date().toISOString(), level: context.outcome || 'info', message: action, actor, authentication: context });
  }

  function notification(entry) {
    return append('notification', { at: new Date().toISOString(), level: entry.outcome || 'info', message: entry.message || 'Notification delivery attempted', notification: entry });
  }

  async function recent(type = 'system', limit = 200) {
    if (!logTypes.includes(type)) throw new Error('Unknown log type');
    await pending.get(type);
    const name = path.parse(fileNames[type]).name;
    const files = [path.join(dataDirectory, `${name}.previous.jsonl`), fileFor(type)];
    if (type === 'system') files.unshift(path.join(dataDirectory, 'logs.previous.jsonl'), path.join(dataDirectory, 'logs.jsonl'));
    const entries = [];
    for (const source of files) {
      let text;
      try { text = await readFile(source, 'utf8'); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
      for (const line of text.split('\n')) if (line) { try { entries.push(JSON.parse(line)); } catch {} }
    }
    return entries.sort((a, b) => String(a.at).localeCompare(String(b.at))).slice(-limit).reverse();
  }

  return { log, feed, audit, authentication, notification, recent };
}
