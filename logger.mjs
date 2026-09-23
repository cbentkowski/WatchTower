import { appendFile, mkdir, readFile, rename, stat } from 'node:fs/promises';
import path from 'node:path';

export function createLogger(dataDirectory) {
  const file = path.join(dataDirectory, 'logs.jsonl');
  let pending = Promise.resolve();
  function append(entry) {
    pending = pending.then(async () => {
      await mkdir(dataDirectory, { recursive: true });
      if ((await stat(file).catch(() => ({ size: 0 }))).size > 5_000_000) await rename(file, path.join(dataDirectory, 'logs.previous.jsonl'));
      await appendFile(file, `${JSON.stringify(entry)}\n`);
    }).catch(error => console.error(`Could not write log: ${error.message}`));
    return pending;
  }
  function log(level, message, detail = '') {
    return append({ at: new Date().toISOString(), level, message, detail: String(detail || '') });
  }
  function audit(action, actor, target, changes, detail) {
    return append({ at: new Date().toISOString(), level: 'audit', message: action, detail, actor, target, changes });
  }
  async function recent(limit = 200) {
    await pending;
    const files = [path.join(dataDirectory, 'logs.previous.jsonl'), file];
    const entries = [];
    for (const source of files) {
      let text;
      try { text = await readFile(source, 'utf8'); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
      for (const line of text.split('\n')) if (line) { try { entries.push(JSON.parse(line)); } catch {} }
    }
    return entries.slice(-limit).reverse();
  }
  return { log, audit, recent };
}
