import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

async function fingerprint(file) {
  try { return createHash('sha256').update(await readFile(file)).digest('hex'); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

export function createYamlMonitor({ files, onChange, intervalMs = 30_000 }) {
  const known = new Map();
  const webWrites = new Set();
  let checking = false;

  async function check() {
    if (checking) return;
    checking = true;
    try {
      const changes = [];
      for (const [name, file] of Object.entries(files)) {
        if (webWrites.has(file)) continue;
        const current = await fingerprint(file);
        if (webWrites.has(file)) continue;
        const previous = known.get(file);
        if (current === previous) continue;
        known.set(file, current);
        changes.push({ name, kind: previous === null ? 'created' : current === null ? 'removed' : 'modified' });
      }
      if (changes.length) await onChange(changes);
    } finally { checking = false; }
  }

  async function webWrite(file, operation) {
    webWrites.add(file);
    try {
      const result = await operation();
      known.set(file, await fingerprint(file));
      return result;
    } finally { webWrites.delete(file); }
  }

  async function start() {
    for (const file of Object.values(files)) known.set(file, await fingerprint(file));
    const timer = setInterval(() => check().catch(error => console.error(`YAML check failed: ${error.message}`)), intervalMs);
    timer.unref();
  }

  return { check, webWrite, start };
}
