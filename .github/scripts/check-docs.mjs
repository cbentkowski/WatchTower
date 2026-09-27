import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const root = process.cwd();
const files = process.argv.slice(2);
if (!files.length) throw new Error('Provide one or more Markdown files to validate');

const cache = new Map();
function slug(value) {
  return value
    .toLowerCase()
    .replace(/<[^>]+>/g, '')
    .replace(/[`*_~]/g, '')
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .trim()
    .replace(/\s+/g, '-');
}

async function document(file) {
  const absolute = path.resolve(root, file);
  if (cache.has(absolute)) return cache.get(absolute);
  const text = await readFile(absolute, 'utf8');
  const anchors = new Set();
  const seen = new Map();
  for (const line of text.split(/\r?\n/)) {
    const heading = line.match(/^#{1,6}\s+(.+?)\s*#*$/);
    if (!heading) continue;
    const base = slug(heading[1]);
    const count = seen.get(base) || 0;
    seen.set(base, count + 1);
    anchors.add(count ? `${base}-${count}` : base);
  }
  const result = { absolute, text, anchors };
  cache.set(absolute, result);
  return result;
}

const failures = [];
for (const file of files) {
  const source = await document(file);
  const linkPattern = /\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
  for (const match of source.text.matchAll(linkPattern)) {
    const href = match[1];
    if (/^(?:https?:|mailto:)/i.test(href)) continue;
    const [rawTarget, rawAnchor = ''] = href.split('#', 2);
    const targetPath = decodeURIComponent(rawTarget || file);
    const target = rawTarget ? path.resolve(path.dirname(source.absolute), targetPath) : source.absolute;
    try { if (!(await stat(target)).isFile()) throw new Error('not a file'); }
    catch { failures.push(`${file}: missing link target ${href}`); continue; }
    if (rawAnchor && target.toLowerCase().endsWith('.md')) {
      const targetDocument = await document(path.relative(root, target));
      const anchor = decodeURIComponent(rawAnchor).toLowerCase();
      if (!targetDocument.anchors.has(anchor)) failures.push(`${file}: missing anchor #${rawAnchor} in ${path.relative(root, target)}`);
    }
  }
}

if (failures.length) {
  console.error(failures.join('\n'));
  process.exit(1);
}
console.log(`Validated ${files.length} Markdown files.`);
