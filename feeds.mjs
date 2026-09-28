import { randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import path from 'node:path';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const allowedFormats = new Set(['auto', 'rss', 'atom', 'json', 'html', 'github']);
const allowedCategories = new Set(['security', 'release', 'lifecycle']);
const MAX_RESPONSE_BYTES = 10_000_000;
const MAX_ENTRIES = 250;
const MAX_REDIRECTS = 4;

const scalar = value => { const raw = value.trim(); if (raw.startsWith('"')) return JSON.parse(raw); return raw === 'true' ? true : raw === 'false' ? false : raw; };
const q = value => JSON.stringify(String(value));

export function parseFeeds(source) {
  const feeds = [];
  let current = null;
  let list = null;
  for (const line of source.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed === 'version: 1' || trimmed === 'feeds:') continue;
    const entry = line.match(/^  - id:\s*(.*)$/);
    const field = line.match(/^    ([A-Za-z][\w]*):\s*(.*)$/);
    const item = line.match(/^      -\s*(.*)$/);
    if (entry) { current = { id: scalar(entry[1]) }; feeds.push(current); list = null; }
    else if (field && current) {
      if (field[2] === '') { current[field[1]] = []; list = field[1]; }
      else { current[field[1]] = scalar(field[2]); list = null; }
    } else if (item && current && list) current[list].push(scalar(item[1]));
    else throw new Error(`Unsupported feed YAML line: ${line}`);
  }
  for (const feed of feeds) normalizeFeed(feed, true);
  if (new Set(feeds.map(feed => feed.id)).size !== feeds.length) throw new Error('Feed IDs must be unique');
  return feeds;
}

export function serializeFeeds(feeds) {
  const body = feeds.map(feed => `  - id: ${feed.id}\n    name: ${q(feed.name)}\n    url: ${q(feed.url)}\n    format: ${q(feed.format)}\n    enabled: ${feed.enabled !== false}\n    categories:\n${feed.categories.map(value => `      - ${q(value)}\n`).join('')}    productAliases:\n${feed.productAliases.map(value => `      - ${q(value)}\n`).join('')}    applicationIds:\n${feed.applicationIds.map(value => `      - ${value}\n`).join('')}`).join('');
  return `# Feed content is always treated as untrusted data. Feed IDs are immutable UUIDs.\nversion: 1\nfeeds:\n${body}`;
}

function normalizeFeed(input, requireId = false, applications = []) {
  const feed = {
    id: String(input.id || '').trim(), name: String(input.name || '').trim(), url: String(input.url || '').trim(),
    format: String(input.format || 'auto').trim().toLowerCase(), enabled: input.enabled !== false,
    categories: [...new Set((input.categories || ['security', 'release', 'lifecycle']).map(value => String(value).trim().toLowerCase()).filter(Boolean))],
    productAliases: [...new Set((input.productAliases || []).map(value => String(value).trim()).filter(Boolean))],
    applicationIds: [...new Set((input.applicationIds || []).map(value => String(value).trim()).filter(Boolean))],
  };
  if (!feed.id && !requireId) feed.id = randomUUID();
  if (!uuid.test(feed.id) || !feed.name || !feed.url) throw new Error('Feed requires an immutable UUID, name, and URL');
  if (!allowedFormats.has(feed.format)) throw new Error('Feed format must be auto, rss, atom, json, html, or github');
  if (!feed.categories.length || feed.categories.some(value => !allowedCategories.has(value))) throw new Error('Feed categories must include security, release, or lifecycle');
  validatePublicHttpsUrl(feed.url);
  if (applications.length) {
    const known = new Set(applications.map(app => app.id));
    if (feed.applicationIds.some(id => !known.has(id))) throw new Error('Feed references an unknown application');
  }
  return feed;
}

export function validateFeedInput(input, applications, existingId = '') {
  return normalizeFeed({ ...input, id: existingId || input?.id }, false, applications);
}

export async function readFeeds(file) { try { return parseFeeds(await readFile(file, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return []; throw error; } }
export async function writeFeeds(file, feeds) { const temporary = `${file}.tmp`; await writeFile(temporary, serializeFeeds(feeds)); await rename(temporary, file); return feeds; }

function blockedIpv4(address) {
  const parts = address.split('.').map(Number);
  return parts[0] === 0 || parts[0] === 10 || parts[0] === 127 || parts[0] >= 224
    || (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127)
    || (parts[0] === 169 && parts[1] === 254) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
    || (parts[0] === 192 && parts[1] === 168) || (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19));
}
function blockedIp(address) {
  if (isIP(address) === 4) return blockedIpv4(address);
  if (isIP(address) !== 6) return true;
  const value = address.toLowerCase();
  if (value === '::' || value === '::1' || value.startsWith('fc') || value.startsWith('fd') || /^fe[89ab]/.test(value)) return true;
  const mapped = value.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  return mapped ? blockedIpv4(mapped) : false;
}

export function validatePublicHttpsUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Feed URL must be a valid HTTPS URL'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port && url.port !== '443') throw new Error('Feed URL must use HTTPS on the standard port without credentials');
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal') || (isIP(hostname) && blockedIp(hostname))) throw new Error('Feed URL must use a public Internet host');
  return url;
}

async function assertPublicResolution(url, resolver = lookup) {
  const records = await resolver(url.hostname, { all: true, verbatim: true });
  if (!records.length || records.some(record => blockedIp(record.address))) throw new Error('Feed host resolves to a private or restricted address');
}

async function limitedBody(response, maximum = MAX_RESPONSE_BYTES) {
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared > maximum) throw new Error('Feed response exceeds the size limit');
  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maximum) { await reader.cancel(); throw new Error('Feed response exceeds the size limit'); }
    chunks.push(value);
  }
  const combined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { combined.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder('utf-8', { fatal: false }).decode(combined);
}

export async function secureFetchText(value, options = {}) {
  let url = validatePublicHttpsUrl(value);
  const fetchImpl = options.fetchImpl || fetch;
  const resolver = options.resolver || lookup;
  const headers = { 'User-Agent': 'WatchTower/0.4 Feed Collector', Accept: 'application/rss+xml, application/atom+xml, application/json, text/html;q=0.8, text/plain;q=0.5', ...(options.headers || {}) };
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    await assertPublicResolution(url, resolver);
    const response = await fetchImpl(url, { headers, redirect: 'manual', signal: AbortSignal.timeout(options.timeout || 15_000) });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location || redirects === MAX_REDIRECTS) throw new Error('Feed redirect limit exceeded');
      url = validatePublicHttpsUrl(new URL(location, url).href);
      continue;
    }
    if (response.status === 304) return { notModified: true, text: '', contentType: '', url: url.href, etag: response.headers.get('etag') || '', modified: response.headers.get('last-modified') || '' };
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const type = String(response.headers.get('content-type') || '').toLowerCase();
    if (type && !/(xml|rss|atom|json|html|text\/plain)/.test(type)) throw new Error(`Unsupported feed content type: ${type.split(';')[0]}`);
    return { text: await limitedBody(response, options.maximumBytes || MAX_RESPONSE_BYTES), contentType: type, url: url.href, etag: response.headers.get('etag') || '', modified: response.headers.get('last-modified') || '' };
  }
  throw new Error('Feed redirect limit exceeded');
}

const entityMap = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
function decodeEntities(value) { return String(value || '').replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (_, key) => key[0] === '#' ? String.fromCodePoint(key[1].toLowerCase() === 'x' ? parseInt(key.slice(2), 16) : parseInt(key.slice(1), 10)) : entityMap[key.toLowerCase()] ?? ' '); }
export function inertText(value) {
  return decodeEntities(String(value || '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/gi, '$1').replace(/<script\b[\s\S]*?<\/script\s*>/gi, ' ').replace(/<style\b[\s\S]*?<\/style\s*>/gi, ' ').replace(/<[^>]+>/g, ' ')).replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 20_000);
}
function tag(block, names) { for (const name of names) { const value = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${name}\\s*>`, 'i'))?.[1]; if (value) return inertText(value); } return ''; }
function attr(block, element, attribute) { return decodeEntities(block.match(new RegExp(`<${element}[^>]*\\s${attribute}=["']([^"']+)["']`, 'i'))?.[1] || ''); }
function safeSourceUrl(value, base) { try { const url = new URL(value, base); return url.protocol === 'https:' ? url.href : ''; } catch { return ''; } }

function xmlEntries(text, base) {
  const blocks = [...text.matchAll(/<(item|entry)\b[^>]*>([\s\S]*?)<\/\1\s*>/gi)].map(match => match[2]).slice(0, MAX_ENTRIES);
  return blocks.map(block => ({
    title: tag(block, ['title']),
    summary: tag(block, ['description', 'summary', 'content', 'content:encoded']),
    published: tag(block, ['pubDate', 'published', 'updated', 'dc:date']),
    url: safeSourceUrl(tag(block, ['link', 'guid']) || attr(block, 'link', 'href'), base),
  }));
}
function jsonEntries(text, base) {
  const data = JSON.parse(text);
  const entries = Array.isArray(data) ? data : data.items || data.entries || data.advisories || data.vulnerabilities || [];
  if (!Array.isArray(entries)) throw new Error('JSON feed does not contain an entry array');
  return entries.slice(0, MAX_ENTRIES).map(item => ({
    title: inertText(item.title || item.name || item.summary || item.ghsa_id || item.id), summary: inertText([item.summary, item.description, item.details, item.body, item.severity, item.cvss?.score ? `CVSS ${item.cvss.score}` : '', ...(item.vulnerabilities || []).map(value => `${value.package?.name || ''} affected ${value.vulnerable_version_range || ''} fixed ${value.first_patched_version?.identifier || ''}`)].filter(Boolean).join(' ')),
    published: String(item.published || item.published_at || item.date || item.updated_at || ''),
    url: safeSourceUrl(item.html_url || item.url || item.link || '', base),
  }));
}
function htmlEntries(text, base) {
  const clean = text.replace(/<script\b[\s\S]*?<\/script\s*>/gi, ' ').replace(/<style\b[\s\S]*?<\/style\s*>/gi, ' ');
  const blocks = [...clean.matchAll(/<(article|tr|li)\b[^>]*>([\s\S]*?)<\/\1\s*>/gi)].map(match => match[2]).filter(block => /(CVE-|security|vulnerab|release|end.of.(?:life|support)|EOL)/i.test(block)).slice(0, MAX_ENTRIES);
  return blocks.map(block => ({ title: tag(block, ['h1', 'h2', 'h3', 'h4', 'title']) || inertText(block).slice(0, 180), summary: inertText(block), published: '', url: safeSourceUrl(attr(block, 'a', 'href'), base) }));
}

function versionParts(value) { return String(value).split('.').map(part => Number(part.replace(/\D.*$/, '')) || 0); }
export function compareFeedVersions(a, b) { const av = versionParts(a), bv = versionParts(b); for (let i = 0; i < Math.max(av.length, bv.length); i++) if ((av[i] || 0) !== (bv[i] || 0)) return (av[i] || 0) - (bv[i] || 0); return 0; }
function parseApplicability(text) {
  const ranges = [];
  for (const match of text.matchAll(/(\d+\.\d+(?:\.\d+)?)\s+(?:to|through|thru|–|—|-)\s+(\d+\.\d+(?:\.\d+)?)/gi)) ranges.push({ introduced: match[1], lastAffected: match[2] });
  for (const match of text.matchAll(/(?:before|prior to|earlier than)\s+(?:version\s+)?(\d+\.\d+(?:\.\d+)?)/gi)) ranges.push({ introduced: '0', fixed: match[1] });
  for (const match of text.matchAll(/(?:>=\s*(\d+\.\d+(?:\.\d+)?)[^\d]{0,20})?<\s*(\d+\.\d+(?:\.\d+)?)/gi)) ranges.push({ introduced: match[1] || '0', fixed: match[2] });
  const fixedVersions = [...text.matchAll(/(?:fixed|patched|resolved)\s+(?:in|by|with)?\s*(?:version\s+)?(\d+\.\d+(?:\.\d+)?)/gi)].map(match => match[1]);
  return { ranges, fixedVersions: [...new Set(fixedVersions)] };
}
function classify(text, title = '') {
  if (/(end.of.(?:life|support)|\bEOL\b|support(?:\s+for\s+.*?)?\s+ends?|unsupported)/i.test(title)) return 'lifecycle';
  if (/(security|vulnerab|advisory|CVE-\d{4}-\d+)/i.test(title)) return 'security';
  if (/(announc|new|patch)\w*.*?\d+\.\d+|\brelease[sd]?\b/i.test(title)) return 'release';
  if (/(CVE-\d{4}-\d+|security|vulnerab|advisory|CVSS)/i.test(text)) return 'security';
  if (/(end.of.(?:life|support)|\bEOL\b|support ends?|unsupported)/i.test(text)) return 'lifecycle';
  if (/(announc|new|patch)\w*\s+(?:version\s+)?\d+\.\d+|\brelease[sd]?\b/i.test(text)) return 'release';
  return 'other';
}
function severity(text) {
  const score = Math.max(0, ...[...text.matchAll(/CVSS(?:v\d(?:\.\d)?)?[^\d]{0,20}(\d+(?:\.\d+)?)/gi)].map(match => Number(match[1])).filter(value => value <= 10));
  const label = /critical/i.test(text) ? 'CRITICAL' : /high/i.test(text) ? 'HIGH' : /medium|moderate/i.test(text) ? 'MEDIUM' : /low/i.test(text) ? 'LOW' : score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : score ? 'LOW' : 'UNKNOWN';
  return { score, severity: label };
}
function eventDate(text) {
  const iso = text.match(/\b(20\d{2}-\d{2}-\d{2})\b/)?.[1];
  if (iso) return iso;
  const months = 'January|February|March|April|May|June|July|August|September|October|November|December';
  const dayFirst = text.match(new RegExp(`\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+(?:of\\s+)?(${months})\\s*,?\\s*(20\\d{2})`, 'i'));
  const monthFirst = text.match(new RegExp(`\\b(${months})\\s+(\\d{1,2})(?:st|nd|rd|th)?\\s*,?\\s*(20\\d{2})`, 'i'));
  const match = dayFirst ? [dayFirst[2], dayFirst[1], dayFirst[3]] : monthFirst ? [monthFirst[1], monthFirst[2], monthFirst[3]] : null;
  if (!match) return '';
  const date = new Date(`${match[0]} ${match[1]}, ${match[2]} UTC`);
  return Number.isFinite(date.getTime()) ? date.toISOString().slice(0, 10) : '';
}

export function normalizeEntries(feed, response) {
  const format = feed.format === 'auto' ? /json/.test(response.contentType) || /^\s*[\[{]/.test(response.text) ? 'json' : /<(rss|feed)\b/i.test(response.text) ? 'rss' : 'html' : feed.format;
  const raw = format === 'json' || format === 'github' && /^\s*[\[{]/.test(response.text) ? jsonEntries(response.text, response.url) : ['rss', 'atom'].includes(format) ? xmlEntries(response.text, response.url) : htmlEntries(response.text, response.url);
  return raw.map((entry, index) => {
    const evidence = inertText(`${entry.title} ${entry.summary}`);
    const type = classify(evidence, entry.title);
    const applicability = parseApplicability(evidence);
    const level = severity(evidence);
    // Release and lifecycle pages frequently embed unrelated dependency and IP
    // numbers in their bodies. Their titles identify the product release line,
    // so only security advisories need full-body version extraction.
    const versionEvidence = type === 'security' ? evidence : inertText(entry.title);
    const versions = [...new Set([...versionEvidence.matchAll(/\b(v?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?)\b/g)].map(match => match[1].replace(/^v/, '')))];
    return {
      id: `${feed.id}:${index}:${entry.url || entry.title}`.slice(0, 1000), feedId: feed.id, feedName: feed.name, type,
      title: inertText(entry.title).slice(0, 300), summary: inertText(entry.summary).slice(0, 4000), published: String(entry.published || '').slice(0, 100),
      url: entry.url || response.url, cves: [...new Set(evidence.match(/CVE-\d{4}-\d{4,}/gi) || [])].map(value => value.toUpperCase()),
      ...level, ...applicability, versions, endDate: type === 'lifecycle' ? eventDate(evidence) : '', confidence: applicability.ranges.length || applicability.fixedVersions.length || type === 'lifecycle' && eventDate(evidence) ? 'high' : type === 'security' ? 'medium' : versions.length ? 'medium' : 'low',
    };
  }).filter(entry => feed.categories.includes(entry.type));
}

export function eventAffectsVersion(event, version) {
  if (event.ranges.some(range => compareFeedVersions(version, range.introduced) >= 0 && (range.lastAffected ? compareFeedVersions(version, range.lastAffected) <= 0 : range.fixed ? compareFeedVersions(version, range.fixed) < 0 : true))) return true;
  return event.fixedVersions.some(fixed => compareFeedVersions(version, fixed) < 0);
}

export function feedRequestUrl(feed) {
  if (feed.format !== 'github') return feed.url;
  const url = validatePublicHttpsUrl(feed.url);
  const match = url.hostname === 'github.com' && url.pathname.match(/^\/([^/]+)\/([^/]+)(?:\/security\/advisories)?\/?$/i);
  return match ? `https://api.github.com/repos/${encodeURIComponent(match[1])}/${encodeURIComponent(match[2])}/security-advisories?per_page=100` : feed.url;
}

export async function collectFeeds(feeds, cacheFile, options = {}) {
  let previous = { feeds: {} };
  try { previous = JSON.parse(await readFile(cacheFile, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const { preserveUnlisted = false, onEvent = async () => {}, ...fetchOptions } = options;
  const result = { checkedAt: new Date().toISOString(), feeds: preserveUnlisted ? { ...(previous.feeds || {}) } : {} };
  for (const feed of feeds) {
    if (!feed.enabled) { result.feeds[feed.id] = { status: 'disabled', entries: [], checkedAt: result.checkedAt }; await onEvent('info', 'Feed collection skipped', `${feed.name}: disabled`); continue; }
    try {
      const old = previous.feeds?.[feed.id] || {};
      const headers = {};
      if (old.etag) headers['If-None-Match'] = old.etag;
      if (old.modified) headers['If-Modified-Since'] = old.modified;
      if (feed.format === 'github') headers.Accept = 'application/vnd.github+json';
      const response = await secureFetchText(feedRequestUrl(feed), { ...fetchOptions, headers });
      result.feeds[feed.id] = response.notModified
        ? { ...old, status: 'ok', checkedAt: result.checkedAt, sourceUrl: response.url, etag: response.etag || old.etag, modified: response.modified || old.modified }
        : { status: 'ok', checkedAt: result.checkedAt, sourceUrl: response.url, etag: response.etag, modified: response.modified, entries: normalizeEntries(feed, response).slice(0, MAX_ENTRIES) };
      await onEvent('info', 'Feed collection succeeded', `${feed.name}: ${result.feeds[feed.id].entries?.length || 0} cached entries${response.notModified ? '; not modified' : ''}`);
    } catch (error) {
      result.feeds[feed.id] = { status: 'error', checkedAt: result.checkedAt, error: String(error.message || error).slice(0, 500), entries: previous.feeds?.[feed.id]?.entries || [] };
      await onEvent('error', 'Feed collection failed', `${feed.name}: ${result.feeds[feed.id].error}`);
    }
  }
  await mkdir(path.dirname(cacheFile), { recursive: true });
  const temporary = `${cacheFile}.tmp`;
  await writeFile(temporary, `${JSON.stringify(result)}\n`);
  await rename(temporary, cacheFile);
  return result;
}
