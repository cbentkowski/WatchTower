import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { collectFeeds, eventAffectsVersion, feedRequestUrl, inertText, normalizeEntries, parseFeeds, secureFetchText, serializeFeeds, validateFeedInput, validatePublicHttpsUrl } from '../src/feeds.mjs';

const feedId = '11111111-1111-4111-8111-111111111111';
const appId = '22222222-2222-4222-8222-222222222222';
const feed = { id: feedId, name: 'Istio News', url: 'https://istio.io/latest/feed.xml', format: 'auto', enabled: true, categories: ['security', 'release', 'lifecycle'], productAliases: ['Istio'], applicationIds: [appId] };

test('feed YAML preserves immutable IDs, categories, aliases, and application associations', () => {
  const parsed = parseFeeds(serializeFeeds([feed]));
  assert.deepEqual(parsed, [feed]);
  assert.equal(validateFeedInput({ ...feed, id: 'ignored' }, [{ id: appId }], feedId).id, feedId);
  assert.throws(() => validateFeedInput({ ...feed, applicationIds: ['33333333-3333-4333-8333-333333333333'] }, [{ id: appId }]), /unknown application/);
});

test('feed URLs reject credentials, alternate ports, and private destinations', () => {
  for (const value of ['http://example.com/feed', 'https://user:pass@example.com/feed', 'https://example.com:8443/feed', 'https://127.0.0.1/feed', 'https://169.254.169.254/latest/meta-data', 'https://service.internal/feed', 'https://localhost/feed']) {
    assert.throws(() => validatePublicHttpsUrl(value), /HTTPS|public Internet/);
  }
  assert.equal(validatePublicHttpsUrl('https://example.com/feed').hostname, 'example.com');
});

test('secure feed fetch revalidates redirects and DNS results', async () => {
  const resolver = async () => [{ address: '93.184.216.34', family: 4 }];
  const ok = await secureFetchText('https://example.com/feed', { resolver, fetchImpl: async () => new Response('<rss/>', { headers: { 'content-type': 'application/rss+xml' } }) });
  assert.equal(ok.text, '<rss/>');
  await assert.rejects(() => secureFetchText('https://example.com/feed', {
    resolver,
    fetchImpl: async () => new Response('', { status: 302, headers: { location: 'https://127.0.0.1/private' } }),
  }), /public Internet/);
  await assert.rejects(() => secureFetchText('https://example.com/feed', {
    resolver: async () => [{ address: '10.0.0.8', family: 4 }], fetchImpl: async () => new Response('never'),
  }), /private or restricted/);
});

test('untrusted markup becomes inert text and security ranges are normalized', () => {
  globalThis.__feedExecuted = false;
  const response = {
    contentType: 'application/rss+xml', url: feed.url,
    text: `<rss><channel><item><title>ISTIO-SECURITY-2026-005</title><link>https://istio.io/security/005</link><description><![CDATA[<img src=x onerror="globalThis.__feedExecuted=true"><script>globalThis.__feedExecuted=true</script>High severity CVE-2026-12345 affects 1.30.1 to 1.30.2. Fixed in 1.30.3.</body>]]></description></item></channel></rss>`,
  };
  const [event] = normalizeEntries(feed, response);
  assert.equal(globalThis.__feedExecuted, false);
  assert.equal(inertText('<script>alert(1)</script><b>Safe</b>'), 'Safe');
  assert.equal(inertText('<script>unsafe</script foo="bar"><b>Visible text</b><strong>Safe</strong>'), 'Visible text Safe');
  const [htmlEvent] = normalizeEntries(feed, { contentType: 'text/html', url: feed.url, text: '<script>unsafe</script foo="bar"><article><h2>Security CVE-2026-54321</h2><p>Safe advisory text</p></article>' });
  assert.equal(htmlEvent.summary.includes('unsafe'), false);
  assert.match(htmlEvent.summary, /Safe advisory text/);
  assert.equal(event.type, 'security');
  assert.equal(event.severity, 'HIGH');
  assert.deepEqual(event.cves, ['CVE-2026-12345']);
  assert.equal(eventAffectsVersion(event, '1.30.1'), true);
  assert.equal(eventAffectsVersion(event, '1.30.3'), false);
  assert.doesNotMatch(event.summary, /script|onerror|globalThis/);
});

test('oversized feed bodies are rejected before parsing', async () => {
  const resolver = async () => [{ address: '93.184.216.34', family: 4 }];
  await assert.rejects(() => secureFetchText('https://example.com/feed', {
    resolver, maximumBytes: 10, fetchImpl: async () => new Response('12345678901', { headers: { 'content-type': 'text/plain' } }),
  }), /size limit/);
});

test('release, lifecycle, and GitHub advisory entries normalize to the common model', () => {
  const events = normalizeEntries(feed, { contentType: 'application/rss+xml', url: feed.url, text: '<rss><channel><item><title>Announcing Istio 1.31.1</title><link>https://istio.io/release</link><description>New release</description></item><item><title>Support for Istio 1.29 ends on the 12th of October, 2026</title><link>https://istio.io/eol</link><description>Upgrade before end of support.</description></item></channel></rss>' });
  assert.equal(events[0].type, 'release');
  assert.deepEqual(events[0].versions, ['1.31.1']);
  assert.equal(events[1].type, 'lifecycle');
  assert.equal(events[1].endDate, '2026-10-12');
  const githubFeed = { ...feed, format: 'github', url: 'https://github.com/istio/istio/security/advisories', categories: ['security'] };
  assert.equal(feedRequestUrl(githubFeed), 'https://api.github.com/repos/istio/istio/security-advisories?per_page=100');
  const [advisory] = normalizeEntries(githubFeed, { contentType: 'application/json', url: feedRequestUrl(githubFeed), text: JSON.stringify([{ ghsa_id: 'GHSA-test', summary: 'Security issue', severity: 'high', cvss: { score: 8.1 }, html_url: 'https://github.com/istio/istio/security/advisories/GHSA-test', vulnerabilities: [{ package: { name: 'Istio' }, vulnerable_version_range: '>= 1.30.0, < 1.30.3', first_patched_version: { identifier: '1.30.3' } }] }]) });
  assert.equal(advisory.severity, 'HIGH');
  assert.equal(eventAffectsVersion(advisory, '1.30.1'), true);
  assert.equal(eventAffectsVersion(advisory, '1.30.3'), false);
});

test('collecting one feed preserves other cached feeds', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-feeds-'));
  const cacheFile = path.join(directory, 'feeds.json');
  const resolver = async () => [{ address: '93.184.216.34', family: 4 }];
  const fetchImpl = async url => new Response(`<rss><channel><item><title>Announcing ${url.pathname.includes('second') ? '2.0.0' : '1.0.0'}</title></item></channel></rss>`, { headers: { 'content-type': 'application/rss+xml' } });
  const second = { ...feed, id: '33333333-3333-4333-8333-333333333333', name: 'Second', url: 'https://example.com/second' };
  await collectFeeds([feed, second], cacheFile, { resolver, fetchImpl });
  await collectFeeds([feed], cacheFile, { resolver, fetchImpl, preserveUnlisted: true });
  const cached = JSON.parse(await readFile(cacheFile, 'utf8'));
  assert.equal(cached.feeds[feed.id].status, 'ok');
  assert.equal(cached.feeds[second.id].status, 'ok');
});
