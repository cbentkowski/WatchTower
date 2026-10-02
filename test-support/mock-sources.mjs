import { appendFileSync, readFileSync } from 'node:fs';

const originalFetch = globalThis.fetch;

globalThis.fetch = async (input, options) => {
  const url = String(input);
  if (process.env.WATCHTOWER_TEST_FETCH_LOG) appendFileSync(process.env.WATCHTOWER_TEST_FETCH_LOG, `${url}\n`);
  if (url.startsWith('https://api.osv.dev/')) {
    const mode = process.env.WATCHTOWER_TEST_OSV_MODE_FILE ? readFileSync(process.env.WATCHTOWER_TEST_OSV_MODE_FILE, 'utf8').trim() : 'empty';
    if (mode === 'offline') return new Response('', { status: 503 });
    if (url.endsWith('/querybatch')) {
      const queries = JSON.parse(options.body).queries;
      return new Response(JSON.stringify({ results: queries.map(() => mode === 'empty' ? {} : { vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz', modified: mode }] }) }));
    }
    return new Response(JSON.stringify({ id: 'GHSA-xxxx-yyyy-zzzz', modified: mode, aliases: ['CVE-2026-1234'], summary: 'Fixture package vulnerability', database_specific: { severity: 'CRITICAL' }, affected: [{ package: { ecosystem: 'npm', name: 'example' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }] }));
  }
  if (url.includes('known_exploited_vulnerabilities.json')) {
    return new Response(JSON.stringify({ vulnerabilities: [] }), { headers: { 'content-type': 'application/json' } });
  }
  if (url.includes('services.nvd.nist.gov/rest/json/cves/2.0')) {
    return new Response(JSON.stringify({ totalResults: 0, vulnerabilities: [] }), { headers: { 'content-type': 'application/json' } });
  }
  if (url.startsWith('https://93.184.216.')) {
    return new Response('<rss><channel><item><title>Test release 1.0.1</title></item></channel></rss>', { headers: { 'content-type': 'application/rss+xml' } });
  }
  return originalFetch(input, options);
};
