import { appendFileSync, readFileSync } from 'node:fs';

const originalFetch = globalThis.fetch;

globalThis.fetch = async (input, options) => {
  const url = String(input);
  if (process.env.WATCHTOWER_TEST_FETCH_LOG) appendFileSync(process.env.WATCHTOWER_TEST_FETCH_LOG, `${url}\n`);
  if (url.startsWith('https://api.osv.dev/')) {
    const mode = process.env.WATCHTOWER_TEST_OSV_MODE_FILE ? readFileSync(process.env.WATCHTOWER_TEST_OSV_MODE_FILE, 'utf8').trim() : 'empty';
    if (mode === 'offline') return new Response('', { status: 503 });
    if (mode === 'replacement') {
      if (url.endsWith('/querybatch')) {
        const queries = JSON.parse(options.body).queries;
        return new Response(JSON.stringify({ results: queries.map(query => {
          const purl = query.package.purl;
          return purl === 'pkg:npm/lodash@4.17.20' ? { vulns: [{ id: 'GHSA-demo-lodash' }] } : purl === 'pkg:npm/minimist@1.2.5' ? { vulns: [{ id: 'GHSA-demo-minimist' }] } : {};
        }) }));
      }
      const name = url.endsWith('lodash') ? 'lodash' : 'minimist';
      return new Response(JSON.stringify({ id: `GHSA-demo-${name}`, summary: `Fixture ${name} finding`, database_specific: { severity: 'HIGH' }, affected: [{ package: { ecosystem: 'npm', name }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: name === 'lodash' ? '4.18.1' : '1.2.6' }] }] }] }));
    }
    if (url.endsWith('/querybatch')) {
      const queries = JSON.parse(options.body).queries;
      return new Response(JSON.stringify({ results: queries.map(() => mode === 'empty' ? {} : { vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz', modified: mode }] }) }));
    }
    return new Response(JSON.stringify({ id: 'GHSA-xxxx-yyyy-zzzz', modified: mode, aliases: ['CVE-2026-1234'], summary: 'Fixture package vulnerability', database_specific: { severity: 'CRITICAL' }, affected: [{ package: { ecosystem: 'npm', name: 'example' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }] }));
  }
  if (url.includes('known_exploited_vulnerabilities.json')) {
    if (process.env.WATCHTOWER_TEST_KEV_FILE) {
      const contents = readFileSync(process.env.WATCHTOWER_TEST_KEV_FILE, 'utf8');
      return contents.trim() === 'offline' ? new Response('', { status: 503 }) : new Response(contents, { headers: { 'content-type': 'application/json' } });
    }
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
