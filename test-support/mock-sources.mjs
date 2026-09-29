import { appendFileSync } from 'node:fs';

const originalFetch = globalThis.fetch;

globalThis.fetch = async (input, options) => {
  const url = String(input);
  if (process.env.WATCHTOWER_TEST_FETCH_LOG) appendFileSync(process.env.WATCHTOWER_TEST_FETCH_LOG, `${url}\n`);
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
