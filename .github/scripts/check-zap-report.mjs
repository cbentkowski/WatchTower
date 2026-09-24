import { readFile } from 'node:fs/promises';

const reportPath = process.argv[2];
if (!reportPath) throw new Error('Usage: node check-zap-report.mjs <zap-report.json>');

// ZAP cannot infer WatchTower's strict Origin/Referer/Sec-Fetch-Site mutation
// checks, and the current branded auth pages intentionally use inline CSS.
// Keep both visible in the report while preventing known false positives from
// hiding new Medium or High alerts.
const accepted = new Map([
  ['10202', 'Mutations require validated same-origin browser headers'],
  ['10055', 'Branded authentication and acknowledgement pages use inline CSS'],
]);

const report = JSON.parse(await readFile(reportPath, 'utf8'));
const alerts = (report.site || []).flatMap(site => site.alerts || []);
const blocking = alerts.filter(alert => Number(alert.riskcode) >= 2 && !accepted.has(String(alert.pluginid)));

for (const alert of alerts.filter(item => Number(item.riskcode) >= 2)) {
  const exception = accepted.get(String(alert.pluginid));
  console.log(`${exception ? 'ACCEPTED' : 'BLOCKING'}: ${alert.name} [${alert.pluginid}]${exception ? ` - ${exception}` : ''}`);
}

if (blocking.length) {
  console.error(`ZAP found ${blocking.length} unaccepted Medium or High alert(s).`);
  process.exit(1);
}

console.log('ZAP found no unaccepted Medium or High alerts.');
