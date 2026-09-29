import { readFile } from 'node:fs/promises';

const [type, reportPath] = process.argv.slice(2);
if (!type || !reportPath) {
  throw new Error('Usage: node summarize-security-report.mjs <type> <report.json>');
}

const limit = 20;
const clean = value => String(value ?? '').replace(/[\r\n]+/g, ' ').trim();

let report;
try {
  report = JSON.parse(await readFile(reportPath, 'utf8'));
} catch (error) {
  console.log(`No readable ${type} JSON report was produced: ${clean(error.message)}`);
  process.exit(0);
}

let findings = [];
switch (type) {
  case 'npm-audit':
    findings = Object.entries(report.vulnerabilities || {}).map(([name, item]) => {
      const advisory = (item.via || []).find(value => typeof value === 'object');
      return `${clean(item.severity).toUpperCase()} ${clean(name)}: ${clean(advisory?.title || 'vulnerable dependency')} (${clean(advisory?.url || 'no advisory URL')})`;
    });
    break;
  case 'gitleaks':
    findings = (Array.isArray(report) ? report : []).map(item =>
      `${clean(item.RuleID || item.Description || 'finding')} at ${clean(item.File)}:${clean(item.StartLine || '?')} (commit ${clean(item.Commit || 'unknown').slice(0, 12)})`,
    );
    break;
  case 'semgrep':
    findings = (report.results || []).map(item =>
      `${clean(item.check_id)} at ${clean(item.path)}:${clean(item.start?.line || '?')}`,
    );
    break;
  case 'hadolint':
    findings = (Array.isArray(report) ? report : []).map(item =>
      `${clean(item.code)} at ${clean(item.file)}:${clean(item.line || '?')}`,
    );
    break;
  case 'trivy':
    findings = (report.Results || []).flatMap(result => (result.Vulnerabilities || []).map(item =>
      `${clean(item.Severity)} ${clean(item.VulnerabilityID)} in ${clean(item.PkgName)} ${clean(item.InstalledVersion)} (fixed: ${clean(item.FixedVersion || 'none')})`,
    ));
    break;
  case 'grype':
    findings = (report.matches || []).map(item =>
      `${clean(item.vulnerability?.severity)} ${clean(item.vulnerability?.id)} in ${clean(item.artifact?.name)} ${clean(item.artifact?.version)} (fixed: ${clean(item.vulnerability?.fix?.versions?.join(', ') || 'none')})`,
    );
    break;
  case 'dockle': {
    const details = report.details || report.Details || report;
    findings = (Array.isArray(details) ? details : []).map(item =>
      `${clean(item.level || item.Level || 'WARN')} ${clean(item.code || item.Code)}`,
    );
    break;
  }
  default:
    throw new Error(`Unsupported security report type: ${type}`);
}

console.log(`${type} produced ${findings.length} finding(s). Showing up to ${limit} sanitized summaries:`);
for (const finding of findings.slice(0, limit)) console.log(`- ${finding}`);
if (findings.length > limit) console.log(`- ... ${findings.length - limit} additional finding(s) omitted`);
