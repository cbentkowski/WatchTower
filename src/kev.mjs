export const kevFeedUrl = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const kevCatalogUrl = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
const cvePattern = /^CVE-\d{4}-\d{4,19}$/;
const text = value => typeof value === 'string' ? value.slice(0, 4096) : '';
const date = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value + 'T00:00:00Z')) && new Date(value + 'T00:00:00Z').toISOString().slice(0, 10) === value ? value : '';

export function normalizeKevCatalog(data, checkedAt = new Date().toISOString()) {
  if (!Array.isArray(data?.vulnerabilities) || data.vulnerabilities.length > 50000) throw new Error('Invalid CISA KEV catalog');
  if (data.count !== undefined && data.count !== data.vulnerabilities.length) throw new Error('Incomplete CISA KEV catalog');
  const records = data.vulnerabilities.map(item => {
    const cveID = text(item?.cveID).toUpperCase();
    if (!cvePattern.test(cveID)) throw new Error('Invalid CISA KEV CVE identifier');
    return { cveID, dateAdded: date(item.dateAdded), dueDate: date(item.dueDate), requiredAction: text(item.requiredAction) };
  });
  if (new Set(records.map(item => item.cveID)).size !== records.length) throw new Error('Duplicate CISA KEV CVE identifier');
  return { records, checkedAt, catalogDate: text(data.dateReleased), catalogVersion: text(data.catalogVersion) };
}

export function kevIndex(catalog, state = 'current', attemptedAt = new Date().toISOString()) {
  const index = new Set((catalog?.records || []).map(item => item.cveID));
  return Object.assign(index, { catalog, state, attemptedAt });
}

export function enrichKevFindings(findings, index, previousFindings = []) {
  const records = new Map((index.catalog?.records || []).map(item => [item.cveID, item]));
  const identifiers = finding => [...new Set([finding.id, finding.advisoryId, ...(finding.aliases || [])].filter(value => typeof value === 'string').map(value => value.toUpperCase()).filter(value => cvePattern.test(value)))];
  const keys = finding => [finding.id, finding.advisoryId, ...identifiers(finding)].filter(Boolean).map(id => `${finding.package ? 'package:' + (finding.package.imageId || '') + ':' + finding.package.purl : 'product'}:${id}`);
  const previousByKey = new Map();
  for (const previous of previousFindings) for (const key of keys(previous)) previousByKey.set(key, previous);
  for (const finding of findings) {
    const ids = identifiers(finding);
    const matches = ids.filter(id => records.has(id)).map(id => records.get(id));
    const previous = keys(finding).map(key => previousByKey.get(key)).find(Boolean);
    const retained = index.state !== 'current' && previous?.knownExploited;
    finding.knownExploited = matches.length > 0 || Boolean(retained);
    finding.kev = {
      state: index.state, lastAttemptAt: index.attemptedAt,
      lastSuccessfulCheckAt: index.catalog?.checkedAt || previous?.kev?.lastSuccessfulCheckAt || '',
      catalogDate: index.catalog?.catalogDate || previous?.kev?.catalogDate || '',
      catalogVersion: index.catalog?.catalogVersion || previous?.kev?.catalogVersion || '',
      entries: matches.length ? matches : retained ? previous.kev?.entries || [] : [], sourceUrl: kevCatalogUrl,
    };
  }
}
