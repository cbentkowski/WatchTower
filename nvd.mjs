function versionParts(value) {
  return String(value ?? '').toLowerCase().split(/[._+~-]/).map(part => /^\d+$/.test(part) ? Number(part) : part);
}

export function compareNvdVersions(left, right) {
  const a = versionParts(left);
  const b = versionParts(right);
  for (let index = 0; index < Math.max(a.length, b.length); index++) {
    const av = a[index] ?? 0;
    const bv = b[index] ?? 0;
    if (av === bv) continue;
    if (typeof av === 'number' && typeof bv === 'number') return av - bv;
    return String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: 'base' });
  }
  return 0;
}

function cpeFields(value) {
  const fields = String(value || '').split(':');
  return { part: fields[2] || '', vendor: fields[3] || '', product: fields[4] || '', version: fields[5] || '*', edition: fields[9] || '*' };
}

function same(value, expected) { return value === '*' || value === expected; }

export function cpeMatchAffectsVersion(match, app) {
  if (!match?.vulnerable) return false;
  const criteria = cpeFields(match.criteria);
  if (!same(criteria.part, 'a') || !same(criteria.vendor, app.cpeVendor) || !same(criteria.product, app.cpeProduct)) return false;
  if (app.cpeEdition && !same(criteria.edition, app.cpeEdition)) return false;
  const version = app.version;
  if (!['*', '-'].includes(criteria.version) && criteria.version !== version) return false;
  if (match.versionStartIncluding && compareNvdVersions(version, match.versionStartIncluding) < 0) return false;
  if (match.versionStartExcluding && compareNvdVersions(version, match.versionStartExcluding) <= 0) return false;
  if (match.versionEndIncluding && compareNvdVersions(version, match.versionEndIncluding) > 0) return false;
  if (match.versionEndExcluding && compareNvdVersions(version, match.versionEndExcluding) >= 0) return false;
  return true;
}

export function cveAffectsApplication(cve, app) {
  return (cve?.configurations || []).some(configuration => (configuration.nodes || []).some(node => (node.cpeMatch || []).some(match => cpeMatchAffectsVersion(match, app))));
}

export function wildcardApplicationCpe(app) {
  return `cpe:2.3:a:${app.cpeVendor}:${app.cpeProduct}:*:*:*:*:${app.cpeEdition || '*'}:*:*:*`;
}
