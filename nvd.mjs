import { mappingFromApp, productCpe } from './cpe.mjs';

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

function same(value, expected) { return value === '*' || value === expected; }

export function cpeMatchAffectsVersion(match, app) {
  if (!match?.vulnerable) return false;
  let criteria;
  try { criteria = mappingFromApp({ cpeName: match.criteria }); } catch { return false; }
  const selected = mappingFromApp(app);
  if (!same(criteria.part, selected.part) || !same(criteria.vendor, selected.vendor) || !same(criteria.product, selected.product)) return false;
  if (selected.mode === 'exact') {
    for (const name of ['update', 'edition', 'language', 'swEdition', 'targetSw', 'targetHw', 'other']) {
      if (!['*', '-'].includes(selected[name]) && !same(criteria[name], selected[name])) return false;
    }
  }
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
  const selected = mappingFromApp(app);
  return selected.mode === 'exact' ? selected.cpeName : productCpe(selected);
}
