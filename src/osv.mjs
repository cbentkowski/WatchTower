import { PackageURL } from 'packageurl-js';

const ecosystems = Object.freeze({ npm: 'npm', pypi: 'PyPI', maven: 'Maven', golang: 'Go', cargo: 'crates.io', gem: 'RubyGems', composer: 'Packagist', nuget: 'NuGet', hex: 'Hex', pub: 'Pub' });
export const osvLimits = Object.freeze({ batch: 100, pages: 10, requests: 200, advisories: 1000, findings: 10000, bytes: 2 * 1024 * 1024, timeoutMs: 15000, assessmentMs: 60000, cacheEntries: 500, cacheMs: 6 * 60 * 60 * 1000 });
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const text = value => typeof value === 'string' ? value.slice(0, 16000) : '';
const safeLink = value => { try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.href : ''; } catch { return ''; } };

export function osvPackage(component) {
  if (['file', 'operating-system', 'container'].includes(component.componentType)) return { ignored: true, reason: 'non-package-inventory-entry' };
  if (component.identityIssue || !component.purl) return { reason: component.identityIssue || 'missing-purl' };
  try {
    const parsed = PackageURL.fromString(component.purl);
    if (!parsed.version || component.version !== parsed.version) return { reason: 'missing-or-conflicting-version' };
    if (!ecosystems[parsed.type]) return { reason: 'unsupported-ecosystem', ecosystem: parsed.type };
    if (Object.keys(parsed.qualifiers || {}).length) return { reason: 'unsupported-qualifiers', ecosystem: parsed.type };
    if (parsed.type === 'maven' && !parsed.namespace) return { reason: 'incomplete-maven-identity' };
    const name = parsed.type === 'maven' ? `${parsed.namespace}:${parsed.name}` : [parsed.namespace, parsed.name].filter(Boolean).join('/');
    // Subpaths describe occurrences; the full original PURL stays in evidence.
    const queryPurl = new PackageURL(parsed.type, parsed.namespace, parsed.name, parsed.version).toString();
    return { queryPurl, name, ecosystem: ecosystems[parsed.type], parsed };
  } catch { return { reason: 'invalid-purl' }; }
}

function boundedRecord(data) {
  const queue = [[data, 0]];
  let count = 0;
  while (queue.length) {
    const [value, depth] = queue.pop();
    if (++count > 100000 || depth > 24 || typeof value === 'string' && value.length > 16000) throw new Error('OSV record processing limit exceeded');
    if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
      if (['__proto__', 'constructor', 'prototype'].includes(key)) throw new Error('Unsafe OSV property');
      queue.push([child, depth + 1]);
    }
  }
  return data;
}

function affectedPackage(record, identity) {
  return (record.affected || []).filter(affected => {
    const pkg = affected.package || {};
    if (pkg.purl) try {
      const parsed = PackageURL.fromString(pkg.purl);
      return parsed.type === identity.parsed.type && parsed.namespace === identity.parsed.namespace && parsed.name === identity.parsed.name;
    } catch { return false; }
    return pkg.ecosystem === identity.ecosystem && pkg.name === identity.name;
  });
}

export function packageFinding(record, component, scope, inventory, identity, lookedUpAt, kev = new Set()) {
  if (!idPattern.test(record.id || '') || !Array.isArray(record.affected) || !Array.isArray(record.aliases || []) || (record.aliases || []).some(alias => !idPattern.test(alias))) throw new Error('Invalid OSV advisory');
  const affected = affectedPackage(record, identity);
  if (!affected.length) throw new Error('OSV advisory does not identify the queried package');
  const aliases = [...new Set([record.id, ...(record.aliases || [])].filter(value => idPattern.test(value)))];
  if (aliases.length > 100) throw new Error('OSV alias limit exceeded');
  const suppliedSeverity = [record.database_specific?.severity, ...affected.map(item => item.database_specific?.severity || item.ecosystem_specific?.severity)].map(value => String(value || '').toUpperCase());
  const label = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].find(level => suppliedSeverity.includes(level)) || 'UNKNOWN';
  const sourceRecords = { id: record.id, aliases, modified: text(record.modified), published: text(record.published), severity: record.severity || [], affected, references: (record.references || []).map(ref => ({ type: text(ref.type), url: safeLink(ref.url) })).filter(ref => ref.url) };
  const incoming = inventory.dependencies.filter(edge => edge.to === component.componentRef);
  return { advisoryId: record.id, aliases, score: null, label, severity: label, severityEvidence: record.severity || [], knownExploited: aliases.some(alias => kev.has(alias.toUpperCase())),
    description: text(record.summary || record.details), url: `https://osv.dev/vulnerability/${encodeURIComponent(record.id)}`, advisories: sourceRecords.references.map(ref => ref.url).slice(0, 10),
    published: text(record.published), source: 'OSV', package: { purl: component.purl, version: component.version, location: component.location || '', imageId: scope.imageId, name: component.name, componentRef: component.componentRef, revisionId: inventory.id, dependencyRelationships: incoming },
    inventoryScope: scope, lookedUpAt, sourceRecords: [sourceRecords], fixedVersions: [...new Set(affected.flatMap(item => (item.ranges || []).filter(range => range.type !== 'GIT').flatMap(range => (range.events || []).map(event => event.fixed).filter(Boolean))))], evidenceState: 'current' };
}

export function correlatePackageFindings(findings) {
  const groups = [];
  for (const finding of findings) {
    const same = previous => previous.package.purl === finding.package.purl && previous.package.location === finding.package.location && previous.package.imageId === finding.package.imageId;
    const matched = groups.filter(previous => same(previous) && previous.aliases.some(alias => finding.aliases.includes(alias)));
    if (!matched.length) { groups.push(finding); continue; }
    const target = matched[0];
    for (const other of [...matched.slice(1), finding]) {
      target.aliases = [...new Set([...target.aliases, ...other.aliases])];
      if (target.aliases.length > 100) throw new Error('Correlated advisory alias limit exceeded');
      target.sourceRecords = [...new Map([...target.sourceRecords, ...other.sourceRecords].map(record => [record.id, record])).values()];
      target.fixedVersions = [...new Set([...target.fixedVersions, ...other.fixedVersions])];
      target.advisories = [...new Set([...target.advisories, ...other.advisories])];
      target.knownExploited ||= other.knownExploited;
      target.package.dependencyRelationships = [...new Map([...target.package.dependencyRelationships, ...other.package.dependencyRelationships].map(edge => [JSON.stringify(edge), edge])).values()];
      target.package.componentRefs = [...new Set([...(target.package.componentRefs || [target.package.componentRef]), ...(other.package.componentRefs || [other.package.componentRef])])];
      const rank = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      if (rank.indexOf(other.severity) > rank.indexOf(target.severity)) target.label = target.severity = other.severity;
      if (other !== finding) groups.splice(groups.indexOf(other), 1);
    }
  }
  return groups;
}

export function createOsvClient({ fetchImpl = (...args) => fetch(...args), now = () => Date.now(), pause = delay } = {}) {
  const cache = new Map();
  let lastRequest = 0;
  let requestChain = Promise.resolve();
  async function request(route, body, budget) {
    for (let attempt = 0; attempt < 3; attempt++) {
      if (++budget.requests > osvLimits.requests) throw new Error('OSV request budget exceeded');
      const remaining = budget.deadline - now();
      if (remaining <= 0) throw new Error('OSV assessment time budget exceeded');
      const permit = requestChain.then(async () => { await pause(Math.max(0, 100 - (now() - lastRequest))); lastRequest = now(); });
      requestChain = permit.catch(() => {});
      await permit;
      const response = await fetchImpl(`https://api.osv.dev/v1/${route}`, { method: body ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, redirect: 'error', signal: AbortSignal.timeout(Math.min(osvLimits.timeoutMs, remaining)) });
      if ([429, 500, 502, 503, 504].includes(response.status) && attempt < 2) {
        const retry = response.headers.get('retry-after');
        const seconds = retry ? Number.isFinite(Number(retry)) ? Number(retry) : (Date.parse(retry) - now()) / 1000 : attempt + 1;
        await response.body?.cancel();
        if (seconds > 2) throw new Error('OSV requested a longer retry delay; retry next assessment');
        await pause(Math.max(100, seconds * 1000 || 1000)); continue;
      }
      if (!response.ok) { await response.body?.cancel(); throw new Error(`OSV HTTP ${response.status}`); }
      if (Number(response.headers.get('content-length')) > osvLimits.bytes) { await response.body?.cancel(); throw new Error('OSV response size limit exceeded'); }
      const reader = response.body?.getReader();
      if (!reader) throw new Error('OSV returned no response body');
      const chunks = []; let bytes = 0;
      try {
        while (true) {
          const part = await reader.read(); if (part.done) break;
          bytes += part.value.length;
          if (bytes > osvLimits.bytes) throw new Error('OSV response size limit exceeded');
          chunks.push(part.value);
        }
      } catch (error) { await reader.cancel(); throw error; }
      return boundedRecord(JSON.parse(Buffer.concat(chunks).toString('utf8')));
    }
  }
  return {
    async assess(inventory, kev = new Set(), { onEvent = () => {} } = {}) {
      const checkedAt = new Date(now()).toISOString();
      const budget = { requests: 0, deadline: now() + osvLimits.assessmentMs };
      const errors = [], unsupported = [], ignored = [], findings = [];
      const packages = new Map();
      for (const component of inventory.components) {
        const identity = osvPackage(component);
        if (identity.ignored) { ignored.push({ componentRef: component.componentRef, name: component.name, componentType: component.componentType, reason: identity.reason }); continue; }
        if (identity.reason) { unsupported.push({ componentRef: component.componentRef, name: component.name, purl: component.purl, ecosystem: identity.ecosystem || component.ecosystem || '', reason: identity.reason }); continue; }
        if (!packages.has(identity.queryPurl)) packages.set(identity.queryPurl, { identity, components: [], advisoryIds: new Map(), complete: false, findingCount: 0 });
        packages.get(identity.queryPurl).components.push(component);
      }
      const entries = [...packages.values()];
      for (let start = 0; start < entries.length; start += osvLimits.batch) {
        const batch = entries.slice(start, start + osvLimits.batch);
        let pending = batch.map(entry => ({ entry, token: '', seen: new Set() }));
        try {
          for (let page = 0; pending.length; page++) {
            if (page >= osvLimits.pages) throw new Error('OSV pagination limit exceeded');
            const response = await request('querybatch', { queries: pending.map(item => ({ package: { purl: item.entry.identity.queryPurl }, ...(item.token ? { page_token: item.token } : {}) })) }, budget);
            if (!Array.isArray(response.results) || response.results.length !== pending.length) throw new Error('OSV batch result count mismatch');
            const next = [];
            response.results.forEach((result, index) => {
              const item = pending[index];
              if (!result || typeof result !== 'object' || Array.isArray(result) || Object.keys(result).some(key => !['vulns', 'next_page_token'].includes(key)) || Object.hasOwn(result, 'vulns') && !Array.isArray(result.vulns)) throw new Error('Invalid OSV batch result');
              for (const vuln of result.vulns || []) {
                if (!idPattern.test(vuln.id || '') || vuln.modified !== undefined && typeof vuln.modified !== 'string' || item.entry.advisoryIds.size >= osvLimits.advisories) throw new Error('Invalid or excessive OSV advisory IDs');
                item.entry.advisoryIds.set(vuln.id, vuln.modified || '');
              }
              if (result.next_page_token) {
                if (typeof result.next_page_token !== 'string' || result.next_page_token.length > 4096 || item.seen.has(result.next_page_token)) throw new Error('Invalid or repeated OSV page token');
                item.seen.add(result.next_page_token); next.push({ ...item, token: result.next_page_token });
              } else item.entry.complete = true;
            });
            pending = next;
          }
        } catch (error) { for (const item of pending) { item.entry.complete = false; errors.push({ purl: item.entry.identity.queryPurl, message: error.message }); } }
      }
      const details = new Map();
      for (const entry of entries) for (const [id, modified] of entry.advisoryIds) {
        if (details.size >= osvLimits.advisories && !details.has(id)) { entry.complete = false; errors.push({ purl: entry.identity.queryPurl, message: 'OSV advisory limit exceeded' }); break; }
        if (details.has(id)) continue;
        try {
          const cached = cache.get(id);
          const record = cached && cached.modified === modified && now() - cached.time < osvLimits.cacheMs ? cached.record : await request(`vulns/${encodeURIComponent(id)}`, null, budget);
          if (record.id !== id) throw new Error('OSV advisory ID mismatch');
          details.set(id, { record });
          cache.delete(id); cache.set(id, { record, modified, time: cached && cached.record === record ? cached.time : now() });
          if (cache.size > osvLimits.cacheEntries) cache.delete(cache.keys().next().value);
        } catch (error) { details.set(id, { error: error.message }); }
      }
      build: for (const entry of entries) for (const id of entry.advisoryIds.keys()) {
        const detail = details.get(id);
        if (!detail || detail.error) { entry.complete = false; errors.push({ purl: entry.identity.queryPurl, message: detail?.error || 'OSV advisory retrieval incomplete' }); continue; }
        if (detail.record.withdrawn) continue;
        for (const component of entry.components) {
          const locations = component.locations?.length ? component.locations : [component.location || ''];
          for (const location of locations) try {
            if (findings.length >= osvLimits.findings) { for (const remaining of entries) remaining.complete = false; errors.push({ message: 'OSV finding count limit exceeded' }); break build; }
            findings.push(packageFinding(detail.record, { ...component, location }, inventory.scope, inventory, entry.identity, checkedAt, kev));
            entry.findingCount++;
          }
          catch (error) { entry.complete = false; errors.push({ purl: entry.identity.queryPurl, message: error.message }); }
        }
      }
      const correlatedFindings = correlatePackageFindings(findings);
      const countsByPurl = new Map();
      for (const finding of correlatedFindings) countsByPurl.set(finding.package.purl, (countsByPurl.get(finding.package.purl) || 0) + 1);
      for (const entry of entries) entry.findingCount = [...new Set(entry.components.map(component => component.purl))].reduce((count, purl) => count + (countsByPurl.get(purl) || 0), 0);
      const lookups = entries.map(entry => ({ purl: entry.identity.queryPurl, ecosystem: entry.identity.ecosystem, name: entry.identity.name, componentCount: entry.components.length, state: entry.complete ? entry.findingCount ? 'findings' : 'no-known-matches' : 'incomplete', findingCount: entry.findingCount }));
      for (const lookup of lookups) await onEvent(lookup.state === 'incomplete' ? 'warn' : 'info', 'SBOM package lookup', `${lookup.purl}: ${lookup.state}; ${lookup.findingCount} finding occurrence(s); ${lookup.componentCount} inventory occurrence(s)`);
      return { checkedAt, ignoredComponentCount: ignored.length, ignored, lookups, packageComponentCount: inventory.components.length - ignored.length, typeMetadataMissing: inventory.components.some(component => !component.componentType), lastSuccessfulLookup: entries.some(entry => entry.complete) ? checkedAt : null, supportedComponentCount: entries.reduce((sum, entry) => sum + entry.components.length, 0), assessedComponentCount: entries.filter(entry => entry.complete).reduce((sum, entry) => sum + entry.components.length, 0), unsupportedComponentCount: unsupported.length, unsupported, errors,
        state: entries.length && entries.every(entry => entry.complete) && !unsupported.length ? 'assessed' : 'incomplete', findings: correlatedFindings };
    },
  };
}
