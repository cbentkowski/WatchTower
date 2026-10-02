import { createHash } from 'node:crypto';
import { osvPackage } from './osv.mjs';

const matchKey = finding => JSON.stringify([finding.package.purl, finding.package.location, finding.package.imageId]);
export async function assessApplicationInventory(app, store, client, kev, { now = new Date(), maxAgeDays = 30 } = {}) {
  let loaded;
  try { loaded = await store.loadActive(app.id); }
  catch (error) { return { configured: true, state: 'incomplete', reasons: [`Package inventory unavailable: ${error.message}`], findings: [], inventories: [] }; }
  const enabled = loaded.images.filter(image => image.enabled && !image.retired);
  const configured = Boolean(loaded.inventories.length || enabled.length || app.assessmentMode === 'inventory');
  if (!configured) return { configured: false, state: 'not-configured', reasons: [], findings: [], inventories: [] };
  const missing = enabled.filter(image => !loaded.inventories.some(inventory => inventory.scope.imageId === image.id));
  const reasons = missing.map(image => `Image ${image.label || image.reference}: awaiting usable SBOM`);
  const findings = [], inventories = [];
  for (const inventory of loaded.inventories) {
    const ageBasis = inventory.generatedAt || inventory.importedAt;
    const age = now.getTime() - Date.parse(ageBasis);
    const stale = !Number.isFinite(age) || age < -86400000 || age > maxAgeDays * 86400000;
    let assessment;
    try { assessment = await client.assess(inventory, kev); }
    catch (error) {
      const unsupported = inventory.components.filter(component => osvPackage(component).reason).map(component => ({ componentRef: component.componentRef, reason: osvPackage(component).reason }));
      assessment = { checkedAt: now.toISOString(), state: 'incomplete', findings: [], errors: [{ message: error.message }], unsupported, assessedComponentCount: 0, supportedComponentCount: inventory.components.length - unsupported.length, unsupportedComponentCount: unsupported.length };
    }
    if (stale) { assessment.state = 'incomplete'; for (const finding of assessment.findings) finding.evidenceState = 'inventory-stale'; reasons.push(`Inventory ${inventory.id}: stale or invalid generation/import time`); }
    if (assessment.state !== 'assessed') {
      reasons.push(`Inventory ${inventory.id}: package assessment incomplete (${assessment.unsupportedComponentCount} unsupported/incomplete components; ${assessment.errors.length} source errors)`);
      const previous = inventory.previousAssessment;
      for (const old of previous?.findings || []) if (!assessment.findings.some(current => matchKey(current) === matchKey(old) && current.aliases.some(alias => old.aliases.includes(alias)))) assessment.findings.push({ ...old, evidenceState: 'unverified' });
      assessment.lastSuccessfulLookup ||= previous?.lastSuccessfulLookup || null;
    }
    const saved = await store.recordAssessment(app.id, inventory.id, assessment);
    if (!saved) { assessment.state = 'incomplete'; reasons.push('Inventory changed during package assessment; refresh again'); }
    findings.push(...assessment.findings);
    const { findings: scopedFindings, ...summary } = assessment;
    inventories.push({ revisionId: inventory.id, imageId: inventory.scope.imageId, componentCount: inventory.componentCount, generatedAt: inventory.generatedAt, importedAt: inventory.importedAt, ageBasis: inventory.generatedAt ? 'generation' : 'import', stale, ...summary });
  }
  if (!loaded.inventories.length) reasons.push('Package inventory awaiting assessment: no usable SBOM imported');
  return { configured, state: inventories.length && !missing.length && inventories.every(inventory => inventory.state === 'assessed') ? 'assessed' : 'incomplete', reasons, findings, inventories };
}

// Alias/source identifiers and URLs may grow without resetting responses. Only
// substantive package applicability, severity and exploitation evidence reopen.
export function packageEvidenceFingerprint(finding) {
  const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
  const ranges = [...new Set((finding.sourceRecords || []).flatMap(record => (record.affected || []).map(affected => JSON.stringify(canonical({ ranges: affected.ranges || [], versions: affected.versions || [] })))))].sort();
  const severity = [...new Set((finding.sourceRecords || []).flatMap(record => (record.severity || []).map(item => JSON.stringify(canonical(item)))))].sort();
  return createHash('sha256').update(JSON.stringify({ ranges, severity, label: finding.severity, knownExploited: finding.knownExploited })).digest('hex');
}
