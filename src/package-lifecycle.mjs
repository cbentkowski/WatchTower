import { PackageURL } from 'packageurl-js';

const family = purl => {
  try { const parsed = PackageURL.fromString(purl); return new PackageURL(parsed.type, parsed.namespace, parsed.name, null, parsed.qualifiers, parsed.subpath).toString(); }
  catch { return null; }
};
const occurrenceKey = (purl, location) => JSON.stringify([purl, location || '']);

// Absence is evidence only in a fresh, complete, committed assessment or an
// explicitly retired image. Other gaps retain the prior finding as unverified.
export function reconcilePackageLifecycle(store, applications, workflow, actor, at) {
  const events = []; let changed = false;
  for (const application of applications) {
    const context = application.inventoryLifecycle || (application.packageAssessment?.configured && application.packageAssessment.state === 'incomplete' ? { images: [], inventories: [] } : null);
    if (!context) continue;
    const currentIds = new Set(application.vulnerabilities.flatMap(finding => [finding.id, ...(finding.identity?.findingIds || [])]));
    const scopes = new Map(context.inventories.map(inventory => {
      const exact = new Set(), families = new Set();
      for (const component of inventory.components) {
        if (!component.purl) continue;
        const packageFamily = family(component.purl);
        for (const location of component.locations?.length ? component.locations : [component.location || '']) {
          exact.add(occurrenceKey(component.purl, location));
          if (packageFamily) families.add(occurrenceKey(packageFamily, location));
        }
      }
      return [inventory.imageId, { ...inventory, exact, families }];
    }));
    for (const record of Object.values(store.records)) {
      const previous = record.packageEvidence;
      if (record.applicationId !== application.id || !previous || currentIds.has(record.findingId)) continue;
      const scope = scopes.get(previous.package.imageId);
      const retired = context.images.find(image => image.id === previous.package.imageId && image.retired);
      let reason = '';
      if (retired) reason = 'image-retired';
      else if (scope?.complete) {
        const same = scope.exact.has(occurrenceKey(previous.package.purl, previous.package.location));
        if (same) reason = 'no-longer-reported';
        else if (scope.revisionId !== previous.package.revisionId) {
          const changedVersion = scope.families.has(occurrenceKey(family(previous.package.purl), previous.package.location));
          reason = changedVersion ? 'version-changed' : 'package-removed';
        }
      }
      if (reason && !record.inventoryResolution) {
        const from = record.state;
        record.state = 'resolved'; record.riskExpiration = '';
        record.updatedAt = at; record.updatedBy = actor;
        record.inventoryResolution = { reason, at, previousRevisionId: previous.package.revisionId, revisionId: scope?.revisionId || null, imageId: previous.package.imageId, image: retired?.reference || null, retiredAt: retired?.retiredAt || null, retiredBy: retired?.retiredBy || null };
        events.push({ at, type: 'finding-inventory-resolved', applicationId: application.id, findingId: record.findingId, actor, from, to: 'resolved', reason, inventory: record.inventoryResolution });
        changed = true;
      }
      if (!reason && !record.inventoryResolution) {
        application.vulnerabilities.push({ ...structuredClone(previous), evidenceState: 'unverified', workflow: workflow(record) });
        if (application.status !== 'red') application.status = ['HIGH', 'CRITICAL'].includes(previous.severity) || previous.knownExploited || previous.score >= 7 ? 'red' : 'unknown';
        const warning = 'Previously reported package finding retained as unverified: current inventory evidence is incomplete';
        if (!application.reasons.includes(warning)) application.reasons.push(warning);
      }
    }
    application.resolvedPackageFindings = Object.values(store.records).filter(record => record.applicationId === application.id && record.packageEvidence && record.inventoryResolution).map(record => ({ ...structuredClone(record.packageEvidence), workflow: workflow(record), resolution: record.inventoryResolution }));
  }
  return { changed, events };
}
