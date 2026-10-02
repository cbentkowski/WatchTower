import { randomUUID } from 'node:crypto';
import { inventoryScope, packageIdentity } from './inventory.mjs';

function advisoryIds(input) {
  if (!Array.isArray(input.aliases ?? [])) throw new Error('Invalid advisory identifiers');
  const values = [input.advisoryId, ...(input.aliases || [])];
  if (values.length > 100 || values.some(value => typeof value !== 'string' || !value || value.length > 200 || /[\s\x00-\x1f]/.test(value))) throw new Error('Invalid advisory identifiers');
  return [...new Set(values.map(value => /^(CVE-|GHSA-)/i.test(value) ? value.toUpperCase() : value))].sort();
}

// Return ambiguity rather than merging independent workflow records. Callers
// must surface it and keep existing records intact until an explicit resolution.
export function reconcilePackageFinding(store, input) {
  const scope = inventoryScope(input.applicationId, input.imageId ?? null);
  const component = packageIdentity(input);
  const aliases = advisoryIds(input);
  const records = store.packageFindings || [];
  const sameComponent = record => record.applicationId === scope.applicationId && record.imageId === scope.imageId && record.purl === component.purl && record.location === component.location;
  const matches = records.filter(record => sameComponent(record) && record.aliases.some(alias => aliases.includes(alias)));
  if (matches.length > 1) return { status: 'ambiguous', findingIds: matches.map(record => record.id) };
  let record = matches[0];
  let changed = false;
  if (!record) {
    record = { id: randomUUID(), ...scope, ...component, aliases };
    records.push(record);
    store.packageFindings = records;
    changed = true;
  } else {
    const merged = [...new Set([...record.aliases, ...aliases])].sort();
    changed = merged.length !== record.aliases.length;
    record.aliases = merged;
  }
  return { status: 'matched', findingId: record.id, changed };
}
