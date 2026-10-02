import { randomUUID } from 'node:crypto';
import { PackageURL } from 'packageurl-js';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function inventoryScope(applicationId, imageId = null) {
  if (!uuid.test(applicationId) || (imageId !== null && !uuid.test(imageId))) throw new Error('Inventory scope requires immutable UUIDs');
  return { applicationId, imageId };
}

// Deliberately require an explicit registry and tag/digest; never assume latest.
export function canonicalImageReference(value) {
  if (typeof value !== 'string' || value.length > 2048 || /[\s?#]/.test(value)) throw new Error('Invalid OCI reference');
  const match = value.match(/^([a-zA-Z0-9.-]+(?::[0-9]+)?)\/([a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*)(?::([A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?(?:@(sha256:[a-fA-F0-9]{64}))?$/);
  if (!match || (!match[3] && !match[4])) throw new Error('OCI reference requires registry, repository, and tag or SHA-256 digest');
  const registry = match[1].toLowerCase();
  const [host, port] = registry.split(':');
  if ((!host.includes('.') && host !== 'localhost' && !port) || host.split('.').some(part => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part)) || (port && (+port < 1 || +port > 65535))) throw new Error('Invalid OCI registry');
  return `${host}${port ? `:${Number(port)}` : ''}/${match[2]}${match[3] ? `:${match[3]}` : ''}${match[4] ? `@${match[4].toLowerCase()}` : ''}`;
}

export function reconcileImages(input, previous = []) {
  if (!Array.isArray(input) || input.length > 100) throw new Error('At most 100 image entries are allowed');
  const ids = new Set(), references = new Set();
  const images = input.map(entry => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error('Image details are required');
    const old = previous.find(image => image.id === entry.id);
    if (entry.id && !old) throw new Error('Image IDs are managed by WatchTower');
    const id = old?.id || randomUUID();
    if (!uuid.test(id)) throw new Error('Invalid persisted image UUID');
    const reference = canonicalImageReference(entry.reference);
    if (ids.has(id) || references.has(reference)) throw new Error('Duplicate image ID or reference');
    ids.add(id); references.add(reference);
    const label = entry.label ?? '';
    if (typeof label !== 'string' || label.length > 120 || /[\r\n]/.test(label)) throw new Error('Invalid image label');
    for (const field of ['enabled', 'retired']) if (entry[field] !== undefined && typeof entry[field] !== 'boolean') throw new Error(`Invalid image ${field}`);
    if (old?.retired && !entry.retired) throw new Error('Retired images cannot be reactivated');
    return { ...old, id, reference, label, enabled: entry.retired ? false : entry.enabled !== false, retired: entry.retired === true };
  });
  if (previous.some(image => !ids.has(image.id))) throw new Error('Retire image entries instead of deleting them');
  return images;
}

export function packageIdentity(input) {
  if (typeof input.purl !== 'string' || input.purl.length > 4096) throw new Error('A bounded PURL is required');
  const parsed = PackageURL.fromString(input.purl);
  if (!parsed.version) throw new Error('Package identity requires an installed version');
  if (input.version !== undefined && input.version !== parsed.version) throw new Error('Package version disagrees with PURL');
  const location = input.location ?? '';
  if (typeof location !== 'string' || location.length > 4096 || /[\x00-\x1f]/.test(location)) throw new Error('Invalid package location');
  return { purl: parsed.toString(), location };
}

// A revision is provenance, never a package or finding identity. Importers supply
// normalized components; raw SBOM parsing and replacement belong to the next slice.
export function createInventoryRevision(scope, metadata, now = new Date()) {
  inventoryScope(scope.applicationId, scope.imageId);
  if (!/^[a-f0-9]{64}$/.test(metadata.checksum || '')) throw new Error('Inventory checksum must be SHA-256');
  return { id: randomUUID(), scope: { ...scope }, importedAt: now.toISOString(), checksum: metadata.checksum };
}
