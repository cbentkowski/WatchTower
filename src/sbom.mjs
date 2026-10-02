import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { PackageURL } from 'packageurl-js';
import { canonicalImageReference } from './inventory.mjs';

export const sbomLimits = Object.freeze({ bytes: 5 * 1024 * 1024, components: 10000, depth: 32, nodes: 200000, text: 8192 });
async function schemaValidator(primary, dependencies = []) {
  const ajv = new Ajv({ strict: false, allErrors: false, validateFormats: true });
  addFormats(ajv);
  ajv.addFormat('iri-reference', value => { try { return !/[\s\x00-\x1f]/.test(value) && Boolean(new URL(value || '.', 'https://sbom.invalid/')); } catch { return false; } });
  ajv.addFormat('idn-email', /^[^\s@]+@[^\s@]+\.[^\s@]+$/u);
  const schemas = await Promise.all([primary, ...dependencies].map(async name => JSON.parse(await readFile(new URL(`./schemas/${name}.json`, import.meta.url), 'utf8'))));
  for (const schema of schemas) ajv.addSchema(schema);
  return ajv.getSchema(schemas[0].$id);
}
// Supporting schema IDs are shared upstream; keep each version's vocabulary isolated.
const [spdxValidator, cdx16Validator, cdx17Validator] = await Promise.all([
  schemaValidator('spdx-2.3'),
  schemaValidator('cyclonedx-1.6', ['cyclonedx-spdx', 'cyclonedx-jsf']),
  schemaValidator('cyclonedx-1.7', ['cyclonedx-1.7-spdx', 'cyclonedx-1.7-jsf', 'cyclonedx-cryptography'])
]);
const validators = { SPDX: spdxValidator, '1.6': cdx16Validator, '1.7': cdx17Validator };
const text = value => typeof value === 'string' ? value.slice(0, sbomLimits.text) : '';

function boundDocument(document) {
  const pending = [[document, 0]];
  let nodes = 0;
  while (pending.length) {
    const [value, depth] = pending.pop();
    if (++nodes > sbomLimits.nodes || depth > sbomLimits.depth) throw new Error('SBOM processing limit exceeded');
    if (typeof value === 'string' && value.length > sbomLimits.text) throw new Error('SBOM text limit exceeded');
    if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
      if (['__proto__', 'prototype', 'constructor'].includes(key)) throw new Error('Unsafe SBOM property');
      pending.push([child, depth + 1]);
    }
  }
}

function normalizedComponent(component, format, index) {
  const spdx = format === 'SPDX';
  const refs = component.externalRefs || [];
  const rawPurl = spdx ? refs.find(ref => ref.referenceType === 'purl')?.referenceLocator : component.purl;
  let purl = '', ecosystem = '', version = text(spdx ? component.versionInfo : component.version), issue = 'missing-purl';
  if (rawPurl && rawPurl.length > 4096) issue = 'purl-too-long';
  else if (rawPurl) try {
    const parsed = PackageURL.fromString(rawPurl);
    if (version && parsed.version && version !== parsed.version) issue = 'version-mismatch';
    else if (!parsed.version) issue = 'missing-purl-version';
    else { purl = parsed.toString(); ecosystem = parsed.type; version = parsed.version; issue = ''; }
  } catch { issue = 'invalid-purl'; }
  const cpes = spdx ? refs.filter(ref => ['cpe23Type', 'cpe22Type'].includes(ref.referenceType)).map(ref => text(ref.referenceLocator)) : component.cpe ? [text(component.cpe)] : [];
  const locations = spdx ? [] : [...new Set((component.evidence?.occurrences || []).map(occurrence => text(occurrence.location)).filter(Boolean))];
  return { componentRef: text(spdx ? component.SPDXID : component['bom-ref']) || `component-${index}`, name: text(component.name), version, purl, declaredPurl: text(rawPurl), ecosystem, identityIssue: issue, cpes,
    supplier: text(spdx ? component.supplier : component.supplier?.name), hashes: spdx ? (component.checksums || []).map(hash => ({ algorithm: text(hash.algorithm), value: text(hash.checksumValue) })) : (component.hashes || []).map(hash => ({ algorithm: text(hash.alg), value: text(hash.content) })),
    licenses: spdx ? [component.licenseConcluded, component.licenseDeclared].filter(Boolean).map(text) : (component.licenses || []).map(license => text(license.expression || license.license?.id || license.license?.name)),
    locations, location: locations.length === 1 ? locations[0] : '', packageFileName: text(component.packageFileName), identityState: issue ? 'incomplete' : 'awaiting-source-support' };
}

export function normalizeSbom(raw) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > sbomLimits.bytes) throw new Error('SBOM exceeds upload size limit');
  let document;
  try { document = JSON.parse(raw); } catch { throw new Error('SBOM must be uncompressed JSON'); }
  boundDocument(document);
  const format = document?.spdxVersion === 'SPDX-2.3' ? 'SPDX' : document?.bomFormat === 'CycloneDX' && ['1.6', '1.7'].includes(document.specVersion) ? 'CycloneDX' : null;
  if (!format) throw new Error('Supported SBOM versions: SPDX JSON 2.3 and CycloneDX JSON 1.6 or 1.7');
  const components = [];
  const pending = [...(format === 'SPDX' ? document.packages || [] : document.components || [])];
  // Include the described root application/container when supplied.
  if (format === 'CycloneDX' && document.metadata?.component) pending.unshift(document.metadata.component);
  while (pending.length) {
    const component = pending.pop();
    if (components.length >= sbomLimits.components) throw new Error('SBOM component count limit exceeded');
    components.push(normalizedComponent(component, format, components.length));
    if (format === 'CycloneDX') pending.push(...(component.components || []));
  }
  const componentRefs = components.map(component => component.componentRef);
  if (new Set(componentRefs).size !== componentRefs.length) throw new Error('Duplicate SBOM component references');
  const validate = validators[format === 'SPDX' ? 'SPDX' : document.specVersion];
  if (!validate(document)) throw new Error(`Invalid ${format} ${document.specVersion || '2.3'} SBOM: ${validate.errors?.[0]?.instancePath || '/'} ${validate.errors?.[0]?.message || ''}`);
  const dependencies = format === 'SPDX' ? (document.relationships || []).map(item => ({ from: text(item.spdxElementId), to: text(item.relatedSpdxElement), relationship: text(item.relationshipType) })) : (document.dependencies || []).flatMap(item => (item.dependsOn || []).map(to => ({ from: text(item.ref), to: text(to), relationship: 'DEPENDS_ON' })));
  const supplierEvidence = format === 'CycloneDX' ? (document.vulnerabilities || []).map(item => ({ id: text(item.id), source: { name: text(item.source?.name), url: text(item.source?.url) }, affects: (item.affects || []).map(affect => ({ ref: text(affect.ref), versions: affect.versions || [] })), analysis: item.analysis || null, attribution: 'supplier', trustedForAssessment: false })) : [];
  const root = document.metadata?.component;
  const reportedImages = [];
  if (root?.type === 'container' && root.name) try { reportedImages.push(canonicalImageReference(root.name)); } catch { /* Plain labels do not establish an image reference. */ }
  for (const property of root?.properties || []) if (property.name === 'oci:image:reference') reportedImages.push(canonicalImageReference(property.value));
  const described = format === 'SPDX' ? (document.packages || []).filter(pkg => (document.documentDescribes || []).includes(pkg.SPDXID) || (document.relationships || []).some(rel => rel.relationshipType === 'DESCRIBES' && rel.spdxElementId === document.SPDXID && rel.relatedSpdxElement === pkg.SPDXID)).flatMap(pkg => (pkg.externalRefs || []).filter(ref => ref.referenceType === 'purl').map(ref => ref.referenceLocator)) : root?.purl ? [root.purl] : [];
  for (const value of described) try {
    const purl = PackageURL.fromString(value);
    if (purl.type === 'oci' && purl.qualifiers?.repository_url && /^sha256:[a-f0-9]{64}$/i.test(purl.version || '')) reportedImages.push(canonicalImageReference(`${purl.qualifiers.repository_url}@${purl.version}`));
  } catch { /* Unsupported PURLs remain incomplete component evidence. */ }
  return { format, specificationVersion: format === 'SPDX' ? '2.3' : '1.6', documentIdentity: text(document.documentNamespace || document.serialNumber), documentVersion: document.version ?? null,
    generator: format === 'SPDX' ? (document.creationInfo.creators || []).map(text) : [...(document.metadata?.tools?.components || []), ...(Array.isArray(document.metadata?.tools) ? document.metadata.tools : [])].map(tool => text([tool.vendor, tool.name, tool.version].filter(Boolean).join(' '))),
    generatedAt: text(format === 'SPDX' ? document.creationInfo.created : document.metadata?.timestamp), checksum: createHash('sha256').update(raw).digest('hex'), components, dependencies, supplierEvidence, reportedImages: [...new Set(reportedImages)],
    componentCount: components.length, incompleteComponentCount: components.filter(component => component.identityIssue).length, assessmentState: 'awaiting-assessment' };
}

export function selectInventoryImage(inventory, images, selection) {
  const active = images.filter(image => image.enabled && !image.retired);
  const matches = inventory.reportedImages.length ? active.filter(image => inventory.reportedImages.every(ref => ref === image.reference || ref.includes('@') && image.reference.split('@')[1] === ref.split('@')[1])) : [];
  if (selection === undefined) {
    if (matches.length !== 1) throw new Error('Select an image or explicitly select application-level inventory');
    return matches[0].id;
  }
  if (selection === null) {
    if (inventory.reportedImages.length) throw new Error('Reported image metadata requires an image scope');
    return null;
  }
  const selected = active.find(image => image.id === selection);
  if (!selected) throw new Error('Selected image is unavailable');
  if (inventory.reportedImages.length && !matches.some(image => image.id === selection)) throw new Error('SBOM image metadata does not match the configured image');
  return selected.id;
}
