import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { PackageURL } from 'packageurl-js';
import { canonicalImageReference } from './inventory.mjs';

const contexts = new Map([['3.0', '3.0'], ['3.0.0', '3.0'], ['3.0.1', '3.0.1']].map(([context, version]) => [`https://spdx.org/rdf/${context}/spdx-context.jsonld`, version]));
const schemas = Object.fromEntries(await Promise.all(['3.0', '3.0.1'].map(async version => [version, JSON.parse(await readFile(new URL(`./schemas/spdx-${version}.json`, import.meta.url), 'utf8'))])));
const validators = new Map();
const text = value => typeof value === 'string' ? value.slice(0, 8192) : '';
const id = value => typeof value === 'string' ? value : value?.spdxId || value?.['@id'] || '';

export function spdx3Version(document) {
  if (!document || (!Object.hasOwn(document, '@context') && !Object.hasOwn(document, '@graph'))) return null;
  const context = document['@context'];
  if (!contexts.has(context)) throw new Error('Unsupported SPDX JSON-LD context. Use the official SPDX 3.0 or 3.0.1 compact JSON-LD context. Remote contexts are not fetched.');
  return contexts.get(context);
}

function validateDocument(document, version) {
  if (!validators.has(version)) {
    const ajv = new Ajv2020({ strict: false, allErrors: false, inlineRefs: false });
    addFormats(ajv);
    validators.set(version, ajv.compile(schemas[version]));
  }
  const validate = validators.get(version);
  // Accept the legacy 3.0 context alias using the complete official 3.0.0 schema.
  // The bundled schema and the original input document remain unchanged.
  const input = { ...document, '@context': schemas[version].properties['@context'].const };
  if (!validate(input)) throw new Error(`Invalid SPDX ${version} JSON-LD: ${validate.errors?.[0]?.instancePath || '/'} ${validate.errors?.[0]?.message || ''}`);
}

export function normalizeSpdx3(document, raw, version, normalizeComponent) {
  validateDocument(document, version);
  const graph = document['@graph'] || [document];
  const objects = [], definitions = new Map();
  const pending = [...graph];
  while (pending.length) {
    const item = pending.pop();
    if (!item || typeof item !== 'object') continue;
    if (!Array.isArray(item) && item.type) {
      objects.push(item);
      const key = id(item);
      if (key) {
        if (definitions.has(key)) throw new Error(`Duplicate SPDX element identifier: ${key}`);
        definitions.set(key, item);
      }
    }
    for (const value of Object.values(item)) if (value && typeof value === 'object') pending.push(...(Array.isArray(value) ? value : [value]));
  }
  const resolve = value => typeof value === 'string' ? definitions.get(value) : value;
  const documents = objects.filter(item => item.type === 'SpdxDocument');
  if (documents.length > 1) throw new Error('SPDX JSON-LD must not contain multiple SpdxDocument elements');
  for (const item of objects) {
    if (item.type === 'CreationInfo' && !['3.0.0', '3.0.1'].includes(item.specVersion)) throw new Error('Unsupported SPDX creation-info specification version');
    if (item.creationInfo && resolve(item.creationInfo)?.type !== 'CreationInfo') throw new Error(`Unresolved SPDX creation information for ${id(item) || item.type}`);
  }
  const packages = objects.filter(item => ['software_Package', 'ai_AIPackage', 'dataset_DatasetPackage'].includes(item.type));
  if (packages.length > 10000) throw new Error('SBOM component count limit exceeded');
  const relationships = objects.filter(item => item.from && Array.isArray(item.to) && item.relationshipType);
  const licenseText = value => {
    const license = resolve(value);
    return text(license?.simplelicensing_licenseExpression || license?.name || id(value));
  };
  const components = packages.map((pkg, index) => {
    const identifiers = (pkg.externalIdentifier || []).map(resolve).filter(Boolean);
    const purls = [...new Set([pkg.software_packageUrl, ...identifiers.filter(ref => ref.externalIdentifierType === 'packageUrl').map(ref => ref.identifier)].filter(Boolean))];
    const refs = purls.map(referenceLocator => ({ referenceType: 'purl', referenceLocator }));
    refs.push(...identifiers.filter(ref => ['cpe22', 'cpe23'].includes(ref.externalIdentifierType)).map(ref => ({ referenceType: ref.externalIdentifierType === 'cpe23' ? 'cpe23Type' : 'cpe22Type', referenceLocator: ref.identifier })));
    const supplier = resolve(pkg.suppliedBy);
    const component = normalizeComponent({ SPDXID: pkg.spdxId, name: pkg.name, versionInfo: pkg.software_packageVersion, supplier: supplier?.name || id(pkg.suppliedBy), externalRefs: refs,
      checksums: (pkg.verifiedUsing || []).map(resolve).filter(value => value?.type === 'Hash').map(value => ({ algorithm: value.algorithm, checksumValue: value.hashValue })) }, 'SPDX', index);
    component.componentType = 'library';
    component.licenses = relationships.filter(rel => id(rel.from) === pkg.spdxId && ['hasDeclaredLicense', 'hasConcludedLicense'].includes(rel.relationshipType)).flatMap(rel => rel.to.map(licenseText));
    if (purls.length > 1) { component.purl = ''; component.identityIssue = 'conflicting-purls'; component.identityState = 'incomplete'; }
    return component;
  });
  const dependencies = relationships.flatMap(rel => rel.to.map(target => ({ from: id(rel.from), to: id(target), relationship: rel.relationshipType.replace(/[A-Z]/g, char => `_${char}`).toUpperCase() })));
  const supplierEvidence = objects.filter(item => item.type.startsWith('security_') || ['affects', 'doesNotAffect', 'fixedIn', 'hasAssessmentFor', 'underInvestigationFor'].includes(item.relationshipType)).map(item => ({ ...item, attribution: 'supplier', trustedForAssessment: false }));
  const root = documents[0];
  const info = resolve(root?.creationInfo) || objects.find(item => item.type === 'CreationInfo');
  const reportedImages = [];
  const roots = new Set(objects.filter(item => ['SpdxDocument', 'software_Sbom'].includes(item.type)).flatMap(item => (item.rootElement || []).map(id)));
  for (const rel of relationships) if (rel.relationshipType === 'describes') for (const target of rel.to) roots.add(id(target));
  for (const component of components.filter(item => roots.has(item.componentRef))) try {
    const parsed = PackageURL.fromString(component.purl);
    if (parsed.type === 'oci' && parsed.qualifiers?.repository_url && /^sha256:[a-f0-9]{64}$/i.test(parsed.version || '')) reportedImages.push(canonicalImageReference(`${parsed.qualifiers.repository_url}@${parsed.version}`));
  } catch { /* Unresolved identities remain incomplete evidence. */ }
  return { format: 'SPDX', specificationVersion: version, documentIdentity: text(root?.spdxId), documentVersion: null,
    generator: (info?.createdUsing || []).map(value => text(resolve(value)?.name || id(value))), generatedAt: text(info?.created), checksum: createHash('sha256').update(raw).digest('hex'),
    components, dependencies, supplierEvidence, reportedImages: [...new Set(reportedImages)], componentCount: components.length,
    incompleteComponentCount: components.filter(component => component.identityIssue).length, assessmentState: 'awaiting-assessment' };
}
