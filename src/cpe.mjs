const componentNames = ['part', 'vendor', 'product', 'version', 'update', 'edition', 'language', 'swEdition', 'targetSw', 'targetHw', 'other'];
const componentPattern = /^(?:\*|-|(?:\\.|[A-Za-z0-9._~%-])+)?$/;

function splitComponents(value) {
  const components = [];
  let current = '';
  let escaped = false;
  for (const character of value) {
    if (escaped) { current += `\\${character}`; escaped = false; continue; }
    if (character === '\\') { escaped = true; continue; }
    if (character === ':') { components.push(current); current = ''; continue; }
    current += character;
  }
  if (escaped) throw new Error('CPE cannot end with an incomplete escape');
  components.push(current);
  return components;
}

export function parseCpe23(value) {
  const raw = String(value ?? '').trim();
  if (!raw.startsWith('cpe:2.3:')) throw new Error('Enter a CPE 2.3 name beginning with cpe:2.3:');
  const fields = splitComponents(raw);
  if (fields.length !== 13 || fields[0] !== 'cpe' || fields[1] !== '2.3') throw new Error('A CPE 2.3 name must contain all 11 components');
  const parsed = Object.fromEntries(componentNames.map((name, index) => [name, fields[index + 2]]));
  if (!['a', 'o', 'h'].includes(parsed.part)) throw new Error('CPE part must be a, o, or h');
  for (const [name, component] of Object.entries(parsed)) if (!componentPattern.test(component)) throw new Error(`CPE ${name} contains unsupported characters`);
  if (['', '*', '-'].includes(parsed.vendor) || ['', '*', '-'].includes(parsed.product)) throw new Error('CPE vendor and product must be specific values');
  return { cpeName: raw, ...parsed };
}

export function productCpe(mapping) {
  const parsed = typeof mapping === 'string' ? parseCpe23(mapping) : mapping;
  return `cpe:2.3:${parsed.part}:${parsed.vendor}:${parsed.product}:*:*:*:*:*:*:*:*`;
}

export function effectiveCpe(mapping, mode = 'product') {
  const parsed = typeof mapping === 'string' ? parseCpe23(mapping) : mapping;
  return mode === 'exact' ? parsed.cpeName : productCpe(parsed);
}

export function legacyCpe(app) {
  return `cpe:2.3:a:${app.cpeVendor}:${app.cpeProduct}:*:*:${app.cpeEdition || '*'}:*:*:*:*:*`;
}

export function mappingFromApp(app) {
  const parsed = parseCpe23(app.cpeName || legacyCpe(app));
  const mode = app.cpeMode === 'exact' || (!app.cpeMode && app.cpeEdition) ? 'exact' : 'product';
  return { ...parsed, mode, title: app.cpeTitle || '', deprecated: app.cpeDeprecated === true || app.cpeDeprecated === 'true' };
}

export function mappingWarnings(mapping, installedVersion = '') {
  const parsed = typeof mapping === 'string' ? parseCpe23(mapping) : mapping;
  const mode = mapping.mode === 'exact' ? 'exact' : 'product';
  const warnings = [];
  if (mapping.deprecated) warnings.push({ code: 'deprecated', level: 'danger', message: 'This CPE is deprecated. Select its replacement when one is available.' });
  if (mode === 'product') warnings.push({ code: 'product-wildcard', level: 'info', message: 'Product mode ignores the CPE version and evaluates the installed version against NVD affected ranges.' });
  if (mode === 'exact' && ['*', '-'].includes(parsed.version)) warnings.push({ code: 'broad-exact', level: 'warning', message: 'Exact mode still contains a wildcard or not-applicable version and may be broader than expected.' });
  if (mode === 'exact' && installedVersion && !['*', '-', installedVersion].includes(parsed.version)) warnings.push({ code: 'version-conflict', level: 'danger', message: `The exact CPE version (${parsed.version}) differs from the installed version (${installedVersion}).` });
  const qualified = ['update', 'edition', 'language', 'swEdition', 'targetSw', 'targetHw', 'other'].filter(name => !['*', '-', ''].includes(parsed[name]));
  if (mode === 'product' && qualified.length) warnings.push({ code: 'qualifiers-ignored', level: 'warning', message: `Product mode ignores these exact qualifiers: ${qualified.join(', ')}.` });
  return warnings;
}

export function cpeSearchMatch(item, filters) {
  const contains = (value, query) => !query || String(value || '').toLowerCase().includes(String(query).toLowerCase());
  const anyText = [item.title, item.cpeName, ...componentNames.map(name => item[name])].join(' ');
  return contains(anyText, filters.any) && componentNames.every(name => contains(item[name], filters[name]));
}
