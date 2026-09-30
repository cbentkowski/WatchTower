const clean = value => String(value ?? '').trim().toLowerCase();
const words = value => clean(value).replace(/[^a-z0-9]+/g, ' ').split(/\s+/).filter(Boolean);

export function normalizeLifecycleProduct(product) {
  return {
    name: String(product?.name || ''),
    label: String(product?.label || product?.name || ''),
    aliases: Array.isArray(product?.aliases) ? product.aliases.map(String) : [],
    category: String(product?.category || ''),
    tags: Array.isArray(product?.tags) ? product.tags.map(String) : [],
    identifiers: Array.isArray(product?.identifiers) ? product.identifiers.map(item => ({ type: String(item.type || ''), id: String(item.id || '') })) : [],
    links: product?.links && typeof product.links === 'object' ? product.links : {},
    releases: Array.isArray(product?.releases) ? product.releases.map(normalizeLifecycleRelease) : [],
  };
}

export function normalizeLifecycleRelease(release) {
  return {
    cycle: String(release?.name || ''),
    label: String(release?.label || release?.name || ''),
    releaseDate: release?.releaseDate || null,
    latest: release?.latest?.name || null,
    latestDate: release?.latest?.date || null,
    latestLink: release?.latest?.link || null,
    lts: release?.isLts === true || release?.ltsFrom || false,
    eol: release?.isEol === false ? false : release?.eolFrom || (release?.isEol === true ? true : false),
    maintained: release?.isMaintained === true,
  };
}

export function matchLifecycleRelease(releases, version) {
  const value = clean(version);
  if (!value) return null;
  return [...releases]
    .filter(item => {
      const cycle = clean(item.cycle);
      const latest = clean(item.latest);
      return value === cycle || value.startsWith(`${cycle}.`) || latest && value === latest;
    })
    .sort((a, b) => String(b.cycle).length - String(a.cycle).length)[0] || null;
}

export function searchLifecycleProducts(products, { query = '', vendor = '', cpe = '', category = '' } = {}) {
  const queryWords = words(query);
  const hintWords = [...new Set([...words(vendor), ...words(cpe).slice(2)])];
  return products.map(normalizeLifecycleProduct).filter(item => !category || item.category === category).map(item => {
    const primary = clean(`${item.label} ${item.name} ${item.aliases.join(' ')}`);
    const all = clean(`${primary} ${item.category} ${item.tags.join(' ')}`);
    if (queryWords.length && !queryWords.every(word => all.includes(word))) return null;
    let score = queryWords.reduce((total, word) => total + (clean(item.name) === word ? 100 : clean(item.aliases).includes(word) ? 60 : primary.includes(word) ? 30 : 10), 0);
    score += hintWords.reduce((total, word) => total + (clean(item.name) === word ? 80 : clean(item.aliases).includes(word) ? 45 : all.includes(word) ? 8 : 0), 0);
    return { ...item, score };
  }).filter(Boolean).sort((a, b) => b.score - a.score || a.label.localeCompare(b.label));
}
