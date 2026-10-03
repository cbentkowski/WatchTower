import { readFile, writeFile } from 'node:fs/promises';

const root = new URL('../../', import.meta.url);
const read = async file => (await readFile(new URL(file, root), 'utf8')).replace(/\r\n/g, '\n');
const lock = JSON.parse(await read('package-lock.json'));
const packageFiles = {
  ajv: 'LICENSE', 'ajv-formats': 'LICENSE', 'fast-deep-equal': 'LICENSE', 'fast-uri': 'LICENSE',
  jose: 'LICENSE.md', 'json-schema-traverse': 'LICENSE', nodemailer: 'LICENSE',
  oauth4webapi: 'LICENSE.md', 'openid-client': 'LICENSE.md', 'packageurl-js': 'LICENSE', 'require-from-string': 'license',
};
const entries = [];
for (const [name, license, source, file] of [
  ['WatchTower', 'Apache-2.0', 'https://github.com/cbentkowski/WatchTower', 'LICENSE'],
  ['SPDX schemas 2.2 and 2.3', 'CC-BY-3.0', 'https://github.com/spdx/spdx-spec', 'src/schemas/LICENSE-SPDX'],
  ['SPDX schemas 3.0 and 3.0.1', 'Community-Spec-1.0 and pre-existing material notices', 'https://github.com/spdx/spdx-spec/tree/3.0.1', 'src/schemas/LICENSE-SPDX-3'],
  ['CycloneDX schemas 1.4–1.7', 'Apache-2.0', 'https://github.com/CycloneDX/specification', 'src/schemas/LICENSE-CycloneDX'],
]) entries.push({ name, license, source, text: await read(file) });
for (const [location, item] of Object.entries(lock.packages)) {
  if (!location || item.dev) continue;
  const name = location.replace(/^node_modules\//, '');
  if (!packageFiles[name]) throw new Error(`Catalog the bundled license for ${name}`);
  entries.push({ name, version: item.version, license: item.license, source: `https://www.npmjs.com/package/${name}/v/${item.version}`, text: await read(`${location}/${packageFiles[name]}`) });
}
const output = JSON.stringify({ notice: await read('NOTICE'), entries }, null, 2) + '\n';
if (process.argv.includes('--check')) {
  if (await read('src/licenses.json') !== output) throw new Error('License catalog is stale. Run node .github/scripts/generate-licenses.mjs');
} else await writeFile(new URL('src/licenses.json', root), output);
