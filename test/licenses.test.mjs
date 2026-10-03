import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';

test('offline license catalog preserves shipped notices and every production dependency license', async () => {
  execFileSync(process.execPath, ['.github/scripts/generate-licenses.mjs', '--check']);
  const catalog = JSON.parse(await readFile('src/licenses.json', 'utf8'));
  assert.equal(catalog.notice, (await readFile('NOTICE', 'utf8')).replace(/\r\n/g, '\n'));
  assert.equal(catalog.entries.find(item => item.name === 'SPDX schemas 3.0 and 3.0.1').text, (await readFile('src/schemas/LICENSE-SPDX-3', 'utf8')).replace(/\r\n/g, '\n'));
  assert.ok(catalog.entries.every(item => item.text.length > 500 && item.source.startsWith('https://')));
  const docker = await readFile('Dockerfile', 'utf8');
  assert.match(docker, /COPY LICENSE NOTICE \/opt\/watchtower\//);
});
