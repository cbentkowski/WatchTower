import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { validateGeneralSettings, readGeneralSettings, writeGeneralSettings } from '../src/general.mjs';

test('SBOM upload limits default, validate and persist independently of the public address', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'watchtower-general-'));
  const file = path.join(directory, 'general.yaml');
  try {
    assert.equal((await readGeneralSettings(file)).sbomUploadLimitMiB, 35);
    await writeFile(file, 'general:\n  protocol: "https"\n  host: "example.com"\n  port: 443\n');
    assert.equal((await readGeneralSettings(file)).sbomUploadLimitMiB, 35);
    for (const limit of [0, 101, 1.5, '', 'invalid', true]) {
      assert.throws(() => validateGeneralSettings({ sbomUploadLimitMiB: limit }), /whole number/);
    }
    for (const limit of [1, 35, 100]) {
      await writeGeneralSettings(file, { sbomUploadLimitMiB: limit });
      const settings = await readGeneralSettings(file);
      assert.equal(settings.sbomUploadLimitMiB, limit);
      assert.equal(settings.host, '');
    }
    await writeGeneralSettings(file, { protocol: 'https', host: 'example.com', port: 443, sbomUploadLimitMiB: 50 });
    assert.equal((await readGeneralSettings(file)).sbomUploadLimitMiB, 50);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
