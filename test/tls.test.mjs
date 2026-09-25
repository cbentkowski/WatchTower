import test from 'node:test';
import assert from 'node:assert/strict';
import { loadTlsConfiguration } from '../tls.mjs';

test('native TLS is disabled by default and rejects invalid flags', async () => {
  assert.deepEqual(await loadTlsConfiguration({}), { enabled: false, protocol: 'http', options: null });
  assert.deepEqual(await loadTlsConfiguration({ TLS_ENABLED: 'false' }), { enabled: false, protocol: 'http', options: null });
  await assert.rejects(loadTlsConfiguration({ TLS_ENABLED: 'sometimes' }), /must be true or false/);
});

test('native TLS requires mounted certificate and key files', async () => {
  await assert.rejects(loadTlsConfiguration({ TLS_ENABLED: 'true' }), /TLS_CERT_FILE and TLS_KEY_FILE/);
  await assert.rejects(loadTlsConfiguration({ TLS_ENABLED: 'true', TLS_CERT_FILE: '/cert', TLS_KEY_FILE: '/key' }, async () => { const error = new Error('missing'); error.code = 'ENOENT'; throw error; }), /certificate files: ENOENT/);
  await assert.rejects(loadTlsConfiguration({ TLS_ENABLED: 'true', TLS_CERT_FILE: '/cert', TLS_KEY_FILE: '/key' }, async () => Buffer.alloc(0)), /must not be empty/);
});

test('native TLS loads secrets with TLS 1.2 as the minimum', async () => {
  const values = new Map([['/cert', Buffer.from('certificate')], ['/key', Buffer.from('private key')]]);
  const configuration = await loadTlsConfiguration({ TLS_ENABLED: 'true', TLS_CERT_FILE: '/cert', TLS_KEY_FILE: '/key' }, async file => values.get(file));
  assert.equal(configuration.enabled, true);
  assert.equal(configuration.protocol, 'https');
  assert.equal(configuration.options.minVersion, 'TLSv1.2');
  assert.equal(configuration.options.cert.toString(), 'certificate');
  assert.equal(configuration.options.key.toString(), 'private key');
});
