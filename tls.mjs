import { readFile } from 'node:fs/promises';

function enabled(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized || normalized === 'false') return false;
  if (normalized === 'true') return true;
  throw new Error('TLS_ENABLED must be true or false');
}

export async function loadTlsConfiguration(env = process.env, loader = readFile) {
  if (!enabled(env.TLS_ENABLED)) return { enabled: false, protocol: 'http', options: null };
  const certFile = String(env.TLS_CERT_FILE || '').trim();
  const keyFile = String(env.TLS_KEY_FILE || '').trim();
  if (!certFile || !keyFile) throw new Error('TLS_CERT_FILE and TLS_KEY_FILE are required when TLS_ENABLED is true');

  let cert;
  let key;
  try { [cert, key] = await Promise.all([loader(certFile), loader(keyFile)]); }
  catch (error) { throw new Error(`Could not read native TLS certificate files: ${error.code || 'read failed'}`); }
  if (!cert?.length || !key?.length) throw new Error('Native TLS certificate files must not be empty');
  return { enabled: true, protocol: 'https', options: { cert, key, minVersion: 'TLSv1.2' } };
}
