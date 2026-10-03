import { readFile, writeFile, rename } from 'node:fs/promises';

export function validateGeneralSettings(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('General settings are required');
  if (input.sbomUploadLimitMiB != null && !['number', 'string'].includes(typeof input.sbomUploadLimitMiB)) throw new Error('SBOM upload limit must be a whole number from 1 to 100 MiB');
  const sbomUploadLimitMiB = Number(input.sbomUploadLimitMiB ?? 35);
  if (!Number.isInteger(sbomUploadLimitMiB) || sbomUploadLimitMiB < 1 || sbomUploadLimitMiB > 100) throw new Error('SBOM upload limit must be a whole number from 1 to 100 MiB');
  const protocol = String(input.protocol ?? '').trim().toLowerCase();
  const host = String(input.host ?? '').trim();
  const port = input.port === '' || input.port == null ? '' : Number(input.port);
  if (!protocol && !host && port === '') return { protocol: '', host: '', port: '', sbomUploadLimitMiB };
  if (!['http', 'https'].includes(protocol)) throw new Error('Protocol must be HTTP or HTTPS');
  if (!host || /[\s/@?#:]/.test(host)) throw new Error('Enter a hostname without a scheme or port');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Web port must be between 1 and 65535');
  return { protocol, host, port, sbomUploadLimitMiB };
}

export async function readGeneralSettings(file) {
  let source;
  try { source = await readFile(file, 'utf8'); } catch (error) { if (error.code === 'ENOENT') return validateGeneralSettings({}); throw error; }
  const parsed = {};
  for (const line of source.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#') || line.trim() === 'general:') continue;
    const match = line.match(/^  (protocol|host|port|sbomUploadLimitMiB):\s*(.*)$/);
    if (!match) throw new Error(`Unsupported general.yaml line: ${line}`);
    parsed[match[1]] = match[2].trim().startsWith('"') ? JSON.parse(match[2].trim()) : match[2].trim();
  }
  return validateGeneralSettings(parsed);
}

export async function writeGeneralSettings(file, input) {
  const settings = validateGeneralSettings(input);
  const contents = `# Public address used in email links.\ngeneral:\n  protocol: ${JSON.stringify(settings.protocol)}\n  host: ${JSON.stringify(settings.host)}\n  port: ${settings.port}\n  sbomUploadLimitMiB: ${settings.sbomUploadLimitMiB}\n`;
  await writeFile(`${file}.tmp`, contents, 'utf8');
  await rename(`${file}.tmp`, file);
  return settings;
}

export function generalUrl(settings) {
  if (!settings.host) return '';
  const url = new URL(`${settings.protocol}://${settings.host}`);
  url.port = String(settings.port);
  return url.origin;
}
