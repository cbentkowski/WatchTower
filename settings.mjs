import { readFile, writeFile, rename } from 'node:fs/promises';

const defaults = { enabled: false, host: '', port: '', secure: false, requireTls: false, unauthenticated: false, from: '', timeZone: 'UTC', sendHour: 8, usernameEnv: '', passwordEnv: '' };
const keys = new Set(Object.keys(defaults));
const scalar = value => {
  const trimmed = value.trim();
  if (trimmed.startsWith('"')) return JSON.parse(trimmed);
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  return trimmed;
};

export function validateSmtpSettings(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('SMTP settings are required');
  const settings = { ...defaults };
  for (const key of keys) if (input[key] != null) settings[key] = input[key];
  for (const key of ['host', 'from', 'timeZone', 'usernameEnv', 'passwordEnv']) settings[key] = String(settings[key]).trim();
  settings.port = settings.port === '' ? '' : Number(settings.port);
  settings.sendHour = settings.sendHour === '' ? '' : Number(settings.sendHour);
  if (settings.port !== '' && (!Number.isInteger(settings.port) || settings.port < 1 || settings.port > 65535)) throw new Error('SMTP port must be between 1 and 65535');
  if (settings.sendHour !== '' && (!Number.isInteger(settings.sendHour) || settings.sendHour < 0 || settings.sendHour > 23)) throw new Error('Send hour must be 0–23');
  for (const key of ['enabled', 'secure', 'requireTls', 'unauthenticated']) if (typeof settings[key] !== 'boolean') throw new Error(`${key} must be true or false`);
  if (settings.secure && settings.requireTls) throw new Error('Choose either SSL/TLS or STARTTLS');
  if (settings.enabled) {
    if (!settings.timeZone) settings.timeZone = 'UTC';
    if (settings.sendHour === '') settings.sendHour = 8;
    if (!settings.host || !settings.port || !settings.from) throw new Error('SMTP host, port, and From address are required when email is enabled');
    if (!settings.secure && !settings.requireTls) throw new Error('Choose SSL/TLS or STARTTLS when email is enabled');
    if (!settings.unauthenticated && (!settings.usernameEnv || !settings.passwordEnv)) throw new Error('Username and password environment variable names are required when authentication is enabled');
  }
  for (const key of ['usernameEnv', 'passwordEnv']) if (settings[key] && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(settings[key])) throw new Error(`${key} must be an environment variable name`);
  if (settings.from && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(settings.from)) throw new Error('Sender must be an email address');
  if (settings.timeZone) try { new Intl.DateTimeFormat('en-US', { timeZone: settings.timeZone }); } catch { throw new Error('Invalid time zone'); }
  if (/\s|[\/\\]/.test(settings.host)) throw new Error('SMTP host must be a hostname or IP address');
  return settings;
}

export async function readSmtpSettings(file) {
  let source;
  try { source = await readFile(file, 'utf8'); } catch (error) { if (error.code === 'ENOENT') return { ...defaults }; throw error; }
  const parsed = {};
  for (const line of source.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#') || line.trim() === 'smtp:') continue;
    const match = line.match(/^  ([A-Za-z][A-Za-z0-9]*):\s*(.*)$/);
    if (match?.[1] === 'baseUrl') continue; // Accept older files until Settings rewrites them.
    if (!match || !keys.has(match[1])) throw new Error(`Unsupported smtp.yaml line: ${line}`);
    parsed[match[1]] = scalar(match[2]);
  }
  return validateSmtpSettings(parsed);
}

export async function writeSmtpSettings(file, input) {
  const settings = validateSmtpSettings(input);
  const contents = `# Credentials are read from environment variables named below; never place their values here.\nsmtp:\n${Object.entries(settings).map(([key, value]) => `  ${key}: ${typeof value === 'string' ? JSON.stringify(value) : value}\n`).join('')}`;
  const temporary = `${file}.tmp`;
  await writeFile(temporary, contents, 'utf8');
  await rename(temporary, file);
  return settings;
}
