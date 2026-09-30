import { randomUUID } from 'node:crypto';
import { readFile, rename, writeFile } from 'node:fs/promises';

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const scalar = value => {
  const raw = value.trim();
  if (raw.startsWith('"')) { try { return JSON.parse(raw); } catch { throw new Error('Invalid quoted owner YAML value'); } }
  return raw.replace(/\s+#.*$/, '').replace(/^'(.*)'$/, '$1');
};
const yamlValue = value => JSON.stringify(String(value));

export function parseOwners(source) {
  const owners = [];
  let current = null;
  for (const line of source.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#') || line.trim() === 'owners:') continue;
    const entry = line.match(/^  - id:\s*(.*)$/);
    const field = line.match(/^    (name|email|escalationEmail|primaryContact|escalationContact):\s*(.*)$/);
    if (entry) { current = { id: scalar(entry[1]) }; owners.push(current); }
    else if (field && current) current[field[1]] = scalar(field[2]);
    else throw new Error(`Unsupported owner YAML line: ${line}`);
  }
  const normalized = owners.map(owner => validateOwner({ ...owner, email: owner.email || owner.primaryContact, escalationEmail: owner.escalationEmail || owner.escalationContact }, owner.id));
  if (new Set(normalized.map(owner => owner.id)).size !== normalized.length) throw new Error('Owner IDs must be unique');
  if (new Set(normalized.map(owner => owner.email.toLowerCase())).size !== normalized.length) throw new Error('Owner email addresses must be unique');
  return normalized;
}

export function validateOwner(input, existingId = '') {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Owner details are required');
  const owner = {
    id: existingId || randomUUID(),
    name: String(input.name || '').trim(),
    email: String(input.email || input.primaryContact || '').trim(),
    escalationEmail: String(input.escalationEmail || input.escalationContact || '').trim(),
  };
  if (!uuidPattern.test(owner.id)) throw new Error('Owner ID must be an immutable UUID');
  if (!owner.name) throw new Error('Owner name is required');
  if (!owner.email) throw new Error('Owner email is required');
  for (const value of [owner.email, owner.escalationEmail].filter(Boolean)) if (!/^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(value)) throw new Error('Enter a valid owner email address');
  for (const [field, value] of Object.entries(owner)) {
    if (/\r|\n/.test(value)) throw new Error(`${field} must be one line`);
    if (value.length > (field === 'name' ? 120 : 240)) throw new Error(`${field} is too long`);
  }
  return owner;
}

export function serializeOwners(owners) {
  return `# Owners are reusable contacts assigned to applications and workspaces by immutable ID.\nowners:\n${owners.map(owner => `  - id: ${owner.id}\n    name: ${yamlValue(owner.name)}\n    email: ${yamlValue(owner.email)}\n${owner.escalationEmail ? `    escalationEmail: ${yamlValue(owner.escalationEmail)}\n` : ''}`).join('')}`;
}

export async function readOwners(file) {
  try { return parseOwners(await readFile(file, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
}

export async function writeOwners(file, owners) {
  const temporary = `${file}.tmp`;
  await writeFile(temporary, serializeOwners(owners));
  await rename(temporary, file);
  return owners;
}
