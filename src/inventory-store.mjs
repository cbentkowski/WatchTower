import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import path from 'node:path';
import { inventoryScope, reconcileImages, createInventoryRevision } from './inventory.mjs';
import { selectInventoryImage } from './sbom.mjs';
import { processSbom } from './sbom-processing.mjs';

const pending = new Map();
const queued = new Map();
export function createInventoryStore(directory) {
  const folder = applicationId => { inventoryScope(applicationId); return path.join(directory, applicationId); };
  const read = async applicationId => {
    try { return JSON.parse(await readFile(path.join(folder(applicationId), 'state.json'), 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') return { version: 1, images: [], revisions: [] }; throw error; }
  };
  async function atomic(file, data) {
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(`${file}.tmp`, JSON.stringify(data), { mode: 0o600 });
    await rename(`${file}.tmp`, file);
  }
  function update(applicationId, operation) {
    const key = folder(applicationId);
    if ((queued.get(key) || 0) >= 10) return Promise.reject(new Error('Application inventory queue is busy; retry later'));
    queued.set(key, (queued.get(key) || 0) + 1);
    const task = (pending.get(key) || Promise.resolve()).catch(() => {}).then(async () => {
      const state = await read(applicationId);
      const result = await operation(state);
      await atomic(path.join(key, 'state.json'), state);
      return result;
    });
    pending.set(key, task);
    return task.finally(() => {
      const remaining = queued.get(key) - 1;
      if (remaining) queued.set(key, remaining); else queued.delete(key);
      if (pending.get(key) === task) pending.delete(key);
    });
  }
  return {
    read,
    setImages: (applicationId, images) => update(applicationId, state => { state.images = reconcileImages(images, state.images); return state; }),
    import: (applicationId, raw, selection, actor) => update(applicationId, async state => {
      const inventory = await processSbom(raw);
      const imageId = selectInventoryImage(inventory, state.images, selection);
      const revision = { ...inventory, ...createInventoryRevision(inventoryScope(applicationId, imageId), inventory), uploader: actor };
      await atomic(path.join(folder(applicationId), `${revision.id}.json`), revision);
      const { components, dependencies, supplierEvidence, ...metadata } = revision;
      for (const old of state.revisions) if (old.scope.imageId === imageId && old.active) old.active = false;
      state.revisions.push({ ...metadata, active: true });
      return { ...metadata, active: true };
    }),
  };
}
