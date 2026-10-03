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
    loadActive: async applicationId => {
      await pending.get(folder(applicationId))?.catch(() => {});
      const state = await read(applicationId);
      const activeImages = new Set(state.images.filter(image => image.enabled && !image.retired).map(image => image.id));
      const inventories = [];
      for (const revision of state.revisions.filter(item => item.active && (item.scope.imageId === null || activeImages.has(item.scope.imageId)))) {
        inventoryScope(revision.id);
        const inventory = JSON.parse(await readFile(path.join(folder(applicationId), `${revision.id}.json`), 'utf8'));
        try { inventory.previousAssessment = JSON.parse(await readFile(path.join(folder(applicationId), `${revision.id}-assessment.json`), 'utf8')); }
        catch (error) { if (error.code !== 'ENOENT') throw error; }
        inventories.push(inventory);
      }
      return { images: state.images, inventories };
    },
    recordAssessment: (applicationId, revisionId, assessment) => update(applicationId, async state => {
      inventoryScope(revisionId);
      const revision = state.revisions.find(item => item.id === revisionId && item.active);
      if (!revision) return false;
      if (revision.scope.imageId && !state.images.some(image => image.id === revision.scope.imageId && image.enabled && !image.retired)) return false;
      await atomic(path.join(folder(applicationId), `${revisionId}-assessment.json`), assessment);
      const { findings, ...summary } = assessment;
      revision.assessment = summary;
      revision.assessmentState = summary.state;
      return true;
    }),
    setImages: (applicationId, images, actor = {}) => update(applicationId, state => {
      const previous = state.images;
      state.images = reconcileImages(images, previous).map(image => image.retired && !previous.find(old => old.id === image.id)?.retired ? { ...image, retiredAt: new Date().toISOString(), retiredBy: actor } : image);
      return state;
    }),
    import: (applicationId, raw, selection, actor) => update(applicationId, async state => {
      const inventory = await processSbom(raw);
      const imageId = selectInventoryImage(inventory, state.images, selection);
      const revision = { ...inventory, ...createInventoryRevision(inventoryScope(applicationId, imageId), inventory), uploader: actor };
      for (const old of state.revisions) if (old.scope.imageId === imageId && old.active) { old.active = false; old.supersededBy = revision.id; old.supersededAt = revision.importedAt; revision.replacesRevisionId = old.id; }
      await atomic(path.join(folder(applicationId), `${revision.id}.json`), revision);
      const { components, dependencies, supplierEvidence, ...metadata } = revision;
      state.revisions.push({ ...metadata, active: true });
      return { ...metadata, active: true };
    }),
  };
}
