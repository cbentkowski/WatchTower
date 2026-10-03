import { sbomLimits } from './sbom.mjs';
import { Worker } from 'node:worker_threads';

let active = 0;
const waiting = [];
export async function processSbom(raw, { maxBytes = sbomLimits.bytes } = {}) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > maxBytes) throw new Error(`SBOM exceeds upload size limit (${maxBytes / 1024 / 1024} MiB)`);
  if (active >= 2) {
    if (waiting.length >= 8) throw new Error('SBOM processor is busy; retry later');
    await new Promise(resolve => waiting.push(resolve));
  } else active++;
  try {
    return await new Promise((resolve, reject) => {
      const worker = new Worker(new URL('./sbom-worker.mjs', import.meta.url), { workerData: { raw, maxBytes }, resourceLimits: { maxOldGenerationSizeMb: 512, stackSizeMb: 4 } });
      const timer = setTimeout(() => { void worker.terminate(); reject(new Error('SBOM processing time limit exceeded')); }, 30000);
      worker.once('message', result => { clearTimeout(timer); void worker.terminate(); result.error ? reject(new Error(result.error)) : resolve(result.inventory); });
      worker.once('error', error => { clearTimeout(timer); reject(error); });
      worker.once('exit', () => { clearTimeout(timer); reject(new Error('SBOM processor stopped before completing')); });
    });
  } finally {
    if (waiting.length) waiting.shift()();
    else active--;
  }
}
