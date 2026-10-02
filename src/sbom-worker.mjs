import { parentPort, workerData } from 'node:worker_threads';
import { normalizeSbom } from './sbom.mjs';
try { parentPort.postMessage({ inventory: normalizeSbom(workerData) }); }
catch (error) { parentPort.postMessage({ error: error.message }); }
