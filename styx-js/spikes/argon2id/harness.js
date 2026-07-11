// harness.js — STYX_SPIKE_PROTOTYPE (argon2id spike). External module (no inline
// scripts, per production CSP). Exposes a typed client for the benchmark worker
// and a main-thread derivation path for the blocking probe.
import { argon2id as argon2idMain } from '../../node_modules/hash-wasm/dist/index.esm.js';

class WorkerClient {
  constructor(url) {
    this._w = new Worker(url, { type: 'module' });
    this._pending = new Map();
    this._seq = 1;
    this.ready = new Promise((r) => { this._onReady = r; });
    this._w.onmessage = (ev) => {
      const { id, ok, result, error } = ev.data || {};
      if (id === 0) { this._onReady(); return; }
      const p = this._pending.get(id);
      if (!p) return;
      this._pending.delete(id);
      if (ok) p.resolve(result);
      else { const e = new Error(error.message); e.code = error.code; p.reject(e); }
    };
  }
  request(type, payload) {
    const id = this._seq++;
    return new Promise((resolve, reject) => {
      this._pending.set(id, { resolve, reject });
      this._w.postMessage({ id, type, payload });
    });
  }
  terminate() {
    this._w.terminate();
    for (const { reject } of this._pending.values()) {
      const e = new Error('terminated'); e.code = 'WORKER_TERMINATED'; reject(e);
    }
    this._pending.clear();
  }
}

window.newArgonClient = () => new WorkerClient(new URL('./argon2-worker.js', import.meta.url));

/** Main-thread derivation (candidate B) for the UI-blocking measurement. */
window.deriveOnMain = (opts) => argon2idMain({ ...opts, outputType: 'binary' });

/**
 * Measure paint starvation while `job` runs: longest gap between rAF frames.
 * A healthy UI stays ≈16 ms; a blocked main thread shows one gap ≈ the job time.
 */
window.measureFrameGaps = async (job) => {
  let last = performance.now();
  let worst = 0;
  let alive = true;
  const tick = () => {
    const now = performance.now();
    worst = Math.max(worst, now - last);
    last = now;
    if (alive) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
  await new Promise((r) => setTimeout(r, 50)); // settle
  const t0 = performance.now();
  await job();
  const jobMs = performance.now() - t0;
  await new Promise((r) => setTimeout(r, 50));
  alive = false;
  return { worstGapMs: worst, jobMs };
};

window.__argonSpikeReady = true;
