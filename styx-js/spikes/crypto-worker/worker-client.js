// worker-client.js — STYX_SPIKE_PROTOTYPE. Typed request/response client for the
// crypto worker: id-correlated promises, optional transferables, and rejection of
// every pending request on worker error/termination (the recovery property the
// vault design needs — a dead worker must not leave the app awaiting forever).

export class CryptoWorkerClient {
  constructor(workerUrl) {
    this._worker = new Worker(workerUrl, { type: 'module' });
    this._pending = new Map(); // id -> {resolve, reject}
    this._seq = 1;
    this.ready = new Promise((resolve) => { this._onReady = resolve; });
    this._worker.onmessage = (ev) => {
      const { id, ok, result, error } = ev.data || {};
      if (id === 0) { this._onReady(); return; }
      const p = this._pending.get(id);
      if (!p) return;
      this._pending.delete(id);
      if (ok) p.resolve(result);
      else { const e = new Error(error.message); e.code = error.code; p.reject(e); }
    };
    this._worker.onerror = (ev) => this._rejectAll('WORKER_CRASHED', ev.message);
  }

  request(type, payload, transfer = []) {
    const id = this._seq++;
    return new Promise((resolve, reject) => {
      this._pending.set(id, { resolve, reject });
      this._worker.postMessage({ id, type, payload }, transfer);
    });
  }

  terminate() {
    this._worker.terminate();
    this._rejectAll('WORKER_TERMINATED', 'worker terminated with operations in flight');
  }

  _rejectAll(code, message) {
    for (const { reject } of this._pending.values()) {
      const e = new Error(message); e.code = code; reject(e);
    }
    this._pending.clear();
  }

  get pendingCount() { return this._pending.size; }
}
