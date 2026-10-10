// B-CHR page: creates the one dedicated worker and relays calls. Port-neutral; carries the factory
// parameter through to the worker URL without interpreting it.
const factory = new URL(location.href).searchParams.get('factory');
let worker = null;
let seq = 0;
const waiting = new Map();

function start() {
  return new Promise((resolve, reject) => {
    worker = new Worker(`/suite/worker.mjs?factory=${encodeURIComponent(factory)}`, { type: 'module' });
    worker.onerror = (e) => reject(new Error(`worker error: ${e.message}`));
    worker.onmessage = (ev) => {
      if (ev.data.ready) { resolve(true); return; }
      const w = waiting.get(ev.data.id);
      if (w === undefined) return;
      waiting.delete(ev.data.id);
      w(ev.data);
    };
  });
}

window.bchr = {
  start,
  /** Terminate the worker (SS memory loss, lock released by context death) and start a fresh one. */
  async restart() { worker.terminate(); waiting.clear(); return start(); },
  call(op, args) {
    const id = ++seq;
    return new Promise((resolve) => { waiting.set(id, resolve); worker.postMessage({ id, op, args }); });
  },
};
window.bchrReady = true;
