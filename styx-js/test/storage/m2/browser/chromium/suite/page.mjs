// B-CHR page: creates the one dedicated worker and relays calls. Port-neutral; carries the factory
// parameter through to the worker URL without interpreting it.
const factory = new URL(location.href).searchParams.get('factory');
let worker = null;
let seq = 0;
const waiting = new Map();

function start() {
  return new Promise((resolve, reject) => {
    const current = worker;
    worker = new Worker(`/suite/worker.mjs?factory=${encodeURIComponent(factory)}`, { type: 'module' });
    // A worker that fails or dies must not leave a caller waiting forever: every outstanding call is
    // rejected, so the host's cell timeout is a backstop, not the only guard (review impl1 F5).
    worker.onerror = (e) => { fail(current, new Error(`worker error: ${e.message}`)); reject(new Error(`worker error: ${e.message}`)); };
    worker.onmessageerror = () => fail(current, new Error('worker message error'));
    worker.onmessage = (ev) => {
      if (ev.data.ready) { resolve(true); return; }
      const w = waiting.get(ev.data.id);
      if (w === undefined) return;
      waiting.delete(ev.data.id);
      w(ev.data);
    };
  });
}
function fail(current, error) {
  for (const [id, w] of [...waiting]) {
    waiting.delete(id);
    w({ id, error: { code: 'WORKER_GONE', message: String(error.message) } });
  }
  void current;
}

window.bchr = {
  start,
  /** Terminate the worker (SS memory loss, lock released by context death) and start a fresh one. */
  async restart() {
    const current = worker;
    worker.terminate();
    fail(current, new Error('worker restarted'));
    return start();
  },
  call(op, args) {
    const id = ++seq;
    return new Promise((resolve) => { waiting.set(id, resolve); worker.postMessage({ id, op, args }); });
  },
};
window.bchrReady = true;
