// B-CHR harness instrumentation of the IndexedDB prototypes (act #317 6091950328 §1 "Harness": kill
// points are placed by harness instrumentation inside the dedicated worker; the instrumentation is
// identical for every port and is never inside a port). It never calls commit() itself.
// Kill-point names, per readwrite transaction i of one armed operation:
//   T<i>:OPEN         the transaction was created, before its first request
//   T<i>:R<j>         before request j of the transaction is issued
//   T<i>:END          right after the request that was the last one in the reference (dry) run
//   T<i>:COMMIT_SENT  right after the port itself called commit(), if it does
//   T<i>:COMPLETE     the backend reported `complete`; this listener is registered before the port's
//                     own, so a kill here is a landed commit whose notification is lost (T6b)
//   R<k>              right after readonly request k of the operation was issued
//   RETURNED          the operation returned or threw; its response is about to be lost
// Faults (identical for every port):
//   PUT_THROW  the first readwrite put throws synchronously (T6b mutant "a put throws mid-enqueue")
//   READ_FAIL  every readonly request throws synchronously (T9 "readback unavailable")
//   TAMPER     the result of readonly request k (or of every one when tamperAt is null) has the last
//              byte of every byte array flipped (T9 "AEAD tamper"); readonly requests are counted in
//              issue order while armed, so k ranges over the reads of the reference (dry) run
const REQUEST_METHODS = ['put', 'add', 'delete', 'clear', 'get', 'getAll', 'getAllKeys', 'getKey', 'count', 'openCursor', 'openKeyCursor'];

function tamper(value) {
  if (value instanceof Uint8Array) { const c = value.slice(); if (c.length > 0) c[c.length - 1] ^= 0x01; return c; }
  if (value instanceof ArrayBuffer) return tamper(new Uint8Array(value)).buffer;
  if (Array.isArray(value)) return value.map(tamper);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) out[k] = tamper(value[k]);
    return out;
  }
  return value;
}
const carriesBytes = (v) => (v instanceof Uint8Array ? v.length > 0 : (v instanceof ArrayBuffer ? v.byteLength > 0
  : (Array.isArray(v) ? v.some(carriesBytes) : (v !== null && typeof v === 'object' ? Object.values(v).some(carriesBytes) : false))));

export function instrument({ hook, state }) {
  // state: { armed, fault, tamperAt, plan: { [txIndex]: lastRequestIndex }, trace: [], next: 0, reads: 0 }
  const info = new WeakMap();
  const tampered = new WeakMap(); // request -> read index
  const resultGetter = Object.getOwnPropertyDescriptor(IDBRequest.prototype, 'result').get;
  Object.defineProperty(IDBRequest.prototype, 'result', {
    configurable: true,
    get() {
      const v = resultGetter.call(this);
      if (!tampered.has(this)) return v;
      const k = tampered.get(this);
      if (!state.trace.some((e) => e.ev === 'TAMPERED' && e.k === k)) state.trace.push({ ev: 'TAMPERED', k, changed: carriesBytes(v) });
      return tamper(v);
    },
  });
  const origTransaction = IDBDatabase.prototype.transaction;
  IDBDatabase.prototype.transaction = function transaction(...args) {
    const tx = origTransaction.apply(this, args);
    if (!state.armed || tx.mode !== 'readwrite') return tx;
    const id = state.next++;
    info.set(tx, { id, requests: 0 });
    state.trace.push({ tx: id, ev: 'OPEN', stores: Array.from(tx.objectStoreNames), durability: tx.durability });
    tx.addEventListener('complete', () => { state.trace.push({ tx: id, ev: 'COMPLETE' }); hook(`T${id}:COMPLETE`); });
    tx.addEventListener('abort', () => { state.trace.push({ tx: id, ev: 'ABORT' }); });
    hook(`T${id}:OPEN`);
    return tx;
  };
  const origCommit = IDBTransaction.prototype.commit;
  IDBTransaction.prototype.commit = function commit(...args) {
    const r = origCommit.apply(this, args);
    const t = info.get(this);
    if (t !== undefined) { state.trace.push({ tx: t.id, ev: 'COMMIT_SENT' }); hook(`T${t.id}:COMMIT_SENT`); }
    return r;
  };
  for (const name of REQUEST_METHODS) {
    const orig = IDBObjectStore.prototype[name];
    if (typeof orig !== 'function') continue;
    IDBObjectStore.prototype[name] = function request(...args) {
      const mode = this.transaction.mode;
      if (state.armed && mode === 'readonly' && state.fault === 'READ_FAIL') {
        state.trace.push({ ev: 'FAULT', fault: 'READ_FAIL', op: name });
        throw new DOMException('injected read failure', 'UnknownError');
      }
      const t = info.get(this.transaction);
      if (t === undefined) {
        const r = orig.apply(this, args);
        if (state.armed && mode === 'readonly') {
          const k = state.reads++;
          state.trace.push({ ev: 'READ', k, op: name });
          if (state.fault === 'TAMPER' && (state.tamperAt === null || state.tamperAt === k)) tampered.set(r, k);
          hook(`R${k}`); // a readonly request boundary: right after request k was issued
        }
        return r;
      }
      const j = t.requests++;
      state.trace.push({ tx: t.id, ev: 'REQ', j, op: name, store: this.name });
      hook(`T${t.id}:R${j}`);
      if (state.fault === 'PUT_THROW' && name === 'put' && !state.faulted) {
        state.faulted = true;
        state.trace.push({ tx: t.id, ev: 'FAULT', fault: 'PUT_THROW', j });
        throw new DOMException('injected request failure', 'UnknownError');
      }
      const r = orig.apply(this, args);
      if (state.plan[t.id] === j) hook(`T${t.id}:END`);
      return r;
    };
  }
}
