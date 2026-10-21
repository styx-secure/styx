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
//   TAMPER     the result of readonly request k (tamperAt k), of every one (tamperAt null) or of every
//              one after the first (tamperAt 'REST') has the last byte of every byte array flipped (T9
//              "AEAD tamper"); readonly requests are counted in issue order while armed
// The OPEN hook carries the transaction's durability and scope to the host, so that a killed context
// still leaves its transaction metadata with the harness (B-CHR PR-r1 F9). `state.onOpen`, when set,
// is called with every armed readwrite transaction (the worker's memory-hold probe).
// Sections (cycle 3, review impl3 R3-5/R3-7): every event is recorded in the trace of the armed section
// it originates in (the section current when its transaction opened, or its read was issued), and a
// kill point of a transaction is reported only while that section is the current one, so that a late
// `complete` or request of an earlier section never lands in, or adds a kill point to, a later one.
// Ownership first (cycle 4, review impl4 R4-4): every transaction, readonly ones included, belongs to the
// section current when it was created; a read fault is injected, and its receipt, a read index or a
// tamper recorded, only for a request of a transaction owned by the current armed section, in that
// section's own trace. A request of an earlier section's transaction is never faulted.
// Selector writes (cycle 4, R4-2): every `put` of a readwrite transaction, armed or not, is shown to
// `state.onPut(value, section)` before it is issued, so that the harness can judge every selector put
// on its own (obligation item 10), not only every public call.
// Keep-alive (cycle 4, R4-1): `keepAlive(tx, until, ms)` keeps a transaction from auto-committing until
// `until` settles (at most `ms`), by chaining harness reads of a key no port writes through the
// uninstrumented `get`: they add no request index, kill point, read index or fault, and no write. A port
// that calls commit() itself ends the chain at once (no request may follow commit()).
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
  // state: { armed, section, fault, tamperAt, plan: { [txIndex]: lastRequestIndex }, trace: [], next: 0, reads: 0 }
  const info = new WeakMap(); // armed readwrite transaction -> { id, requests, trace, section }
  const owner = new WeakMap(); // every transaction -> { section, trace, armed } at its creation
  const rawGet = IDBObjectStore.prototype.get;
  const tampered = new WeakMap(); // request -> read index
  const resultGetter = Object.getOwnPropertyDescriptor(IDBRequest.prototype, 'result').get;
  Object.defineProperty(IDBRequest.prototype, 'result', {
    configurable: true,
    get() {
      const v = resultGetter.call(this);
      if (!tampered.has(this)) return v;
      const { k, trace } = tampered.get(this);
      if (!trace.some((e) => e.ev === 'TAMPERED' && e.k === k)) trace.push({ ev: 'TAMPERED', k, changed: carriesBytes(v) });
      return tamper(v);
    },
  });
  const origTransaction = IDBDatabase.prototype.transaction;
  IDBDatabase.prototype.transaction = function transaction(...args) {
    const tx = origTransaction.apply(this, args);
    owner.set(tx, { section: state.section, trace: state.trace, armed: state.armed });
    if (!state.armed || tx.mode !== 'readwrite') return tx;
    const id = state.next++;
    const { trace, section } = state;
    info.set(tx, { id, requests: 0, trace, section });
    const current = () => state.section === section;
    const meta = { stores: Array.from(tx.objectStoreNames), durability: tx.durability };
    trace.push({ tx: id, ev: 'OPEN', ...meta });
    tx.addEventListener('complete', () => { trace.push({ tx: id, ev: 'COMPLETE' }); if (current()) hook(`T${id}:COMPLETE`); });
    tx.addEventListener('abort', () => { trace.push({ tx: id, ev: 'ABORT' }); });
    if (typeof state.onOpen === 'function') state.onOpen(id, tx);
    hook(`T${id}:OPEN`, meta);
    return tx;
  };
  const origCommit = IDBTransaction.prototype.commit;
  IDBTransaction.prototype.commit = function commit(...args) {
    const r = origCommit.apply(this, args);
    const t = info.get(this);
    if (t !== undefined) { t.trace.push({ tx: t.id, ev: 'COMMIT_SENT' }); if (state.section === t.section) hook(`T${t.id}:COMMIT_SENT`); }
    return r;
  };
  const READS = new Set(['get', 'getAll', 'getAllKeys', 'getKey', 'count', 'openCursor', 'openKeyCursor']);
  const readFault = () => state.armed && (state.fault === 'READ_FAIL' || state.fault === 'TAMPER');
  // The transaction's owner when it is the current armed section (R4-4), null otherwise.
  const currentOwner = (tx) => {
    const o = owner.get(tx);
    return o !== undefined && o.armed && state.armed && o.section === state.section ? o : null;
  };
  for (const name of REQUEST_METHODS) {
    const orig = IDBObjectStore.prototype[name];
    if (typeof orig !== 'function') continue;
    IDBObjectStore.prototype[name] = function request(...args) {
      const mode = this.transaction.mode;
      const mine = currentOwner(this.transaction);
      // Read faults reach every read request, whatever the transaction mode (B-CHR-CANON r1 C3): a port
      // may read inside a readwrite transaction that writes nothing. Only a request of a transaction of
      // the current armed section is faulted, and the receipt goes to that section's trace (R4-4).
      if (mine !== null && READS.has(name) && readFault() && state.fault === 'READ_FAIL') {
        mine.trace.push({ ev: 'FAULT', fault: 'READ_FAIL', op: name });
        throw new DOMException('injected read failure', 'UnknownError');
      }
      if (name === 'put' && mode === 'readwrite' && typeof state.onPut === 'function') state.onPut(args[0], owner.get(this.transaction)?.section ?? null);
      const t = info.get(this.transaction);
      if (t === undefined) {
        const r = orig.apply(this, args);
        if (mine !== null && mode === 'readonly') {
          const k = state.reads++;
          mine.trace.push({ ev: 'READ', k, op: name });
          if (state.fault === 'TAMPER' && (state.tamperAt === null || state.tamperAt === k || (state.tamperAt === 'REST' && k >= 1))) tampered.set(r, { k, trace: mine.trace });
          hook(`R${k}`); // a readonly request boundary: right after request k was issued
        }
        return r;
      }
      const j = t.requests++;
      const current = state.section === t.section;
      t.trace.push({ tx: t.id, ev: 'REQ', j, op: name, store: this.name });
      if (current) hook(`T${t.id}:R${j}`);
      if (current && state.fault === 'PUT_THROW' && name === 'put' && !state.faulted) {
        state.faulted = true;
        t.trace.push({ tx: t.id, ev: 'FAULT', fault: 'PUT_THROW', j });
        throw new DOMException('injected request failure', 'UnknownError');
      }
      const r = orig.apply(this, args);
      if (current && READS.has(name) && readFault()) {
        // A read inside a readwrite transaction takes the next read index (no kill point of its own).
        const k = state.reads++;
        state.trace.push({ ev: 'READ', k, op: name, tx: t.id });
        if (state.tamperAt === null || state.tamperAt === k || (state.tamperAt === 'REST' && k >= 1)) tampered.set(r, { k, trace: state.trace });
      }
      if (current && state.plan[t.id] === j) hook(`T${t.id}:END`);
      return r;
    };
  }
  const KEEP_ALIVE_KEY = 'styx-bchr-harness-keepalive';
  function keepAlive(tx, until, ms) {
    let stop = false;
    const timer = setTimeout(() => { stop = true; }, ms);
    const end = () => { stop = true; clearTimeout(timer); };
    Promise.resolve(until).then(end, end);
    let store;
    try { store = tx.objectStore(tx.objectStoreNames[0]); } catch { end(); return; }
    const ping = () => {
      if (stop) return;
      let r;
      try { r = rawGet.call(store, KEEP_ALIVE_KEY); } catch { end(); return; } // committed, aborted or finished
      r.onsuccess = ping;
      r.onerror = (ev) => { ev.preventDefault?.(); ev.stopPropagation?.(); end(); };
    };
    ping();
  }
  return { keepAlive };
}
