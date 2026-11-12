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
// Sections (cycle 3/4): every event is recorded in the trace of the armed section it originates in, and a
// kill point of a transaction is reported only while that section is the current one. A read fault is
// injected only for a request of a transaction owned by the current armed section.
// Keep-alive (cycle 4, R4-1): `keepAlive(tx, until, ms)` keeps a transaction from auto-committing until
// `until` settles (at most `ms`), by chaining harness reads of a key no port writes through the captured
// native `get`: they add no request index, kill point, read index, fault, write or record.
//
// Substituted-clone observer (owner act v2 on #317, §3-§5; it replaces the traversal of caller values).
// The observer never inspects a value or key object the port passes. Every intrinsic it uses is captured
// below, at the top-level evaluation of this module, which worker.mjs imports before every other module,
// and is called through captured bindings. One write call (`put`, `add`, cursor `update`, store `delete`;
// cursor `delete()` and `clear()` are recorded) does, in order:
//   1. brand-check the receiver with captured WebIDL getters; on failure, or with a required argument
//      missing, the native method is called unchanged; otherwise the write record is created;
//   2. classify an explicit key without running any code (string, number other than NaN, exact
//      Uint8Array by slot accessors, then copied); any other key makes the write NON_CANONICAL_WRITE and
//      the call is delegated unchanged with no further step;
//   3. for a value-carrying call, call the native method with an uncloneable sentinel and the key; an
//      exception other than DataCloneError is PRECLONE_REJECTED and rethrown (no getter runs); a sentinel
//      call that does not throw is an observer error and the write never proceeds;
//   4. clone the value once with the captured structuredClone; any call to a wrapped IndexedDB method or
//      setter during the clone, on any transaction, makes the write NON_CANONICAL_WRITE (a request of the
//      transaction being cloned throws TransactionInactiveError, best-effort emulation);
//   5. classify the clone `c` and the key under domain D (act §4), check every store and index key path;
//   6. call the native method with `c` and the key.

// ---- captured intrinsics (top-level evaluation) ---------------------------------------------------------
const C = (() => {
  const rawGopd = Reflect.getOwnPropertyDescriptor; const setProto = Reflect.setPrototypeOf;
  // Every descriptor the observer reads is a fresh object with a null prototype (Argon C4): no field can be
  // inherited from Object.prototype; isData/ownField below additionally read own fields only (D20).
  const gopd = (o, k) => { const d = rawGopd(o, k); if (d !== undefined) setProto(d, null); return d; };
  const getter = (o, k) => { const d = o === undefined || o === null ? undefined : gopd(o, k); return d === undefined ? undefined : d.get; };
  const setter = (o, k) => { const d = o === undefined || o === null ? undefined : gopd(o, k); return d === undefined ? undefined : d.set; };
  const has = (name) => typeof globalThis[name] === 'function';
  const TA = Reflect.getPrototypeOf(Uint8Array.prototype);
  const P = (name) => (has(name) ? globalThis[name].prototype : undefined);
  const S = P('IDBObjectStore'); const I = P('IDBIndex'); const CU = P('IDBCursor'); const T = P('IDBTransaction');
  const D = P('IDBDatabase'); const F = P('IDBFactory'); const R = P('IDBRequest');
  return Object.freeze({ __proto__: null,
    apply: Reflect.apply, gopd, getter, setter, ownKeys: Reflect.ownKeys, getProto: Reflect.getPrototypeOf, hasOwn: Object.hasOwn,
    defineProperty: Reflect.defineProperty, isArray: Array.isArray, structuredClone: globalThis.structuredClone,
    DOMException: globalThis.DOMException, Error: globalThis.Error, isNaN: Number.isNaN, Symbol: globalThis.Symbol,
    MapCtor: Map, mapGet: Map.prototype.get, mapSet: Map.prototype.set, mapHas: Map.prototype.has,
    WeakMapCtor: WeakMap, wmGet: WeakMap.prototype.get, wmSet: WeakMap.prototype.set, wmHas: WeakMap.prototype.has,
    ObjectProto: Object.prototype, ArrayProto: Array.prototype, U8: Uint8Array, U8Proto: Uint8Array.prototype,
    taSet: TA.set, taTag: getter(TA, Symbol.toStringTag), taBuffer: getter(TA, 'buffer'), taByteOffset: getter(TA, 'byteOffset'),
    taByteLength: getter(TA, 'byteLength'), taLength: getter(TA, 'length'),
    abByteLength: getter(ArrayBuffer.prototype, 'byteLength'), abResizable: getter(ArrayBuffer.prototype, 'resizable'),
    abDetached: getter(ArrayBuffer.prototype, 'detached'),
    sabByteLength: has('SharedArrayBuffer') ? getter(SharedArrayBuffer.prototype, 'byteLength') : undefined,
    dvByteLength: getter(DataView.prototype, 'byteLength'), mapSize: getter(Map.prototype, 'size'), setSize: getter(Set.prototype, 'size'),
    dateGetTime: Date.prototype.getTime, regexpSource: getter(RegExp.prototype, 'source'), RegExpProto: RegExp.prototype,
    numValueOf: Number.prototype.valueOf, strValueOf: String.prototype.valueOf, boolValueOf: Boolean.prototype.valueOf,
    bigValueOf: BigInt.prototype.valueOf, symValueOf: Symbol.prototype.valueOf,
    pop: Array.prototype.pop, charCodeAt: String.prototype.charCodeAt, split: String.prototype.split,
    getRandomValues: globalThis.crypto?.getRandomValues, crypto: globalThis.crypto, performanceNow: globalThis.performance?.now,
    performance: globalThis.performance, setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout,
    Promise: globalThis.Promise, promiseResolve: Promise.resolve, promiseThen: Promise.prototype.then,
    addEventListener: globalThis.EventTarget?.prototype.addEventListener,
    domName: getter(globalThis.DOMException?.prototype, 'name'),
    listLength: getter(P('DOMStringList'), 'length'), listItem: P('DOMStringList')?.item,
    // IndexedDB natives and WebIDL getters/setters.
    S, I, CU, T, D, F, R,
    storeTx: getter(S, 'transaction'), storeKeyPath: getter(S, 'keyPath'), storeIndexNames: getter(S, 'indexNames'),
    storeName: getter(S, 'name'), storeIndex: S?.index, storeAutoIncrement: getter(S, 'autoIncrement'), indexStore: getter(I, 'objectStore'), indexKeyPath: getter(I, 'keyPath'),
    cursorSource: getter(CU, 'source'), txMode: getter(T, 'mode'), txDurability: getter(T, 'durability'),
    txStoreNames: getter(T, 'objectStoreNames'), requestResult: getter(R, 'result'), requestError: getter(R, 'error'),
    // K19 (owner decision on #317 6384613341 §1): database identity, versionchange schema and late reports.
    txDb: getter(T, 'db'), dbName: getter(D, 'name'), requestTx: getter(R, 'transaction'), cursorPrimaryKey: getter(CU, 'primaryKey'),
    vcOld: getter(P('IDBVersionChangeEvent'), 'oldVersion'), vcNew: getter(P('IDBVersionChangeEvent'), 'newVersion'),
    U32: Uint32Array, XHR: globalThis.XMLHttpRequest, xhrOpen: globalThis.XMLHttpRequest?.prototype.open,
    xhrSend: globalThis.XMLHttpRequest?.prototype.send, encodeURIComponent: globalThis.encodeURIComponent,
    native: Object.freeze({ __proto__: null,
      S: S === undefined ? { __proto__: null } : Object.fromEntries(Reflect.ownKeys(S).filter((k) => typeof k === 'string' && typeof gopd(S, k).value === 'function').map((k) => [k, S[k]])),
      I: I === undefined ? { __proto__: null } : Object.fromEntries(Reflect.ownKeys(I).filter((k) => typeof k === 'string' && typeof gopd(I, k).value === 'function').map((k) => [k, I[k]])),
      CU: CU === undefined ? { __proto__: null } : Object.fromEntries(Reflect.ownKeys(CU).filter((k) => typeof k === 'string' && typeof gopd(CU, k).value === 'function').map((k) => [k, CU[k]])),
      T: T === undefined ? { __proto__: null } : Object.fromEntries(Reflect.ownKeys(T).filter((k) => typeof k === 'string' && typeof gopd(T, k).value === 'function').map((k) => [k, T[k]])),
      D: D === undefined ? { __proto__: null } : Object.fromEntries(Reflect.ownKeys(D).filter((k) => typeof k === 'string' && typeof gopd(D, k).value === 'function').map((k) => [k, D[k]])),
      F: F === undefined ? { __proto__: null } : Object.fromEntries(Reflect.ownKeys(F).filter((k) => typeof k === 'string' && typeof gopd(F, k).value === 'function').map((k) => [k, F[k]])),
    }),
    setters: Object.freeze([
      ...['name'].map((k) => [S, k, setter(S, k)]), ...['name'].map((k) => [I, k, setter(I, k)]),
      ...['onsuccess', 'onerror'].map((k) => [R, k, setter(R, k)]),
      ...['oncomplete', 'onabort', 'onerror'].map((k) => [T, k, setter(T, k)]),
      ...['onabort', 'onclose', 'onerror', 'onversionchange'].map((k) => [D, k, setter(D, k)]),
      ...['onblocked', 'onupgradeneeded'].map((k) => [P('IDBOpenDBRequest'), k, setter(P('IDBOpenDBRequest'), k)]),
    ].filter(([o, , s]) => o !== undefined && s !== undefined)),
  });
})();

// Append without Set semantics (no inherited setter can run), pop through a captured method.
const push = (a, v) => { C.defineProperty(a, a.length, { __proto__: null, value: v, writable: true, enumerable: true, configurable: true }); };
const pop = (a) => C.apply(C.pop, a, []);
// A property descriptor is an ordinary object whose prototype is Object.prototype: a field it does not own
// (`value` of an accessor descriptor, `get`/`set` of a data descriptor) would be read from there. Every
// descriptor is read through its OWN fields only, by the captured Object.hasOwn (D20).
const ownField = (d, k) => d !== undefined && C.apply(C.hasOwn, undefined, [d, k]);
/** A data descriptor: it owns `value`. Only then is `d.value` its own field. */
const isData = (d) => ownField(d, 'value');
const throws = (fn, x) => { try { C.apply(fn, x, []); return false; } catch { return true; } };
const hasSlot = (fn, x) => fn !== undefined && !throws(fn, x);
/** WebIDL DOMString conversion (ECMAScript ToString: a Symbol throws TypeError, an object runs ToPrimitive). */
const domString = (v) => `${v}`;
// Only a DOMException's name is read (through its internal slot); any other thrown value is never touched,
// so no getter or trap of the caller runs (act §3 non-interference).
const errorName = (e) => { try { return C.apply(C.domName, e, []); } catch { return 'non-DOMException'; } };
const SENTINEL = C.Symbol('bchr-preclone-sentinel');
const callGlobal = (fn, ...a) => C.apply(fn, undefined, a);
export const OBJECT_LIMIT = 4096;

/**
 * The selector-envelope recogniser the observer applies to the fresh copy of every exact Uint8Array node
 * (act §4). A node is a selector envelope iff the frozen C-FMT codec would decode it as one: this is a
 * byte-exact replica of `decodeEnvelope` for record kind 17 GENERATION_SELECTOR (session-codec.js), with
 * `decodeAad` and `decodeSelectorKey` (consensus review R1: a header-only match attributed bytes the codec
 * rejects). It runs on captured operations only: indexed reads of a fresh typed array, integer arithmetic
 * and string concatenation, so no intrinsic the port can replace is called. Every canonical re-encoding
 * check of the codec is implied by the fixed layout verified here.
 */
const HEX = '0123456789abcdef';
const MAGIC = [0x53, 0x54, 0x59, 0x58, 0x46, 0x4d, 0x54, 0x31]; // STYXFMT1
const AAD_MAGIC = [0x53, 0x54, 0x59, 0x58, 0x41, 0x41, 0x44, 0x31]; // STYXAAD1
const SEL_MAGIC = [0x53, 0x54, 0x59, 0x58, 0x53, 0x45, 0x4c, 0x31]; // STYXSEL1
const MAX_PLAINTEXT = 16 * 1024 * 1024;
const SELECTOR_KIND = 17; const SELECTOR_KIND_VERSION = 3;
function hexOf(u, from, to) { let s = ''; for (let i = from; i < to; i++) { const b = u[i]; s = s + HEX[b >> 4] + HEX[b & 15]; } return s; }
export function recognizeSelector(u) {
  const len = C.apply(C.taLength, u, []);
  const r16 = (o) => u[o] * 256 + u[o + 1];
  const r32 = (o) => ((u[o] * 256 + u[o + 1]) * 256 + u[o + 2]) * 256 + u[o + 3];
  const magicAt = (o, m) => { if (o + 8 > len) return false; for (let i = 0; i < 8; i++) if (u[o + i] !== m[i]) return false; return true; };
  const zero = (o, n) => { for (let i = 0; i < n; i++) if (u[o + i] !== 0) return false; return true; };
  const same = (o1, o2, n) => { for (let i = 0; i < n; i++) if (u[o1 + i] !== u[o2 + i]) return false; return true; };
  // Envelope header (36 bytes).
  if (len < 36 || !magicAt(0, MAGIC)) return null;
  if (r16(8) !== 1 || r16(10) !== SELECTOR_KIND || r16(12) !== SELECTOR_KIND_VERSION || r16(14) !== 1 || r16(16) !== 1 || r16(18) !== 1 || r16(34) !== 16) return null;
  const kl = r16(20); const al = r32(22); const pl = r32(26); const cl = r32(30);
  if (pl > MAX_PLAINTEXT || cl !== pl || 36 + kl + al + 12 + cl + 16 !== len) return null;
  const k0 = 36; const a0 = 36 + kl;
  // Selector key: STYXSEL1, version 1, a nonzero 32-byte localContextId, exactly 42 bytes.
  if (kl !== 42 || !magicAt(k0, SEL_MAGIC) || r16(k0 + 8) !== 1 || zero(k0 + 10, 32)) return null;
  // AAD: STYXAAD1, format/envelope/key versions 1, kind 17 and its version, the framed record key equal to
  // the envelope's, the selector key's localContextId, a 32-byte profile digest, scope 1 or 2 (2: a nonzero
  // session identity and a binding digest), then exactly a nonzero u64 generation, a 32-byte mutation
  // identity and the plaintext length of the envelope.
  if (al < 22 || !magicAt(a0, AAD_MAGIC)) return null;
  if (r16(a0 + 8) !== 1 || r16(a0 + 10) !== 1 || r16(a0 + 12) !== SELECTOR_KIND || r16(a0 + 14) !== SELECTOR_KIND_VERSION || r16(a0 + 16) !== 1) return null;
  const akl = r32(a0 + 18);
  let o = a0 + 22;
  if (akl !== kl || o + akl + 65 > a0 + al || !same(o, k0, kl)) return null;
  o += akl;
  if (zero(o, 32) || !same(o, k0 + 10, 32)) return null;
  o += 64; // localContextId, productProfileDigest
  const scope = u[o]; o += 1;
  if (scope === 2) { if (o + 64 > a0 + al || zero(o, 32)) return null; o += 64; } else if (scope !== 1) return null;
  if (o + 44 !== a0 + al) return null;
  if (zero(o, 8)) return null; // writeGeneration 0
  if (r32(o + 40) !== pl) return null;
  const n = a0 + al;
  return { __proto__: null, envelope: hexOf(u, 0, len), nonce: hexOf(u, n, n + 12) };
}
/** Append without Set semantics: no inherited accessor can intercept or drop the element (K6). */
export function append(a, v) { push(a, v); return a; }

/** Brand of an object node of a PLATFORM-CREATED clone (no Proxy, no accessor), by captured slot accessors. */
export function brandOf(x) {
  const tag = C.apply(C.taTag, x, []);
  if (tag !== undefined) return tag; // any typed array, by [[TypedArrayName]]
  if (hasSlot(C.dvByteLength, x)) return 'DataView';
  if (hasSlot(C.abByteLength, x)) return 'ArrayBuffer';
  if (hasSlot(C.sabByteLength, x)) return 'SharedArrayBuffer';
  if (hasSlot(C.mapSize, x)) return 'Map';
  if (hasSlot(C.setSize, x)) return 'Set';
  if (hasSlot(C.dateGetTime, x)) return 'Date';
  if (x !== C.RegExpProto && hasSlot(C.regexpSource, x)) return 'RegExp';
  if (hasSlot(C.numValueOf, x)) return 'Number';
  if (hasSlot(C.strValueOf, x)) return 'String';
  if (hasSlot(C.boolValueOf, x)) return 'Boolean';
  if (hasSlot(C.bigValueOf, x)) return 'BigInt';
  if (hasSlot(C.symValueOf, x)) return 'Symbol';
  if (C.isArray(x)) return 'Array';
  return null; // ordinary, or an Error/platform object, recognised by its prototype
}

/** An exact Uint8Array (act §4): name, intrinsic prototype, own keys its indices, plain unshared full buffer. */
function exactU8(v) {
  if (C.apply(C.taTag, v, []) !== 'Uint8Array') return 'not-u8';
  if (C.getProto(v) !== C.U8Proto) return 'u8-prototype';
  const buf = C.apply(C.taBuffer, v, []);
  if (!hasSlot(C.abByteLength, buf)) return 'u8-shared-buffer';
  if (C.abResizable !== undefined && C.apply(C.abResizable, buf, [])) return 'u8-resizable-buffer';
  if (C.abDetached !== undefined && C.apply(C.abDetached, buf, [])) return 'u8-detached';
  const len = C.apply(C.taLength, v, []);
  if (C.apply(C.taByteOffset, v, []) !== 0 || C.apply(C.abByteLength, buf, []) !== len) return 'u8-partial-window';
  if (C.ownKeys(v).length !== len) return 'u8-extra-properties';
  return null;
}
function copyU8(v) { const copy = new C.U8(C.apply(C.taLength, v, [])); C.apply(C.taSet, copy, [v]); return copy; }

const isIndex = (k, len) => {
  if (typeof k !== 'string' || k.length === 0 || (k.length > 1 && C.apply(C.charCodeAt, k, [0]) === 48)) return false;
  let n = 0;
  for (let i = 0; i < k.length; i++) { const d = C.apply(C.charCodeAt, k, [i]) - 48; if (d < 0 || d > 9) return false; n = n * 10 + d; }
  return n < len;
};

/**
 * Classify a platform-created clone `c` against domain D (act §4). Returns { inD, reasons, envelopes,
 * objects }. A selector envelope is emitted only as the complete content of one exact Uint8Array node;
 * aliases and cycles are allowed (an envelope node seen twice counts once).
 */
export function classifyClone(c, limit = OBJECT_LIMIT) {
  const reasons = []; const envelopes = []; const seenEnv = new C.MapCtor(); const seen = new C.WeakMapCtor();
  let objects = 0; const stack = [c];
  const reason = (r) => { if (!C.apply(C.mapHas, seenEnv, [`reason:${r}`])) { C.apply(C.mapSet, seenEnv, [`reason:${r}`, true]); push(reasons, r); } };
  while (stack.length) {
    const v = pop(stack);
    if (v === null || (typeof v !== 'object' && typeof v !== 'function')) {
      if (typeof v === 'symbol' || typeof v === 'function') reason(`primitive:${typeof v}`);
      continue;
    }
    if (C.apply(C.wmHas, seen, [v])) continue;
    C.apply(C.wmSet, seen, [v, true]);
    if (++objects > limit) { reason('object-limit'); break; }
    const brand = brandOf(v); const proto = C.getProto(v);
    if (brand === 'Uint8Array') {
      const bad = exactU8(v);
      if (bad !== null) { reason(bad); continue; }
      const e = recognizeSelector(copyU8(v));
      if (e !== null && !C.apply(C.mapHas, seenEnv, [e.envelope])) { C.apply(C.mapSet, seenEnv, [e.envelope, true]); push(envelopes, e); }
      continue;
    }
    if (brand === 'Array') {
      if (proto !== C.ArrayProto) { reason('array-prototype'); continue; }
      const ld = C.gopd(v, 'length'); const len = ld.value; const keys = C.ownKeys(v);
      if (keys.length !== len + 1 || ld.enumerable) { reason('array-not-dense-or-extra'); continue; }
      let ok = true;
      for (let x = 0; x < keys.length; x++) {
        const k = keys[x];
        if (k === 'length') continue;
        const d = C.gopd(v, k);
        if (!isIndex(k, len) || !isData(d) || !d.enumerable) { ok = false; break; }
        push(stack, d.value);
      }
      if (!ok) reason('array-not-dense-or-extra');
      continue;
    }
    if (brand !== null) { reason(`class:${brand}`); continue; }
    if (proto !== C.ObjectProto) { reason('prototype-not-Object.prototype'); continue; }
    const own = C.ownKeys(v);
    for (let x = 0; x < own.length; x++) {
      const k = own[x];
      if (typeof k !== 'string') { reason('symbol-key'); continue; }
      const d = C.gopd(v, k);
      if (!isData(d) || !d.enumerable) { reason('non-data-or-non-enumerable'); continue; }
      push(stack, d.value);
    }
  }
  return { __proto__: null, inD: reasons.length === 0, reasons, envelopes, objects };
}

/**
 * An explicit key under act §3 step 2, without running any code: a string, a number other than NaN, or an
 * exact Uint8Array (copied; the copy is used from then on). Anything else is outside D.
 */
export function classifyKey(k) {
  if (typeof k === 'string') return { __proto__: null, inD: true, key: k, envelopes: [] };
  if (typeof k === 'number') return C.isNaN(k) ? { __proto__: null, inD: false, reason: 'key-NaN' } : { __proto__: null, inD: true, key: k, envelopes: [] };
  if (k === null || typeof k !== 'object') return { __proto__: null, inD: false, reason: `key-${typeof k}` };
  const bad = exactU8(k); // a Proxy has no [[TypedArrayName]]: no trap runs
  if (bad !== null) return { __proto__: null, inD: false, reason: `key-${bad}` };
  const key = copyU8(k);
  const e = recognizeSelector(copyU8(key));
  return { __proto__: null, inD: true, key, envelopes: e === null ? [] : [e] };
}

/**
 * The selector envelopes reachable from a platform-created value, through exact Uint8Array nodes and the
 * own data properties of arrays (and, with `objects`, of ordinary objects). The budget counts DISTINCT
 * objects, as D does (act §4: at most 4,096 distinct objects), never primitives or repeated aliases
 * (D19); a walk that exceeds it is reported as `over`, never as a complete empty result.
 */
function envelopesReachable(root, objects) {
  const out = []; const stack = [root]; const seen = new C.WeakMapCtor(); let count = 0;
  while (stack.length > 0) {
    const v = pop(stack);
    if (v === null || typeof v !== 'object') continue;
    if (C.apply(C.wmHas, seen, [v])) continue;
    C.apply(C.wmSet, seen, [v, true]);
    if (++count > OBJECT_LIMIT) return { __proto__: null, envelopes: out, over: true };
    const b = brandOf(v);
    if (b === 'Uint8Array') { const k = classifyKey(v); if (k.inD) for (let z = 0; z < k.envelopes.length; z++) push(out, k.envelopes[z]); continue; }
    if (b !== 'Array' && !(objects && b === null)) continue;
    const keys = C.ownKeys(v);
    for (let q = 0; q < keys.length; q++) { const d = C.gopd(v, keys[q]); if (isData(d)) push(stack, d.value); }
  }
  return { __proto__: null, envelopes: out, over: false };
}
/** Selector envelopes reachable in a platform-created value (a read result): { envelopes, over }. */
function selectorsIn(root) { return envelopesReachable(root, true); }

/**
 * A key path evaluated on `c` (act §4): every segment an own data property of an ordinary object or array
 * node; an absent segment and every later one must be absent from the intrinsic `Object.prototype` and
 * `Array.prototype` (act §4, literally). Chromium evaluates key paths on own properties only (native probe
 * kp-probe, Chromium 131.0.6778.33: no inherited getter, data property or Proxy trap is ever consulted), so
 * the ancestors of `Array.prototype` are never walked: the two intrinsics are ordinary objects, and reading
 * their own descriptors runs no code of the port (D24) and needs no depth limit (D25). `''` is `c` itself.
 * Returns { safe, present, value }.
 */
function absentFromIntrinsics(key) {
  return C.gopd(C.ObjectProto, key) === undefined && C.gopd(C.ArrayProto, key) === undefined;
}
function evalKeyPath(c, path) {
  if (path === '') return { __proto__: null, safe: true, present: true, value: c };
  const segs = C.apply(C.split, path, ['.']);
  let node = c;
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    if (node === null || typeof node !== 'object') return { __proto__: null, safe: false };
    const b = brandOf(node);
    if (b !== null && b !== 'Array') return { __proto__: null, safe: false };
    const d = C.gopd(node, seg);
    if (d === undefined) {
      for (let j = i; j < segs.length; j++) if (!absentFromIntrinsics(segs[j])) return { __proto__: null, safe: false };
      return { __proto__: null, safe: true, present: false, at: i };
    }
    if (!isData(d)) return { __proto__: null, safe: false };
    node = d.value;
  }
  return { __proto__: null, safe: true, present: true, value: node };
}

/**
 * Store and index key paths on `c`: unsafe paths are outside D; the store's inline key must satisfy the key
 * rule of §3 step 2 (no array key path, no array key); an envelope reached as a key is attributed and
 * makes the write NON_CANONICAL_WRITE.
 */
export function checkKeyPaths(c, storeKeyPath, indexKeyPaths) {
  const reasons = []; const keyEnvelopes = []; let inline = null;
  const keyValue = (v, where) => {
    if (v === undefined) return;
    const k = classifyKey(v);
    if (!k.inD) push(reasons, `${where}:${k.reason}`);
    else for (let x = 0; x < k.envelopes.length; x++) { push(keyEnvelopes, k.envelopes[x]); push(reasons, 'envelope-in-key'); }
  };
  if (storeKeyPath !== null && storeKeyPath !== undefined) {
    if (C.isArray(storeKeyPath)) push(reasons, 'keypath-array');
    else {
      const r = evalKeyPath(c, storeKeyPath);
      if (!r.safe) push(reasons, 'keypath-unsafe');
      else { inline = { __proto__: null, present: r.present, value: r.value }; if (r.present) keyValue(r.value, 'inline-key'); }
    }
  }
  for (let x = 0; x < indexKeyPaths.length; x++) {
    const kp = indexKeyPaths[x]; const paths = C.isArray(kp) ? kp : [kp];
    for (let y = 0; y < paths.length; y++) {
      const p = paths[y];
      const r = evalKeyPath(c, p);
      if (!r.safe) push(reasons, 'index-keypath-unsafe');
      else if (r.present) {
        // An index key may be an array (array key, or one entry per element with multiEntry): every
        // Uint8Array reachable through array elements is a key candidate.
        const w = envelopesReachable(r.value, false);
        for (let z = 0; z < w.envelopes.length; z++) { push(keyEnvelopes, w.envelopes[z]); push(reasons, 'envelope-in-key'); }
        if (w.over) push(reasons, 'index-keypath-object-limit');
      }
    }
  }
  return { __proto__: null, reasons, keyEnvelopes, inline };
}

// ---- K19 durable identity (owner decision on #317 6384613341 §1, "Durable reconciliation") --------------
// The observer records, for every write request, the database, store and key it targets and a digest of
// the value it lets the native call store (the platform-created clone `c` of §3 step 4). A trusted reader
// in a later worker life, before any port is imported, encodes the durable keys and values with the same
// two functions, so the host can rebuild the durable state from the judged requests and compare. Both run
// on captured operations only (indexed reads of fresh typed arrays, captured reflection, string
// concatenation): no intrinsic the port can replace is called and no code of the port runs.

/** A deterministic identity of an IndexedDB key (binary keys of any view or buffer as bytes). */
export function keyEnc(k) {
  if (typeof k === 'string') return `s${k.length}:${k}`;
  if (typeof k === 'number') return `n:${k}`;
  if (k === null || typeof k !== 'object') return `?${typeof k}`;
  if (hasSlot(C.abByteLength, k)) { const n = C.apply(C.abByteLength, k, []); return `b:${hexOf(new C.U8(k), 0, n)}`; }
  if (C.apply(C.taTag, k, []) !== undefined) {
    const buf = C.apply(C.taBuffer, k, []); const off = C.apply(C.taByteOffset, k, []); const n = C.apply(C.taByteLength, k, []);
    return `b:${hexOf(new C.U8(buf, off, n), 0, n)}`;
  }
  if (hasSlot(C.dateGetTime, k)) return `d:${C.apply(C.dateGetTime, k, [])}`;
  if (C.isArray(k)) {
    const len = C.gopd(k, 'length').value; let s = 'a[';
    for (let i = 0; i < len; i++) { const d = C.gopd(k, `${i}`); s = s + (i > 0 ? ',' : '') + (isData(d) ? keyEnc(d.value) : '?'); }
    return `${s}]`;
  }
  return '?object';
}

/**
 * A canonical encoding of a platform-created value (a clone `c`, or a value read back from the store):
 * primitives with their type, exact Uint8Arrays as bytes, arrays and ordinary objects in own-key order,
 * aliases and cycles as back references; every other node is encoded by its brand only (such a value is
 * NON_CANONICAL_WRITE anyway). More than `limit` objects make the encoding opaque.
 */
export function canonicalValue(root, limit = OBJECT_LIMIT) {
  let out = ''; const ids = new C.WeakMapCtor(); let n = 0;
  const work = [{ __proto__: null, v: root }];
  while (work.length > 0) {
    const item = pop(work);
    if (item.t !== undefined) { out = out + item.t; continue; }
    const v = item.v;
    if (v === undefined) { out = `${out}U`; continue; }
    if (v === null) { out = `${out}N`; continue; }
    if (typeof v === 'boolean') { out = out + (v ? 'T' : 'F'); continue; }
    if (typeof v === 'number') { out = `${out}n${v === 0 && 1 / v < 0 ? '-0' : `${v}`};`; continue; }
    if (typeof v === 'bigint') { out = `${out}g${v};`; continue; }
    if (typeof v === 'string') { out = `${out}s${v.length}:${v}`; continue; }
    if (typeof v !== 'object') { out = `${out}X${typeof v};`; continue; }
    if (C.apply(C.wmHas, ids, [v])) { out = `${out}r${C.apply(C.wmGet, ids, [v])};`; continue; }
    C.apply(C.wmSet, ids, [v, n]);
    if (++n > limit) return `${out}L`;
    const brand = brandOf(v); const proto = C.getProto(v);
    if (brand === 'Uint8Array' && exactU8(v) === null) { const len = C.apply(C.taLength, v, []); out = `${out}u${len}:${hexOf(copyU8(v), 0, len)}`; continue; }
    if (brand === 'Array' && proto === C.ArrayProto) {
      const len = C.gopd(v, 'length').value; out = `${out}a${len}[`;
      push(work, { __proto__: null, t: ']' });
      for (let i = len - 1; i >= 0; i--) { const d = C.gopd(v, `${i}`); push(work, isData(d) ? { __proto__: null, v: d.value } : { __proto__: null, t: 'H' }); }
      continue;
    }
    if (brand === null && proto === C.ObjectProto) {
      const own = C.ownKeys(v); out = `${out}o${own.length}{`;
      push(work, { __proto__: null, t: '}' });
      for (let x = own.length - 1; x >= 0; x--) {
        const k = own[x];
        if (typeof k !== 'string') { push(work, { __proto__: null, t: 'Y' }); continue; }
        const d = C.gopd(v, k);
        push(work, isData(d) ? { __proto__: null, v: d.value } : { __proto__: null, t: 'A' });
        push(work, { __proto__: null, t: `k${k.length}:${k}` });
      }
      continue;
    }
    out = `${out}x${brand === null ? (proto === null ? 'null-proto' : 'proto') : brand};`;
  }
  return out;
}

// SHA-256 over the UTF-16 code units of a string (two bytes each, big-endian), on captured typed arrays.
const SHA_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
export function sha256Hex(str) {
  const len = str.length * 2; const total = ((len + 9 + 63) >> 6) << 6;
  const m = new C.U8(total);
  for (let i = 0; i < str.length; i++) { const c = C.apply(C.charCodeAt, str, [i]); m[2 * i] = c >> 8; m[2 * i + 1] = c & 255; }
  m[len] = 0x80;
  const bits = len * 8;
  const lo = bits >>> 0; const hi = (bits / 4294967296) >>> 0;
  for (let i = 0; i < 4; i++) { m[total - 1 - i] = (lo >>> (8 * i)) & 255; m[total - 5 - i] = (hi >>> (8 * i)) & 255; }
  const H = new C.U32(8); const init = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  for (let i = 0; i < 8; i++) H[i] = init[i];
  const W = new C.U32(64);
  const rotr = (x, r) => (x >>> r) | (x << (32 - r));
  for (let o = 0; o < total; o += 64) {
    for (let t = 0; t < 16; t++) W[t] = (m[o + 4 * t] << 24) | (m[o + 4 * t + 1] << 16) | (m[o + 4 * t + 2] << 8) | m[o + 4 * t + 3];
    for (let t = 16; t < 64; t++) {
      const a = W[t - 15]; const b = W[t - 2];
      W[t] = (W[t - 16] + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + W[t - 7] + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10))) >>> 0;
    }
    let a = H[0]; let b = H[1]; let c = H[2]; let d = H[3]; let e = H[4]; let f = H[5]; let g = H[6]; let h = H[7];
    for (let t = 0; t < 64; t++) {
      const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[t] + W[t]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  let s = '';
  for (let i = 0; i < 8; i++) for (let j = 3; j >= 0; j--) { const x = (H[i] >>> (8 * j)) & 255; s = s + HEX[x >> 4] + HEX[x & 15]; }
  return s;
}
/** The digest of a platform-created value: SHA-256 of its canonical encoding. */
export const digestValue = (v) => sha256Hex(canonicalValue(v));

function tamper(value) {
  if (value instanceof Uint8Array) { const c = value.slice(); if (c.length > 0) c[c.length - 1] ^= 0x01; return c; }
  if (value instanceof ArrayBuffer) return tamper(new Uint8Array(value)).buffer;
  if (Array.isArray(value)) return value.map(tamper);
  if (value !== null && typeof value === 'object') {
    const out = { __proto__: null };
    for (const k of Object.keys(value)) out[k] = tamper(value[k]);
    return out;
  }
  return value;
}
const carriesBytes = (v) => (v instanceof Uint8Array ? v.length > 0 : (v instanceof ArrayBuffer ? v.byteLength > 0
  : (Array.isArray(v) ? v.some(carriesBytes) : (v !== null && typeof v === 'object' ? Object.values(v).some(carriesBytes) : false))));

const READS = ['get', 'getAll', 'getAllKeys', 'getKey', 'count', 'openCursor', 'openKeyCursor'];

/**
 * Install the observer and the kill/fault instrumentation. `state`: { armed, section, fault, tamperAt,
 * plan: { [txIndex]: lastRequestIndex }, trace: [], next: 0, reads: 0, onWrite(record), onOpen(id, tx),
 * portCalls }.
 */
export function instrument({ hook, state }) {
  const N = C.native;
  /** An IDBFactory receiver (brand check without side effect: the native cmp of two numbers). */
  const isFactory = (x) => N.F.cmp !== undefined && !throws(function f() { C.apply(N.F.cmp, x, [0, 0]); }, undefined);
  const info = new C.WeakMapCtor(); // armed readwrite transaction -> { id, requests, trace, section }
  const owner = new C.WeakMapCtor(); // every transaction -> lifetime record
  const temporal = new C.WeakMapCtor();
  const tampered = new C.WeakMapCtor(); // request -> read index
  const txList = []; // every transaction lifetime, armed or not, in open order (act §5)
  const observerErrors = [];
  let seq = 0; let requestId = 0; let txId = 0;
  const tick = () => ++seq;
  const session = Array.from(C.apply(C.getRandomValues, C.crypto, [new Uint8Array(8)]), (x) => x.toString(16).padStart(2, '0')).join('');
  const listen = (target, type, fn) => C.apply(C.addEventListener, target, [type, fn]);
  let activeClone = null; // { rec, tx } while one value is being cloned (act §3 step 4)
  const installed = []; // [proto, key, kind ('value'|'set'), fn]
  // K19 continuous collection (owner decision on #317 6384613341 §1): every write record, versionchange
  // schema record and selector read of this worker life, from instrument() on, whatever is attached later.
  const allWrites = []; const allSchema = []; const allReads = []; const lateLog = [];
  const vcOf = new C.WeakMapCtor(); // connection -> lifetime of its running versionchange transaction

  /**
   * K19 closure: once the final audit closed this life (`state.closed`), every IndexedDB call the
   * observer wraps is an observer error. It is recorded and reported to the host synchronously, before
   * the native call, through the existing /hook channel with captured bindings only, so a request that
   * then fails, aborts or leaves no durable effect is still reported.
   */
  function late(op) {
    const seq = tick();
    push(lateLog, { __proto__: null, op, seq });
    if (C.XHR === undefined) return;
    try {
      const d = `{"k19late":true,"life":"${session}","op":"${op}","seq":${seq}}`;
      const x = new C.XHR();
      C.apply(C.xhrOpen, x, ['GET', `/hook?p=K19%3ALATE&d=${C.apply(C.encodeURIComponent, undefined, [d])}`, false]);
      C.apply(C.xhrSend, x, []);
    } catch { push(observerErrors, `late request ${op} after the final audit could not be reported`); }
  }
  const install = (proto, key, fn) => {
    const g = function wrapped(...a) { if (state.closed === true) late(key); return C.apply(fn, this, a); };
    proto[key] = g; push(installed, [proto, key, 'value', g]);
  };
  const installSetter = (proto, key, nativeSet) => {
    const d = C.gopd(proto, key);
    const fn = proto === C.S && key === 'name'
      ? function set(v) { reentrant(`set:${key}`, null); return renameStore(this, nativeSet, v); }
      : function set(v) { reentrant(`set:${key}`, null); return C.apply(nativeSet, this, [v]); };
    C.defineProperty(proto, key, { __proto__: null, configurable: true, enumerable: d.enumerable, get: ownField(d, 'get') ? d.get : undefined, set: fn });
    push(installed, [proto, key, 'set', fn]);
  };
  /**
   * D23 (K19 durable identity): `IDBObjectStore.name` set in a versionchange transaction renames the store
   * with its content. The native setter runs unchanged; when it returns and the name changed, a schema
   * record `renameObjectStore { from, store }` is added to the transaction, ordered by its sequence number
   * among the requests and schema changes of that transaction.
   */
  function renameStore(store, nativeSet, v) {
    let tx = null;
    try { tx = C.apply(C.storeTx, store, []); } catch { tx = null; }
    if (tx === null) return C.apply(nativeSet, store, [v]); // not an IDBObjectStore: the native setter throws
    // The WebIDL DOMString conversion of the new name, once, before the native setter (as the binding does
    // first): user code it runs (a nested rename included) happens before `from` is read (review R3).
    const name = domString(v);
    let from = null; try { from = C.apply(C.storeName, store, []); } catch { from = null; }
    const r = C.apply(nativeSet, store, [name]);
    if (tx === null) return r;
    let to = null; try { to = C.apply(C.storeName, store, []); } catch { to = null; }
    if (to !== from) {
      if (C.apply(C.wmGet, owner, [tx]) === undefined) adopt(tx);
      const lt = C.apply(C.wmGet, owner, [tx]);
      let db = null; try { db = dbNameOf(C.apply(C.txDb, tx, [])); } catch { db = null; }
      schemaRecord(lt, { method: 'renameObjectStore', db, from, store: to, opaque: to === null || from === null });
    }
    return r;
  }
  /** Act §3 step 4: any wrapped IndexedDB call during a clone. True when it targets the cloned transaction. */
  function reentrant(name, tx) {
    if (activeClone === null) return false;
    activeClone.rec.nonCanonical = true;
    push(activeClone.rec.reasons, `reentrant:${name}`);
    return tx !== null && tx === activeClone.tx;
  }
  const inactive = () => new C.DOMException('the transaction is inactive while its value is cloned', 'TransactionInactiveError');
  const observerError = (what) => { push(observerErrors, what); };

  // ---- tamper (T9) on request results --------------------------------------------------------------------
  const resultGetter = C.requestResult;
  const tamperedResult = function result() {
      const v = C.apply(resultGetter, this, []);
      if (!C.apply(C.wmHas, tampered, [this])) return v;
      const { k, trace } = C.apply(C.wmGet, tampered, [this]);
      let seen = false; for (let x = 0; x < trace.length; x++) if (trace[x].ev === 'TAMPERED' && trace[x].k === k) seen = true;
      if (!seen) push(trace, { __proto__: null, ev: 'TAMPERED', k, changed: carriesBytes(v) });
      return tamper(v);
  };
  C.defineProperty(C.R, 'result', { __proto__: null, configurable: true, enumerable: C.gopd(C.R, 'result').enumerable, get: tamperedResult });
  push(installed, [C.R, 'result', 'get', tamperedResult]);

  /** The terminal event of a transaction, on every write and schema record it holds. */
  function settleRecords(lifetime, ev) {
    for (let x = 0; x < lifetime.writes.length; x++) { lifetime.writes[x].terminal = ev; lifetime.writes[x].terminalSeq = lifetime.terminalSeq; }
    for (let x = 0; x < lifetime.schema.length; x++) { lifetime.schema[x].terminal = ev; lifetime.schema[x].terminalSeq = lifetime.terminalSeq; }
  }
  const dbNameOf = (db) => { try { return C.apply(C.dbName, db, []); } catch { return null; } };
  /** A schema record (K19 durable identity): database creation/upgrade, object store creation/deletion, database deletion. */
  function schemaRecord(lifetime, fields) {
    const s = { __proto__: null, token: `${session}:schema${requestId++}`, kind: 'schema', section: state.section, txg: lifetime === null ? null : lifetime.gid,
      status: 'success', terminal: null, terminalSeq: null, seq: tick(), settledSeq: null, inPortCall: (state.portCalls ?? 0) > 0, ...fields };
    if (lifetime !== null) push(lifetime.schema, s);
    push(allSchema, s);
    return s;
  }
  /** A transaction not opened through IDBDatabase.transaction (versionchange): tracked from its upgradeneeded or first write. */
  function adopt(tx) {
    let mode = null; try { mode = C.apply(C.txMode, tx, []); } catch { mode = null; }
    const lifetime = { __proto__: null, gid: txId++, openSeq: tick(), mode, section: state.section, trace: state.trace, armed: state.armed,
      writes: [], schema: [], terminal: null, terminalSeq: null, adopted: true };
    C.apply(C.wmSet, owner, [tx, lifetime]);
    push(txList, lifetime);
    const terminal = (ev) => { lifetime.terminal = ev; lifetime.terminalSeq = tick(); settleRecords(lifetime, ev); };
    listen(tx, 'complete', () => terminal('complete'));
    listen(tx, 'abort', () => terminal('abort'));
  }
  // ---- transactions ----------------------------------------------------------------------------------------
  install(C.D, 'transaction', function transaction(...args) {
    reentrant('transaction', null);
    const tx = C.apply(N.D.transaction, this, args);
    const mode = C.apply(C.txMode, tx, []);
    const lifetime = { __proto__: null, gid: txId++, openSeq: tick(), mode, section: state.section, trace: state.trace, armed: state.armed,
      writes: [], schema: [], terminal: null, terminalSeq: null };
    C.apply(C.wmSet, owner, [tx, lifetime]);
    push(txList, lifetime);
    const terminal = (ev) => { lifetime.terminal = ev; lifetime.terminalSeq = tick(); settleRecords(lifetime, ev); };
    listen(tx, 'complete', () => terminal('complete'));
    listen(tx, 'abort', () => terminal('abort'));
    if (!state.armed || mode !== 'readwrite') return tx;
    const id = state.next++;
    const { trace, section } = state;
    C.apply(C.wmSet, info, [tx, { __proto__: null, id, requests: 0, trace, section }]);
    lifetime.armedId = id;
    const current = () => state.section === section;
    const names = C.apply(C.txStoreNames, tx, []); const stores = [];
    for (let i = 0; i < C.apply(C.listLength, names, []); i++) push(stores, C.apply(C.listItem, names, [i]));
    const meta = { __proto__: null, stores, durability: C.apply(C.txDurability, tx, []) };
    push(trace, { __proto__: null, tx: id, ev: 'OPEN', ...meta });
    listen(tx, 'complete', () => { push(trace, { __proto__: null, tx: id, ev: 'COMPLETE' }); if (current()) hook(`T${id}:COMPLETE`); });
    listen(tx, 'abort', () => { push(trace, { __proto__: null, tx: id, ev: 'ABORT' }); });
    if (typeof state.onOpen === 'function') state.onOpen(id, tx);
    hook(`T${id}:OPEN`, meta);
    return tx;
  });
  install(C.T, 'commit', function commit(...args) {
    if (reentrant('commit', this)) throw new C.DOMException('the transaction is inactive while its value is cloned', 'InvalidStateError');
    const r = C.apply(N.T.commit, this, args);
    const t = C.apply(C.wmGet, info, [this]);
    if (t !== undefined) { push(t.trace, { __proto__: null, tx: t.id, ev: 'COMMIT_SENT' }); if (state.section === t.section) hook(`T${t.id}:COMMIT_SENT`); }
    return r;
  });
  // abort() is natively allowed on an inactive transaction: during the clone of its own value it is
  // deferred until the native write call returned (the request is created, then fails with AbortError).
  install(C.T, 'abort', function abort(...args) {
    if (reentrant('abort', this)) {
      if (activeClone.deferredAbort) throw new C.DOMException('the transaction was already aborted', 'InvalidStateError');
      activeClone.deferredAbort = this; return undefined;
    }
    return C.apply(N.T.abort, this, args);
  });
  for (const k of ['objectStore']) install(C.T, k, function m(...a) { reentrant(k, null); return C.apply(N.T[k], this, a); });
  if (N.D.close) install(C.D, 'close', function m(...a) { reentrant('close', null); return C.apply(N.D.close, this, a); });
  // K19 (durable identity): the schema changes of a versionchange transaction are recorded on it.
  if (N.D.createObjectStore) install(C.D, 'createObjectStore', function m(...a) {
    reentrant('createObjectStore', null);
    const store = C.apply(N.D.createObjectStore, this, a);
    let name = null; try { name = C.apply(C.storeName, store, []); } catch { name = null; }
    const lt = C.apply(C.wmGet, vcOf, [this]);
    schemaRecord(lt === undefined ? null : lt, { method: 'createObjectStore', db: dbNameOf(this), store: name, opaque: lt === undefined || name === null });
    return store;
  });
  if (N.D.deleteObjectStore) install(C.D, 'deleteObjectStore', function m(...a) {
    reentrant('deleteObjectStore', null);
    // The name the native call uses: the WebIDL DOMString conversion, done once here after the brand check
    // and before the native call, exactly where the binding does it (review R2: a non-string name).
    const name = a.length > 0 && hasSlot(C.dbName, this) ? domString(a[0]) : null;
    const r = C.apply(N.D.deleteObjectStore, this, name === null ? a : [name]);
    const lt = C.apply(C.wmGet, vcOf, [this]);
    schemaRecord(lt === undefined ? null : lt, { method: 'deleteObjectStore', db: dbNameOf(this), store: name, opaque: lt === undefined || name === null });
    return r;
  });
  if (N.F.open) install(C.F, 'open', function m(...a) {
    reentrant('open', null);
    const req = C.apply(N.F.open, this, a);
    // Registered before the caller can set its own handlers: the versionchange transaction is adopted
    // before any schema change or write of the upgrade runs.
    listen(req, 'upgradeneeded', (ev) => {
      let tx = null; let db = null;
      try { tx = C.apply(C.requestTx, req, []); db = C.apply(resultGetter, req, []); } catch { tx = null; }
      if (tx === null || db === null) { observerError('an upgradeneeded event without its transaction'); return; }
      if (C.apply(C.wmGet, owner, [tx]) === undefined) adopt(tx);
      const lt = C.apply(C.wmGet, owner, [tx]);
      C.apply(C.wmSet, vcOf, [db, lt]);
      let oldVersion = null; let newVersion = null;
      try { oldVersion = C.apply(C.vcOld, ev, []); newVersion = C.apply(C.vcNew, ev, []); } catch { oldVersion = null; }
      schemaRecord(lt, { method: 'upgrade', db: dbNameOf(db), oldVersion, newVersion, opaque: newVersion === null });
    });
    return req;
  });
  if (N.F.deleteDatabase) install(C.F, 'deleteDatabase', function m(...a) {
    reentrant('deleteDatabase', null);
    const name = a.length > 0 && isFactory(this) ? domString(a[0]) : null; // as deleteObjectStore (review R2)
    const req = C.apply(N.F.deleteDatabase, this, name === null ? a : [name]);
    const s = schemaRecord(null, { method: 'deleteDatabase', db: name, status: 'pending', opaque: name === null });
    listen(req, 'success', () => { s.status = 'success'; s.settledSeq = tick(); });
    listen(req, 'error', () => { s.status = 'error'; s.settledSeq = tick(); });
    return req;
  });
  for (const k of ['databases', 'cmp']) if (N.F[k]) install(C.F, k, function m(...a) { reentrant(k, null); return C.apply(N.F[k], this, a); });
  for (const [proto, key, s] of C.setters) installSetter(proto, key, s);
  for (const k of ['createIndex', 'deleteIndex', 'index']) {
    install(C.S, k, function m(...a) {
      let tx = null; try { tx = C.apply(C.storeTx, this, []); } catch { reentrant(k, null); return C.apply(N.S[k], this, a); }
      if (reentrant(k, k === 'index' ? null : tx)) throw inactive();
      return C.apply(N.S[k], this, a);
    });
  }

  const replayAbort = (clone) => { if (clone.deferredAbort) { const t = clone.deferredAbort; clone.deferredAbort = undefined; C.apply(N.T.abort, t, []); } };
  const keyPathsOf = (store) => {
    const out = []; const names = C.apply(C.storeIndexNames, store, []);
    const n = C.apply(C.listLength, names, []);
    for (let i = 0; i < n; i++) push(out, C.apply(C.indexKeyPath, C.apply(N.S.index, store, [C.apply(C.listItem, names, [i])]), []));
    return out;
  };
  const storeOfSource = (src) => { try { C.apply(C.storeTx, src, []); return src; } catch { return C.apply(C.indexStore, src, []); } };

  /** After a native request was issued: lifecycle, item-6 temporal accounting. */
  function issued(tx, r, w) {
    if (w !== null) {
      w.issued = true; w.status = 'pending'; w.issuedSeq = tick();
      listen(r, 'success', () => {
        w.status = 'success'; w.settledSeq = tick();
        // K19 durable identity: the key the request wrote is its result (put, add, cursor update).
        if (w.method === 'put' || w.method === 'add' || w.method === 'update') { try { w.key = keyEnc(C.apply(resultGetter, r, [])); } catch { w.key = null; } }
      });
      listen(r, 'error', () => { w.status = 'error'; w.settledSeq = tick(); try { const e = C.apply(C.requestError, r, []); w.error = e === null ? 'UnknownError' : errorName(e); } catch { w.error = 'UnknownError'; } });
    }
    const t = C.apply(C.wmGet, temporal, [tx]);
    if (t !== undefined) {
      t.pending++; t.generation++; t.check();
      const finish = () => { t.pending--; t.check(); };
      listen(r, 'success', finish); listen(r, 'error', finish);
    }
    return r;
  }

  /** The write record, created before any code of the caller can run (act §3 step 1; K12). */
  function record(tx, store, method) {
    if (C.apply(C.wmGet, owner, [tx]) === undefined) adopt(tx);
    const o = C.apply(C.wmGet, owner, [tx]); const t = C.apply(C.wmGet, info, [tx]);
    let name = null; try { name = C.apply(C.storeName, store, []); } catch { name = null; }
    const w = { __proto__: null, token: `${session}:request${requestId++}`, section: o?.section ?? null, tx: t?.id ?? null, txg: o?.gid ?? null,
      method, store: name, attempted: true, issued: false, status: 'attempted', terminal: null, attribution: 'complete',
      nonCanonical: false, reasons: [], envelopes: [], seq: tick(), inPortCall: (state.portCalls ?? 0) > 0,
      kind: 'write', db: dbNameOf(C.apply(C.txDb, tx, [])), key: null, digest: null, opaque: false, terminalSeq: null };
    push(allWrites, w); // K19: collected whatever collector the worker attaches, from instrument() on
    if (typeof state.onWrite === 'function') state.onWrite(w);
    if (o !== undefined) push(o.writes, w);
    return w;
  }
  const nonCanonical = (w, reason) => { w.nonCanonical = true; w.attribution = 'non-canonical'; push(w.reasons, reason); };
  const addEnvelopes = (w, list) => {
    for (let i = 0; i < list.length; i++) {
      let dup = false;
      for (let j = 0; j < w.envelopes.length; j++) if (w.envelopes[j].envelope === list[i].envelope) dup = true;
      if (!dup) push(w.envelopes, list[i]);
    }
  };

  /**
   * One value-carrying write (`put`, `add`, cursor `update`) through act §3 steps 2-6. `kargs` is [] or
   * [key]; `injected` replaces step 6 by the PUT_THROW fault.
   */
  function valueWrite(self, native, method, tx, store, args, injected) {
    const w = record(tx, store, method);
    const hasKey = method !== 'update' && args.length > 1 && args[1] !== undefined;
    let kargs = [];
    if (hasKey) {
      const k = classifyKey(args[1]);
      if (!k.inD) {
        nonCanonical(w, k.reason); w.opaque = true;
        let r; try { r = C.apply(native, self, args); } catch (e) { w.status = 'throw'; w.error = errorName(e); throw e; }
        return issued(tx, r, w);
      }
      if (k.envelopes.length > 0) { addEnvelopes(w, k.envelopes); nonCanonical(w, 'envelope-in-key'); }
      kargs = [k.key]; w.key = keyEnc(k.key);
    }
    if (method === 'update') { try { w.key = keyEnc(C.apply(C.cursorPrimaryKey, self, [])); } catch { w.key = null; } }
    // Step 3: the native pre-clone checks, with an uncloneable sentinel. Nothing is issued.
    let pre;
    const preArgs = [SENTINEL]; if (kargs.length > 0) push(preArgs, kargs[0]);
    try { pre = C.apply(native, self, preArgs); } catch (e) {
      const n = errorName(e);
      if (n !== 'DataCloneError') { w.status = 'PRECLONE_REJECTED'; w.error = n; throw e; }
      pre = undefined;
    }
    if (pre !== undefined) {
      w.status = 'observer-error'; w.observerError = 'the sentinel pre-call returned a request';
      observerError(`${w.token}: the sentinel pre-call returned a request`);
      throw new C.Error('B-CHR observer error: the sentinel pre-call returned a request');
    }
    // Step 4: the single clone.
    const previous = activeClone;
    const clone = { __proto__: null, rec: w, tx, deferredAbort: undefined };
    activeClone = clone;
    let c;
    try { c = C.apply(C.structuredClone, undefined, [args[0]]); } catch (e) {
      activeClone = previous;
      nonCanonical(w, `clone:${errorName(e)}`); w.status = 'throw'; w.error = errorName(e);
      replayAbort(clone);
      throw e;
    }
    activeClone = previous;
    // Step 5: D on the clone and on every key path.
    const k = classifyClone(c);
    w.digest = digestValue(c); // K19 durable identity: the value the native call stores is `c`
    for (let x = 0; x < k.reasons.length; x++) nonCanonical(w, k.reasons[x]);
    addEnvelopes(w, k.envelopes);
    let kp; let storeKeyPath = null; let autoIncrement = false;
    try {
      const target = method === 'update' ? storeOfSource(C.apply(C.cursorSource, self, [])) : store;
      storeKeyPath = C.apply(C.storeKeyPath, target, []); autoIncrement = C.apply(C.storeAutoIncrement, target, []) === true;
      kp = checkKeyPaths(c, storeKeyPath, keyPathsOf(target));
    } catch (e) { kp = { __proto__: null, reasons: [`keypath-inspection:${errorName(e)}`], keyEnvelopes: [], inline: null }; }
    for (let x = 0; x < kp.reasons.length; x++) nonCanonical(w, kp.reasons[x]);
    addEnvelopes(w, kp.keyEnvelopes);
    // K19 durable identity (D26): the key the write targets, as soon as it is determined before issuance
    // (an explicit key above, a cursor's primary key, or the inline key on `c`, evaluated on own properties
    // as Chromium does); a generated key is known only from the request's result.
    if (w.key === null && kp.inline !== null && kp.inline.present && kp.inline.value !== undefined) { const ik = classifyKey(kp.inline.value); if (ik.inD) w.key = keyEnc(ik.key); }
    // D22: an inline key path with a key generator and no key in `c`: the stored value is `c` with the
    // generated key injected along the key path, as the native store does; the digest follows on success.
    // (A key-path property present with the value undefined is not a missing key: Chromium 131 throws
    // DataError, request case plan-inline-auto-undefined-key.)
    const inject = method !== 'update' && kargs.length === 0 && autoIncrement && typeof storeKeyPath === 'string' && storeKeyPath !== ''
      && kp.inline !== null && !kp.inline.present ? storeKeyPath : null;
    w.objects = k.objects;
    // Step 6: the native call with c (or the injected fault).
    let r;
    try {
      if (injected) throw new C.DOMException('injected request failure', 'UnknownError');
      const callArgs = [c]; if (kargs.length > 0) push(callArgs, kargs[0]);
      r = C.apply(native, self, callArgs);
    } catch (e) { w.status = 'throw'; w.error = errorName(e); throw e; } finally { replayAbort(clone); }
    issued(tx, r, w);
    if (inject !== null) listen(r, 'success', () => { try { injectKey(c, inject, C.apply(resultGetter, r, [])); w.digest = digestValue(c); } catch { w.digest = null; w.opaque = true; } });
    return r;
  }
  /** Inject a generated key into the observer's own clone `c` along `path` (missing objects created). */
  function injectKey(c, path, key) {
    const segs = C.apply(C.split, path, ['.']);
    let node = c;
    for (let i = 0; i < segs.length - 1; i++) {
      const d = C.gopd(node, segs[i]);
      if (isData(d)) { node = d.value; continue; }
      const o = {};
      C.defineProperty(node, segs[i], { __proto__: null, value: o, writable: true, enumerable: true, configurable: true });
      node = o;
    }
    C.defineProperty(node, segs[segs.length - 1], { __proto__: null, value: key, writable: true, enumerable: true, configurable: true });
  }

  /** store.delete(key): key rule of §3 step 2; cursor.delete() and store.clear(): recorded. */
  function keyWrite(self, native, method, tx, store, args) {
    const w = record(tx, store, method);
    let call = args;
    if (method === 'delete') {
      const k = classifyKey(args[0]);
      if (!k.inD) { nonCanonical(w, k.reason); w.opaque = true; } else {
        if (k.envelopes.length > 0) { addEnvelopes(w, k.envelopes); nonCanonical(w, 'envelope-in-key'); }
        call = [k.key]; w.key = keyEnc(k.key);
      }
    }
    if (method === 'cursor-delete') { try { w.key = keyEnc(C.apply(C.cursorPrimaryKey, self, [])); } catch { w.opaque = true; } }
    let r;
    try { r = C.apply(native, self, call); } catch (e) { w.status = 'throw'; w.error = errorName(e); throw e; }
    return issued(tx, r, w);
  }

  const isRead = (n) => n === 'get' || n === 'getAll' || n === 'getAllKeys' || n === 'getKey' || n === 'count' || n === 'openCursor' || n === 'openKeyCursor';
  const readFault = () => state.armed && (state.fault === 'READ_FAIL' || state.fault === 'TAMPER');
  const currentOwner = (tx) => {
    const o = C.apply(C.wmGet, owner, [tx]);
    return o !== undefined && o.armed && state.armed && o.section === state.section ? o : null;
  };

  // ---- object store requests: kill points, faults, observer ----------------------------------------------
  for (const name of ['put', 'add', 'delete', 'clear', ...READS]) {
    const native = N.S[name];
    if (typeof native !== 'function') continue;
    install(C.S, name, function request(...args) {
      let tx;
      try { tx = C.apply(C.storeTx, this, []); } catch { reentrant(name, null); return C.apply(native, this, args); } // brand check failed
      if ((name === 'put' || name === 'add' || name === 'delete') && args.length === 0) { reentrant(name, null); return C.apply(native, this, args); }
      if (reentrant(name, tx)) throw inactive();
      const mode = C.apply(C.txMode, tx, []);
      const mine = currentOwner(tx);
      if (mine !== null && isRead(name) && readFault() && state.fault === 'READ_FAIL') {
        push(mine.trace, { __proto__: null, ev: 'FAULT', fault: 'READ_FAIL', op: name });
        throw new C.DOMException('injected read failure', 'UnknownError');
      }
      const run = (injected) => {
        if (name === 'put' || name === 'add') return valueWrite(this, native, name, tx, this, args, injected);
        if (name === 'delete' || name === 'clear') return keyWrite(this, native, name, tx, this, args);
        const rr = issued(tx, C.apply(native, this, args), null);
        if (name === 'get' || name === 'getAll') {
          // Item 10 (red-team Fase 4): every selector envelope a read returns is known from then on; a later
          // write of it is a reused nonce. The native result getter is read in our own listener.
          listen(rr, 'success', () => {
            let v; try { v = C.apply(resultGetter, rr, []); } catch { return; }
            const found = selectorsIn(v); const at = tick();
            // D19 (read side): a result beyond the object limit is reported, never read as "no envelope".
            if (found.over) push(allReads, { __proto__: null, envelope: null, nonce: null, limit: true, seq: at, via: name });
            for (let q = 0; q < found.envelopes.length; q++) {
              const seen = { __proto__: null, envelope: found.envelopes[q].envelope, nonce: found.envelopes[q].nonce, seq: at, via: name };
              push(allReads, seen); if (typeof state.onRead === 'function') state.onRead(seen);
            }
          });
        }
        return rr;
      };
      const t = C.apply(C.wmGet, info, [tx]);
      if (t === undefined) {
        const r = run(false);
        if (mine !== null && mode === 'readonly') {
          const k = state.reads++;
          push(mine.trace, { __proto__: null, ev: 'READ', k, op: name });
          if (state.fault === 'TAMPER' && (state.tamperAt === null || state.tamperAt === k || (state.tamperAt === 'REST' && k >= 1))) C.apply(C.wmSet, tampered, [r, { __proto__: null, k, trace: mine.trace }]);
          hook(`R${k}`);
        }
        return r;
      }
      const j = t.requests++;
      const current = state.section === t.section;
      push(t.trace, { __proto__: null, tx: t.id, ev: 'REQ', j, op: name, store: C.apply(C.storeName, this, []) });
      if (current) hook(`T${t.id}:R${j}`);
      const injected = current && state.fault === 'PUT_THROW' && name === 'put' && !state.faulted;
      if (injected) {
        state.faulted = true;
        push(t.trace, { __proto__: null, tx: t.id, ev: 'FAULT', fault: 'PUT_THROW', j });
      }
      const r = run(injected);
      if (current && isRead(name) && readFault()) {
        const k = state.reads++;
        push(state.trace, { __proto__: null, ev: 'READ', k, op: name, tx: t.id });
        if (state.tamperAt === null || state.tamperAt === k || (state.tamperAt === 'REST' && k >= 1)) C.apply(C.wmSet, tampered, [r, { __proto__: null, k, trace: state.trace }]);
      }
      if (current && state.plan[t.id] === j) hook(`T${t.id}:END`);
      return r;
    });
  }
  // Index requests: re-entrancy only.
  for (const name of READS) {
    const native = N.I[name];
    if (typeof native !== 'function') continue;
    install(C.I, name, function request(...args) {
      let tx; try { tx = C.apply(C.storeTx, C.apply(C.indexStore, this, []), []); } catch { reentrant(name, null); return C.apply(native, this, args); }
      if (reentrant(name, tx)) throw inactive();
      return issued(tx, C.apply(native, this, args), null);
    });
  }
  // Cursor: update (value-carrying), delete (recorded), navigation (re-entrancy only).
  const cursorTx = (cur) => C.apply(C.storeTx, storeOfSource(C.apply(C.cursorSource, cur, [])), []);
  for (const name of ['update', 'delete', 'continue', 'advance', 'continuePrimaryKey']) {
    const native = N.CU[name];
    if (typeof native !== 'function') continue;
    install(C.CU, name, function cursor(...args) {
      let tx; let store;
      try { store = storeOfSource(C.apply(C.cursorSource, this, [])); tx = cursorTx(this); } catch { reentrant(`cursor.${name}`, null); return C.apply(native, this, args); }
      if (name === 'update' && args.length === 0) { reentrant(`cursor.${name}`, null); return C.apply(native, this, args); }
      if (reentrant(`cursor.${name}`, tx)) throw inactive();
      if (name === 'update') return valueWrite(this, native, 'update', tx, store, args, false);
      if (name === 'delete') return keyWrite(this, native, 'cursor-delete', tx, store, args);
      return C.apply(native, this, args);
    });
  }

  /** Act §3: at the end of every operation the observer checks that its wrappers are installed. */
  function checkInstalled() {
    const failures = [];
    for (let x = 0; x < installed.length; x++) {
      const proto = installed[x][0]; const key = installed[x][1]; const kind = installed[x][2]; const fn = installed[x][3];
      // D20: only the descriptor's OWN field counts: a data descriptor owning `value` for a method wrapper,
      // an accessor descriptor owning `set`/`get` for an accessor wrapper (an inherited field is never read).
      const d = C.gopd(proto, key);
      const field = kind === 'value' ? 'value' : kind;
      const now = ownField(d, field) ? (kind === 'value' ? d.value : (kind === 'set' ? d.set : d.get)) : undefined;
      if (now !== fn) push(failures, `observer error: the wrapper ${String(key)} is not installed`);
    }
    for (let x = 0; x < observerErrors.length; x++) push(failures, observerErrors[x]);
    observerErrors.length = 0;
    return failures;
  }

  const KEEP_ALIVE_KEY = 'styx-bchr-harness-keepalive';
  function keepAlive(tx, until, ms, diagnostic = () => {}) {
    let stop = false; let committed = false;
    const timer = callGlobal(C.setTimeout, () => { diagnostic({ __proto__: null, kind: 'timeout' }); end(); }, ms);
    const end = () => { stop = true; callGlobal(C.clearTimeout, timer); };
    listen(tx, 'complete', end); listen(tx, 'abort', end);
    C.apply(C.promiseThen, C.apply(C.promiseResolve, C.Promise, [until]), [end, end]);
    let store;
    try { store = C.apply(N.T.objectStore, tx, [C.apply(C.listItem, C.apply(C.txStoreNames, tx, []), [0])]); } catch (e) { diagnostic({ __proto__: null, kind: 'store-error', error: errorName(e) }); end(); return; }
    const ping = () => {
      if (stop) return;
      let r;
      try { r = C.apply(N.S.get, store, [KEEP_ALIVE_KEY]); } catch (e) {
        committed = errorName(e) === 'TransactionInactiveError';
        diagnostic({ __proto__: null, kind: committed ? 'inactive' : 'read-throw', error: errorName(e) }); end(); return;
      }
      listen(r, 'success', ping);
      listen(r, 'error', () => { diagnostic({ __proto__: null, kind: 'read-error', error: C.apply(C.requestError, r, [])?.name }); end(); });
    };
    ping();
  }
  // OPEN/POST are points, not a universal observation interval. The real port
  // path proof is separately required for transient promotions and output exits.
  function watchTransaction(tx, sample, recordAnswer, ms = 5000) {
    const i = { __proto__: null, pending: 0, generation: 0, closed: false, scheduled: false, post: [], check };
    C.apply(C.wmSet, temporal, [tx, i]);
    let finish; const until = new C.Promise((resolve) => { finish = resolve; });
    let openDone = false; let postDone = false;
    const stopIfReady = () => { if (openDone && postDone && i.pending === 0) finish(); };
    const now = () => C.apply(C.performanceNow, C.performance, []);
    const capture = async (phase, generation) => {
      const at = now();
      let answer;
      try {
        const h = await sample();
        answer = { __proto__: null, phase, generation, requestedAt: at, answeredAt: now(), late: i.closed,
          invalidated: phase === 'POST' && generation !== i.generation, held: h !== null };
      } catch (e) { answer = { __proto__: null, phase, generation, late: true, error: String(e?.code ?? e?.message ?? e) }; }
      recordAnswer(answer); if (phase === 'POST') push(i.post, answer);
      return answer;
    };
    function check() {
      for (let x = 0; x < i.post.length; x++) if (i.post[x].generation !== i.generation) i.post[x].invalidated = true;
      if (i.closed || i.pending || i.scheduled) return;
      i.scheduled = true; const g = i.generation;
      callGlobal(C.setTimeout, async () => {
        i.scheduled = false;
        if (i.closed) return;
        if (i.pending || g !== i.generation) { check(); return; }
        const a = await capture('POST', g);
        if (a.invalidated) { check(); return; }
        postDone = true; stopIfReady();
      }, 0);
    }
    const terminal = () => { i.closed = true; finish(); };
    listen(tx, 'complete', terminal); listen(tx, 'abort', terminal);
    keepAlive(tx, until, ms, (d) => recordAnswer({ __proto__: null, phase: 'AUX', diagnostic: d }));
    C.apply(C.promiseThen, capture('OPEN', i.generation), [() => { openDone = true; stopIfReady(); }]);
    check();
    return until;
  }
  /** Transactions (armed or not) and their write records, for the act §5 correspondence. */
  const transactions = () => txList;
  return { __proto__: null, keepAlive, watchTransaction, tick, transactions, checkInstalled,
    // K19: the continuous collection of this worker life and its identity.
    writes: allWrites, schema: allSchema, reads: allReads, lateLog, session };
}

/**
 * K19 continuous collection (owner decision on #317 6384613341 §1): in the B-CHR dedicated worker, the
 * observer is installed here, at the top-level evaluation of this module, which worker.mjs imports
 * before every other module and so before the port module is imported. It collects every request of the
 * worker life until the worker is terminated; worker.mjs attaches its harness hook to `state.hook`.
 * Other importers (observer-cases.mjs, Node) get `null` and call instrument() themselves.
 */
const WORKER_PATH = (() => {
  try { return typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope ? new URL(self.location.href).pathname : null; } catch { return null; }
})();
export const WORKER_OBSERVER = WORKER_PATH !== '/suite/worker.mjs' ? null : (() => {
  const state = { armed: false, section: 0, fault: null, tamperAt: null, plan: {}, trace: [], probes: [], pending: [], next: 0, reads: 0, faulted: false,
    onOpen: null, onWrite: null, onRead: null, portCalls: 0, closed: false, initialized: false, hook: null };
  const api = instrument({ hook: (p, d) => { if (state.armed && typeof state.hook === 'function') state.hook(p, d); }, state });
  return Object.freeze({ __proto__: null, state, api });
})();
