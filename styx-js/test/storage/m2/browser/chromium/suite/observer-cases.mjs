// Permanent native discriminants of the substituted-clone observer (owner act v2 on #317, §3-§6; attack
// classes K1-K19; K19 per the owner act on #317 6379513740). No product hook or alternative port ABI. Each case runs in a fresh DEDICATED WORKER
// (like the port), once without the observer (native baseline) and once with it; observer-regressions.mjs
// compares the two under the act §3 non-interference rule and asserts the expected conformance verdict
// below. The K9 (other realm) cases run in the page, where an iframe gives a second realm.
// instrument.mjs is imported FIRST: its top-level evaluation captures the intrinsics (act §3).
import { append, instrument } from './instrument.mjs';
import { decodeEnvelope, M2_KIND } from '/src/storage/m2/session-codec.js';
import { nonceBook } from './expectations.mjs';

// Captured before any case runs, for the case harness itself (a K6 case replaces intrinsics).
const H = Object.freeze({
  addEventListener: EventTarget.prototype.addEventListener, put: globalThis.IDBObjectStore?.prototype.put, apply: Reflect.apply,
});
const on = (t, type, fn) => H.apply(H.addEventListener, t, [type, fn]);
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export function selectorBytes(bytes) {
  try {
    const e = decodeEnvelope(bytes);
    return e.recordKind === M2_KIND.GENERATION_SELECTOR ? { envelope: hex(bytes), nonce: hex(e.nonce) } : null;
  } catch { return null; }
}

/**
 * Expected verdict per case (act §4/§6), fixed before the cases were run:
 *   v: 'NCW' (NON_CANONICAL_WRITE), 'ACCEPTED' (no failure), 'NONCE' (rejected for nonce reuse or
 *      collision), 'OBSERVER_ERROR' (an observer error, never PASS);
 *   env: the number of distinct selector envelopes attributed to issued requests (when given);
 *   ni: false for the two exclusions of act §3 (calls during the clone; storage-only types) and for
 *       cases whose fault exists only with the observer; otherwise baseline and observer must match;
 *   k: the attack class; coi: run only in a cross-origin-isolated context; page: run in the page (K9).
 */
export const EXPECTED = Object.freeze({
  // K15 / in-D controls
  'control-envelope': { k: 'K15', v: 'ACCEPTED', env: 1 },
  'control-generation': { k: 'K15', v: 'ACCEPTED', env: 1 },
  'control-alias-cycle': { k: 'K15', v: 'ACCEPTED', env: 1 },
  'control-deep40': { k: 'K15', v: 'ACCEPTED', env: 1 },
  'control-array': { k: 'K15', v: 'ACCEPTED', env: 1 },
  'control-null-proto': { k: 'K15', v: 'ACCEPTED', env: 1 },
  // historical regressions (act §6)
  alias: { k: 'K15', v: 'ACCEPTED', env: 1 },
  cycle: { k: 'K15', v: 'ACCEPTED', env: 1 },
  deep: { k: 'K15', v: 'NONCE', env: 1 },
  map: { k: 'K3', v: 'NCW' },
  set: { k: 'K3', v: 'NCW' },
  view: { k: 'K8', v: 'NCW' },
  'view-shadow-getter': { k: 'K8', v: 'NCW' },
  collision: { k: 'K15', v: 'NONCE' },
  getter: { k: 'K1', v: 'ACCEPTED', env: 1 },
  'mixed-getter': { k: 'K1', v: 'NONCE' },
  'self-delete': { k: 'K1', v: 'ACCEPTED', env: 1 },
  'graph-mutation': { k: 'K1', v: 'ACCEPTED', env: 1 },
  overwrite: { k: 'K11', v: 'NONCE' },
  delete: { k: 'K10', v: 'ACCEPTED', env: 1 },
  generated: { k: 'K10', v: 'ACCEPTED', env: 1 },
  'generated-twice': { k: 'K10', v: 'NONCE', env: 1 },
  inline: { k: 'K10', v: 'ACCEPTED', env: 1 },
  'inline-getter': { k: 'K1', v: 'ACCEPTED', env: 1 },
  'clone-error': { k: 'K3', v: 'NCW' },
  'put-throw': { k: 'K11', v: 'ACCEPTED', env: 0, ni: false },
  'request-error': { k: 'K11', v: 'NONCE' },
  'error-prevent': { k: 'K11', v: 'NONCE' },
  'abort-before': { k: 'K11', v: 'ACCEPTED', env: 1 },
  'abort-after': { k: 'K11', v: 'ACCEPTED', env: 1 },
  commit: { k: 'K11', v: 'ACCEPTED', env: 1 },
  'callback-write': { k: 'K11', v: 'NONCE' },
  add: { k: 'K10', v: 'ACCEPTED', env: 1 },
  // K1 getters
  'getter-throws': { k: 'K1', v: 'NCW' },
  // K2 changed prototypes
  'u8-proto-object': { k: 'K2', v: 'ACCEPTED', env: 1 },
  'map-proto-null': { k: 'K2', v: 'NCW' },
  'map-proto-object': { k: 'K2', v: 'NCW' },
  'set-proto-object': { k: 'K2', v: 'NCW' },
  'set-proto-null': { k: 'K2', v: 'NCW' },
  'dataview-proto-object': { k: 'K2', v: 'NCW' },
  // K3 hidden slots and platform objects
  date: { k: 'K3', v: 'NCW' }, regexp: { k: 'K3', v: 'NCW' }, error: { k: 'K3', v: 'NCW' },
  'number-wrapper': { k: 'K3', v: 'NCW' }, 'string-wrapper': { k: 'K3', v: 'NCW' }, 'boolean-wrapper': { k: 'K3', v: 'NCW' },
  'bigint-wrapper': { k: 'K3', v: 'NCW' }, float32: { k: 'K3', v: 'NCW' }, arraybuffer: { k: 'K3', v: 'NCW' },
  blob: { k: 'K3', v: 'NCW' }, file: { k: 'K3', v: 'NCW' }, dommatrix: { k: 'K3', v: 'NCW' }, imagedata: { k: 'K3', v: 'NCW' },
  cryptokey: { k: 'K3', v: 'NCW' }, 'message-port': { k: 'K3', v: 'NCW' }, function: { k: 'K3', v: 'NCW' },
  'filesystem-handle': { k: 'K3', v: 'NCW' },
  // K4 fake objects with a built-in prototype
  'fake-date-proto-object': { k: 'K4', v: 'NCW' },
  'fake-date-object-create': { k: 'K4', v: 'ACCEPTED', env: 1 },
  // K5 Proxy
  'proxy-root': { k: 'K5', v: 'NCW' }, 'proxy-nested': { k: 'K5', v: 'NCW' }, 'proxy-self-replacing': { k: 'K5', v: 'NCW' },
  'proxy-revoked': { k: 'K5', v: 'NCW' }, 'proxy-array': { k: 'K5', v: 'NCW' },
  'key-proxy-array': { k: 'K5', v: 'NCW' }, 'key-proxy-u8': { k: 'K5', v: 'NCW' }, 'delete-proxy-array': { k: 'K5', v: 'NCW' },
  // K6 intrinsics and wrappers changed after start
  'inherited-setter': { k: 'K6', v: 'ACCEPTED', env: 1 },
  'tostringtag-getter': { k: 'K6', v: 'NCW' },
  'intrinsics-replaced': { k: 'K6', v: 'ACCEPTED', env: 1 },
  'wrapper-removed': { k: 'K6', v: 'OBSERVER_ERROR', ni: false },
  'inherited-descriptor-get': { k: 'K6', v: 'ACCEPTED', env: 1 },
  // K7
  'symbol-key-nonenum': { k: 'K7', v: 'ACCEPTED', env: 0 },
  // K8 buffers and views
  'u8-partial-window': { k: 'K8', v: 'NCW' }, 'u8-extra-prop': { k: 'K8', v: 'ACCEPTED', env: 1 },
  'resizable-ab': { k: 'K8', v: 'NCW' }, 'u8-detached': { k: 'K8', v: 'NCW' },
  'u8-on-sab': { k: 'K8', v: 'NCW', coi: true }, 'sab-then-getter': { k: 'K18', v: 'NCW', ni: false, coi: true },
  'coi-control': { k: 'K8', v: 'ACCEPTED', env: 1, coi: true },
  // K9 other realm (page + iframe)
  'realm-u8': { k: 'K9', v: 'ACCEPTED', env: 1, page: true },
  'realm-object': { k: 'K9', v: 'ACCEPTED', env: 1, page: true },
  'realm-map': { k: 'K9', v: 'NCW', page: true },
  'realm-getter': { k: 'K9', v: 'ACCEPTED', env: 1, page: true },
  // K10 keys, key paths, indexes, arity
  'key-nan': { k: 'K10', v: 'NCW' }, 'key-bigint': { k: 'K10', v: 'NCW' }, 'key-date': { k: 'K10', v: 'NCW' },
  'key-cyclic': { k: 'K10', v: 'NCW' }, 'key-u8': { k: 'K10', v: 'ACCEPTED', env: 0 }, 'key-u8-envelope': { k: 'K10', v: 'NCW' },
  'key-array-ok': { k: 'K10', v: 'NCW' }, 'key-array-hole': { k: 'K10', v: 'NCW' }, 'key-object': { k: 'K10', v: 'NCW' },
  'key-array-getter': { k: 'K10', v: 'NCW' }, 'key-array-twice-getter': { k: 'K10', v: 'NCW' },
  'key-array-extra-getter': { k: 'K10', v: 'NCW' }, 'key-u8-mutated-by-value-getter': { k: 'K10', v: 'ACCEPTED', env: 0 },
  'key-u8-partial': { k: 'K10', v: 'NCW' },
  'delete-string': { k: 'K10', v: 'ACCEPTED', env: 1 }, 'delete-keyrange': { k: 'K10', v: 'NCW' },
  'delete-array-getter': { k: 'K10', v: 'NCW' }, 'delete-u8-envelope': { k: 'K10', v: 'NCW' },
  'keypath-inherited-getter': { k: 'K10', v: 'NCW' }, 'index-inherited-getter': { k: 'K10', v: 'NCW' },
  'inline-key-envelope': { k: 'K10', v: 'NCW' }, 'index-envelope': { k: 'K10', v: 'NCW' },
  // Red-team Fase 4 (Argon R3, R4, R7)
  // D7 revisited (consensus plan C3b): Chromium evaluates key paths on own properties only, so a getter on
  // an ancestor of Array.prototype is never run natively (DataError, 0 getters, in both arms); the value is
  // in D under act v2 §4 (absent from the intrinsic Object.prototype and Array.prototype). `thrown` pins the
  // native own-property semantics: if Chromium ever read inherited key-path properties, this turns red.
  'keypath-array-proto-chain-getter': { k: 'K10', v: 'ACCEPTED', env: 0, thrown: 'DataError' },
  'index-multientry-array-envelope': { k: 'K10', v: 'NCW', env: 1 }, 'index-array-envelope': { k: 'K10', v: 'NCW', env: 1 },
  'throwing-getter-custom-error-name': { k: 'K6', v: 'NCW' },
  // Red-team Fase 4 (Sol r3 #1, #3)
  'inherited-record-objects-setter': { k: 'K6', v: 'ACCEPTED', env: 1 }, 'getter-throws-name-accessor': { k: 'K1', v: 'NCW', env: 0 },
  'keypath-empty-string': { k: 'K10', v: 'ACCEPTED', env: 0 }, 'keypath-empty-u8-envelope': { k: 'K10', v: 'NCW' },
  'keypath-empty-array': { k: 'K10', v: 'NCW' }, 'keypath-array': { k: 'K10', v: 'NCW' },
  'arity-put-none': { k: 'K10', v: 'ACCEPTED', env: 0 }, 'arity-delete-none': { k: 'K10', v: 'ACCEPTED', env: 0 },
  'arity-update-none': { k: 'K10', v: 'ACCEPTED', env: 0 },
  'cursor-update-valid': { k: 'K10', v: 'ACCEPTED', env: 1 }, 'cursor-update-readonly': { k: 'K11', v: 'ACCEPTED', env: 0 },
  'cursor-update-after-continue': { k: 'K11', v: 'ACCEPTED', env: 0 }, 'cursor-update-keycursor': { k: 'K11', v: 'ACCEPTED', env: 0 },
  'cursor-update-inline-changed': { k: 'K10', v: 'ACCEPTED', env: 0 }, 'cursor-update-map': { k: 'K10', v: 'NCW' },
  'cursor-delete': { k: 'K10', v: 'ACCEPTED', env: 1 }, clear: { k: 'K10', v: 'ACCEPTED', env: 1 },
  // K11 pre-clone ordering and lifecycle
  'order-valid': { k: 'K11', v: 'ACCEPTED', env: 1 }, 'order-readonly': { k: 'K11', v: 'ACCEPTED', env: 0 },
  'order-inactive': { k: 'K11', v: 'ACCEPTED', env: 0 }, 'order-finished': { k: 'K11', v: 'ACCEPTED', env: 0 },
  'order-keypath-and-key': { k: 'K11', v: 'ACCEPTED', env: 0 }, 'order-no-key': { k: 'K11', v: 'ACCEPTED', env: 0 },
  'order-key-nan': { k: 'K11', v: 'NCW' }, 'order-key-object': { k: 'K11', v: 'NCW' },
  'order-inline-missing': { k: 'K11', v: 'ACCEPTED', env: 0 }, 'order-autoinc-nonobject': { k: 'K10', v: 'NCW' },
  'order-add-duplicate': { k: 'K11', v: 'ACCEPTED', env: 1 }, 'order-deleted-store': { k: 'K11', v: 'ACCEPTED', env: 0 },
  'order-readonly-key-getter': { k: 'K11', v: 'NCW' },
  'outside-D-sync-throw': { k: 'K11', v: 'NCW' }, 'outside-D-preclone': { k: 'K11', v: 'NCW' },
  // K14 limits
  'objects-4096': { k: 'K14', v: 'ACCEPTED', env: 1 }, 'objects-4097': { k: 'K14', v: 'NCW' },
  // K18 calls during the clone; storage-only types
  'reentrant-put': { k: 'K18', v: 'NCW', ni: false }, 'reentrant-get': { k: 'K18', v: 'NCW', ni: false },
  'reentrant-objectStore': { k: 'K18', v: 'NCW', ni: false }, 'reentrant-commit': { k: 'K18', v: 'NCW', ni: false },
  'reentrant-abort': { k: 'K18', v: 'NCW', ni: false }, 'reentrant-double-abort': { k: 'K18', v: 'NCW', ni: false },
  'reentrant-abort-then-objectStore': { k: 'K18', v: 'NCW', ni: false }, 'reentrant-get-noarg': { k: 'K18', v: 'NCW', ni: false },
  'reentrant-other-tx': { k: 'K18', v: 'NCW', ni: false }, 'reentrant-other-tx-get': { k: 'K18', v: 'NCW', ni: false },
  'reentrant-transaction': { k: 'K18', v: 'NCW', ni: false }, 'reentrant-createIndex-nonupgrade': { k: 'K18', v: 'NCW', ni: false },
  'reentrant-createIndex-upgrade': { k: 'K18', v: 'NCW', ni: false }, 'reentrant-handler-setter': { k: 'K18', v: 'NCW', ni: false },
  'reentrant-put-noarg': { k: 'K18', v: 'NCW', ni: false },
  'wasm-module': { k: 'K18', v: 'NCW', ni: false }, 'wasm-then-getter': { k: 'K18', v: 'NCW', ni: false },
  'getter-then-wasm': { k: 'K18', v: 'NCW', ni: false }, 'wasm-then-throwing-getter': { k: 'K18', v: 'NCW', ni: false },
  'audiodata-then-getter': { k: 'K18', v: 'NCW', ni: false }, 'videoframe-then-getter': { k: 'K18', v: 'NCW', ni: false },
  'encoded-video-chunk-then-getter': { k: 'K18', v: 'NCW', ni: false }, 'encoded-audio-chunk-then-getter': { k: 'K18', v: 'NCW', ni: false },
  'wasm-shared-memory': { k: 'K18', v: 'NCW', ni: false, coi: true },
  // K19 coverage of the audit (owner act on #317 6379513740 §2): every write request is judged, armed or
  // not, in every transaction mode including versionchange.
  'k19-versionchange-ncw': { k: 'K19', v: 'NCW' }, 'k19-versionchange-ok': { k: 'K19', v: 'ACCEPTED', env: 1 },
  'k19-versionchange-delete-envelope': { k: 'K19', v: 'NCW' }, 'k19-versionchange-cursor-map': { k: 'K19', v: 'NCW' },
  'k19-versionchange-clear': { k: 'K19', v: 'ACCEPTED', env: 0 }, 'k19-versionchange-key-nan': { k: 'K19', v: 'NCW' },
  'k19-armed-ncw': { k: 'K19', v: 'NCW' }, 'k19-armed-ok': { k: 'K19', v: 'ACCEPTED', env: 1 },
  'k19-unarmed-later-tx-ncw': { k: 'K19', v: 'NCW' },
  // red-team K19 round, Sol (REVIEW-SOL-k19.md), literal probes
  'review-wide-index-false': { k: 'K10', v: 'NCW', env: 1 },
  'review-wide-index-true': { k: 'K10', v: 'NCW', env: 1 },
  'review-wrapper-descriptor-spoof': { k: 'K6', v: 'OBSERVER_ERROR' },
  'review-prototype-proxy': { k: 'K6', v: 'ACCEPTED', env: 0 },
  'review-long-prototype-chain': { k: 'K14', v: 'ACCEPTED', env: 0 },
  // consensus plan (CONSENSO-PIANO.md): variants of the same classes
  'plan-wide-index-alias': { k: 'K10', v: 'NCW', env: 1 }, 'plan-wide-index-nested': { k: 'K10', v: 'NCW', env: 1 },
  'plan-wide-index-control': { k: 'K10', v: 'ACCEPTED', env: 1 },
  'plan-descriptor-spoof-set': { k: 'K6', v: 'OBSERVER_ERROR' },
  'plan-object-prototype-value-control': { k: 'K6', v: 'ACCEPTED', env: 1 },
  'plan-index-own-only': { k: 'K10', v: 'ACCEPTED', env: 0, native: [{ status: 'success', result: 'k' }, { status: 'success', result: 0 }] },
  'plan-inline-auto-explicit-key-abort': { k: 'K19', v: 'ACCEPTED', env: 0, recordKey: 'n:7' },
  'plan-inline-auto-undefined-key': { k: 'K19', v: 'ACCEPTED', env: 0, thrown: 'DataError' },
  // final consensus review (REVISIONE-FINALE, Astra R1), literal
  'final-nonselector-header': { k: 'K16', v: 'ACCEPTED', env: 0 },
});

// ---- case definitions ------------------------------------------------------------------------------------
const WASM = () => new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** Each case: { schema, run(x) } with x = { db, tx, store, c: { n, traps, inner }, ENV(), OTHER(), track(r), done, name }. */
const CASES = {};
const put = (name, make, schema = {}, key = 'k') => {
  CASES[name] = { schema, run: (x) => { const v = make(x); return x.track(schema.store?.keyPath !== undefined || key === null ? x.store.put(v) : x.store.put(v, key)); } };
};
const G = (x, val) => ({ get envelope() { x.c.n++; return val; } });
const tryInner = (x, f) => { try { f(); x.c.inner.push('ok'); } catch (e) { x.c.inner.push(e.name); } };
put('control-envelope', (x) => x.ENV());
put('control-generation', (x) => ({ nonce: new Uint8Array(12), ct: x.ENV() }));
put('control-alias-cycle', (x) => { const o = { a: x.ENV() }; o.b = o.a; o.self = o; return o; });
put('control-deep40', (x) => { let v = x.ENV(); for (let i = 0; i < 40; i++) v = { a: v }; return v; });
put('control-array', (x) => [x.ENV(), 1, 'x', null, true, 2n, undefined]);
put('control-null-proto', (x) => Object.assign(Object.create(null), { e: x.ENV() }));
put('alias', (x) => { const e = x.ENV(); return { a: e, b: e.slice() }; });
put('cycle', (x) => { const v = { envelope: x.ENV() }; v.self = v; return v; });
const twice = (name, make) => { CASES[name] = { schema: {}, run: (x) => { const v = make(x); x.track(x.store.put(v, 'k')); return x.track(x.store.put(v, 'k')); } }; };
twice('deep', (x) => { let v = x.ENV(); for (let i = 0; i < 40; i++) v = { a: v }; return v; });
twice('map', (x) => { const e = x.ENV(); return new Map([[e, { a: e }]]); });
twice('set', (x) => new Set([x.ENV()]));
twice('view', (x) => { const e = x.ENV(); const b = new Uint8Array(e.length + 8); b.set(e, 3); return new DataView(b.buffer, 3, e.length); });
twice('view-shadow-getter', (x) => { const e = x.ENV(); const v = new DataView(e.buffer, e.byteOffset, e.byteLength); const fake = new ArrayBuffer(e.buffer.byteLength); Object.defineProperty(v, 'buffer', { get() { x.c.n++; return fake; } }); return v; });
put('collision', (x) => ({ envelope: x.ENV(), other: x.OTHER() }));
put('getter', (x) => ({ get envelope() { x.c.n++; return x.c.n === 1 ? x.ENV() : null; } }));
// mixed-getter (act §6): the getter returns a second envelope whose nonce collides with the visible one.
put('mixed-getter', (x) => ({ visible: x.ENV(), get hidden() { x.c.n++; return x.OTHER(); } }));
put('self-delete', (x) => ({ get hidden() { x.c.n++; delete this.hidden; return x.ENV(); } }));
put('graph-mutation', (x) => ({ first: x.ENV(), get hidden() { x.c.n++; this.first = x.OTHER(); return null; } }));
CASES.overwrite = { schema: {}, run: (x) => { x.track(x.store.put({ envelope: x.ENV() }, 'k')); return x.track(x.store.put({ envelope: x.OTHER() }, 'k')); } };
CASES.delete = { schema: {}, run: (x) => { x.track(x.store.put({ envelope: x.ENV() }, 'k')); return x.track(x.store.delete('k')); } };
put('generated', (x) => ({ envelope: x.ENV() }), { store: { autoIncrement: true } }, null);
// Direct discriminant (Phase 2): the sentinel pre-call never consumes the key generator; the generated
// keys (request results and durable keys) must equal the baseline's.
CASES['generated-twice'] = { schema: { store: { autoIncrement: true } }, run: (x) => {
  const v = { envelope: x.ENV() };
  x.track(x.store.put(v)); return x.track(x.store.put(v));
} };
put('inline', (x) => ({ id: 'k', envelope: x.ENV() }), { store: { keyPath: 'id' } });
put('inline-getter', (x) => ({ get id() { x.c.n++; return 'k'; }, envelope: x.ENV() }), { store: { keyPath: 'id' } });
put('clone-error', (x) => ({ envelope: x.ENV(), fn: () => {} }));
CASES['put-throw'] = { schema: {}, fault: 'PUT_THROW', run: (x) => x.track(x.store.put({ envelope: x.ENV() }, 'k')) };
for (const name of ['request-error', 'error-prevent']) {
  CASES[name] = { schema: { indexes: [['unique', 'unique', { unique: true }]] }, run: (x) => {
    const p = (v, k) => { const r = x.store.put(v, k); if (name === 'error-prevent') on(r, 'error', (ev) => ev.preventDefault()); return x.track(r); };
    p({ envelope: x.ENV(), unique: 1 }, 'a'); return p({ envelope: x.OTHER(), unique: 1 }, 'b');
  } };
}
CASES['abort-before'] = { schema: {}, run: (x) => { const r = x.track(x.store.put({ envelope: x.ENV() }, 'k')); x.tx.abort(); return r; } };
CASES['abort-after'] = { schema: {}, run: (x) => { const r = x.track(x.store.put({ envelope: x.ENV() }, 'k')); on(r, 'success', () => x.tx.abort()); return r; } };
CASES.commit = { schema: {}, run: (x) => { const r = x.track(x.store.put({ envelope: x.ENV() }, 'k')); x.tx.commit(); return r; } };
CASES['callback-write'] = { schema: {}, run: (x) => { const r = x.track(x.store.put({ envelope: x.ENV() }, 'k')); on(r, 'success', () => x.track(x.store.put({ envelope: x.OTHER() }, 'later'))); return r; } };
CASES.add = { schema: {}, run: (x) => x.track(x.store.add({ envelope: x.ENV() }, 'k')) };
put('getter-throws', (x) => ({ e: x.ENV(), get g() { x.c.n++; throw new RangeError('boom'); } }));
put('u8-proto-object', (x) => Object.setPrototypeOf(x.ENV(), Object.prototype));
put('map-proto-null', (x) => Object.setPrototypeOf(new Map([['envelope', x.ENV()]]), null));
put('map-proto-object', (x) => Object.setPrototypeOf(new Map([['envelope', x.ENV()]]), Object.prototype));
put('set-proto-object', (x) => Object.setPrototypeOf(new Set([x.ENV()]), Object.prototype));
put('set-proto-null', (x) => Object.setPrototypeOf(new Set([x.ENV()]), null));
put('dataview-proto-object', (x) => Object.setPrototypeOf(new DataView(x.ENV().buffer), Object.prototype));
put('date', (x) => ({ d: new Date(1), e: x.ENV() }));
put('regexp', () => /x/g);
put('error', () => new TypeError('x'));
put('number-wrapper', () => Object(1)); put('string-wrapper', () => Object('s')); put('boolean-wrapper', () => Object(true));
put('bigint-wrapper', () => Object(1n));
put('float32', (x) => new Float32Array(x.ENV().slice(0, 32).buffer));
put('arraybuffer', (x) => x.ENV().buffer);
put('blob', (x) => new Blob([x.ENV()]));
put('file', (x) => new File([x.ENV()], 'f'));
put('dommatrix', () => new DOMMatrix());
put('imagedata', () => new ImageData(1, 1));
put('cryptokey', (x) => ({ k: x.cryptoKey, e: x.ENV() }));
put('message-port', () => new MessageChannel().port1);
put('function', (x) => ({ e: x.ENV(), f() {} }));
put('filesystem-handle', (x) => ({ h: x.fsHandle, e: x.ENV() }));
put('fake-date-proto-object', () => Object.setPrototypeOf(new Date(12345), Object.prototype));
put('fake-date-object-create', (x) => Object.assign(Object.create(Date.prototype), { e: x.ENV() }));
const trapped = (x, t) => new Proxy(t, { ownKeys(o) { x.c.traps++; return Reflect.ownKeys(o); }, getPrototypeOf(o) { x.c.traps++; return Reflect.getPrototypeOf(o); }, get(o, k) { x.c.traps++; return o[k]; } });
put('proxy-root', (x) => trapped(x, { e: x.ENV() }));
put('proxy-nested', (x) => ({ a: trapped(x, { e: x.ENV() }) }));
put('proxy-self-replacing', (x) => { const root = { a: null }; root.a = new Proxy({}, { getPrototypeOf(t) { x.c.traps++; root.a = x.ENV(); return Reflect.getPrototypeOf(t); }, ownKeys() { x.c.traps++; root.a = x.ENV(); return []; } }); return root; });
put('proxy-revoked', () => { const p = Proxy.revocable({}, {}); p.revoke(); return { a: p.proxy }; });
put('proxy-array', (x) => new Proxy([x.ENV()], { get(t, k) { x.c.traps++; return t[k]; } }));
CASES['inherited-setter'] = { schema: {}, run: (x) => {
  Object.defineProperty(Object.prototype, 'envelope', { configurable: true, get() { return undefined; }, set() { x.c.n++; } });
  Object.defineProperty(Array.prototype, '0', { configurable: true, get() { return undefined; }, set() { x.c.n++; } });
  try { return x.track(x.store.put({ envelope: x.ENV(), list: [x.ENV()] }, 'k')); } finally { delete Object.prototype.envelope; delete Array.prototype['0']; }
} };
CASES['tostringtag-getter'] = { schema: {}, run: (x) => {
  Object.defineProperty(Object.prototype, Symbol.toStringTag, { configurable: true, get() { x.c.n++; return 'Object'; } });
  try { return x.track(x.store.put({ d: Object.setPrototypeOf(new Date(1), Object.prototype), e: x.ENV() }, 'k')); } finally { delete Object.prototype[Symbol.toStringTag]; }
} };
// K6: every intrinsic the observer uses, replaced after instrument() (the observer captured them). The
// native write path calls none of them, so the baseline sees no trap either.
CASES['intrinsics-replaced'] = { schema: {}, run: (x) => {
  const v = { envelope: x.ENV(), list: [1, 2] };
  const saved = [];
  const def = Object.defineProperty; const gopd = Object.getOwnPropertyDescriptor;
  const keep = (o, k) => def(saved, saved.length, { value: [o, k, gopd(o, k)], writable: true, enumerable: true, configurable: true });
  const swap = (o, k, val) => { keep(o, k); def(o, k, { configurable: true, writable: true, value: val }); };
  const swapGet = (o, k, g) => { keep(o, k); def(o, k, { configurable: true, get: g }); };
  const TA = Object.getPrototypeOf(Uint8Array.prototype);
  const bad = () => { x.c.traps++; throw new Error('replaced intrinsic called'); };
  const restore = Reflect.defineProperty; const del = Reflect.deleteProperty;
  let r;
  try {
    swap(Array.prototype, 'push', bad); swap(Array.prototype, 'pop', bad); swap(Array.prototype, Symbol.iterator, bad);
    swap(Array.prototype, 'includes', bad); swap(Array.prototype, 'some', bad); swap(Array, 'isArray', bad);
    swap(Reflect, 'apply', bad); swap(Reflect, 'ownKeys', bad); swap(Reflect, 'getOwnPropertyDescriptor', bad);
    swap(Reflect, 'getPrototypeOf', bad); swap(Object, 'getPrototypeOf', bad);
    swap(WeakMap.prototype, 'get', bad); swap(WeakMap.prototype, 'set', bad); swap(WeakMap.prototype, 'has', bad);
    swap(Map.prototype, 'get', bad); swap(Map.prototype, 'set', bad); swap(Map.prototype, 'has', bad);
    swap(globalThis, 'structuredClone', () => { x.c.traps++; return { forged: true }; });
    swap(String.prototype, 'split', bad); swap(String.prototype, 'charCodeAt', bad); swap(TA, 'set', bad);
    swapGet(TA, Symbol.toStringTag, bad); swapGet(TA, 'buffer', bad); swapGet(TA, 'length', bad); swapGet(TA, 'byteOffset', bad);
    swapGet(ArrayBuffer.prototype, 'byteLength', bad); swapGet(Map.prototype, 'size', bad);
    swap(EventTarget.prototype, 'addEventListener', bad); swap(Number, 'isNaN', bad);
    swap(Reflect, 'defineProperty', bad);
    r = x.store.put(v, 'k');
  } finally {
    for (let i = saved.length - 1; i >= 0; i--) { const o = saved[i][0]; const k = saved[i][1]; const d = saved[i][2]; if (d === undefined) del(o, k); else restore(o, k, d); }
  }
  return x.track(r);
} };
CASES['wrapper-removed'] = { schema: {}, run: (x) => { IDBObjectStore.prototype.put = H.put; return x.track(x.store.put({ envelope: x.ENV() }, 'k')); } };
put('symbol-key-nonenum', (x) => { const o = { [Symbol('s')]: x.ENV() }; Object.defineProperty(o, 'h', { value: x.ENV(), enumerable: false }); return o; });
put('u8-partial-window', (x) => { const e = x.ENV(); const b = new Uint8Array(e.length * 2); b.set(e, 0); return new Uint8Array(b.buffer, 0, e.length); });
put('u8-extra-prop', (x) => { const u = x.ENV(); u.x = 1; return u; });
put('resizable-ab', (x) => { const e = x.ENV(); const b = new ArrayBuffer(e.length, { maxByteLength: e.length * 2 }); new Uint8Array(b).set(e); return new Uint8Array(b); });
put('u8-detached', (x) => { const e = x.ENV(); structuredClone(e.buffer, { transfer: [e.buffer] }); return { e }; });
put('u8-on-sab', (x) => { const e = x.ENV(); const u = new Uint8Array(new SharedArrayBuffer(e.length)); u.set(e); return u; });
put('sab-then-getter', (x) => ({ s: new SharedArrayBuffer(8), get g() { x.c.n++; return 1; } }));
put('coi-control', (x) => ({ envelope: x.ENV() }));
const keyCase = (name, key, make = () => ({ e: 1 })) => { CASES[name] = { schema: {}, run: (x) => x.track(x.store.put(make(x), key(x))) }; };
keyCase('key-nan', () => NaN); keyCase('key-bigint', () => 10n); keyCase('key-date', () => new Date(1));
keyCase('key-cyclic', () => { const a = []; a.push(a); return a; });
keyCase('key-u8', () => Uint8Array.from([1, 2, 3, 4]));
keyCase('key-u8-envelope', (x) => x.ENV());
keyCase('key-u8-partial', () => new Uint8Array(new Uint8Array(8).buffer, 2, 4));
keyCase('key-array-ok', (x) => ['a', 1, x.ENV()]);
keyCase('key-array-hole', () => [1, , 2]); // eslint-disable-line no-sparse-arrays
keyCase('key-object', () => ({}));
keyCase('key-array-getter', (x) => { const a = ['x']; Object.defineProperty(a, 0, { get() { x.c.n++; return x.c.n === 1 ? 'safe' : 'other'; }, enumerable: true }); return a; });
keyCase('key-proxy-array', (x) => new Proxy(['safe'], { get(t, k) { x.c.traps++; return t[k]; }, getOwnPropertyDescriptor(t, k) { x.c.traps++; return Reflect.getOwnPropertyDescriptor(t, k); } }));
keyCase('key-proxy-u8', (x) => new Proxy(Uint8Array.from([1, 2, 3]), { get(t, k) { x.c.traps++; const v = Reflect.get(t, k, t); return typeof v === 'function' ? v.bind(t) : v; }, getPrototypeOf(t) { x.c.traps++; return Reflect.getPrototypeOf(t); }, ownKeys(t) { x.c.traps++; return Reflect.ownKeys(t); } }));
keyCase('key-array-twice-getter', (x) => { const a = [0]; Object.defineProperty(a, 0, { enumerable: true, get() { x.c.n++; return x.c.n === 1 ? () => {} : 'k'; } }); return a; });
keyCase('key-array-extra-getter', (x) => { const a = ['k']; Object.defineProperty(a, 'extra', { enumerable: true, get() { x.c.n++; return 'x'; } }); return a; });
CASES['key-u8-mutated-by-value-getter'] = { schema: {}, run: (x) => { const k = Uint8Array.from([1, 2, 3, 4]); return x.track(x.store.put({ get g() { x.c.n++; k[0] ^= 0xff; return 1; } }, k)); } };
const delCase = (name, key) => { CASES[name] = { schema: {}, run: (x) => { x.track(x.store.put({ envelope: x.ENV() }, 'k')); return x.track(x.store.delete(key(x))); } }; };
delCase('delete-string', () => 'k'); delCase('delete-keyrange', () => IDBKeyRange.only('k'));
delCase('delete-proxy-array', (x) => new Proxy(['k'], { get(t, k) { x.c.traps++; return t[k]; } }));
delCase('delete-array-getter', (x) => { const a = ['x']; Object.defineProperty(a, 0, { get() { x.c.n++; return 'k'; }, enumerable: true }); return a; });
delCase('delete-u8-envelope', (x) => x.ENV());
CASES['keypath-inherited-getter'] = { schema: { store: { keyPath: 'id' } }, run: (x) => {
  Object.defineProperty(Object.prototype, 'id', { configurable: true, get() { x.c.n++; return `k-${x.c.n}`; } });
  try { return x.track(x.store.put({ a: 1 })); } finally { delete Object.prototype.id; }
} };
CASES['index-inherited-getter'] = { schema: { indexes: [['ix', 'idx']] }, run: (x) => {
  Object.defineProperty(Object.prototype, 'idx', { configurable: true, get() { x.c.n++; return x.ENV(); } });
  try { return x.track(x.store.put({ a: 1 }, 'k')); } finally { delete Object.prototype.idx; }
} };
put('inline-key-envelope', (x) => ({ id: x.ENV() }), { store: { keyPath: 'id' } });
put('index-envelope', (x) => ({ e: x.ENV() }), { indexes: [['ie', 'e']] });
// Red-team Fase 4 (Argon R3): a getter on a prototype inserted above Array.prototype.
CASES['keypath-array-proto-chain-getter'] = {
  schema: { store: { keyPath: 'id' }, indexes: [['idx', 'idx']] },
  run: (x) => {
    Object.setPrototypeOf(Array.prototype, {
      get id() { x.c.n++; return x.ENV(); },
      get idx() { x.c.n++; return x.ENV(); },
    });
    return x.track(x.store.put([1, 2]));
  },
};
// Red-team Fase 4 (Argon R4): an index key path that yields an array holding the envelope.
put('index-multientry-array-envelope', (x) => ({ e: [x.ENV()] }), { indexes: [['ie', 'e', { multiEntry: true }]] });
put('index-array-envelope', (x) => ({ e: [x.ENV()] }), { indexes: [['ie', 'e']] });
// Red-team Fase 4 (Sol r3 #1): an inherited setter for a field the observer adds to its own record.
CASES['inherited-record-objects-setter'] = {
  schema: {},
  run: (x) => {
    const v = { envelope: x.ENV() };
    let r;
    Object.defineProperty(Object.prototype, 'objects', {
      configurable: true,
      set() {
        x.c.n++;
        throw new RangeError('observer record');
      },
    });
    try {
      r = x.store.put(v, 'k');
    } finally {
      delete Object.prototype.objects;
    }
    return x.track(r);
  },
};
// Red-team Fase 4 (Sol r3 #3): a thrown plain object with a `name` accessor.
put('getter-throws-name-accessor', (x) => {
  const error = {};
  Object.defineProperty(error, 'name', {
    get() {
      x.c.n++;
      return 'RangeError';
    },
  });
  return {
    get envelope() {
      x.c.n++;
      throw error;
    },
  };
});
// Red-team Fase 4 (Argon R7): a thrown error whose `name` is an accessor.
put('throwing-getter-custom-error-name', (x) => ({
  get a() {
    x.c.n++;
    const err = new Error('boom');
    Object.defineProperty(err, 'name', { get() { x.c.n++; return 'CustomErr'; } });
    throw err;
  },
}));
put('keypath-empty-string', () => 'k', { store: { keyPath: '' } });
put('keypath-empty-u8-envelope', (x) => x.ENV(), { store: { keyPath: '' } });
put('keypath-empty-array', () => [1, 2], { store: { keyPath: '' } });
put('keypath-array', () => ({ a: 'x', b: 'y' }), { store: { keyPath: ['a', 'b'] } });
const order = (name, schema, op) => { CASES[name] = { schema, run: op }; };
order('order-valid', {}, (x) => x.track(x.store.put(G(x, x.ENV()), 'k')));
order('order-readonly', {}, (x) => x.track(x.db.transaction('s', 'readonly').objectStore('s').put(G(x, x.ENV()), 'k')));
order('order-inactive', {}, async (x) => { await sleep(20); return x.track(x.store.put(G(x, x.ENV()), 'k')); });
order('order-finished', {}, async (x) => { await x.done; return x.track(x.store.put(G(x, x.ENV()), 'k')); });
order('order-keypath-and-key', { store: { keyPath: 'id' } }, (x) => x.track(x.store.put(G(x, x.ENV()), 'k')));
order('order-no-key', {}, (x) => x.track(x.store.put(G(x, x.ENV()))));
order('order-key-nan', {}, (x) => x.track(x.store.put(G(x, x.ENV()), NaN)));
order('order-key-object', {}, (x) => x.track(x.store.put(G(x, x.ENV()), {})));
order('order-inline-missing', { store: { keyPath: 'id' } }, (x) => x.track(x.store.put(G(x, x.ENV()))));
order('order-autoinc-nonobject', { store: { keyPath: 'id', autoIncrement: true } }, (x) => x.track(x.store.put(5)));
order('order-add-duplicate', {}, (x) => { x.track(x.store.put(1, 'k')); return x.track(x.store.add(G(x, x.ENV()), 'k')); });
order('order-deleted-store', {}, async (x) => {
  x.tx.abort(); x.db.close();
  const r = indexedDB.open(x.name, 2);
  await new Promise((res) => { r.onupgradeneeded = () => { const s = r.transaction.objectStore('s'); r.result.deleteObjectStore('s'); try { s.put(G(x, x.ENV()), 'k'); x.c.inner.push('no-throw'); } catch (e) { x.c.inner.push(e.name); } }; r.onsuccess = () => { r.result.close(); res(); }; r.onerror = () => res(); });
  return null;
});
order('order-readonly-key-getter', {}, (x) => { const a = ['k']; Object.defineProperty(a, 0, { enumerable: true, get() { x.c.n++; return 'k'; } }); return x.track(x.db.transaction('s', 'readonly').objectStore('s').put(1, a)); });
// Act §6: every synchronous throw outside D is NON_CANONICAL_WRITE (with or without an envelope).
order('outside-D-sync-throw', { store: { keyPath: 'id' } }, (x) => x.track(x.store.put({ m: new Map(), envelope: x.ENV() }, 'k')));
order('outside-D-preclone', {}, (x) => x.track(x.db.transaction('s', 'readonly').objectStore('s').put({ e: 1 }, NaN)));
order('arity-put-none', { store: { autoIncrement: true } }, (x) => x.track(x.store.put()));
order('arity-delete-none', {}, (x) => x.track(x.store.delete()));
CASES.clear = { schema: {}, run: (x) => { x.track(x.store.put({ envelope: x.ENV() }, 'k')); return x.track(x.store.clear()); } };
// K14: the root, the envelope node and 4,094 (or 4,095) empty objects: 4,096 (or 4,097) distinct objects.
CASES['objects-4096'] = { schema: {}, run: (x) => { const v = { envelope: x.ENV() }; for (let i = 0; i < 4094; i++) v[`o${i}`] = {}; return x.track(x.store.put(v, 'k')); } };
CASES['objects-4097'] = { schema: {}, run: (x) => { const v = { envelope: x.ENV() }; for (let i = 0; i < 4095; i++) v[`o${i}`] = {}; return x.track(x.store.put(v, 'k')); } };
// Cursor cases: the store holds 'a' and 'b'; a second transaction opens a cursor on 'a'.
const cursorCase = (name, schema, op, { mode = 'readwrite', key = false } = {}) => { CASES[name] = { schema, cursor: { mode, key }, run: op }; };
cursorCase('cursor-update-valid', {}, (x, cur) => x.track(cur.update(G(x, x.ENV()))));
cursorCase('cursor-update-readonly', {}, (x, cur) => x.track(cur.update(G(x, x.ENV()))), { mode: 'readonly' });
cursorCase('cursor-update-after-continue', {}, (x, cur) => { cur.continue(); return x.track(cur.update(G(x, x.ENV()))); });
cursorCase('cursor-update-keycursor', {}, (x, cur) => x.track(cur.update(G(x, x.ENV()))), { key: true });
cursorCase('cursor-update-inline-changed', { store: { keyPath: 'id' } }, (x, cur) => x.track(cur.update({ get id() { x.c.n++; return 'other'; } })));
cursorCase('cursor-update-map', {}, (x, cur) => x.track(cur.update(new Map([['e', x.ENV()]]))));
cursorCase('cursor-delete', {}, (x, cur) => { x.track(x.store.put({ envelope: x.ENV() }, 'z')); return x.track(cur.delete()); });
cursorCase('arity-update-none', {}, (x, cur) => x.track(cur.update()));
// K18: calls during the clone (the getter of the value runs inside the single clone).
const re = (name, inner) => { CASES[name] = { schema: {}, run: (x) => x.track(x.store.put({ get envelope() { x.c.n++; tryInner(x, () => inner(x)); return x.ENV(); } }, 'k')) }; };
re('reentrant-put', (x) => x.store.put(1, 'inner'));
re('reentrant-get', (x) => x.store.get('k'));
re('reentrant-objectStore', (x) => x.tx.objectStore('t'));
re('reentrant-commit', (x) => x.tx.commit());
re('reentrant-abort', (x) => x.tx.abort());
re('reentrant-double-abort', (x) => { x.tx.abort(); x.tx.abort(); });
re('reentrant-abort-then-objectStore', (x) => { x.tx.abort(); x.tx.objectStore('t'); });
re('reentrant-get-noarg', (x) => x.store.get());
re('reentrant-other-tx', (x) => x.db.transaction('t', 'readwrite').objectStore('t').put(1, 'other'));
re('reentrant-other-tx-get', (x) => x.otherStore.get('nothing'));
re('reentrant-transaction', (x) => x.db.transaction('t', 'readonly'));
re('reentrant-createIndex-nonupgrade', (x) => x.store.createIndex('i', 'a'));
re('reentrant-handler-setter', (x) => { x.tx.onerror = null; });
// Red-team Fase 4 (Sol, K18): a zero-argument call to a wrapped write method during the clone.
re('reentrant-put-noarg', (x) => x.store.put());
// Red-team Fase 4 (Sol, K6): an inherited `get` on Object.prototype while the request is issued.
CASES['inherited-descriptor-get'] = { schema: {}, run: (x) => {
  const v = { envelope: x.ENV() };
  let r;
  Object.defineProperty(Object.prototype, 'get', { configurable: true, value: function () { return undefined; } });
  try { r = x.store.put(v, 'k'); } finally { delete Object.prototype.get; }
  return x.track(r);
} };
CASES['reentrant-createIndex-upgrade'] = { schema: {}, run: async (x) => {
  x.tx.abort(); x.db.close();
  await new Promise((res) => { const r = indexedDB.open(x.name, 2); r.onupgradeneeded = () => { const s2 = r.transaction.objectStore('s'); const v = { get g() { x.c.n++; tryInner(x, () => s2.createIndex('late', 'a')); return 1; } }; try { x.track(s2.put(v, 'k')); } catch (e) { x.thrown = e.name; } }; r.onsuccess = () => { r.result.close(); res(); }; r.onerror = () => res(); r.onblocked = () => res(); });
  return null;
} };
put('wasm-module', () => WASM());
put('wasm-then-getter', (x) => ({ m: WASM(), get g() { x.c.n++; return 1; } }));
put('getter-then-wasm', (x) => ({ get g() { x.c.n++; return 1; }, m: WASM() }));
put('wasm-then-throwing-getter', (x) => ({ m: WASM(), get g() { x.c.n++; throw new RangeError('later'); } }));
put('audiodata-then-getter', (x) => ({ a: new AudioData({ format: 'f32', sampleRate: 8000, numberOfFrames: 1, numberOfChannels: 1, timestamp: 0, data: new Float32Array(1) }), get g() { x.c.n++; return 1; } }));
put('videoframe-then-getter', (x) => ({ f: x.videoFrame, get g() { x.c.n++; return 1; } }));
put('encoded-video-chunk-then-getter', (x) => ({ f: new EncodedVideoChunk({ type: 'key', timestamp: 0, data: new Uint8Array(4) }), get g() { x.c.n++; return 1; } }));
put('encoded-audio-chunk-then-getter', (x) => ({ f: new EncodedAudioChunk({ type: 'key', timestamp: 0, data: new Uint8Array(4) }), get g() { x.c.n++; return 1; } }));
put('wasm-shared-memory', () => ({ b: new WebAssembly.Memory({ initial: 1, maximum: 1, shared: true }).buffer }));
// K19: writes in a versionchange transaction (a transaction no wrapper opened), in an armed section and in
// a later unarmed transaction. The case reopens its database at version 2; `fn` runs in the upgrade.
const upgradeCase = (name, fn) => { CASES[name] = { schema: {}, run: async (x) => {
  x.tx.abort(); x.db.close();
  await new Promise((res) => {
    const r = indexedDB.open(x.name, 2);
    r.onupgradeneeded = () => {
      const t = r.transaction;
      x.done2 = new Promise((d) => { on(t, 'complete', () => d('complete')); on(t, 'abort', () => d('abort')); });
      try { fn(x, t.objectStore('s')); } catch (e) { x.thrown = e.name; }
    };
    r.onsuccess = () => { r.result.close(); res(); }; r.onerror = () => res(); r.onblocked = () => res();
  });
  return null;
} }; };
upgradeCase('k19-versionchange-ncw', (x, s) => x.track(s.put(new Map([['e', x.ENV()]]), 'k')));
upgradeCase('k19-versionchange-ok', (x, s) => x.track(s.put({ envelope: x.ENV() }, 'k')));
upgradeCase('k19-versionchange-delete-envelope', (x, s) => { x.track(s.put(1, 'k')); x.track(s.delete(x.ENV())); });
upgradeCase('k19-versionchange-cursor-map', (x, s) => {
  x.track(s.put(1, 'a'));
  const r = s.openCursor();
  on(r, 'success', () => { const cur = r.result; if (cur) { try { x.track(cur.update(new Map([['e', x.ENV()]]))); } catch (e) { x.thrown = e.name; } } });
});
upgradeCase('k19-versionchange-clear', (x, s) => { x.track(s.put(1, 'k')); x.track(s.clear()); });
upgradeCase('k19-versionchange-key-nan', (x, s) => x.track(s.put({ e: 1 }, NaN)));
CASES['k19-armed-ncw'] = { schema: {}, armed: true, run: (x) => x.track(x.store.put(new Set([x.ENV()]), 'k')) };
CASES['k19-armed-ok'] = { schema: {}, armed: true, run: (x) => x.track(x.store.put({ envelope: x.ENV() }, 'k')) };
// A second readwrite transaction opened after the first one completed, unarmed.
CASES['k19-unarmed-later-tx-ncw'] = { schema: {}, run: async (x) => {
  x.track(x.store.put({ envelope: x.ENV() }, 'k'));
  await x.done;
  const t2 = x.db.transaction('t', 'readwrite');
  x.done2 = new Promise((d) => { on(t2, 'complete', () => d('complete')); on(t2, 'abort', () => d('abort')); });
  return x.track(t2.objectStore('t').put(new DataView(new ArrayBuffer(4)), 'late'));
} };


// ---- red-team K19 round, Sol (REVIEW-SOL-k19.md), literal probes ---------------------------------------
for (const multiEntry of [false, true]) {
  CASES[`review-wide-index-${multiEntry}`] = {
    schema: { indexes: [['ix', 'e', { multiEntry }]] },
    run: (x) => {
      const a = Array(5000).fill(0);
      a[0] = x.ENV();
      return x.track(x.store.put({ e: a }, 'k'));
    },
  };
}
CASES['review-wrapper-descriptor-spoof'] = {
  schema: {},
  run: (x) => {
    const expected = IDBObjectStore.prototype.put;

    Object.defineProperty(Object.prototype, 'value', {
      __proto__: null,
      value: expected,
      configurable: true,
    });
    Object.defineProperty(IDBObjectStore.prototype, 'put', {
      __proto__: null,
      configurable: true,
      get() { return H.put; },
    });

    return x.track(x.store.put(new Map([['a', 1]]), 'k'));
  },
};
CASES['review-prototype-proxy'] = {
  schema: { indexes: [['ix', 'absent']] },
  run: (x) => {
    const previous = Object.getPrototypeOf(Array.prototype);
    const parent = new Proxy(previous, {
      getOwnPropertyDescriptor(t, k) {
        x.c.traps++;
        return Reflect.getOwnPropertyDescriptor(t, k);
      },
      getPrototypeOf(t) {
        x.c.traps++;
        return Reflect.getPrototypeOf(t);
      },
    });

    let r;
    Object.setPrototypeOf(Array.prototype, parent);
    try {
      r = x.store.put({ a: 1 }, 'k');
    } finally {
      Object.setPrototypeOf(Array.prototype, previous);
    }
    return x.track(r);
  },
};
CASES['review-long-prototype-chain'] = {
  schema: { indexes: [['ix', 'absent']] },
  run: (x) => {
    const previous = Object.getPrototypeOf(Array.prototype);
    let parent = previous;
    for (let i = 0; i < 80; i++) parent = Object.create(parent);

    let r;
    Object.setPrototypeOf(Array.prototype, parent);
    try {
      r = x.store.put({ a: 1 }, 'k');
    } finally {
      Object.setPrototypeOf(Array.prototype, previous);
    }
    return x.track(r);
  },
};

// ---- consensus plan (CONSENSO-PIANO.md): variants of the same classes -------------------------------------
// P3(a): the object budget counts distinct objects, never primitives or aliases.
CASES['plan-wide-index-alias'] = {
  schema: { indexes: [['ix', 'e', { multiEntry: true }]] },
  run: (x) => { const a = Array(5000).fill(0); a[0] = x.ENV(); return x.track(x.store.put({ e: [a, a] }, 'k')); },
};
CASES['plan-wide-index-nested'] = {
  schema: { indexes: [['ix', 'e']] },
  run: (x) => { const a = Array(5000).fill(0); a[4999] = [x.ENV()]; return x.track(x.store.put({ e: a }, 'k')); },
};
CASES['plan-wide-index-control'] = {
  schema: { indexes: [['ix', 'e']] },
  run: (x) => { const a = Array(5000).fill(0); return x.track(x.store.put({ e: a, envelope: x.ENV() }, 'k')); },
};
// P4: an inherited `set` field for an accessor wrapper: the setter of IDBObjectStore.name replaced by a data
// property while Object.prototype.set holds the installed wrapper.
CASES['plan-descriptor-spoof-set'] = {
  schema: {},
  run: (x) => {
    const wrapper = Object.getOwnPropertyDescriptor(IDBObjectStore.prototype, 'name').set;
    Object.defineProperty(Object.prototype, 'set', { __proto__: null, value: wrapper, configurable: true });
    Object.defineProperty(IDBObjectStore.prototype, 'name', { __proto__: null, value: 's', configurable: true, writable: true });
    return x.track(x.store.put({ a: 1 }, 'k'));
  },
};
// P4 control: Object.prototype.value present while an in-D value is written: accepted, counters equal.
CASES['plan-object-prototype-value-control'] = {
  schema: {},
  run: (x) => {
    Object.defineProperty(Object.prototype, 'value', { __proto__: null, value: 1, configurable: true, writable: true });
    try { return x.track(x.store.put({ envelope: x.ENV(), n: [1, 2] }, 'k')); } finally { delete Object.prototype.value; }
  },
};
// P3(b): Chromium evaluates an index key path on own properties only: a getter above Array.prototype gives
// no index entry (asserted on the arm without the observer by `native`).
CASES['plan-index-own-only'] = {
  schema: { indexes: [['ix', 'idx']] },
  run: (x) => {
    const previous = Object.getPrototypeOf(Array.prototype);
    Object.setPrototypeOf(Array.prototype, Object.create(previous, { idx: { get() { x.c.n++; return x.ENV(); }, configurable: true } }));
    let r;
    try { r = x.store.put([1, 2], 'k'); } finally { Object.setPrototypeOf(Array.prototype, previous); }
    x.track(r);
    return x.track(x.store.index('ix').count());
  },
};
// P5(c): an inline key present on a store with a key generator is known before issuance (the transaction
// aborts: the request never succeeds, the record still carries its key).
// Final consensus review R1 (Astra), literal: bytes with a selector-like header that the codec rejects.
CASES['final-nonselector-header'] = {
  schema: {},
  run(x) {
    const u = new Uint8Array(64);
    u.set([0x53, 0x54, 0x59, 0x58, 0x46, 0x4d, 0x54, 0x31]);

    const d = new DataView(u.buffer);
    for (const [p, v] of [
      [8, 1], [10, 17], [12, 65535],
      [14, 1], [16, 1], [18, 1], [34, 16],
    ]) d.setUint16(p, v);

    x.track(x.store.put(u, 'first'));
    return x.track(x.store.put(u, 'second'));
  },
};
// P5(a): a key-path property present with the value undefined on a store with a key generator: Chromium 131
// throws DataError (it is not a missing key; no key is generated or injected), with and without observer.
CASES['plan-inline-auto-undefined-key'] = {
  schema: { store: { keyPath: 'id', autoIncrement: true } },
  run: (x) => x.track(x.store.put({ id: undefined, a: 1 })),
};
CASES['plan-inline-auto-explicit-key-abort'] = {
  schema: { store: { keyPath: 'id', autoIncrement: true } },
  run: (x) => { const r = x.track(x.store.put({ id: 7, a: 1 })); x.tx.abort(); return r; },
};

// ---- K9: other realm, in the page (an iframe is a second realm) ------------------------------------------
const REALM_CASES = {
  'realm-u8': { schema: {}, run: (x) => { const u = new x.realm.Uint8Array(x.ENV()); return x.track(x.store.put(u, 'k')); } },
  'realm-object': { schema: {}, run: (x) => { const o = new x.realm.Object(); o.envelope = new x.realm.Uint8Array(x.ENV()); return x.track(x.store.put(o, 'k')); } },
  'realm-map': { schema: {}, run: (x) => x.track(x.store.put(new x.realm.Map([['e', new x.realm.Uint8Array(x.ENV())]]), 'k')) },
  'realm-getter': { schema: {}, run: (x) => { x.realm.__env = new x.realm.Uint8Array(x.ENV()); const o = x.realm.eval('({ get envelope() { return globalThis.__env; } })'); return x.track(x.store.put(o, 'k')); } },
};

// ---- case runner ---------------------------------------------------------------------------------------
function openDb(name, schema) {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(name, 1);
    r.onupgradeneeded = () => {
      const s = r.result.createObjectStore('s', schema.store ?? {});
      for (const [n, kp, o] of schema.indexes ?? []) s.createIndex(n, kp, o ?? {});
      r.result.createObjectStore('t');
    };
    r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error);
  });
}
function canonical(v, m = new Map()) {
  if (v === null || typeof v !== 'object') return typeof v === 'bigint' ? `${v}n` : (typeof v === 'number' && Number.isNaN(v) ? 'NaN' : (v === undefined ? '#undefined' : v));
  if (m.has(v)) return { ref: m.get(v) };
  const id = m.size; m.set(v, id);
  const tag = Object.prototype.toString.call(v);
  if (v instanceof ArrayBuffer) return { id, tag, bytes: hex(new Uint8Array(v)) };
  if (ArrayBuffer.isView(v)) return { id, tag, bytes: hex(new Uint8Array(v.buffer)), off: v.byteOffset, len: v.byteLength };
  if (v instanceof Map) return { id, tag, map: [...v].map(([k, x]) => [canonical(k, m), canonical(x, m)]) };
  if (v instanceof Set) return { id, tag, set: [...v].map((x) => canonical(x, m)) };
  if (v instanceof Date) return { id, tag, t: v.getTime() };
  return { id, tag, proto: Object.getPrototypeOf(v) === Object.prototype ? 'O' : (Object.getPrototypeOf(v) === Array.prototype ? 'A' : String(Object.getPrototypeOf(v)?.constructor?.name)),
    fields: Reflect.ownKeys(v).map((k) => { const d = Object.getOwnPropertyDescriptor(v, k); return [String(k), 'value' in d ? canonical(d.value, m) : 'accessor']; }) };
}
const settle = (r) => new Promise((res) => { r.onsuccess = () => res(r.result); r.onerror = () => res(`error:${r.error?.name}`); });
export const CASE_NAMES = Object.freeze(Object.keys(EXPECTED));

/** Run one case in this realm; `observer` installs the substituted-clone observer first. */
export async function runCase(name, observer, envHex, realm = null) {
  const cs = CASES[name] ?? REALM_CASES[name];
  if (cs === undefined) throw new Error(`unknown case ${name}`);
  const envBytes = Uint8Array.from(envHex.match(/../g), (h) => parseInt(h, 16));
  const records = [];
  const state = { armed: false, section: 1, trace: [], plan: {}, next: 0, reads: 0, fault: null, portCalls: 0,
    onWrite: (r) => { append(records, r); } };
  let api = null;
  // Platform objects that need an await are made before any transaction opens.
  const cryptoKey = name === 'cryptokey' ? await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, false, ['encrypt']) : null;
  const fsHandle = name === 'filesystem-handle' ? await (await navigator.storage.getDirectory()).getFileHandle('bchr-observer-case', { create: true }) : null;
  const videoFrame = name === 'videoframe-then-getter' ? new VideoFrame(new Uint8Array(16), { format: 'RGBA', codedWidth: 2, codedHeight: 2, timestamp: 0 }) : null;
  if (observer) api = instrument({ hook: () => {}, state });
  const dbName = `bchr-observer-${name}-${crypto.randomUUID()}`;
  const c = { n: 0, traps: 0, inner: [] };
  const requests = [];
  let thrown = null;
  const db = await openDb(dbName, cs.schema);
  if (cs.fault) { state.armed = true; state.fault = cs.fault; }
  if (cs.armed) state.armed = true; // K19: an armed section (the hook is a no-op here)
  const tx = db.transaction(['s', 't'], 'readwrite', { durability: 'strict' });
  const store = tx.objectStore('s');
  const done = new Promise((res) => { on(tx, 'complete', () => res('complete')); on(tx, 'abort', () => res('abort')); });
  const x = { db, tx, store, otherStore: null, c, done, name: dbName, cryptoKey, fsHandle, videoFrame, realm, thrown: null, done2: null,
    ENV: () => envBytes.slice(), OTHER: () => { const o = envBytes.slice(); o[o.length - 1] ^= 1; return o; },
    track: (r) => {
      if (r === null || r === undefined) return r;
      const e = { status: 'pending' }; requests.push(e);
      on(r, 'success', () => { e.status = 'success'; const v = r.result; e.result = typeof v === 'object' && v !== null ? 'object' : canonical(v); });
      on(r, 'error', () => { e.status = `error:${r.error?.name}`; });
      return r;
    } };
  try {
    if (name === 'reentrant-other-tx-get') x.otherStore = db.transaction('t', 'readonly').objectStore('t');
    if (cs.cursor) {
      const inline = cs.schema.store?.keyPath !== undefined;
      x.track(inline ? store.put({ id: 'a', v: 1 }) : store.put(1, 'a'));
      x.track(inline ? store.put({ id: 'b', v: 2 }) : store.put(2, 'b'));
      await done;
      const t2 = db.transaction('s', cs.cursor.mode); const s2 = t2.objectStore('s');
      x.tx = t2; x.store = s2;
      x.done2 = new Promise((res) => { on(t2, 'complete', () => res('complete')); on(t2, 'abort', () => res('abort')); });
      const cur = await new Promise((res) => { const r = cs.cursor.key ? s2.openKeyCursor() : s2.openCursor(); r.onsuccess = () => res(r.result); });
      try { await cs.run(x, cur); } catch (e) { thrown = e.name; }
    } else {
      try { await cs.run(x); } catch (e) { thrown = e.name; }
    }
  } catch (e) { thrown = `HARNESS:${e?.name}:${e?.message}`; }
  if (x.thrown) thrown = x.thrown;
  const terminal = await Promise.race([x.done2 ?? done, sleep(3000).then(() => 'timeout')]);
  state.armed = false;
  const observerErrors = api ? api.checkInstalled() : [];
  // Durable keys and values, read back after the case.
  let durable = null;
  try {
    const d2 = await new Promise((res, rej) => { const r = indexedDB.open(dbName); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    if (d2.objectStoreNames.contains('s')) {
      const t3 = d2.transaction('s'); const s3 = t3.objectStore('s');
      const [vals, keys] = await Promise.all([settle(s3.getAll()), settle(s3.getAllKeys())]);
      durable = canonical({ vals, keys });
    } else durable = 'no-store';
    d2.close();
  } catch (e) { durable = `read:${e?.name}`; }
  db.close(); indexedDB.deleteDatabase(dbName);
  if (videoFrame) videoFrame.close();
  const book = nonceBook();
  for (const r of records) book.addPut(r);
  const failures = book.failures();
  const issuedEnvelopes = new Set(records.filter((r) => r.issued).flatMap((r) => (r.envelopes ?? []).map((e) => e.envelope)));
  const verdict = !observer ? null
    : (observerErrors.length > 0 || failures.some((f) => f.harnessError) ? 'OBSERVER_ERROR'
      : (records.some((r) => r.nonCanonical) ? 'NCW'
        : (failures.some((f) => !f.unobserved) ? (failures.some((f) => !f.unobserved && /nonce/.test(f.cite)) ? 'NONCE' : 'REJECTED')
          // An unobserved entry is insufficient observation: never ACCEPTED (CP, act v2 §5 "unobserved is never erased").
          : (failures.length > 0 ? 'UNOBSERVED' : 'ACCEPTED'))));
  return { name, observer, thrown, requests, terminal, getters: c.n, traps: c.traps, inner: c.inner, durable,
    records: JSON.parse(JSON.stringify(records)), failures, observerErrors, verdict, envelopes: issuedEnvelopes.size };
}

// ---- dedicated-worker entry -----------------------------------------------------------------------------
if (typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope) {
  const p = new URL(self.location.href).searchParams;
  runCase(p.get('case'), p.get('mode') === 'observer', p.get('env'))
    .then((r) => self.postMessage(r), (e) => self.postMessage({ name: p.get('case'), harnessError: String(e?.stack ?? e) }));
}
