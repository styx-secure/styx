// crypto-worker.js — STYX_SPIKE_PROTOTYPE (spike/crypto-worker).
//
// NOT PRODUCTION CODE. A dedicated *module* Worker that owns the OpenMLS/WASM
// runtime (and, via the vault prototype, IndexedDB) to answer the Blocco 3
// question: what belongs inside a Crypto Worker, and how does the boundary
// behave (typed messages, transfers, errors, termination, locks, CSP)?
//
// Message protocol (structured-clone JSON + optional transferables):
//   request:  { id, type, payload }
//   response: { id, ok: true,  result }            (+ transfer for big buffers)
//           | { id, ok: false, error: { code, message } }   — NEVER key material
//
// Types: INIT · UNLOCK · LOCK · VAULT_GET · VAULT_PUT · MLS_RESTORE ·
//        MLS_SERIALIZE · MLS_DECRYPT · ECHO_TRANSFER · BUSY · LEAK_PROBE · SHUTDOWN

import initWasm, {
  Provider,
  Identity,
  Group,
} from '../../vendor/openmls-wasm/openmls_wasm.js';

// Minimal inline IndexedDB KV (namespace stores), enough to prove the worker
// owns IndexedDB. The full design probes live in the sibling indexeddb-vault
// spike; the two spikes stay branch-independent on purpose.
function openVault({ name }) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(name, 1);
    req.onupgradeneeded = () => { for (const ns of ['meta', 'mls']) req.result.createObjectStore(ns); };
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      const db = req.result;
      const op = (ns, mode, fn) => new Promise((res, rej) => {
        const r = fn(db.transaction(ns, mode).objectStore(ns));
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(r.error);
      });
      resolve({
        get: (ns, key) => op(ns, 'readonly', (s) => s.get(key)),
        put: (ns, key, value) => op(ns, 'readwrite', (s) => s.put(value, key)),
      });
    };
  });
}

let provider = null;
let identity = null;
const groups = new Map(); // contactId -> Group
let vault = null;

const errors = {
  NOT_INITIALIZED: 'WORKER_NOT_INITIALIZED',
  LOCKED: 'WORKER_LOCKED',
  RESTORE_FAILED: 'MLS_RESTORE_FAILED',
  BAD_REQUEST: 'WORKER_BAD_REQUEST',
};

function fail(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

const handlers = {
  async INIT({ wasmUrl }) {
    // Allowlist, not a free URL: the worker only ever loads the vendored engine
    // from its own origin (also satisfies CodeQL js/client-side-request-forgery).
    const allowed = new URL('/vendor/openmls-wasm/openmls_wasm_bg.wasm', self.location.origin);
    if (new URL(wasmUrl, self.location.origin).href !== allowed.href) {
      throw fail(errors.BAD_REQUEST, 'wasmUrl is not the vendored engine path');
    }
    const t0 = performance.now();
    const bytes = new Uint8Array(await (await fetch(allowed)).arrayBuffer());
    await initWasm({ module_or_path: bytes });
    return { wasmInitMs: performance.now() - t0 };
  },

  /** Create a fresh identity, or restore one when state bytes are provided. */
  async UNLOCK({ name, idpk, state }) {
    if (state) {
      provider = new Provider();
      try {
        provider.restore_state(state);
        identity = Identity.load(provider, name, idpk);
      } catch (e) {
        provider = null;
        throw fail(errors.RESTORE_FAILED, `restore refused: ${e?.message ?? 'unknown'}`);
      }
      if (!identity) {
        provider = null;
        throw fail(errors.RESTORE_FAILED, 'identity not found in state');
      }
    } else {
      provider = new Provider();
      identity = new Identity(provider, name);
    }
    return { unlocked: true };
  },

  /** Drop the in-worker handles. (WASM-internal zeroization is the crate's job.) */
  async LOCK() {
    provider = null; identity = null; groups.clear();
    return { locked: true };
  },

  async MLS_RESTORE({ name, idpk, state, groupMap }) {
    await handlers.UNLOCK({ name, idpk, state });
    // Contacts are 64-hex pubkeys by contract; enforce it so an attacker-chosen
    // key can never become a property write (CodeQL js/remote-property-injection)
    // — and build the result via entries, never by assigning dynamic keys.
    const entries = [];
    for (const [contact, groupId] of Object.entries(groupMap || {})) {
      if (!/^[0-9a-f]{64}$/.test(contact)) throw fail(errors.BAD_REQUEST, 'contact is not a 64-hex pubkey');
      const g = Group.load(provider, groupId);
      if (g) { groups.set(contact, g); entries.push([contact, g.member_identities()]); }
    }
    return { members: Object.fromEntries(entries) };
  },

  async MLS_SERIALIZE() {
    if (!provider) throw fail(errors.LOCKED, 'no unlocked provider');
    const state = provider.serialize_state();
    // The response transfers the underlying buffer — zero-copy to the main thread.
    return { __transferResult: { state }, __transferList: [state.buffer] };
  },

  async MLS_DECRYPT({ contact, ciphertext }) {
    if (!provider) throw fail(errors.LOCKED, 'no unlocked provider');
    const g = groups.get(contact);
    if (!g) throw fail(errors.BAD_REQUEST, `no group for ${contact}`);
    const out = g.process_message(provider, ciphertext);
    return { plaintext: out };
  },

  async VAULT_PUT({ ns, key, value }) {
    vault ||= await openVault({ name: 'styx-worker-vault-spike' });
    await vault.put(ns, key, value);
    return { stored: true };
  },

  async VAULT_GET({ ns, key }) {
    vault ||= await openVault({ name: 'styx-worker-vault-spike' });
    return { value: await vault.get(ns, key) };
  },

  /** Round-trip measurement helper: reply with (optionally transferred) buffer. */
  async ECHO_TRANSFER({ buf, transferBack }) {
    return transferBack
      ? { __transferResult: { buf, len: buf.byteLength }, __transferList: [buf.buffer ?? buf] }
      : { buf, len: buf.byteLength };
  },

  /** Long CPU-bound operation, used by the mid-operation termination probe. */
  async BUSY({ ms }) {
    const end = performance.now() + ms;
    let x = 0;
    while (performance.now() < end) { for (let i = 0; i < 1e5; i += 1) x = (x + i) % 9973; }
    return { done: true, x };
  },

  /**
   * Deliberately send a live WASM handle across the boundary and observe what
   * the platform does. SPIKE FINDING (W-F3): wasm-bindgen wrappers are plain JS
   * objects holding a raw pointer, so structured clone does NOT refuse them —
   * no DataCloneError safety net. What crosses is an inert `{__wbg_ptr}` (the
   * key material stays in the worker's WASM memory), but the design lesson is
   * that the message protocol itself must enforce an explicit allowlist of what
   * may be posted; the platform will not catch accidental leaks.
   */
  async LEAK_PROBE() {
    if (!provider) throw fail(errors.LOCKED, 'no unlocked provider');
    try {
      self.postMessage({ id: -1, stray: { leaked: provider } });
      return { cloned: true };
    } catch (e) {
      return { cloned: false, refusedAs: e.name };
    }
  },

  async LOCK_PROBE({ name }) {
    // Web Locks from inside a dedicated worker (same origin as the page).
    const granted = await new Promise((resolve) => {
      navigator.locks.request(name, { mode: 'exclusive', ifAvailable: true }, (lock) => {
        resolve(lock !== null);
        return undefined; // release immediately if granted
      }).catch(() => resolve(false));
    });
    return { granted };
  },

  async SHUTDOWN() {
    setTimeout(() => self.close(), 0);
    return { closing: true };
  },
};

self.onmessage = async (ev) => {
  // Dedicated workers only receive messages from their owning page (ev.origin is
  // the empty string there); refuse anything else defensively
  // (CodeQL js/missing-origin-check).
  if (ev.origin !== '' && ev.origin !== self.location.origin) return;
  const { id, type, payload } = ev.data || {};
  const handler = handlers[type];
  if (!handler) {
    self.postMessage({ id, ok: false, error: { code: errors.BAD_REQUEST, message: `unknown type ${type}` } });
    return;
  }
  try {
    const result = await handler(payload || {});
    if (result && result.__transferResult) {
      self.postMessage({ id, ok: true, result: result.__transferResult }, result.__transferList);
    } else {
      self.postMessage({ id, ok: true, result });
    }
  } catch (e) {
    // Structured, allowlisted error surface: code + message only, never payloads.
    self.postMessage({ id, ok: false, error: { code: e.code || 'WORKER_ERROR', message: String(e?.message ?? e) } });
  }
};

self.postMessage({ id: 0, ok: true, result: { ready: true } });
