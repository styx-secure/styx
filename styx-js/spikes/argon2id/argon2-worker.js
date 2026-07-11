// argon2-worker.js — STYX_SPIKE_PROTOTYPE (spike/argon2id).
//
// Benchmark worker for the two Argon2id candidates, run in the context the
// crypto-worker spike selected (a dedicated module worker):
//   A: project-built Rust/WASM crate (RustCrypto `argon2`, pinned toolchain)
//   B: hash-wasm (exact-pinned in the spike-local package.json, never in styx-js;
//      npm provenance recorded in the doc)
//
// Typed protocol like the crypto worker: {id,type,payload} → {id,ok,result|error}.
// Types: INIT_A · INIT_B · DERIVE · CROSS_CHECK · SHUTDOWN

import initA, { argon2id_derive } from './crate/pkg/argon2id_spike.js';
import { argon2id as argon2idB } from './node_modules/hash-wasm/dist/index.esm.js';

let aReady = false;

const handlers = {
  async INIT_A() {
    const t0 = performance.now();
    const bytes = new Uint8Array(await (await fetch(new URL('./crate/pkg/argon2id_spike_bg.wasm', import.meta.url))).arrayBuffer());
    await initA({ module_or_path: bytes });
    aReady = true;
    return { initMs: performance.now() - t0, wasmBytes: bytes.length };
  },

  async INIT_B() {
    // hash-wasm lazy-inits its wasm on first use; warm it with a tiny derivation.
    const t0 = performance.now();
    await argon2idB({
      password: 'warmup', salt: new Uint8Array(16), iterations: 1, memorySize: 64, parallelism: 1, hashLength: 32, outputType: 'binary',
    });
    return { initMs: performance.now() - t0 };
  },

  /**
   * One derivation with either candidate. Memory probe: WASM memory pages for A
   * (candidate B manages its own instance internally; its growth is not
   * observable from here — recorded as a limitation in the doc).
   */
  async DERIVE({ impl, password, salt, mKib, t, p, outLen }) {
    const t0 = performance.now();
    let out;
    if (impl === 'A') {
      if (!aReady) throw Object.assign(new Error('INIT_A first'), { code: 'NOT_INITIALIZED' });
      out = argon2id_derive(password, salt, mKib, t, p, outLen);
    } else {
      out = await argon2idB({
        password, salt, iterations: t, memorySize: mKib, parallelism: p, hashLength: outLen, outputType: 'binary',
      });
    }
    return { ms: performance.now() - t0, out };
  },

  /** Both candidates on identical inputs must agree byte-for-byte. */
  async CROSS_CHECK({ password, salt, mKib, t, p, outLen }) {
    const a = await handlers.DERIVE({ impl: 'A', password, salt, mKib, t, p, outLen });
    const b = await handlers.DERIVE({ impl: 'B', password, salt, mKib, t, p, outLen });
    const equal = a.out.length === b.out.length && a.out.every((x, i) => x === b.out[i]);
    return { equal, aMs: a.ms, bMs: b.ms, hex: [...a.out.slice(0, 8)].map((x) => x.toString(16).padStart(2, '0')).join('') };
  },

  async SHUTDOWN() { setTimeout(() => self.close(), 0); return { closing: true }; },
};

self.onmessage = async (ev) => {
  // Dedicated workers only receive messages from their owning page (ev.origin is
  // the empty string there); refuse anything else defensively
  // (CodeQL js/missing-origin-check).
  if (ev.origin !== '' && ev.origin !== self.location.origin) return;
  const { id, type, payload } = ev.data || {};
  const handler = handlers[type];
  if (!handler) { self.postMessage({ id, ok: false, error: { code: 'BAD_REQUEST', message: `unknown ${type}` } }); return; }
  try {
    self.postMessage({ id, ok: true, result: await handler(payload || {}) });
  } catch (e) {
    self.postMessage({ id, ok: false, error: { code: e.code || 'DERIVE_ERROR', message: String(e?.message ?? e) } });
  }
};

self.postMessage({ id: 0, ok: true, result: { ready: true } });
