// test-worker.js — TEST-ONLY entry of the vault worker (PR-3). Same runtime,
// same loader, same STATIC glue import as the production entry
// (src/crypto/vault-worker.js), plus handler overrides for RESERVED types so
// the browser suite can exercise behaviors the production build does not
// activate yet: a real synchronous Argon2id run (strong-cancellation proof),
// a transferable echo, an intentionally leaking / crashing / stalling
// handler. Everything here is synthetic; this file lives in the test tree and
// is NOT reachable from the production worker or the app bundle.

/* eslint-disable no-restricted-globals */
import { initSync, argon2id_derive } from '../../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js';
import { createVaultKdfLoader } from '../../../src/crypto/vault-kdf-loader.js';
import { createVaultWorkerRuntime } from '../../../src/crypto/vault-worker-runtime.js';
import { VaultWorkerError, VaultWorkerErrorCodes } from '../../../src/crypto/vault-worker-errors.js';

const kdfLoader = createVaultKdfLoader(Object.freeze({
  origin: self.location.origin,
  fetchImpl: (url, options) => fetch(url, options),
  subtleImpl: crypto.subtle,
  initSyncImpl: initSync,
  deriveImpl: argon2id_derive,
}));

const runtime = createVaultWorkerRuntime(Object.freeze({
  postMessage: (message, transfer = []) => self.postMessage(message, transfer),
  close: () => self.close(),
  kdfLoader,
  testOverrides: {
    // Real SYNCHRONOUS Argon2id on synthetic data: the only way to cancel it
    // is terminating the worker (mandate §15). The derived output is zeroized
    // and never crosses the boundary.
    UNLOCK: async (payload) => {
      if (!kdfLoader.isLoaded()) {
        throw new VaultWorkerError(VaultWorkerErrorCodes.WRONG_STATE, 'INIT first', { reason: 'not-ready' });
      }
      const rounds = Math.min(Math.max(1, payload?.rounds ?? 1), 64);
      const mKib = Math.min(Math.max(1024, payload?.mKib ?? 65536), 262144);
      const t = Math.min(Math.max(1, payload?.t ?? 3), 16);
      const password = new TextEncoder().encode('STYX-VAULT-TEST-ONLY unlock password');
      const salt = new Uint8Array(16).fill(7);
      let out = null;
      for (let i = 0; i < rounds; i += 1) {
        out = argon2id_derive(password, salt, mKib, t, 1, 32);
        out.fill(0);
      }
      password.fill(0);
      return { result: { unlocked: true, rounds } };
    },
    // Transferable echo: bytes go page → worker (transferred), come back
    // worker → page (transferred again). No copy travels through the protocol.
    PUT: async (payload) => {
      const src = payload?.buffer;
      if (!(src instanceof ArrayBuffer)) {
        throw new VaultWorkerError(VaultWorkerErrorCodes.BAD_REQUEST, 'buffer required', { reason: 'bad-transfer-fixture' });
      }
      const echoed = src.slice(0);
      return { result: { echoed, byteLength: echoed.byteLength }, transfer: [echoed] };
    },
    // Tries to smuggle a wasm-bindgen-like handle out: the response
    // serializer must refuse it (boundary proof).
    GET: async () => ({ result: { leak: { __wbg_ptr: 7 } } }),
    // Never answers: timeout-is-fatal proof.
    LIST: () => new Promise(() => {}),
    // Crashes OUTSIDE the handler: uncaught → the Worker 'error' event fires
    // on the page side (respawn proof).
    DESTROY: async () => {
      setTimeout(() => { throw new Error('TEST-ONLY scheduled crash'); }, 10);
      return { result: { scheduled: true } };
    },
  },
}));

self.onmessage = (event) => {
  // Same explicit origin guard as the production entry (review PR39 F3).
  if (typeof event.origin === 'string' && event.origin !== '') return;
  runtime.handleMessage(event);
};
