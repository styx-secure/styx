// vault-worker.js — THIN production entry of the vault crypto worker
// (Blocco 3, PR-3). All logic lives in the pure factories; this file only
// wires them to the Worker global scope with FROZEN, module-internal
// dependencies. Nothing here is importable by the app bundle (enforced by
// the web anti-bundle gate) and nothing the page sends can inject code:
// the KDF glue is imported STATICALLY — never from a URL in a message.

/* eslint-disable no-restricted-globals */
import { initSync, argon2id_derive } from '../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js';
import { createVaultKdfLoader } from './vault-kdf-loader.js';
import { createVaultWorkerRuntime } from './vault-worker-runtime.js';

const runtime = createVaultWorkerRuntime(Object.freeze({
  postMessage: (message, transfer = []) => self.postMessage(message, transfer),
  close: () => self.close(),
  kdfLoader: createVaultKdfLoader(Object.freeze({
    origin: self.location.origin,
    fetchImpl: (url, options) => fetch(url, options),
    subtleImpl: crypto.subtle,
    initSyncImpl: initSync,
    deriveImpl: argon2id_derive,
  })),
  // no testOverrides: the production worker has exactly INIT/STATUS/SHUTDOWN
}));

self.onmessage = (event) => { runtime.handleMessage(event); };
