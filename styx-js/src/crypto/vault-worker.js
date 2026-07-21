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

self.onmessage = (event) => {
  // Review PR39 F3 (CodeQL js/missing-origin-check): page→dedicated-worker
  // messages always carry an empty origin; anything else is not our protocol
  // and is dropped without a response (no error oracle for foreign senders).
  // The runtime keeps its own origin rejection as defense in depth.
  if (typeof event.origin === 'string' && event.origin !== '') return;
  runtime.handleMessage(event);
};
