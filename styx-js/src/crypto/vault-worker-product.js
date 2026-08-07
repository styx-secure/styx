// vault-worker-product.js — thin stage-enabled product entry for US-009.
// The fixed database name is module-internal; no page input can select it.

/* eslint-disable no-restricted-globals */
import { initSync, argon2id_derive } from '../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js';
import { createVaultKdfLoader } from './vault-kdf-loader.js';
import {
  createVaultWorkerLifecycle, VAULT_WORKER_PRODUCT_DB_NAME,
} from './vault-worker-lifecycle.js';
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
  vaultLifecycle: createVaultWorkerLifecycle(Object.freeze({
    deriveImpl: argon2id_derive,
    dbName: VAULT_WORKER_PRODUCT_DB_NAME,
  })),
}));

self.onmessage = (event) => {
  if (typeof event.origin === 'string' && event.origin !== '') return;
  runtime.handleMessage(event);
};
