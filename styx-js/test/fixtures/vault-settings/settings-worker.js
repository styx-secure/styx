// Real US-009 worker assembly with a fixed, disposable test database. This is
// the production runtime/lifecycle/KDF path; only the internal DB name differs.

/* eslint-disable no-restricted-globals */
import { initSync, argon2id_derive } from '../../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js';
import { createVaultKdfLoader } from '../../../src/crypto/vault-kdf-loader.js';
import { createVaultWorkerRuntime } from '../../../src/crypto/vault-worker-runtime.js';
import { createVaultWorkerLifecycle } from '../../../src/crypto/vault-worker-lifecycle.js';

const kdfLoader = createVaultKdfLoader(Object.freeze({
  origin: self.location.origin,
  fetchImpl: (url, options) => fetch(url, options),
  subtleImpl: crypto.subtle,
  initSyncImpl: initSync,
  deriveImpl: argon2id_derive,
}));

const vaultLifecycle = createVaultWorkerLifecycle(Object.freeze({
  deriveImpl: argon2id_derive,
  dbName: 'styx-vault-test-settings-v1',
}));

const runtime = createVaultWorkerRuntime(Object.freeze({
  postMessage: (message, transfer = []) => self.postMessage(message, transfer),
  close: () => self.close(),
  kdfLoader,
  vaultLifecycle,
}));

self.onmessage = (event) => {
  if (typeof event.origin === 'string' && event.origin !== '') return;
  runtime.handleMessage(event);
};
