// TEST-ONLY real vault worker whose DB wrapper can stall after a durable
// commit. The page then lets the normal client timeout terminate the worker,
// proving recovery from the commit-before-ack ambiguity with real IndexedDB.

/* eslint-disable no-restricted-globals */
import { initSync, argon2id_derive } from '../../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js';
import { createVaultKdfLoader } from '../../../src/crypto/vault-kdf-loader.js';
import { createVaultWorkerLifecycle } from '../../../src/crypto/vault-worker-lifecycle.js';
import { createVaultWorkerRuntime } from '../../../src/crypto/vault-worker-runtime.js';
import { openVaultDb } from '../../../src/storage/vault-db.js';

let stallAfterCommit = false;

async function openInstrumentedDb(options) {
  const db = await openVaultDb(options);
  return Object.freeze({
    get version() { return db.version; },
    get: (...args) => db.get(...args),
    list: (...args) => db.list(...args),
    close: () => db.close(),
    destroy: () => db.destroy(),
    transaction: async (...args) => {
      const result = await db.transaction(...args);
      if (stallAfterCommit) {
        stallAfterCommit = false;
        await new Promise(() => {}); // termination is the only release
      }
      return result;
    },
  });
}

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
  vaultLifecycle: createVaultWorkerLifecycle(Object.freeze({
    deriveImpl: argon2id_derive,
    openDb: openInstrumentedDb,
    dbName: 'styx-vault-test-worker-atomic-v1',
  })),
  testOverrides: {
    MIGRATE: async (payload) => {
      stallAfterCommit = payload?.stallAfterCommit === true;
      return { result: { armed: stallAfterCommit } };
    },
  },
}));

self.onmessage = (event) => {
  if (typeof event.origin === 'string' && event.origin !== '') return;
  runtime.handleMessage(event);
};
