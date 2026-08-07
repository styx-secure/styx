// vault-worker-lifecycle.js — production assembly of one worker-owned vault.
// The page can select no database name,
// storage implementation, KDF function or lifecycle factory through the wire.

import { openVaultDb } from '../storage/vault-db.js';
import { createVault } from '../storage/vault.js';
import { deriveWithBounds, KDF_POLICY, KDF_PROFILES } from './kdf-bounds.js';

// US-009 adds one fixed product name; no identifier crosses the worker protocol.
export const VAULT_WORKER_CANARY_DB_NAME = 'styx-vault-test-worker-canary-v1';
export const VAULT_WORKER_PRODUCT_DB_NAME = 'styx-vault-default';

function profileFor({ mKib, t, p }) {
  return Object.entries(KDF_PROFILES).find(([, candidate]) => (
    candidate.mKib === mKib && candidate.t === t && candidate.p === p
  ))?.[0];
}

/**
 * Assemble and own one vault lifecycle. Optional factories are test-only
 * injection seams; the production entry supplies only the statically imported
 * WASM derive function and therefore always uses the internal DB name and
 * native implementations above.
 */
export function createVaultWorkerLifecycle({
  deriveImpl,
  openDb = openVaultDb,
  createLifecycle = createVault,
  dbName = VAULT_WORKER_CANARY_DB_NAME,
} = {}) {
  if (typeof deriveImpl !== 'function') throw new TypeError('deriveImpl is required');
  if (typeof openDb !== 'function' || typeof createLifecycle !== 'function') {
    throw new TypeError('vault lifecycle factories must be functions');
  }
  if (typeof dbName !== 'string'
    || (dbName !== VAULT_WORKER_PRODUCT_DB_NAME && !dbName.startsWith('styx-vault-test-'))) {
    throw new TypeError('vault database name is not an approved internal name');
  }

  let db = null;
  let vault = null;

  const deriveKek = async (password, { salt, mKib, t, p, outLen }) => {
    const profile = profileFor({ mKib, t, p });
    return deriveWithBounds(deriveImpl, password, {
      kdf: KDF_POLICY.kdf,
      kdfVersion: KDF_POLICY.kdfVersion,
      mKib,
      t,
      p,
      salt,
      outLen,
      profile,
    });
  };

  async function initialize() {
    if (vault !== null) return vault;
    const opened = await openDb({ name: dbName });
    try {
      const lifecycle = createLifecycle({ db: opened, deriveKek });
      await lifecycle.status(); // force the initial persisted-state load
      db = opened;
      vault = lifecycle;
      return vault;
    } catch (error) {
      try { opened.close(); } catch { /* failed initialization owns no live DB */ }
      throw error;
    }
  }

  function close() {
    try { db?.close(); } catch { /* worker teardown is best-effort */ }
    db = null;
    vault = null;
  }

  return Object.freeze({ initialize, close });
}
