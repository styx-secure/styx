// Module-internal production assembly of IndexedDB + bounded Argon2id.
import { describe, test, expect } from '@jest/globals';
import {
  createVaultWorkerLifecycle, VAULT_WORKER_CANARY_DB_NAME, VAULT_WORKER_PRODUCT_DB_NAME,
} from '../../src/crypto/vault-worker-lifecycle.js';

describe('vault worker lifecycle assembly', () => {
  test('opens only the internal canary DB, initializes once and closes ownership', async () => {
    const openedNames = [];
    let closes = 0;
    let creates = 0;
    let capturedDerive;
    const db = { close: () => { closes += 1; } };
    const vault = { status: async () => ({ state: 'UNINITIALIZED' }) };
    const owner = createVaultWorkerLifecycle({
      deriveImpl: () => new Uint8Array(32),
      openDb: async ({ name }) => { openedNames.push(name); return db; },
      createLifecycle: (deps) => { creates += 1; capturedDerive = deps.deriveKek; return vault; },
    });
    expect(await owner.initialize()).toBe(vault);
    expect(await owner.initialize()).toBe(vault);
    expect(openedNames).toEqual([VAULT_WORKER_CANARY_DB_NAME]);
    expect(VAULT_WORKER_CANARY_DB_NAME.startsWith('styx-vault-test-')).toBe(true);
    expect(creates).toBe(1);

    const salt = new Uint8Array(16);
    expect(await capturedDerive(new Uint8Array([1]), {
      salt, mKib: 19456, t: 4, p: 1, outLen: 32,
    })).toHaveLength(32);
    await expect(capturedDerive(new Uint8Array([1]), {
      salt, mKib: 19457, t: 4, p: 1, outLen: 32,
    })).rejects.toThrow();
    owner.close();
    expect(closes).toBe(1);
  });

  test('allows only the fixed product database or the test prefix', async () => {
    const openedNames = [];
    const owner = createVaultWorkerLifecycle({
      deriveImpl: () => new Uint8Array(32), dbName: VAULT_WORKER_PRODUCT_DB_NAME,
      openDb: async ({ name }) => { openedNames.push(name); return { close() {} }; },
      createLifecycle: () => ({ status: async () => ({ state: 'LOCKED' }) }),
    });
    await owner.initialize();
    expect(openedNames).toEqual(['styx-vault-default']);
    expect(() => createVaultWorkerLifecycle({
      deriveImpl: () => new Uint8Array(32), dbName: 'styx-vault-user-alice',
    })).toThrow(TypeError);
  });

  test('an initialization failure closes the unowned connection', async () => {
    let closes = 0;
    const owner = createVaultWorkerLifecycle({
      deriveImpl: () => new Uint8Array(32),
      openDb: async () => ({ close: () => { closes += 1; } }),
      createLifecycle: () => { throw new Error('synthetic'); },
    });
    await expect(owner.initialize()).rejects.toThrow('synthetic');
    expect(closes).toBe(1);
  });
});
