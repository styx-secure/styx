// test/storage/encrypted-key-store.test.js
import { describe, test, expect, beforeEach } from '@jest/globals';
import { EncryptedKeyStore } from '../../src/storage/encrypted-key-store.js';

/** Minimal in-memory KV backend for tests. */
function memoryBackend() {
  const map = new Map();
  return {
    async get(key) {
      return map.has(key) ? map.get(key) : null;
    },
    async set(key, value) {
      map.set(key, value);
    },
    async delete(key) {
      map.delete(key);
    },
  };
}

describe('EncryptedKeyStore', () => {
  let store;

  beforeEach(() => {
    store = new EncryptedKeyStore({ backend: memoryBackend() });
  });

  test('initialize then unlock returns the same secret', async () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    await store.initialize({ password: 'correct horse', secret });

    const recovered = await store.unlock({ password: 'correct horse' });

    expect(recovered).toEqual(secret);
  });

  test('unlock with the wrong password throws Invalid password', async () => {
    await store.initialize({
      password: 'correct horse',
      secret: new Uint8Array([9, 9, 9]),
    });

    await expect(store.unlock({ password: 'wrong' })).rejects.toThrow(
      'Invalid password',
    );
  });

  test('unlock before initialize throws not initialized', async () => {
    await expect(store.unlock({ password: 'x' })).rejects.toThrow(
      'not initialized',
    );
  });

  test('hasIdentity reflects whether an identity exists', async () => {
    expect(await store.hasIdentity()).toBe(false);
    await store.initialize({
      password: 'pw',
      secret: new Uint8Array([1]),
    });
    expect(await store.hasIdentity()).toBe(true);
  });

  test('initialize twice throws already initialized', async () => {
    await store.initialize({ password: 'pw', secret: new Uint8Array([1]) });

    await expect(
      store.initialize({ password: 'pw', secret: new Uint8Array([2]) }),
    ).rejects.toThrow('already initialized');
  });

  test('changePassword: old password stops working, new one unlocks', async () => {
    const secret = new Uint8Array([4, 2, 4, 2]);
    await store.initialize({ password: 'old-pw', secret });

    await store.changePassword({ oldPassword: 'old-pw', newPassword: 'new-pw' });

    await expect(store.unlock({ password: 'old-pw' })).rejects.toThrow(
      'Invalid password',
    );
    expect(await store.unlock({ password: 'new-pw' })).toEqual(secret);
  });

  test('changePassword with wrong old password throws', async () => {
    await store.initialize({ password: 'old-pw', secret: new Uint8Array([1]) });

    await expect(
      store.changePassword({ oldPassword: 'nope', newPassword: 'new-pw' }),
    ).rejects.toThrow('Invalid password');
  });

  test('each initialize uses a fresh random salt and IV', async () => {
    // Encrypt the same secret+password twice in independent stores and
    // confirm the ciphertext records differ (salt/iv are random).
    const s1 = new EncryptedKeyStore({ backend: memoryBackend() });
    const s2 = new EncryptedKeyStore({ backend: memoryBackend() });
    const secret = new Uint8Array([7, 7, 7]);
    await s1.initialize({ password: 'same', secret });
    await s2.initialize({ password: 'same', secret });
    const r1 = await s1._backend.get('styx:identity');
    const r2 = await s2._backend.get('styx:identity');
    expect(r1.salt).not.toEqual(r2.salt);
    expect(r1.iv).not.toEqual(r2.iv);
    expect(r1.ct).not.toEqual(r2.ct);
  });
});
