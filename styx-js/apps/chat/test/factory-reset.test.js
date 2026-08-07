// The app-layer reset must touch every persistent surface while treating the
// product vault as a deterministic, fail-closed prerequisite.
import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { factoryReset } from '../src/lib/factory-reset.js';

function installGlobals({ blockedProduct = false } = {}) {
  const state = {
    caches: new Map([['workbox-precache-v2', {}], ['other', {}]]),
    idbDeleted: [],
    localStore: new Map([['styx-identity', 'x'], ['styx-theme', 'dark'], ['styx-install-dismissed', '1'], ['keep', '1']]),
    unregistered: 0,
    unsubscribed: 0,
    events: [],
  };
  const sub = { endpoint: 'https://push.example/abc', async unsubscribe() { state.unsubscribed += 1; return true; } };
  const registration = {
    pushManager: { async getSubscription() { return sub; } },
    async unregister() { state.unregistered += 1; return true; },
  };
  globalThis.caches = {
    async keys() { return [...state.caches.keys()]; },
    async delete(n) { return state.caches.delete(n); },
  };
  globalThis.navigator = {
    serviceWorker: {
      async getRegistration() { return registration; },
      async getRegistrations() { return [registration]; },
    },
  };
  globalThis.indexedDB = {
    deleteDatabase(name) {
      state.idbDeleted.push(name);
      state.events.push(`delete:${name}`);
      const request = {};
      queueMicrotask(() => {
        if (name === 'styx-vault-default' && blockedProduct) {
          request.onblocked?.();
          request.onerror?.();
        }
        else request.onsuccess?.();
      });
      return request;
    },
  };
  globalThis.localStorage = {
    removeItem(k) { state.localStore.delete(k); },
  };
  globalThis.location = { reload: () => state.events.push('reload') };
  return state;
}

describe('factoryReset — app-layer total wipe', () => {
  let state;
  beforeEach(() => { state = installGlobals(); });
  afterEach(() => {
    for (const k of ['caches', 'navigator', 'indexedDB', 'localStorage', 'location']) delete globalThis[k];
  });

  test('stops the product worker before deleting its fixed database', async () => {
    const chat = { wipe: jest.fn(async () => state.events.push('wipe')), me: { pubkey: 'a' }, signBridgeRegistration: jest.fn() };
    await factoryReset({
      chat,
      destroyVault: async () => state.events.push('destroy-vault'),
      stopVault: async () => state.events.push('stop-vault'),
      reload: false,
    });
    expect(state.events.slice(0, 4)).toEqual([
      'destroy-vault', 'stop-vault', 'delete:styx-vault-default', 'wipe',
    ]);
    expect(state.idbDeleted).toContain('styx-ledger');
    expect(chat.wipe).toHaveBeenCalledTimes(1);
    expect(state.caches.size).toBe(0);
    expect(state.unregistered).toBe(1);
    expect(state.unsubscribed).toBe(1);
    expect(state.localStore.has('styx-identity')).toBe(false);
    expect(state.localStore.has('styx-theme')).toBe(false);
    expect(state.localStore.has('styx-install-dismissed')).toBe(false);
    expect(state.localStore.has('keep')).toBe(true);
  });

  test('a failed chat wipe does not report a successful reset', async () => {
    const chat = { wipe: jest.fn(async () => { throw new Error('boom'); }), me: {} };
    await expect(factoryReset({ chat, reload: false })).rejects.toThrow('boom');
    expect(state.caches.size).toBe(2);
    expect(state.unregistered).toBe(0);
    expect(state.localStore.has('styx-theme')).toBe(true);
  });

  test('blocked product-vault deletion fails closed before wiping legacy state', async () => {
    for (const k of ['caches', 'navigator', 'indexedDB', 'localStorage', 'location']) delete globalThis[k];
    state = installGlobals({ blockedProduct: true });
    const chat = { wipe: jest.fn(async () => state.events.push('wipe')) };
    await expect(factoryReset({
      chat,
      destroyVault: async () => state.events.push('destroy-vault'),
      stopVault: async () => state.events.push('stop-vault'),
      reload: false,
    }))
      .rejects.toThrow('database deletion failed');
    expect(state.events).toEqual(['destroy-vault', 'stop-vault', 'delete:styx-vault-default']);
    expect(chat.wipe).not.toHaveBeenCalled();
    expect(state.localStore.has('styx-theme')).toBe(true);
  });
});
