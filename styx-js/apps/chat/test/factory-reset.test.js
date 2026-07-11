// test/factory-reset.test.js — the app-layer reset must touch every persistent surface.
// Node test env has none of these globals, so we inject fakes and assert factoryReset
// clears each one (with reload:false so the test process survives).
import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { factoryReset } from '../src/lib/factory-reset.js';

const saved = {};
function installGlobals() {
  const state = {
    caches: new Map([['workbox-precache-v2', {}], ['other', {}]]),
    idbDeleted: [],
    localStore: new Map([['styx-identity', 'x'], ['styx-theme', 'dark'], ['keep', '1']]),
    unregistered: 0,
    unsubscribed: 0,
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
  globalThis.indexedDB = { deleteDatabase(n) { state.idbDeleted.push(n); } };
  globalThis.localStorage = {
    removeItem(k) { state.localStore.delete(k); },
  };
  return state;
}

describe('factoryReset — app-layer total wipe', () => {
  let state;
  beforeEach(() => { state = installGlobals(); });
  afterEach(() => {
    for (const k of ['caches', 'navigator', 'indexedDB', 'localStorage']) delete globalThis[k];
  });

  test('clears every surface and wipes the chat, without reloading', async () => {
    const chat = { wipe: jest.fn(async () => {}), me: { pubkey: 'a' }, signBridgeRegistration: jest.fn() };

    await factoryReset({ chat, reload: false });

    expect(chat.wipe).toHaveBeenCalledTimes(1);   // lib backend wipe
    expect(state.caches.size).toBe(0);            // Cache Storage cleared
    expect(state.unregistered).toBe(1);           // service worker unregistered
    expect(state.unsubscribed).toBe(1);           // push subscription dropped
    expect(state.idbDeleted).toContain('styx-ledger');
    expect(state.localStore.has('styx-identity')).toBe(false);
    expect(state.localStore.has('styx-theme')).toBe(false);
    expect(state.localStore.has('keep')).toBe(true); // only our keys, not everything
  });

  test('a failure in one surface does not stop the others', async () => {
    // chat.wipe throws — caches/SW/IDB/localStorage must still be cleared.
    const chat = { wipe: jest.fn(async () => { throw new Error('boom'); }), me: {} };

    await factoryReset({ chat, reload: false });

    expect(state.caches.size).toBe(0);
    expect(state.unregistered).toBe(1);
    expect(state.idbDeleted).toContain('styx-ledger');
  });
});
