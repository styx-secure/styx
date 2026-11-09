// test/legacy-robustness.test.js — reference app robustness:
//   - connection parameters from a link are used only after a confirmation;
//   - the writer lock says when the multi-tab guard is missing;
//   - the total reset erases every ?ns= namespace and does not wait forever
//     for the push bridge;
//   - the static server answers HEAD without reading the file, and the
//     header-less serve.py is gone.
import { describe, test, expect, afterEach, jest } from '@jest/globals';
import { existsSync, mkdtempSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request } from 'node:http';
import { fileURLToPath } from 'node:url';
import * as config from '../src/lib/config.js';
import { acquireWriterLock } from '../src/lib/writer-lock.js';
import * as factoryResetModule from '../src/lib/factory-reset.js';

const { factoryReset } = factoryResetModule;
// Absent on code that predates the bound: the test then waits for the documented 5 s.
const BRIDGE_UNREGISTER_TIMEOUT_MS = factoryResetModule.BRIDGE_UNREGISTER_TIMEOUT_MS ?? 5000;

const APP_DIR = fileURLToPath(new URL('..', import.meta.url));

describe('connection parameters from a link need a confirmation', () => {
  test('without URL parameters nothing is asked and the defaults are used', () => {
    const confirm = jest.fn(() => true);
    const c = config.resolveConnection('', { confirm, fallbackBridge: 'https://b.default' });
    expect(confirm).not.toHaveBeenCalled();
    expect(c).toEqual({ relays: ['wss://relay.damus.io', 'wss://nos.lol'], bridge: 'https://b.default', fromUrl: false });
  });

  test('declined, relay, bridge and local from the URL are all ignored', () => {
    const confirm = jest.fn(() => false);
    const c = config.resolveConnection('?relay=wss://evil.example&bridge=https://evil.example&local=1', { confirm });
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(c.relays).toEqual(['wss://relay.damus.io', 'wss://nos.lol']);
    expect(c.bridge).toBe('');
    expect(c.fromUrl).toBe(false);
  });

  test('the confirmation lists exactly what the link asks for', () => {
    let shown = '';
    config.resolveConnection('?relay=wss://r.example&bridge=https://b.example/', {
      confirm: (m) => { shown = m; return false; },
    });
    expect(shown).toContain('wss://r.example');
    expect(shown).toContain('https://b.example');
  });

  test('confirmed, the URL values are used', () => {
    const relay = config.resolveConnection('?relay=wss://r1&relay=wss://r2&bridge=https://b/', { confirm: () => true });
    expect(relay).toEqual({ relays: ['wss://r1', 'wss://r2'], bridge: 'https://b', fromUrl: true });
    const local = config.resolveConnection('?local=1', { confirm: () => true });
    expect(local.relays).toEqual([]);
    expect(config.transportOptions(local.relays).allowInsecureTransport).toBe(true);
  });

  test('a confirm that throws counts as declined', () => {
    const c = config.resolveConnection('?local=1', { confirm: () => { throw new Error('no dialog'); } });
    expect(c.relays).toEqual(['wss://relay.damus.io', 'wss://nos.lol']);
  });
});

describe('acquireWriterLock reports a missing multi-tab guard', () => {
  test('without Web Locks the tab writes but is unguarded', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const r = await acquireWriterLock(undefined, 'styx-mls:');
      expect(r.held).toBe(true);
      expect(r.guarded).toBe(false);
    } finally { warn.mockRestore(); }
  });

  test('with Web Locks the writer is guarded', async () => {
    const locks = { request(name, opts, cb) { return Promise.resolve(cb({ name })); } };
    const r = await acquireWriterLock(locks, 'styx-mls:');
    expect(r.held).toBe(true);
    expect(r.guarded).toBe(true);
    r.release();
  });
});

describe('factoryReset — every namespace, bounded bridge wait', () => {
  const GLOBALS = ['caches', 'navigator', 'indexedDB', 'localStorage', 'location', 'fetch', 'window'];
  afterEach(() => { for (const k of GLOBALS) delete globalThis[k]; });

  function install({ fetchImpl } = {}) {
    const store = new Map([
      ['styxchat:alias', 'a'], ['styxchat:alice:alias', 'b'], ['styxchat:bob:msgs', '{}'],
      ['styx-theme', 'dark'], ['keep', '1'],
    ]);
    const state = { store, unsubscribed: 0, fetched: [] };
    const sub = { endpoint: 'https://push.example/x', async unsubscribe() { state.unsubscribed += 1; return true; } };
    const registration = { pushManager: { async getSubscription() { return sub; } }, async unregister() { return true; } };
    globalThis.caches = { async keys() { return []; }, async delete() { return true; } };
    globalThis.navigator = {
      serviceWorker: { async getRegistration() { return registration; }, async getRegistrations() { return [registration]; } },
    };
    globalThis.indexedDB = {
      deleteDatabase() { const r = {}; queueMicrotask(() => r.onsuccess?.()); return r; },
    };
    globalThis.localStorage = {
      get length() { return store.size; },
      key(i) { return [...store.keys()][i] ?? null; },
      removeItem(k) { store.delete(k); },
    };
    globalThis.location = { reload() {} };
    globalThis.fetch = fetchImpl || (async (url) => { state.fetched.push(url); return { ok: true }; });
    return state;
  }

  test('erases the chat data of every ?ns= namespace, and only that', async () => {
    const state = install();
    await factoryReset({ chat: { wipe: async () => {} }, reload: false, bridgeUrl: '' });
    expect([...state.store.keys()].filter((k) => k.startsWith('styxchat:'))).toEqual([]);
    expect(state.store.has('keep')).toBe(true);
  });

  test('a bridge that never answers does not hold the reset back', async () => {
    const state = install({ fetchImpl: () => new Promise(() => {}) });
    // The session's bridge, as a link would set it (confirmation answered yes).
    globalThis.window = { location: { search: '?bridge=https://bridge.example' }, confirm: () => true };
    const wiped = jest.fn(async () => {});
    const chat = { wipe: wiped, me: { pubkey: 'a' }, signBridgeRegistration: async () => 'sig' };
    // Virtual clock: the outcome must not depend on real elapsed time.
    jest.useFakeTimers({ doNotFake: ['queueMicrotask', 'nextTick', 'setImmediate'] });
    try {
      let done = false;
      factoryReset({ chat, reload: false, bridgeUrl: 'https://bridge.example' }).then(() => { done = true; });
      await jest.advanceTimersByTimeAsync(BRIDGE_UNREGISTER_TIMEOUT_MS - 1);
      expect(done).toBe(false); // still waiting for the bridge, within the bound
      await jest.advanceTimersByTimeAsync(1);
      expect(done).toBe(true); // the bound expired: the reset went on without the bridge
    } finally {
      jest.useRealTimers();
    }
    expect(wiped).toHaveBeenCalledTimes(1);
    expect(state.unsubscribed).toBe(1);
  });

  test('a bridge that answers is still told to unregister', async () => {
    const state = install();
    const chat = { wipe: async () => {}, me: { pubkey: 'a' }, signBridgeRegistration: async () => 'sig' };
    await factoryReset({ chat, reload: false, bridgeUrl: 'https://bridge.example' });
    expect(state.fetched).toEqual(['https://bridge.example/unregister']);
  });
});

describe('static serving', () => {
  test('serve.py, which set no security header, is not shipped', () => {
    expect(existsSync(join(APP_DIR, 'serve.py'))).toBe(false);
  });

  test('HEAD answers with the size of a file it does not read', async () => {
    if (typeof process.getuid === 'function' && process.getuid() === 0) return; // root reads anything
    const dist = mkdtempSync(join(tmpdir(), 'styx-head-'));
    const file = join(dist, 'big.bin');
    writeFileSync(file, Buffer.alloc(4096, 1));
    writeFileSync(join(dist, 'index.html'), '<!doctype html>');
    chmodSync(file, 0o000); // stat works, reading fails
    const previous = process.env.STYX_DIST;
    process.env.STYX_DIST = dist;
    let server;
    try {
      ({ server } = await import('../static-server.mjs'));
      expect(server).toBeDefined();
      await new Promise((r) => server.listen(0, '127.0.0.1', r));
      const { port } = server.address();
      const head = await new Promise((resolve, reject) => {
        const req = request({ host: '127.0.0.1', port, path: '/big.bin', method: 'HEAD' }, (res) => {
          res.resume();
          res.on('end', () => resolve({ status: res.statusCode, length: res.headers['content-length'] }));
        });
        req.on('error', reject);
        req.end();
      });
      expect(head).toEqual({ status: 200, length: '4096' });
    } finally {
      if (server?.listening) await new Promise((r) => server.close(r));
      if (previous === undefined) delete process.env.STYX_DIST; else process.env.STYX_DIST = previous;
      chmodSync(file, 0o600);
      rmSync(dist, { recursive: true, force: true });
    }
  });
});
