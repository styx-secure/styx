// test/chat/styx-chat-wipe.test.js
// A real reset must leave nothing recoverable in the backend. wipe() is the lib-layer
// half: destroy the transport and delete every key this backend owns. (Push, Cache
// Storage, the service worker and IndexedDB are browser-global surfaces cleared by the
// app-layer factoryReset, not here.)
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

/** A backend that owns its whole key space, with clear() like LocalStorageBackend. */
function memBackend() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
    async clear() { m.clear(); },
    get size() { return m.size; },
  };
}

describe('StyxChat.wipe() — lib-layer reset', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  async function chatWithBackend() {
    const be = memBackend();
    const engine = await MlsEngine.create({ name: 'a'.repeat(64) });
    const roster = new ContactRoster({ backend: be });
    await roster.load();
    const chat = new StyxChat({
      identity: { pubkey: 'a'.repeat(64), alias: 'Me' },
      engine,
      roster,
      transport: { async send() {}, onMessage() { return () => {}; } },
    });
    chat._backend = be; // DI construction does not set a backend; wire one for the test
    return { chat, be };
  }

  test('wipe() empties every key the backend owns', async () => {
    const { chat, be } = await chatWithBackend();
    await be.set('mls:state', 'x');
    await be.set('msgs', [1, 2, 3]);
    await be.set('styx:contacts', { a: 1 });
    expect(be.size).toBeGreaterThan(0);

    await chat.wipe();

    expect(be.size).toBe(0);
  });

  test('wipe() tears down the transport and drops the engine', async () => {
    const { chat } = await chatWithBackend();
    let closed = false;
    chat._transport = { async send() {}, onMessage() { return () => {}; }, close() { closed = true; } };
    await chat.start();

    await chat.wipe();

    expect(closed).toBe(true);
    expect(chat._engine).toBeNull();
  });
});
