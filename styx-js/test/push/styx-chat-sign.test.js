// test/push/styx-chat-sign.test.js — StyxChat signs a push registration with its
// internal Nostr secret; the signature must verify against its public key over
// the shared digest (i.e. it's a real, bound schnorr signature).
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { schnorr } from '@noble/curves/secp256k1';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { registrationDigest } from '../../src/push/registration-digest.js';
import { hexToBytes } from '../../src/utils.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

function memBackend() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
  };
}

describe('StyxChat.signBridgeRegistration', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('produces a schnorr signature that verifies over the shared digest', async () => {
    const chat = new StyxChat();
    await chat.init({ password: 'pw', backend: memBackend(), channelName: 'sign-1', alias: 'A' });
    const endpoint = 'https://push.example/xyz';
    const sig = await chat.signBridgeRegistration('register', endpoint);
    const digest = registrationDigest('register', chat.me.pubkey, endpoint);
    expect(typeof sig).toBe('string');
    expect(schnorr.verify(hexToBytes(sig), digest, chat.me.pubkey)).toBe(true);
    // A signature for a different action must NOT verify against the register digest.
    const sig2 = await chat.signBridgeRegistration('unregister', endpoint);
    expect(schnorr.verify(hexToBytes(sig2), digest, chat.me.pubkey)).toBe(false);
    chat.destroy();
  });
});
