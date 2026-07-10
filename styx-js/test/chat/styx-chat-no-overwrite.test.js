// test/chat/styx-chat-no-overwrite.test.js
// A3: a welcome must never replace an established MLS session. That overwrite is
// the C2 silent-MITM vector: it hijacks a conversation already in progress.
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

describe('MlsEngine A3 no-overwrite', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('joinSession throws if a session for the contact already exists', async () => {
    const inviter = await MlsEngine.create({ name: 'inviter' });
    const joiner = await MlsEngine.create({ name: 'joiner' });
    const { welcome, ratchetTree } = inviter.startSession('peer', joiner.keyPackageBytes());

    joiner.joinSession('peer', welcome, ratchetTree);
    expect(() => joiner.joinSession('peer', welcome, ratchetTree)).toThrow(/already exists/);
  });

  test('the original session survives a rejected re-join attempt', async () => {
    const inviter = await MlsEngine.create({ name: 'inviter2' });
    const joiner = await MlsEngine.create({ name: 'joiner2' });
    const { session: inviterSession, welcome, ratchetTree } = inviter.startSession('peer', joiner.keyPackageBytes());
    joiner.joinSession('peer', welcome, ratchetTree);
    const original = joiner.session('peer');

    // An attacker replays a welcome for the same contact.
    const attacker = await MlsEngine.create({ name: 'attacker' });
    const evil = attacker.startSession('victim', joiner.keyPackageBytes());
    expect(() => joiner.joinSession('peer', evil.welcome, evil.ratchetTree)).toThrow(/already exists/);

    // Same session object, and it still decrypts traffic from the genuine peer.
    expect(joiner.session('peer')).toBe(original);
    const ct = inviterSession.encrypt(new TextEncoder().encode('still us'));
    expect(new TextDecoder().decode(joiner.session('peer').decrypt(ct).plaintext)).toBe('still us');
  });
});
