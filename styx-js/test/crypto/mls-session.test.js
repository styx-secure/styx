// test/crypto/mls-session.test.js
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';

const wasmPath = fileURLToPath(
  new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url),
);
const wasmBytes = readFileSync(wasmPath);

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

describe('MlsEngine / MlsSession — 1:1 round-trip on OpenMLS-WASM', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('two peers pair via KeyPackage/Welcome and exchange encrypted messages', async () => {
    const alice = await MlsEngine.create({ name: 'alice' });
    const bob = await MlsEngine.create({ name: 'bob' });

    // Bob publishes his KeyPackage; Alice starts a session by adding him.
    const bobKp = bob.keyPackageBytes();
    const { session: aliceSession, welcome, ratchetTree } = alice.startSession('bob', bobKp);
    expect(welcome.length).toBeGreaterThan(0);

    // Bob joins from Welcome + ratchet tree.
    const bobSession = bob.joinSession('alice', welcome, ratchetTree);

    // alice -> bob
    const ct1 = aliceSession.encrypt(enc('Ciao Bob 🔐'));
    const r1 = bobSession.decrypt(ct1);
    expect(r1.kind).toBe('application');
    expect(dec(r1.plaintext)).toBe('Ciao Bob 🔐');

    // bob -> alice
    const ct2 = bobSession.encrypt(enc('Ricevuto'));
    const r2 = aliceSession.decrypt(ct2);
    expect(dec(r2.plaintext)).toBe('Ricevuto');
  });

  test('a sequence of messages each decrypts (ratchet advances per message)', async () => {
    const alice = await MlsEngine.create({ name: 'alice2' });
    const bob = await MlsEngine.create({ name: 'bob2' });
    const { session: aliceSession, welcome, ratchetTree } = alice.startSession('bob', bob.keyPackageBytes());
    const bobSession = bob.joinSession('alice', welcome, ratchetTree);

    for (let i = 0; i < 5; i++) {
      const r = bobSession.decrypt(aliceSession.encrypt(enc(`msg-${i}`)));
      expect(r.kind).toBe('application');
      expect(dec(r.plaintext)).toBe(`msg-${i}`);
    }
  });

  test('each engine yields a distinct, non-empty KeyPackage', async () => {
    const a = await MlsEngine.create({ name: 'x' });
    const b = await MlsEngine.create({ name: 'y' });
    const ka = a.keyPackageBytes();
    const kb = b.keyPackageBytes();
    expect(ka.length).toBeGreaterThan(0);
    expect(Buffer.from(ka).equals(Buffer.from(kb))).toBe(false);
  });

  test('engine tracks the session by contactId', async () => {
    const alice = await MlsEngine.create({ name: 'alice3' });
    const bob = await MlsEngine.create({ name: 'bob3' });
    const { session } = alice.startSession('bob-id', bob.keyPackageBytes());
    expect(alice.session('bob-id')).toBe(session);
    expect(alice.session('nope')).toBeUndefined();
  });
});
