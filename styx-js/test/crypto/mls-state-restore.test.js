// test/crypto/mls-state-restore.test.js — the committed mls-state-v1 fixture restores
// on the real WASM runtime, and every corruption fails closed (structured error, no
// WASM trap, no silent fresh-start).
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import {
  MlsStateError,
  MlsStateErrorCodes,
  encodeMlsStateEnvelope,
  parseMlsStateEnvelope,
  assertMlsStateCompatibility,
} from '../../src/storage/mls-state-envelope.js';
import { base64ToBytes, bytesToBase64, utf8Decode } from '../../src/utils.js';

const fixtureDir = fileURLToPath(new URL('../fixtures/mls-state-v1/', import.meta.url));
const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);
const FIXTURE_ENVELOPE = JSON.parse(readFileSync(`${fixtureDir}envelope.json`, 'utf8'));
const CTX = JSON.parse(readFileSync(`${fixtureDir}context.json`, 'utf8'));

async function restoreFromFixture() {
  const { envelope, stateBytes } = parseMlsStateEnvelope(FIXTURE_ENVELOPE);
  assertMlsStateCompatibility(envelope);
  const engine = await MlsEngine.restore({
    name: CTX.name,
    stateBytes,
    identityPubKey: base64ToBytes(CTX.idpk),
  });
  for (const [contact, groupId] of Object.entries(CTX.groups)) {
    engine.loadSession(contact, groupId);
  }
  return engine;
}

describe('mls-state-v1 fixture restore (real WASM)', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('restores identity, group and membership, and decrypts the reference message', async () => {
    const engine = await restoreFromFixture();
    expect(bytesToBase64(engine.identityPublicKey())).toBe(CTX.idpk);
    const session = engine.session(CTX.peer);
    expect(session).toBeTruthy();
    expect(session.memberIdentities().sort()).toEqual([CTX.name, CTX.peer].sort());
    expect(engine.peerIdentity(CTX.peer)).toBe(CTX.peer);
    // The proof the ratchet state is right: a message encrypted AFTER the snapshot.
    const out = session.decrypt(base64ToBytes(CTX.refCiphertext));
    expect(out.kind).toBe('application');
    expect(utf8Decode(out.plaintext)).toBe(CTX.refPlaintext);
  });

  test('repeated restore from the same fixture works (read-only source)', async () => {
    const first = await restoreFromFixture();
    const second = await restoreFromFixture();
    for (const engine of [first, second]) {
      expect(engine.peerIdentity(CTX.peer)).toBe(CTX.peer);
      expect(utf8Decode(engine.session(CTX.peer).decrypt(base64ToBytes(CTX.refCiphertext)).plaintext))
        .toBe(CTX.refPlaintext);
    }
  });

  test('a single flipped payload byte is caught by the digest, before any WASM runs', () => {
    const bytes = base64ToBytes(FIXTURE_ENVELOPE.payload);
    bytes[Math.floor(bytes.length / 2)] ^= 0x01;
    const corrupted = { ...FIXTURE_ENVELOPE, payload: bytesToBase64(bytes) };
    let caught;
    try { parseMlsStateEnvelope(corrupted); } catch (e) { caught = e; }
    expect(caught).toBeInstanceOf(MlsStateError);
    expect(caught.code).toBe(MlsStateErrorCodes.CORRUPTED);
    expect(caught).not.toBeInstanceOf(WebAssembly.RuntimeError);
  });

  test('a truncated payload is caught by the digest', () => {
    const bytes = base64ToBytes(FIXTURE_ENVELOPE.payload).slice(0, 100);
    const truncated = { ...FIXTURE_ENVELOPE, payload: bytesToBase64(bytes) };
    expect(() => parseMlsStateEnvelope(truncated))
      .toThrow(expect.objectContaining({ code: MlsStateErrorCodes.CORRUPTED }));
  });

  test('an unknown storage schema is refused without touching the runtime', () => {
    const alien = { ...FIXTURE_ENVELOPE, storageSchemaVersion: 99 };
    expect(() => parseMlsStateEnvelope(alien))
      .toThrow(expect.objectContaining({ code: MlsStateErrorCodes.SCHEMA_UNSUPPORTED }));
  });

  test('a digest-valid but garbage payload fails in the runtime as a clean Error, never a trap', async () => {
    // Bypass the digest on purpose: wrap random bytes in a *valid* envelope, so the
    // failure happens inside restore_state — the hardened WASM boundary must return
    // a catchable Error, not a WebAssembly.RuntimeError.
    const garbage = new Uint8Array(512).map((_, i) => (i * 37 + 11) % 256);
    const { stateBytes } = parseMlsStateEnvelope(
      JSON.parse(JSON.stringify(encodeMlsStateEnvelope(garbage))),
    );
    let caught;
    try {
      await MlsEngine.restore({ name: CTX.name, stateBytes, identityPubKey: base64ToBytes(CTX.idpk) });
    } catch (e) { caught = e; }
    expect(caught).toBeTruthy();
    expect(caught).not.toBeInstanceOf(WebAssembly.RuntimeError);
    // And the engine is still usable afterwards: no poisoned global state.
    const engine = await restoreFromFixture();
    expect(engine.peerIdentity(CTX.peer)).toBe(CTX.peer);
  });
});
