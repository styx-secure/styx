// test/crypto/mls-panic.test.js
//
// N1 — a malformed message off the relay must NOT trap the WASM instance.
//
// The engine holds one WASM instance and one Provider shared by every session in the
// app. Before the N1 fix, `process_message` deserialized attacker-controlled bytes with
// .unwrap(), so a single garbage ciphertext trapped the instance — and a trap is not a
// catchable error: it poisons the linear memory for every other session too.
//
// The invariant these tests defend: a bad message throws a catchable Error, and the
// engine keeps working afterwards.
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

/** Two engines already joined into one 1:1 group (a = inviter, b = joiner). */
async function pairedSessions() {
  const a = await MlsEngine.create({ name: 'a'.repeat(64) });
  const b = await MlsEngine.create({ name: 'b'.repeat(64) });
  const { welcome, ratchetTree } = a.startSession('b', b.keyPackageBytes());
  b.joinSession('a', welcome, ratchetTree);
  return { a, b };
}

describe('MLS engine — malformed wire input does not poison the instance (N1)', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('garbage ciphertext throws, and the engine still decrypts a real message', async () => {
    const { a, b } = await pairedSessions();

    expect(() => b.session('a').decrypt(new Uint8Array([1, 2, 3, 4, 5]))).toThrow();

    // The instance must still be alive: a genuine message round-trips.
    const ct = a.session('b').encrypt(enc('still alive'));
    const out = b.session('a').decrypt(ct);
    expect(out.kind).toBe('application');
    expect(dec(out.plaintext)).toBe('still alive');
  });

  test('the failure is a catchable Error, not a WASM trap', async () => {
    const { b } = await pairedSessions();

    let caught;
    try {
      b.session('a').decrypt(new Uint8Array([0xff, 0x00, 0xff, 0x00]));
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeDefined();
    // A trap surfaces as WebAssembly.RuntimeError ("unreachable") and leaves the
    // instance in an undefined state. An Error means the Rust returned Err.
    expect(caught).not.toBeInstanceOf(WebAssembly.RuntimeError);
  });

  test('repeated garbage does not degrade the session', async () => {
    const { a, b } = await pairedSessions();

    for (let i = 0; i < 20; i += 1) {
      expect(() => b.session('a').decrypt(new Uint8Array([i, i + 1, i + 2]))).toThrow();
    }

    const ct = a.session('b').encrypt(enc('twenty rejections later'));
    expect(dec(b.session('a').decrypt(ct).plaintext)).toBe('twenty rejections later');
  });
});
