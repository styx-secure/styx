// test/crypto/mls-adversarial.test.js
//
// Every parser that eats untrusted bytes, exercised with hostile input.
//
// Four entry points take attacker-controlled data: process_message (relay ciphertext,
// covered in mls-panic.test.js), the Welcome and the ratchet tree (both arrive over the
// wire during pairing), and the KeyPackage (scanned from a QR code). A failure in any of
// them must be a catchable Error and must leave the engine usable — never a WASM trap,
// which would poison the instance shared by every session.
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

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);

/** A fresh inviter + joiner, plus the genuine pairing material between them. */
async function freshPair() {
  const a = await MlsEngine.create({ name: A });
  const b = await MlsEngine.create({ name: B });
  const { welcome, ratchetTree } = a.startSession('b', b.keyPackageBytes());
  return { a, b, welcome, ratchetTree };
}

/** The engine is alive if a genuine pairing still completes and a message round-trips. */
function expectStillUsable(a, b, welcome, ratchetTree, marker) {
  b.joinSession('a', welcome, ratchetTree);
  const ct = a.session('b').encrypt(enc(marker));
  const out = b.session('a').decrypt(ct);
  expect(out.kind).toBe('application');
  expect(dec(out.plaintext)).toBe(marker);
}

/** Deterministic PRNG — a seeded fuzz run reproduces exactly on failure. */
function mulberry32(seed) {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let x = t;
    x = Math.imul(x ^ (x >>> 15), x | 1);
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

describe('MLS engine — hostile Welcome', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('garbage welcome is rejected, and a genuine join still works after it', async () => {
    const { a, b, welcome, ratchetTree } = await freshPair();

    expect(() => b.joinSession('imposter', new Uint8Array([9, 9, 9, 9]), ratchetTree)).toThrow();
    expect(b.session('imposter')).toBeUndefined();

    expectStillUsable(a, b, welcome, ratchetTree, 'genuine after garbage welcome');
  });

  test('truncated welcome is rejected', async () => {
    const { b, welcome, ratchetTree } = await freshPair();
    const half = welcome.slice(0, Math.max(1, welcome.length >> 1));

    expect(() => b.joinSession('imposter', half, ratchetTree)).toThrow();
  });

  test('bit-flipped welcome is rejected', async () => {
    const { b, welcome, ratchetTree } = await freshPair();
    const flipped = Uint8Array.from(welcome);
    flipped[flipped.length >> 1] ^= 0xff;

    expect(() => b.joinSession('imposter', flipped, ratchetTree)).toThrow();
  });

  test('an empty welcome is rejected', async () => {
    const { b, ratchetTree } = await freshPair();

    expect(() => b.joinSession('imposter', new Uint8Array(0), ratchetTree)).toThrow();
  });
});

describe('MLS engine — hostile ratchet tree', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('garbage ratchet tree is rejected, engine stays usable', async () => {
    const { a, b, welcome, ratchetTree } = await freshPair();

    expect(() => b.joinSession('imposter', welcome, new Uint8Array([7, 7, 7]))).toThrow();
    expect(b.session('imposter')).toBeUndefined();

    expectStillUsable(a, b, welcome, ratchetTree, 'genuine after garbage tree');
  });

  test('truncated ratchet tree is rejected', async () => {
    const { b, welcome, ratchetTree } = await freshPair();

    expect(() => b.joinSession('imposter', welcome, ratchetTree.slice(0, 10))).toThrow();
  });
});

describe('MLS engine — hostile KeyPackage', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('garbage KeyPackage is rejected, leaves no phantom session, and a retry succeeds', async () => {
    const a = await MlsEngine.create({ name: A });
    const c = await MlsEngine.create({ name: 'c'.repeat(64) });

    expect(() => a.startSession('c', new Uint8Array([1, 2, 3]))).toThrow();

    // startSession creates the group before it parses the KeyPackage, so the group
    // is orphaned in provider storage — but no session must be registered, or the
    // contact could never be paired again.
    expect(a.session('c')).toBeUndefined();

    const { welcome, ratchetTree } = a.startSession('c', c.keyPackageBytes());
    c.joinSession('a', welcome, ratchetTree);
    const ct = a.session('c').encrypt(enc('retry works'));
    expect(dec(c.session('a').decrypt(ct).plaintext)).toBe('retry works');
  });

  test('truncated KeyPackage is rejected', async () => {
    const a = await MlsEngine.create({ name: A });
    const c = await MlsEngine.create({ name: 'c'.repeat(64) });
    const kp = c.keyPackageBytes();

    expect(() => a.startSession('c', kp.slice(0, kp.length >> 1))).toThrow();
  });

  test('bit-flipped KeyPackage is rejected (signature must not validate)', async () => {
    const a = await MlsEngine.create({ name: A });
    const c = await MlsEngine.create({ name: 'c'.repeat(64) });
    const kp = Uint8Array.from(c.keyPackageBytes());
    kp[kp.length >> 1] ^= 0xff;

    expect(() => a.startSession('c', kp)).toThrow();
  });
});

describe('MLS engine — seeded fuzz over every untrusted parser', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('100 random buffers never trap the WASM, and the engine survives them all', async () => {
    const { a, b, welcome, ratchetTree } = await freshPair();
    const rnd = mulberry32(42);

    for (let i = 0; i < 100; i += 1) {
      const len = Math.floor(rnd() * 513); // 0..512
      const buf = new Uint8Array(len);
      for (let j = 0; j < len; j += 1) buf[j] = Math.floor(rnd() * 256);

      // Each buffer is fed to every untrusted parser. None may trap; all must throw
      // (a random buffer is not a valid Welcome, tree, or KeyPackage).
      for (const attempt of [
        () => b.joinSession(`fuzz-w-${i}`, buf, ratchetTree),
        () => b.joinSession(`fuzz-t-${i}`, welcome, buf),
        () => a.startSession(`fuzz-k-${i}`, buf),
      ]) {
        let caught;
        try {
          attempt();
        } catch (e) {
          caught = e;
        }
        expect(caught).toBeDefined();
        expect(caught).not.toBeInstanceOf(WebAssembly.RuntimeError);
      }
    }

    // 300 rejected parses later, the engine must still pair and talk.
    expectStillUsable(a, b, welcome, ratchetTree, 'alive after fuzzing');
  });
});
