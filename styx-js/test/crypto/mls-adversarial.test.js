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

describe('MLS engine — hostile persisted state (restore_state)', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  // Blob format: u64 count (BE), then per entry u64 key_len, u64 val_len, key, val.
  // restore runs before Identity.load, so a malformed blob is rejected regardless of
  // the name/pubkey we pass.
  const restore = (stateBytes) =>
    MlsEngine.restore({ name: 'x'.repeat(64), stateBytes, identityPubKey: new Uint8Array(32) });

  function blob(...u64s) {
    const out = new Uint8Array(u64s.length * 8);
    const dv = new DataView(out.buffer);
    u64s.forEach((n, i) => dv.setBigUint64(i * 8, BigInt(n), false));
    return out;
  }

  test('a key length that overflows the offset math throws, it does not trap', async () => {
    // count=1, key_len=0xFFFFFFFF (fits u32 but i+kl overflows on wasm32), val_len=0.
    // Pre-fix this wrapped past the bound check into an out-of-range slice → trap.
    const evil = blob(1, 0xffffffff, 0);
    let caught;
    try { await restore(evil); } catch (e) { caught = e; }
    expect(caught).toBeDefined();
    expect(caught).not.toBeInstanceOf(WebAssembly.RuntimeError);
  });

  test('a length that does not fit in usize is rejected', async () => {
    const evil = blob(1, 0x100000000, 0); // 2^32, cannot index a wasm32 buffer
    await expect(restore(evil)).rejects.toBeDefined();
  });

  test('a truncated blob is rejected', async () => {
    const evil = blob(5); // claims 5 entries, carries none
    await expect(restore(evil)).rejects.toBeDefined();
  });

  test('the engine still works after a rejected restore', async () => {
    try { await restore(blob(1, 0xffffffff, 0)); } catch { /* expected */ }
    // A fresh pairing must still succeed — the failed restore did not poison the wasm.
    const a = await MlsEngine.create({ name: A });
    const b = await MlsEngine.create({ name: B });
    const { welcome, ratchetTree } = a.startSession('b', b.keyPackageBytes());
    b.joinSession('a', welcome, ratchetTree);
    const ct = a.session('b').encrypt(enc('alive after bad restore'));
    expect(dec(b.session('a').decrypt(ct).plaintext)).toBe('alive after bad restore');
  });
});

describe('MLS engine — seeded fuzz over every untrusted parser', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('100 random buffers never trap the WASM, and the engine survives them all', async () => {
    const { a, b, welcome, ratchetTree } = await freshPair();
    // A live session so the fuzz can reach process_message — the parser N1 actually
    // changed. Without this the loop would only exercise the join/KeyPackage parsers,
    // which already returned Result before this work.
    b.joinSession('live', welcome, ratchetTree);
    const rnd = mulberry32(42);

    for (let i = 0; i < 100; i += 1) {
      const len = Math.floor(rnd() * 513); // 0..512
      const buf = new Uint8Array(len);
      for (let j = 0; j < len; j += 1) buf[j] = Math.floor(rnd() * 256);

      // Each buffer is fed to every untrusted parser. None may trap; all must throw
      // (a random buffer is not a valid message, Welcome, tree, or KeyPackage).
      for (const attempt of [
        () => b.session('live').decrypt(buf), // process_message — the N1 surface
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

    // 400 rejected parses later, the live session must still carry a real message.
    const ct = a.session('b').encrypt(enc('alive after fuzzing'));
    const out = b.session('live').decrypt(ct);
    expect(out.kind).toBe('application');
    expect(dec(out.plaintext)).toBe('alive after fuzzing');
  });
});
