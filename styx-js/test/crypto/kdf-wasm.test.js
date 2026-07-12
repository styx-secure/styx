// kdf-wasm.test.js — the real styx-kdf-wasm artifact (PR-1).
// Known-answer tests (cross-validated vectors), the Rust absolute bounds
// (called directly, BYPASSING the JS policy on purpose), failure recovery,
// anti-drift against SHA256SUMS/PROVENANCE, and the anti-allocation property
// against the real derive function.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import initKdf, { argon2id_derive } from '../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js';
import { deriveWithBounds, KdfBoundsError } from '../../src/crypto/kdf-bounds.js';
import { KDF_KAT_VECTORS, toHex } from '../fixtures/kdf-kat-vectors.js';

const wasmUrl = new URL('../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm', import.meta.url);

beforeAll(async () => {
  await initKdf({ module_or_path: readFileSync(wasmUrl) });
});

describe('styx-kdf-wasm: known-answer tests', () => {
  for (const v of KDF_KAT_VECTORS) {
    test(`KAT ${v.name}`, () => {
      const out = argon2id_derive(v.password, v.salt, v.mKib, v.t, v.p, v.outLen);
      expect(out).toBeInstanceOf(Uint8Array);
      expect(out.length).toBe(v.outLen);
      expect(toHex(out)).toBe(v.hex);
    });
  }
  test('derivation is deterministic across repeated calls', () => {
    const v = KDF_KAT_VECTORS[4]; // absolute-min-bounds: the cheapest vector
    const a = argon2id_derive(v.password, v.salt, v.mKib, v.t, v.p, v.outLen);
    const b = argon2id_derive(v.password, v.salt, v.mKib, v.t, v.p, v.outLen);
    expect(toHex(a)).toBe(toHex(b));
  });
});

describe('styx-kdf-wasm: absolute component bounds (direct calls, no JS policy)', () => {
  const pw = new Uint8Array([1, 2, 3, 4]);
  const salt16 = new Uint8Array(16);
  const cases = [
    ['empty password', () => argon2id_derive(new Uint8Array(0), salt16, 19456, 2, 1, 32)],
    ['oversized password', () => argon2id_derive(new Uint8Array(4097), salt16, 19456, 2, 1, 32)],
    ['salt too short', () => argon2id_derive(pw, new Uint8Array(7), 19456, 2, 1, 32)],
    ['salt too long', () => argon2id_derive(pw, new Uint8Array(65), 19456, 2, 1, 32)],
    ['memory below absolute floor', () => argon2id_derive(pw, salt16, 1023, 2, 1, 32)],
    ['memory above absolute max', () => argon2id_derive(pw, salt16, 262145, 2, 1, 32)],
    ['multi-GiB memory (DoS attempt)', () => argon2id_derive(pw, salt16, 3 * 1024 * 1024, 2, 1, 32)],
    ['zero iterations', () => argon2id_derive(pw, salt16, 19456, 0, 1, 32)],
    ['iterations above max', () => argon2id_derive(pw, salt16, 19456, 17, 1, 32)],
    ['zero lanes', () => argon2id_derive(pw, salt16, 19456, 2, 0, 32)],
    ['parallelism above max', () => argon2id_derive(pw, salt16, 19456, 2, 5, 32)],
    ['output too short', () => argon2id_derive(pw, salt16, 19456, 2, 1, 15)],
    ['output too long', () => argon2id_derive(pw, salt16, 19456, 2, 1, 65)],
  ];
  for (const [name, call] of cases) {
    test(`rejects ${name} with KDF_PARAMS_INVALID, never a WASM trap`, () => {
      let err;
      const t0 = performance.now();
      try {
        call();
      } catch (e) {
        err = e;
      }
      const elapsed = performance.now() - t0;
      expect(err).toBeDefined();
      expect(err).toBeInstanceOf(Error);
      expect(err).not.toBeInstanceOf(WebAssembly.RuntimeError);
      expect(String(err.message)).toMatch(/^KDF_PARAMS_INVALID/);
      // rejection happens before any Argon2 work or block allocation:
      expect(elapsed).toBeLessThan(200);
    });
  }
  test('float parameters: the binding layer coerces deterministically, never traps', () => {
    // wasm-bindgen converts JS numbers to u32 by truncation — it does NOT
    // reject non-integers. Integer enforcement therefore lives in the JS
    // policy layer (kdf-bounds.js, tested in kdf-bounds.test.js); here we pin
    // the coercion behaviour so a change in the binding layer is visible.
    const a = argon2id_derive(pw, salt16, 1024.9, 1, 1, 32);
    const b = argon2id_derive(pw, salt16, 1024, 1, 1, 32);
    expect(toHex(a)).toBe(toHex(b));
  });
  test('error messages never echo password or salt material', () => {
    const noisyPw = new TextEncoder().encode('SUPER-secret-PW-material');
    let err;
    try {
      argon2id_derive(noisyPw, salt16, 999, 2, 1, 32);
    } catch (e) {
      err = e;
    }
    expect(err.message).not.toContain('secret');
    expect(err.message).not.toMatch(/[0-9a-f]{16,}/);
  });
});

describe('styx-kdf-wasm: failure recovery', () => {
  test('a rejected derivation does not poison the instance; no partial output escapes', () => {
    const pw = new TextEncoder().encode('recovery-pw');
    const salt = new Uint8Array(16).fill(5);
    expect(() => argon2id_derive(pw, salt, 512, 2, 1, 32)).toThrow(/KDF_PARAMS_INVALID/);
    const v = KDF_KAT_VECTORS[4];
    const out = argon2id_derive(v.password, v.salt, v.mKib, v.t, v.p, v.outLen);
    expect(toHex(out)).toBe(v.hex); // still byte-correct after the failure
  });
});

describe('styx-kdf-wasm: policy layer wired to the real artifact', () => {
  test('deriveWithBounds derives 32 bytes with a real profile', () => {
    const out = deriveWithBounds(argon2id_derive, new TextEncoder().encode('integration-pw'), {
      kdf: 'argon2id',
      kdfVersion: 19,
      mKib: 19456,
      t: 4,
      p: 1,
      salt: new Uint8Array(16).fill(9),
      outLen: 32,
      profile: 'mobile-low-memory',
    });
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.length).toBe(32);
  });
  test('anti-allocation against the REAL function: invalid policy params never reach WASM', () => {
    let called = 0;
    const counting = (...args) => {
      called += 1;
      return argon2id_derive(...args);
    };
    const bad = {
      kdf: 'argon2id',
      kdfVersion: 19,
      mKib: 3 * 1024 * 1024,
      t: 4,
      p: 1,
      salt: new Uint8Array(16),
      outLen: 32,
      profile: 'mobile-low-memory',
    };
    expect(() => deriveWithBounds(counting, new Uint8Array(8), bad)).toThrow(KdfBoundsError);
    expect(called).toBe(0);
  });
});

describe('styx-kdf-wasm: artifact anti-drift', () => {
  test('committed wasm digest matches SHA256SUMS and PROVENANCE.md', () => {
    const digest = createHash('sha256').update(readFileSync(wasmUrl)).digest('hex');
    const sums = readFileSync(new URL('../../vendor/styx-kdf-wasm/pkg/SHA256SUMS', import.meta.url), 'utf8');
    expect(sums).toContain(`${digest}  styx_kdf_wasm_bg.wasm`);
    const provenance = readFileSync(new URL('../../vendor/styx-kdf-wasm/PROVENANCE.md', import.meta.url), 'utf8');
    expect(provenance).toContain(digest);
  });
  test('the KDF artifact is distinct from the OpenMLS artifact (separate lifecycle)', () => {
    const kdf = createHash('sha256').update(readFileSync(wasmUrl)).digest('hex');
    const mls = createHash('sha256')
      .update(readFileSync(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)))
      .digest('hex');
    expect(kdf).not.toBe(mls);
    expect(mls).toBe('b56e3ea095c3be3dc9a589e27ad2092bcc6de663cc788db30853e89c02ff386a');
  });
});
