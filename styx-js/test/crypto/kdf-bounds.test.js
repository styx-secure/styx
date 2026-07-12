// kdf-bounds.test.js — the JS policy layer for Argon2id parameters (PR-1).
// Pure tests: no WASM here. The anti-allocation property (invalid params never
// reach the derive function) is proven with a spy; the same property against
// the real artifact is in kdf-wasm.test.js.
import {
  KDF_PROFILES,
  KDF_FLOOR_M_KIB,
  KDF_POLICY,
  KdfBoundsError,
  validateKdfParams,
  deriveWithBounds,
} from '../../src/crypto/kdf-bounds.js';

const validParams = (over = {}) => ({
  kdf: 'argon2id',
  kdfVersion: 19,
  mKib: 19456,
  t: 4,
  p: 1,
  salt: new Uint8Array(16),
  outLen: 32,
  profile: 'mobile-low-memory',
  ...over,
});

const expectRejected = (params, hint) => {
  expect(() => validateKdfParams(params)).toThrow(KdfBoundsError);
  try {
    validateKdfParams(params);
  } catch (e) {
    expect(e.code).toBe('KDF_PARAMS_INVALID');
    expect(e.message).not.toMatch(/[0-9a-f]{32}/); // never echo key-sized material
    if (hint) expect(e.message).toContain(hint);
  }
};

describe('kdf-bounds: profiles and policy constants', () => {
  test('profiles are frozen, respect the OWASP floor, and use p=1', () => {
    expect(Object.isFrozen(KDF_PROFILES)).toBe(true);
    for (const [name, prof] of Object.entries(KDF_PROFILES)) {
      expect(Object.isFrozen(prof)).toBe(true);
      expect(prof.mKib).toBeGreaterThanOrEqual(KDF_FLOOR_M_KIB);
      expect(prof.mKib).toBeLessThanOrEqual(KDF_POLICY.mMaxKib);
      expect(prof.p).toBe(1);
      expect(name).toMatch(/^[a-z-]+$/);
    }
  });
});

describe('kdf-bounds: validateKdfParams accepts exactly the allowed shapes', () => {
  test('every profile with its exact numbers validates', () => {
    for (const [profile, prof] of Object.entries(KDF_PROFILES)) {
      const v = validateKdfParams(validParams({ profile, mKib: prof.mKib, t: prof.t, p: prof.p }));
      expect(v).toEqual({ mKib: prof.mKib, t: prof.t, p: prof.p, outLen: 32 });
      expect(Object.isFrozen(v)).toBe(true);
    }
  });
});

describe('kdf-bounds: fail-closed rejection', () => {
  test('non-object params', () => {
    for (const bad of [null, undefined, 'x', 42, [], () => {}]) expectRejected(bad);
  });
  test('unknown and missing fields', () => {
    expectRejected(validParams({ extra: 1 }), 'unknown field');
    const p = validParams();
    delete p.profile;
    expectRejected(p, 'missing field');
  });
  test('wrong algorithm and version', () => {
    expectRejected(validParams({ kdf: 'argon2i' }), 'algorithm');
    expectRejected(validParams({ kdf: 'ARGON2ID' }), 'algorithm');
    expectRejected(validParams({ kdfVersion: 16 }), 'version');
  });
  test('salt shape', () => {
    expectRejected(validParams({ salt: new Uint8Array(15) }), 'salt');
    expectRejected(validParams({ salt: new Uint8Array(17) }), 'salt');
    expectRejected(validParams({ salt: 'AAAAAAAAAAAAAAAA' }), 'salt');
    expectRejected(validParams({ salt: new Array(16).fill(0) }), 'salt');
  });
  test('output length must be exactly 32', () => {
    for (const outLen of [16, 31, 33, 64, 0, -32]) expectRejected(validParams({ outLen }));
  });
  test('memory bounds: below floor, above max', () => {
    expectRejected(validParams({ mKib: KDF_FLOOR_M_KIB - 1 }), 'floor');
    expectRejected(validParams({ mKib: KDF_POLICY.mMaxKib + 1 }), 'maximum');
    expectRejected(validParams({ mKib: 3 * 1024 * 1024 }), 'maximum'); // 3 GiB DoS attempt
  });
  test('iteration bounds', () => {
    expectRejected(validParams({ t: 0 }));
    expectRejected(validParams({ t: 1 }));
    expectRejected(validParams({ t: 9 }));
    expectRejected(validParams({ t: 1000 }));
  });
  test('parallelism must be exactly 1', () => {
    for (const p of [0, 2, 4, -1]) expectRejected(validParams({ p }));
  });
  test('non-integer numerics: NaN, Infinity, floats, negatives, strings', () => {
    for (const field of ['mKib', 't', 'p', 'outLen', 'kdfVersion']) {
      for (const bad of [NaN, Infinity, -Infinity, 3.5, -1, '19456', 19456n, null]) {
        expectRejected(validParams({ [field]: bad }));
      }
    }
  });
  test('unknown profile and profile/parameter mismatch', () => {
    expectRejected(validParams({ profile: 'paranoid' }), 'profile');
    expectRejected(validParams({ profile: 42 }), 'profile');
    // prototype-chain names must not resolve to a "profile" (review K2):
    expectRejected(validParams({ profile: '__proto__' }), 'profile');
    expectRejected(validParams({ profile: 'constructor' }), 'profile');
    expectRejected(validParams({ profile: 'toString' }), 'profile');
    // valid numbers, but not the numbers of the declared profile:
    expectRejected(validParams({ profile: 'desktop' }), 'declared profile');
    expectRejected(validParams({ t: 5 })); // in range, but not mobile-low-memory's t
    expectRejected(validParams({ mKib: 20480 })); // above floor, but not a profile combination
  });
});

describe('kdf-bounds: deriveWithBounds anti-allocation guarantee', () => {
  const makeSpy = () => {
    const spy = (...args) => { spy.calls.push(args); return new Uint8Array(32); };
    spy.calls = [];
    return spy;
  };

  test('invalid params: the derive function is NEVER invoked', () => {
    const spy = makeSpy();
    const badCases = [
      validParams({ mKib: 3 * 1024 * 1024 }),
      validParams({ t: NaN }),
      validParams({ profile: 'paranoid' }),
      validParams({ extra: true }),
    ];
    for (const params of badCases) {
      expect(() => deriveWithBounds(spy, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), params)).toThrow(KdfBoundsError);
    }
    expect(spy.calls).toHaveLength(0);
  });
  test('invalid password shape: derive never invoked', () => {
    const spy = makeSpy();
    for (const pw of [new Uint8Array(0), new Uint8Array(4097), 'password', null]) {
      expect(() => deriveWithBounds(spy, pw, validParams())).toThrow(KdfBoundsError);
    }
    expect(spy.calls).toHaveLength(0);
  });
  test('valid params: derive invoked once with the validated numbers', () => {
    const spy = makeSpy();
    const pw = new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9]);
    const params = validParams();
    const out = deriveWithBounds(spy, pw, params);
    expect(out).toEqual(new Uint8Array(32));
    expect(spy.calls).toHaveLength(1);
    expect(spy.calls[0]).toEqual([pw, params.salt, 19456, 4, 1, 32]);
  });
});
