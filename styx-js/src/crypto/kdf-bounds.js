// kdf-bounds.js — THE single JS policy validator for Argon2id KDF parameters
// (Blocco 3 plan, PR-1; vault spec §7.1). Pure module, zero dependencies, no
// I/O: PR-2 (wrapper codec) and PR-3 (crypto worker) MUST import this module,
// never copy it.
//
// Two validation layers exist by design:
//   * THIS policy layer: profiles, OWASP floor, exact production shapes.
//   * The absolute bounds inside styx-kdf-wasm (Rust): a component safety net,
//     intentionally wider — never a second copy of this policy.
//
// Errors never contain the password, the salt bytes, or derived output.

/**
 * Parameter profiles measured in the Argon2id spike
 * (docs/superpowers/spikes/2026-07-12-argon2id.md). Values are exact allowed
 * combinations: a wrapper claiming profile X must carry exactly X's numbers.
 * MOBILE PROFILES ARE PROVISIONAL until the manual device plan (M5) completes.
 */
export const KDF_PROFILES = Object.freeze({
  desktop: Object.freeze({ mKib: 131072, t: 3, p: 1 }),
  'mobile-balanced': Object.freeze({ mKib: 65536, t: 3, p: 1 }),
  'mobile-low-memory': Object.freeze({ mKib: 19456, t: 4, p: 1 }),
});

/** OWASP floor for Argon2id: never derive below this, whatever the wrapper says. */
export const KDF_FLOOR_M_KIB = 19456;

/** Production policy: single algorithm, single output shape. */
export const KDF_POLICY = Object.freeze({
  kdf: 'argon2id',
  kdfVersion: 19, // Argon2 v1.3
  saltLen: 16,
  outLen: 32,
  p: 1,
  tMin: 2,
  tMax: 8,
  mMaxKib: 262144, // 256 MiB
  // KDF-layer bounds in UTF-8 BYTES. The user-facing password policy of the
  // vault (8-1024 characters, plan B3.0.4) is a separate constraint imposed by
  // the vault caller in PR-2/PR-3 — characters are not bytes, and this module
  // must accept any byte string the vault layer has already accepted.
  passwordMinLen: 1,
  passwordMaxLen: 4096,
});

const ALLOWED_KEYS = Object.freeze(['kdf', 'kdfVersion', 'mKib', 't', 'p', 'salt', 'outLen', 'profile']);

export class KdfBoundsError extends Error {
  constructor(message) {
    super(message);
    this.name = 'KdfBoundsError';
    this.code = 'KDF_PARAMS_INVALID';
  }
}

const isInt = (x) => typeof x === 'number' && Number.isSafeInteger(x);

/**
 * Fail-closed validation of a KDF parameter object BEFORE any WASM call.
 * Expects exactly: { kdf, kdfVersion, mKib, t, p, salt (Uint8Array), outLen,
 * profile }. Unknown fields are rejected. Returns a frozen copy of the
 * numeric parameters ready for the derive call.
 * @throws {KdfBoundsError}
 */
export function validateKdfParams(params) {
  if (params === null || typeof params !== 'object' || Array.isArray(params)) {
    throw new KdfBoundsError('params must be a plain object');
  }
  for (const key of Object.keys(params)) {
    if (!ALLOWED_KEYS.includes(key)) throw new KdfBoundsError(`unknown field: ${key}`);
  }
  for (const key of ALLOWED_KEYS) {
    if (!Object.hasOwn(params, key)) throw new KdfBoundsError(`missing field: ${key}`);
  }
  if (params.kdf !== KDF_POLICY.kdf) throw new KdfBoundsError('unsupported kdf algorithm');
  if (params.kdfVersion !== KDF_POLICY.kdfVersion) throw new KdfBoundsError('unsupported kdf version');
  if (!(params.salt instanceof Uint8Array) || params.salt.length !== KDF_POLICY.saltLen) {
    throw new KdfBoundsError(`salt must be a Uint8Array of ${KDF_POLICY.saltLen} bytes`);
  }
  if (!isInt(params.outLen) || params.outLen !== KDF_POLICY.outLen) {
    throw new KdfBoundsError(`output length must be exactly ${KDF_POLICY.outLen}`);
  }
  if (!isInt(params.p) || params.p !== KDF_POLICY.p) {
    throw new KdfBoundsError(`parallelism must be exactly ${KDF_POLICY.p}`);
  }
  if (!isInt(params.mKib)) throw new KdfBoundsError('memory cost must be an integer');
  if (params.mKib < KDF_FLOOR_M_KIB) throw new KdfBoundsError('memory cost below the OWASP floor');
  if (params.mKib > KDF_POLICY.mMaxKib) throw new KdfBoundsError('memory cost above the policy maximum');
  if (!isInt(params.t)) throw new KdfBoundsError('iteration count must be an integer');
  if (params.t < KDF_POLICY.tMin || params.t > KDF_POLICY.tMax) {
    throw new KdfBoundsError('iteration count out of policy bounds');
  }
  // Object.hasOwn: a profile name like '__proto__' or 'constructor' must not
  // resolve through the prototype chain (review K2).
  const profile = typeof params.profile === 'string' && Object.hasOwn(KDF_PROFILES, params.profile)
    ? KDF_PROFILES[params.profile]
    : undefined;
  if (profile === undefined) {
    throw new KdfBoundsError('unknown profile');
  }
  if (params.mKib !== profile.mKib || params.t !== profile.t || params.p !== profile.p) {
    throw new KdfBoundsError('parameters do not match the declared profile');
  }
  return Object.freeze({ mKib: params.mKib, t: params.t, p: params.p, outLen: params.outLen });
}

/**
 * The only sanctioned call path to the WASM derive function: validates policy
 * bounds and password shape FIRST; on any violation the derive function is
 * never invoked (anti-allocation guarantee at the policy layer).
 * @param {(pw: Uint8Array, salt: Uint8Array, mKib: number, t: number, p: number, outLen: number) => Uint8Array} deriveFn
 * @param {Uint8Array} password
 * @param {object} params - as accepted by validateKdfParams
 * @returns {Uint8Array} the derived key (outLen bytes)
 * @throws {KdfBoundsError}
 */
export function deriveWithBounds(deriveFn, password, params) {
  if (typeof deriveFn !== 'function') throw new KdfBoundsError('deriveFn must be a function');
  const v = validateKdfParams(params);
  if (
    !(password instanceof Uint8Array)
    || password.length < KDF_POLICY.passwordMinLen
    || password.length > KDF_POLICY.passwordMaxLen
  ) {
    throw new KdfBoundsError('password must be a Uint8Array within policy length bounds');
  }
  return deriveFn(password, params.salt, v.mKib, v.t, v.p, v.outLen);
}
