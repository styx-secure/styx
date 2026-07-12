// vault-aad.js — the single canonicalization module for the vault crypto
// formats (Blocco 3, PR-2; vault spec §6/§7). Pure, zero dependencies, no I/O.
//
// Everything that must be byte-identical across implementations (JS today,
// Dart tomorrow — spec §16) lives here and ONLY here: the two canonical AAD
// serializations and canonical Base64. Wrapper and record codecs import these;
// they never re-implement them.
//
// Canonical form: the UTF-8 bytes (no BOM) of JSON.stringify over a
// fixed-order array of already-validated primitives. JSON.stringify of
// primitive strings/numbers has no toJSON hook and no key-ordering ambiguity,
// so the byte sequence is fully determined by the values.

const UTF8 = new TextEncoder();

function assertPrimitiveString(name, value) {
  if (typeof value !== 'string') throw new TypeError(`${name} must be a primitive string`);
}

function assertSafeInteger(name, value) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new TypeError(`${name} must be a safe integer`);
  }
}

/**
 * Canonical AAD of the KDF wrapper (spec §7): UTF-8 bytes of
 * `JSON.stringify([format, version, kdf, kdfVersion, mKib, t, p, saltB64,
 * outLen, keyVersion])`. `profile`, `createdAt` and `calibratedMs` are
 * DELIBERATELY excluded: they are informational metadata, validated but never
 * trusted for derivation, so binding them would only make benign metadata
 * edits (e.g. a re-calibration note) break the unwrap. Everything that decides
 * HOW the KEK is derived and WHAT it unwraps IS bound.
 *
 * Inputs must already be validated by the wrapper codec; this function only
 * asserts primitive types so a hostile object can never reach JSON.stringify.
 * @returns {Uint8Array}
 */
export function buildWrapperAadBytes({
  format, version, kdf, kdfVersion, mKib, t, p, saltB64, outLen, keyVersion,
}) {
  assertPrimitiveString('format', format);
  assertSafeInteger('version', version);
  assertPrimitiveString('kdf', kdf);
  assertSafeInteger('kdfVersion', kdfVersion);
  assertSafeInteger('mKib', mKib);
  assertSafeInteger('t', t);
  assertSafeInteger('p', p);
  assertPrimitiveString('saltB64', saltB64);
  assertSafeInteger('outLen', outLen);
  assertSafeInteger('keyVersion', keyVersion);
  return UTF8.encode(
    JSON.stringify([format, version, kdf, kdfVersion, mKib, t, p, saltB64, outLen, keyVersion]),
  );
}

/**
 * Canonical AAD of an encrypted record (spec §6): UTF-8 bytes of
 * `JSON.stringify([v, ns, k, rv, kv, ct])`. The BINDING READ-SIDE RULE lives
 * in the record codec: `ns` and `k` come from the caller's REQUEST, the other
 * fields from the record — this function just serializes what it is given.
 * @returns {Uint8Array}
 */
export function buildRecordAadBytes({ v, ns, k, rv, kv, ct }) {
  assertSafeInteger('v', v);
  assertPrimitiveString('ns', ns);
  assertPrimitiveString('k', k);
  assertSafeInteger('rv', rv);
  assertSafeInteger('kv', kv);
  assertPrimitiveString('ct', ct);
  return UTF8.encode(JSON.stringify([v, ns, k, rv, kv, ct]));
}

// ---------------------------------------------------------------------------
// Canonical Base64 (standard alphabet, mandatory padding, no whitespace).
// Hand-rolled on purpose: atob/Buffer are lenient (whitespace, missing
// padding, nonzero trailing bits), and a canonical field must have exactly
// ONE accepted encoding per byte string.
// ---------------------------------------------------------------------------

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_VALUE = new Map([...B64_ALPHABET].map((c, i) => [c, i]));

/** @returns {string} canonical Base64 of the bytes */
export function encodeBase64(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('encodeBase64 expects a Uint8Array');
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64_ALPHABET[b0 >> 2];
    out += B64_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? B64_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < bytes.length ? B64_ALPHABET[b2 & 0x3f] : '=';
  }
  return out;
}

/**
 * Strict decoder: returns the decoded bytes ONLY when `str` is the canonical
 * Base64 of those bytes (correct alphabet, correct padding, zero trailing
 * bits — verified by re-encode equality). Returns `null` on any deviation;
 * callers translate `null` into their own coded error.
 * @returns {Uint8Array|null}
 */
export function decodeCanonicalBase64(str) {
  if (typeof str !== 'string' || str.length === 0 || str.length % 4 !== 0) return null;
  const padIndex = str.indexOf('=');
  const padLen = padIndex === -1 ? 0 : str.length - padIndex;
  if (padLen > 2) return null;
  const body = padLen === 0 ? str : str.slice(0, -padLen);
  if (body.includes('=')) return null; // '=' only as trailing padding
  const byteLen = (str.length / 4) * 3 - padLen;
  const out = new Uint8Array(byteLen);
  let acc = 0;
  let accBits = 0;
  let o = 0;
  for (const ch of body) {
    const v = B64_VALUE.get(ch);
    if (v === undefined) return null;
    acc = (acc << 6) | v;
    accBits += 6;
    if (accBits >= 8) {
      accBits -= 8;
      out[o] = (acc >> accBits) & 0xff;
      o += 1;
    }
  }
  if (o !== byteLen) return null;
  // Canonicality: exactly one encoding per byte string (catches nonzero
  // trailing bits like 'QQF=' vs 'QQE=' and any leniency missed above).
  return encodeBase64(out) === str ? out : null;
}
