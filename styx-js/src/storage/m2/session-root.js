// M2 keyed complete-record root/manifest construction and cross-record authority validation.
// Internal-only: no barrel export.
//
// This module builds the C-FMT canonical manifest, its literal digest, the keyed root and the
// manifest record key, and decides whether the already-stored complete set named by the
// authenticated fixed-locator version-3 selector is internally consistent and authoritative.
// It reuses `./session-codec.js` unchanged for the canonical record key, the kind-17 plaintext
// codec and the namespace key schedule.
import {
  M2_KIND,
  encodeRecordKey,
  decodeRecordKey,
  decodePlaintext,
} from './session-codec.js';

const TE = new TextEncoder();
const ASCII = (s) => TE.encode(s);
const U64_MAX = (1n << 64n) - 1n;
const MAX_PLAINTEXT = 16 * 1024 * 1024;
const MANIFEST_MAGIC = 'STYXMAN1';
const ROOT_LABEL = 'STYXROOT1';
const CIPHERTEXT_DIGEST_LABEL = 'STYX-M2-CIPHERTEXT-DIGEST-V1';
const MANIFEST_ROOT_INFO = 'styx/m2/fmt/v1/manifest-root';

export const M2_ROOT = Object.freeze({
  MANIFEST_VERSION: 1,
  MANIFEST_KIND: 16,
  SELECTOR_KIND: 17,
  DATA_KIND_COUNT: 15,
});

const DATA_KINDS = Object.freeze(Array.from({ length: M2_ROOT.DATA_KIND_COUNT }, (_, i) => i + 1));
const MUTATION_HOLD_KIND = M2_KIND.MUTATION_HOLD;
const SELECTOR_STATE_RECONCILIATION_REQUIRED = 3;
const COMMIT_OUTCOME = Object.freeze({ COMMITTED: 1, NOT_COMMITTED: 2, INDETERMINATE: 3 });
const COMMIT_OUTCOME_INDETERMINATE = COMMIT_OUTCOME.INDETERMINATE;

const CODE = Object.freeze({
  MALFORMED_INPUT: 'MALFORMED_INPUT',
  UNSUPPORTED_VALUE: 'UNSUPPORTED_VALUE',
  CONTEXT_MISMATCH: 'CONTEXT_MISMATCH',
  MANIFEST_INCOMPLETE: 'MANIFEST_INCOMPLETE',
  ROOT_MISMATCH: 'ROOT_MISMATCH',
  HISTORICAL_SUBSET: 'HISTORICAL_SUBSET',
  CANDIDATE_MISMATCH: 'CANDIDATE_MISMATCH',
  PARENT_MISMATCH: 'PARENT_MISMATCH',
});

export class M2RootError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'M2RootError';
    this.code = code;
  }
}

const fail = (code, message) => { throw new M2RootError(code, message); };
const malformed = (m) => fail(CODE.MALFORMED_INPUT, m);
const unsupported = (m) => fail(CODE.UNSUPPORTED_VALUE, m);
const mismatch = (m) => fail(CODE.CONTEXT_MISMATCH, m);

function strictObject(value, keys, name = 'value') {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) malformed(`${name} must be a plain object`);
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some((k) => typeof k !== 'string' || !keys.includes(k))) {
    malformed(`${name} has an unknown, missing, or symbol property`);
  }
  const out = {};
  for (const key of keys) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) malformed(`${name}.${key} must be enumerable data`);
    out[key] = d.value;
  }
  return out;
}
function bytes(value, length, name) {
  if (!(value instanceof Uint8Array) || (length !== null && value.length !== length)) malformed(`${name} has wrong byte width`);
  // Uint8Array.prototype.slice, never value.slice(): Buffer overrides slice() to return a view.
  return Uint8Array.prototype.slice.call(value);
}
function nonzero(value, name) {
  const out = bytes(value, 32, name);
  if (out.every((b) => b === 0)) malformed(`${name} must be nonzero`);
  return out;
}
function safeInt(value, max, name) {
  if (!Number.isSafeInteger(value) || value < 0 || value > max) malformed(`${name} is out of range`);
  return value;
}
function u64(value, name) {
  if (typeof value !== 'bigint' || value < 0n || value > U64_MAX) malformed(`${name} is out of range`);
  return value;
}
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const sameIdentity = (a, b) => (a === null || b === null ? a === b : equal(a, b));
const concat = (...parts) => {
  const length = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(length); let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
};
const be16 = (n) => Uint8Array.of((n >>> 8) & 255, n & 255);
const be32 = (n) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
function be64(n) { const out = new Uint8Array(8); let x = n; for (let i = 7; i >= 0; i -= 1) { out[i] = Number(x & 255n); x >>= 8n; } return out; }
const frame = (x) => concat(be32(x.length), x);
const read16 = (b, o) => b[o] * 256 + b[o + 1];
const read32 = (b, o) => b[o] * 0x1000000 + b[o + 1] * 0x10000 + b[o + 2] * 0x100 + b[o + 3];
const read64 = (b, o) => { let n = 0n; for (let i = 0; i < 8; i += 1) n = (n << 8n) | BigInt(b[o + i]); return n; };

// Compact synchronous SHA-256 / HMAC-SHA-256, needed by the synchronous canonical encoders.
function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
function sha256(input) {
  const b = bytes(input, null, 'sha256 input'); const bitLen = BigInt(b.length) * 8n;
  const total = Math.ceil((b.length + 9) / 64) * 64; const p = new Uint8Array(total); p.set(b); p[b.length] = 0x80;
  for (let i = 0; i < 8; i += 1) p[total - 1 - i] = Number((bitLen >> BigInt(i * 8)) & 255n);
  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const w = new Uint32Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i += 1) w[i] = ((p[off + i * 4] << 24) | (p[off + i * 4 + 1] << 16) | (p[off + i * 4 + 2] << 8) | p[off + i * 4 + 3]) >>> 0;
    for (let i = 16; i < 64; i += 1) { const a = w[i - 15], z = w[i - 2]; const s0 = rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3); const s1 = rotr(z, 17) ^ rotr(z, 19) ^ (z >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0; }
    let [a, c, d, e, f, g, j, k] = h;
    for (let i = 0; i < 64; i += 1) { const s1 = rotr(f, 6) ^ rotr(f, 11) ^ rotr(f, 25); const ch = (f & g) ^ (~f & j); const t1 = (k + s1 + ch + K256[i] + w[i]) >>> 0; const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22); const maj = (a & c) ^ (a & d) ^ (c & d); const t2 = (s0 + maj) >>> 0; k = j; j = g; g = f; f = (e + t1) >>> 0; e = d; d = c; c = a; a = (t1 + t2) >>> 0; }
    const q = [a, c, d, e, f, g, j, k]; for (let i = 0; i < 8; i += 1) h[i] = (h[i] + q[i]) >>> 0;
  }
  const out = new Uint8Array(32); for (let i = 0; i < 8; i += 1) { out[i * 4] = h[i] >>> 24; out[i * 4 + 1] = h[i] >>> 16; out[i * 4 + 2] = h[i] >>> 8; out[i * 4 + 3] = h[i]; } return out;
}
function hmacSha256(key, message) {
  const blockSize = 64;
  let hk = bytes(key, null, 'hmac key');
  if (hk.length > blockSize) hk = sha256(hk);
  const padded = new Uint8Array(blockSize); padded.set(hk);
  const ipad = new Uint8Array(blockSize); const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i += 1) { ipad[i] = padded[i] ^ 0x36; opad[i] = padded[i] ^ 0x5c; }
  return sha256(concat(opad, sha256(concat(ipad, message))));
}

const kindVersionFor = (kind) => { if (kind === MUTATION_HOLD_KIND) return 2; return 1; };

function manifestKeyParts(manifestKey, name) {
  const key = bytes(manifestKey, null, name);
  let decoded;
  try { decoded = decodeRecordKey(key); } catch (e) {
    mismatch(`${name} is not a canonical record key: ${e.message}`);
  }
  if (decoded.recordKind !== M2_ROOT.MANIFEST_KIND) mismatch(`${name} is not a kind-16 manifest key`);
  if (decoded.objectId.length !== 0) mismatch(`${name} carries a non-empty object id`);
  return { key, decoded };
}

/**
 * HMAC-SHA-256 keyed root over the canonical manifest.
 * `manifestRootKey` is the C-FMT `manifestRoot` KDF stage (K_manifest).
 */
export function computeKeyedRoot(input) {
  const s = strictObject(input, ['manifestRootKey', 'manifestKey', 'generation', 'manifestBytes'], 'keyed root');
  const km = bytes(s.manifestRootKey, 32, 'manifestRootKey');
  const { key, decoded: manifestKeyDecoded } = manifestKeyParts(s.manifestKey, 'manifestKey');
  const generation = u64(s.generation, 'generation');
  if (generation === 0n) malformed('generation zero');
  const mbytes = bytes(s.manifestBytes, null, 'manifestBytes');
  // The keyed root covers the literal bytes of a complete canonical manifest only, and every entry
  // must be a record of that very generation: a manifest of the current generation that carries a
  // historical key of one kind is a partial generation, not a complete one.
  const entries = decodeManifest(mbytes);
  for (const entry of entries) {
    const ed = decodeRecordKey(entry.recordKey);
    if (ed.writeGeneration !== generation) {
      fail(CODE.HISTORICAL_SUBSET, 'manifest entry key belongs to a different generation than the manifest');
    }
    if (ed.scope !== manifestKeyDecoded.scope
        || !equal(ed.localContextId, manifestKeyDecoded.localContextId)
        || !sameIdentity(ed.secureSessionIdentity, manifestKeyDecoded.secureSessionIdentity)) {
      mismatch('manifest entry key is not in the manifest key locator context');
    }
  }
  const message = concat(
    ASCII(ROOT_LABEL), be16(M2_ROOT.MANIFEST_VERSION), be64(generation),
    be16(key.length), key, sha256(mbytes), mbytes,
  );
  return hmacSha256(km, message);
}

/** SHA-256 of the literal complete canonical manifest key. */
export function manifestKeyDigest(manifestKey) {
  const { key } = manifestKeyParts(manifestKey, 'manifestKey');
  return sha256(key);
}

/** C-FMT ciphertext digest of one sealed data record. */
export function ciphertextDigest(input) {
  const s = strictObject(input, ['recordKey', 'recordKind', 'ciphertext', 'tag'], 'ciphertext digest');
  const key = bytes(s.recordKey, null, 'recordKey');
  const kind = safeInt(s.recordKind, 65535, 'recordKind');
  if (kind < 1 || kind > M2_ROOT.DATA_KIND_COUNT) unsupported('ciphertext digest kind is not a data record kind');
  const ciphertext = bytes(s.ciphertext, null, 'ciphertext');
  const tag = bytes(s.tag, 16, 'tag');
  if (ciphertext.length > MAX_PLAINTEXT) malformed('ciphertext exceeds bound');
  return sha256(concat(ASCII(CIPHERTEXT_DIGEST_LABEL), frame(key), be16(kind), be16(kindVersionFor(kind)), frame(concat(ciphertext, tag))));
}

/** One canonical manifest entry for a data record. */
export function manifestEntry(input) {
  const s = strictObject(input, ['recordKey', 'recordKind', 'ciphertextDigest'], 'manifest entry');
  const key = bytes(s.recordKey, null, 'recordKey');
  const kind = safeInt(s.recordKind, 65535, 'recordKind');
  if (kind < 1 || kind > M2_ROOT.DATA_KIND_COUNT) unsupported('manifest entry kind is not a data record kind');
  let decoded;
  try { decoded = decodeRecordKey(key); } catch (e) { mismatch(`manifest entry key is not canonical: ${e.message}`); }
  if (decoded.recordKind !== kind) mismatch('manifest entry key kind does not match its record kind');
  const digest = bytes(s.ciphertextDigest, 32, 'ciphertextDigest');
  return Object.freeze({ recordKey: key, recordKind: kind, recordKindVersion: kindVersionFor(kind), ciphertextDigest: digest });
}

const ENTRY_KEYS = ['recordKey', 'recordKind', 'recordKindVersion', 'ciphertextDigest'];

function canonicalEntry(value, name) {
  const s = strictObject(value, ENTRY_KEYS, name);
  const key = bytes(s.recordKey, null, `${name}.recordKey`);
  const kind = safeInt(s.recordKind, 65535, `${name}.recordKind`);
  if (kind < 1 || kind > M2_ROOT.DATA_KIND_COUNT) unsupported(`${name}.recordKind is not a data record kind`);
  const version = safeInt(s.recordKindVersion, 65535, `${name}.recordKindVersion`);
  if (version !== kindVersionFor(kind)) unsupported(`${name}.recordKindVersion does not match its record kind`);
  let decoded;
  try { decoded = decodeRecordKey(key); } catch (e) { mismatch(`${name}.recordKey is not canonical: ${e.message}`); }
  if (decoded.recordKind !== kind) mismatch(`${name}.recordKey kind does not match its record kind`);
  const digest = bytes(s.ciphertextDigest, 32, `${name}.ciphertextDigest`);
  return { recordKey: key, recordKind: kind, recordKindVersion: version, ciphertextDigest: digest };
}

/**
 * Encode the canonical complete manifest. `entries` must already contain exactly the fifteen
 * data kinds 1..15, each once, in strictly ascending unsigned-lexicographic canonical-key order.
 */
export function encodeManifest(entries) {
  if (!Array.isArray(entries)) malformed('entries must be an array');
  if (entries.length !== M2_ROOT.DATA_KIND_COUNT) {
    fail(entries.length < M2_ROOT.DATA_KIND_COUNT ? CODE.HISTORICAL_SUBSET : CODE.MANIFEST_INCOMPLETE,
      `manifest must carry exactly ${M2_ROOT.DATA_KIND_COUNT} entries`);
  }
  const canonical = entries.map((entry, i) => canonicalEntry(entry, `entries[${i}]`));
  const seen = new Set();
  for (const entry of canonical) {
    if (seen.has(entry.recordKind)) unsupported('manifest has a duplicate data record kind');
    seen.add(entry.recordKind);
  }
  for (const kind of DATA_KINDS) if (!seen.has(kind)) fail(CODE.MANIFEST_INCOMPLETE, `manifest omits data kind ${kind}`);
  for (let i = 1; i < canonical.length; i += 1) {
    const prev = canonical[i - 1].recordKey; const cur = canonical[i].recordKey;
    if (compareBytes(prev, cur) >= 0) malformed('manifest entries are not in strictly ascending canonical-key order');
  }
  const parts = [];
  for (const entry of canonical) {
    parts.push(be16(entry.recordKey.length), entry.recordKey, be16(entry.recordKind), be16(entry.recordKindVersion), entry.ciphertextDigest);
  }
  const out = concat(ASCII(MANIFEST_MAGIC), be16(M2_ROOT.MANIFEST_VERSION), be32(canonical.length), ...parts);
  if (out.length > MAX_PLAINTEXT) malformed('manifest exceeds the C-FMT plaintext cap');
  return out;
}

function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

/** Decode the canonical complete manifest; rejects every non-canonical or incomplete byte string. */
export function decodeManifest(value) {
  const b = bytes(value, null, 'manifest');
  if (b.length > MAX_PLAINTEXT) malformed('manifest exceeds the C-FMT plaintext cap');
  const magic = ASCII(MANIFEST_MAGIC);
  if (b.length < magic.length + 6 || !equal(b.slice(0, magic.length), magic)) malformed('wrong manifest magic');
  let o = magic.length;
  if (read16(b, o) !== M2_ROOT.MANIFEST_VERSION) unsupported('unknown manifest version');
  o += 2;
  const count = read32(b, o); o += 4;
  if (count !== M2_ROOT.DATA_KIND_COUNT) {
    fail(count < M2_ROOT.DATA_KIND_COUNT ? CODE.HISTORICAL_SUBSET : CODE.MANIFEST_INCOMPLETE,
      `manifest declares ${count} entries, expected ${M2_ROOT.DATA_KIND_COUNT}`);
  }
  const out = [];
  const seen = new Set();
  let previous = null;
  for (let i = 0; i < count; i += 1) {
    if (o + 2 > b.length) malformed('truncated manifest entry');
    const kl = read16(b, o); o += 2;
    if (o + kl + 36 > b.length) malformed('truncated manifest entry');
    const key = b.slice(o, o + kl); o += kl;
    const kind = read16(b, o); o += 2;
    const version = read16(b, o); o += 2;
    const digest = b.slice(o, o + 32); o += 32;
    if (kind < 1 || kind > M2_ROOT.DATA_KIND_COUNT) unsupported('manifest entry kind is not a data record kind');
    if (version !== kindVersionFor(kind)) unsupported('manifest entry kind version mismatch');
    let decoded;
    try { decoded = decodeRecordKey(key); } catch (e) { mismatch(`manifest entry key is not canonical: ${e.message}`); }
    if (decoded.recordKind !== kind) mismatch('manifest entry key kind does not match its record kind');
    if (seen.has(kind)) unsupported('manifest has a duplicate data record kind');
    seen.add(kind);
    if (previous !== null && compareBytes(previous, key) >= 0) malformed('manifest entries are not in strictly ascending canonical-key order');
    previous = key;
    out.push(Object.freeze({ recordKey: key.slice(), recordKind: kind, recordKindVersion: version, ciphertextDigest: digest.slice() }));
  }
  if (o !== b.length) malformed('manifest has trailing bytes');
  for (const kind of DATA_KINDS) if (!seen.has(kind)) fail(CODE.MANIFEST_INCOMPLETE, `manifest omits data kind ${kind}`);
  const frozen = Object.freeze(out);
  if (!equal(encodeManifest(frozen), b)) malformed('noncanonical manifest');
  return frozen;
}

/** Canonical kind-16 manifest record key with an empty object id. */
export function encodeManifestKey(input) {
  const s = strictObject(input, ['localContextId', 'scope', 'secureSessionIdentity', 'writeGeneration'], 'manifest key');
  return encodeRecordKey({
    scope: s.scope,
    localContextId: s.localContextId,
    secureSessionIdentity: s.secureSessionIdentity,
    writeGeneration: s.writeGeneration,
    recordKind: M2_ROOT.MANIFEST_KIND,
  });
}

/**
 * C-FMT `manifestRoot` KDF stage: HKDF-SHA-256(K_namespace, 32 zero bytes,
 * ASCII "styx/m2/fmt/v1/manifest-root" || u16be(1) || frame(localContextId) || frame(productProfileDigest)).
 */
export async function deriveManifestRootKey(input) {
  const s = strictObject(input, ['namespaceKey', 'localContextId', 'productProfileDigest'], 'manifest root KDF');
  const namespaceKey = bytes(s.namespaceKey, 32, 'namespaceKey');
  const context = nonzero(s.localContextId, 'localContextId');
  const profileDigest = bytes(s.productProfileDigest, 32, 'productProfileDigest');
  const info = concat(ASCII(MANIFEST_ROOT_INFO), be16(1), frame(context), frame(profileDigest));
  const key = await crypto.subtle.importKey('raw', namespaceKey, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info }, key, 256);
  return new Uint8Array(bits);
}

const GENERATION_KEYS = ['generation', 'manifestKey', 'manifestBytes', 'manifestCipherDigest', 'keyedRoot', 'mutationHold', 'sessionBindingDigest'];
const HOLD_REQUIRED_KEYS = ['presence', 'resultStatus', 'parentGeneration', 'parentKeyedRoot'];

// Reads exactly the fields this module consumes and ignores the further kind-13 fields the contract
// leaves in place (the decoded hold value carries more than these four).
function requiredFields(value, keys, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) malformed(`${name} must be a plain value`);
  const out = {};
  for (const key of keys) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) malformed(`${name}.${key} must be enumerable data`);
    out[key] = d.value;
  }
  return out;
}

function holdFacts(hold, name) {
  if (hold === null) return null;
  if (typeof hold !== 'object' || Array.isArray(hold)) malformed(`${name} must be null or a plain object`);
  const presence = Object.getOwnPropertyDescriptor(hold, 'presence');
  if (!presence || !Object.hasOwn(presence, 'value')) malformed(`${name} must be a plain value`);
  if (presence.value === 0) {
    requiredFields(hold, ['presence'], name);
    return Object.freeze({ presence: 0 });
  }
  if (presence.value !== 1) unsupported(`${name} has an invalid presence`);
  const h = requiredFields(hold, HOLD_REQUIRED_KEYS, name);
  const resultStatus = safeInt(h.resultStatus, 255, `${name}.resultStatus`);
  // The C-MUT outcome is a closed set: an undefined outcome must fail closed, never read as terminal.
  if (resultStatus !== COMMIT_OUTCOME.COMMITTED && resultStatus !== COMMIT_OUTCOME.NOT_COMMITTED
      && resultStatus !== COMMIT_OUTCOME.INDETERMINATE) {
    unsupported(`${name}.resultStatus is not a defined commit outcome`);
  }
  const parentGeneration = u64(h.parentGeneration, `${name}.parentGeneration`);
  const parentKeyedRoot = bytes(h.parentKeyedRoot, 32, `${name}.parentKeyedRoot`);
  return Object.freeze({ presence: 1, resultStatus, parentGeneration, parentKeyedRoot });
}

function generationFacts(value, name) {
  const s = strictObject(value, GENERATION_KEYS, name);
  const generation = u64(s.generation, `${name}.generation`);
  if (generation === 0n) malformed(`${name}.generation is zero`);
  const { key, decoded } = manifestKeyParts(s.manifestKey, `${name}.manifestKey`);
  if (decoded.writeGeneration !== generation) mismatch(`${name} manifest key generation does not match its generation`);
  const manifestBytes = bytes(s.manifestBytes, null, `${name}.manifestBytes`);
  const manifestCipherDigest = bytes(s.manifestCipherDigest, 32, `${name}.manifestCipherDigest`);
  const keyedRoot = bytes(s.keyedRoot, 32, `${name}.keyedRoot`);
  const holdValue = holdFacts(s.mutationHold, `${name}.mutationHold`);
  const sessionBindingDigest = s.sessionBindingDigest === null ? null : bytes(s.sessionBindingDigest, 32, `${name}.sessionBindingDigest`);
  const sessionScoped = decoded.scope === 2;
  if ((sessionBindingDigest !== null) !== sessionScoped) mismatch(`${name} session binding digest does not match its key scope`);
  return { generation, key, decoded, manifestBytes, manifestCipherDigest, keyedRoot, hold: holdValue, sessionBindingDigest, sessionScoped };
}

/**
 * Decide whether the complete set named by the authenticated selector is internally consistent
 * and authoritative. Never mutates its inputs and never promotes a candidate to authority.
 */
export function validateAuthority(input) {
  const s = strictObject(input, ['selector', 'manifestRootKey', 'selected', 'candidate'], 'authority input');
  const manifestRootKey = bytes(s.manifestRootKey, 32, 'manifestRootKey');
  const selectorBytes = bytes(s.selector, null, 'selector');
  let selector;
  try { selector = decodePlaintext(M2_ROOT.SELECTOR_KIND, selectorBytes); } catch (e) {
    unsupported(`selector plaintext is not canonical: ${e.message}`);
  }
  if (selector.presence !== 1) unsupported('selector plaintext is a tombstone');
  const selected = generationFacts(s.selected, 'selected');
  const candidate = s.candidate === null ? null : generationFacts(s.candidate, 'candidate');
  if (candidate !== null && !equal(candidate.decoded.localContextId, selected.decoded.localContextId)) {
    mismatch('candidate manifest key context does not match the selected locator context');
  }

  if (selected.generation !== selector.generation) mismatch('selector generation does not match the selected generation');
  if (!equal(sha256(selected.key), selector.manifestKeyDigest)) mismatch('selector manifest key digest does not match the selected manifest key');
  if (!equal(selected.manifestCipherDigest, selector.manifestCipherDigest)) fail(CODE.ROOT_MISMATCH, 'selector manifest ciphertext digest does not match the selected manifest record');
  decodeManifest(selected.manifestBytes);
  const selectedRoot = computeKeyedRoot({
    manifestRootKey, manifestKey: selected.key, generation: selected.generation, manifestBytes: selected.manifestBytes,
  });
  if (!equal(selectedRoot, selected.keyedRoot)) fail(CODE.ROOT_MISMATCH, 'selected generation declares a keyed root that its own manifest does not produce');
  if (!equal(selectedRoot, selector.keyedRoot)) fail(CODE.ROOT_MISMATCH, 'selector keyed root does not match the selected manifest');

  const tupleSame = selector.candidateGeneration === selector.generation
    && equal(selector.candidateManifestKeyDigest, selector.manifestKeyDigest)
    && equal(selector.candidateManifestCipherDigest, selector.manifestCipherDigest)
    && equal(selector.candidateKeyedRoot, selector.keyedRoot);
  const reconciliationRequired = selector.state === SELECTOR_STATE_RECONCILIATION_REQUIRED;
  if (tupleSame === reconciliationRequired) {
    fail(CODE.CANDIDATE_MISMATCH, 'selector state and candidate tuple are inconsistent');
  }

  let candidateRoot = null;
  if (tupleSame) {
    if (candidate !== null) fail(CODE.CANDIDATE_MISMATCH, 'a separate candidate is present although the selector declares none');
    // The selector names the selected generation itself as authority, so a present unresolved hold
    // must name that same physical generation and root.
    if (selected.hold !== null && selected.hold.presence === 1
        && selected.hold.resultStatus === COMMIT_OUTCOME_INDETERMINATE
        && (selected.hold.parentGeneration !== selector.generation
          || !equal(selected.hold.parentKeyedRoot, selector.keyedRoot))) {
      fail(CODE.PARENT_MISMATCH, 'selected unresolved hold parent does not match the selector physical authority');
    }
    return Object.freeze({
      authority: 'SELECTED',
      state: selector.state,
      selectedGeneration: selected.generation,
      candidateGeneration: selector.candidateGeneration,
      selectedKeyedRoot: selectedRoot.slice(),
      candidateKeyedRoot: null,
      candidateIsAuthority: false,
    });
  }

  // A separate candidate: selected MUTATION_HOLD must be a tombstone and the candidate hold must be present.
  if (candidate === null) fail(CODE.CANDIDATE_MISMATCH, 'selector names a separate candidate that was not supplied');
  if (selected.hold === null || selected.hold.presence !== 0) {
    fail(CODE.CANDIDATE_MISMATCH, 'selected generation MUTATION_HOLD is not a tombstone');
  }
  if (candidate.hold === null || candidate.hold.presence !== 1) {
    fail(CODE.CANDIDATE_MISMATCH, 'candidate generation MUTATION_HOLD is not present');
  }
  if (candidate.generation !== selector.candidateGeneration) mismatch('selector candidate generation does not match the candidate');
  if (!equal(sha256(candidate.key), selector.candidateManifestKeyDigest)) {
    fail(CODE.CANDIDATE_MISMATCH, 'selector candidate manifest key digest does not match the candidate manifest key');
  }
  if (!equal(candidate.manifestCipherDigest, selector.candidateManifestCipherDigest)) {
    fail(CODE.CANDIDATE_MISMATCH, 'selector candidate manifest ciphertext digest does not match the candidate manifest record');
  }
  decodeManifest(candidate.manifestBytes);
  candidateRoot = computeKeyedRoot({
    manifestRootKey, manifestKey: candidate.key, generation: candidate.generation, manifestBytes: candidate.manifestBytes,
  });
  if (!equal(candidateRoot, candidate.keyedRoot)) {
    fail(CODE.CANDIDATE_MISMATCH, 'candidate generation declares a keyed root that its own manifest does not produce');
  }
  if (!equal(candidateRoot, selector.candidateKeyedRoot)) {
    fail(CODE.CANDIDATE_MISMATCH, 'selector candidate keyed root does not match the candidate manifest');
  }
  if (selected.sessionBindingDigest !== null && candidate.sessionBindingDigest !== null
      && !equal(candidate.sessionBindingDigest, selected.sessionBindingDigest)) {
    fail(CODE.CANDIDATE_MISMATCH, 'candidate session binding digest does not match the selected profile binding');
  }
  if (candidate.hold.resultStatus === COMMIT_OUTCOME_INDETERMINATE) {
    if (candidate.hold.parentGeneration !== selector.generation
        || !equal(candidate.hold.parentKeyedRoot, selector.keyedRoot)) {
      fail(CODE.PARENT_MISMATCH, 'unresolved candidate hold parent does not match the selector physical authority');
    }
  }
  return Object.freeze({
    authority: 'SELECTED',
    state: selector.state,
    selectedGeneration: selected.generation,
    candidateGeneration: selector.candidateGeneration,
    selectedKeyedRoot: selectedRoot.slice(),
    candidateKeyedRoot: candidateRoot.slice(),
    candidateIsAuthority: false,
  });
}
