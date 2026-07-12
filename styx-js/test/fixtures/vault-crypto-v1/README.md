# vault-crypto-v1 — frozen test vectors (Blocco 3, PR-2)

Known-answer vectors for the vault cryptographic formats v1: KDF wrapper
(spec §7), encrypted records (spec §6), HKDF key hierarchy (spec §5, amended
with `settings`/`canary`) and manifest HMAC (spec §11).

**These vectors are a compatibility contract.** After the PR-2 merge they are
FROZEN: any change requires an explicit motivation and a compatibility review
(a changed vector means a persisted-format break or a crypto regression). The
jest suites (`test/storage/vault-wrapper.test.js`,
`test/storage/vault-record.test.js`, `test/crypto/vault-keys.test.js`) and the
browser spec (`test/crypto/vault-crypto.browser.spec.js`) assert against them.

## No real data

Every secret is **synthetic and TEST-ONLY**, deterministically derived from
labels of the form `STYX-VAULT-TEST-ONLY … v1` via SHA-256 (see `generate.js`).
No real password, Root Storage Key, KEK, user payload, identity or production
value appears anywhere in these files. The fixture "Root Key" and "KEK" have
never protected anything.

## Provenance and regeneration

- Generator: `generate.js` (this directory) — deterministic: no randomness, no
  clock; two runs produce byte-identical files.
- Regenerate with: `cd styx-js && node test/fixtures/vault-crypto-v1/generate.js`
- Generated and cross-checked on: Node 24 (V8 WebCrypto), Chromium and Firefox
  via `npx playwright test -c playwright.vault.config.js` (byte-identical
  results on all three engines).

## Algorithms and canonicalization

| Item | Value |
|---|---|
| Record / wrapper encryption | AES-256-GCM, 96-bit nonce, 128-bit tag (WebCrypto) |
| Key hierarchy | HKDF-SHA-256; salt = SHA-256(UTF-8 `styx-vault-v1`); info = exact strings in `src/crypto/vault-keys.js` |
| Manifest integrity | HMAC-SHA-256 (32-byte MAC) |
| Wrapper AAD | UTF-8 of `JSON.stringify([format, version, kdf, kdfVersion, mKib, t, p, saltB64, outLen, keyVersion])` |
| Record AAD | UTF-8 of `JSON.stringify([v, ns, k, rv, kv, ct])` |
| Base64 fields | canonical: standard alphabet, mandatory padding, zero trailing bits, no whitespace — exactly one encoding per byte string |

AAD builders and constants are imported from the production modules
(`src/crypto/vault-aad.js`, `src/crypto/vault-keys.js`) so the serialization
contract is shared, never duplicated. The ciphertexts are produced with
WebCrypto directly and **fixed nonces**, because the production APIs generate
nonces internally and accept none from the caller (spec §6) — that is why this
generator exists as a separate tool.

## Files

| File | Contents |
|---|---|
| `hkdf-v1.json` | Root Key (hex) → OKM of all 10 info strings (8 payload namespaces + manifest + backup) |
| `wrapper-v1.json` | complete wrapper v1 with KEK, salt, nonce, AAD and wrapped Root Key |
| `record-v1-json.json` | `settings` record, `ct: 'json'`, with plaintext, AAD and ciphertext |
| `record-v1-bytes.json` | `canary` record, `ct: 'bytes'` |
| `manifest-hmac-v1.json` | canonical sample bytes + HMAC-SHA-256 under the derived manifest key |

Byte fields are hex-encoded (`…Hex`) or canonical Base64 (`…B64`) for JSON
readability; the real persisted formats use `Uint8Array` via structured clone,
never Base64 (spec §6).

Independent standard vectors (RFC 5869 HKDF, AES-256-GCM, RFC 4231 HMAC) are
embedded as literals in `test/crypto/vault-keys.test.js`, NOT generated here:
producer and verifier must not share an implementation error.
