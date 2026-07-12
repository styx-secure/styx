# styx-kdf-wasm

Bounded Argon2id derivation for the Styx vault (Blocco 3, PR‑1). A
**separate WASM artifact from `openmls-wasm`** by design: the MLS state
envelope pins that artifact's digest, so the KDF must never share its binary.
This crate knows nothing about MLS, envelopes, ciphersuites or the wire
protocol. Full provenance: `PROVENANCE.md`.

**Not yet integrated**: nothing in the production runtime imports this
package (verified by the web gate). Vault, Root Storage Key, wrappers and any
persistence are later PRs of the Blocco 3 plan, each separately authorized.

## API (all of it)

```js
argon2id_derive(passwordBytes, saltBytes, mKib, t, p, outLen) -> Uint8Array
```

Byte arrays in, bytes out — no string/encoding ambiguity. Production callers
must go through the single JS policy validator
(`styx-js/src/crypto/kdf-bounds.js`, profiles + OWASP floor + exact
production shapes); the crate itself enforces wider ABSOLUTE bounds (memory
≤ 256 MiB, so multi-GiB allocations are unreachable; salt 8–64 B; out 16–64 B;
t 1–16; p 1–4; password 1–4096 B) as a component safety net, with memory
reserved via `try_reserve` so an environment that cannot satisfy the cost
fails typed (`KDF_MEMORY_UNAVAILABLE`) instead of aborting.

Stable error codes: `KDF_PARAMS_INVALID`, `KDF_MEMORY_UNAVAILABLE`,
`KDF_DERIVATION_FAILED`. Messages never contain password, salt or output
material.

ABI caveat: JS numbers are reduced mod 2³² (and floats truncated) by the
wasm-bindgen u32 boundary before the absolute bounds see them — integer
enforcement lives ONLY in the JS policy layer, which is the single sanctioned
call path. Both behaviours are pinned by tests.

## Scripts (all need Docker; no host Rust toolchain)

```bash
./build.sh                 # reproducible build → pkg/ (pinned image + wasm-pack, --locked)
CARGO_TEST=1 ./build.sh    # also run the native test suite first
./verify.sh                # double build; must be byte-identical to pkg/ (CI: hermetic job)
./audit.sh                 # cargo audit + cargo deny with sha256-verified release binaries
```

## Tests

- native: `cargo test --locked` (KAT anchors, absolute-bounds table, recovery)
- jest: `styx-js/test/crypto/kdf-wasm.test.js` (KAT, bounds via direct WASM
  calls, anti-drift vs `SHA256SUMS`/`PROVENANCE.md`) and
  `kdf-bounds.test.js` (policy layer, anti-allocation)
- browsers: `npx playwright test -c playwright.kdf.config.js` (KAT on
  Chromium + Firefox)
