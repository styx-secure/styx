# PROVENANCE — styx-kdf-wasm

A deliberately **separate WASM artifact from `openmls-wasm`**: the MLS state
envelope v1 pins that artifact's digest (`wasmArtifactSha256`), so the KDF can
never share its binary (vault spec §2.1). This crate has its own lifecycle,
its own lockfile and its own digest; updating it cannot invalidate persisted
MLS state, and an OpenMLS update cannot change this artifact.

## Source

- Crate source: `./Cargo.toml` + `./src/lib.rs` (this repository, no external
  clone; `build.sh` builds from a clean copy of the committed sources only).
- Direct dependencies (exact pins, `--locked` against `./Cargo.lock`):
  - `argon2 = 0.5.3` (RustCrypto) — sha256 of the crates.io archive recorded in
    `Cargo.lock` (`checksum` field), license MIT OR Apache-2.0
  - `wasm-bindgen = 0.2.126` — checksum in `Cargo.lock`, MIT OR Apache-2.0
  - `js-sys = 0.3.103` (the wasm-bindgen release paired with 0.2.126) —
    checksum in `Cargo.lock`, MIT OR Apache-2.0. Added for the hardened ABI
    (review K8): Uint8Array buffers are type- and length-checked in Rust
    WITHOUT a pre-validation copy into WASM memory.
- Full dependency graph: 32 crates from crates.io (checksums in `Cargo.lock`)
  plus this root crate. Notable transitive crates and why they exist:
  - `blake2`, `password-hash`, `digest`, `block-buffer`, `crypto-common`,
    `generic-array`, `typenum`, `subtle`, `base64ct`, `rand_core`,
    `cpufeatures` — the RustCrypto Argon2 implementation stack
  - `wasm-bindgen-macro(-support)`, `wasm-bindgen-shared`, `syn`, `quote`,
    `proc-macro2`, `unicode-ident`, `bumpalo`, `once_cell`, `cfg-if`,
    `rustversion`, `version_check`, `libc` — the wasm-bindgen binding layer
    (build-time proc-macros; only the minimal runtime reaches the artifact)

## Toolchain

| Input | Pin |
|---|---|
| Docker image (same as the canonical `openmls-wasm` build) | `rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376` |
| wasm-pack | `0.15.0`, release tarball sha256 `c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a` (verified by `build.sh`) |
| Dependency graph | `./Cargo.lock`, `cargo … --locked`, post-build drift guard (`cmp`) |
| Build command | `./build.sh` (host); inside the container: `wasm-pack build --target web -- --locked` |

## Artifact

| File | sha256 |
|---|---|
| `pkg/styx_kdf_wasm_bg.wasm` (42 082 bytes) | `ad67202689c58d5e7b7a0b845d7b9d7253ecc04542f8921804c11d62942ae8f5` |
| `pkg/styx_kdf_wasm.js` | `e2a9b15c55c6e485de53a450c5a471d5138d71a987ca9bb6dbd9c0da2cacf2d7` |
| `pkg/styx_kdf_wasm.d.ts` | `c54d7288c263e4fa5f3fd7f48cb5deaf99da436555b2ccceec179c7a986d732b` |
| `pkg/styx_kdf_wasm_bg.wasm.d.ts` | `c54c3ec5abba29c7de59a15174cefdf6f3408636034403dde7a6945ff5f80a12` |

Machine-readable copy: `pkg/SHA256SUMS` (checked by `verify.sh` and by the
jest anti-drift test).

- Build date: 2026-07-12 (UTC). Source commit: the commit that introduces this
  file (the artifact is byte-reproducible from the pins above, so the commit —
  not the date — is the meaningful identity).
- **Double-build verification**: `./verify.sh` executed 2026-07-12 — two
  independent container builds byte-identical to each other AND to the
  committed `pkg/` files (all four `REPRODUCIBLE`, `SHA256SUMS: OK`, exit 0).
- `cargo test --locked` (native, in the pinned image): 6/6 passed — one spike
  known-answer anchor plus two additional cross-validated vectors (all outputs
  byte-identical to hash-wasm 4.12.0), the exact f64→u32 gate (review K7:
  2^32+1024 can never wrap into 1024), the absolute-bounds rejection table,
  failure-then-recovery. All three spike anchors run in the JS and browser KAT
  suites (Node, Chromium, Firefox).
- **ABI hardening (reviews K7/K8, 2026-07-12)**: the export takes `JsValue`
  buffers and `f64` numbers; numbers are validated (finite, integral,
  non-negative, ≤ u32::MAX) BEFORE the u32 conversion, and Uint8Array buffers
  are type- and length-checked BEFORE their bytes are copied into WASM memory
  (the glue contains no `passArray8ToWasm0`; guarded by an anti-drift test).
  The five KAT outputs are unchanged: the ABI changed, Argon2id did not.

## Supply-chain checks (2026-07-12, `./audit.sh`)

- `cargo audit` (cargo-audit 0.22.2, release binary sha256
  `7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428`):
  1159 advisories loaded, 33 crate dependencies scanned (post js-sys),
  **0 vulnerabilities**.
- `cargo deny --locked check` (cargo-deny 0.20.2, release binary sha256
  `9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f`, policy
  `./deny.toml`): **advisories ok, bans ok, licenses ok, sources ok**.
- Licenses in the tree: MIT OR Apache-2.0 (majority), `generic-array` MIT,
  `subtle` BSD-3-Clause, `unicode-ident` (MIT OR Apache-2.0) AND Unicode-3.0 —
  all permissive; allowlist enforced by `deny.toml`.

## Update procedure

Any dependency or toolchain bump requires: authorization, `build.sh` bootstrap
of a fresh `Cargo.lock`, `verify.sh` green, `audit.sh` green, this file updated
with the new digests, and the KAT suite green (the anchors must NOT change for
a pure toolchain bump; an argon2 crate bump that changes outputs is a breaking
event requiring explicit review). Rollback = revert of the artifact commit
(byte-identical restore without rebuild).
