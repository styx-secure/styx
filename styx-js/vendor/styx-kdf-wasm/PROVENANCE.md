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
- Full dependency graph: 27 crates, all from crates.io, checksums in
  `Cargo.lock`. Notable transitive crates and why they exist:
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
| `pkg/styx_kdf_wasm_bg.wasm` (36 912 bytes) | `0456f5d38a5b11e1e1d306a46049480d1dfe4a58d77ab4154fe1559d2042891b` |
| `pkg/styx_kdf_wasm.js` | `dbeacb4fda86c8a7f7514e773ad4cdb4b76f2114806c9f0a2516f8664f31e8ec` |
| `pkg/styx_kdf_wasm.d.ts` | `ec952ab231c25ddb075015cbc142a7c11eeef0732617fafb99d8b2ee53ef0310` |
| `pkg/styx_kdf_wasm_bg.wasm.d.ts` | `b2d9a34e455bb548b7ef372cd9cbdb4bc09792e3d4d469bf10a1a77a34bc81bf` |

Machine-readable copy: `pkg/SHA256SUMS` (checked by `verify.sh` and by the
jest anti-drift test).

- Build date: 2026-07-12 (UTC). Source commit: the commit that introduces this
  file (the artifact is byte-reproducible from the pins above, so the commit —
  not the date — is the meaningful identity).
- **Double-build verification**: `./verify.sh` executed 2026-07-12 — two
  independent container builds byte-identical to each other AND to the
  committed `pkg/` files (all four `REPRODUCIBLE`, `SHA256SUMS: OK`, exit 0).
- `cargo test --locked` (native, in the pinned image): 5/5 passed — three
  known-answer anchors (cross-validated against hash-wasm 4.12.0 and stable
  across Chromium/Firefox in the Argon2id spike), the absolute-bounds
  rejection table, failure-then-recovery.

## Supply-chain checks (2026-07-12, `./audit.sh`)

- `cargo audit` (cargo-audit 0.22.2, release binary sha256
  `7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428`):
  1159 advisories loaded, 27 dependencies scanned, **0 vulnerabilities**.
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
