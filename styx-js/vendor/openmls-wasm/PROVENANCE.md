# OpenMLS-WASM artifact provenance

This directory contains a **vendored, pre-built** WASM artifact. OpenMLS publishes no npm
package, so the crate is compiled here and the binary is committed. This file records where
that binary comes from, so its origin is auditable without a rebuild.

## Licensing classification

This directory is licensed path by path (root `REUSE.toml` + `LICENSING.md`), not as a
whole: upstream, derived and generated OpenMLS material (`openmls_wasm_bg.wasm`,
`openmls_wasm.js`, `.d.ts` files, `package.json`, `Cargo.lock`) is MIT — Copyright (c)
2020 OpenMLS Authors; `patch/lib.rs` is a Styx-modified MIT derivative (OpenMLS Authors +
Maurizio Verde, modifications); the Styx-authored scripts and docs (`build.sh`,
`verify.sh`, `test.sh`, `roundtrip.mjs`, `README.md`, this file) are
`AGPL-3.0-or-later`. The
committed artifact also statically links third-party crates (e.g. BSD-3-Clause `subtle`);
see the root `THIRD_PARTY_NOTICES.md`.

## Upstream pin

- **Upstream:** https://github.com/openmls/openmls
- **Pinned commit:** `09e92777dba0528d3d29e2e5e681b7e91637c7be` (2026-07-08 — *"feat: new app data update processing for PublicGroups (#2098)"*)
- **Position relative to releases:** descendant of tag `openmls-v0.8.1` (2026-02-13) — **76 commits ahead, 0 behind**. This is an **unreleased `main` commit**, not a published release.

## Security status of the pin — verified, not assumed

The SRLabs security audit (funded by the Sovereign Tech Agency) found 8 issues in OpenMLS.
**The remediations are present at this pin.** Verified at source level, not inferred from
version numbers:

- **S3-7 (High, CWE-354) — MAC comparison accepted truncated MACs.** `equal_ct` compared
  byte-by-byte with `zip`, which stops at the shorter slice, so a truncated or empty MAC
  compared equal — impersonation / group fork.
  - *Before* (tag `openmls-v0.7.0`, `openmls/src/ciphersuite/mod.rs`): no length check.
  - *At this pin* (same file): `if a.len() != b.len() { return false }` before the
    constant-time loop. **Fixed.**
- **Dependency advisories.** Release 0.8.1 updated `libcrux` and the `rust_crypto` provider
  for GHSA-435g-fcv3-8j26 (libcrux) and GHSA-g433-pq76-6cmf (hpke-rs). This pin contains
  0.8.1 in full (0 commits behind), so it carries those updates.

**Do not "upgrade" to the `openmls-v0.8.1` tag.** It would be a five-month downgrade (−76
commits) *and* it would change the persisted storage format: PR #2034 (present at this pin,
absent in 0.8.1) restores serde storage-tag compatibility with v0.7.1 by default, with the
`0-8-1-storage-format` feature retained for v0.8.1 compatibility. Downgrading would break
MLS state already written to disk by this artifact.

## Residual risks (accepted, recorded on purpose)

- **The pin is unreleased `main`.** 76 commits beyond the last published release are not part
  of any crates.io version and were not the subject of the SRLabs audit, which targeted the
  released crate. This is a supply-chain exposure we accept in exchange for the upstream fixes
  those commits carry.
  - *Follow-up:* move the pin to the first upstream tag that is a descendant of this commit,
    once OpenMLS publishes one.
- **The local patch is not audited.** `patch/lib.rs` is Styx code compiled into the crate. In
  addition to persistence, reload, member inspection and wire-error hardening, it now contains
  the isolated Phase B1/Phase B2 probe APIs, the isolated B3.1 group-profile capability
  wrapper, the isolated B3.2 embedded-tree Welcome wrapper, and explicit staged/pending
  Commit APIs. It is outside the scope of every
  upstream OpenMLS or Marmot-family audit; review it separately.
- ~~`Provider::restore_state` `u64 as usize` length arithmetic wraps on wasm32.~~ **Fixed
  2026-07-11** (code review): all offsets use checked arithmetic and oversized lengths are
  rejected, so a crafted `mls:state` blob returns an error instead of trapping. Regression
  test: `test/crypto/mls-adversarial.test.js` (the wrap case traps on the pre-fix artifact).
- Some `unwrap()`s remain on locally-built material (KeyPackage builder, storage `RwLock`,
  `to_bytes`/serialize paths). They are not reachable from untrusted input; the wire-facing
  parsers all return `Result`.

## Build configuration

- **Upstream feature:** `extensions-draft` is enabled explicitly and reproducibly. It is needed
  for the isolated application-component probe and expands the parser surface even when the
  shipping product remains on the legacy path.
- **Legacy ciphersuite (shipping):**
  `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (`patch/lib.rs`).
- **Phase B1, Phase B2, Phase B3.1 and Phase B3.2 ciphersuite (non-product probes):**
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`).
- **Crypto provider:** `openmls_rust_crypto` (RustCrypto), not libcrux.
- **Rebuild:** `./build.sh` — Docker, no host Rust toolchain needed.
- **Native tests:** `./test.sh` — exact pin, lockfile and `extensions-draft` feature in the
  pinned Rust container.
- **Verify:** `./verify.sh` — two builds must be byte-identical to each other and to the
  committed artifact.

## Toolchain pins and artifact hashes

Every input to the build is pinned. The digest — not the tag — is the real pin for the
image: a tag can be re-pushed, a digest cannot.

| Input | Pin |
|---|---|
| Rust toolchain | `rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376` |
| wasm-pack | `0.15.0`, release binary, sha256 `c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a` |
| Dependency graph | `./Cargo.lock` (workspace lockfile; builds run `-- --locked`, and `build.sh` aborts on drift) |
| OpenMLS source | commit `09e9277…` (above) |

**Artifact (rebuilt 2026-08-14 for the isolated B3.2 embedded-tree Welcome capability, from the
unchanged source pin and pins above):**

| File | sha256 |
|---|---|
| `openmls_wasm_bg.wasm` | `d281d4a4c3c72999e966c1e70bff68b0ddc5eda23653295adbf620bad723f62c` |
| `openmls_wasm.js` | `e46684332ea0cb885988a2ff2cf6c6519b46d0f78125bb828b8a1b4b258ad09c` |
| `openmls_wasm.d.ts` | `60af6c9ffb9a0d4acb7a5fd16e762adc31626de33ec4e9ff225e7c86a4bec5e2` |
| `openmls_wasm_bg.wasm.d.ts` | `e2b96efae4fab9be193ae32b24927d0a34aca4c5d427f3d9563fba8e6c309bbe` |
| `package.json` | `88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85` |

**Reproducibility: verified 2026-08-14 for B3.2.** Two complete disposable builds
from these pins were byte-identical to each other and to the committed output
set; `./verify.sh` independently repeats the same comparison.

The immediately preceding B3.1 artifact digest
`26a41d86d7fd2c9ab4184344e4ff00f5eebb5bc7609ba22e98b12ce903d4a4dd`
remains an exact state-writer compatibility tuple. Before admission, its frozen
synthetic Provider fixture under `test/fixtures/mls-state-b3-1/` was restored by
the B3.2 artifact and its exact non-last-resort KeyPackage was parsed and rebound
to the restored identity. This is state-load and KeyPackage evidence only, not
a claim that arbitrary B3.1 artifacts are compatible.

The preceding B2.7 artifact digest
`ed5e740d9c93aa46aa1afb7b6065e4b5b92be972a8a080ddd0a35091260691bb`
remains an exact state-writer compatibility tuple. Before it was admitted, the
fixed synthetic PhaseB2 provider fixture under `test/fixtures/mls-state-b2-7/`
was restored by the B3.1 artifact, its post-snapshot reference ciphertext was
decrypted with authenticated sender attribution, and a non-empty reply was
created. The preceding B2.2 artifact digest
`60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a`
remains an exact state-writer compatibility tuple. Its fixed synthetic PhaseB2
provider fixture under `test/fixtures/mls-state-b2-2/` restores, decrypts its
reference ciphertext and creates a reply under this artifact. The immediately
preceding B2.1 artifact digest
`d0399fddc2ed5f030927f9786d295c394bcdfa133a1c69feeb9514edf2cd6f01`
remains an exact state-writer compatibility tuple. Its fixed synthetic fixture
under `test/fixtures/mls-state-b2-1/` is restored by this artifact. The earlier
Phase B1 artifact digest
`61cce676c81366fc9c62752a09ea1547a4998ede7f144013ac5ade088e70a863`
remains an exact state-writer compatibility tuple. Its fixed synthetic fixture
under `test/fixtures/mls-state-b1/` is also restored by this artifact in the test
suite. This is bounded compatibility evidence, not a general migration or
interoperability claim.

The complete generated public surface is discovered structurally and frozen at
70,501 canonical JSON bytes with SHA-256
`91b6d584a5612678ff7b9d1fd6551bf299ee4fceb9e74858ddfe3e2ed3ddc860`.
Relative to B3.1, the named exports added are `PhaseB32PendingWelcome`,
`PhaseB32JoinProjection`, and `PhaseB32Group`; no product source may reference
any isolated Phase B probe type.

Two build inputs remain pinned only indirectly, and are listed here rather than hidden:
`wasm-bindgen-cli` is fetched by wasm-pack at the version the lockfile dictates, but the
download itself is not hash-verified; `wasm-opt`/binaryen is pinned by the wasm-pack version.
