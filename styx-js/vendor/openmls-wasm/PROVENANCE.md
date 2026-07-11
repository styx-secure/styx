# OpenMLS-WASM artifact provenance

This directory contains a **vendored, pre-built** WASM artifact. OpenMLS publishes no npm
package, so the crate is compiled here and the binary is committed. This file records where
that binary comes from, so its origin is auditable without a rebuild.

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
- **The local patch is not audited.** `patch/lib.rs` is Styx code compiled into the crate — it
  adds `Provider.serialize_state`/`restore_state`, `Group.load`, `Identity.public_key`/`load`,
  `Group.member_identities`, and replaces panics on wire input with `Result`s. It is outside
  the scope of any upstream audit; review it separately.
- **`Provider::restore_state`** does `u64 as usize` length arithmetic that can wrap on wasm32.
  Reachable only from locally persisted state, never from the wire.
- Some `unwrap()`s remain on locally-built material (KeyPackage builder, storage `RwLock`,
  `to_bytes`/serialize paths). They are not reachable from untrusted input; the wire-facing
  parsers all return `Result`.

## Build configuration

- **Ciphersuite (fixed):** `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
  (`patch/lib.rs`). X25519 HPKE, ChaCha20-Poly1305 AEAD, SHA-256, Ed25519.
- **Crypto provider:** `openmls_rust_crypto` (RustCrypto), not libcrux.
- **Rebuild:** `./build.sh` — Docker, no host Rust toolchain needed.
- **Verify:** `./verify.sh` — two builds must be byte-identical to each other and to the
  committed artifact.
