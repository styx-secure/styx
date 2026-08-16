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
  wrapper, the isolated B3.2/B3.2a embedded-tree Welcome wrappers, the isolated B3.3a
  application-message wrapper, the B3.3b-1 sequential self-update wrapper, and
  explicit staged/pending Commit APIs. It is outside the scope of every
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
- **Phase B1, Phase B2, Phase B3.1, Phase B3.2, Phase B3.2a, Phase B3.3a and Phase B3.3b-1
  ciphersuite (non-product probes):**
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

**Artifact (rebuilt 2026-08-16 for the isolated B3.3b-1 sequential self-update
and retained-traffic capability, from the
unchanged source pin and pins above):**

| File | sha256 |
|---|---|
| `openmls_wasm_bg.wasm` | `fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e` |
| `openmls_wasm.js` | `3de8fd46e4897aae117ee7b10ac41dffd02b507952c4024b0fe69d89fbb0c973` |
| `openmls_wasm.d.ts` | `057974ec53e3588da3dbf159f183b3e3ddb4a3b0a57d5391194f124a483ede86` |
| `openmls_wasm_bg.wasm.d.ts` | `c21ace2360b264437541025e4703bcb38b53010793829d1904cb85b3d2aa238a` |
| `package.json` | `88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85` |

**Reproducibility: verified 2026-08-16 for the reviewed B3.3b-1 candidate.** Two
complete disposable locked builds associated with exact reviewed source commit
`f7a7cb7b08e1f9a86652e2d5a2230c8aadc46f30`, tree
`d59f8192b8b97d94215266b93e9bc4f72c3a4380`, and patch SHA-256
`334331f481ec173a6f151ecbe73887d6ea67d22574fc4014a5827c8eb667b22d`
were byte-identical across the complete five-file tuple. The owner separately
approved those exact five digests and the 2,358,165-byte WASM before
installation. An independent exact-head review reproduced all native and
focused JavaScript checks and a third byte-identical build (report SHA-256
`6471f04fccdf589c41fcb7382985aab5cfb8672adc3dc747af0036b128fc708c`). `./verify.sh`
independently rebuilds twice and compares both results with the committed set.

The immediately preceding B3.3a artifact digest
`7087b53f8f0597f0107802d5b629cd211d138d4f916b2ddd5831862088551624`
remains an exact state-writer compatibility tuple. B3.3b-1 preserves the
canonical Provider serializer/parser while adding isolated epoch-transition
and retention mechanics. Historical B3.3a evidence must be supplied from its
explicit approved five-file tuple; the current installed runtime is never
relabelled as B3.3a evidence.

The immediately preceding B3.2a artifact digest
`f1596c27c90f71e50998bfae1be212e6b016944e18fe3c3fecee1eb44e64f869`
remains an exact state-writer compatibility tuple. B3.3a preserves its canonical
Provider format and adds only isolated one-use application send/receive handles;
it does not relabel the B3.2a writer identity.

The immediately preceding B3.2 artifact digest
`d281d4a4c3c72999e966c1e70bff68b0ddc5eda23653295adbf620bad723f62c`
remains an exact state-writer compatibility tuple. B3.2a preserves the legacy
Provider serializer/parser and all historical state-load behavior; the bounded
B3.2a durable-input parser and canonical candidate serializer are isolated and
do not relabel the legacy format.

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
126,632 canonical JSON bytes with SHA-256
`ae1d2704345fff570c5c4f33cd847ce05a5483716738792476c69fb77908330e`.
Relative to B3.2a, the high-level additions include `PhaseB33aGroup`,
`PhaseB33aPendingOutbound`, `PhaseB33aOutboundRelease`,
`PhaseB33aPendingInbound`, `PhaseB33aInboundRelease`, and the isolated
`PhaseB33b1*` activation, local-pending and inbound-staging types; no historical
high-level export was removed or renamed, and product source remains barred
from all isolated Phase B surfaces.

Two build inputs remain pinned only indirectly, and are listed here rather than hidden:
`wasm-bindgen-cli` is fetched by wasm-pack at the version the lockfile dictates, but the
download itself is not hash-verified; `wasm-opt`/binaryen is pinned by the wasm-pack version.
