# Vendored OpenMLS-WASM

This directory contains the pinned OpenMLS WebAssembly engine used by the
legacy Styx chat and by an isolated Phase B1 capability probe. The complete pin,
toolchain, licensing classification, hashes, and residual risks are recorded in
[`PROVENANCE.md`](./PROVENANCE.md).

## Build and verification

- Upstream: `github.com/openmls/openmls`, crate `openmls-wasm`
- Commit: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- Rust image: `rust:1.96.1`, pinned by manifest digest
- wasm-pack: `0.15.0`, release archive verified by SHA-256
- Dependencies: committed workspace `Cargo.lock`, always built with `--locked`
- Enabled upstream feature: `extensions-draft`

The source revision has not changed. The draft feature is enabled because the
non-product Phase B1 probe needs the upstream application-data dictionary and
staged-commit APIs. The feature expands the compiled parser surface for both
profiles; it does not make the shipping product select the probe profile.

Run from this directory:

```bash
./build.sh       # one clean, pinned rebuild
./test.sh        # native wrapper tests on the exact pin and feature set
./verify.sh      # two clean rebuilds; compare both with the committed artifact
```

Docker is required. No host Rust toolchain is used. The committed WASM is
1,962,774 bytes raw and approximately 696 KiB gzip.

## Profiles

The legacy API remains the shipping path:

- ciphersuite:
  `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`;
- `BasicCredential.identity`: existing UTF-8 hexadecimal Nostr public-key text;
- bare KeyPackage serialization;
- existing `Identity`, `Group`, `KeyPackage`, `RatchetTree`, and automatic
  inbound merge semantics are unchanged.

The separate `PhaseB1*` exports are capability-probe types only:

- ciphersuite:
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`);
- exactly 32 raw x-only Nostr account-key bytes in `BasicCredential.identity`,
  distinct from the Ed25519 MLS leaf signing key;
- application component `0x8009` with one exact 104-byte account-identity-proof
  v2 entry and an explicit component capability list;
- non-last-resort, bounded-lifetime KeyPackages inside MLSMessage framing;
- WASM-owned, single-use staged Commit handles bound to a provider instance,
  provider-restore generation, group instance, group ID, and prior epoch;
- explicit merge/discard for inbound staged Commits and explicit
  confirm/discard for local pending Add Commits.

No product source imports the probe. It demonstrates local mechanics only: it
is not a Marmot interoperability, security-audit, or production-readiness claim.

## Styx patch

`patch/lib.rs` is applied over the pinned upstream `openmls-wasm/src/lib.rs`.
It adds:

- whole-provider persistence and strict hostile-input restoration;
- legacy identity/group reload and member-identity inspection;
- returned errors rather than WASM traps on hostile wire bodies;
- the isolated Phase B1 profile, framed KeyPackage inspection, and explicit
  pending/staged Commit lifecycles described above.

The patch and its probe API are outside the scope of upstream OpenMLS audits.
`roundtrip.mjs` proves the unchanged legacy 1:1 path; the Phase B1 evidence is
in `../../spikes/marmot-phase-b1/probe.mjs` and the corresponding tests.

## Licensing

This is a mixed directory. The OpenMLS derivative, generated bindings,
metadata, lockfile, and compiled artifact retain their existing upstream and
aggregate classifications. Styx-authored scripts and documents, including the
new `test.sh`, remain under the repository's AGPL-3.0-or-later default. See the
root `REUSE.toml`, `LICENSING.md`, and `THIRD_PARTY_NOTICES.md`; this change does
not introduce Marmot, MDK, Darkmatter, or Least Authority code or fixtures.

## Remaining limitations

- Provider persistence rewrites the complete in-memory store.
- The legacy API still auto-merges inbound Commits by design; only the isolated
  Phase B1 API exposes explicit staging.
- Phase B1 does not implement durable publish-before-apply, crash recovery,
  authorization policy, fork resolution, or concurrent Commit convergence.
- Browser-origin control, compromised devices/extensions, metadata exposure,
  malicious recipients, and rollback/physical-erasure limits remain.
