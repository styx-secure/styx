# Vendored OpenMLS-WASM

This directory contains the pinned OpenMLS WebAssembly engine used by the
legacy Styx chat and by isolated Phase B1/Phase B2/B3.1/B3.2/B3.2a/B3.3a/B3.3b-1
capability probes. The complete pin,
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
non-product Phase B1/Phase B2/B3.1/B3.2/B3.2a/B3.3a/B3.3b-1 probes need the upstream application-data dictionary and
staged-commit APIs. The feature expands the compiled parser surface for both
profiles; it does not make the shipping product select the probe profile.

Run from this directory:

```bash
./build.sh       # one clean, pinned rebuild
./test.sh        # native wrapper tests on the exact pin and feature set
./verify.sh      # two clean rebuilds; compare both with the committed artifact
```

Docker is required. No host Rust toolchain is used. The committed WASM is
2,358,165 bytes raw and 824,040 bytes gzip (`gzip -9 -n`).

Those are the current installed-tuple measurements. They supersede, but do not
rewrite, the historical B3.2a artifact recorded by Issue #175 / PR #176:
2,243,916 bytes raw and 789,498 bytes gzip (`gzip -9 -n`), freshly reproduced
from squash commit `1404d05ed2604195e3b697caeccad9133a6cdc34` on 2026-08-17.
The historical artifact SHA-256 remains
`f1596c27c90f71e50998bfae1be212e6b016944e18fe3c3fecee1eb44e64f869`;
it is evidence for that bounded stage, not the currently installed runtime.

## Profiles

The legacy API remains the shipping path:

- ciphersuite:
  `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`;
- `BasicCredential.identity`: existing UTF-8 hexadecimal Nostr public-key text;
- bare KeyPackage serialization;
- existing `Identity`, `Group`, `KeyPackage`, `RatchetTree`, and automatic
  inbound merge semantics are unchanged.

The separate `PhaseB1*`, `PhaseB2*`, `PhaseB31*`, `PhaseB32*`, `PhaseB32a*` and
`PhaseB33a*` exports are
capability-probe types only. They use:

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
  confirm/discard for local pending Commits.

`PhaseB2*` additionally exposes bounded Add, Remove and self-update preparation,
authenticated inbound Commit staging, complete candidate-state projection, and
a WASM-recomputed digest over the candidate leaves. B2.7 adds an isolated
sender-preserving application receive result containing the OpenMLS-authenticated
sender leaf, credential identity and leaf signature key. It does not verify the
BIP-340 account-identity proof; that remains the JavaScript policy boundary.

`PhaseB31KeyPackage` is a proof-only, non-product wrapper that advertises the
exact supported component set `[0x8001, 0x8003, 0x8009, 0x800c]` decoded from
the emitted LeafNode bytes. Its constructor performs an internal strict
round-trip of canonical present-empty `marmot.group.profile.v1` GroupContext
state. Existing `PhaseB2*` lists, validators, serialized state and behavior are
unchanged, and B3.1 exposes no product getter or mutation API.

The B3.2 wrapper consumes one clone of an exact B3.1 Provider, identity and
non-last-resort KeyPackage together with an MDK-authored Welcome. It permits
only the RatchetTree embedded in encrypted GroupInfo, prepares the join without
mutating the predecessor, projects and validates the complete candidate, and
releases candidate Provider bytes exactly once. `PhaseB32PendingWelcome`,
`PhaseB32JoinProjection`, and `PhaseB32Group` remain isolated probe types; they
do not expose a product join path or establish application-message compatibility.

The B3.2a wrapper replaces live externally supplied join state with exact
digest-bound durable predecessor bytes, restores them into a private Provider,
admits only the two exact Stage 1 leaf profiles, canonicalizes and scratch-restores
the candidate, and releases its already validated bytes exactly once. Its closed
file journal makes `WELCOME_RECORDED -> JOINED` the sole durable join
linearization point. The strict `MessageSecrets.added_at` comparator classifies
only the pinned retention-timestamp variance between independent preparations;
it never rewrites candidate bytes or excludes them from SHA-256.
Candidate release consumes the pending wrapper before caller-controlled
validation. Success transfers the exact candidate once; every rejection wipes
and clears it, returns a stable bounded error category, and makes retry fail
closed.

The B3.3a wrapper loads only that exact B3.2a canonical state into a private
operation-scoped Provider. Its outbound and inbound handles are one-use and
bind the post-operation canonical state to the ciphertext and, for inbound
traffic, plaintext digests before release. Authenticated sender evidence is
derived from the processed MLS message and rebound by the JavaScript adapter
to the exact two-member roster. The wrapper does not expose Commit processing,
epoch changes, product APIs or transport behavior.

The B3.3b-1 wrapper adds an isolated sequential self-update lifecycle. It fixes
retention to exactly five past epochs, binds local pending and inbound staged
Commits to one-use handles and authenticated candidate projections, and exposes
only the MDK-compatible ordering inputs needed by a future convergence probe.
The JavaScript journal persists every transition before publication,
confirmation or plaintext release. The bounded probe neither chooses between
concurrent branches nor creates a product Commit path.

No product source imports the probe. It demonstrates local mechanics only: it
is not a Marmot interoperability, security-audit, or production-readiness claim.

## Styx patch

`patch/lib.rs` is applied over the pinned upstream `openmls-wasm/src/lib.rs`.
It adds:

- whole-provider persistence and strict hostile-input restoration;
- legacy identity/group reload and member-identity inspection;
- returned errors rather than WASM traps on hostile wire bodies;
- the isolated Phase B1 and Phase B2 profiles, the isolated B3.1
  KeyPackage/profile capability, framed KeyPackage inspection,
  explicit pending/staged Commit lifecycles, bounded candidate projection and
  sender-preserving application receive boundary, the isolated B3.2/B3.2a
  embedded-tree Welcome preparation/release surfaces, the isolated B3.3a
  one-use application-message boundary, and the isolated B3.3b-1 sequential
  Commit lifecycle described above.

The patch and its probe API are outside the scope of upstream OpenMLS audits.
`roundtrip.mjs` proves the unchanged legacy 1:1 path; the capability evidence is
in `../../spikes/marmot-phase-b1/`, `../../spikes/marmot-phase-b2-2/`, and the
corresponding native and generated-surface tests.

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
  Phase B1/Phase B2 APIs expose explicit staging.
- The capability APIs do not implement durable publish-before-apply, production
  crash recovery, authorization policy, fork resolution, or concurrent Commit
  convergence. The B3.2a and B3.3a spikes own only their isolated synthetic
  file-backed journal evidence.
- Browser-origin control, compromised devices/extensions, metadata exposure,
  malicious recipients, and rollback/physical-erasure limits remain.
