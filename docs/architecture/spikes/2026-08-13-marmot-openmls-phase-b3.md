# Phase B3 — exact-pin Styx/MDK bounded NO-GO

Status: implementation evidence for Issue #165. This report describes an
isolated synthetic probe, not a product capability. Exact-head independent
agent review, independent human security review and CI remain mandatory before
merge.

## Question

Can Styx at the exact post-B2.7 baseline give its durably owned,
non-last-resort MLS 1.0 KeyPackage to the exact pinned MDK peer, then complete
the contract's direct two-member group, bidirectional traffic, self-update and
restart flow without patching either implementation or translating protocol
semantics?

## Result

No. The two exact peers reproducibly stop at the same first public MDK
operation, before group creation.

The Styx KeyPackage is successfully generated under ciphersuite `0x0001`,
persisted before exposure, restored after a provider restart and parsed again
through the installed Styx current-profile reader. Its supported application
component ids are `0x8003`, `0x8009` and `0x800c`.

MDK receives the exact framed bytes through public
`CreateGroupRequest.members`, parses their MLS capabilities and returns its
typed `MissingRequiredCapabilities` outcome. Its current-profile founding
policy requires `0x8001`, `0x8003`, `0x8009` and `0x800c`; the exact missing set
is the single component `0x8001`, `marmot.group.profile.v1`.

The harness records:

- first incompatible operation:
  `mdk_create_group_from_styx_key_package`;
- rejected value: decimal `32769`, hexadecimal `0x8001`;
- MDK classification: `mdk_missing_required_capabilities`; and
- Styx classification:
  `STYX_KEY_PACKAGE_MISSING_MDK_REQUIRED_GROUP_PROFILE_COMPONENT`.

The result is a bounded NO-GO. B3 did not establish Styx/MDK interoperability
at the tested pins. It is not evidence that the architectures cannot converge,
and it is not permission to weaken either validator.

## Exact immutable inputs

| Input | Exact identity |
|---|---|
| Styx base | `925554ef89921ee6b6fa8ea1c976ed3a05977a26` |
| Styx base tree | `48899a558c67e9ec0aad8a6814a1d56078d2f54c` |
| OpenMLS source | `09e92777dba0528d3d29e2e5e681b7e91637c7be` |
| OpenMLS-WASM SHA-256 | `ed5e740d9c93aa46aa1afb7b6065e4b5b92be972a8a080ddd0a35091260691bb` |
| Marmot specification | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` |
| Marmot tree | `10d941f358de5d9fe4ee1db75581f3e5363f5e92` |
| MDK | `9396adb6aa6b95b521a7979facd5ea7040c07288` |
| MDK tree | `a1145de604e616634dae9a1ef6bf5033c9c9e879` |
| MDK upstream `Cargo.lock` SHA-256 | `edb8c706e12934b8d94239203f73d24a2d480033c3ec6830f19d06c85a247b09` |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`) |

The pin verifier checks the exact revisions, trees, clean upstream checkouts,
artifact and lock digests, allowed repository paths, MDK license identity and
the complete local Rust manifest before each run.

## Public API topology

Stage 0 confirmed the contract's intended direction:

1. Styx can create a non-last-resort KeyPackage and retain its private bundle
   across restart.
2. MDK's own public fresh-KeyPackage path remains last-resort at the tested pin;
   that is why MDK is the founder and consumes the Styx package.
3. MDK accepts external framed KeyPackage bytes through
   `CreateGroupRequest.members`.
4. The local Rust peer uses MDK public engine and SQLite storage APIs. The only
   enabled observation feature is `test-conformance-snapshot`; it supplies
   read-only projections and does not change policy or state.
5. The Styx-authored `TransportPeeler` identity adapter constructs MDK's typed
   local envelope but does not inspect or modify MLS bytes.
6. The account-proof signer is supplied through MDK's public signer callback;
   the synthetic signing key remains in the private run directory.

No MDK source, fixture, vector or documentation was copied or modified.

## Reproduced evidence

Two clean executions independently produced the same operation sequence and
the same typed incompatibility. MLS randomness was not made deterministic, so
their KeyPackage and transcript digests correctly differ.

| Run | Styx KeyPackage SHA-256 | Transcript head SHA-256 | Result |
|---|---|---|---|
| `run-a` | `7719addc5520066699ee01139835948721fe617f76fb9b63ec312788e3436f95` | `aec5fbd97af2492db6df99a7b4906b4a6b504ee035b79eb4975690446362e3bb` | missing `0x8001` before group creation |
| `run-b` | `a504cd5a7e6ec40d74f9d362eca1693d2a370aa5888191b98aa331f1246cc0dc` | `0e5b432f95c9698348888354788e4dc1d2ad7521bdaa8316800539246aef6297` | missing `0x8001` before group creation |

Each transcript is a canonical, sequence-numbered SHA-256 chain. The report
binds its final transcript head. Jest independently recomputes every record,
rejects mutation, validates both typed outcomes and refuses to reinterpret the
report as compatibility.

## Evidence and secret boundary

The public artifacts under
`/home/mverde/.local/share/styx-b3-runs/issue-165/` contain only synthetic public
KeyPackage/proof bytes, public identities and leaf keys, hashes, component
sets, pin evidence and typed dispositions.

The following remain private and are never written to the repository or public
run directory:

- Nostr account signing secrets and MLS private KeyPackage bundle;
- serialized OpenMLS provider state;
- SQLCipher database, database key and signer-secret file;
- raw exporter values; and
- decrypted non-synthetic content.

Each private run child is mode `0700`; secret files are mode `0600`. The
orchestrator validates the real path beneath the exact private root and removes
only that exact child in its `finally` path. Both official private children were
absent after their commands returned.

## Smallest hypothetical remedy

The narrowest next experiment is to add `marmot.group.profile.v1` (`0x8001`) to
the Styx current-profile KeyPackage supported-capability set and to the strict
validated application-component model, rebuild the reproducible OpenMLS-WASM
artifact, freeze a new baseline and rerun B3.

That work is outside Issue #165: its WASM interface, feature set, artifact and
all prior Phase B formats are frozen. The current task neither implements the
component nor assumes that doing so resolves later Welcome, message, Commit or
restart seams.

## Licensing and provenance

The driver and harness are original Styx code under `AGPL-3.0-or-later` and the
Rust executable is `publish = false`. MDK is fetched from
[the upstream repository](https://github.com/marmot-protocol/mdk) at the exact
commit above under the MIT License, copyright 2024–2026 Internet Privacy
Foundation. Its license remains with the fetched packages. Because no MDK
material is copied into Styx, this increment does not change repository license
maps or third-party notices.

## Verification status

Already completed successfully while constructing the candidate:

- MDK `group_creation`: 50 passed;
- MDK exact staged-publication lifecycle case: 1 passed;
- local Rust peer `cargo build --locked`: pass;
- local Rust peer `cargo test --locked`: 2 passed;
- two exact orchestrator runs: bounded NO-GO reproduced twice; and
- focused B3 Jest: 3 passed.

The full exact command set, exact-head CI, independent GLM 5.2 review and
`@manexada` human review remain external gates. This report does not presume
their outcome.

## Residual risks and non-claims

- The later B3 flow is untested because execution correctly stops at the first
  incompatibility. No conclusion follows about Welcome consumption, ratchet
  trees, message traffic, Commit lifecycle or durable restart across peers.
- A successful later repair would remain revision- and scope-bound, not full
  Marmot conformance.
- Both upstreams and draft-extension semantics remain experimental and moving.
- No relay, Nostr transport, NIP-59 delivery, metadata privacy, anonymity,
  multi-device, push, media, browser-origin, vault or product behavior was
  tested.
- No upstream audit transfers to Styx and no Styx review transfers to MDK.
- Synthetic local evidence does not establish safe use for whistleblowing,
  accounting, legal evidence or other real sensitive data.
