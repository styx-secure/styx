# Marmot / OpenMLS Phase A capability probe

**Issue:** [#124](https://github.com/styx-secure/styx/issues/124)  
**Date:** 2026-08-08  
**Result:** **GO**, subject to the Phase B entry gates in this report  
**Scope:** source capability and documentation only; no interoperability claim

## Executive conclusion

The OpenMLS revision already pinned by Styx contains the primitives needed to
attempt a Marmot-compatible profile without replacing the MLS engine:

- Marmot's mandatory AES-128-GCM ciphersuite is implemented by the selected
  RustCrypto provider;
- the generic `app_data_dictionary`, component, LeafNode extension, and
  capability mechanisms needed by account-identity-proof v2 exist behind an
  upstream feature that the current Styx artifact does not enable;
- inbound processing already returns an inspectable `StagedCommit`, and local
  Commit creation already retains pending state until an explicit merge;
- KeyPackage construction can set the required credential bytes, lifetime,
  capabilities, LeafNode application components, and MLS framing.

The current Styx wrapper exposes almost none of those controls. It hardcodes a
different ciphersuite, uses 64-byte hexadecimal text rather than the 32 raw
Nostr public-key bytes as credential identity, builds a bare and unextended
KeyPackage, auto-merges inbound Commits, and merges locally generated Add
Commits immediately. Current Styx is therefore **not Marmot-compatible**.

The missing surface is bounded but security-critical. A Phase B may expose it
only through a new human-approved contract, a provenance-clean licensing map,
an explicit migration/new-group policy, adversarial tests derived from the MDK
audit, and a real wire round trip against an independent implementation.

## Pinned inputs and reproducibility

| Input | Pinned revision |
|---|---|
| Styx | `98f35c39fac574700f490743b8fac710b8c1b568` |
| Styx OpenMLS base | `09e92777dba0528d3d29e2e5e681b7e91637c7be` |
| Marmot specification | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` |
| MDK comparison | `9396adb6aa6b95b521a7979facd5ea7040c07288` |
| Darkmatter, secondary only | `606bae4cdc61ffc9a570d259fe707f1bb7bdcccb` |

The repositories were checked out detached at those exact revisions. Useful
reproduction commands are:

```bash
git clone https://github.com/openmls/openmls.git
git -C openmls checkout 09e92777dba0528d3d29e2e5e681b7e91637c7be

git clone https://github.com/marmot-protocol/marmot.git
git -C marmot checkout 4ad4ae21479c3f3fa9950c6fc4556a76941a62e1

git clone https://github.com/marmot-protocol/mdk.git
git -C mdk checkout 9396adb6aa6b95b521a7979facd5ea7040c07288
```

No conclusion in this report silently follows a later upstream branch.

## Evidence summary

| Phase A question | Current source capability | Current Styx exposure | Result |
|---|---|---|---|
| Mandatory suite `0x0001` | Implemented by the pinned OpenMLS types and RustCrypto provider | Wrapper hardcodes suite `0x0003` | **Supported; wrapper change required** |
| Account-identity-proof v2 | Generic component and dictionary representation exists behind `extensions-draft` | Feature disabled; no raw credential or proof API | **Representable; bounded security patch required** |
| Stage without merge | OpenMLS returns `StagedCommit`; explicit merge/clear APIs exist | Inbound wrapper auto-merges; local Add path merges immediately | **Supported; wrapper lifecycle redesign required** |
| Current KeyPackage | Builder supports lifetime, capabilities, LeafNode extensions, and MLS framing | Wrapper emits a bare default KeyPackage | **Feasible for non-last-resort packages** |
| Persisted-format impact | OpenMLS stores the ciphersuite and leaves in group state | Existing groups contain old suite and credential form | **New-profile/migration decision required** |
| Sustainable bounded effort | No MLS-engine replacement is forced by the four probes | All shipping changes cross sensitive gates | **GO to a gated Phase B PoC** |

## 1. Mandatory ciphersuite

Marmot requires
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`) in its pinned
[MLS profile](https://github.com/marmot-protocol/marmot/blob/4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/foundation/mls-protocol.md).

At the pinned OpenMLS revision:

- `traits/src/types.rs::Ciphersuite` defines `0x0001` and maps it to X25519,
  AES-128-GCM, SHA-256, and Ed25519;
- `openmls_rust_crypto/src/provider.rs::RustCrypto::supports` accepts it;
- the provider implements AES-128-GCM seal/open and the applicable HPKE AEAD;
- default LeafNode capabilities advertise it.

The Styx patch instead fixes `CIPHERSUITE` to
`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` in
`styx-js/vendor/openmls-wasm/patch/lib.rs`. This is a wrapper policy, not a
missing primitive.

Changing the creation constant does not make old groups AES groups. Existing
serialized group records retain their ciphersuite and must remain loadable or
be retired through an explicit policy. Phase B must demonstrate side-by-side
load of legacy state and creation of a new-profile group; it must not rewrite
opaque state or label a destructive re-pair as a transparent migration.

**Finding:** the mandatory suite is supportable without downgrading OpenMLS.
The artifact and new-group wire behavior would change and therefore require the
vendored-WASM, crypto, persisted-state, migration, and human gates.

## 2. Account-identity-proof v2 and capabilities

The pinned Marmot
[identity specification](https://github.com/marmot-protocol/marmot/blob/4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/foundation/identity.md)
and
[proof specification](https://github.com/marmot-protocol/marmot/blob/4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/app-components/account-identity-proof-v2.md)
require every member LeafNode and KeyPackage to:

- use the raw 32-byte x-only Nostr public key as `BasicCredential.identity`;
- advertise app component `0x8009`;
- carry one 104-byte `0x8009` proof entry in the LeafNode
  `app_data_dictionary`;
- bind the credential identity to that leaf's distinct Ed25519 MLS signature
  key with a BIP-340 signature over the specified local Nostr event.

At the pinned OpenMLS revision:

- `openmls/src/component.rs::{ComponentData, ComponentsList}` represents
  arbitrary component ids and support lists;
- `openmls/src/extensions/app_data_dict_extension.rs` represents the ordered,
  unique dictionary;
- `KeyPackageBuilder::leaf_node_extensions` and
  `KeyPackageBuilder::leaf_node_capabilities` accept the required structures;
- `LeafNodeParameters` provides the equivalent update surface;
- `openmls-wasm/Cargo.toml` can forward `extensions-draft` to OpenMLS and its
  RustCrypto storage implementation.

The current Styx artifact is built without `--features extensions-draft`.
The local wrapper constructs a `BasicCredential` from `name.bytes()`, where the
caller supplies hexadecimal pubkey text, and its KeyPackage builder supplies no
custom capabilities or LeafNode extensions. It also has no API to inject,
extract, or validate the proof.

A bounded Phase B shape is possible:

1. create or load the leaf's separate Ed25519 MLS signer;
2. expose its public key before KeyPackage/LeafNode construction;
3. have the authorized Nostr signer produce the exact v2 proof for that key;
4. pass raw account bytes, proof bytes, capabilities, and leaf extensions into
   OpenMLS;
5. validate the same binding on every KeyPackage, proposed replacement leaf,
   staged Commit, and resulting membership before merge.

Validation must not be reduced to checking the outer Nostr event author. The
v2 proof and the transport-author binding protect different boundaries.

**Finding:** proof v2 is representable in the pinned engine. Enabling the
feature and implementing validation are crypto/WASM and identity-boundary
changes, not documentation or ordinary wrapper work.

## 3. Commit staging and publish-before-apply

At the pinned OpenMLS revision,
`MlsGroup::process_message` returns
`ProcessedMessageContent::StagedCommitMessage(Box<StagedCommit>)` for an
authenticated inbound Commit. `StagedCommit` publicly exposes the queued Add,
Remove, Update, PSK, and draft application proposals, the update-path LeafNode,
the provisional GroupContext, credentials requiring validation, and the target
epoch. `MlsGroup::merge_staged_commit` is a separate operation.

For locally generated Commits, `commit_to_pending_proposals` retains pending
state and returns the outbound Commit. `merge_pending_commit` applies it and
`clear_pending_commit` discards it. These are the primitives required by
Marmot's pinned
[publish lifecycle](https://github.com/marmot-protocol/marmot/blob/4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/protocol-core/publish-lifecycle.md).

The local Rust wrapper currently consumes the inbound staged value and calls
`merge_staged_commit` inside `Group::process_message`. It returns only an empty
byte array for any handshake. The JS `MlsSession.decrypt` consequently cannot
inspect, reject, retain, or explicitly merge a Commit. The local Add flow also
calls `merge_pending_commit` immediately after generating the Welcome.

The wrapper can be changed without replacing OpenMLS by returning an opaque
WASM-owned staged handle plus a policy projection, and by adding explicit
merge/discard entry points. The handle must remain single-use and bound to the
group and prior epoch. Local pending state needs explicit publish-confirm and
discard operations.

This bounded API change is not sufficient by itself. Phase B must define:

- a whitelist of allowed proposal and Commit shapes;
- account-proof and immutable-identity validation on proposed leaves;
- atomic durability for pending, published, merging, and stable states;
- recovery after a crash between publish acknowledgement and local merge;
- behavior for a competing valid Commit based on the same epoch;
- fail-closed behavior when pending-state persistence fails.

**Finding:** staged Commit without merge is available in the engine and can be
exposed by a bounded wrapper patch. The current wrapper's auto-merge is a
security-policy defect for Marmot compatibility.

## 4. Current Marmot-compatible KeyPackage

The pinned Marmot
[KeyPackage specification](https://github.com/marmot-protocol/marmot/blob/4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/foundation/key-packages.md)
requires raw account identity, proof v2, capability advertisement, a bounded
Lifetime, and publication of the public KeyPackage inside an `MLSMessage` with
the key-package wire format.

The pinned OpenMLS builder supports all of those generic inputs. Its default
Lifetime is 84 days plus the one-hour skew margin, matching Marmot's maximum
range. `MlsMessageOut` supports KeyPackage framing. A conforming single-use,
non-last-resort KeyPackage is therefore feasible without replacing the engine
or changing the outer Styx vault schema.

The current wrapper is not conforming:

- `Identity::key_package` uses default capabilities and no proof component;
- the credential identity is hex text;
- `KeyPackage::to_bytes` serializes the bare `KeyPackage`, not the containing
  `MLSMessage`;
- `KeyPackage::from_bytes` validates MLS structure but not Marmot identity,
  capability, transport-author, or application-component rules;
- product code has no current single-use/last-resort publication lifecycle.

Last-resort support is deliberately excluded from the minimum Phase B proof.
MDK's pinned dependency uses an OpenMLS fork 18 commits beyond the Styx pin.
Two changes in that range are directly relevant: stricter rejection of trailing
app-data extension bytes and draft-10 last-resort encoding. A non-last-resort
round trip can proceed without adopting last-resort semantics; production
asynchronous discovery cannot claim complete support until the selected engine
pin and wire behavior are explicitly reconciled.

**Finding:** a current non-last-resort KeyPackage is feasible. Shipping it
still changes the vendored artifact and identity/wire behavior and must pass
the crypto, WASM, transport, persisted-state, and migration gates.

## 5. Required changes and human gates

| Candidate Phase B change | Why needed | Mandatory gates |
|---|---|---|
| Enable OpenMLS `extensions-draft` in reproducible WASM build | Component dictionaries and draft proposals | vendored WASM, dependency feature, lock/artifact integrity, crypto review |
| Add a Marmot profile instead of changing one global constant | Preserve explicit legacy behavior while creating suite `0x0001` groups | crypto, wire format, migration, persisted state |
| Accept raw 32-byte credential identity | Current hex identity is non-conforming | identity, persisted state, migration, pairing |
| Build and verify proof v2 | Prevent account/leaf key substitution | cryptographic boundary, vault signer authorization, worker API |
| Expose staged inbound Commit handles | Policy must run before merge | vendored wrapper, crypto/WASM, hostile-input tests |
| Expose local confirm/discard lifecycle | Publish-before-apply | storage atomicity, epoch recovery, transport acknowledgement |
| Emit and parse framed KeyPackages | Current wrapper uses bare bytes | wire format, transport, backward compatibility |
| Validate capability and component invariants | Reject malformed or incompatible members | security policy, adversarial conformance |
| Compare bytes with independent MDK peer | Establish actual interoperability | clean-room/provenance, permissive test surface, independent review |

The existing whole-provider serialization is especially important. A pending
or staged epoch transition cannot be made recoverable merely by returning a
new JavaScript object. Phase B needs a durable state machine and atomic write
plan before application code can publish Commit bytes.

## 6. MDK and Least Authority audit evidence

The March 2026
[Least Authority MDK final audit](https://leastauthority.com/wp-content/uploads/2026/03/Least-Authority-White-Noise-MDK-Final-Audit-Report.pdf)
was read before defining Phase B adversarial work. It reviewed initial MDK
revision `94792c1f734da0aae4afd094d35dd4dd37a7559c` and verification revision
`a6815c7e61cd5beed615f893770bc6d4b83259e5`. Neither is the MDK comparison
revision pinned by this Issue.

The audit reported resolved or dispositioned failures involving:

- Commit authorization before merge;
- binding inner authorship to the MLS-authenticated sender;
- KeyPackage transport author and credential identity;
- immutable member identity across Update and Commit processing;
- deterministic resolution of same-epoch Commit races;
- Welcome validation and unseen-epoch forks;
- premature application of group changes;
- KeyPackage encoding, relay-tag validation, and last-resort reuse;
- unbounded storage inputs, cross-group message identifiers, and stale caches;
- media nonce reuse and input validation.

The unresolved high-severity last-resort finding at final verification is an
additional reason not to include last-resort support in the first PoC.

Phase B adversarial tests must adapt these classes to Styx rather than copying
the old implementation's assumptions. At minimum they must cover malicious
Add/Update/Remove/PSK/GroupContext/AppData proposal combinations, account-proof
substitution, transport-author mismatch, same-epoch Commit races, Welcome
before prerequisite state, publish failure, crash at every pending-state
boundary, malformed and oversized component data, and replay across groups.

The audit does **not** audit Styx, this OpenMLS wrapper, current Marmot, current
MDK, marmot-ts, NIP-59 handling, browser storage, the PWA origin, or the future
Phase B code.

## 7. Dart conformance extraction before freeze

The independent Dart stack must be used to challenge and complete the
language-neutral specification before it is frozen. Extraction is a separate
task; this Issue changes no implementation or vector.

| Behavior to capture | Dart evidence | Required vector classes |
|---|---|---|
| Canonical event bytes, ids, hash links, and Ed25519 signatures | `packages/ledger_engine/lib/src/event_factory.dart`, `chain_validator.dart` | genesis/non-genesis bytes; invalid previous hash; altered payload/type/clock/signature |
| Hybrid Logical Clock | `packages/ledger_engine/lib/src/hlc.dart` | wall clock ahead/behind/equal; receive tie cases; canonical parse/serialize; invalid inputs |
| Vector-clock causality | `packages/ledger_engine/lib/src/vector_clock.dart` | before/after/equal/concurrent; merge; missing actor; canonical ordering |
| Deterministic concurrent ordering | `packages/ledger_engine/lib/src/conflict/deterministic_merge.dart` | vector total first, byte-defined pubkey tie-break, permutation/property tests |
| Fork detection and merge-event construction | `packages/ledger_engine/lib/src/conflict/**` | shared ancestor, missing ancestor, multiple branches, duplicate/replayed events |
| Prune request, acknowledgement, and execution | `packages/ledger_engine/lib/src/pruning/**` | bilateral and unilateral paths; retained hash/evidence; invalid or repeated acknowledgements |
| Event type and payload rules | `packages/ledger_engine/lib/src/event.dart` and facade tests | every defined event type, unknown type, absent payload, maximum sizes |
| Outbox retry and failover semantics | `packages/transport/lib/src/failover/**` | retry ordering, duplicate delivery, partial transport failure, reconnect |
| Pairing and replay prevention | `packages/styx/lib/src/pairing/**` | nonce expiry/reuse, transcript mismatch, explicit trust state |
| Backup share encoding and reconstruction | `packages/crypto_core/lib/src/shamir/**` | threshold, duplicates, corrupted shares, canonical encoding |

The extraction task must first identify where the JS port currently agrees by
shared assumption rather than by an independent vector. Locale-sensitive
string comparison is an example requiring an explicit byte-order rule rather
than two apparently similar implementation methods.

## 8. Licensing, attribution, and documentation consequences

This section is a technical provenance assessment, not legal advice. Any
licensing amendment remains a human/legal decision under `LICENSING.md`.

### 8.1 Current licenses at the pins

- The pinned [Marmot repository](https://github.com/marmot-protocol/marmot/blob/4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/LICENSE)
  is MIT, copyright 2025 Parres.
- The pinned [MDK repository](https://github.com/marmot-protocol/mdk/blob/9396adb6aa6b95b521a7979facd5ea7040c07288/LICENSE)
  is MIT, copyright 2024–2026 Internet Privacy Foundation.
- Neither pinned repository contains a separate NOTICE or trademark-policy file.
- Original Styx software and documentation remain AGPL-3.0-or-later except for
  the exact path-level exceptions in `LICENSING.md` and `REUSE.toml`.

### 8.2 What does not require a Styx license change

An independent implementation that reads the Marmot specification and writes
new Styx code can remain under Styx's AGPL default. Protocol compatibility does
not require adopting the upstream software license for independently written
code. Merely citing Marmot or testing behavior against MDK also does not add
Marmot or MDK to the distributed Styx dependency graph.

Therefore **no root `LICENSE` change is required now**, and no Marmot/MDK entry
must be added to `THIRD_PARTY_NOTICES.md` solely because this report cites the
projects.

### 8.3 What does require preservation of MIT notices

If a later task copies or derives a substantial portion of Marmot or MDK code,
documentation, examples, tests, fixtures, or vectors, the applicable upstream
MIT copyright and permission notice must travel with that material. Conservative
classification is appropriate for ported audit tests and the Marmot signing
fixture even if individual protocol facts or numbers may not be copyrightable.

Recommended classification before Phase B:

| Material | Recommended license treatment |
|---|---|
| Styx-authored implementation against the published protocol | Existing AGPL default |
| Patch intended for contribution to MDK or Marmot | MIT from its first commit, matching that upstream |
| Verbatim or derived Marmot spec fixture/vector | MIT with Parres notice and exact provenance |
| Verbatim or derived MDK test/code | MIT with Internet Privacy Foundation notice and exact provenance |
| New Styx-only conformance vectors | Apache-2.0 is suitable if separately human-approved; do not mix copied MIT material into an Apache-only file |
| Protocol/profile text intended for broad reuse | Decide exact paths before creation; permissive licensing is strategically recommended but not authorized here |

The existing six Apache-2.0 vector exceptions do not automatically cover a
future Marmot profile, fixtures, harness, or upstream patch. A separate Issue
must enumerate every permissive path and update `LICENSING.md`, `REUSE.toml`,
SPDX metadata, license texts if needed, and `THIRD_PARTY_NOTICES.md` when copied
material is actually distributed.

### 8.4 How Styx should cite compatibility

A future README may use wording equivalent to:

> Styx targets wire compatibility with the Marmot Protocol at revision
> `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`. The implementation is independent
> and experimental. Marmot and MDK are third-party MIT-licensed projects; no
> affiliation, certification, or endorsement is implied. The Least Authority
> audit of specific historical MDK revisions is not an audit of Styx.

Do not use “official Marmot”, “Marmot-certified”, or “audited by Least
Authority” for Styx. Pin the referenced spec revision in compatibility claims
and distinguish “targets compatibility” from “interoperable”, which requires a
passing cross-implementation test.

### 8.5 Documentation inventory

The following changes are needed but are forbidden in Issue #124 and must be
handled by exact-path follow-ups, preferably linked to documentation epic
[#118](https://github.com/styx-secure/styx/issues/118):

| Path | Finding | Follow-up |
|---|---|---|
| `README.md` | License section is accurate; product description still presents the JS chat as the active product | Reframe as secure application substrate, Themis first, chat reference; add compatibility/acknowledgement wording only after Phase B evidence |
| `styx-js/README.md` | Incorrectly says the package is MIT and makes stale production/privacy claims | Correct to the path-level AGPL/upstream map immediately; describe JS ledger, runtime shell, and reference chat separately |
| `docs/PANORAMICA-PROGETTO.md` | Says licensing has not been applied and records the old chat-product pivot | Refresh or clearly mark historical; point to `LICENSING.md` and the approved vision |
| `SECURITY.md` and threat-model docs | Do not yet express the new runtime-profile boundary | Add origin-control limitation and state that MDK/Marmot audits do not transfer |
| `CLAUDE.md` and `AGENTS.md` | Still describe the JS chat as the active product | Reconcile in a dedicated governance Issue with a human gate; do not weaken task controls |
| ADR-0001 / ADR-0003 and planning docs | Encode the superseded product-stack framing | Supersede through a new ADR rather than silently rewriting history |
| `LICENSING.md`, `REUSE.toml`, `THIRD_PARTY_NOTICES.md` | Correct for current files; no future Marmot surface is classified | Change only when an exact permissive surface or copied upstream material is approved |

The stale `styx-js/README.md` MIT statement is a present repository defect even
if Marmot is never used. It should be corrected in a small licensing/docs task
before another public release.

## 9. Phase B entry criteria

Phase B may start only when a new approved Issue provides all of the following:

1. exact allowed paths for wrapper, WASM build, tests, fixtures, migrations,
   transport adapter, and documentation;
2. an exact-path licensing map established before any upstream-targeted or
   derived material is created;
3. a choice between the Styx OpenMLS pin, a reviewed descendant, or the MDK
   fork, with source-diff and provenance evidence;
4. a new-profile/legacy-group migration policy with rollback and recovery;
5. an API design for raw account identity, proof creation/validation, staged
   inbound handles, and local confirm/discard;
6. atomic durable lifecycle states and crash-recovery invariants;
7. adversarial cases informed by the audit classes above;
8. a non-last-resort KeyPackage and two-member group round trip against the
   pinned MDK peer, comparing exact bytes where the protocol requires them;
9. reproducible WASM artifacts, integrity hashes, and all repository gates;
10. independent agent and human security review.

Last-resort KeyPackages, transport kind `445`, NIP-59 Welcome delivery,
metadata protection, multi-device behavior, and product integration remain
separate increments after the minimum PoC. The PoC must not be used by end
users or presented as a beta.

## Binary decision

**GO.** The pinned engine contains the mandatory suite and the generic draft
component, KeyPackage, and staged-Commit primitives. The wrapper work is
substantial and security-sensitive but bounded; the evidence does not force an
MLS-engine replacement or an unbounded fork.

This GO authorizes only preparation of a separately contracted Phase B PoC. It
is not evidence of Marmot interoperability, production security, metadata
anonymity, audit coverage, or fitness of current builds for sensitive use.
