# Phase B2.7 Stage 2 — durable authenticated MLS sender attribution

Status: implementation candidate for Issue #163. This is isolated executable
evidence, not product activation. Exact-head independent and human review remain
mandatory before merge.

## Question

Can the B2.6 durable message machine preserve the current-epoch sender identity
authenticated by OpenMLS, bind it to the same independently verified account
roster and producing epoch edge, and release plaintext or sender authority only
from the exact committed IndexedDB record?

## Result

The bounded Stage 2 implementation answers the local question affirmatively.

The installed OpenMLS-WASM boundary returns the authenticated sender leaf,
BasicCredential identity and leaf signature key together with the application
plaintext. The isolated B2.7 adapter uniquely resolves that leaf in the same
BIP-340-validated parent projection, checks the returned identity and signature
key byte-for-byte, recomputes the exact B2.4 verified-leaf digest and obtains the
104-byte account proof only from that projection. Application payload bytes are
never sender authority.

The provider successor and strict ACCEPTED record are committed by one
IndexedDB compare-and-swap transaction. The caller receives plaintext and the
sender tuple only after the exact record is re-read and parsed. Duplicates return
only the stored result. Transaction failure, pre-commit crash and CAS loss expose
neither plaintext nor sender fields.

This result is deliberately current-epoch and local. It does not identify a
human or device, prove delivery to a third party, create non-repudiation or make
the PoC suitable for sensitive data.

## Frozen identity and artifact transition

- Contract base: `097fc88f05e8fc740ba67ef13ff07906d6999006`
- Approved Stage 2 continuation head:
  `fc358ad82eaa7c54ab1790b8b7e1876d3df3819f`
- Artifact-install commit: `ae9477402ae02bc288497063cecd3e5aa7bda9ad`
- Durable-machine commit: `96d75915478b445f4bbdaa90eca1467422b457a8`
- OpenMLS revision: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- Marmot specification revision:
  `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`
- Rust image:
  `rust:1.96.1@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376`
- wasm-pack: `0.15.0`, release SHA-256
  `c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a`
- Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`

The installed generated set matches the approved Stage 1 candidate exactly:

| File | Bytes | SHA-256 |
|---|---:|---|
| `openmls_wasm.js` | 105,588 | `3ae01d30c30d2fdb7bcd48d8406d485a875f5c0a8ad25e726cb6ed7b820c6083` |
| `openmls_wasm.d.ts` | 36,771 | `890693bda50ca202181f1988078b43d6dfa81e5468a2b7034f5fedbd71fe37d6` |
| `openmls_wasm_bg.wasm` | 2,081,600 | `ed5e740d9c93aa46aa1afb7b6065e4b5b92be972a8a080ddd0a35091260691bb` |
| `openmls_wasm_bg.wasm.d.ts` | 19,972 | `d9eb6767743ef6436580e16f78bb8c549764fd3cedea8977f73640d720b74b4d` |
| `package.json` | 449 | `88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85` |

The generated public surface remains exactly 57,363 canonical JSON bytes with
SHA-256
`84fc77b3394fff5d48027dce3fe55c29aa339507bf9bd140f9c9966a60ba4061`.
Two new clean external builds matched each other and every installed file.

The isolated B2.7 durable runtime stamp records the installed candidate WASM
digest `ed5e740d...`. It deliberately overrides the inherited B2.3/B2.2 writer
digest, so a B2.7 record states the artifact that actually performed its MLS
operation rather than merely remaining internally self-consistent with an older
writer tuple.

The B2.2 writer is admitted only as the named exact tuple recorded in
`MLS_BUILD_INFO`. The immutable synthetic fixture restores with the candidate,
decrypts its reference ciphertext and creates a reply. No generic or partial
compatibility rule was added.

## Fresh durable format

The implementation uses database prefix `styx-b2-7-poc-v1-`, record version 1,
profile `sender-attributed-message-ratchet-poc` and fresh
`STYX-B2-7-...-V1` digest domains. It neither opens nor migrates a B2.6 or
product database.

An ACCEPTED inbound record binds, in one fresh content digest:

- transcript-derived instance and retained-base identity;
- group id, decimal epoch, GroupContext digest and verified-leaf digest;
- exact ciphertext and plaintext digests and stored plaintext;
- unsigned 32-bit sender leaf index;
- 32-byte account identity;
- 32-byte MLS leaf signature key; and
- 104-byte BIP-340-verified account proof.

Missing, extra, malformed, out-of-range or contradictory fields fail closed.
DEFERRED, INVALIDATED, REJECTED and STALE records structurally reject plaintext
and every sender field. A DEFERRED record can gain sender attribution only after
the retained exact-epoch instance authenticates it; current-roster fallback is
forbidden.

## Adversarial and concurrency evidence

The Stage 2 Jest suite has 72 tests. It covers:

- three members, three interleaved senders and per-sender out-of-order delivery;
- payload false identity, restart, duplicate and exact durable re-read;
- corrupted records and malformed exact-field inputs;
- out-of-roster leaf, identity, signature-key, epoch, group and producing-roster
  mismatch;
- canonical and retained historical receive without cross-epoch fallback;
- removal and re-addition at the same leaf with a new signature key and proof;
- tampered, replayed and malformed ciphertext with no durable ACCEPTED record;
- disposable-provider recovery of the original tampered generation followed by
  the next sender generation; and
- pre-commit crash, transaction failure, CAS loss, convergence, re-adoption,
  release, truncation and history bounds inherited from B2.6.

The Playwright suite has 12 tests and passed in Chromium and Firefox with zero
skip. Each browser executed 100 two-connection competing inbound receives
without Web Locks. Every race produced exactly one durable attributed winner;
the typed loser exposed no plaintext or sender authority. Moving the
message-state CAS check ahead of the duplicate fast path was required to close
a race discovered by this browser evidence.

The long-lived Stage 1 source probe documents that a failed authentication can
consume a receiver generation. In the durable path, each attempt uses a
disposable restored provider and persists it only on success, so a failed
tampered attempt does not durably burn the generation. This narrows the local
failure but does not remove the inherited selective-drop/liveness/DoS residual.

## Verification results

Completed successfully on the implementation candidate:

- pinned native OpenMLS-WASM tests: 17 passed, 0 failed;
- two clean external builds: all five outputs byte-identical to one another and
  the committed artifact;
- legacy OpenMLS 1:1 round trip: pass in both directions;
- B2.7 Jest: 72 passed, 0 failed;
- B2.7 Playwright: 12 passed, 0 failed, 0 skipped;
- chat PWA production build: pass;
- agent-enforcement: 54 passed;
- docs-claims-lint tests: 10 passed;
- docs/spec claims scan: 57 files, 0 findings;
- frozen Stage 1 patch, source probe, generator and fixture: byte-identical to
  continuation head `fc358ad8...`; and
- full root Jest: 93 suites and 1,403 tests passed; and
- `git diff --check`: pass.

The first full root Jest run passed 1,402 of 1,403 tests and exposed one stale
hard-coded B2.2 OpenMLS digest in `test/crypto/kdf-wasm.test.js`. Work stopped
because that path was not authorized. The product owner then approved an exact
minimal contract amendment at implementation head `96d7591...`; the Issue body
now permits only replacing that expected digest with the already approved B2.7
digest while preserving the KDF/OpenMLS inequality assertion. After that exact
one-line change, the full required root invocation passed all 1,403 tests. No
KDF artifact, test logic, manifest, lockfile or product file changed.

The root invocation also reported the documented relay-test self-skips because
no relay was running at `ws://localhost:17777`. The changed paths do not depend
on relay behavior. These skips are not counted as B2.7 evidence.

Post-correction exact-head CI, focused reviewer re-verification and independent
human review are external gate evidence; this candidate report does not presume
or describe them as green.

## Independent review

Fable 5 reviewed the complete Stage 2 contract before implementation and then
performed a fresh clean read-only exact-source review of source head
`8f203e9752e4e9255f8dab0999a3730ab71e3611`, tree
`2975a3c1710c8eb211f3a5e3b0574ebed057b189`, in Claude Code session
`d51cd29e-0d4f-4447-9a09-252bc5c351b4`. The external report is 31,653 bytes,
SHA-256 `10ef0e47713c1eb5f9b6e14360601a0861cd8851c01de79d660c2d528d5b593f`,
and its verdict is `APPROVE WITH NON-BLOCKING NOTES`.

The reviewer found no exploitable security, integrity, attribution, durability,
compatibility, concurrency or parser defect. Its LOW-1 note identified that the
B2.7 runtime stamp inherited the superseded B2.2 WASM digest. The implementation
now overrides that stamp with the installed B2.7 digest, and the existing
72-test B2.7 suite pins it without adding or weakening a test. LOW-2 concerned
only stale Draft-PR metadata, which is updated separately without changing the
reviewed tree. The correction requires focused re-verification by the same
reviewer on its exact source head; Claude Opus does not review this task.

The Fable environment could not execute shell commands because its nested-user
sandbox failed closed. The review therefore treated the independently executed
local and exact-head CI results as external evidence, disclosed that limitation,
and verified the source, Git trees, scope and completed CI metadata read-only.
Agent review is evidence only and cannot satisfy the independent human gate.

## Rollback

Before merge, revert the Stage 2 commits or delete the task branch/worktree and
close Draft PR #164. The base runtime remains authoritative.

After merge, revert the squash commit. Delete the isolated B2.7 namespace
rather than migrating it; product databases were never opened. A product MLS
envelope written with the candidate artifact can be read after revert only if
the revert deliberately retains the separately proven exact compatibility
tuple. Otherwise loading fails closed as `OPENMLS_INCOMPATIBLE`.

Generated artifact, provenance and build tuple must be reverted or retained as
one exact unit. Keeping only part of that tuple is forbidden.

## Residual risks and non-claims

- The Styx Rust patch is outside upstream audit coverage; the unreleased pin and
  `extensions-draft` remain deliberate risks.
- Failed authentication can consume a receiver generation in a long-lived
  provider; malicious selective drop and bounded liveness/DoS remain.
- Current-epoch-only attribution intentionally sacrifices some late-message
  liveness rather than interpreting a past message with a current roster.
- The same-origin runtime, XSS, extensions, compromised browser/OS/device,
  coherent IndexedDB rewrite/rollback, eviction, physical erasure and unlocked
  device compromise remain outside the claim.
- Local attribution binds an MLS leaf/account tuple, not a human, device,
  transport endpoint or legal identity. It is neither non-repudiation nor a
  third-party proof.
- Synthetic plaintext is persisted in an isolated PoC and is unsuitable for
  real sensitive data.
- Storage and history bounds are operational evidence, not a full retention or
  compaction policy.
- No product, transport, anonymity, metadata privacy, delivery, business-rule,
  Marmot-conformance, interoperability or independent-audit claim follows from
  B2.7.
