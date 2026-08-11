# Phase B2.3 local MLS durability evidence

Status: **candidate implementation evidence; product activation remains
forbidden**

This report records the isolated proof authorized by Issue #151. It shows that
one pinned B2.2 Provider dedicated to one PoC group can be driven from a
strict, atomic local journal without retaining a stale JavaScript/WASM object
as canonical state.

The new claim is intentionally narrow: in the tested Chromium and Firefox
profiles, one successful journal head forms a gap-free, hash-linked local
sequence, and the tested abort, quota, reload, hostile-record and concurrent
actor cases cannot install two canonical successors for the same durable head.

This is not a product or Marmot interoperability report.

## Frozen authority and engine tuple

- Contract: Issue #151, approved REST body SHA-256
  `04e3e1f8d697275c030891050f648bc0391901e43b1c575a28fde91765855edb`.
- The pre-repair approved body SHA-256 was
  `4a82671213f122e832bf534152d25f0e6a4d1558c2e2d358a0ab82b414b45777`.
  The product owner approved the structural-only parser repair in
  `issuecomment-5252221087`: exact required headings were restored without
  changing any scope, format, acceptance criterion, test, gate or
  authorization.
- Narrow required-test amendment approved in Issue comment
  `issuecomment-5251678319`; its independent Opus 5 review report SHA-256 is
  `7479b6a453e123e06cb66375dad2eb87b619f0fe101bedf4337d5348182e448e`.
- Base commit: `62000a9f5c6d886a23a96bab9cf2b7cd20d6efcc`.
- Base tree: `be9aca70bc02e37cf9f82d74cba1aaa9cac1c8c1`.
- OpenMLS revision:
  `09e92777dba0528d3d29e2e5e681b7e91637c7be`.
- WASM artifact SHA-256:
  `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a`.
- Ciphersuite:
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- Database prefix: `styx-b2-3-poc-`.
- Schema version: `1`.
- Durable states: exactly `STABLE` and `PREPARED`.

The spike imports the existing `openVaultDb()` and generated B2.2 surface
read-only. It changes no product path, vendor artifact, manifest, dependency,
lockfile, workflow or license file.

## Architecture

The proof has four boundaries:

1. A strict codec snapshots closed objects without invoking getters or
   `toJSON`, validates all scalars, arrays and byte lengths, and produces
   fixed-order domain-separated encodings.
2. A private four-store journal owns the sole canonical head. Snapshot blobs
   are content-addressed, while authenticated GroupContext TLS digests identify
   logical MLS epochs.
3. A disposable adapter restores a new Provider for each operation, reloads
   the exact identity and group, checks epoch/GroupContext/own-identity/pending
   bindings, performs at most one transition and frees every exposed handle.
4. Jest exercises the real pinned WASM engine; Playwright exercises native
   IndexedDB transaction serialization across two independent connections.

No Provider, Group, Identity, staged/pending handle or closure capable of
calling one escapes the adapter.

## Private storage and atomic successor rule

Each exact database contains one PoC group and four stores:

| Store | Role |
| --- | --- |
| `head` | sole CAS target and current canonical record |
| `snapshot` | exact Provider bytes keyed by SHA-256 |
| `transition` | immutable transition evidence and exact Commit/Welcome/artifact bytes |
| `evidence` | append-only opaque publication evidence; every record is independently bounded |

Initialization fails unless every store is empty. A read fails on a missing
referenced snapshot or any orphan/split snapshot. Historical transitions and
evidence remain immutable; superseded snapshots are deleted in the same
transaction that installs their successor. This is logical cleanup, not a
physical-erasure claim.

The PoC deliberately exposes no general history-enumeration API: transition
and evidence retention is append-only and therefore requires separately
designed checkpoint/compaction before product activation. `evidenceCount` and
`maxEvidence` bound one `PREPARED` publication lifecycle; they are not a
whole-history cap that can permanently exhaust later lifecycles.

Every CAS performs, in one IndexedDB `readwrite` transaction:

1. read and strictly parse the current head;
2. compare its safe-integer sequence and exact head digest with the caller's
   validated predecessor;
3. reject transition-id, evidence-id or snapshot-content collisions;
4. write the exact successor snapshot, transition and evidence;
5. replace the head; and
6. remove the superseded snapshot.

A loser returns `B23_CAS_CONFLICT`, writes nothing and discards its mutated
Provider. Web Locks, heartbeats and leases are not safety prerequisites.

## Frozen canonical formats

Canonical records are UTF-8 `JSON.stringify` encodings of fixed-order arrays of
already validated primitives and payload digests. The domain labels are:

- `STYX-B2-3-HEAD-V1`;
- `STYX-B2-3-TRANSITION-V1`;
- `STYX-B2-3-PROJECTION-V1`; and
- `STYX-B2-3-EVIDENCE-V1`.

The head order is:

```text
format, version, profile, groupIdHex, accountKeyHex, signatureKeyHex,
openMlsRevision, wasmArtifactSha256, ciphersuite, seq, state, epochDec,
epochDigestHex, snapshotKeyHex, snapshotBytes, transitionIdHex,
priorHeadDigestHex, pendingCommitDigestHex, pendingWelcomeDigestHex,
candidateEpochDec, candidateEpochDigestHex, verifiedLeafDigestHex,
artifactId, artifactDigestHex, publishAttempts, evidenceCount,
lastAppliedCommitDigestHex
```

`headDigestHex` is SHA-256 over that domain encoding. A transition separately
binds its id, kind, group, sequence, predecessor digest, phase, epoch,
snapshot key, Commit/Welcome/projection/candidate/verified-leaf digests,
artifact identity/digest, counters and applied-Commit digest.

The digests are corruption and CAS identities, not MACs. An origin or storage
attacker able to rewrite all records can recompute them.

## Bounds and strict parsing

| Value | Bound |
| --- | ---: |
| Provider snapshot | 8,388,608 bytes |
| Provider entries | 4,096 |
| Provider key | 65,536 bytes |
| GroupContext TLS | 65,536 bytes |
| Commit | 1,048,576 bytes |
| Welcome / generic artifact | 2,097,152 bytes |
| evidence payload | 65,536 bytes |
| PoC members | 16 |
| proposals | 32 |
| publication attempts / evidence records | 64 each per `PREPARED` lifecycle |

Epochs are canonical unsigned-64-bit decimal strings, never JavaScript
Numbers. Identifiers and digests use exact lowercase hexadecimal forms. The
projection parser is closed and validates all member, proposal and update-path
fields, candidate ordering, committer membership, candidate epoch progression,
GroupContext TLS digest and all component/count bounds.

Before OpenMLS sees a snapshot, a structural parser validates the Provider
format (`u64 count`, then `u64 key length`, `u64 value length`, key and value),
rejecting truncation, integer/length overflow, trailing bytes and duplicate
keys. This closes cases the pinned `restore_state()` format alone does not
reject.

Unknown, missing, extra, accessor-bearing, non-canonical, inconsistent or
oversized input fails with a closed `B23_*` error and no repair, fresh-state
fallback or memory-only continuation.

## Outbound lifecycle and recovery

| Durable point | Recovery decision |
| --- | --- |
| `STABLE(N)` | restore and resume |
| `PREPARED(N, attempts=0)` | explicit discard through proven clear, or publish exact Commit |
| intent CAS failed | predecessor `PREPARED(..., attempts=0)` remains canonical |
| `PREPARED(N, attempts>0)` | discard/regeneration forbidden; confirm and retain exact artifact for retry |
| confirm successor CAS failed | the attempted `PREPARED` predecessor remains canonical; restore and confirm again |
| `STABLE(N+1)` after confirm | restore successor; exact Commit/Welcome/artifact remains in its immutable transition |

The publication-intent CAS occurs before any external call. It freezes generic
`{id, bytes, digest}` data and increments the attempt count. Retries accept only
the exact id and bytes. Silence, timeout or disconnect is not success evidence.

Before the first attempt only, `clear_pending_commit` is checked against the
same prior epoch and own identity, serialized, and installed as a new
`STABLE(N)` head with a higher journal sequence. After an attempt, recovery
confirms locally even if no peer received the Commit; this preserves the only
later convergence route but does not prove delivery.

## Inbound lifecycle

From `STABLE(N)`, the adapter restores fresh state, stages the exact received
PublicMessage Commit, captures the complete bounded projection and proves that
staging did not alter serialized Provider state. A synchronous injected
decision then chooses:

- reject: discard handles and perform zero writes;
- accept: merge in RAM, re-check candidate epoch, GroupContext and
  verified-leaf digest, serialize the complete successor and CAS
  `STABLE(N+1)`; or
- CAS loss: discard the mutated Provider and return a typed conflict.

Exact re-staging yields the same canonical projection bytes. After advance, an
exact duplicate Commit is recognized by its digest before any Provider access
and performs zero engine calls and zero writes. Same-epoch non-applicable peer
races are reported, not resolved.

## Adversarial and crash evidence

| Case | Executable result |
| --- | --- |
| two real IndexedDB connections, 100 races/browser | one successor, one `B23_CAS_CONFLICT`, one sequence increment, one reachable snapshot |
| prepare versus inbound-accept over two real connections | exactly one `PREPARED` or accepted `STABLE` successor |
| real OpenMLS prepare versus inbound merge | one serialized fake-connection CAS winner; separate browser evidence proves native transaction serialization |
| stale sequence/digest mixtures, old-head replay and ABA | fail closed; same-epoch successor still has new sequence/id/digest |
| head/transition extra, missing, malformed and digest mismatch | rejected before engine use |
| truncated, oversized, trailing and duplicate-key Provider blobs | rejected before `restore_state()` |
| snapshot for wrong group/account/signature key/epoch | engine binding rejection; no successor write |
| missing or orphan snapshot | `B23_CORRUPT`; no repair |
| deterministic callback crash or request-level mapped quota failure | all four stores retain the complete predecessor; no unhandled request rejection |
| prepare, intent, clear, confirm or inbound CAS failure | fresh mutated Provider discarded; durable predecessor unchanged |
| reload after prepare and publication intent | only the committed strict head determines recovery |
| exact retry after ambiguous publication | changed id/bytes rejected; frozen bytes retained after confirm |
| inbound reject, retry, duplicate and CAS loss | zero-write reject/duplicate/conflict and successful exact retry |
| self-produced outbound Commit applied as inbound | OpenMLS rejects; pending-confirm recovery remains mandatory |
| pending confirm/clear after restore | fresh-provider operations succeed and bidirectional application liveness remains |

The browser abort probe performs a real native transaction write followed by
an injected callback abort and observes no partial snapshot. A deterministic
IndexedDB request-level write failure drives the real `VaultDb` abort and quota
mapping, proves predecessor preservation and observes no unhandled rejection.
The shared `FakeVaultDb` fails writes synchronously and does not itself model
that request path. Reproducible real quota exhaustion was not forced: it is
recorded as **manual/unexecuted**, as permitted by the contract.

No test claims physical power-loss survival. “Crash after CAS” means a fresh
page reload reads only the transactionally committed record.

## Resource measurement

One exact targeted run constructed the frozen cap of 16 MLS members. It made
the following non-deterministic observation; snapshot size varies with fresh
key material:

```text
members=16
max_snapshot_bytes=39919
wasm_before_bytes=1441792
wasm_peak_bytes=1638400
```

The largest snapshot was below the 8 MiB fail-closed bound. WASM memory is a
process-level high-water observation and is not a retained-secret, secure
deletion or general production-capacity claim.

## Exact local test evidence

- Targeted Jest: 1 suite, 19 tests passed. Log SHA-256
  `7906049e4054c7579e4aa94443d0e574496e940c2ae39b009ef1ab53f3a55240`.
- Playwright: Chromium and Firefox, 6 tests passed; each browser completed 100
  two-connection races without skip. Log SHA-256
  `9893cea5bd9207946046ddb61d39c13fe79b4b2d0ec9cedf95b83f3dc06bd10c`.
- Pre-contract E-1 (`get` then `put` in one `VaultDb.transaction`) passed 2/2;
  evidence SHA-256
  `2332ecdda45718adc9e2971cc666ecee9b95f91387e431fc8cad99768565c59e`.

Full repository regression, exact vendor-hash, exact-HEAD CI and independent
candidate-review evidence are recorded on the Draft PR because their logs and
HEAD identity are produced after this report enters the candidate commit.

The pre-commit regression run additionally recorded:

- complete Jest: 87 suites and 1,174 tests passed; log SHA-256
  `f5803b7e560e215d554550fb77ee2aeb05686366a86c6f6fe95c94a4ea8f891d`;
- B2.2 capability probe against the exact B2.1 parent artifact extracted from
  `0bcd19f114ad1dd9cc419a8c53f0d53d33428ac0` and the current pinned vendor:
  passed; log SHA-256
  `e31fd84df728a02b4de78eea9621eae4233f3ab44115b59a7a2900c1a183669b`;
- B2.2 composition probe over the same inputs: passed; log SHA-256
  `6090ac29fcc257e54d58251f63853990f65e0fb8cc2bd83156f2ee524b9fc3a8`;
- reference chat `npm ci && npm run build`: passed; build-log SHA-256
  `daa21273f5a4f5858cf32f32a48b07f83831fed6a0507743bb84b5531eb41906`;
- agent-enforcement: 54 tests passed; log SHA-256
  `e15d07951d4c97caf5d539a9bdaae1ce5aa6cb20fbb4038cc5f2b981064b3ecd`;
- current vendor WASM, JavaScript and declaration hashes remained respectively
  `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a`,
  `50599ddc433619fd617d8071990f1edb94866388028c6875a493c7ac7ec1de7d`
  and `17daa548987cdde22b9704921264ce85ec8ad70411eee255f544de70cd8e5d30`.

The two original bare B2.2 commands in Issue #151 omitted the mandatory
committed and candidate directory arguments and therefore exited before
probing. The product owner approved the independently reviewed narrow amendment
in `issuecomment-5251678319`: one self-contained repository-root command now
extracts the frozen B2.1 parent artifact outside the working tree and supplies
both exact directories. The successful evidence above uses those inputs. No
other contract term, scope boundary, test or gate changed.

The first exact-candidate reviews found two local robustness defects and one
test-model gap: historical evidence enumeration could mislabel a valid journal
after the per-lifecycle cap, and real `VaultDb` write-request promises were not
owned by the transaction callback. The remediation removes the unused
unbounded history-enumeration helper, awaits every queued write request, and
adds a deterministic request-level failure probe against the real `VaultDb`.
No canonical field, encoding, digest, cap, schema version, runtime tuple or
product path changed. Independent design follow-ups were produced by Opus 5
(SHA-256
`008463344368771406ef3cab94c59b666531e30f660e36f40af2603a69cef8f0`)
and DeepSeek V4 Pro (SHA-256
`8f969cb8800c04ba888cae8674dfe67dc1877db3ac282572be00377405e74714`).

## Rejected alternatives

- Persisting JavaScript/WASM objects or closures: stale heap state would become
  an unreviewable second authority.
- `MERGING` or `RECOVERY_REQUIRED` durable states: merge is replayable RAM work;
  invalid durable data must fail rather than be repaired.
- Web Locks, leases or heartbeats for safety: they are liveness mechanisms and
  cannot replace atomic CAS.
- Snapshot hashes as epoch identities: Provider serialization is not canonical;
  authenticated GroupContext TLS and epoch are checked instead.
- Discard after possible publication: it can strand a peer in the candidate
  epoch and destroy the only exact recovery artifact.
- Interpreting transport acknowledgements: B2.3 deliberately stores only opaque
  evidence and makes no delivery assertion.
- Sharing the product vault database: the proof uses an exact private prefix
  and local migration so no production schema or user record is touched.

## Non-claims and remaining Phase B work

B2.3 does not prove peer convergence, same-epoch fork selection, rejoin,
cross-device consistency, delivery, power-loss survival, full-profile rollback
resistance, at-rest encryption, authorization, account-proof validation,
transport correctness, notification privacy, Safari support, native-runtime
behavior, audit status or fitness for sensitive use.

The journal enforces sequence monotonicity and transition-internal epoch
coherence, but does not compare `epochDec` between every durable predecessor
and successor. Durable epoch non-regression is not claimed and belongs with
the separately designed rollback/freshness mechanism.

Later separately approved work must still provide at least:

- B2.4 account-identity-proof and application authorization policy;
- peer-race/fork convergence, rejoin and retained-history rules;
- a transport-neutral wire/conformance layer and real interoperability tests;
- vault/sealer integration and external rollback anchors;
- product runtime integration, native profiles and security review.

The implementation is Styx-authored under the repository's default
AGPL-3.0-or-later classification. No Marmot, MDK, Darkmatter, Least Authority or
other third-party code, fixture, vector, example or prose was copied or
adapted. The shared high-level problem space does not constitute a Marmot
compatibility assertion.

## Rollback

Before merge, close the Draft PR. After merge, revert the task commits and, if
the harness was run, delete only the exact `styx-b2-3-poc-<databaseTag>` database
opened by that harness. Never use a wildcard. IndexedDB deletion is not claimed
as physical erasure.
