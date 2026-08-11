# Phase B2.5a — deterministic same-parent branch-selection kernel

Date: 2026-08-12

Status: experimental, isolated, non-product proof

Authority: Issue #155; Phase B Epic #128
Base: `361b654ab27f567fcae6f279bb3d507ae119959d`

## 1. Result

Phase B2.5a implements a bounded convergence kernel for one specific conflict:
multiple valid one-Commit MLS children of the same retained parent. Given the
same frozen input set, independent clients select the same canonical Commit and
reach the same epoch and GroupContext regardless of input or evaluation order.

This result is narrower than Marmot convergence. It proves neither global input
closure nor convergence across multiple epochs, retained-history rewind,
witness scoring, local-publisher races, transport behavior, or suitability for
sensitive use.

## 2. Exact dependency identity

| Component | Exact identity |
|---|---|
| Styx base | `361b654ab27f567fcae6f279bb3d507ae119959d` |
| OpenMLS | `09e92777dba0528d3d29e2e5e681b7e91637c7be` |
| Marmot specification | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` |
| Installed WASM SHA-256 | `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a` |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` |
| Database namespace | `styx-b2-5a-poc-v1-` |

The implementation is independently Styx-authored from public protocol facts.
No MDK, Darkmatter, audit, upstream test, fixture, vector, example, or source
code was copied or adapted. The cited Least Authority report transfers no audit
coverage to Styx, its wrapper, configuration, journal, or this kernel.

## 3. Why the reduced ordering is valid

Pinned Marmot `protocol-core/convergence.md` orders eligible branches by:

1. higher effective Commit depth;
2. witness quorum before no quorum;
3. higher application witness score;
4. lower tip priority;
5. lower authenticated tip committer;
6. lower tip digest.

B2.5a admits only direct children of one parent. Every eligible branch has raw
depth one, no application witness is admitted, quorum is false, and witness
score is zero. Criteria 1–3 therefore tie. The bounded comparison is exactly
the remaining suffix:

```text
priority: 0 for B2.4-authorized Add/Remove, 1 for self-update
committer: authenticated raw 32-byte account identity from the MLS projection
commit digest: SHA-256 of the exact serialized MLSMessage Commit bytes
```

Comparison is numeric for priority and unsigned bytewise lexicographic for the
two 32-byte values. Transport author, relay, event id, timestamp, receive order,
caller hints, randomness, and wall clock never enter admission or ordering.

## 4. Candidate admission and selection

For each frozen Commit:

1. Restore a new provider from the exact retained parent snapshot.
2. Load and verify the local account/signature identity and group binding.
3. Require no pending Commit and the exact retained epoch and GroupContext.
4. Stage the exact bytes using `PhaseB2Group.stage_inbound_commit`.
5. Verify staging did not mutate provider state.
6. Project authenticated candidate data using `projectB2Commit`.
7. Evaluate `evaluateB24Authorization` over exact parent, projection and bytes.
8. Verify the decision binding and direct-child epoch.
9. Persist immutable evidence. Only `AUTHORIZED` evidence receives ordering
   authority.

Engine/decode/parent failure produces `NOT_CANDIDATE`; an authenticated Commit
that B2.4 rejects produces `REJECTED`. Neither state creates an edge or merges
anything. The resolver sorts only complete `AUTHORIZED` evidence and rejects
equal total-order identities as corruption.

The public journal exposes collection, freeze and read operations only. Its
initialization and final-resolution functions are private methods supplied as
opaque closures to an adapter created by that journal. Consequently no public
journal call accepts caller-provided candidate evidence, priority, committer,
authorization digest, parent metadata, or successor snapshot. Engine and policy
invariant errors with a typed code propagate; only closed OpenMLS staging/decode
outcomes become `NOT_CANDIDATE`.

The selected input is restored, staged, projected, authorized, and checked a
second time. Its evidence digest must match the first pass before merge. The
successor epoch and GroupContext must equal the projected candidate.

## 5. Frozen durable schema

All records use strict direct objects, exact field sets, bounded values,
domain-separated JSON encoding, SHA-256 digests, and the frozen runtime tuple.
Unknown fields, states, versions, impossible nullable combinations, digest
mismatches, and unsafe counters fail closed.

| Store | Logical record | Important binding |
|---|---|---|
| `head` | canonical local head | identity, sequence, state, epoch, GroupContext, snapshot, prior head, transition, winner |
| `retained-state` | exact provider snapshot | content digest, identity, epoch, GroupContext, runtime |
| `input` | exact Commit bytes | group, first batch, digest, length, disposition |
| `frozen-batch` | immutable decision set | protocol base, sorted Commit set, local CAS head, nullable result |
| `candidate-evidence` | admission/policy evidence | parent, candidate, authorization, committer and total-order tuple |
| `transition` | durable head change | predecessor, batch, winner, outcome digest and successor |

Canonical digest domains are:

- `STYX-B2-5A-HEAD-V1`
- `STYX-B2-5A-RETAINED-STATE-V1`
- `STYX-B2-5A-INPUT-V1`
- `STYX-B2-5A-PROTOCOL-BATCH-V1`
- `STYX-B2-5A-BATCH-V1`
- `STYX-B2-5A-CANDIDATE-EVIDENCE-V1`
- `STYX-B2-5A-COMPARISON-TUPLE-V1`
- `STYX-B2-5A-OUTCOMES-V1`
- `STYX-B2-5A-TRANSITION-V1`

The protocol batch identity includes group id, base epoch, base GroupContext
digest, and sorted unique Commit digests. The local base-head digest is kept in
the batch record for CAS but deliberately excluded from cross-member identity.

## 6. State and recovery table

| Durable condition | Action | Canonical MLS result |
|---|---|---|
| Collected, not frozen | More input may be retained | unchanged |
| `FROZEN` with retained parent | Replay deterministic decision | unchanged until atomic commit |
| Valid winner | Atomic evidence, transition, snapshot and head commit | exact selected successor |
| No valid candidate | `RESOLVED`, null winner, closed outcomes | byte-identical head |
| Transaction/CAS abort | Retry from durable `FROZEN` | exact predecessor |
| Missing retained parent | terminal `UNRECOVERABLE` head/transition | epoch, GroupContext and snapshot reference unchanged |
| Malformed/incoherent state | typed fail-closed error | no authorized mutation |
| Already `RESOLVED` | validate result, never reapply | unchanged |

There is no durable `RESOLVING`. The write transaction re-reads the canonical
head, batch, retained parent, every input, and every pending evidence record.
It validates the complete frozen bundle and then writes all final evidence,
dispositions, successor state, transition and head atomically.

The base parent and selected successor remain retained. B2.5a performs no
pruning. This makes recovery evidence simple but retains historical private MLS
material longer and makes no forward-secrecy material-release claim. Resolution
also revalidates the current head's transition record, so all six stores are in
the decision read-set even for a null winner.

## 7. Cross-client identity and provider-state finding

The shared convergence identity is:

```text
(group id, protocol batch digest, selected Commit digest,
 successor epoch, successor GroupContext digest)
```

It excludes local identity, local head digest and provider snapshot digest.
Distinct members hold different private state. Their agreement is demonstrated
by the same selected identity plus bidirectional application-message liveness.

Two replicas of the same member produce identical cryptographic provider-map
contents after winner merge, but the pinned OpenMLS serializer records a local
merge-time value at `MessageSecrets.message_secrets.added_at`. Its nanoseconds
differ even when the MLS protocol state is otherwise identical. The diagnostic
same-member comparison sorts keys and normalizes only that timestamp. Exact
snapshots remain unmodified and content-addressed. This timestamp is not used
for selection, protocol identity, or persistence decisions.

## 8. Hostile evidence matrix

The focused real-WASM suite exercises:

- three-candidate insertion and asynchronous completion permutations;
- privileged Add versus ordinary self updates;
- privileged Remove versus ordinary self update;
- two ordinary authenticated committers;
- two Commit values from one authenticated committer, with digest fallback;
- exact duplicate retention and caller-buffer mutation after retention;
- wrong group, wrong parent epoch, malformed bytes and non-admin operation;
- frozen-set immutability and post-freeze deferral to a later batch;
- own freshly prepared Commit staging (`OwnCommit`) as a closed non-candidate;
- null-winner terminal resolution and idempotent restart behavior;
- losing-branch non-application and winner bidirectional message liveness;
- changed stored bytes, missing retained parent, a storage-key/content collision,
  and fully bound forged final evidence blocked by the absent public finalizer;
- empty, oversized and over-cap input sets;
- abort at writes to each of the six stores, exact rollback and retry; and
- strict unknown-field, disposition, digest and safe-counter rejection.

The same-member provider semantic comparison found the volatile timestamp
described above; the implementation records rather than hides that distinction.

## 9. Own-Commit asymmetry

At the pinned OpenMLS revision, staging a client's own freshly prepared Commit
from a fresh restore fails closed as `OwnCommit`. B2.5a records it as
`NOT_CANDIDATE` and mutates no state. A later local-publisher integration cannot
reuse the inbound staging path. It needs durable B2.4 pending evidence and two
outcomes:

- if the local Commit wins, confirm the exact pending Commit after publish
  obligation evidence;
- if it loses, clear the pending Commit and apply the selected inbound branch.

The B2.5a candidate-evidence record contains results and bindings rather than a
WASM handle, so it remains neutral to that future admission mechanism.

## 10. Pinned Marmot mapping and explicit deferrals

| Kernel element | Pinned normative source | B2.5a treatment |
|---|---|---|
| Parent from MLS replay, not transport | `protocol-core/convergence.md`; `inbound-processing.md` | implemented for one retained parent |
| Freeze/cutoff rule | `protocol-core/convergence.md` | explicit caller-controlled freeze; scheduler deferred |
| Ordering criteria 1–6 | `protocol-core/convergence.md` | criteria 1–3 tied; criteria 4–6 implemented |
| Missing retained anchor | `protocol-core/retained-history.md` | typed terminal `UNRECOVERABLE` |
| Retained-history horizon | `protocol-core/retained-history.md` | parent/successor retained; rewind/pruning deferred |
| Publish before local apply | `protocol-core/publish-lifecycle.md` | existing B2.4 behavior; conflict integration deferred |

Within this one-pass kernel, `LOSING` and `NOT_CANDIDATE` are terminal for the
exact frozen input and exact Commit bytes are deduplicated thereafter. Pinned
Marmot instead defers losing branches and missing anchors for later eligibility.
That multi-pass behavior is deliberately not claimed here and must replace, not
silently inherit, these terminal probe outcomes in the retained-history phase.

## 11. Rejected alternatives

- **Apply on arrival:** rejected because transport order becomes consensus.
- **Trust parent/committer/priority hints:** rejected because transport metadata
  is not MLS-authenticated authority.
- **Use raw provider snapshot digest as shared identity:** rejected because
  serialization and member-private state are local.
- **Persist `RESOLVING`:** rejected because it creates an unnecessary partial
  durable state; one transaction can move `FROZEN` directly to `RESOLVED`.
- **Treat all-invalid as corruption:** rejected because a closed null result is
  deterministic and expected under hostile input.
- **Integrate publisher, scheduler, witnesses and rewind now:** rejected because
  each adds a separate state machine and would obscure the depth-one base case.

## 12. Evidence and limitations

Focused evidence at the working candidate currently passes 15/15 tests. Exact
full-suite, browser, build, enforcement, artifact-integrity, independent-agent,
CI and human evidence is recorded on the candidate PR rather than claimed by
this pre-merge report.

This proof does not provide:

- full Marmot or MDK interoperability/conformance;
- global or fair input closure, liveness scheduling, or relay guarantees;
- multi-Commit branches, rewind, supersession, witness quorum or scoring;
- locally pending/published branch integration;
- pruning, compaction, exporter retention or forward-secrecy release;
- keyed journal authenticity, external monotonic anchoring, or rollback defense;
- browser storage persistence, eviction/quota guarantees, secure erasure;
- malicious-origin, compromised browser/OS, metadata-privacy or anonymity
  protection; or
- audit coverage or readiness for real sensitive data.

Strict container/unknown-field failures use the B2.5a error namespace. Some
primitive field bounds reused from B2.3, including safe-counter overflow, retain
their stable `B23_*` typed error codes; neither category authorizes mutation.

Passing the synthetic and real-WASM probes is executable evidence for this
bounded branch-selection property only.

## 13. Remaining path toward full convergence

1. Define and test the local-publisher admission path around durable B2.4
   pending evidence and publish-before-apply.
2. Add retained-history indexing, a five-Commit rewind horizon, deterministic
   supersession, and explicit material-release/pruning rules.
3. Add multi-Commit branches and effective-depth comparison.
4. Add application-witness admission, quorum and witness scoring.
5. Specify quiescence/deadline collection, fair local-intent opportunity,
   multi-pass settlement and missing-parent acquisition.
6. Integrate a transport-neutral protocol adapter only under a separate
   compatibility, threat-model and persistence decision.

None of those steps is silently implied by B2.5a.
