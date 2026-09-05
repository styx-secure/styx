# Draft task contract — minimum language-neutral application-core interface

Working draft only; this file is not repository authority. The superseding
provider authority is Issue #295 comment `5550502736`. Exact combined-remediation
Base: `e0af4e1e2173deb2481eabdb24d8622282b33455`. The closed native dependency
relation contains 65 Base files; its digest is bound by the package manifest.

<!-- styx-task-contract:v1 -->

## Outcome

Define a versioned, deterministic, bounded, data-only interface exposing the
ratified C0.3 application-kernel behavior without selecting a programming
language, runtime, UI, transport, secure-session provider, storage engine or
product. Supply a machine-readable interface model/schema, hostile scenarios
and a validator. Do not implement a supported runtime adapter in this task.

The interface has two explicitly different uses:

1. **Conformance data plane.** A pure evaluator consumes canonical data and
   emits deterministic candidate observations/proposals. It is serializable so
   independent readers can be compared. Its output is never authority.
2. **Future trusted composition plane.** A supported adapter may call that
   evaluator only behind locally authenticated K/AP/RS boundaries. Public or
   caller-supplied conformance data, a structurally similar object or a passing
   result can never manufacture an accepted context, authority capability or
   durable commit.

This separation resolves the apparent conflict between a language-neutral
data interface and the unforgeable local capabilities required by O-07 and the
future persistence boundary. The contract must test both halves: deterministic
data agreement and non-substitutability for production authority.

## Candidate operation registry

The ratified Issue shall select a closed operation registry. The current
candidate is:

| Operation | Input | Output | Authority effect |
| --- | --- | --- | --- |
| `DESCRIBE_PROFILE` | exact profile identifier | immutable descriptor and capability requirements | none |
| `VALIDATE_TRANSCRIPT` | exact bounded genesis/event transcript plus declared profile | K-owned syntax/commitment/signature observation and operation-specific validated/rejected result | none |
| `EVALUATE_GENESIS` | bounded genesis transcript and exact raw O-03 ceremony tuple material, but no ceremony verdict/capability | closed observations plus either one proposed genesis snapshot or none | none |
| `REPLAY_CONTEXT` | proposed genesis snapshot, complete bounded candidate record set and explicit evidence set | deterministic AP/K projection, pending/quarantine sets and proposed context snapshot | none |
| `EVALUATE_CANDIDATE` | prior proposed snapshot, one candidate and explicit evidence-fact projection | terminal no-successor result or precommit proposal containing one complete successor | none |
| `EVALUATE_EVIDENCE_UPDATE` | prior proposed snapshot and one non-empty bounded monotone set of raw content/opening additions | closed observations and either one complete proposed application delta or none | none |

No v0 operation creates an authoritative context, commits state, publishes a
message, opens a session, restores durable truth, negotiates a version or
returns a raw secret. A future supported adapter owns those effects and may not
expose a public constructor for its local capabilities.

The exact operation names are candidate normative choices. Reviewers may
replace the registry before ratification; the executor may not alter it after
ratification.

## Closed interface objects

The Issue must define exact, additional-properties-forbidden schemas for:

- `ProfileDescriptor`: exact AP/K profile, version, signature suite, resource
  envelope, supported operations and required external boundaries;
- `TranscriptCandidate`: canonical bytes plus only the explicit framing/profile
  inputs already selected by C0.3;
- `EvidenceProjection`: only the complete purpose-separated raw content/opening
  material that O-04 deliberately keeps outside the signed K transcripts. All
  credential, predecessor, causal, fork and replay-dependency relations are
  regenerated from the complete transcript closure; caller copies are unknown
  fields. It contains no caller-supplied verification, authorization,
  admission, freshness or persistence verdict, and never a trusted capability;
- `ProposedGenesisSnapshot`: the exact deterministic semantic projection that
  would follow from a valid genesis plus the stated conformance facts. It is
  not an accepted context, a ceremony record or a local capability;
- `ProposedContextSnapshot`: canonical, bounded, immutable full raw replay
  closure plus a field-by-field derived projection. Every reuse replays the raw
  closure and compares the projection; neither the projection nor a digest is
  accepted as durable authority;
- operation-specific closed results: transcript validation, genesis proposal,
  whole-context replay and incremental precommit evaluation are distinct;
  candidate evaluation uses the exact O-10-derived three-axis relation;
  evidence-only evaluation uses a distinct closed additive/idempotent/rejected
  relation because it retains no new K event and can change multiple existing
  record outcomes; either operation emits at most one `ProposedApplicationDelta`;
- `ProposedApplicationDelta`: exactly one complete successor snapshot. The
  prior is the already revalidated operation input and is not copied into the
  result; no changed-subset, affected-namespace list, invariant list or digest
  competes with the successor. It contains no persistence container, proposal
  digest, commit binding or commit capability;

Byte strings use one canonical representation selected by the ratified
contract. Integer widths, field order, duplicate-key behavior, Unicode/text
policy and canonical JSON rules must be explicit. Floating point, host-native
paths, timestamps, environment values and implementation-specific handles are
forbidden in the conformance plane.

The canonical JSON used by this increment is evidence serialization only. Its
bytes, digest or successful validation are not a wire/storage encoding, durable
record identity, mutation binding or future O-11 authority. `SS-ADAPTER-0`
composes the application delta with SS state; O-11 and the authenticated RS
boundary later define the exact indivisible mutation container and its binding.

## Interface surface to specify

- profile/capability query with exact version and supported/unsupported result;
- evaluate the already-ratified genesis and authority context as a proposal;
  the data plane never consumes a serialized ceremony decision and never
  accepts the proposal as authoritative;
- evaluate a candidate application object against explicit prior state and
  supplied authenticated evidence;
- evaluate late raw content/opening material as a prior-bound monotone update;
  full replay alone is not an online mutation authority;
- return an operation-specific closed result; an incremental result is either
  terminal with no successor or a non-authoritative precommit proposal;
- commit nothing: the interface emits deterministic semantic data only; a
  later adapter constructs the combined APP/K/O-04/SS mutation and a separately
  ratified RS boundary owns its authenticated commit outcome;
- export only bounded, canonical proposed state/evidence required for the next
  evaluation; no UI/public projection, raw secret, clock, network or filesystem
  access.

For every accepted incremental candidate, `EVALUATE_CANDIDATE` must be
extensionally equivalent to `REPLAY_CONTEXT` over the same exact genesis,
prior record set, appended candidate and raw evidence set. Neither operation
may trust a digest, cached verdict or field copied from a prior proposed
snapshot: all security-relevant bindings are recomputed from the complete
bounded input. A mismatch is a fail-closed conformance defect, not an
implementation-specific optimization allowance.

For every accepted evidence-only update, `EVALUATE_EVIDENCE_UPDATE` must be
extensionally equivalent to `REPLAY_CONTEXT` over the same exact prior record
closure and the prior evidence plus only the validated additions. It may not
delete, replace or reframe prior material, introduce material for an unknown
event, or consume a caller-supplied completeness/verification verdict.

The candidate registry deliberately omits close/reset and public-state
projection from the serializable evaluator: there is no resource-owning handle
or product consumer in this plane. Handle lifecycle and redacted application
views belong to `SS-ADAPTER-0` and the later SDK contract. If review selects a
handle-bearing or public-projection core interface instead, the Issue must be
amended to define its unforgeability, ownership, locality, disclosure and
use-after-close semantics before execution.

Exact operation names and field layouts remain subject to the contract review;
the semantic obligations above are fixed by existing normative sources.

## Mandatory boundaries

- K verifies exact transcript/commitment/signature mechanics; AP owns
  application identity, authorization and causality; SS protects opaque bytes;
  RS owns authoritative durability; TR owns routing/delivery; PV owns workflow.
- Signature validity, key possession, SS membership/decryption, relay order,
  local time and storage presence never substitute for AP authority.
- O-08 limits apply before allocation/work/mutation.
- O-10 precedence and fail-closed results are preserved; internal exceptions
  are never public outcomes.
- Unsupported versions/topologies/capabilities are rejected, never negotiated
  or downgraded.
- APP-core v0 has no expected-reference input. `TRS-011` and `GRS-011` retain
  their schema tokens only as `RESERVED_UNREACHABLE_V0`; neither
  `REFERENCE_MISMATCH` nor `referenceVerification = REJECTED` may be emitted.
  Selecting such an input later requires reopening K, O-07 and INTERFACE.
- No implicit migration or legacy interpretation.

## Evidence

- schema/model consistency and exact source pins;
- provider-bound historical Issue/PR/exact-HEAD approvals and a live mutable
  scope-intersection audit;
- reference evaluator plus interface-only adapter with no expected-result
  oracle in inputs;
- exhaustive positive/negative corpus projection from existing C0.3 bytes;
- mutants for authority substitution, context confusion, wrong precedence,
  resource-check ordering, hidden mutation and result-string leakage;
- independent implementation task remains a separate dependent increment.

The existing C0.3 blind-kit builder, frozen oracle-free reader and clean-room
comparison are mandatory native evidence, not work to recreate. This increment
must:

- map every closed interface operation/object to the existing corpus families;
- prove that expected results remain absent from ordinary reader input;
- define the exact additional interface-only cases not covered by the existing
  transcript/K surface;
- preserve the frozen clean-room reader while supplying a new thin interface
  projection in the later conformance increment; and
- treat any disagreement as a normative adjudication, never as majority vote or
  automatic preference for the current Python model.

## Hostile requirement families

The executable inventory must include at least one distinct scenario and one
named mutant for every applicable item below:

1. unknown profile/version/operation and silent downgrade;
2. missing, duplicate, reordered and unknown object fields;
3. noncanonical integer, byte and JSON representations;
4. forged ceremony/authority/K evidence flags or structural lookalikes;
5. cross-context, cross-case, cross-profile and cross-purpose substitution;
6. signature/possession/SS-membership/decryption substituted for AP authority;
7. wrong O-10 precedence and exception-string promotion;
8. O-08 checks performed after allocation/work/mutation;
9. hidden mutation, partial mutation and state change on rejection;
10. replay/idempotence/retention conflation;
11. state snapshot accepted as durable or restored authority;
12. secret, absolute path, username, host, PID, timestamp or duration leakage;
13. unsupported operation accepted by inference;
14. omitted corpus family, reader, mutant, source pin or negative control.
15. incremental evaluation disagreeing with complete replay, including after
    rejection, pending, quarantine, fork and credential succession;
16. a cached digest, prior observation or proposed-snapshot field substituted
    for recomputation from the complete bounded input.

An aggregate scenario cannot satisfy distinct hostile constructions. Shared
setup is allowed, but each required atom has its own perturbation, assertion,
observation and detector.

The current pre-ratification candidate is mechanically finite:

- `APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json`: 87 property-bearing object
  schemas (82 direct definitions plus five inline/union-arm objects), 347
  properties and 25 named custom-keyword occurrences;
- `APP-CORE-IFACE-0-OWNERSHIP-CANDIDATE.json`: exact ownership/source coverage
  for all 87 object schemas and 347 properties;
- `APP-CORE-IFACE-0-STRUCTURAL-AXES-CANDIDATE.json`: 24 closed structural rule
  families reconciling every reachable schema assertion/applicator keyword into 1,553
  execution instances;
- `APP-CORE-IFACE-0-ONEOF-DISJOINTNESS-CANDIDATE.json`: all 101 pairwise arm
  relations for the 16 `oneOf` occurrences, including the nested root proof;
- `APP-CORE-IFACE-0-STRUCTURAL-WITNESS-SCHEMA-CANDIDATE.json`: the closed schema
  for the future 1,553-row carrier/perturbation/observation relation;
- `APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json`: one bounded ordered
  hostile-synthesis recipe for each of the 24 structural perturbation kinds;
- `APP-CORE-IFACE-0-POSITIVE-CARRIER-INVENTORY-SCHEMA-CANDIDATE.json`: the
  closed request/withheld-response carrier inventory shape and disclosure
  relation;
- `APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json` plus
  `derive_app_core_carrier_reachability.py`: the byte-identical derived
  12-root relation proving all 124 retained definitions, 87 object schemas and
  57 `oneOf` arms are reachable;
- `validate_app_core_contract_candidates.py`: one fail-closed package check for
  meta-schemas, root reachability, ownership, oneOf pairs, structural/semantic
  cardinalities, F13 equality against the pinned O-10 taxonomy and all manifest
  digests;
- `derive_interface_maxima.py`: symbolic twelve-root derivation of
  `OUTER_REQUEST_OCTETS = 138547674`, `OUTER_RESPONSE_OCTETS = 71096500` and
  `MAX_RETAINED_DECODED_OCTETS = 35300616`, with the maximizing-root
  breakdowns embedded in the manifest;
- `APP-CORE-IFACE-0-WITNESS-GENERATION-CONTRACT.md`: deterministic carrier
  selection, instance numbering, perturbation isolation and two-reader
  generation rules for the 87 seed rows and 1,553 witnesses;
- `APP-CORE-IFACE-0-SEMANTIC-CONSTRAINTS-CANDIDATE.json`: 84 closed semantic
  rule families;
- `APP-CORE-IFACE-0-INSTANCE-AXES-CANDIDATE.json`: the literal expansion axes
  for those 84 families;
- `APP-CORE-IFACE-0-EXECUTION-PHASES-CANDIDATE.json`: the closed partition
  between blind-input execution, post-output mutation and validator self-test;
- `APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json`: 23 content-axis,
  25 F13 primary/axis, ten fork/join-label, 16 authority-projection-dimension,
  11 graph-admission-dimension, 16 transcript reason/stage, 17 genesis
  reason/stage, 17 signature-verification path and 33 terminal-predicate rows; and
- `APP-CORE-IFACE-0-SEED-REGISTRY-SCHEMA-CANDIDATE.json`: the closed schema
  for the post-implementation 87-row canonical positive-carrier relation; and
- `APP-CORE-IFACE-0-ATOM-DERIVATION-CANDIDATE.md`: 24 structural and 84
  semantic rule families, deriving exactly 7,088 structural-plus-semantic
  execution instances after both axis registries are expanded.

These files are candidates, not authority. The executable Issue must bind their
exact bytes after independent review and human ratification. A family count,
suite-level PASS or reused aggregate result cannot substitute for exact
instance-set equality.

## Candidate repository scope

The candidate mutable path set is closed and literal:

```text
docs/protocol/styx-app-kernel-v0-decisions.md
docs/protocol/styx-app-kernel-v0-payload-commitment-analysis.md
docs/protocol/styx-app-kernel-v0-payload-state-falsification-report.md
docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md
docs/protocol/styx-app-kernel-v0-genesis-checkpoint-analysis.md
docs/protocol/styx-app-kernel-v0-genesis-checkpoint-falsification-report.md
docs/protocol/styx-app-kernel-v0-resource-envelope-analysis.md
docs/protocol/styx-app-kernel-v0-resource-envelope-falsification-report.md
docs/protocol/review/README.md
docs/protocol/review/styx-app-kernel-v0-review-model.json
docs/protocol/review/styx-app-kernel-v0-review-model.schema.json
tools/protocol-review-model/validate.py
tools/causal-flow-simulator/app_core_iface0/**
tools/causal-flow-simulator/c03/**
tools/causal-flow-simulator/o07/**
tools/causal-flow-simulator/o08/**
conformance/application-protocol/c03/**
tools/protocol-review-model/tests/**
```

The responsibility matrix, protocol-hardening plan, threat model, existing C0.3
corpus and clean-room tooling are read-only native dependencies. The interface
increment creates no new runtime trust-boundary actor and therefore does not
edit the threat model merely to restate a non-authoritative evidence plane.
No path under `styx-js/src/**`, `packages/**`, `conformance/**`, `.github/**`,
vendored code, runtime manifests or lockfiles is permitted. No deletion,
rename, copy, symlink, submodule or binary change is allowed.

If exact model synchronization needs a path not listed above, the Issue must be
amended and re-ratified before execution; the executor cannot infer scope.

The live contract on Issue #270 may modify only `REUSE.toml`,
`docs/architecture/decisions/ADR-0004-licensing-strategy.md` and
`docs/protocol/protocol-hardening-plan.md`. None is in this task's mutable path
set. Reading the hardening plan as a Base-pinned dependency creates no shared
write ownership. Any later task whose mutable paths intersect this set blocks
execution until the overlap is closed or an explicit integration owner is
ratified.

## Acceptance criteria

1. The provider-bound amendment comment, exact Base
   `e0af4e1e2173deb2481eabdb24d8622282b33455`, and every one of the 65 native
   source/corpus/tool rows are provider-bound before execution. The derived
   path set and relation digests equal the ratified native inventory.
   Historical provider authority also equals the ratified five-increment
   relation; a live re-fetch must prove zero mutable-path overlap with every
   currently open executable task contract.
2. The operation and object registries are closed, exact and versioned.
3. Every operation has one owner, complete preconditions, output invariants,
   failure behavior and explicit no-authority effect.
4. Every field is owned by K, AP or the non-authoritative interface projection;
   SS/RS/TR/PV values cannot enter by inference.
5. Unknown versions, operations, fields and capabilities fail closed without
   negotiation or migration.
6. O-08 bounds are checked before allocation/work/mutation in both readers.
7. O-10 precedence, stage, mutation and closed results match the ratified
   taxonomy exactly. Deterministic O-08 S6 accounting runs only on the
   would-be `APPLIED` path; no other primary acquires an S6 path. The pure core
   stages but never publishes a successor-bearing primary. A separately
   ratified adapter/RS lifecycle publishes that exact recomputed primary and
   installs the complete successor only after exact-bound `COMMITTED`, without
   inventing or reordering an O-10 primary (`OPEN-F14`).
8. The exact ratified result relation copies O-10 `mutation` unchanged and
   separately fixes AP-transition effect, K-evidence retention and
   complete-successor presence for all 25 O-10 primaries. No implementation may
   infer one axis from another, and auxiliary evidence cannot upgrade any axis.
   `STALE_EVIDENCE` remains reserved and structurally unreachable in v0; making
   it reachable requires explicit capacity accounting and renewed
   falsification. This criterion remains blocked by `OPEN-F13` until the exact
   relation is independently re-reviewed and human-ratified.
9. A serialized genesis snapshot, context snapshot, result or proposal cannot satisfy an adapter
   authority/commit capability in any model or test helper; no hash of the
   evidence serialization is accepted as a future O-11/RS binding.
10. Existing C0.3 corpus bytes, clean-room reader and historical evidence remain
    byte-identical.
11. The hostile inventory is closed and equals the ratified 7,088-instance
    relation; every instance has a distinct required perturbation, assertion,
    observation and detector, all required mutants are killed, and all negative
    controls fail for the intended reason. A single aggregate pass cannot
    satisfy multiple quantified instances.
12. Python and independent JavaScript readers agree on every interface case;
    the later frozen third-reader projection is specified but not implemented
    in this increment.
13. Canonical reports are deterministic and free of repository/runtime/secret
    provenance.
14. Two distinct clean exact-HEAD worktrees regenerate byte-identical evidence.
15. All applicable repository tests/checks pass without unexplained skip.
16. Independent exact-final review has no unresolved BLOCKER/HIGH/MEDIUM.
17. `manexada` approves the exact final HEAD and `maverde73` separately approves
    Ready/merge through ForgeRelay.
18. The final capability registry still reports no supported adapter, durable
    persistence, SDK, delivery, product, demo, deployment or sensitive use.

## Required evidence commands

The final Issue shall provide literal commands, exact tool versions and a
single fail-closed final gate. At minimum it runs:

- interface schema/model unit tests;
- closed hostile-inventory validation;
- reference and independent-JavaScript cross-runtime comparison;
- source-mutant kill run;
- the complete existing C0.3 validator/replay/mutation/clean-room suites;
- protocol review-model validation;
- documentation claims/translation checks, REUSE and `git diff --check`;
- a two-clean-checkout regeneration/comparison gate; and
- exact live CI/provider verification.

Silence, timeout, empty output, missing family or unexpectedly skipped check is
failure.

## Non-goals

No SS corpus/adapter, persistence, SDK ergonomics, delivery, browser API,
Flegias workflow, compliance, product or sensitive-use claim.

No production ceremony mechanism, application profile policy, recovery,
physical-time semantics, destructive effect, profile succession, migration,
wire/storage encoding, mutation-container identity or stable public error
strings are selected.

## Human gates

Ratified exact Issue, exact-final independent review, exact-HEAD human approval,
Ready and merge are all distinct provider-bound events.

The contract review must explicitly adjudicate the three independent planes:
exact O-10 classification, APP candidate-state effect and adapter/RS commit
lifecycle. It must also adjudicate the operation-scoped F16 rejection/capacity
tokens and authoritative-prior obligation. A review that checks only schema
syntax or current implementation compatibility is insufficient.

## Rollback and residual risks

Before merge, close the Draft PR and remove only its dedicated branch/worktree.
After merge, revert the single increment. No persisted data rollback exists
because the task creates no production state or format.

Agreement among the reference, JavaScript and later clean-room reader can still
share a mistaken normative interpretation. A language-neutral schema can still
be awkward or unsafe to expose as an SDK. The interface proves bounded semantic
agreement only; it does not prove cryptography, runtime isolation, persistence,
transport, product safety or regulatory compliance.
