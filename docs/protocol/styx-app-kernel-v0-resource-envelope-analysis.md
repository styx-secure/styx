# Styx application kernel v0 — bounded resource-envelope analysis

Status: O-08 candidate selection completed for Issue #250; final exact-HEAD
evidence, independent review and human gates remain pending. This document is
normative only for the transcript-only C0.3 entry profile. It is not a product,
browser, mobile, transport, secure-session or persistence profile.

## 1. Remediation identity

- Base: `ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3`.
- Selection HEAD: `16c379fba756516edb173ab3ba722bbf97bfacab`.
- Candidate-set digest:
  `12f9e068ca02b965062859fc98d922722e44909efbe819771ab7e3d5aaba040f`.
- Selected candidate: `balanced`; canonical envelope digest:
  `317206449117fcad351f0338c719085a8eb623605d7768327e27d26fd48256fd`.
- Selection authority: immutable `maverde73` ForgeRelay decision in GitHub
  Issue-comment object `5431295833` at
  `https://api.github.com/repos/styx-secure/styx/issues/comments/5431295833`.
- Deterministic comparison digest:
  `ec3a5ceee0e1e9e19e04e226604550fe8081fc4c70b5eddaa0883b225431cb9e`.

`tools/causal-flow-simulator/o08/resource-envelope.candidate.json` materializes
that exact selected envelope. It remains conformance evidence only and is not
an ambient wire, authorization, checkpoint or storage authority.

## 2. Decision

Three strictly increasing candidates (`conservative`, `balanced`, `expansive`)
were measured five cold and five warm times under two declared capability
profiles. Exact-width, explicit-zero and structurally derived entries are the
only equal values. `balanced` was selected because both declared capability
profiles pass its deterministic structural gates while it provides materially
more operating margin than `conservative`; `expansive` is unsupported by the
minimal capability profile.

Deterministic structural evidence is normative selection evidence. Host CPU,
wall-time and RSS observations are non-normative operational comparisons only;
they are recorded after the selection HEAD is frozen and cannot make an
incoherent candidate pass.

## 3. Conservative candidate entry dimensions

Every entry below has an exact unit, scope, stage list, integer range,
pre-protected-work enforcement point, comparison direction and reopen predicate
in a materialized canonical record. A maximum admits `0..selected`; four
capability inputs require `observed >= selected`; the capability-key declaration
requires exact equality to its four-key closed set; chunk size requires closed-set
membership; and the two unsupported dimensions require exact zero. Negative,
overflow, duplicate, missing and unknown values fail closed.

| Family | Conservative candidate C0.3 entries |
| --- | --- |
| Canonical framing | `FRAMING_OBJECT_OCTETS=4096`; `FRAMING_CONTEXT_OCTETS=8192`; `AP_TRANSITION_BLOCK_OCTETS=2048`; `REFERENCE_OCTETS=32`; `TEXT_FIELD_OCTETS=0`; `SEQUENCE_VALUE=1023` (derived from lifetime); `INTEGER_FIELD_RANGE` is evidence-only with no selected value |
| Causal admission | `EVENTS_ADMITTED=32`; `EVIDENCE_PER_CREDENTIAL=8`; `CONTEXT_LIFETIME_EVENTS=1024`; `PARENTS_PER_EVENT=4`; `ACTIVE_FRONTIER=8`; `GRAPH_DEPTH=64`; `ANCESTRY_RELATIONS=4096`; `PENDING_ROOTS=8`; `PENDING_DESCENDANTS=32`; `HALTED_REPLAY_SPAN=64` |
| Credential and authority | `CREDENTIALS=8`; `LINEAGE_DEPTH=4`; `ALIASES_PER_CREDENTIAL=2`; `CONTROL_EVENTS=8`; `FORK_SLOTS=2`; `SIBLINGS_PER_FORK=2`; `AUTHORITY_CONCURRENT_CONTROLS=2`; `AUTHORITY_STATES=32`; `AUTHORITY_TRANSITIONS=64`; `ORDINARY_PREFIX_QUERIES=16`; `REPLAYED_EVENT_WORK=4096`; evidence-only `AUTHORITY_CONTENTION_BOUND=B4(P)` is derived per admitted trace and is not selected |
| Payload commitment | `CONTENT_EXACT_OCTETS=65536`; `AP_EXPANDED_CONTENT_OCTETS=32768`; `CHUNK_OCTETS={4096}`; `CHUNKS_PER_CONTENT=16`; `TREE_FAN_OUT=2`; `COMMITMENT_VALUE_OCTETS=32`; `RANDOMIZER_OCTETS=32`; `PART_SYMBOL_OCTETS=32`; `RECORDS=32`; `REMOVAL_DIRECTIVES=8` |
| Genesis/checkpoint | `CHECKPOINT_REFERENCES=0`; `GENESIS_ATTEMPTS=2`; `GENESIS_BODY_OCTETS=4096`; `GENESIS_POLICY_OCTETS=2048` |
| Signature verification | `SIGNATURE_ATTEMPTS=16`; `SIGNATURE_OCTETS=64`; `VERIFICATION_KEY_OCTETS=32` |
| Durability/runtime capability | `DURABLE_REQUIRED_OCTETS=1048576`; `DURABLE_RECORDS=128`; `CUSTODY_REDUNDANCY=1`; `TRANSIENT_MEMORY_CAPABILITY=67108864` |
| Activation/profile | `ACTIVATION_CAPABILITY_SET={DURABLE_REQUIRED_OCTETS,DURABLE_RECORDS,CUSTODY_REDUNDANCY,TRANSIENT_MEMORY_CAPABILITY}` (derived cardinality 4); `PROFILE_VERSION_SKEW=0`; `ACTORS=2`; `ROLE_ASSIGNMENTS=4`; `PHYSICAL_TIME_SKEW=0` |

`CUSTODY_REDUNDANCY=1`, the exact-width values and unsupported zeros are frozen inputs, so they remain
equal across all three compared candidates. They are still three explicit
candidate records; equality records a frozen dependency rather than a missing
alternative.

## 4. Growth, enforcement and recovery

The 28 pinned source anchors assign every dimension to one of 12 source
families. The 66 entry dimension×stage rows are exhaustive:
`S0=9`, `S1=0`, `S3=22`, `S4=10`, `S5=15`, `S6=10`.

- structural octet/count limits reject the current object before allocation,
  slicing, hashing, signature work or commitment materialization;
- graph totals reject before graph/frontier/closure mutation and return whole
  context capacity exhaustion or dependency deferral as appropriate;
- the exact maximum antichain of the admitted C0.2j authority poset is checked
  before DP state insertion; authority width/state/transition/replay totals
  reject before Pass0/state insertion or replay and return
  `AUTHORITY_PROJECTION_UNAVAILABLE`, never an empty or partial authority set;
- capability inputs reject profile activation before context creation;
- deterministic S6 capacity accounting preserves all prior authoritative state
  and does not claim persistence I/O, physical custody or recovery;
- unsupported checkpoint and physical-time inputs are exact zero and cannot be
  negotiated or silently downgraded.

O-10 owns stable public/local codes. O-08 transfers only safe semantic recovery
classes and does not collapse cases whose safe recovery differs.

## 5. Non-entry dimensions

Eleven transport, delivery, secure-session and renewable operational-budget
dimensions remain `POST_C03_LAYER_PROFILE`. Five representability/exploration values
remain `EVIDENCE_ONLY`. Neither class can affect C0.3 semantic validity,
authority, absence, removal or the selected envelope without the separately
ratified gate-amendment process.

For every admitted authority trace, the evidence layer computes exact `B4(P)`
and requires `reachable_states <= B4(P)` and
`authority_transitions <= width(P) * B4(P)`. A trace is in the proved region
only when those two derived ceilings fit inside the selected state and
transition limits. Otherwise the unchanged bounded fold runs in the explicit
grey zone and fails closed on exhaustion. Fresh replay work additionally
includes both initial admission and authority/prefix work:
`EVENTS_ADMITTED + AUTHORITY_TRANSITIONS * (1 + ORDINARY_PREFIX_QUERIES)`.

## 6. Reopen predicates and non-claims

Reopen O-08 if a trace inside the selected covered-topology tuple exhausts the
whole authority projection; if a trace outside that topology is not rejected
before DP state insertion; if a selected dimension's semantics, unit, scope,
stage ownership, safe recovery, capability assumption or bound changes; if the
source inventory gains or merges a dimension; or if independent oracles disagree.

This decision does not claim a production ceremony, durable storage, physical
eviction handling, recovery, freshness, rollback detection, finality, delivery,
transport privacy, secure-session capacity, N-party support, browser/mobile
suitability, product readiness or sensitive-use fitness.
