# Styx application kernel v0 — bounded resource-envelope analysis

Status: bounded O-08 decision for Issue #250 after replacement candidate
selection, final-gate response-shape correction, two-clean-checkout evidence,
independent exact-HEAD review and technical human approval. This document is
normative only for the transcript-only C0.3 entry profile. It is not a product,
browser, mobile, transport, secure-session or persistence profile.

## 1. Remediation identity

- Base: `ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3`.
- Superseded selection HEAD: `16c379fba756516edb173ab3ba722bbf97bfacab`.
- Replacement selection HEAD: `613427c857d8f1f2b80d16b28b2ca9112cf6e96b`.
- Candidate-set digest:
  `12f9e068ca02b965062859fc98d922722e44909efbe819771ab7e3d5aaba040f`.
- Replacement selected candidate: `balanced`; canonical envelope digest:
  `317206449117fcad351f0338c719085a8eb623605d7768327e27d26fd48256fd`.
- Replacement selection authority: immutable `maverde73` ForgeRelay decision
  in GitHub Issue-comment object `5431393925` at
  `https://api.github.com/repos/styx-secure/styx/issues/comments/5431393925`.
- Deterministic comparison digest:
  `c9d3689041f09589df55165c2bdc48deffcff1b974daac8165f103b6601cbfe8`.

`tools/causal-flow-simulator/o08/resource-envelope.candidate.json` materializes
that exact replacement selection. It remains conformance evidence only and is
not an ambient wire, authorization, checkpoint or storage authority.

## 2. Decision

Three strictly increasing candidates (`conservative`, `balanced`, `expansive`)
were measured five cold and five warm times under two declared capability
profiles. Exact-width, explicit-zero and structurally derived entries are the
only equal values. The replacement decision independently selected `balanced`
because both declared capability profiles pass its deterministic structural
gates while it provides materially more operating margin than `conservative`;
`expansive` is unsupported by the minimal capability profile.

Deterministic structural evidence is normative selection evidence. Host CPU,
wall-time and RSS observations are non-normative operational comparisons only;
they are recorded after the selection HEAD is frozen and cannot make an
incoherent candidate pass.

## 3. Selected `balanced` entry dimensions

Every entry below has an exact unit, scope, stage list, integer range,
pre-protected-work enforcement point, comparison direction and reopen predicate
in a materialized canonical record. A maximum admits `0..selected`; four
capability inputs require `observed >= selected`; the capability-key declaration
requires exact equality to its four-key closed set; chunk size requires closed-set
membership; and the two unsupported dimensions require exact zero. Negative,
overflow, duplicate, missing and unknown values fail closed.

| Family | Selected `balanced` C0.3 entries |
| --- | --- |
| Canonical framing | `FRAMING_OBJECT_OCTETS=8192`; `FRAMING_CONTEXT_OCTETS=16384`; `AP_TRANSITION_BLOCK_OCTETS=4096`; `REFERENCE_OCTETS=32`; `TEXT_FIELD_OCTETS=0`; `SEQUENCE_VALUE=4095` (derived from lifetime); `INTEGER_FIELD_RANGE` is evidence-only with no selected value |
| Causal admission | `EVENTS_ADMITTED=64`; `EVIDENCE_PER_CREDENTIAL=16`; `CONTEXT_LIFETIME_EVENTS=4096`; `PARENTS_PER_EVENT=8`; `ACTIVE_FRONTIER=16`; `GRAPH_DEPTH=256`; `ANCESTRY_RELATIONS=32768`; `PENDING_ROOTS=16`; `PENDING_DESCENDANTS=128`; `HALTED_REPLAY_SPAN=256` |
| Credential and authority | `CREDENTIALS=16`; `LINEAGE_DEPTH=8`; `ALIASES_PER_CREDENTIAL=4`; `CONTROL_EVENTS=12`; `FORK_SLOTS=3`; `SIBLINGS_PER_FORK=3`; `AUTHORITY_CONCURRENT_CONTROLS=3`; `AUTHORITY_STATES=256`; `AUTHORITY_TRANSITIONS=512`; `ORDINARY_PREFIX_QUERIES=64`; `REPLAYED_EVENT_WORK=65536`; evidence-only `AUTHORITY_CONTENTION_BOUND=B4(P)` is derived per admitted trace and is not selected |
| Payload commitment | `CONTENT_EXACT_OCTETS=262144`; `AP_EXPANDED_CONTENT_OCTETS=131072`; `CHUNK_OCTETS={16384}`; `CHUNKS_PER_CONTENT=64`; `TREE_FAN_OUT=2`; `COMMITMENT_VALUE_OCTETS=32`; `RANDOMIZER_OCTETS=32`; `PART_SYMBOL_OCTETS=32`; `RECORDS=128`; `REMOVAL_DIRECTIVES=32` |
| Genesis/checkpoint | `CHECKPOINT_REFERENCES=0`; `GENESIS_ATTEMPTS=4`; `GENESIS_BODY_OCTETS=8192`; `GENESIS_POLICY_OCTETS=4096` |
| Signature verification | `SIGNATURE_ATTEMPTS=64`; `SIGNATURE_OCTETS=64`; `VERIFICATION_KEY_OCTETS=32` |
| Durability/runtime capability | `DURABLE_REQUIRED_OCTETS=4194304`; `DURABLE_RECORDS=512`; `CUSTODY_REDUNDANCY=1`; `TRANSIENT_MEMORY_CAPABILITY=134217728` |
| Activation/profile | `ACTIVATION_CAPABILITY_SET={DURABLE_REQUIRED_OCTETS,DURABLE_RECORDS,CUSTODY_REDUNDANCY,TRANSIENT_MEMORY_CAPABILITY}` (derived cardinality 4); `PROFILE_VERSION_SKEW=0`; `ACTORS=8`; `ROLE_ASSIGNMENTS=32`; `PHYSICAL_TIME_SKEW=0` |

`CUSTODY_REDUNDANCY=1`, the exact-width values and unsupported zeros are frozen inputs, so they remain
equal across all three compared candidates. They are still three explicit
candidate records; equality records a frozen dependency rather than a missing
alternative.

## 4. Growth, enforcement and recovery

The 28 pinned source anchors assign every dimension to one of 12 source
families. The 66 entry dimension×stage rows are exhaustive:
`S0=9`, `S1=0`, `S3=21`, `S4=10`, `S5=16`, `S6=10`.

- structural octet/count limits reject the current object before allocation,
  slicing, hashing, signature work or commitment materialization;
- graph totals reject before graph/frontier/closure mutation and return whole
  context capacity exhaustion or dependency deferral as appropriate;
- the exact maximum antichain of the admitted C0.2j authority poset is checked
  before DP state insertion; authority width rejects before DP state insertion,
  transition and replay totals reject before the protected work they bound, and
  the state total rejects at the frontier boundary before result use; every case
  returns `AUTHORITY_PROJECTION_UNAVAILABLE`, never an empty or partial
  authority set;
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

The selected covered-topology tuple means the complete selected structural
tuple, including `AUTHORITY_STATES`, `AUTHORITY_TRANSITIONS` and
`REPLAYED_EVENT_WORK`; it is not the width-only `COVERED` classification used
by selection measurements. Reopen O-08 if complete non-stale evidence within
every selected entry dimension other than the three projection-work ceilings,
and inside the proved region, makes the whole authority projection unavailable;
if any K-admitted history has reachable states above `B4(P)` or transitions
above `width(P) * B4(P)`, even when the fold succeeds; if the evidence poset
differs from the fold poset; if Python and JavaScript disagree or understate
`B4(P)`; if the C0.2j state key, predecessor relation, permanent-termination
semantics or lineage closure changes; or if a selected dimension's meaning,
scope, unit, bound or recovery changes. Failure to reject an outside-width trace
before DP state insertion also reopens O-08. Grey-zone exhaustion alone does
not reopen it because availability is not claimed there.

Issue-comment `5432143151` records a bounded procedural exception for the
incomplete Section 8.1 AST assignment guard. Protocol governance/agent-
enforcement owns the debt. Before any later review-model or validator module-
assignment change, a separately scoped human-approved task must implement the
full AST allowlist and explicit O-14-removal negative test; otherwise that
change fails closed and reopens this disposition.

This decision does not claim a production ceremony, durable storage, physical
eviction handling, recovery, freshness, rollback detection, finality, delivery,
transport privacy, secure-session capacity, N-party support, browser/mobile
suitability, product readiness or sensitive-use fitness.
