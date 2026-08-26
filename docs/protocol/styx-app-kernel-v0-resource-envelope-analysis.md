# Styx application kernel v0 — bounded resource-envelope analysis

Status: selected O-08 conformance envelope for Issue #250. This document is
normative only for the transcript-only C0.3 entry profile. It is not a product,
browser, mobile, transport, secure-session or persistence profile.

## 1. Selection identity

- Base: `ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3`.
- Selection HEAD: `aed184aa3424225c343fbadfd1a7031a1c7e925a`.
- Candidate set SHA-256:
  `5bca7bf02e6ed2d6ed7fd4621bc60ffe732f08aabd396dcd36aa017d889fb659`.
- Selected candidate: `conservative`.
- Selected envelope digest:
  `de5032e66efdad9eefb0af4b7a113510368c9f02b8790361a053a509b4898daa`.
- ForgeRelay/GitHub provider object: Issue #250 comment `5425570807`.

The canonical record is
`tools/causal-flow-simulator/o08/resource-envelope.candidate.json`. Its digest
identifies the candidate values; it is conformance evidence only and is not an
ambient wire, authorization, checkpoint or storage authority.

## 2. Decision

Three monotone candidates (`conservative`, `balanced`, `expansive`) were
measured five cold and five warm times under two declared capability profiles.
All six measurement executions completed. `conservative` activated under both
capability profiles. `balanced` and `expansive` activated under the balanced
profile but failed closed as `PROFILE_ACTIVATION_UNSUPPORTED` under the
conservative profile because their declared custody requirement exceeded that
profile. Selecting `conservative` therefore preserves the widest declared
runtime availability without relaxing a semantic gate or inflating a limit.

Host measurements are selection evidence, not normative thresholds. On the
selection host their p95 CPU time was below 0.9 ms, p95 wall time below 0.9 ms,
peak process RSS below 23 MiB and retained report output below 14 KiB for all
six runs. Those numbers neither claim production performance nor replace the
selected capability inputs.

## 3. Selected entry dimensions

Every entry below has an exact unit, scope, stage list, integer range,
pre-protected-work enforcement point, comparison direction and reopen predicate
in the canonical record. A maximum admits `0..selected`; a capability input
requires `observed >= selected`; the two unsupported dimensions require exact
zero. Negative, overflow, duplicate, missing and unknown values fail closed.

| Family | Selected C0.3 entries |
| --- | --- |
| Canonical framing | `FRAMING_OBJECT_OCTETS=4096`; `FRAMING_CONTEXT_OCTETS=8192`; `AP_TRANSITION_BLOCK_OCTETS=2048`; `REFERENCE_OCTETS=32`; `TEXT_FIELD_OCTETS=0`; `INTEGER_FIELD_RANGE=4294967295`; `SEQUENCE_VALUE=9007199254740991` |
| Causal admission | `EVENTS_ADMITTED=32`; `EVIDENCE_PER_CREDENTIAL=8`; `CONTEXT_LIFETIME_EVENTS=1024`; `PARENTS_PER_EVENT=4`; `ACTIVE_FRONTIER=8`; `GRAPH_DEPTH=64`; `ANCESTRY_RELATIONS=1024`; `PENDING_ROOTS=8`; `PENDING_DESCENDANTS=32`; `HALTED_REPLAY_SPAN=64` |
| Credential and authority | `CREDENTIALS=8`; `LINEAGE_DEPTH=4`; `ALIASES_PER_CREDENTIAL=2`; `CONTROL_EVENTS=16`; `FORK_SLOTS=4`; `SIBLINGS_PER_FORK=2`; `AUTHORITY_STATES=128`; `AUTHORITY_TRANSITIONS=512`; `ORDINARY_PREFIX_QUERIES=16`; `REPLAYED_EVENT_WORK=4096` |
| Payload commitment | `CONTENT_EXACT_OCTETS=65536`; `AP_EXPANDED_CONTENT_OCTETS=32768`; `CHUNK_OCTETS=4096`; `CHUNKS_PER_CONTENT=16`; `TREE_FAN_OUT=2`; `COMMITMENT_VALUE_OCTETS=32`; `RANDOMIZER_OCTETS=32`; `PART_SYMBOL_OCTETS=32`; `RECORDS=32`; `REMOVAL_DIRECTIVES=8` |
| Genesis/checkpoint | `CHECKPOINT_REFERENCES=0`; `GENESIS_ATTEMPTS=2`; `GENESIS_BODY_OCTETS=4096`; `GENESIS_POLICY_OCTETS=2048` |
| Signature verification | `SIGNATURE_ATTEMPTS=16`; `SIGNATURE_OCTETS=64`; `VERIFICATION_KEY_OCTETS=32` |
| Durability/runtime capability | `DURABLE_REQUIRED_OCTETS=1048576`; `DURABLE_RECORDS=128`; `CUSTODY_REDUNDANCY=1`; `TRANSIENT_MEMORY_CAPABILITY=67108864` |
| Activation/profile | `ACTIVATION_CAPABILITY_SET=5`; `PROFILE_VERSION_SKEW=0`; `ACTORS=2`; `ROLE_ASSIGNMENTS=4`; `PHYSICAL_TIME_SKEW=0` |

The exact-width values and unsupported zeros are frozen inputs, so they remain
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
- authority totals reject before Pass0/state insertion or replay and return
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
dimensions remain `POST_C03_LAYER_PROFILE`. Three factorial/exploration values
remain `EVIDENCE_ONLY`. Neither class can affect C0.3 semantic validity,
authority, absence, removal or the selected envelope without the separately
ratified gate-amendment process.

## 6. Reopen predicates and non-claims

Reopen O-08 if a selected dimension's semantics, unit, scope, stage ownership,
safe recovery, fixed width, capability assumption or bound changes; if an
under-bound adversarial trace exceeds the declared capability; if the source
inventory gains or merges a dimension; or if independent oracles disagree.

This decision does not claim a production ceremony, durable storage, physical
eviction handling, recovery, freshness, rollback detection, finality, delivery,
transport privacy, secure-session capacity, N-party support, browser/mobile
suitability, product readiness or sensitive-use fitness.
