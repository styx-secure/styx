# Styx application protocol v0: causal topology analysis

Status: C0.2c normative decision analysis for O-01, O-05 and O-06

Base: `75a82ac0748c0621df40e59035f7bb253cdd5957`

Issue: [#211](https://github.com/styx-secure/styx/issues/211)

## 1. Scope and non-claims

This document selects application-event causality, clock placement and
identifier roles. It does not select transcript bytes, a hash or signature
algorithm, wire/storage encoding, payload detachment, complete genesis,
numeric profile limits, error codes or a persistence implementation.

The rules constrain a future language-neutral specification. Current Dart,
JavaScript and Phase B code do not conform merely because this document exists.
The analysis does not prove executable convergence, fork prevention, global
rollback detection, security, anonymity, interoperability, audit coverage or
production readiness. Current builds remain unsuitable for sensitive use.

## 2. Evidence and provenance

Normative repository inputs are:

- [the decision registry](styx-app-kernel-v0-decisions.md), especially K-01
  through K-10 and O-01/O-05/O-06;
- [the responsibility matrix](styx-app-kernel-v0-responsibility-matrix.md),
  especially `OB-K01`, `OB-K05` through `OB-K07`, `OB-K12` through `OB-K14`,
  `OB-AP02` and `OB-AP04`;
- [the identity/context decision](styx-app-kernel-v0-identity-context-analysis.md),
  especially endpoint credentials, rotation/revocation and the context tuple;
- [the threat model](../security/STYX-THREAT-MODEL.md); and
- [the application capability model](../platform/application-capability-model.md)
  §§5.3, 5.5, 5.10, 5.13 and 5.15.

The C0.1 characterization and retained `PRIV-01` through `PRIV-04` evidence
show that current counters are fixed to two parties, can wrap, and are not all
authenticated. They also show that current comparator equality and HLC text are
not safe protocol rules. The isolated Phase B2.5c retained-history graph is
evidence that exact-parent replay and deterministic branch selection can be
implemented, not authority for application topology.

External primary sources are used only for comparison:

- Parker et al., [*Detection of Mutual Inconsistency in Distributed
  Systems*](https://escholarship.org/uc/item/04h0568c)
  (1983), introduced version-vector inconsistency detection;
- Preguiça et al., [*Dotted Version Vectors: Efficient Causality Tracking for
  Distributed Key-Value Stores*](https://gsd.di.uminho.pt/members/vff/dotted-version-vectors-2012.pdf)
  (2012), analyzes accurate causality tracking and vector-scaling/pruning
  tradeoffs;
- Sanjuán et al., [*Merkle-CRDTs: Merkle-DAGs meet
  CRDTs*](https://arxiv.org/abs/2004.00107) (2020), analyzes content-addressed
  DAG replication; and
- Li et al., [*Secure Untrusted Data Repository*
  (SUNDR)](https://www.cs.princeton.edu/courses/archive/fall11/cos518/papers/sundr.pdf)
  (2004), establishes the limit that an untrusted server can conceal a branch
  until clients exchange later evidence; it does not give Styx global rollback
  detection.

These works do not define Styx authorization, retention or application policy.

## 3. Semantic vocabulary

- **Event:** one authoritative, context-bound application object signed by one
  O-02 endpoint credential.
- **Author endpoint:** one device/runtime instance exercising one context-local
  O-02 credential under authenticated AP authority; it is not an account,
  person, MLS member, Nostr key or transport sender by implication.
- **Event reference:** a domain-separated digest deterministically derived from
  the validated canonical signed transcript, excluding the signature bytes and
  any carried convenience identifier.
- **Direct author predecessor:** the prior event reference claimed for the same
  context-local credential.
- **Causal parent:** an authenticated event reference, distinct from the direct
  author-predecessor field, that the producer declares as an immediate
  dependency.
- **Frontier:** the set of maximal validated events known to an honest producer.
  The causal-parent field carries that set after removing the separately
  encoded direct author predecessor. It is an antichain: no member is an
  ancestor of another.
- **Happens-before:** the irreflexive transitive closure of authenticated parent
  and direct-author-predecessor edges. Equality is handled as duplication, not
  causality.
- **Concurrent:** neither event is reachable from the other.
- **Duplicate:** the same validated event reference is observed again.
- **Replay:** a duplicate or previously consumed semantic operation presented
  again at an interface where repetition is not permitted.
- **Author equivocation/fork:** two distinct valid events for one credential use
  the same author sequence, or claim the same direct author predecessor.
- **Missing parent:** a referenced event is not locally available.
- **Deferred/orphan:** a structurally bounded event whose required parent is
  absent within the recoverable horizon; it causes no application transition.
- **Stale:** required evidence is provably before the retained checkpoint and is
  not supplied by an accepted checkpoint proof.
- **Checkpoint/compaction boundary:** an authenticated transition that commits
  the exact evidence retained for future validation while allowing older
  material to become unavailable under a later retention design.
- **Affected replay boundary:** the first position where the canonical order
  over a prior validated set differs from the order over an expanded validated
  set, or the end of the prior order when it remains an exact prefix. It names
  the earliest replay point, not a checkpoint or finality claim. A prefix is
  reusable only when every per-event `K → AP` handoff in it is byte-identical
  to fresh full replay over the expanded set. The v0 handoff rule below makes
  that condition prefix-local; a future handoff change that violates it must
  move the boundary earlier rather than reuse stale AP input.

A signed causal claim proves what the credential asserted. It cannot prove that
a malicious endpoint truthfully disclosed every event it had observed.

## 4. Candidate constructions

### 4.1 Fixed or sparse version vector

Each event carries a map from participant identifier to counter. Component-wise
comparison classifies causality and concurrency.

This is compact for a stable small set and supports offline comparison without
fetching parents. It scales with represented participants, requires stable
component identity across credential rotation, exposes participant membership,
and cannot by itself authenticate which concrete event a counter denotes. Safe
pruning requires additional membership and retirement rules. The legacy fixed
two-party vector and any counter sum remain rejected. This candidate is
**REJECTED** as the kernel topology.

### 4.2 Dotted version vector

A causal context vector is paired with a dot identifying the new update. It
distinguishes concurrent siblings more accurately than lossy client vectors and
can bound growth to a configured replica set in its intended store model.

For Styx, the replica set is not the same as endpoint credentials or application
actors. Dynamic devices, credential rotation and case-ephemeral profiles still
need stable component allocation and retirement. The vector exposes the active
component set and does not retain concrete authenticated parent evidence without
another structure. It is useful prior art but **REJECTED** as the kernel
topology.

### 4.3 Authenticated parent-reference DAG only

Each event signs a set of parent event references. Reachability defines
causality, and content addressing detects substituted parents.

This supports dynamic participants, offline branches and child-before-parent
recovery without a global component registry. However, a DAG alone does not
efficiently detect one credential producing two successors or skipping its own
history. A malicious producer can also inflate a parent set or create many
sibling tips. This candidate is **REJECTED** alone but retained as the shared
causal component.

### 4.4 Per-author chain plus authenticated causal frontier

Each event authenticates:

1. its O-03 context tuple and O-02 credential identifier;
2. a non-wrapping per-credential author sequence that is zero for the first
   event and advances by exactly one thereafter;
3. an absent direct author predecessor for the credential's first event, or the
   exact prior event reference thereafter; and
4. a separate canonical, duplicate-free, profile-bounded antichain of maximal
   causal-parent references.

The author chain detects gaps and equivocation per endpoint. The parent frontier
captures cross-author causality without enumerating every participant. Event
references authenticate concrete predecessors. Candidate 4 is **SELECTED**.

The selected model does not prevent a malicious author from omitting another
author's event and thereby asserting concurrency. Honest producers include
their complete validated maximal frontier. Applications that require stronger
freshness or multi-party approval must add AP policy evidence; the kernel does
not invent consensus.

### 4.5 Trusted sequencer, relay order, blockchain or wall-clock baseline

A global sequencer, relay receipt, blockchain order or timestamp could impose a
total order, but adds an authority/availability dependency, does not make a
business conflict valid and may expose metadata. It is **REJECTED** as kernel
causality. An application profile may separately require an external witness,
timestamp or consensus receipt for a named policy purpose; that receipt cannot
rewrite the kernel graph.

## 5. Comparison

| Dimension | Version vector | Dotted vector | Parent DAG | Chain + frontier |
| --- | --- | --- | --- | --- |
| Self-authenticated causal claim | Signed counters, not concrete events | Signed context/dot, partial event identity | Signed concrete parents | Signed concrete parents and author link |
| Concrete authenticated predecessor | No | Dot only | Yes | Yes |
| Dynamic endpoint credentials | Component churn | Replica registry | Natural | Natural |
| Separate devices / multi-device | Stable component allocation needed | Stable replica allocation needed | Natural distinct authors | Natural distinct credential chains |
| Per-author gap/fork evidence | Counter ambiguity | Dot-aware | Costly graph search | Explicit sequence + predecessor |
| Offline concurrency | Yes | Yes | Yes | Yes |
| Child before parent | Comparison possible | Comparison possible | Defer/fetch | Defer/fetch |
| Missing-parent recovery | No concrete object request | Partial | Exact reference | Exact reference |
| Participant enumeration | Vector keys | Context keys | Only observed authors/events | Only observed authors/events |
| Per-event growth | Active component count | Replica/context count | Frontier width | Frontier width + constant author link |
| Malicious fan-out | Counter inflation | Context inflation | Parent/sibling inflation | Bounded parents; sibling equivocation visible |
| Credential rotation | Component migration | Component migration | New author naturally | New credential chain plus AP grant |
| Checkpoint/pruning | Vector retirement proof | Context pruning proof | Frontier/history proof | Frontier + author-head proof |
| Rollback detectability | Needs external retained vector | Needs external retained context | Detects only against retained/cross-view evidence | Detects only against retained/cross-view evidence |
| Deterministic convergence | Same vectors/set | Same contexts/set | Same graph/set | Same validated graph/set |
| Parser/resource bounds | Map cardinality and counter widths | Context/dot cardinality and widths | Parent count, depth and deferred graph | Parent count plus constant author link, depth and deferred graph |
| DoS surface | Component inflation | Context inflation | Fan-out, missing-parent and sibling floods | Bounded frontier; missing-parent and sibling floods remain |
| Linkability | Stable component map | Stable component map | Context-local refs | Context-local refs |
| O-02/O-03 compatibility | Needs identity-to-component mapping | Needs identity-to-replica mapping | Context and author bind naturally | Context and endpoint credential bind naturally |
| Legacy migration | Unsafe semantic carry-over | New model | Hard cut | Hard cut |
| Selected | No | No | No alone | **Yes** |

## 6. Selected causal rules

### 6.1 Producer rule

Before signing, an honest producer validates its current context state and
constructs the maximal frontier after all locally accepted events. It removes
duplicates, the separately encoded direct author predecessor, and any frontier
member reachable from another frontier member. It checks the profile parent-
count and byte bounds, advances its author sequence by exactly one without
overflow, and authenticates every field under K-01/K-02. The first event for a
credential uses sequence zero, no direct author predecessor, and MUST causally
descend from the transition that granted the credential.

If the current frontier exceeds the active profile bound, production fails
closed with the later O-10 resource outcome. The producer cannot silently drop
parents, truncate the frontier or use a checkpoint not validated under the
future checkpoint rules. O-08 selects numeric bounds.

### 6.2 Validator rule

Before any AP transition, `K` verifies:

1. domain/version, context/genesis binding and bounded canonical field grammar;
2. the event signature and O-02 credential-key binding;
3. sorted unique parent references and the parent-count/byte envelope;
4. that every available causal parent and author predecessor belongs to the
   same context and is valid;
5. that the causal-parent frontier is an antichain within the validated graph;
6. that the first author event has sequence zero, no author predecessor and a
   validated grant ancestor, while each later event references a valid event
   from the same credential at sequence `n - 1` and advances without overflow
   by exactly one; and
7. duplicate, missing-parent, stale and equivocation classification.

An unavailable required causal parent or author predecessor yields `deferred`
while recoverable. Evidence that the reference lies outside an accepted
checkpoint without a sufficient proof yields `stale`; neither outcome changes
AP state. A cycle is invalid because an event reference commits the transcript
containing only already-derived references; validators also reject any observed
cycle defensively.

### 6.3 Causality, order and AP handoff

Reachability over validated causal-parent and direct-author-predecessor edges
determines happens-before. Two events are concurrent only when neither is
reachable from the other. `K` performs a deterministic topological sort: among
currently ready concurrent events, it uses unsigned-byte lexicographic order of
their authenticated event references.

For each event, `K` hands `AP` the validated event, author credential,
predecessor state, causal relationship set, fork/equivocation flags and relevant
authenticated grant/revocation state. `AP` decides accept, reject, combine,
supersede or require human review. The byte order is only a deterministic replay
schedule; it is never authorization or universal last-writer-wins.

The `K → AP` handoff at replay position *i* is prefix-scoped. Its AP-visible
classification and causal, fork and live-revocation relations describe only the
event itself and references already replayed at positions `0..i-1`; they MUST
NOT incorporate a later-sorting event merely because set-relative graph
diagnostics already know it. A later event supplies the newly actionable fork,
revocation or concurrency fact when that event is replayed. Set-relative graph
classification remains available for diagnostics and validation but is not a
retroactive AP transition. Authenticated checkpoint authority outside the live
replay horizon is supplied through the checkpoint/predecessor input, not
invented as a live per-event relation.

The handoff is deliberately application-neutral. A shared-accounting profile
may combine independent expenses and escalate a concurrent edit to the same
entry, while a whistleblowing/case-management profile may allow concurrent
evidence submission but require role-qualified review for a competing case
assignment. A generic shared-state profile may define still another merge or
human-review rule. All consume the same `K` classification; none changes it.

The topology is transport-neutral: no relay arrival, MLS epoch, Nostr key,
routing handle or storage position creates a causal edge or authorizes an
event. `SS`, `TR` and `RS` may carry or retain the protected object only under
their separately versioned profiles.

Given the same validated event set, accepted checkpoint/profile inputs and
cryptographic registry, replicas derive the same graph and order. This is a
design invariant to be tested, not an implementation claim.

The canonical order is a pure function of that complete input set, not an
append-only finality claim. A newly admitted concurrent event whose reference
sorts before an already projected event can change the previously derived
suffix. A future implementation therefore MUST replay from the earliest
affected replay boundary, or use an incremental algorithm proven equivalent to
full replay. Arrival cannot freeze the old position. Until a
separately approved profile defines stronger finality evidence, `AP` and `PV`
MUST NOT infer authorization, delivery or an irreversible external effect from
the current replay position alone. This obligation does not select RS
persistence or external-effect mechanics here.

### 6.4 Fork and malicious-author limits

Two distinct events with the same credential and sequence, or two distinct
successors naming the same direct author predecessor, are retained as fork
evidence and classified before AP evaluation. The kernel does not choose the
branch by arrival time. AP may quarantine the credential, reject both, accept a
policy-selected branch or escalate, but cannot erase the evidence required by
the active retention policy.

A compromised credential can sign internally valid forks and omit observed
cross-author parents. Signatures make that behavior attributable to the
credential; they do not make it honest. A relay can conceal a branch. Without a
later cross-view exchange or independent checkpoint witness, complete rollback
or split-view detection is impossible.

## 7. O-05 clock placement

### 7.1 Compared placements

- **HLC in the kernel:** supplies a convenient near-time order but introduces
  skew, precision fingerprinting, text/width complexity and false authority. It
  duplicates causality and is rejected.
- **Physical or logical time as an AP/profile field:** useful for deadlines,
  display or regulated workflow when its source and bounds are declared. It is
  authenticated when influential but not consumed by K causality/order or
  authorization. Selected where a profile needs time.
- **Per-author sequence plus authenticated parents:** supplies the kernel's
  logical ordering and gap/fork evidence without wall time. Selected for K.

### 7.2 Decision

O-05 is **DECIDED**: v1 has no HLC or physical-time field in the semantic kernel.
The per-credential author sequence and causal parents are the kernel logical
clock. A profile may define an authenticated physical-time claim only for one
named AP purpose. It MUST NOT influence kernel causality, deterministic order,
credential authorization or freshness by itself.

K-05's conditional microsecond unit and O-12 apply only if a later profile
retains physical time. A profile without physical time makes O-12 inapplicable
to its objects; this decision does not choose an epoch, width, skew or source.

## 8. O-06 identifier roles

The causal/reference portion of O-06 is **DECIDED at the semantic-role level**;
O-06 overall remains **OPEN** until the exact derivation is selected:

- **Event reference:** domain-separated digest of the canonical signed
  transcript excluding signature bytes and any carried identifier. It includes
  every K-01 semantic field, including context, author, sequence and parents.
  The verified signature authenticates that transcript. This reference is used
  for parents, exact duplicate detection and the K-06 concurrent tiebreak.
- **Payload/content commitment:** separate O-04 value with no decision here on
  raw/detached payload, length or digest. It is not interchangeable with the
  event reference.
- **Application idempotency/operation key:** optional AP-schema field,
  authenticated when it affects replay or workflow, but not event identity.
- **Transport/routing identifier:** TR-owned outer-envelope value and never an
  application parent or author identifier.
- **Storage key:** RS-owned index derived or bound for local use and never
  protocol identity by itself.

An event reference is derived, not trusted from the wire. A decoder may compare
a carried cache hint only after recomputation. Exact transcript bytes, digest
algorithm registry and output width remain downstream specification work under
K-02/K-03; changing them changes the protocol version. O-06 reopens if a
non-circular derivation cannot be specified or O-04 requires an identifier role
that conflicts with this separation.

## 9. Hostile worked traces

Notation: `A0(-;G)` is credential A's first event, with no direct author
predecessor and causal frontier `G`; `A1(A0;B0)` has direct author predecessor
`A0` and causal frontier `B0`. `G` abbreviates sufficient validated
grant/genesis ancestry for the illustrated credentials.

| Trace | Input/order variants | Required result |
| --- | --- | --- |
| Two concurrent authors | `A0(-;G)`, `B0(-;G)` arrive in either order | Concurrent; ready-set ordered by event-reference bytes; AP evaluates conflict |
| Three authors | `A0(-;G)`, `B0(-;G)`, `C0(-;A0,B0)` | A0/B0 concurrent; both precede C0; same topological order on all replicas |
| Author equivocation | distinct `A1(A0;B0)` and `A1'(A0;C0)` | Same sequence/predecessor fork flag; no arrival-order winner |
| Child before parent | `B1(B0;A0)` arrives before B0 | B1 deferred; after B0 validation graph is recomputed |
| Parent beyond horizon | event references pre-checkpoint object without accepted proof | Stale or missing-history outcome; no AP transition |
| Duplicate/replay | same validated event reference repeated | One graph node; interface-specific replay result, never a second effect |
| Revocation race | old-key event is concurrent with the revocation transition | O-01 reports concurrency; AP's authenticated policy decides, not timestamp |
| Rotation successor | a new credential's `C0(-;grant-C)` follows an old-credential event | New chain starts only after the authorized grant; no old-key resurrection |
| Malicious fan-out | event supplies duplicate, ancestor-redundant or excessive parents | Reject canonicality/resource violation before AP state change |
| Cross-context parent | parent reference resolves to another O-03 tuple | Reject context binding |
| Late branch after checkpoint | late event depends on pruned history | Accept only with sufficient authenticated checkpoint proof; otherwise stale |
| Late concurrent insertion | A is projected, then concurrent B arrives with a lower event reference | Recompute the affected suffix; result equals full replay over A+B, never arrival-order append |
| Late exact-prefix fork | `A0`, then one `A1(A0;G)`, then a higher-reference sibling with the same sequence/predecessor | Prior handoffs remain identical; the sibling handoff exposes the fork and AP revises or quarantines reversible state |
| Late exact-prefix revocation | an old-key action is projected, then a higher-reference concurrent revocation arrives | Prior handoff remains identical; the revocation transition supplies the new AP fact and cannot retroactively authorize an irreversible effect |
| Delivery permutation | replicas receive the same valid bounded set in different orders | Same graph, fork flags and deterministic topological order |

## 10. Checkpoint, pruning and rollback obligations

A future checkpoint must authenticate at least the context/genesis binding,
accepted frontier, per-credential sequence heads needed for gap/fork detection,
active and revoked credential authority needed for AP validation, predecessor
checkpoint reference, and commitments needed by O-04/O-07. It must distinguish
absent, pruned, released and corrupt evidence.

Compaction may remove material only when later validation, fork/replay checks,
revocation and context/genesis checks retain sufficient authenticated evidence.
Checkpoint-proven revocations outside the live replay prefix remain explicit
checkpoint/AP authority evidence; they are not repeated as though they were
new live-replay relations on every handoff.
The exact snapshot, payload-retention and RS transaction design remain open.
An external or peer-held checkpoint can improve rollback detection; no local
chain can prove that an adversary did not restore both state and its local head.

## 11. Resource and privacy envelope

- Author sequence width/range, maximum parents, active credentials, deferred
  nodes, graph depth and checkpoint horizon are profile-measured O-08 inputs.
- All collections and references are length-bounded before allocation, hashing,
  signature verification or graph traversal.
- Parent sets are sorted, unique and antichains; redundant ancestors and excess
  parents are rejected rather than normalized.
- Missing-parent requests are deduplicated and rate-limited by TR/RS profiles.
- A malicious credential can create many valid siblings until AP/RS limits or
  revocation intervene; causal structure alone is not abuse prevention.
- Parent references reveal relationships inside decrypted application objects.
  They must not be copied to outer routing envelopes. A version vector would
  expose a wider participant map; the selected model still exposes actual
  authorship and graph structure to authorized recipients.
- The v1 topology is a hard cut from `styx-legacy-c0`; legacy counters, HLCs and
  hashes are not migrated or dual-accepted without a future migration contract.

## 12. Decision table

| Item | Decision | Rejected alternatives | Open dependencies |
| --- | --- | --- | --- |
| O-01 | Authenticated per-credential chain plus bounded maximal causal-parent frontier; reachability defines causality | Fixed/sparse vector, dotted vector, DAG alone, counter sum, arrival/wall/relay order | O-04 checkpoint retention; O-07 genesis; O-08 numeric bounds; O-10 outcomes |
| O-05 | No HLC/physical time in K; per-author sequence plus parents is kernel logical clock; optional time is purpose-bound AP data | HLC as kernel causality/order; wall time as authority | O-12 only for profiles retaining physical time |
| O-06 | Derived event reference authenticates the canonical semantic transcript and serves parents/dedup/tiebreak; payload, AP, TR and RS identifiers remain distinct | Unsigned random event ID; content hash/event hash conflation; routing/storage IDs as parents | Exact K-02 bytes/hash registry; O-04 payload commitment |

### 12.1 Reopen conditions

Reopen O-01 if an executable model finds delivery-order divergence, the
profile-bounded frontier cannot preserve required causality, rotation/revocation
cannot reject stale authority, or checkpointing cannot retain necessary fork
evidence within the supported runtime envelope.

Reopen O-05 if a kernel invariant demonstrably requires physical time and
cannot be expressed by sequence, parents or AP policy. Convenience, display
order and arrival time are insufficient reasons.

Reopen O-06 if exact non-circular transcript derivation is impossible, two
semantically distinct valid events can share a reference under the selected
registry, or O-04 requires a conflicting content/reference role.

## 13. Required executable follow-up

A dedicated causal-flow simulator or small formal state model is required
before production implementation and before these choices become conformance
bytes. It needs no networking, UI, storage engine or cryptography implementation.

Minimum input:

- closed synthetic contexts, credentials, grants/revocations and events;
- parent sets, author predecessor/sequence and deterministic reference bytes;
- delivery prefixes, late concurrent insertions, permutations, checkpoint
  horizons and bounded resource profiles;
- three-or-more-event mixed causal/concurrent late insertions, late forks and
  late events that leave the prior order as an exact prefix; and
- adversarial duplicate, omission, fork, gap, fan-out and rollback operations.

Minimum output:

- validation/classification for every event;
- causal graph, ready sets, deterministic topological order and AP handoff;
- earliest affected replay boundary for every late admitted event;
- retained checkpoint evidence and explicit unavailable/stale states; and
- machine-checkable invariant failures with minimal traces.

It must test set/order convergence, acyclicity, author-sequence monotonicity,
fork visibility, equivalence of incremental suffix replay to full replay, no
state change on missing evidence, context separation, arrival/time
independence, bounded work and preservation of AP/K ownership.
This follow-up is a falsification gate: a counterexample reopens the affected
decision rather than being patched around.

## 14. Downstream transcript and negative-vector inventory

The later specification must encode or derive:

- object/version domain and O-03 context/genesis binding;
- O-02 credential identifier and verification-key binding;
- bounded author sequence and nullable direct author predecessor;
- canonical bounded parent frontier;
- event type/schema/policy and O-04 payload commitment;
- derived event reference and signature; and
- optional AP-purpose time only when its profile defines O-12 bounds.

Negative families include malformed/duplicate/unsorted/redundant parents,
cycles, cross-context parents, missing parents, author gaps, overflow, same-seq
and same-predecessor forks, invalid signatures, unauthorized credentials,
revocation races, excessive frontier/fan-out, checkpoint substitution, pruned
parent without proof, identifier mismatch, delivery permutations and legacy
objects. This inventory is not a wire format or conformance corpus.
