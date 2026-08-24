# Styx application protocol v0: payload commitment and detachment analysis

Status: C0.2e normative O-04 decision; C0.2f bounded gate executed

Base: `b49482a13e239b3cec42ac0b264ca452cd78bd9f`

Issue: [#215](https://github.com/styx-secure/styx/issues/215)

## 1. Scope and non-claims

This document selects the semantic contract for committing application content,
observing its local availability and applying a permitted logical removal. It
does not select exact transcript bytes, a digest or commitment algorithm,
output or randomizer widths, chunk sizes, wire/storage encodings, fetch
locators, error codes, a physical-deletion finality rule or product code.

The decision constrains a future language-neutral specification. It does not
make the current Dart or JavaScript ledgers conforming, repair their known
preimage and pruning defects, authorize product integration, prove physical
erasure, establish legal compliance or make current builds suitable for
sensitive use. C0.3 remains `NO-GO`.

## 2. Evidence and provenance

Normative repository inputs are:

- the [decision registry](styx-app-kernel-v0-decisions.md), especially K-01,
  K-02, K-03, K-04, K-10 and O-01/O-03/O-04/O-06;
- the [responsibility matrix](styx-app-kernel-v0-responsibility-matrix.md),
  especially `OB-K10`, `OB-K14`, `OB-AP05`, `OB-AP08`, `OB-RS05` and
  `OB-PV11`;
- the [causal-topology decision](styx-app-kernel-v0-causal-topology-analysis.md)
  and its [bounded falsification report](styx-app-kernel-v0-causal-falsification-report.md);
- the [threat model](../security/STYX-THREAT-MODEL.md);
- the [application capability model](../platform/application-capability-model.md),
  especially §§5.12, 5.15 and 5.16; and
- the [legacy integrity findings](../security/2026-08-17-ledger-preimage-and-signature-coverage-findings.md).

Three agents investigated the exact base independently, then challenged their
own conclusions and the complete reports of the other reviewers over five
passes. Reports are retained outside the repository; their digests are evidence
identifiers, not votes:

| Pass | Agent | Retained report | SHA-256 |
| --- | --- | --- | --- |
| Blind | GLM 5.3 | `README_GLM53_20260818T210430Z.md` | `1d15836846916d17e98f167c2a7a9512e92adcdc8757cfd0d30398223e345ad0` |
| Reconciliation | GLM 5.3 | `README_GLM53_RECONCILE_20260818T210430Z.md` | `f38d9b5169b48d545582199c5e4f8349c091a782bad998fdccedcd6ee24fc01e` |
| Blind | Qwen 3.8 Max | `README_QWEN38_MAX_20260818T210430Z.md` | `8974e0db317db217dcbf16fbfb5c6d8cb99fd64b83a042fa48ff11ae388c1243` |
| Reconciliation | Qwen 3.8 Max | `README_QWEN38_MAX_RECONCILE_20260818T210430Z.md` | `d8e2b9b1afe9126d02679b7b317ba52026d3dcc269580f4c18501129a5215c77` |
| Blind | Claude Opus 5 | `README_OPUS5_20260818T210430Z.md` | `bf6257ed2f5bf787cf20c3ae6e9c6fd4016a08e65c3b5dde56177641345a0109` |
| Reconciliation | Claude Opus 5 | `README_OPUS5_RECONCILE_20260818T210430Z.md` | `ae22765850f2ff21263c3ff1cfece34c4b0bc23f9183235711727bd6b0c2f313` |
| Decision challenge | GLM 5.3 | `README_GLM53_ROUND3_20260819.md` | `3e2525d9717388d02106f22ff7f1af5412cda19a4fc96b338e8be93d9c775b69` |
| Decision challenge | Qwen 3.8 Max | `README_QWEN38_MAX_ROUND3_20260819.md` | `3312f16064f290a17faa9abf7cc67ba379f31319fda7a6f57c7344ad67d3a5d7` |
| Decision challenge | Claude Opus 5 | `README_OPUS5_ROUND3_20260819.md` | `b952f89dcea5b93fd7a8a57a58448cfe3eecf5bf411a581a503471389ac79c73` |
| Narrow adjudication | GLM 5.3 | `README_GLM53_ROUND4_20260819.md` | `9478633efa461c84c3effad1881250f1da8a8314da4cf2e1e713b16e6ced2980` |
| Narrow adjudication | Qwen 3.8 Max | `README_QWEN38_MAX_ROUND4_20260819.md` | `945a6a4899c879e830778655de21630d87aa2b68ea5093bb3afc795c44b5493a` |
| Narrow adjudication | Claude Opus 5 | `README_OPUS5_ROUND4_20260819.md` | `f9a912e8ed6a1af6ba11d24a4bcd304f112adb2a84231d90efcf277ec965bf26` |
| Checkpoint falsification | GLM 5.3 | `README_GLM53_ROUND5_20260819.md` | `0cc4fda73cdef1a07b74846fda0f2df5ca9d04e82b0e8c671f34f0a7e4f86c5a` |
| Checkpoint falsification | Qwen 3.8 Max | `README_QWEN38_MAX_ROUND5_20260819.md` | `d010dd698bdd5afcd26e30834129e194bf463889e2f6dc2873a6e9ef928d3a98` |
| Checkpoint falsification | Claude Opus 5 | `README_OPUS5_ROUND5_20260819.md` | `c657154575f3e389a2555ab30f066411eb748c729027e30121f1ac6ea6e80f9c` |

External primary sources are comparisons, not Styx authority:

- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) demonstrates explicit
  leaf/interior-node domain separation and authenticated tree size in an
  append-only Merkle construction;
- [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) §15.1 explains why
  content encryption alone does not conceal message length and why padding is
  a separate policy;
- [NIST SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) provides a
  public example of named/customized hash domains; and
- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html) is considered only to
  explain why a keyed construction would add key-custody and late-verifier
  dependencies that v0 does not accept.

No external construction is imported by reference. O-06 must later select and
test the exact Styx suites.

## 3. Security properties and vocabulary

The design separates properties that the legacy formats collapsed:

- **event validity** authenticates a bounded semantic event and is independent
  of whether its content bytes are locally present;
- **content binding** says supplied bytes and an opening recompute the exact
  authenticated commitment;
- **content availability** is a local observation, not signed history and not a
  fork;
- **content necessity** is an authenticated declaration of whether replay may
  proceed without the bytes;
- **logical removal** is an authenticated later transition that changes what
  AP/PV may expose without rewriting the target event;
- **physical destruction** is a runtime action with weaker evidence and a
  separate authorization/finality problem; and
- **reconstructibility** says whether a fresh replica can derive the profile's
  current authoritative state from retained events and directly verified
  required content. V0 defines no accepted AP-state checkpoint substitution.

The **content opening** is the exact content bytes plus the fresh per-commitment
randomizer. It may be transported or stored together with an event, but it is
not part of the K signed transcript. “Detached” therefore describes byte
placement or availability, never a second event interpretation.

## 4. Design-space decision

| Candidate | Binding and bounds | Privacy after local removal | Verification after removal | Decision |
| --- | --- | --- | --- | --- |
| Raw content in the signed transcript | Direct but payload-scaled; cannot detach without rewriting | Content remains forever in signed history | Always, because content was not removed | **Rejected** |
| Deterministic digest plus length | Bounded and verifiable | Leaks equality and is an offline oracle for low-entropy content | Anyone with candidate bytes can test forever | **Rejected for v0** |
| Randomizer in the signed transcript | Hides cross-event equality when honestly fresh | Retained transcript still permits targeted candidate guessing | Public candidate testing remains possible | **Rejected for v0** |
| Keyed commitment | Bounded | Depends on key secrecy and rotation | Late/offline verification depends on key custody | **Rejected for v0** |
| Randomizer carried only in the content opening | Bounded; multi-party verification by any opening holder | Retained history alone is not a practical equality or guessing oracle under the future suite assumptions | Requires the opening; a profile may retain it when durable evidence dominates removal | **Selected** |
| Provably hiding commitment | Stronger hiding may be possible | Depends on construction | Adds primitives and proof surface not justified by current requirements | **Deferred; requiring it reopens O-04** |

The selected mechanism deliberately provides one v0 privacy baseline rather
than an application-configurable family of deterministic, keyed and salted
modes. AP selects retention of the opening by data class; it does not redefine
K cryptography. Retaining an opening preserves later verification but weakens
the local-removal privacy benefit. Destroying it gives up later verification by
a party that has only the retained ledger. A product MUST NOT promise both
properties for the same copy and data class.

Randomization is not a proof of formal hiding. Its exact strength, width and
commitment algorithm remain O-06/O-08 work. A producer MUST obtain a fresh
randomizer from the supported runtime's CSPRNG and fail closed before event
creation if generation fails. A `REQUIRED` content opening is a durable replay
dependency and cannot be acknowledged as stored without the randomizer. Test
profiles may inject a vector-defined randomizer only through the future
conformance interface; production profiles never fall back to deterministic
generation. A malicious producer can still reuse or encode information in its
randomizer; signatures attribute that choice but do not make it honest.

## 5. Selected semantic model

### 5.1 Committed object and non-circular derivation

Every authoritative event authenticates exactly one bounded content descriptor:

```text
ContentDescriptor = {
  content_class,
  content_type_id,
  exact_content_length,
  commitment_suite_id,
  commitment_shape,
  commitment_value,
  optional_chunk_geometry
}
```

This is an abstract semantic record, not selected wire bytes. K-02 later gives
it exact framing. All discriminants and identifiers come from closed,
versioned registries and all numeric fields obey K-04. A profile that permits
`DETACHABLE` content MUST choose `content_type_id` granularity that does not
itself disclose a value the profile claims to remove; fine-grained content
labels are retained metadata.

For content-bearing classes, the abstract commitment binds at least:

```text
Styx payload-commitment domain
+ commitment suite identifier
+ complete O-03 application/context tuple
+ content type identifier
+ exact content length
+ commitment shape and authenticated geometry
+ exact application-content octets at the K boundary
+ fresh opening randomizer
```

The K transcript contains the descriptor, never the content octets or opening.
O-06 later derives the event reference over the complete event transcript,
which already contains the descriptor. The content commitment never contains
its event reference. This one-way relationship avoids circularity:

```text
content + opening -> commitment -> signed event transcript -> event reference
```

The committed octets are the exact plaintext application content emitted at
the `AP/K ↔ SS` boundary before secure-session encryption. K MUST NOT commit
over MLS/session ciphertext, transport envelopes, storage ciphertext or a
fetch locator. AP may define an independently encrypted attachment object, but
that object and its fresh per-object key/descriptor remain AP content; they do
not turn SS/TR/RS ciphertext into K semantics.

### 5.2 Authenticated content classes

`content_class` has three semantic values:

- `NONE`: no content exists. Length is canonically zero and no opening or
  commitment value may be supplied.
- `REQUIRED`: verified content is necessary to evaluate the authoritative AP
  transition. Absence never invalidates the already authenticated event or its
  causal position, but replay stops before this transition.
- `DETACHABLE`: the AP profile defines a deterministic current-state
  interpretation from retained events, descriptors and removal evidence
  without needing the content bytes. The bytes may enrich presentation but
  MUST NOT be the hidden authority for a later transition. Checkpoint-based
  AP-state substitution is suspended in v0.

A zero-length `REQUIRED` or `DETACHABLE` content value still has a commitment
and opening. It is not `NONE`. Detachability is fixed when the event is signed;
an unauthenticated storage flag, missing file or wire field cannot change it.

Authority grants, revocations, policy bounds, genesis inputs and any content
whose value affects durable authorization or future deterministic state MUST be
`REQUIRED` or represented directly as bounded transcript fields. A profile may
use `DETACHABLE` only when it specifies replay after removal. If it cannot do
so, that data class is `REQUIRED`.

### 5.3 Single and chunked commitments

The descriptor permits a single-content shape and a chunk-tree shape. Exact
algorithms and sizes remain O-06/O-08 decisions.

For chunk trees, every leaf derivation binds its ordinal, exact leaf length and
the commitment's fresh randomizer, or an O-06 construction with equivalent
cross-event unlinkability. Leaf and interior-node domains are distinct; the
root descriptor authenticates total length, chunk size, chunk count and tree
shape. K checks declared geometry, including the final-chunk length, against
`exact_content_length` before allocation or hashing. Inconsistent geometry is
a structural rejection, not a binding mismatch. Parameters come from a closed
bounded profile. The full declared output width is retained. Partial fetch may
verify individual chunks, but K does not hand content to AP as verified until
the complete declared object verifies. Partial redaction is not supported by
v0; requiring it reopens O-04. O-06 must prevent identical live chunks in two
events from exposing a cross-event equality oracle through leaf commitments.

K never decompresses, decodes, sanitizes, transcodes or semantically parses
content. If AP chooses compression or a structured attachment format, AP/RS
must bound its expanded form and isolated parser separately. K commits the
exact opaque bytes it receives.

### 5.4 Orthogonal typed state

Implementations MUST represent at least these independent axes rather than one
boolean such as `isPruned` or `verified`:

| Axis | Minimum values |
| --- | --- |
| Authenticated class | `NONE`, `REQUIRED`, `DETACHABLE` |
| Local availability | `ABSENT`, `PARTIAL`, `PRESENT` |
| Binding observation | `NOT_APPLICABLE`, `NOT_CHECKED`, `VERIFIED`, `OPENING_MISSING`, `LENGTH_MISMATCH`, `COMMITMENT_MISMATCH` |
| Retention state | `ACTIVE`, `LOGICALLY_REMOVED` |
| Replay readiness | `READY`, `CONTENT_DEFERRED`, `STALE_EVIDENCE` |

Availability and binding are per-replica, per-observation facts; they are not
authenticated consensus state and differing observations are not forks. O-10
must enumerate a closed legal set of axis combinations. Any combination outside
that set is a fail-closed rejection with a stable local typed outcome; an
impossible combination is never normalized into a legal one. At minimum, the
following cases remain observably distinct:

| Case | Required interpretation |
| --- | --- |
| `NONE` with no supplied bytes | valid no-content event |
| `NONE` with supplied bytes/opening | unexpected content; never content-bearing |
| Content-bearing class, zero bytes, valid opening | verified zero-length content |
| Content-bearing class, partial bytes or incomplete opening | partial and unverified; never usable for replay or active presentation |
| `REQUIRED`, bytes absent | valid event; content-deferred AP replay |
| `DETACHABLE`, bytes absent, active | valid event; explicit content-unavailable presentation |
| Opening absent while bytes exist | unverifiable opening, not absent and not removed |
| Declared/actual length differs | corruption/substitution, not absence |
| Commitment differs | corruption/substitution, not absence |
| Valid removal, bytes absent | logically removed with retained proof |
| Valid removal, opening retained, matching bytes later presented and verified | removed-but-presented; MUST NOT silently return to active or verified presentation |
| Valid removal, opening missing or destroyed, bytes later presented | removed with unverifiable presentation; MUST NOT silently return to active or verified presentation |
| Valid removal, opening retained, later bytes mismatch length or commitment | removed with substituted presentation rejected; MUST NOT silently return to active or verified presentation |
| Checkpoint evidence unavailable or unusable | stale/deferred within the separately decided causal-checkpoint envelope; never AP-state reconstruction |

O-10 will assign rich local stable machine codes to the closed legal set and a
single opaque remote fetch-boundary outcome. The local-to-remote mapping is
many-to-one and MUST NOT reveal through outcome, response size or response
timing whether a remote object is absent, opening-missing, mismatched, removed
or locally lost. Local typed durability reporting from RS to K/AP/PV is a
separate trusted boundary and does not weaken this remote opacity rule.

### 5.5 Replay and availability

Content availability MUST NOT influence event validity, event reference,
causal/fork classification, deterministic order or duplicate identity. It is an
explicit input to AP readiness only.

Let `V` be the K-valid event set, `R` the active `REQUIRED` events and `O_r` one
replica's monotone set of locally verified openings. `K-valid` includes admitted
and fork-classified O-01 graph evidence. Define:

```text
roots_r   = R ∖ O_r
pending_r = roots_r ∪ {e ∈ V | ∃ root ∈ roots_r: root happens-before e}
applied_r = canonical_order(V ∖ pending_r)
```

Logical removal is inapplicable to `REQUIRED`, so retention does not alter
`R`. Opening verification is a pure function of the authenticated O-03 context,
descriptor and supplied opening. Pending calculation never consults AP
authority, AP outcome, retention, time or delivery state. A root is
`PENDING_OPENING`; an event pending only through causal descent is
`PENDING_ANCESTOR`. `OPENING_MISSING`, `LENGTH_MISMATCH` and
`COMMITMENT_MISMATCH` remain distinct local binding observations rather than
stable O-10 wire codes. These two pending outcomes refine the historical
model-local `CONTENT_DEFERRED` readiness label for the C0.2i amended fold; O-10
still owns the future stable legal-axis taxonomy and wire codes.

For this amended profile, every grant, revoke, rotate, recovery, policy,
closure and future disposition is a content-free control event: its
`content_class` is `NONE` and its bounded semantics are authenticated in the
event transcript. C0.2j/O-07 owns the exact K-readable carriage. The v2 model
treats rotation/recovery as symbolic evidence only and does not use either to
mint, rebind or resurrect a credential identifier.

When the live K graph is fork-free and not stale, AP applies exactly the
non-pending K-valid events in their unchanged canonical relative order.
Therefore a causally independent event applies even when it
sorts after a hole, while no descendant can bypass that hole. Adding a verified
opening monotonically removes one reason for pending status, recomputes the
descendant closure and replays from the earliest affected canonical position.
Incremental replay MUST equal fresh full replay. Equal transcript and verified-
opening sets converge. Timeout, retry count, wall time, arrival order, relay
response, peer count, checkpoint, majority statement or unauthenticated
disposition never substitutes for a missing or non-verifying opening. V0 has no
`ABANDON_REQUIRED`, control lane or provisional-effect lane.

Any K-admitted same-author fork has the lineage-scoped effect ratified by
C0.2j and recorded under O-01. Fork siblings remain `FORK_EVIDENCE`; the
forking credential and its grant-descendant lineage are terminated or
quarantined as defined by the bounded C0.2j Pass-0 and selected-slot fold.
Pending sets remain observable diagnostics. Surviving operational authority is
recomputed from the complete control-evidence set: an independent lineage is
not automatically lost, but neither its continued authority nor context
availability is guaranteed. An eligible reduction by the forking credential
in its selected contested slot is evaluated before the fork join and is not
reversed by it. Separately, `STALE_EVIDENCE` retains whole-projection precedence
and a missing `REQUIRED` opening retains its causal-subtree effect only in a
fork-free non-stale context.

The whole-projection `STALE_EVIDENCE` rule takes precedence when any symbolic
replay dependency intersects checkpoint evidence absent from the live admitted
graph. A retained admitted reference does not become stale merely because a
checkpoint also names it. The sole exemption is O-07's static genesis-authority
abstraction. This rule models neither checkpoint authentication nor acceptance,
and its replay-dependency set remains an unvalidated oracle. Checkpoints do not
substitute for retained authenticated
history, and authority-event transcripts remain non-releasable AP dependencies.
C0.2i falsifies the pending construction within a bounded v2 model; it does not
solve compaction, custody, finality or permanent opening loss.

An active `DETACHABLE` event may hand AP its authenticated descriptor plus an
explicit unavailable-content observation. The AP profile must define the same
authoritative transition regardless of local byte availability; content arrival
may change local presentation, not hidden authority, causality or order.

### 5.6 Logical removal

Removal is a new authenticated application event with a kernel-visible,
domain-separated retention role. Its semantic fields identify at least the
target event reference and target commitment. The producer MUST target a
retained accepted causal ancestor; O-04 does not widen the pre-existing
checkpoint trust envelope to prove a compacted removal target. K validates the
directive's structure, context, target-reference framing and causal placement
before target lookup. When the target is retained, K classifies target
consistency as a readiness/applicability input without changing directive-event
validity. AP alone validates actor, data-class, legal-hold and policy
authorization.

For a consumer, absence or non-retention of the target affects only replay
readiness: the directive event remains valid and is deferred. Target
availability never affects directive validity, event reference, causality,
order or duplicate identity. No current AP checkpoint authorizes treating
missing target evidence as permanently stale or guessing the target state.

A valid directive against `NONE` or `REQUIRED` content is inapplicable and MUST
NOT produce a removed state. A valid AP-authorized directive against
`DETACHABLE` content changes the target's retention axis to
`LOGICALLY_REMOVED`. It never rewrites, rehashes, re-signs or changes the
validity of the target. Legal hold is expressible in v0 only through
authenticated AP policy events; the retention axis has no hold value and
logical removal MUST NOT implement a hold.

Logical removal immediately prevents AP/PV from exposing the bytes as active
content. It does not itself authorize destruction of the last local content
copy or opening. O-13 tracks the separate cross-layer authorization decision.
Until O-13 closes, an implementation may quarantine and withhold content but
MUST NOT infer physical-destruction authority from replay position, timeout,
retry or peer count, relay/provider/transport response, quota or storage
pressure, cache expiry or eviction, private-mode teardown, session end or any
other runtime-convenience path. Physical loss through one of those paths is a
typed RS durability failure, never logical removal. A supported profile cannot
promise deletion, erasure or post-removal unlinkability while O-13 is open.

Retention state is a replay-derived fold. A late-admitted fork applies the
C0.2j lineage-scoped effect and forces removal state to be replayed under the
resulting bounded Pass-0 and selected-slot authority fold; it does not supply a
separate context-wide reset rule. A fork-free revocation that invalidates a
removal directive must restore the same state under full and incremental
replay. Rolling the event store back past a valid removal directive
re-derives the target as `ACTIVE` while quarantined bytes may remain present,
re-exposing content that policy had removed. This is a privacy regression
bounded by the existing `OB-RS09` rollback non-claim; PV MUST NOT describe the
post-rollback exposure as a corrected state.

### 5.7 Checkpoints, compaction and fresh reconstruction

Any future AP-state checkpoint proposal would have to make its contents a
deterministic function of the validated event set, the authoritative AP fold up
to the horizon, the declared AP profile/version and the applicable
suite-registry version. It must never encode which payload bytes happened to be
present on the producer. Availability may govern whether a producer is eligible
to emit at a horizon, never what an emitted checkpoint says. A conforming
producer may reference a frontier only when every `REQUIRED` event in that
frontier's causal ancestry, including the referenced events, has a verified
opening locally. That is a producer custody/fetch conformance
precondition, not a checkpoint availability bit or a consumer-facing
guarantee. Checkpoint existence at a horizon would nevertheless reveal a
possession observation: some producer claims to have held every in-horizon
`REQUIRED` opening.

In v0 a checkpoint does not substitute for missing `REQUIRED` content or its
opening, and checkpoint-based AP-state reconstruction for `DETACHABLE` content
is suspended. No decided Styx document defines the checkpoint authenticator or
acceptance rule. The C0.2i model treats checkpoint evidence and replay
dependencies as symbolic caller-supplied sets, not trusted or authenticated
state. Only a checkpoint reference absent from the live admitted graph is
checkpoint-only; matching such absent evidence makes the whole AP projection
stale. O-04 records but does not widen that pre-existing deferral. A replica
deriving AP state must replay from genesis and
directly verify every `REQUIRED` content/opening in its replay horizon. Each
missing opening makes its event and causal descendants pending; independent
work remains subject to the fork-free pending rule and, after an admitted
fork, to the separate C0.2j lineage-scoped authority fold. Causal compaction and continuation over references,
author heads and other O-01 evidence remain possible, but `REQUIRED`
content/openings and authority-event transcripts are non-releasable dependencies
for AP replay in v0. Missing `REQUIRED` bytes produce a pending root and causal
descendant closure; insufficient
checkpoint evidence produces `STALE_EVIDENCE` for either content-bearing class.
An active `DETACHABLE` event is never `CONTENT_DEFERRED` because its own bytes
or opening are unavailable; it may still be inside the causal subtree of an
earlier pending `REQUIRED` event. A fresh replica never fabricates state from a
commitment or current checkpoint.

An AP profile may therefore declare `DETACHABLE` in v0 only when retained
events, descriptors and directives suffice to reconstruct the authoritative
state without removed bytes. If that contract does not hold, the data class is
`REQUIRED`.

O-07 tracks a future checkpoint-authentication, acceptance and substitution
contract as a suspended gate. Before any checkpoint may substitute for
`REQUIRED` content or activate checkpoint-based AP-state reconstruction for
`DETACHABLE` content, that separately approved contract must define checkpoint
authentication; AP-authorized producer(s) or a
threshold and their trust assumptions; acceptance; anti-rollback and
freshness; exact replay horizon; predecessor-chain and same-horizon
equivocation handling; AP profile/version and suite-registry binding; and late
fork/revocation invalidation and recovery. The checkpoint must authenticate the
resulting AP-state boundary and its causal, authority, fork and revocation
dependencies. Producer eligibility remains a conformance obligation, never an
encoded availability fact; consumer safety rests on the acceptance rule.

No authorization model is justified today: self-checkpointing does not help a
fresh replica, a designated producer would assert state the consumer cannot
recompute and could conceal its own revocation, a threshold introduces a new
authority/availability dependency, and succinct proofs are outside the selected
primitive set. Substitution also replaces a replay dependency with a
checkpoint-chain-or-refetch dependency and can become stale after late-admitted
evidence. The future decision may therefore conclude that substitution remains
unsupported. Activation reopens O-01 and O-04, reopens O-02 if it creates a new
producer-authority class, amends the threat model, affects O-07/O-08/O-10/O-11,
reruns C0.2f under C0.2d §9 and must pass C0.3. Until then, conflicting,
unauthenticated or unavailable checkpoint material never permits selective
continuation or bypass of the `REQUIRED` halt.

## 6. Layer ownership

| Layer | Sole responsibilities for O-04 | Must not claim or decide |
| --- | --- | --- |
| `K` | Authenticate descriptor/class; derive and verify commitments; classify binding/availability/retention; validate directive structure; preserve proof across checkpoints | Business retention authority, physical deletion success, content meaning or transport location |
| `AP` | Define content types, necessity, maximum semantic sizes, replay after removal, actor/policy authorization, legal hold and evidence-vs-removal intent | Redefine event validity, commitment math or claim that local deletion affected peers |
| `RS` | Atomically store content with its opening; enforce local bounds; quarantine/delete only under an approved irreversible-effect rule; report rollback/deletion limits | Treat a missing record as authenticated removal or prove flash/backups erased |
| `SS` | Confidentially authenticate delivery of the opaque event/content material under its session profile | Substitute session ciphertext for the K commitment or infer AP retention authority |
| `TR` | Bounded opaque publication/fetch, retry and non-oracular remote errors | Put mutable locators into K semantics or claim relay deletion proves recipient deletion |
| `PV` | Show active, unavailable, corrupt, removed and deletion-pending states truthfully; disclose profile limits | Label commitment-only evidence as content-verified, legally true or physically erased |

## 7. Normative invariant set

### MUST

1. Every event authenticates exactly one K-02-framed content descriptor.
2. Every validation-relevant descriptor field is authenticated directly or by
   one unambiguous derivation.
3. Content-bearing descriptors bind context, type, exact length, shape,
   geometry, exact K-boundary octets and a fresh opening randomizer.
4. Production randomizer generation uses the supported runtime CSPRNG and
   fails closed; deterministic injection is restricted to conformance vectors.
5. The descriptor retains the full output of its future approved suite.
6. Content and opening travel and persist as one logical object; a `REQUIRED`
   opening is not acknowledged durable without its randomizer.
7. Every control-role event is `NONE`-class and authenticates its bounded
   semantics in the transcript; content-bearing control rejects structurally.
8. Content class, availability, binding, retention and replay readiness remain
   separately typed.
9. The legal axis combinations form a closed set; unlisted combinations reject.
10. Removal is append-only and AP-authorized; target evidence remains retained.
11. Checkpoints remain availability-independent and preserve commitments and
   directives.
12. Profile-declared limits and internally consistent chunk geometry are
   checked before allocation, hashing, signature
   work, fetch fan-out or decompression by an owning layer.
13. A supported profile states its post-removal reconstruction contract and
   its evidence-versus-removal trade-off.
14. In a fork-free, non-stale context, pending roots and their causal
   descendants do not apply while independent K-valid events do apply in
   canonical relative order. Any admitted fork instead applies the C0.2j
   lineage-scoped effect: the bounded Pass-0 and selected-slot fold determines
   surviving authority and application state without a context-wide reset or a
   guarantee that an independent lineage continues.
15. An honest frontier producer retains a verified opening for every
   `REQUIRED` event in the frontier's causal ancestry and can serve it through
   the future O-11 authenticated fetch contract.

### MUST NOT

1. Put payload octets or the opening in the K signed transcript.
2. Rewrite, rehash or resign a historical event to detach or remove content.
3. Let local availability affect K validity, references, causality, forks,
   deterministic order or duplicate identity.
4. Treat a missing opening, mismatched bytes, zero-length content, `NONE`,
   logical removal and physical deletion as interchangeable.
5. Commit K semantics over SS/TR/RS ciphertext or a mutable fetch locator.
6. Let K parse, decompress, sanitize or interpret content.
7. Infer detachability or removal from an unauthenticated runtime/storage flag.
8. Apply an unavailable `REQUIRED` event or any causal descendant, or block an
   independent event because of that hole in a fork-free, non-stale context.
9. Substitute timeout, retry count, time, arrival order, relay/peer response,
   checkpoint, majority statement or unauthenticated disposition for a missing
   or non-verifying opening.
10. Trigger destruction of the last local copy/opening from replay position,
   timeout, retry or peer count, relay/provider/transport response, quota or
   storage pressure, cache expiry/eviction, private-mode teardown, session end
   or another runtime-convenience path.
11. Present local deletion as evidence that another peer, backup, flash medium
   or screenshot erased content.
12. Reveal a rich local content-loss/binding cause over the remote fetch
    boundary, including through response size or timing.
13. Accept legacy `styx-legacy-c0` prune/rewrite or dual-interpretation behavior
    as v1.

### SHOULD

1. Use `DETACHABLE` for presentation content whose authoritative current state
   is defined without bytes and `REQUIRED` for authority/state-bearing content.
2. Keep content/opening storage physically separable from the event ledger.
3. Pad according to an AP/SS/TR profile when length metadata is sensitive;
   padding does not change `exact_content_length` semantics.
4. Bound and deduplicate content fetches without exposing which peer retains a
   copy.
5. Use fresh per-object encryption keys for AP-encrypted large blobs and keep
   any ciphertext-integrity descriptor below K as AP content.

### MAY

1. Co-locate content/opening with an event in a wire or storage representation;
   this does not put them in the K transcript.
2. Retain an opening for an evidence-preserving data class, while explicitly
   accepting that the retained copy remains verifiable and less erasable.
3. Evaluate a separately approved checkpoint-substitution contract only by
   reopening O-01/O-04 and the dependencies named in §5.7; v0 does not provide
   this capability.

## 8. Attack and failure analysis

| Vector | Required outcome |
| --- | --- |
| Substitute bytes, opening, type, length, context or chunk geometry | Binding failure; never absence/removal |
| Supply bytes to a `NONE` event | Unexpected-content classification |
| Remove an unauthenticated local record | Availability changes only; no logical removal |
| Replay or forge a removal directive | Duplicate/reject under O-01 and AP authorization; target unchanged |
| Present matching bytes after removal with opening retained | Removed-but-presented and verified only as a removed presentation; never silently active |
| Present bytes after removal with opening missing/destroyed | Removed with unverifiable presentation; never silently active or verified |
| Substitute bytes after removal while opening remains | Removed presentation rejected as substituted; never silently active |
| Withhold `REQUIRED` content | Valid pending root; causal descendants wait and independent events apply while fork-free; permanent subtree DoS surfaced |
| Withhold `DETACHABLE` content | Explicit unavailable presentation; authoritative AP result unchanged |
| Guess low-entropy removed content from retained ledger | No practical test without the destroyed opening under future suite assumptions; exact guarantee remains O-06 |
| Reuse a randomizer maliciously | Attribution/residual risk; no false claim that K can prove freshness |
| Production CSPRNG fails | Event creation fails closed; no deterministic fallback |
| Advertise huge content/chunk count | Reject before allocation/hash/fetch under O-08 bounds |
| Supply inconsistent length/chunk geometry | Structural rejection before allocation; never a binding mismatch |
| Reuse an identical live chunk in two events | O-06 suite prevents equality through leaf commitments or equivalent audit paths |
| Decompression bomb or hostile media | K never decodes; AP/RS isolated bounded parser rejects |
| Restore event store without content store | Explicit absence/deferred state, not corruption-free reconstruction |
| Producer lacks a required opening at a checkpoint horizon | Producer is ineligible and emits nothing at that horizon; no availability bit enters checkpoint state |
| Supply conflicting or unauthenticated checkpoint material | Unusable evidence; deferred/stale only, never AP-state substitution or selective continuation |
| Delete then admit a late fork/revocation | Revocation may replay logical state; a fork applies the C0.2j lineage-scoped effect and forces authority/removal replay without asserting that any independent lineage survives; physical destruction remains blocked until a separate finality/effect rule exists |
| Roll back past an accepted removal directive | Retention re-derives active and may re-expose quarantined bytes; explicit OB-RS09 privacy regression |
| Probe remote fetch failures | One opaque remote result independent of the rich local loss/binding cause |
| Publish content-bearing control | Structural rejection before commitment/opening processing or AP evaluation |
| Revoke, rotate or recover independently of a hole | Independent control applies; a control descendant remains pending |
| Bind an already bound credential identifier | `CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED`; all chains remain graph evidence but produce no AP effect; no safe-continuation claim |
| Publish any K-admitted same-author fork | Preserve graph/fork/pending diagnostics; apply the C0.2j Pass-0 and selected-slot fold, terminate or quarantine the affected credential lineage and descendants, and recompute authority/removal/application state without inferring producer eligibility or guaranteed independent-lineage continuation |
| Concurrently grant a successor while a peer revokes the compromised credential | Preserve both grindable reference-order outcomes, including the order where the successor remains operational; C0.2j blocks use |
| Present a checkpoint-only authority dependency | Whole projection `STALE_EVIDENCE`; no checkpoint substitution |
| Copy a current descriptor across credentials or author sequences | Accepted current-profile non-protection; AP infers no authorship/possession; C0.2k remains mandatory |

## 9. Required C0.2i falsification gate

The immutable C0.2d/C0.2f v1 simulator remains evidence for the superseded
whole-suffix construction. Before C0.3 or implementation, an isolated v2 model
must re-encode the causal families, every C0.2f obligation and every C0.2i
hostile family without importing v1. It includes authenticated symbolic
descriptors, per-replica monotone verified-opening observations, distinct
binding failures, symbolic AP control events, checkpoint non-substitution,
injected randomizers/chunks and explicit small resource bounds.

The deterministic v2 report searches at least for counterexamples to:

1. K validity, references, graph, ready sets, fork/duplicate classification and
   canonical order remaining invariant under openings and AP authority;
2. checkpoint contents remaining availability-independent while producer
   eligibility controls only whether a horizon can be emitted;
3. incremental replay equaling full replay for identical transcript and
   verified-opening sets;
4. pending-root/descendant deferral and deterministic resumption, with no
   descendant bypass and continued application of independent events only in a
   fork-free, non-stale context;
5. exhaustive typed-axis classification and fail-closed illegal combinations;
6. no directive mutating a prior event or removing `REQUIRED` content;
7. unauthorized directives never producing logical removal;
8. post-removal verified, unverifiable and substituted presentation remaining
   distinct and never becoming silently active;
9. fresh-replica replay requiring every in-horizon `REQUIRED` opening and never
   accepting checkpoint substitution;
10. late revocation replaying removal state, while any late fork applies the
    C0.2j lineage-scoped effect and recomputes the projection without a
    context-wide reset rule;
11. fork siblings and pending sets remaining diagnostic evidence while every
    admitted fork terminates or quarantines the affected credential lineage and
    descendants under C0.2j, recomputes authority/removal/application state and
    confers no producer eligibility or guaranteed independent-lineage continuation;
12. matching absent checkpoint-only dependencies producing whole-projection
    staleness, retained live references remaining non-stale, and neither case
    authenticating or accepting a checkpoint;
13. opening-divergent replicas not becoming event forks;
14. removal target edge cases remaining deterministic;
15. frozen geometry boundaries and current-profile copy non-protections; and
16. bounded work independent of attacker-declared length, chunk, directive and
    pending-root inflation.

The closed registry additionally covers event/opening interleavings, selective
disclosure convergence, overlapping roots, delay/withholding, authority and
control interactions, fork quarantine, fork-free grant/revoke laundering,
nested-root replay, collision rejection, custody/frontier eligibility and
checkpoint staleness. Every required family has a presence check, and the
closed assertion registry pins one discriminating assertion
for every retained C0.2f obligation and the critical fork, stale, ancestry,
genesis-collision and role-separation claims. Repeated family labels and delivery
permutations are coverage, not independent semantic shapes. A repository-owned
deterministic mutation harness kills thirteen required kernel/test mutants,
including weakened evidence assertions: nine are detected by the executable
required suite and four by the independent AST assertion-contract registry. The
registry does not claim that every scenario label is a distinct proof
obligation. Target-prefix abandonment remains a construction-only negative
constraint, while checkpoint-retained-live and late-authority-replay are
coverage reassertions rather than new semantic obligations.
Inputs with multiple K-valid bindings for one credential identifier reject
before positive exploration as `CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED`;
negative witnesses remain, and no positive verdict covers that class. The model
also supplies symbolic K-readable control kinds, grant subjects, binding
references and verification keys that the current O-06b-1 transcript does not
yet carry; these are construction-only inputs, not a runtime claim. A hostile
party can withhold checkpoint-named transcript material and force fail-closed
whole-projection staleness, while fork arrival can remain asymmetric between
replicas until transcript sets converge.

### C0.2i result

The historical v1 run remains byte-identical at SHA-256
`8bee78b7bde503597d331bea63bca1548bb3d8f006ea4505854b7973b3a5a3f7`.
The dependency-free v2 model on base
`468e822d7c7113ccceeea339eede27ec56f12ab3` exercised the amended closed
registry and returned `NO_COUNTEREXAMPLE_WITHIN_BOUNDS`. Its exact counts,
instrumentation, digest, reproduction commands and non-claims are recorded in
the [C0.2i report](styx-app-kernel-v0-pending-subtree-falsification-report.md).

This is bounded falsification, not proof. It selects no O-06 cryptography, O-07
checkpoint authority, O-08 production bounds, O-10 codes, O-11 encoding or
implementation. C0.2j, C0.2k and O-06c remain sequential blockers.

## 10. Dependencies and follow-ups

- **O-06:** choose exact domain tags, commitment/event-reference suites, full
  widths, randomizer requirements and transcript bytes without circularity.
- **O-07:** make genesis and initial authority content requirements explicit and
  own the suspended checkpoint authentication/acceptance/substitution contract
  described in §5.7. O-04 explicitly declines the checkpoint-authentication
  work assigned across O-04/O-07/O-08/O-11 by C0.2d §6 and records it here
  rather than silently dropping it at semantic closure.
- **O-08:** select content, descriptor, chunk, pending-root/descendant, replay-
  work and fetch bounds from supported runtime evidence, including opening-
  custody redundancy.
- **O-10:** assign rich local codes to the closed typed-state set and one opaque
  remote fetch result, with a non-oracular many-to-one boundary mapping.
- **O-11:** select wire/storage encoding, content/opening colocation, locator and
  fetch contracts without changing O-04 semantics.
- **C0.2i:** §9 is implemented in isolated v2 and passed within recorded bounds;
  preserve and rerun v1, v2, v3 and C0.2k baseline and mutation evidence whenever
  a dependent decision changes.
- **C0.2j then C0.2k:** first decide collision-resistant credential identity,
  binding resolution, grant provenance, revocation concurrency/transitivity,
  fork namespace and two-sided possible/required authority; then bind that exact
  credential plus author sequence into an amended commitment context. Both are
  mandatory before O-06c and C0.3.
- **O-13 irreversible-effect authorization:** coordinating record owned by AP
  for authorization semantics, referencing one-owner RS execution/custody/loss
  and PV disclosure/claim obligations. Until it closes, quarantine/withholding
  is the only authorized effect and no deletion, erasure or post-removal
  unlinkability promise is supported. Any O-13 candidate evidence class that
  references an accepted checkpoint is unevaluable until O-07's checkpoint
  contract closes.
- **O-15/O-16:** respectively own profile succession/optional disposition and
  finality/stability. V0 selects neither; all visible AP state is provisional.
- **Legacy containment:** defects and live legal-erasure claims outside Issue
  #215 require separate scoped work; this decision does not repair them.

## 11. Reconciliation and rejected minority positions

All three reviewers converged after five passes on: descriptor-first
commitment; plaintext K-boundary content; no historical rewrite; authenticated
`NONE`/`REQUIRED`/`DETACHABLE`; independent validity/availability; retained
commitment evidence; append-only removal; a closed typed-state set; bounded
opaque K processing; current checkpoint non-substitution; explicit non-claims;
C0.2i before C0.3/implementation; and continued C0.3 `NO-GO`.

The proposed synthesis records both convergence and surviving minorities:

- **Commitment variability:** all three reconciliation reports retained a mode
  family: GLM proposed five modes with the default unresolved; Qwen proposed a
  randomized-opening default plus a declared deterministic exception and keyed
  MAY; Opus proposed a `commitment_type` registry. The single randomized-
  opening mode is the implementer's synthesis, accepted in the later challenge
  passes because granting a ledger-only holder the ability to open a commitment
  necessarily grants that same holder the candidate-testing oracle: the two are
  one capability. That identity was first argued by Opus and not independently
  derived in the blind passes; if falsified, GLM's registry is the stronger
  fallback. Opus withdrew its two blind-pass blockers and later judged its own
  earlier O-13 form structurally worse than the selected synthesis.
- **Commitment context:** binding the O-03 tuple in the commitment preimage was
  also implementer-originated. GLM/Qwen retain it for cross-context opening
  non-transferability; Opus considers it redundant for event substitution and
  a cost to isolated verification. The human ratifier must accept this choice
  consciously.
- **Irreversible effects:** O-13 is a coordinating registry record, following
  the O-02 pattern. AP alone owns authorization semantics; RS owns execution,
  custody and typed loss; PV owns claims. K supplies evidence and never owns
  physical destruction. O-13 does not block transcript-only C0.3, but it blocks
  every destruction-capable increment and related product promise. A plain
  AP-owned open question remains a defensible simpler record form; the
  coordinating form was selected to make the referenced one-owner obligations
  explicit.
- **Checkpoint substitution:** checkpoint authentication was deliberately
  deferred by C0.2d but not given a single tracked contract. V0 declines to
  widen that trust boundary, suspends checkpoint-based AP-state reconstruction
  for `DETACHABLE` content and requires direct AP replay of all `REQUIRED`
  content. A future O-07-owned contract may conclude that substitution is
  permanently unsound; designated-producer, threshold and late-admission risks
  remain visible.
- **Typed outcomes:** the axes model avoids conflating availability with event
  validity, but its nominal state space is large. O-10 must enumerate the
  closed legal subset. A text-only first profile remains a legitimate scope
  reduction, not a reason to omit the future chunk-shape boundary.
- **Liveness:** C0.2i supersedes the authorization-blind whole-suffix halt. In
  a fork-free, non-stale context, a withheld or lost `REQUIRED` opening now
  stalls exactly its pending causal subtree while independent work proceeds.
  Descendant bypass, provisional
  effects and target-prefix abandonment remain rejected. Permanent orphaning,
  profile succession and finality remain explicit O-15/O-16 gaps.
- **Inline content:** Qwen permitted transcript-inline content. It is rejected
  because it makes transcript work payload-scaled and defeats detachment.
  Wire/storage colocation remains permitted under O-11.
- **Parallel ciphertext commitment and keyed commitments:** preserved as
  possible AP/storage mechanisms outside the K transcript; neither is a v0 K
  alternative. Erasure duties and later forensic verification remain
  irreducibly opposed for some data classes.
- **Legal hold:** v0 represents a hold only through AP policy events, not a
  third retention-axis value. A future profile that needs a distinct hold state
  must reopen the axis rather than misuse logical removal.

## 12. Closure, residual risks and reopen conditions

O-04 remains `REOPENED` under the Issue #225 amendment. The candidate removal,
retained-verification, pending-subtree and fork-quarantine semantics become
`DECIDED` only after the exact-final C0.2i evidence, independent-review and
human gates pass. This eventual status would authorize neither implementation
nor product use. The C0.2f v1 report remains immutable evidence for superseded
semantics.

Residual risks include malicious randomizer reuse; permanent length/type and
commitment correlation; loss or withholding of openings; subtree-scoped and
potentially permanent `REQUIRED`-content denial of service; `REQUIRED` content
and openings remaining non-releasable for AP replay; authority-bearing personal
data classified as `REQUIRED` having no authorized logical-removal or
destruction path in v0, including after O-13 closes unless O-04 is separately
reopened; fresh replicas needing all in-horizon `REQUIRED` content; no sound v0
AP-state continuation checkpoint; checkpoint existence leaking a producer-
possession observation; authorized recipients retaining plaintext;
peers/backups/flash/screenshots retaining copies; inability to prove physical
destruction; commitments remaining personal/correlatable data; rollback past
removal re-exposing quarantined content; randomized openings intentionally
forfeiting stable K-level cross-replica content deduplication, while storage-
level deduplication can reintroduce equality leakage; K being unable to verify
at runtime that an AP profile's `DETACHABLE` declaration satisfies its
reconstruction contract (that requires AP conformance evidence under matrix
§8); whole-profile rollback and split-view limits; and bounded exploration
missing larger counterexamples. Credential-identifier collision remains an
unsupported, cheap, retroactive authority denial of service until C0.2j;
selective opening distribution can temporarily diverge projections; delayed
reveal can amplify replay work; and no AP result is final. The current 44-octet
context still permits cross-credential descriptor copy and same-credential
cross-sequence self-copy until C0.2k.

Reopen O-04 if C0.2i finds a counterexample; O-06 cannot supply a bounded
randomized-opening suite with the required binding/privacy properties; a
supported runtime cannot keep content/opening atomic; a required profile needs
deterministic, keyed, provably hiding or chunk-partial-redaction semantics; a
profile cannot define post-removal reconstruction; implementation consumes an
unauthenticated payload-related field; current checkpoint evidence is used for
AP-state substitution; a future checkpoint contract changes authentication,
authority, acceptance, profile/suite binding, equivocation, rollback, horizon
or late-admission behavior; checkpoint retention cannot fit a supported
envelope; or installed legacy data requires migration rather than strict v1
separation. O-04 also reopens if O-10's normative legal axis set differs from
the model-local set exercised by C0.2i.

Human ratification of the exact final HEAD remains required under Issue #225.
