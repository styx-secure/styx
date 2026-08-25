# Styx application-event semantic transcript and identifier analysis — O-06a

- **Status:** selected O-06a semantic inventory; O-06b-1 fixes its exact
  application transcript/reference profile and O-06b-2 fixes commitment and
  chunk-tree internals, while executable evidence remains open under O-06c.
- **Authority:** Issues #219 and #233, ADR-0007 and the ratified K-01 through K-11 and
  historical O-01 through O-05 decisions, with O-01/O-02/O-04 subsequently
  reopened by the Issue #225 amendment.
- **Exact evidence base:**
  `787b501823cb0b9f36412acef36cbc9c3b81135b`.
- **O-06b-1 amendment base:**
  `4c2fecd0e9a81421b1d74f988572599162ac3095` under Issue #221.
- **O-06b-2 amendment base:**
  `cf93e6fa9136a383e125dfee76312bb5ca957455` under Issue #223.
- **Language:** English is canonical for external, language-neutral review.
- **Ratification:** O-06a, O-06b-1 and O-06b-2 were ratified under Issues #219,
  #221 and #223. The C0.2j amendment is governed by Issue #233 and its exact-final
  independent-review and human gates.

This document's O-06a decision fixes the semantic inventory and separation
rules needed before O-06 selects cryptographic bytes. O-06a itself selected no digest,
signature primitive, output width, exact domain tag, randomizer width, chunk
geometry, registry value, wire encoding, storage encoding or executable
vector. The separate O-06b-1 and O-06b-2 profiles now select
transcript/reference and commitment/chunk-tree bytes respectively; O-06 remains
`OPEN`, and none of these documents authorizes implementation.

## 1. Inputs, method and decision boundary

The inventory is derived from the following normative inputs rather than from
the current Dart or JavaScript ledgers:

- K-01 through K-11 and the current O-01 through O-05 status and candidate
  rules in `styx-app-kernel-v0-decisions.md`;
- the reopened O-02 candidate and decided O-03 identity/context model;
- the O-01/O-05 causal topology and C0.2d falsification evidence;
- the O-04 content model and C0.2f falsification evidence;
- the application-protocol responsibility matrix and threat model; and
- ADR-0007's assignment of language-neutral state-transition authority.

For each value that a future validator, authorization rule, causal rule,
duplicate detector, fork detector or replay rule could consume, this document
assigns exactly one disposition:

- **`INCLUDE`** — the semantic value is an explicit member of the regenerated
  signed transcript;
- **`DERIVE`** — the value is obtained deterministically from already
  authenticated state or another included field and is not repeated as an
  author-controlled transcript member; or
- **`EXCLUDE`** — the value is not a direct member of the regenerated
  transcript and K cannot consume it as an independent semantic input. An
  excluded value may still affect K or AP semantics when it is authenticated
  indirectly through an included or derived value; for example, content octets
  are bound through the O-04 descriptor and commitment rather than inserted
  directly into payload-scaled transcript bytes.

These are semantic dispositions, not byte layouts. O-06b-1 instantiates
them with one injective K-02 encoding. O-06c must later try to falsify the exact
construction before O-06 may close.

## 2. Semantic object and derivation roles

O-06b-1 gives every row below a distinct versioned cryptographic domain.
The names are descriptive and are not selected domain-tag bytes.

| Role | Semantic input | Output/use | Relationship |
| --- | --- | --- | --- |
| Application-event signature transcript | The complete inventory in §3 for one event | Bytes signed by the event credential | Primary authenticated semantic object |
| Genesis signature transcript | O-03 tuple plus the seven-field O-07 genesis inventory | Bytes signed by the single context-local root under O-14 suite `0x0001` | Separate object kind; exact body fixed by O-07 and the transcript profile |
| Event reference | The complete regenerated signature transcript, excluding signature bytes and any carried reference | Parent/predecessor reference, exact duplicate key and K-06 concurrent tiebreak | One-way derivation after transcript construction |
| Genesis reference | The event-reference-role derivation over the complete genesis signature transcript | Authenticated genesis binding carried by later events | Same reference mechanism under a genesis-specific domain; not a second commitment species |
| Payload commitment | O-04 content, fresh opening and complete binding context | Value authenticated inside the content descriptor | Computed before the event transcript; never contains the event reference |
| Chunk leaf | One chunk plus ordinal, exact leaf length, fresh per-object opening and O-04 context | Input to the commitment tree | Separate from event, commitment and interior-node roles |
| Chunk interior node | Ordered child values plus authenticated tree position/shape inputs selected by O-06b-2 | Input to the commitment root | Separate from leaves and all other roles |

A removal directive is an **application event with closed role class `0x01`**,
not a second signature container. Its signature transcript therefore uses the
application-event object kind and includes the role-class discriminant and the
extra fields in §3.3. O-06b-1 ensures that this role cannot be reinterpreted as
an ordinary application action.

Credential grants, revocations, policy transitions and other authority-bearing
actions are application events with closed role class `0x02`
(`CREDENTIAL_CONTROL`). They are always `NONE`-class. Their exact K binding,
target and succession values use the role-specific tail selected by C0.2j;
profile-specific policy values remain in the authenticated AP transition block.
A profile must not hide durable authority in `REQUIRED` or `DETACHABLE` content.

## 3. Complete K-01 field inventory

### 3.1 Fields common to every authoritative application event

| Semantic field | Disposition | Owner/source | Rationale and rejected alternative |
| --- | --- | --- | --- |
| Styx protocol version | `INCLUDE` | `K`, from the O-03 tuple | Separates legacy and future protocols. Ambient version or decoder choice is rejected. |
| Application-profile identifier | `INCLUDE` | `AP`, bounded by the O-03 tuple | Prevents cross-profile replay. A UI, package name or transport label cannot substitute. |
| Application-profile version | `INCLUDE` | `AP`, bounded by the O-03 tuple | Binds the closed schema/policy family. Silent "latest" interpretation is rejected. |
| 32-byte context identifier | `INCLUDE` | `K/AP`, from the O-03 tuple | Prevents cross-case replay. It is not a public routing handle or anonymity mechanism. |
| Application-event object-kind/role-class discriminant | `INCLUDE` | `K`, closed registry | Prevents cross-object and ordinary/removal/credential-control reinterpretation. Decoder entry point is insufficient. |
| Event type identifier | `INCLUDE` | `AP`, closed profile registry | Selects the transition schema. Free-form names and inferred types are rejected. |
| Schema identifier/version needed to parse the transition | `INCLUDE` | `AP`, closed profile registry | Any schema that changes validation must be authenticated. Ambient schema selection is rejected. |
| AP type-specific transition-field block | `INCLUDE` | `AP`, membership and internal order fixed by the authenticated closed schema identifier/version | Every direct field that changes authorization or transition semantics is authenticated in one bounded schema-defined position. Decoder order, maps and undeclared extension fields are rejected. |
| Effective grant/policy state | `DERIVE` | `AP`, from authenticated replay state under O-02 | An author-carried "current policy" selector is excluded; the order-sensitive concurrent case is constrained in §3.4 and §6. |
| Credential identifier | `INCLUDE` | O-02 context-local credential state | Names the author binding without embedding a global account or session identity. |
| Verification key | `DERIVE` | Direct lookup of the K-valid binding `GRANT` whose event reference equals the credential identifier | Repeating an author-supplied key permits substitution. Only that GRANT tail creates a binding; missing/forward lookup, wrong context, suite/key mismatch or observed reference collision fails closed. |
| Signature algorithm identifier | `DERIVE` | Authenticated binding `GRANT`; O-14 selects only internal Styx suite `0x0001` (`STYX-ED25519-PRIMEORDER-RFC8032-V1`) | An author-selected algorithm field could enable downgrade or cross-algorithm ambiguity. Zero, reserved, unknown, inconsistent, fallback and cross-registry values fail closed before verification. |
| Signature bytes | `EXCLUDE` | Supplied beside the regenerated transcript | Including the signature in event identity is circular and makes resigning change identity. The signature authenticates, but is not part of, its content. |
| Author sequence | `INCLUDE` | O-01 | Detects per-credential gaps and equivocation. Arrival order and aggregate counters are rejected. |
| Direct author-predecessor presence | `INCLUDE` | O-01 | Presence is distinct from a zero or empty reference. Implicit null conventions are rejected. |
| Direct author-predecessor reference | `INCLUDE` when present | O-01/O-06 | Authenticates the author chain. It is absent only for sequence zero. |
| Canonical causal-parent count | `INCLUDE` | O-01; bound supplied later by O-08 | Frames the sorted-unique antichain and permits bounds before allocation. End-of-buffer inference is rejected. |
| Canonical causal-parent references | `INCLUDE` | O-01/O-06 | The bytewise sorted-unique maximal antichain is authenticated. Arrival or insertion order is rejected. |
| Genesis reference | `INCLUDE` | O-03 and the O-07 seven-field signed genesis transcript | Binds every event to one accepted genesis without making the random context identifier depend on genesis. |
| O-04 content descriptor | `INCLUDE` | `K/AP` under O-04 | Authenticates class, type, length, suite, shape, value and geometry. Raw content/opening are excluded. |
| Author-carried event reference/cache hint | `EXCLUDE` | Convenience representation only | A consumer recomputes the reference. A mismatch is an O-11 representation diagnostic, never K semantic invalidity; removing or correcting the hint cannot change admission. |
| Application-purpose physical time | `EXCLUDE` from K | `AP`, if a later time-bearing profile is approved | O-05 removed physical time from the kernel. Any time claim is committed application content and remains subject to O-12 at that profile boundary. |
| Relay timestamp, arrival order, storage order, UI time | `EXCLUDE` | `TR`, `RS` or `PV` observations | None may affect validity, causality, replay, fork handling or authorization. |
| MLS epoch/member identity, Nostr key/event identifier, relay identifier | `EXCLUDE` | `SS`/`TR` | Session and transport authentication do not establish application authorship or context. |
| Storage key, database name or record identifier | `EXCLUDE` | `RS` | Storage location cannot become event identity or semantic input. |

The application-event signature itself MUST authenticate the complete
transcript represented by the included rows. Event-reference derivation uses
that same complete semantic transcript under its own domain and excludes the
signature bytes and any carried reference.

### 3.2 Content descriptor members

The content descriptor is one included field whose members remain individually
typed and authenticated:

| Descriptor member | Disposition | Rule |
| --- | --- | --- |
| `content_class` | `INCLUDE` | Closed `NONE`, `REQUIRED`, `DETACHABLE` registry. |
| `content_type_id` | `INCLUDE` when content-bearing | Closed AP registry; granularity must respect removal/privacy claims. `content_class` is the presence discriminant. |
| `exact_content_length` | `INCLUDE` | Exact non-wrapping integer; zero content-bearing value remains distinct from `NONE`. |
| `commitment_suite_id` | `INCLUDE` when content-bearing | O-06b-2 pins the exact active-profile value. Unknown or inconsistent values fail closed; an event cannot negotiate or downgrade among suites. |
| `commitment_shape` | `INCLUDE` when content-bearing | Closed single/chunk-tree discriminant. |
| `commitment_value` | `INCLUDE` when content-bearing | Full 32-octet O-06b-2 output, never a locator or storage hash. |
| chunk-geometry presence | `INCLUDE` when content-bearing | Absence is valid only for the single shape and cannot alias zero geometry. |
| chunk size/count/tree geometry | `INCLUDE` when present | Exact O-06b-2 representation; O-08 supplies enforceable profile maxima. |
| content octets | `EXCLUDE` | Bound through the commitment; raw payload-scaled transcript work is rejected. |
| opening randomizer | `EXCLUDE` | Retained separately; putting it in the transcript enables public candidate testing. |
| fetch locator, ciphertext, compression/storage metadata | `EXCLUDE` | AP/SS/TR/RS representation cannot change K semantics. |

For `NONE`, exact length is zero, geometry is absent, and no commitment value
or opening may be supplied. A zero-length `REQUIRED` or `DETACHABLE` value has
a commitment and opening and therefore cannot encode as `NONE`.

### 3.3 Removal-directive fields

In addition to all common event fields, the retention role includes:

| Field | Disposition | Rationale |
| --- | --- | --- |
| retention-role discriminant | `INCLUDE` | Prevents an ordinary action from being reinterpreted as removal. |
| target event reference | `INCLUDE` | Names one retained accepted causal ancestor without mutating it. |
| target commitment | `INCLUDE` | Detects reference/descriptor substitution and binds the intended content. |
| claimed removal authorization, legal hold or data-class decision | `DERIVE` from the deterministic AP replay prefix and authenticated policy events | An author cannot make removal authorized by declaring it so. Prefix-derived authority may permit only the append-only logical-removal transition after AP validation; physical destruction remains gated by O-13 and cannot be inferred from replay position. |
| local deletion/quarantine result | `EXCLUDE` | `RS` owns custody and loss reporting; runtime outcome is not application authority. |
| relay/provider acknowledgement, timeout, retry/peer count or quota state | `EXCLUDE` | O-13 forbids inferring irreversible authority from operational convenience. |

The target-reference and target-commitment pair is the complete v0 target
identity. Adding another field that changes applicability or authorization
requires a K-01 inventory amendment before reopening O-06b-1.

### 3.4 Authorization and application-owned identifiers

The authenticated event does not carry an author-selected "current policy"
selector. Authorization is evaluated against the deterministic, authenticated
AP state visible at the event's canonical replay prefix, including the
credential grant and any actionable rotation, revocation or policy events.
That prefix is order-sensitive: a concurrent revocation, rotation or policy
event that sorts later is not visible in the acting event's own handoff. AP
therefore MUST NOT treat the prefix-visible authority set as final when a
concurrent authority transition is later disclosed. Per the ratified C0.2d
rule, it must revise only reversible state and MUST NOT authorize an
irreversible effect before stronger evidence. O-06a tightens that safety rule:
evidence used to justify an irreversible effect cannot derive its authority
from the event's replay position and must be order-independent. The resulting
AP decision still covers the exact action, context, credential and effective
policy state known at that prefix; it is not a finality claim.

The C0.2j amendment closes the K-readable control location. Grant, revoke,
rotate, recovery, policy and closure use role class `0x02`, are `NONE`-class
and begin their role-specific tail with one closed control-kind octet. The
`GRANT` arm directly authenticates grantee suite and verification key;
`REVOKE` authenticates its target; `ROTATE`/`RECOVER` authenticate a target and
an already admitted fresh-GRANT reference. `POLICY`/`CLOSURE` add no other
K-owned credential field. Their profile-specific semantics remain in the
existing authenticated AP transition block.

Only `GRANT` creates a binding. Its event reference is the non-genesis
credential identifier and its common field 11 is the issuer. No declared
subject or derived identifier appears in that preimage. `ROTATE` and `RECOVER`
create no binding and cannot rebind or resurrect an identifier. Any new K-owned
control location outside the selected tail reopens O-06b-1.

If a future profile needs another explicit policy reference because the
effective state cannot be derived unambiguously, that reference becomes an
`INCLUDE` field through a separately ratified O-02/AP amendment. Until then,
an author-declared policy version cannot weaken or select stale authority.

An AP idempotency/operation key is not an event reference. When present, it is
an AP-schema value inside directly authenticated bounded fields or `REQUIRED`
committed content and is interpreted only after verification. It cannot serve
as a parent, duplicate key, fork identifier, transport route or storage key.
If a profile asks K to consume it before AP verification, K-01 and this
inventory must reopen.

## 4. Abstract framing calculus

O-06b-1 instantiates an injective encoding satisfying all of these rules:

1. every object and derivation role has a distinct versioned domain;
2. every value is either fixed-width or preceded by an exact length whose own
   width and valid range are fixed;
3. the transcript has one total field order and no map iteration, locale or
   implementation order;
4. optional fields carry an explicit presence discriminant; absent, present
   empty and present zero are different assignments;
5. closed discriminants are validated before dependent fields are parsed;
6. counts and lengths are validated against the active profile before
   allocation, hashing, signature work, graph traversal or fetch fan-out;
7. parent references are full-width, canonical bytewise sorted, unique and
   form the O-01 maximal antichain; the direct author predecessor and genesis
   reference are encoded separately and excluded from that frontier. An event's
   frontier is empty exactly when it has no causal parent other than its direct
   author predecessor and the genesis reference; multiple concurrent
   founding-credential events may therefore each have an empty frontier;
8. a decoder never repairs, clamps, truncates, normalizes or ignores trailing
   semantic bytes;
9. the regenerated transcript is not a generic wire document; O-11 may choose
   a different wire/storage representation without changing these semantics;
10. any two distinct valid field assignments must produce distinct preimages
    before the cryptographic primitive is applied.

The final item is an O-06b-1 written proof obligation and an O-06c adversarial
property. This document does not claim it has been met by exact bytes.

## 5. Dependency separation and non-circularity

| Boundary | O-06a decision | Remaining owner/work |
| --- | --- | --- |
| O-02 / O-06 | Include the grant-rooted credential identifier; derive key and signature algorithm by direct K lookup of its binding GRANT; authenticate closed credential-control arms. Do not let an event choose its own verification algorithm. | O-14 selects suite `0x0001`, canonical 32-octet Ed25519 keys, canonical 64-octet `R || S`, prime-order guards and terminal no-fallback verification. AP/O-02 still own authority. |
| O-03 / O-06 / O-07 | Later events include a genesis reference derived over the complete seven-field signed genesis transcript. It is not the random context identifier and creates no self-reference. | O-07 fixes single-root contents and authenticated external acceptance; O-06b-1 defines exact reference bytes. |
| O-04 / O-06 | Commitment is computed first from content/opening/context; its descriptor enters the event transcript; the event reference is computed last. The commitment never includes the event reference. | O-06b-1 selects the reference suite and O-06b-2 selects the commitment suite; O-06c falsifies the construction. |
| O-06 / O-08 | Semantic counts, lengths and geometry slots exist; exact transcript and commitment-geometry widths are fixed by O-06b-1/O-06b-2. | O-08 supplies measured enforceable profile maxima and activation bounds. |
| O-06 / O-10 | O-06a identifies rejection sites and safe distinctions without assigning stable codes. | O-10 closes the bounded taxonomy after exact fields close. |
| O-06 / O-11 | K regenerates transcript/reference preimages from validated semantics. | O-11 owns wire/storage decoding and canonical representation. |
| O-05/O-12 / O-06 | No physical-time field exists in the v0 K transcript. | A future time-bearing AP profile must close O-12 for its own committed content. |

This separation removes the apparent genesis cycle and prevents runtime bounds,
error names, wire formats or application authority from being smuggled into a
cryptographic-identifier decision.

## 6. Event-reference grinding and policy prohibition

A reference used as the K-06 tiebreak is deterministic from an author-controlled
signed transcript. Any holder of valid signing-key material, including a
credential already revoked by the AP fold, may vary otherwise valid inputs —
most notably fresh content/opening choices — and spend work to bias bits of its
own future reference. Signatures make the chosen transcript attributable; they
do not make its digest an unbiased random beacon.

Therefore:

- K-06 reference order is only a deterministic replay schedule for events
  already proven concurrent;
- replay position MUST NOT by itself confer authorization, priority, ownership,
  first-writer-wins truth, expiry, logical-removal authority or permission for
  an irreversible external effect. Authenticated prefix state may authorize an
  append-only logical-removal transition under AP policy, but physical
  destruction remains gated by O-13 and never follows from replay position;
- AP must evaluate semantic conflicts independently under K-07; and
- a future profile claiming fairness or unpredictability requires a separate
  mechanism and threat analysis.

Changing replay position does not change signature/credential validity,
graph-set causality or the existence of underlying fork/revocation evidence.
It **can** change which concurrent revocation, rotation or policy facts appear
in the acting event's prefix-scoped handoff. An author that omits an observed
cross-author parent can grind below a concurrent authority transition and make
that transition absent from its own evaluation point. Later replay still
discloses the concurrency, so AP must revise reversible state and cannot treat
the earlier prefix result as irreversible authority. C0.2j closes the previously
confirmed laundering witness without selecting one replay-order winner. Pass0
projects every bounded admissible causal interpretation before contested
reductions; expansion is admitted only from necessary Pass0 authority. For each
actor, only the first eligible contested author-sequence slot can contribute
accepted reductions, and every eligible sibling in that selected slot is
included. A reduction target must already be causally available under R-1,
except that `RECOVER` retains its separately authorized bootstrap semantics. An
accepted ancestor reduction terminates every provenance descendant. A ground
reference on either side of a concurrent reduction cannot select a surviving
successor within the bounded model. Grinding can also move an
event with unavailable `REQUIRED` content across concurrent peers. In a
fork-free, non-stale context, C0.2i removes replay position from the readiness
boundary: only that event and its causal descendants enter the pending set,
while independent events remain applicable. Order can still change
deterministic presentation among otherwise
concurrent applicable events, but it cannot enlarge the pending causal subtree,
confer authority or create finality; indefinite withholding remains an accepted
O-04 risk.

The historical C0.2i v2 model preserves the superseded laundering witness in
both ordering directions. The independent C0.2j v3 model exercises attacker-
selected references on both sides, every bounded delivery order and the new
Pass0/selected-slot terminal fold. It also
moves an unavailable-`REQUIRED` event across
concurrent peers in both directions and verifies that the pending causal
subtree and opening-triggered replay are order-independent. C0.2j replaces the
model's fail-closed unique-identifier assumption with exact grant-rooted
identity and K-readable grant binding; C0.2k must next
bind the commitment to that identity before O-06c re-falsifies the exact byte
profile. None of these increments may assert the false stronger property that
every prefix-scoped handoff or reversible readiness result is unchanged.

## 7. Rejection-site inventory for later O-10 work

O-06a identifies these classes without assigning stable codes:

- unsupported protocol/profile/object/event/suite discriminant;
- malformed, non-canonical, truncated, overlong or trailing transcript input;
- absent/present/empty/zero state inconsistent with its discriminant;
- numeric overflow, wrap, precision loss or out-of-profile bound;
- invalid parent count/order/uniqueness, redundant ancestor, missing parent,
  direct-predecessor mismatch or cross-context reference;
- unknown credential, key-binding mismatch, unsupported signature algorithm or
  invalid signature;
- missing/forward binding GRANT, malformed credential-control arm, declared
  GRANT subject, target/replacement inconsistency or prohibited identifier
  resurrection;
- carried/recomputed event-reference mismatch as an O-11 representation
  diagnostic that cannot invalidate the regenerated semantic event;
- content-class/descriptor/geometry inconsistency;
- commitment/opening/length mismatch;
- removal target/reference/commitment inconsistency; and
- observed collision between semantically distinct valid objects, which is
  invalid and never deduplication.

O-10 may collapse classes only when doing so cannot change safe caller
recovery. Remote-facing outcomes remain subject to the threat model's opacity
requirements.

## 8. Rejected alternatives

| Alternative | Reason rejected |
| --- | --- |
| Select SHA-256, SHA-3, BLAKE3 or any other primitive in O-06a | Primitive choice before the semantic field inventory would freeze assumptions the task exists to test. |
| Include signature bytes in the event reference | Circular identity and unstable reference on resigning. |
| Let events carry authoritative event IDs | Mutable or substituted identity can poison deduplication, parents and ordering. |
| Hash only content or the O-04 descriptor as event identity | Distinct authorship, causality, policy and context could alias. |
| Reuse event reference as content, idempotency, route or storage identity | Conflates ownership, leaks correlation and permits one layer's success to substitute for another. |
| Put content or opening in the signed transcript | Payload-scaled signing and public candidate testing defeat detachment/privacy goals. |
| Put current verification key/algorithm in every event as author-selected authority | Enables substitution/downgrade and bypasses authenticated credential state. |
| Include HLC, wall time, relay time or arrival order in the kernel | Reintroduces O-05-rejected authority and runtime divergence. |
| Derive context ID from genesis or expose it as routing ID | Creates avoidable linkability and a context/genesis cycle. |
| Make replay position decide business conflict | Digest grinding becomes an authorization or integrity attack. |

## 9. Required next increments

### O-06b-1 — exact application transcript and reference profile

Issue #221 selects the exact scalar grammar, ordered application-event
transcript, seven-role domain registry and SHA-256 full-width event/genesis
reference derivation in
`styx-app-kernel-v0-transcript-encoding-profile.md`. The written injectivity
argument is conditional on the still-open AP schema and commitment-suite
interiors: it proves only that distinct admitted field tuples cannot collide at
the encoding layer. It neither claims mathematical injectivity of SHA-256 nor
authorizes production implementation.

O-06b-1 does not select the signature suite owned by O-14. It defines only a
future compatibility/reopen predicate: reopen this transcript choice if O-14
cannot authenticate the selected bytes, requires an author-controlled or
per-event transcript/digest selector, invalidates the recorded runtime and
supply-chain basis, or materially requires a different reference digest.

### O-06b-2 — exact commitment and chunk profile

Issue #223 selects suite `styx.commitment-suite.v1/0x0001`: full-width SHA-256,
a fresh 32-octet randomizer, exact content/leaf/interior-node preimages and a
left-complete binary chunk tree under the domains allocated by O-06b-1. The
complete construction, written inverse, assumptions and runtime evidence are in
`styx-app-kernel-v0-commitment-encoding-profile.md`. O-07 subsequently rejects
all checkpoint authority/substitution in v0. This document does not set O-08
runtime maxima, assign O-10 codes, create a
conformance corpus or authorize production implementation. O-06 remains
`OPEN` after O-06b-2.

### C0.2i, C0.2j, C0.2k and O-06c — staged executable closure

C0.2i supplies a fresh isolated v2 model for pending-subtree replay while
preserving the historical v1 evidence byte-for-byte. It deliberately fails
closed on a credential-identifier collision before positive exploration.
C0.2j selects the binding `GRANT` reference as non-genesis credential identity,
the exact K tail, provenance, bounded Pass0/selected-slot authority and lineage fork containment;
its independent v3 evidence is bounded rather than a production proof. C0.2k
binds the content commitment to that exact identity and author sequence through
the selected 84-octet `CTX`; the superseded 44-octet `CTX` does neither and
remains a recorded non-protection rather than an inferred guarantee.

O-06c tests framing injectivity, absence/emptiness,
cross-role/context separation, non-circularity, cross-event chunk equality,
parent canonicality, suite binding, unknown-suite rejection, structural versus
binding failures, collision handling, grinding/prefix-handoff interaction and
bounded work. Its evidence must report the deterministic work order and
per-stage work counters so an implementation cannot hide attacker-controlled
parsing, hashing, graph or replay work behind a final verdict. It must rerun
C0.2d/C0.2f/C0.2i without changing their recorded results
and must not add `conformance/**` files before the separate K-11 licensing task.
Issue #243 supplies that bounded no-counterexample result with independent
Python/JavaScript encoders, a closed 16-class source-mutant registry, complete-
object octet/scalar mutation, frozen-section checks and exact historical reruns.
It moves O-06/O-06c to condition-bearing `DECIDED` only after independent
exact-final review and human ratification. The result is not proof or
implementation conformance and must be rerun or reopened for any selected
placeholder input or later counterexample.

## 10. Security/privacy consequences and residual risk

The selected inventory is designed to prevent unsigned causal, context,
descriptor or role metadata from influencing authoritative behavior and to
prevent session, transport and storage identifiers from substituting for event
identity. It does not make stable references private: authorized recipients can correlate
equal references and graph structure, and any profile exposing them outside
the protected application object inherits that correlator.

O-06b-1 now supplies an exact application-event encoding and reference digest,
and O-06b-2 supplies an exact randomized-opening commitment and chunk-tree
construction, but neither is an implementation proof. SHA-256
collision/second-preimage resistance, commitment hiding/binding assumptions,
randomizer custody/misuse, parser safety, runtime capacity and signature-suite
downgrade remain residual or open. Bounded C0.2i/O-06c evidence does not prove
absence of counterexamples outside its envelope. A hostile
holder of valid signing-key material, including a revoked credential, can
withhold parents, equivocate, reuse randomizers or grind its replay position.
Grinding can suppress a later-sorting concurrent authority transition from one
acting-prefix observation, but C0.2j no longer selects that observation as
terminal expansion authority. Its DP projection retains every distinct
reachable control state keyed by processed controls, authority, revoked
credentials and forked credentials; crossing the state or transition envelope
makes authority explicitly unavailable instead of choosing a partial result. It cannot widen
the C0.2i pending set beyond the unavailable event's causal descendants merely
by changing order. Later disclosure requires reversible AP repair and does not
retroactively make an irreversible effect safe; later opening verification
replays the affected subtree, while indefinite withholding remains possible. The protocol can
attribute and classify these actions but cannot force honest claims or
availability.

Reopen this inventory or the O-06b-1 profile if an admitted schema cannot be
injectively framed without changing a semantic field; O-07 genesis cannot bind
without self-reference or ambiguity;
an AP rule needs an unauthenticated input; a signature-suite decision requires
an author-controlled algorithm field; a supported profile needs physical time
inside K; or executable evidence finds a cross-role, cross-context,
non-circularity or replay-policy counterexample.

## 11. C0.3 gate

O-06b-1 plus O-06b-2 and C0.2j do not make C0.3 executable. C0.2k, O-06c and
O-07 and O-14 are condition-bearing `DECIDED`; O-08 and O-10 remain open blockers.
O-14's unchanged placeholder in O-06c must be replaced by the selected `0x0001`
semantics and the complete combined evidence rerun under a separate
human-ratified task before corpus authorization. O-12 additionally blocks any
time-bearing profile. O-11 does not block a transcript-only corpus but must
close before supported persistence or remote admission. K-11 requires a
separate exact-path licensing amendment before C0.3 creates any normative corpus
file. No supported Phase B adapter may persist current application-ledger
objects while this `NO-GO` remains in force.
