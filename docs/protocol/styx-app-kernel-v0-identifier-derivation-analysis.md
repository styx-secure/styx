# Styx application-event semantic transcript and identifier analysis — O-06a

- **Status:** selected semantic inventory; exact cryptographic profile and
  executable evidence remain open under O-06.
- **Authority:** Issue #219, ADR-0007 and the ratified K-01 through K-11 and
  O-01 through O-05 decisions.
- **Exact evidence base:**
  `787b501823cb0b9f36412acef36cbc9c3b81135b`.
- **Language:** English is canonical for external, language-neutral review.
- **Ratification:** every selection below is proposed until `maverde73`
  ratifies the exact final PR HEAD after independent review.

This document fixes the semantic inventory and separation rules needed before
O-06 can select cryptographic bytes. It deliberately selects no digest,
signature primitive, output width, exact domain tag, randomizer width, chunk
geometry, registry value, wire encoding, storage encoding or executable
vector. O-06 remains `OPEN`, and this document authorizes no implementation.

## 1. Inputs, method and decision boundary

The inventory is derived from the following normative inputs rather than from
the current Dart or JavaScript ledgers:

- K-01 through K-11 and O-01 through O-05 in
  `styx-app-kernel-v0-decisions.md`;
- the O-02/O-03 identity and context model;
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
- **`EXCLUDE`** — the value cannot influence kernel validity, causality,
  ordering, duplicate identity or application authorization.

These are semantic dispositions, not byte layouts. O-06b must instantiate
them with one injective K-02 encoding. O-06c must then try to falsify the exact
construction before O-06 may close.

## 2. Semantic object and derivation roles

O-06b must give every row below a distinct versioned cryptographic domain.
The names are descriptive and are not selected domain-tag bytes.

| Role | Semantic input | Output/use | Relationship |
| --- | --- | --- | --- |
| Application-event signature transcript | The complete inventory in §3 for one event | Bytes signed by the event credential | Primary authenticated semantic object |
| Genesis signature transcript | O-03 tuple plus the bounded O-07 genesis inventory | Bytes signed under the future genesis authority rule | Separate object kind; O-07 still owns genesis contents |
| Event reference | The complete regenerated signature transcript, excluding signature bytes and any carried reference | Parent/predecessor reference, exact duplicate key and K-06 concurrent tiebreak | One-way derivation after transcript construction |
| Genesis reference | The event-reference-role derivation over the complete genesis signature transcript | Authenticated genesis binding carried by later events | Same reference mechanism under a genesis-specific domain; not a second commitment species |
| Payload commitment | O-04 content, fresh opening and complete binding context | Value authenticated inside the content descriptor | Computed before the event transcript; never contains the event reference |
| Chunk leaf | One chunk plus ordinal, exact leaf length, fresh per-object opening and O-04 context | Input to the commitment tree | Separate from event, commitment and interior-node roles |
| Chunk interior node | Ordered child values plus authenticated tree position/shape inputs selected by O-06b | Input to the commitment root | Separate from leaves and all other roles |

A removal directive is an **application event with a distinct, closed retention
role**, not a second signature container. Its signature transcript therefore
uses the application-event object kind and includes the retention-role
discriminant and the extra fields in §3.3. O-06b must still ensure that this
role cannot be reinterpreted as an ordinary application action.

Credential grants, revocations, policy transitions and other authority-bearing
actions are closed application-event types. Their authoritative values are
either bounded direct transcript fields or `REQUIRED` O-04 content. A profile
must not hide durable authority in `DETACHABLE` content.

## 3. Complete K-01 field inventory

### 3.1 Fields common to every authoritative application event

| Semantic field | Disposition | Owner/source | Rationale and rejected alternative |
| --- | --- | --- | --- |
| Styx protocol version | `INCLUDE` | `K`, from the O-03 tuple | Separates legacy and future protocols. Ambient version or decoder choice is rejected. |
| Application-profile identifier | `INCLUDE` | `AP`, bounded by the O-03 tuple | Prevents cross-profile replay. A UI, package name or transport label cannot substitute. |
| Application-profile version | `INCLUDE` | `AP`, bounded by the O-03 tuple | Binds the closed schema/policy family. Silent "latest" interpretation is rejected. |
| 32-byte context identifier | `INCLUDE` | `K/AP`, from the O-03 tuple | Prevents cross-case replay. It is not a public routing handle or anonymity mechanism. |
| Application-event object-kind/role discriminant | `INCLUDE` | `K`, closed registry | Prevents cross-object and ordinary/removal reinterpretation. Decoder entry point is insufficient. |
| Event type identifier | `INCLUDE` | `AP`, closed profile registry | Selects the transition schema. Free-form names and inferred types are rejected. |
| Schema identifier/version needed to parse the transition | `INCLUDE` | `AP`, closed profile registry | Any schema that changes validation must be authenticated. Ambient schema selection is rejected. |
| Credential identifier | `INCLUDE` | O-02 context-local credential state | Names the author binding without embedding a global account or session identity. |
| Verification key | `DERIVE` | Authenticated O-02 credential state selected by credential identifier and replay prefix | Repeating an author-supplied key permits substitution. The key is compared through authenticated state. |
| Signature algorithm identifier | `DERIVE` | Authenticated credential record; exact registry ownership remains open in O-14 | An author-selected algorithm field could enable downgrade or cross-algorithm ambiguity. Unknown or inconsistent algorithms must fail closed. |
| Signature bytes | `EXCLUDE` | Supplied beside the regenerated transcript | Including the signature in event identity is circular and makes resigning change identity. The signature authenticates, but is not part of, its content. |
| Author sequence | `INCLUDE` | O-01 | Detects per-credential gaps and equivocation. Arrival order and aggregate counters are rejected. |
| Direct author-predecessor presence | `INCLUDE` | O-01 | Presence is distinct from a zero or empty reference. Implicit null conventions are rejected. |
| Direct author-predecessor reference | `INCLUDE` when present | O-01/O-06 | Authenticates the author chain. It is absent only for sequence zero. |
| Canonical causal-parent count | `INCLUDE` | O-01; bound supplied later by O-08 | Frames the sorted-unique antichain and permits bounds before allocation. End-of-buffer inference is rejected. |
| Canonical causal-parent references | `INCLUDE` | O-01/O-06 | The bytewise sorted-unique maximal antichain is authenticated. Arrival or insertion order is rejected. |
| Genesis reference | `INCLUDE` | O-03, semantic form selected in §2; contents remain O-07 | Binds every event to one authenticated genesis without making the random context identifier depend on genesis. |
| O-04 content descriptor | `INCLUDE` | `K/AP` under O-04 | Authenticates class, type, length, suite, shape, value and geometry. Raw content/opening are excluded. |
| Author-carried event reference/cache hint | `EXCLUDE` | Convenience representation only | A consumer recomputes the reference. A carried value may be compared only after derivation and cannot be authoritative. |
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
| `content_type_id` | `INCLUDE` | Closed AP registry; granularity must respect removal/privacy claims. |
| `exact_content_length` | `INCLUDE` | Exact non-wrapping integer; zero content-bearing value remains distinct from `NONE`. |
| `commitment_suite_id` | `INCLUDE` | Exact value remains O-06b; unknown values fail closed. |
| `commitment_shape` | `INCLUDE` | Closed single/chunk-tree discriminant. |
| `commitment_value` | `INCLUDE` | Full future O-06b output, never a locator or storage hash. |
| chunk-geometry presence | `INCLUDE` | Absence is valid only for the single shape and cannot alias zero geometry. |
| chunk size/count/tree geometry | `INCLUDE` when present | Exact O-06b representation; O-08 supplies enforceable profile maxima. |
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
| claimed removal authorization, legal hold or data-class decision | `DERIVE` from the deterministic AP replay prefix and authenticated policy events | An author cannot make removal authorized by declaring it so. |
| local deletion/quarantine result | `EXCLUDE` | `RS` owns custody and loss reporting; runtime outcome is not application authority. |
| relay/provider acknowledgement, timeout, retry/peer count or quota state | `EXCLUDE` | O-13 forbids inferring irreversible authority from operational convenience. |

The target-reference and target-commitment pair is the complete v0 target
identity. Adding another field that changes applicability or authorization
requires a K-01 inventory amendment before O-06b.

### 3.4 Authorization and application-owned identifiers

The authenticated event does not carry an author-selected "current policy"
selector. Authorization is evaluated against the deterministic, authenticated
AP state visible at the event's canonical replay prefix, including the
credential grant and any actionable rotation, revocation or policy events.
The resulting AP decision covers the exact action, context, credential and
effective policy state.

If a future profile needs an explicit grant or policy reference because the
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

O-06b must instantiate an injective encoding satisfying all of these rules:

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
   form the O-01 maximal antichain; the direct author predecessor is encoded
   separately and excluded from that frontier;
8. a decoder never repairs, clamps, truncates, normalizes or ignores trailing
   semantic bytes;
9. the regenerated transcript is not a generic wire document; O-11 may choose
   a different wire/storage representation without changing these semantics;
10. any two distinct valid field assignments must produce distinct preimages
    before the cryptographic primitive is applied.

The final item is an O-06b written proof obligation and an O-06c adversarial
property. This document does not claim it has been met by exact bytes.

## 5. Dependency separation and non-circularity

| Boundary | O-06a decision | Remaining owner/work |
| --- | --- | --- |
| O-02 / O-06 | Include the credential identifier; derive key and signature algorithm from authenticated credential state. Do not let an event choose its verification algorithm. | O-14 owns the exact signature-suite registry and downgrade rules. AP/O-02 own authority. |
| O-03 / O-06 / O-07 | Later events include a genesis reference derived over the complete genesis signed transcript. It is not the random context identifier and creates no self-reference. | O-07 defines necessary genesis fields and authority; O-06b defines exact reference bytes. |
| O-04 / O-06 | Commitment is computed first from content/opening/context; its descriptor enters the event transcript; the event reference is computed last. The commitment never includes the event reference. | O-06b selects exact commitment/reference suites; O-06c falsifies the construction. |
| O-06 / O-08 | Semantic counts, lengths and geometry slots exist; exact cryptographic widths may be fixed by O-06b. | O-08 supplies measured enforceable profile maxima and activation bounds. |
| O-06 / O-10 | O-06a identifies rejection sites and safe distinctions without assigning stable codes. | O-10 closes the bounded taxonomy after exact fields close. |
| O-06 / O-11 | K regenerates transcript/reference preimages from validated semantics. | O-11 owns wire/storage decoding and canonical representation. |
| O-05/O-12 / O-06 | No physical-time field exists in the v0 K transcript. | A future time-bearing AP profile must close O-12 for its own committed content. |

This separation removes the apparent genesis cycle and prevents runtime bounds,
error names, wire formats or application authority from being smuggled into a
cryptographic-identifier decision.

## 6. Event-reference grinding and policy prohibition

A reference used as the K-06 tiebreak is deterministic from an author-controlled
signed transcript. An authorized author may vary otherwise valid inputs — most
notably fresh content/opening choices — and spend work to bias bits of its own
future reference. Signatures make the chosen transcript attributable; they do
not make its digest an unbiased random beacon.

Therefore:

- K-06 reference order is only a deterministic replay schedule for events
  already proven concurrent;
- replay position MUST NOT confer authorization, priority, ownership,
  first-writer-wins truth, expiry, removal authority or permission for an
  irreversible external effect;
- AP must evaluate semantic conflicts independently under K-07; and
- a future profile claiming fairness or unpredictability requires a separate
  mechanism and threat analysis.

O-06c must exercise grinding as a non-interference property: changing replay
position may change evaluation order but cannot change credential validity,
causal classification, fork evidence or the rule that AP owns conflict policy.

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
- carried/recomputed event-reference mismatch;
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

### O-06b — exact cryptographic profile

A separately approved security/crypto task must select exactly one v0 profile:
the digest/commitment suite registry, exact versioned domains, every transcript
byte and width, randomizer rule, chunk construction, algorithm-agility and
downgrade behavior, plus an explicit injectivity argument. It must not select
the signature-suite registry owned by O-14, define O-07 checkpoint authority,
set O-08 runtime maxima, assign O-10 codes, create a conformance corpus or
authorize production implementation. O-06 remains `OPEN` after O-06b.

### O-06c — bounded executable falsification

A later isolated tool must test framing injectivity, absence/emptiness,
cross-role/context separation, non-circularity, cross-event chunk equality,
parent canonicality, suite binding, unknown-suite rejection, structural versus
binding failures, collision handling, grinding non-interference and bounded
work. It must rerun C0.2d/C0.2f without changing their recorded results and
must not add `conformance/**` files before the separate K-11 licensing task.
Only a bounded no-counterexample result plus independent review and human
ratification may move O-06 to `DECIDED`.

## 10. Security/privacy consequences and residual risk

The selected inventory prevents unsigned causal, context, descriptor or role
metadata from influencing authoritative behavior and prevents session,
transport and storage identifiers from substituting for event identity. It
does not make stable references private: authorized recipients can correlate
equal references and graph structure, and any profile exposing them outside
the protected application object inherits that correlator.

The inventory is not an exact encoding or proof. Collision resistance,
commitment hiding/binding, randomizer misuse, tree construction, parser safety,
runtime capacity and algorithm downgrade remain open. Bounded O-06c evidence
will not prove absence of counterexamples outside its envelope. A hostile
authorized author can withhold parents, equivocate, reuse randomizers or grind
its replay position; the protocol can attribute and classify these actions but
cannot force honest claims.

Reopen this inventory if exact encoding cannot be injective without changing a
semantic field; O-07 genesis cannot bind without self-reference or ambiguity;
an AP rule needs an unauthenticated input; a signature-suite decision requires
an author-controlled algorithm field; a supported profile needs physical time
inside K; or executable evidence finds a cross-role, cross-context,
non-circularity or replay-policy counterexample.

## 11. C0.3 gate

O-06a does not make C0.3 executable. O-06b, O-06c, O-07, O-08, O-10 and O-14
remain blockers; O-12 additionally blocks any time-bearing profile. O-11 does
not block a transcript-only corpus but must close before supported persistence
or remote admission. K-11 requires a separate exact-path licensing amendment
before C0.3 creates any normative corpus file. No supported adapter may persist
current application-ledger objects while this `NO-GO` remains in force.
