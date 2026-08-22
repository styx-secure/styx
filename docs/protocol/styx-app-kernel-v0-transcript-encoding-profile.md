# Styx v0 application-event transcript encoding profile — O-06b-1

- **Status:** selected O-06b-1 transcript profile, amended by the selected
  O-06b-2 commitment profile; executable falsification remains open under
  O-06c.
- **Authority:** Issue #221, ADR-0007, ratified K-01 through K-11, O-01 through
  O-05, O-09 and the O-06a semantic inventory.
- **Exact evidence base:**
  `4c2fecd0e9a81421b1d74f988572599162ac3095`.
- **O-06b-2 amendment base:**
  `cf93e6fa9136a383e125dfee76312bb5ca957455` under Issue #223.
- **Language:** English is canonical for language-neutral review.
- **Ratification:** O-06b-1 was ratified under Issue #221. The O-06b-2
  amendments remain proposed until `maverde73` ratifies the exact final PR HEAD
  under Issue #223 after independent and human crypto review.

This document fixes exact bytes only for the v0 application-event signature
transcript, the seven-role domain registry and event/genesis-reference digest
derivation. It deliberately does **not** select payload-commitment or chunk-tree
internals itself, a signature suite, genesis contents, a wire/storage
representation, an executable vector or implementation. The exact commitment
internals are now selected separately by
`styx-app-kernel-v0-commitment-encoding-profile.md`. O-06 remains `OPEN`;
O-06c remains mandatory, and C0.3 remains `NO-GO`.

## 1. Inputs and bounded claim

The normative semantic input is the O-06a inventory in
`styx-app-kernel-v0-identifier-derivation-analysis.md`. Current Dart and
JavaScript layouts are evidence of runtime availability only and do not select
bytes.

O-06b-1 establishes this bounded proposition:

> Given one valid O-06a application-event field assignment, canonical and
> injective AP-schema bytes, and canonical suite-interior bytes, the encoding in
> this document has one deterministic byte string and one unique structural
> inverse. Two assignments that differ in any O-06b-1-owned value have different
> transcript preimages, and no registered role preimage can equal another role's
> preimage.

The proposition is about **preimages**, not SHA-256 outputs. SHA-256 is not
mathematically injective. Reference uniqueness therefore additionally depends
on its collision and second-preimage resistance. Content-binding and hiding
depend on the separate O-06b-2 profile and are not claimed by O-06b-1.

## 2. Primitive and runtime evidence

### 2.1 Selected reference suite

| Property | V0 selection |
| --- | --- |
| Registry | `styx.reference-suite.v1` |
| Suite identifier | unsigned 16-bit integer `0x0001` |
| Digest | SHA-256 as specified by NIST FIPS 180-4 section 6.2 |
| Output | the complete 32 digest octets; truncation is forbidden |
| Active suites in Styx protocol v1 | exactly `0x0001` |
| Negotiation | none; an event cannot choose a suite |

Primary and repository evidence:

- [NIST FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4) defines SHA-256
  and its 256-bit result. NIST has announced a revision, so a future replacement
  is a reopen event rather than an assumed transparent upgrade.
- [Web Cryptography Level 2 section 32](https://www.w3.org/TR/webcrypto/#sha)
  registers `SHA-256` for `digest` and delegates its operation to FIPS 180-4.
  The specification leaves algorithm support implementation-defined; SHA-256
  is the existing browser capability to verify during activation, so the
  browser profile needs no new package for one-shot hashing when that probe
  passes and must fail closed when it does not.
- The exact JavaScript lock already contains `@noble/hashes` `1.8.0`, and that
  package exposes SHA-256 over byte arrays. It is existing implementation
  evidence, not permission to reuse the legacy ledger projection.
- The Dart reference already declares `package:crypto`, whose
  [publisher documentation](https://pub.dev/packages/crypto) exposes SHA-256
  and chunked hashing. The dependency is not a production assurance claim; the
  Dart line remains a reference oracle under ADR-0007. No Dart dependency lock
  or distribution-assurance gate for conformance use is defined by this
  increment, so such use remains blocked rather than inferred from the declared
  dependency range.

SHA-384/SHA-512 would enlarge every causal reference and signed parent frontier
without evidence that v0 needs the additional output width. SHA-3, BLAKE2 and
BLAKE3 would add a non-WebCrypto primitive or another implementation boundary
to the browser profile. A generic user-selected digest and a silent fallback to
another digest are rejected. These are bounded v0 engineering conclusions, not
claims that SHA-256 is universally preferable or indefinitely sufficient.

### 2.2 Agility and downgrade rule

The protocol version, domain-registry version and reference-suite selection are
one closed profile. Styx protocol v1 accepts only suite `0x0001`. The suite ID is
not an event-selected transcript member: it is derived from the authenticated
Styx protocol version. A future suite requires a new ratified protocol/profile
version and a new domain-registry version. It cannot reuse these v1 domains.

Any carried convenience suite value is future O-11 representation data. If such
a value is present, it must equal the suite derived from the validated protocol
version; mismatch, unknown value, missing implementation or attempted fallback
fails closed before signature work, graph traversal or allocation. A consumer
never tries several suites until one succeeds.

## 3. Exact scalar and framing calculus

All integers are unsigned, fixed-width, network-byte-order (big-endian) octets.
The only integer widths are:

| Name | Width | Representable range |
| --- | --- | --- |
| `u8` | 1 octet | `0 .. 2^8 - 1` |
| `u16` | 2 octets | `0 .. 2^16 - 1` |
| `u32` | 4 octets | `0 .. 2^32 - 1` |
| `u64` | 8 octets | `0 .. 2^64 - 1` |

Negative values, non-integers, overflow, wrap, truncation, floating-point
coercion and non-minimal source representations are rejected before encoding.
An implementation may use a wider internal integer only if exact range checks
precede conversion.

`opaque32` is exactly 32 octets. `opaque32_vector` is `count:u32` followed by
exactly `count` adjacent `opaque32` values. `opaque_u32` is `length:u32`
followed by exactly `length` octets. The length is part of the preimage; trailing
octets and short values are invalid. No representable integer ceiling,
including either `u32` or `u64`, is an O-08 activation maximum. O-08 must select
materially smaller enforceable limits, checked before allocation, hashing,
signature work, graph traversal or fetch.

A count over fixed-width `opaque32` elements determines the exact octet extent
as `count * 32` after checked multiplication and therefore satisfies K-02's
explicit-framing requirement. `u64` gives the non-wrapping author sequence a
separate exhaustion boundary from every `u32` registry, count and framing
field; O-08 still owns the supported event rate, lifetime and lower operational
bounds. A supported O-08 envelope that could exhaust `u64` reopens this choice.

Presence values are exactly `0x00` for absent and `0x01` for present; every
other octet is invalid. A present value is followed by its complete field even
when that field is otherwise all-zero. Absence, present empty and present zero
therefore do not alias.

Text is never encoded directly by this profile. AP identifiers and schema fields
enter K as registry integers or already canonical schema bytes. JSON, locale,
Unicode normalization and implementation-native strings are not inputs.

## 4. Closed versioned domain registry

Every domain is exactly 16 octets:

```text
ASCII("STYX") || registry_version:u16 || role_code:u16 || reserved:8*0x00
```

Registry version v1 is `0x0001`. Every reserved octet must be zero. The complete
v1 registry is:

| Role code | Role | Exact hexadecimal domain |
| --- | --- | --- |
| `0x0001` | application-event signature transcript | `53545958000100010000000000000000` |
| `0x0002` | genesis signature transcript | `53545958000100020000000000000000` |
| `0x0003` | event reference | `53545958000100030000000000000000` |
| `0x0004` | genesis reference | `53545958000100040000000000000000` |
| `0x0005` | payload commitment | `53545958000100050000000000000000` |
| `0x0006` | chunk leaf | `53545958000100060000000000000000` |
| `0x0007` | chunk interior node | `53545958000100070000000000000000` |

V1 accepts exactly these seven values. An unallocated role code, non-zero
reserved octet or unknown registry version is unsupported. Adding, splitting or
reinterpreting a role requires a ratified protocol/domain-registry version
change; no later document may assign an eighth v1 code by convention. O-06b-2
must place the exact allocated commitment/leaf/node domain as the first 16
octets of each corresponding preimage, with no preceding bytes, and still owns
the remainder of those complete preimages.

## 5. Application-event signature transcript

Let `D_APP` be domain `0x0001`. The signed byte string is:

```text
application_event_transcript = D_APP || body_length:u32 || body
```

`body_length` is the exact octet length of `body`. Its O-08 active maximum must
be checked before allocating or constructing `body`. Independently of that
smaller operational maximum, it must not exceed `2^32 - 21`, because the
complete transcript adds 20 octets and must itself be representable by the
`len32` used in section 6.

### 5.1 Common body

The total order is normative:

| # | Field | Exact encoding and validity |
| ---: | --- | --- |
| 1 | Styx protocol version | `u16`; exactly `0x0001` in this profile |
| 2 | application-profile identifier | `u32`; closed AP registry; zero is invalid |
| 3 | application-profile version | `u32`; zero is invalid |
| 4 | context identifier | `opaque32` |
| 5 | object kind | `u16`; exactly `0x0001` (`APPLICATION_EVENT`) |
| 6 | event role | `u8`; `0x00` ordinary AP transition, `0x01` logical-removal directive |
| 7 | event type identifier | `u32`; closed AP registry; zero is invalid |
| 8 | schema identifier | `u32`; closed AP registry; zero is invalid |
| 9 | schema version | `u32`; zero is invalid |
| 10 | AP transition block | `opaque_u32`; its canonical interior is fixed by fields 2, 3, 8 and 9 |
| 11 | credential identifier | `opaque32`; context-local and non-secret |
| 12 | author sequence | `u64`; sequence zero is permitted only for that credential's first event; each later value increments by exactly one and never wraps |
| 13 | direct-predecessor presence | one exact presence octet |
| 14 | direct predecessor | `opaque32` iff field 13 is `0x01`; omitted iff `0x00` |
| 15 | causal-parent count and frontier | `opaque32_vector`; count is field 15's leading `u32` |
| 16 | genesis reference | `opaque32` |
| 17 | content descriptor | section 5.2 |
| 18 | role-specific tail | absent for ordinary events; section 5.3 for logical removal |

The AP transition block is not self-describing. Its authenticated schema fixes
one bounded canonical field set and total order. Unknown schema, non-canonical
schema bytes or an AP block that violates its declared length fails closed. The
outer framing is injective even when two schemas use different internal
grammars; semantic injectivity inside each schema remains an AP/C0.3 obligation.

The causal-parent values are full reference outputs, sorted by unsigned-byte
lexicographic order, unique and the O-01 maximal antichain. The vector excludes
the separately encoded direct predecessor and genesis reference. Count zero is
the unique empty frontier and is not absence. A count/length product that
overflows or exceeds the active O-08 envelope is rejected before allocation.

The event role is the O-06a retention-role discriminant. It is encoded once,
not duplicated in the role-specific tail. An unknown event role is invalid.
Author sequence is zero if and only if direct-predecessor presence is `0x00`;
every positive author sequence requires presence `0x01`. The predecessor must
be the immediately prior accepted event for that credential under O-01.

### 5.2 Content descriptor

Every event encodes these leading descriptor fields:

```text
content_class:u8 || exact_content_length:u64
```

`content_class` is `0x00` `NONE`, `0x01` `REQUIRED` or `0x02` `DETACHABLE`.
For `NONE`, length must be zero and the descriptor ends immediately. Commitment,
opening and geometry are absent and must not be represented by zero placeholders.

For `REQUIRED` and `DETACHABLE`, the descriptor continues in this order:

```text
content_type_id:u32
commitment_suite_id:u16
commitment_shape:u8
commitment_value:opaque_u32
chunk_geometry_presence:u8
[chunk_geometry:opaque_u32]  // iff presence == 0x01
```

`content_type_id` is non-zero and belongs to the authenticated AP registry.
`commitment_suite_id` is derive-and-compare data and is exactly `0x0001` for
Styx protocol v1. `commitment_shape` is `0x00` for one value or `0x01` for a
chunk tree. `commitment_value` is exactly 32 octets. Single shape requires
absent geometry; tree shape requires the canonical 16-octet geometry selected
by `styx-app-kernel-v0-commitment-encoding-profile.md`. Its cross-field rules
are mandatory. An outer length mismatch, unknown suite/shape, malformed
geometry or inconsistent presence fails closed. These selected bytes do not
authorize production activation; section 12 records the remaining blockers.

A zero-length content-bearing object remains distinct from `NONE` because its
class, type, suite, shape and commitment are present. Raw content, opening,
locator, ciphertext, compression and storage metadata never enter this
transcript.

### 5.3 Logical-removal tail

When `event_role == 0x01`, append exactly:

```text
target_event_reference:opaque32
target_commitment:opaque_u32
```

The same role structurally requires `content_class == 0x00` (`NONE`). A
candidate with `event_role == 0x01` and any content-bearing class is rejected
before commitment/opening processing, target lookup or AP evaluation. Grant,
revoke, rotate, policy, closure and future disposition control events likewise
use `NONE` and a bounded authenticated representation; their exact K-readable
carriage remains C0.2j work and is not allocated by this profile.

The target-commitment container length is exactly 32 octets, derived from the
suite active for the authenticated protocol version rather than from the
directive descriptor or target. The equality/applicability rule and the absence
of a canonical filler are fixed by
`styx-app-kernel-v0-commitment-encoding-profile.md`. Target absence affects
readiness, not structural identity. Authorization, legal hold, quarantine,
local deletion result, transport acknowledgement, time, quota and retry state
are derived or excluded exactly as O-04/O-06a require and are not appended.

## 6. Reference derivation

Let `H` be the selected SHA-256 operation and `len32(X)` the exact `u32`
encoding of the octet length of `X`.

For a regenerated application transcript `T_app` from section 5:

```text
event_reference = H(D_EVENT_REF || len32(T_app) || T_app)
```

where `D_EVENT_REF` is domain `0x0003`. The result is all 32 digest octets.
Signature bytes and a carried reference are not inputs.

O-07 will define the complete genesis semantic inventory and transcript body.
That future transcript `T_genesis` must begin with `D_GENESIS_SIG` (`0x0002`)
and use this profile's outer `body_length:u32 || body` rule, but this document
does not define its body fields or internal bytes. As with `T_app`, the future
genesis `body_length` must not exceed `2^32 - 21`, so the complete transcript
length remains representable by `len32`. Once O-07 supplies a complete canonical
`T_genesis`:

```text
genesis_reference = H(D_GENESIS_REF || len32(T_genesis) || T_genesis)
```

where `D_GENESIS_REF` is domain `0x0004`. The result is all 32 digest octets.
The conditional formula breaks self-reference: the random context identifier
does not depend on genesis, the genesis transcript does not contain its own
reference, and later events contain only the resulting reference.

Because O-07 bytes are not fixed, O-06b-1 does not claim genesis-transcript
injectivity or unblock O-07 closure. If O-07 cannot instantiate its contents
without altering this outer boundary, O-06b-1 reopens.

## 7. Written injectivity argument

Define `P` as the following proof-only inverse over a candidate application
transcript. `P` is not a normative decoder and does not select O-11 wire/storage
representation.

1. Read exactly 16 octets and require `D_APP`; every other registered domain is
   distinct in the `role_code` field defined in section 4, so cross-role
   equality is impossible.
2. Read `body_length:u32`, isolate exactly that many body octets and require end
   of input. This makes the outer boundary unique.
3. Read fields 1–17 in their single fixed order. Fixed-width fields consume one
   known number of octets. Each `opaque_u32` consumes its `u32` length and
   exactly that many octets; each `opaque32_vector` consumes its `u32` count and
   exactly `count * 32` octets after checked non-wrapping multiplication.
4. The predecessor presence octet uniquely determines whether one `opaque32`
   follows. The parent count uniquely determines the number of 32-octet entries.
   Canonical sort and uniqueness prevent alternate frontier representations.
5. The content-class octet uniquely chooses the `NONE` or content-bearing arm.
   In the latter arm, shape and geometry-presence rules select exactly one arm.
   A control role with a content-bearing arm is structurally invalid rather than
   another inverse branch.
6. The event-role octet uniquely determines absence or presence of the removal
   tail and, for role `0x01`, requires the already parsed class to be `NONE`.
   Require exact end of body after the selected tail.

Each step consumes one unambiguous prefix and leaves one unambiguous suffix.
Therefore `P(encode(x)) = x` for every O-06b-1-owned valid assignment `x`, so two
different such assignments cannot share an encoded preimage.

This proof is conditional in two explicit places:

- an AP transition block must have one canonical injective representation under
  its authenticated schema; and
- commitment/geometry containers have the canonical injective representation
  selected by the O-06b-2 profile.

Two different content byte strings can still produce the same descriptor if the
selected commitment collides, and two different transcript preimages can in
principle produce the same SHA-256 output. O-06b-2 records the exact
binding/hiding assumptions; O-06c must attempt executable framing, role,
context, commitment and collision falsification. Neither is replaced by this
written inverse.

## 8. O-14 compatibility and reopen predicate

O-14 has no ratified candidate set, so this task does not invent one. O-14 must
authenticate the exact section 5 transcript bytes under the verification key and
algorithm derived from authenticated credential state. It must not replace the
signed message with the event reference, add an event-selected algorithm field
or reinterpret a carried suite hint.

O-06b-1 reopens if a later O-14 selection:

1. requires changing the signed transcript or its prehash semantics;
2. cannot authenticate the bounded arbitrary octet string defined here;
3. introduces an algorithm/suite selector that must become an authenticated
   semantic field rather than remaining derived credential state;
4. invalidates the runtime or supply-chain basis for the selected reference
   digest; or
5. demonstrates that a different reference digest is necessary to avoid a
   material additional primitive or unsafe implementation boundary.

Merely using an internal hash different from SHA-256 does not alias the event
reference and is not by itself a reopen reason. O-14 owns its key/signature
encodings, exact registry, downgrade evidence and negative cases.

## 9. Rejection surfaces for O-10

This profile adds rejection sites but does not assign stable codes:

- unknown protocol/domain/suite/object/role/class/shape/schema value;
- event-type/schema inconsistency;
- non-zero reserved domain octet;
- invalid integer, range, length, count, presence or exact-end condition;
- malformed, truncated, overlong or trailing block;
- predecessor/frontier inconsistency, non-canonical order or duplicate parent;
- inconsistent class/length/commitment/geometry arm;
- a control role paired with any content-bearing class;
- removal tail absent, present or malformed for the wrong role; and
- carried-suite mismatch or attempted digest fallback.

O-10 may combine outcomes only when safe recovery remains identical. Remote
errors remain bounded and opaque under the threat model.

## 10. Security and privacy consequences

Exact framing removes cross-field and cross-role reinterpretation from this
surface. A closed digest suite prevents negotiation and fallback downgrade.
Stable 32-octet references still expose equality, graph shape and replay order
to every authorized observer that can see them. SHA-256 does not make the
reference unpredictable: any holder of valid signing-key material, including a
revoked credential, can vary valid inputs and grind its concurrent replay
position. The current v0 AP fold demonstrably permits a concurrently granted
successor to survive revocation in one such order. All O-06a prohibitions on treating that position
as authority, priority, finality or irreversible permission remain in force.

Lengths, parent counts, event type/schema IDs and commitment geometry remain
authenticated metadata visible inside the protected application object.
Nothing here hides outer transport timing, size or routing metadata. SHA-256
availability does not establish that a browser origin, dependency update or
runtime is trustworthy. The Dart package's own documentation disclaims a
professional security review; later implementation and distribution gates must
assess exact resolved artifacts rather than inherit this specification choice.

## 11. Rejected alternatives and reopen conditions

| Alternative | Reason rejected |
| --- | --- |
| Raw concatenation, JSON, CBOR or a generic TLV document | Reintroduces ambiguity/decoder surface or preempts O-11; fixed-order TLS-style presentation suffices. |
| Put the event reference or signature bytes in its own preimage | Circular or resigning-sensitive identity. |
| Carry a per-event digest selector and try fallbacks | Downgrade and algorithm-confusion surface. |
| Use the event reference as the signed message | Changes O-06a and couples signature verification to digest selection. |
| Fix commitment and chunk interiors here | Hides the most contested O-04-dependent construction inside a framing task; O-06b-2 owns it. |
| Fix complete genesis bytes here | Preempts O-07 contents and initial authority. |
| Treat representable integer ceilings as supported maxima | Preempts O-08 and invites allocation/DoS errors. |
| Reuse session, Nostr, storage or legacy-ledger identifiers | Violates the ratified identifier-role separation. |

Reopen O-06b-1 if the written inverse fails; an O-06c counterexample finds an
alias; O-06b-2 cannot fit canonical suite interiors into the selected framed
containers; O-07 needs a different outer genesis boundary; O-14 meets a section
8 predicate; a ratified O-02 credential construction or closed AP registry
cannot fit the widths in section 5.1; later O-08 evidence makes the profile
infeasible or could exhaust the `u64` author sequence; SHA-256 is withdrawn or
materially weakened for this use; or a role/domain must be added, split or
reinterpreted.

## 12. Required next increments and gate

1. **O-06b-2 is selected:**
   `styx-app-kernel-v0-commitment-encoding-profile.md` fixes exactly one
   randomized-opening suite, its preimages and chunk-tree construction.
2. **C0.2i** supplies isolated pending-subtree replay evidence without changing
   these bytes or the historical v1 evidence.
3. **C0.2j** selects collision-resistant K credential identity and K-readable
   grant binding; **C0.2k** then amends the commitment context to bind that
   identity and author sequence.
4. **O-06c** implements bounded adversarial falsification of the combined
   construction, emits deterministic work-order/per-stage instrumentation and
   reruns C0.2d/C0.2f/C0.2i unchanged.
5. Only after O-06c passes independent review and human ratification may O-06
   move to `DECIDED`.

O-06b-1 and O-06b-2 together do not make C0.3 executable. C0.2j, C0.2k and
O-06c are mandatory in that order. O-07, O-08, O-10 and O-14 remain blockers;
O-12 additionally blocks any time-bearing profile. O-11 remains required before
supported persistence or remote admission, and K-11 remains required before any
normative corpus file.
