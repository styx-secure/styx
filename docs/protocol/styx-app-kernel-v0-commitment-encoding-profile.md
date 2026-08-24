# Styx v0 payload-commitment and chunk-tree profile — O-06b-2

- **Status:** selected O-06b-2 profile, amended by the C0.2k
  credential/sequence binding; combined executable falsification remains open
  under O-06c.
- **Authority:** Issue #223, ADR-0007, ratified K-01 through K-11, O-01 through
  O-05, O-09, O-06a and O-06b-1.
- **Exact evidence bases:** original O-06b-2 selection
  `cf93e6fa9136a383e125dfee76312bb5ca957455`; C0.2k amendment base
  `745de6d8954a39ad3a39e9ccc5303ba08fa8508c`.
- **Language:** English is canonical for language-neutral review.
- **Ratification:** every selection below remains proposed until `maverde73`
  ratifies the exact final PR HEAD after independent and human crypto review.

This document instantiates the payload-commitment, chunk-leaf and interior-node
roles allocated by O-06b-1. It fixes one hash-only randomized-opening suite and
one left-complete chunk-tree construction. C0.2k supplies an isolated bounded
model and adversarial evidence for the context amendment only; it creates no
product implementation, wire/storage format, conformance claim or production
authority. O-06 remains `OPEN`; O-06c remains mandatory, and C0.3 remains
`NO-GO`.

## 1. Selected suite and closed agility rule

| Property | Styx protocol v1 selection |
| --- | --- |
| Registry | `styx.commitment-suite.v1` |
| Suite identifier | unsigned `u16` `0x0001`; zero is invalid |
| Digest | SHA-256, NIST FIPS 180-4 section 6.2 |
| Commitment output | all 32 digest octets; truncation is forbidden |
| `commitment_value` length | exactly `0x00000020` (32 octets) |
| Opening randomizer | exactly 32 octets |
| Active suites | exactly `0x0001` |
| Negotiation/fallback | none |

The active commitment suite is derived from the authenticated Styx protocol
version. A carried `commitment_suite_id` is derive-and-compare data: it MUST
equal the derived value. A mismatch, unknown value, unsupported implementation
or attempted fallback fails closed before allocation, hashing, signature work,
graph traversal or fetch. A consumer never tries several suites until one
succeeds.

The C0.2k amendment is a pre-corpus supersession inside protocol v1 and suite
`0x0001`: there is no released C0.3 corpus, supported consumer or persisted
population for the former context grammar, and the ratified dependency order
required this amendment before O-06c. From this amendment onward, only the
84-octet section 2 grammar is valid. The former 44-octet grammar is invalid;
there is no compatibility decoder, fallback, mixed-profile mode or migration
population.

Any later incompatible change after a corpus or supported consumer exists
requires a new ratified protocol/profile version, commitment-suite identifier
and domain-registry version. It cannot reuse the v1 identifiers or domains with
different semantics.

Primary evidence:

- [NIST FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4) defines SHA-256 and
  its 256-bit result. NIST's announced revision removes SHA-1 and updates
  guidance; it does not withdraw SHA-256. Withdrawal or material weakening of
  SHA-256 remains a reopen predicate.
- [Web Cryptography Level 2](https://www.w3.org/TR/webcrypto/#sha) registers
  `SHA-256` for `SubtleCrypto.digest()`. The operation consumes one complete
  `BufferSource`; the API exposes no streaming digest interface. Its
  [`getRandomValues`](https://www.w3.org/TR/webcrypto/#Crypto-method-getRandomValues)
  algorithm fills a caller-provided integer typed array from a cryptographically
  secure random source and rejects requests over 65,536 octets; the selected
  32-octet request is within that quota. `SubtleCrypto` is exposed only in a
  secure context. A missing API, insecure context, exception or short result is
  a blocking runtime capability failure.
- [`Random.secure()`](https://api.dart.dev/dart-math/Random/Random.secure.html)
  is the Dart platform's cryptographically secure generator constructor and
  throws `UnsupportedError` when no secure source is available. This is
  reference-runtime evidence, not a production primitive selection.
- The exact JavaScript lock already contains `@noble/hashes` `1.8.0`, and the
  Dart reference declares `package:crypto` `^3.0.7`. These are existing runtime
  evidence only, not permission to change dependencies and not distribution
  assurance.

## 2. Domains and authenticated commitment context

The O-06b-1 domains are reused without reinterpretation:

```text
D_COMMIT = 53545958000100050000000000000000
D_LEAF   = 53545958000100060000000000000000
D_NODE   = 53545958000100070000000000000000
```

Each is exactly 16 octets and is the first 16 octets of its corresponding
preimage, with no preceding caller-supplied bytes.

The exact commitment context is:

```text
CTX = commitment_suite_id:u16
   || styx_protocol_version:u16
   || application_profile_id:u32
   || application_profile_version:u32
   || context_identifier:opaque32
   || credential_identifier:opaque32
   || author_sequence:u64
```

`CTX` is exactly 84 octets. Its first 44 octets are the ratified O-03 tuple
prefixed by `commitment_suite_id`; the suite prefix is required by the C0.2f
structural correspondence and is not part of the O-03 context. C0.2k appends
exactly common transcript field 11, the 32-octet grant-rooted
`credential_identifier` selected by C0.2j, followed by common field 12,
`author_sequence`, as unsigned big-endian `u64`. Sequence zero is structurally
valid for a credential's first event; later sequencing legality remains owned by
O-01. Values never wrap and no shorter integer representation is accepted.

The genesis reference is deliberately absent. Compared with the C0.2f symbolic
`context_token`, `CTX` also carries the ratified O-03 protocol-version member and
the C0.2j author slot. The symbolic token bundled a genesis reference instead;
this byte profile tightens that symbolic token to authenticated fields already
present in the application transcript. O-07 still owns the complete genesis and
checkpoint evidence contract.

## 3. Exact preimages

`len32(X)` is the O-06b-1 `u32` big-endian octet length of `X`. Every preimage
has the exact form `D || len32(body) || body`.

### 3.1 Chunk leaf

```text
B_L = CTX
   || content_type_id:u32
   || leaf_ordinal:u64
   || leaf_length:u32
   || opening_randomizer:32
   || leaf_octets

leaf_i = SHA256(D_LEAF || len32(B_L) || B_L)
```

The fixed prefix of `B_L` is 132 octets. The complete leaf preimage is therefore
`152 + leaf_length` octets. `leaf_ordinal` is zero-based and strictly less than
the authenticated chunk count. `leaf_length` MUST equal the number of terminal
`leaf_octets` exactly.

The object's one opening randomizer is repeated in every leaf. It is never
replaced with per-leaf derived values. Fresh randomizers make equal chunks in
different events produce distinct leaf preimages; the ordinal makes equal
chunks inside one event produce distinct leaf preimages. Equality of the
resulting digests for distinct preimages -- as randomizer freshness and ordinal
separation require here -- is a collision finding under A1, never an accepted
alias.

### 3.2 Interior node

```text
B_N = commitment_suite_id:u16
   || subtree_leaf_count:u64
   || left_child:32
   || right_child:32

node = SHA256(D_NODE || len32(B_N) || B_N)
```

`B_N` is exactly 74 octets and the complete node preimage is exactly 94 octets.
`subtree_leaf_count` is the exact number of leaves represented by the node and
is at least two. Binding it is a deliberate strengthening of the pure RFC 9162
node hash and prevents a verifier from treating the same child pair as a
different subtree size.

Interior nodes bind the suite and subtree size, but not `CTX`. This is safe only
for v0 whole-object verification: the verifier recomputes every leaf using its
own authenticated context and recomputes the entire root. O-11 MUST revisit this
boundary before defining any inclusion-proof or audit-path format.

### 3.3 Commitment

```text
B_C = CTX
   || content_type_id:u32
   || exact_content_length:u64
   || commitment_shape:u8
   || [chunk_size:u32 || chunk_count:u64 || final_chunk_length:u32
       iff commitment_shape == 0x01]
   || root:32
   || opening_randomizer:32

commitment_value = SHA256(D_COMMIT || len32(B_C) || B_C)
```

`B_C` is 161 octets for single shape and 177 octets for tree shape. The complete
preimage is therefore 181 or 197 octets. The result is all 32 SHA-256 octets.

`commitment_shape` is `0x00` for `SINGLE` and `0x01` for `TREE`; every other
value is invalid. Exact content length, shape, geometry, type, context, suite,
root and randomizer are all bound into the commitment.

## 4. Chunk geometry and tree construction

### 4.1 Geometry container

For tree shape, the O-06b-1 `chunk_geometry:opaque_u32` container has length
exactly `0x00000010` and this exact body:

```text
chunk_size:u32 || chunk_count:u64 || final_chunk_length:u32
```

For single shape geometry is absent. Geometry presence MUST equal the shape:
absent for `0x00`, present for `0x01`.

All of these predicates are checked on authenticated transcript values before
allocation, hashing, signature work, traversal or fetch:

1. `exact_content_length == 0` requires single shape.
2. Single shape requires `exact_content_length <= 2^32 - 1 - 132`, namely
   `4294967163`, and within the active O-08 maximum.
3. Tree shape requires `chunk_size >= 1`,
   `chunk_size <= 4294967163`, and membership in the authenticated active
   profile's closed chunk-size set. O-08 selects that set's numeric values.
4. Tree shape requires `chunk_size < exact_content_length`, equivalently
   `chunk_count >= 2`.
5. `chunk_count` equals `ceil(exact_content_length / chunk_size)`, computed with
   checked non-wrapping arithmetic.
6. `chunk_size * (chunk_count - 1)` is computed without wrap, and
   `final_chunk_length` equals
   `exact_content_length - chunk_size * (chunk_count - 1)`.
7. `1 <= final_chunk_length <= chunk_size`.
8. Exact content length, chunk count, depth and aggregate work remain within
   the active O-08 maxima. Representable integer ceilings are not supported
   maxima.

`final_chunk_length` is intentionally redundant because ratified O-04 requires
declared final-chunk length. A mismatch is rejected; it is never repaired.
`chunk_size` set-membership failure is a structural rejection. Descriptor
legality is therefore a function of the authenticated active AP profile and
version, consistent with O-06b-1's closed AP registries.

This byte profile deliberately tightens the C0.2f symbolic legality domain in
exactly two geometry dimensions:

1. tree shape requires `chunk_count >= 2`, whereas
   `tools/causal-flow-simulator/payload_model.py:380` also admits
   `chunk_count == 1` in its bounded `CHUNKED` arm; and
2. `chunk_size` must belong to the authenticated active profile's closed set,
   whereas `tools/causal-flow-simulator/payload_model.py:378` admits every
   bounded value from one through `max_chunk_size`.

Both byte-level restrictions are strict subsets of the model's legality
predicate in their respective dimensions. This is a structural comparison, not
a claim that the byte profile's numerical domain is contained in C0.2f's
concrete search envelope: that envelope remains `max_chunk_size = 256` and
`max_chunks = 8`. Removing legal vectors cannot manufacture a counterexample
within that envelope, and no claim is made for production-scale geometries that
the bounded search did not exercise.

Leaf boundaries are derived only from authenticated geometry:
`leaf_length = chunk_size` for every ordinal below `chunk_count - 1`, and
`leaf_length = final_chunk_length` for the last ordinal.

### 4.2 Left-complete tree

For single shape the object has exactly one leaf: `leaf_ordinal = 0` and
`leaf_length = exact_content_length`; its root is that leaf digest.

The tree follows the left-complete split rule of
[RFC 9162 section 2.1.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.1):

```text
root = leaf_0
       iff commitment_shape == 0x00

root = MTH(leaf_0, ..., leaf_(n-1)), n = chunk_count, n >= 2
       iff commitment_shape == 0x01

MTH(one element) = that element

MTH(m elements), m > 1:
  k = largest power of two strictly less than m
  left  = MTH(first k elements)
  right = MTH(remaining m-k elements)
  result = node(subtree_leaf_count=m, left_child=left, right_child=right)
```

Only the left-complete split rule is adopted from RFC 9162. Styx deliberately
replaces its one-octet leaf/node prefixes with the registered 16-octet domains
and `len32` framing, and binds the additional leaf and node fields defined in
section 3. `MTH(one element)` here receives an already-computed Styx leaf digest
rather than hashing raw content again, and the RFC empty-tree case is
unreachable because zero-length content uses the non-empty single shape. These
are deliberate profile adaptations, not claims of byte compatibility with RFC
9162.

The tree has `n` leaves, `n - 1` interior nodes and depth
`ceil(log2(n))`. A tree commitment performs `2n` digest invocations: `n` leaf
hashes, `n - 1` node hashes and one commitment hash. Single shape performs two.
With an explicit node stack, peak hashing state is
`O(chunk_size + depth * 32)`. The one-shot WebCrypto single-shape path may need
an approximately 4 GiB `BufferSource` at the framing ceiling; O-08 MUST choose a
materially smaller supported maximum.

## 5. Opening and randomizer rules

The semantic content opening is exactly the pair:

```text
(opening_randomizer:32, content_octets:exact_content_length)
```

The opening never enters the application-event transcript. O-11 owns its
wire/storage container, colocation, locator and fetch protocol.

The randomizer MUST:

- be generated by one supported runtime CSPRNG call per commitment, returning
  exactly 32 octets;
- be uniform and independent in the deployment assumption;
- never be derived from content, context, credential, time, author sequence or
  another event field;
- never be reused across commitments; and
- fail closed before event creation on a short read, exception, absent API,
  non-secure browser context or missing implementation. There is no fallback to
  `Math.random`, `dart:math Random()`, time, a counter or a derived value.

Every 32-octet value, including all zeroes, is structurally valid. Rejecting
zero would make a legitimately generated opening unverifiable and cannot prove
freshness. Producer-side repeated-output detection may diagnose a broken RNG,
but freshness and malicious derivation remain unverifiable honest-producer
obligations.

Deterministic randomizer injection may exist only behind a future conformance
interface that is absent from production builds. No such interface is created
here.

## 6. Logical-removal tail

The O-06b-1 tail remains unconditionally:

```text
target_event_reference:opaque32 || target_commitment:opaque_u32
```

The logical-removal role is a control event. C0.2i therefore adds the structural
cross-field rule `event_role == 0x01 => content_class == NONE`. A violating
event is rejected before commitment/opening processing, target lookup or AP
evaluation. The tail remains unchanged and authenticated; `NONE` supplies no
opening and cannot itself create a pending root.

For Styx protocol v1, the tail length is derived from the single commitment
suite active for the authenticated protocol version, never from the directive's
own descriptor and never from the target. Suite `0x0001` therefore requires
`target_commitment` length exactly `0x00000020`. Every other length is a
structural rejection before target lookup. The analysed `{0, 32}` alternative
is rejected because it adds an inverse arm without actionable information.

The 32 octets are never a framing-validity input. Target-class applicability is
evaluated before commitment equality. Equality is checked only when the target
is retained, validated and `DETACHABLE`; then the value MUST equal the target
descriptor's commitment, and mismatch is a binding observation on a valid
directive with no removal effect.

For a retained validated target of class `NONE` or `REQUIRED`, equality is
vacuous and the directive is inapplicable regardless of these octets. For an
absent or non-retained target, readiness is deferred. No canonical filler,
sentinel or reserved value exists; implementations MUST NOT require, generate,
normalise or infer meaning from all-zero or any other particular value. A filler
cannot be conditioned on the target class because structural validation precedes
target lookup; it would manufacture an outcome for a directive that O-04 already
declares inert; and any fixed constant could equal a genuine commitment value.

An honest producer targets a retained accepted causal ancestor and therefore
knows its descriptor and commitment. The unconstrained case represents a
producer defect, not a recommended production path.

The unconstrained octets are nevertheless authenticated transcript bytes.
Changing them changes the transcript, event reference, exact duplicate key and
potential K-06 concurrent tiebreak position, absent a SHA-256 collision. The
variants are distinct events, not encodings of one event. This creates a 2^256
grinding space for an inapplicable directive. It confers no AP authority,
priority, finality or irreversible effect. A removal directive is necessarily
`NONE`, so it cannot create an opening hole or change AP state merely through
these tail octets. If it causally descends from another pending root, it remains
a pending descendant until that root is released.

## 7. Verification inputs and rejection classes

Commitment recomputation uses only:

1. authenticated fields of the validated event descriptor;
2. the supplied content octets; and
3. the supplied 32-octet randomizer.

Unauthenticated geometry, length, type, suite or shape values from a wire or
storage container are compared with authenticated values and rejected on
mismatch; they are never verification inputs. Chunk boundaries are derived
from authenticated geometry. The supplied octet count MUST equal
`exact_content_length`; trailing or missing octets are binding observations.
K hands no content to AP as verified until the complete object verifies.

The mandatory work order is:

1. decode only the bounded fixed-width descriptor framing and reject malformed
   lengths, presence octets and trailing data without attacker-sized
   allocation;
2. derive the protocol/profile suite and local O-08 limits, then compare the
   carried suite, class, shape and profile-relative closed-set membership;
3. validate exact container lengths, shape/presence consistency and every
   geometry equation using checked non-wrapping arithmetic;
4. reject any declared length, count, depth or aggregate-work value outside the
   active limits before signature work, graph traversal, fetch or payload-sized
   allocation;
5. authenticate the regenerated event transcript; and only then
6. accept supplied opening/content bytes for complete recomputation, allocating
   or streaming no more than the already validated bounds permit.

No attacker-declared count, length or geometry controls work before these
checks. This ordering selects no O-08 number and no O-11 decoder.

Structural rejection sites include unknown protocol/domain/suite/class/shape,
unsupported implementation, carried-suite mismatch, invalid randomizer width,
invalid container length, inconsistent shape/presence, geometry outside the
authenticated profile, arithmetic overflow, impossible chunk count/final
length, malformed/truncated/overlong input and extra preimage octets.

Binding observations leave the event structurally valid and include missing
content/opening, supplied-length mismatch, commitment mismatch, target
commitment mismatch, unexpected bytes for `NONE`, unavailable target and
content previously logically removed. This document assigns no stable O-10
code and creates no new remote-facing outcome.

## 8. Written inverse and bounded proposition

The following inverses are proof devices, not normative O-11 decoders.

`P_L` reads and verifies `D_LEAF`, then `len32`, isolates exactly that body and
requires end of input. It reads the 132-octet fixed prefix; the remaining
`len32 - 132` octets are `leaf_octets`, and their number MUST equal
`leaf_length`. The split is unique.

`P_N` reads and verifies `D_NODE`, then `len32`, then the four fixed-width fields
totalling 74 octets, and requires exact end. The inverse is unique.

`P_C` reads and verifies `D_COMMIT`, then `len32`, isolates the body and requires
end of input. It reads 84-octet `CTX`, `content_type_id:u32`,
`exact_content_length:u64` and `commitment_shape:u8`. Shape `0x00` consumes no
geometry; shape `0x01` consumes exactly 16 geometry octets. It then reads
`root:32`, `opening_randomizer:32` and exact end. The inverse is unique.

Therefore two assignments that differ in any suite-owned field have distinct
preimages. Domains separate all seven v1 roles. Framing is prefix-free:
appending bytes makes embedded `len32` inconsistent, so SHA-256 length extension
cannot turn one valid registered preimage into another. Suffix-free padding is a
distinct property and is not the reason for this conclusion. Single/tree shape
cannot alias because shape and geometry differ and tree shape requires at least
two leaves.

This discharges O-06b-1's suite-interior injectivity condition. It does not make
SHA-256 injective. Binding still depends on collision and second-preimage
resistance, and AP-transition-block injectivity remains an AP/C0.3 obligation.
O-06c must attempt executable falsification.

## 9. Binding and hiding assumption ledger

| Id | Assumption | Purpose | Status |
| --- | --- | --- | --- |
| A1 | SHA-256 collision resistance | commitment binding; leaf/node/root and inherited reference uniqueness | standard computational assumption |
| A2 | SHA-256 second-preimage resistance | leaf/node substitution and subtree grafting | standard computational assumption |
| A3 | hash inputs containing content also contain a secret uniform 32-octet randomizer and SHA-256 behaves as a hiding hash/random oracle for this family | ledger-only candidate/equality hiding after opening destruction | non-standard-model assumption |
| A4 | runtime CSPRNG emits uniform independent 32-octet values | randomizer freshness | deployment assumption |
| A5 | section 8 framing injectivity | unique structural preimages | proved here |
| A6 | honest producer does not reuse or maliciously derive the randomizer | practical cross-event separation | unverifiable producer obligation |

There is no statistical or information-theoretic hiding claim. Binding does not
prove content truth. Length, type, shape, geometry and commitment remain
correlatable retained metadata.

### 9.1 Two-reduction appendix

**Selected salted-hash family.** Every selected digest whose caller-supplied
preimage directly contains content octets also contains the same secret,
uniform 32-octet opening randomizer. Interior-node preimages contain only child
digests; their hiding argument composes inductively from randomized leaf
digests, because testing a candidate subtree requires first recomputing its
leaves with the unknown randomizer. The top-level commitment directly binds
both that randomized root and the same randomizer. Under the
random-oracle/hiding-hash assumption, an observer without the randomizer cannot
test a candidate content value against the retained commitment more efficiently
than guessing the randomizer or breaking that assumption. This is the selected
argument. It is not a standard-model proof for SHA-256 as deployed.

**Rejected HMAC family.** The alternative uses the fixed-width 32-octet opening
randomizer as the HMAC-SHA-256 key. Its hiding argument is PRF-based. For a fixed
key, equality `HMAC(K,m1) = HMAC(K,m2)` for unequal messages requires a SHA-256
collision at an inner or outer call; that statement is separate from
variable-length HMAC key-padding injectivity, which is out of scope because the
key width would be fixed. This alternative still assumes unproved properties of
SHA-256's compression construction as deployed; it is a different assumption
shape, not a proved-versus-unproved choice.

The alternative is rejected because O-04 ratified **no keyed K commitment
mode**, whereas the selected hash-only construction unambiguously complies.
O-04 recorded that a keyed commitment depends on key secrecy and rotation and
makes late or offline verification depend on key custody. When the proposed key
is the per-commitment opening randomizer, that opening is already the custody
object required by either construction, so the rationale is not perfectly
symmetric; this distinction is surfaced for the independent human crypto gate
and does not authorize the executor to reopen O-04.
Selecting HMAC would require all of: an explicit O-04 clarification that a
per-commitment opening used as a key is permitted; an O-06b-1 section 4
clarification that "preimage" means the caller-supplied primitive input rather
than internal compression input; and renewed `maverde73` ratification. The
section 4 point is a disambiguation, not a current defect. The selected hash-only
construction satisfies either reading and needs no reopen.

Destroying the randomizer, not merely the content, removes the ledger holder's
candidate-testing capability. Conversely, revealing the randomizer to a party
without content grants that capability. The opening MUST be protected at least
as strongly as content; O-08 and RS own custody and redundancy numbers.

## 10. Adversarial consequences and boundaries

- Equal chunks in different events have distinct leaf preimages when
  randomizers are fresh. Equal chunks at different ordinals inside one event
  have distinct leaf preimages. Equal leaf digests in either case are a
  blocking collision finding under A1.
- Domain separation prevents leaf/node/commitment/reference/transcript
  confusion. Context binding prevents unchanged-opening reuse across
  application contexts, credentials and author sequences.
- `subtree_leaf_count`, top-level `chunk_count` and the deterministic split rule
  resist subtree grafting and duplicate-last-leaf constructions.
- A malicious producer can derive/reuse or grind a randomizer. K cannot prove
  honest randomness. The signed producer is attributable, but hiding and replay
  position may degrade.
- Randomized openings intentionally remove stable K-level cross-replica content
  deduplication. Storage-level deduplication may reintroduce equality leakage.
- Chunk-size choice is a profile fingerprint. O-08 owns a closed set to reduce
  variation. Padding remains outside exact-content semantics.
- Chunk-granular refetch can reveal which part is missing and may violate remote
  opacity. O-11 owns fetch design; v0 defines no inclusion proof, audit path,
  partial acceptance or partial redaction.
- Verification is whole-object. Under C0.2i, one unavailable `REQUIRED` opening
  defers exactly that event and its causal descendants; in a fork-free,
  non-stale context, causally independent events remain applicable even when
  they sort later. The subtree can remain
  pending indefinitely, and delayed reveal can trigger a large reversible
  replay. O-08 owns production bounds.
- The superseded 44-octet `CTX` accepted cross-credential descriptor copy and
  same-credential cross-sequence self-copy. The selected 84-octet grammar makes
  an unchanged commitment/opening fail under either changed field. A holder who
  knows content and opening can nevertheless recompute a fresh valid commitment
  for another context, and same-credential same-sequence siblings remain fork
  evidence. AP MUST NOT infer possession, knowledge, authorship, originality,
  first submission, truth or authority from successful verification.
- No erasure, deletion, post-removal unlinkability, anonymity, compliance,
  interoperability, audit or readiness claim is made.

O-06b-1 may be edited only to fill its named O-06b-2 slots and update references
or status. A change to its width, domain, role, framing, body cap or reference
derivation is a formal reopen and is blocked by this task.

## 11. O-06c executable handoff

C0.2i adds a separate v2 bounded model for the amended pending fold while the
v1 C0.2d/C0.2f evidence remains immutable. After C0.2j and C0.2k, O-06c MUST
build an independent bounded corpus/model that attempts at least:

1. framing injectivity for all three preimages and separation across all seven
   v1 roles;
2. cross-context opening non-transferability and cross/intra-event leaf
   separation;
3. single/tree non-aliasing, exclusion of one-leaf tree, and zero-length single
   remaining distinct from `NONE`;
4. geometry inconsistency rejected before allocation, checked arithmetic and
   bounded work independent of attacker-declared inflation;
5. subtree grafting and duplicate-last-leaf resistance;
6. prefix-freeness and length-extension non-applicability;
7. randomizer width, CSPRNG failure, unknown suite/shape and fallback failure;
8. commitment equality/mismatch, verifier use of authenticated fields only and
   complete-object verification;
9. grinding in both K-06 ordering directions, including the fork-free
   concurrent grant/revoke laundering counterexample; an unavailable
   `REQUIRED` event blocks exactly its causal subtree only while the context is
   fork-free, whereas any admitted fork quarantines the whole v0 AP context;
10. control-role/`NONE` enforcement before opening or AP work;
11. rejection of the superseded 44-octet grammar and unchanged-opening
    cross-credential/cross-sequence copy, while retaining same-credential,
    same-sequence equivocation siblings as verifying fork evidence; and
12. byte-identical reruns of the combined C0.2d/C0.2f v1 and C0.2i v2 required
    suites; and
13. deterministic work-order instrumentation and per-stage counters for parsing,
    transcript regeneration, hashing, graph construction, opening verification
    and replay, so attacker-controlled work is visible before the final verdict.

### 11.1 Removal-tail octet-variance property

Fix one validated event set and a removal directive `D` by credential `c` at
sequence `s`, with target bytes `v`. Construct `D'` with `v' != v` and every
other semantic field identical. Evaluate separate otherwise-identical runs.
`D` and `D'` are distinct events, never alternate encodings of one event.

Where the equality rule is vacuous because the validated target is `NONE` or
`REQUIRED`, or is absent/not retained, O-06c MUST show:

- structural validity, inapplicability/deferred classification, absence of a
  removal effect, target validity, target event reference, target descriptor,
  target binding-observation status, target retention/presentation and
  graph-set causality remain invariant;
- the full AP projection remains invariant when the directive's own content is
  `NONE`, `DETACHABLE`, or verified `REQUIRED`;
- regenerated transcript, event reference, exact duplicate identity and K-06
  ordering input differ, and O-06c explicitly asserts each difference; equality
  of references is a blocking collision finding, never a pass;
- the K-06 position relative to concurrent peers may differ where reference
  order differs, but happens-before/concurrency relations do not; O-06c MUST
  demonstrate that this deterministic-order variance remains separate from the
  invariant AP result;
- any implementation that collapses `D` and `D'` as the same intent against the
  same target is non-conforming, and O-06c MUST carry this as a directed negative
  case;
- a directive cannot itself have `REQUIRED` content. When it descends from a
  pending root, both tail variants remain in that same pending causal subtree;
  independent events outside the subtree remain applicable only when each
  variant is evaluated in a separate fork-free transcript, and no authority,
  priority, finality or irreversible effect follows; and
- admitting both variants at the same credential/sequence is same-author
  equivocation that permanently quarantines the whole v0 AP context, never
  deduplication, silent reconciliation or a winning removal.

No octet value may make a directive remove a `NONE`, `REQUIRED` or absent
target, alter authorization, first-writer truth, expiry or removal authority,
confer priority or finality, or permit an irreversible external effect.

## 12. Remaining ownership and reopen predicates

- **O-07:** genesis/checkpoint contents, authority, acceptance, rollback,
  equivocation, horizon and late admission remain open. The commitment context
  deliberately excludes genesis reference.
- **O-08:** every supported maximum, closed chunk-size set, fan-out, memory
  envelope, custody redundancy and halt envelope remain open.
- **O-10:** stable codes and safe outcome combination remain open.
- **O-11:** wire/storage/opening containers, locators, fetch, inclusion proofs
  and extension rules remain open.
- **O-12/O-13/O-14:** no physical time, destruction permission, erasure claim,
  signature suite or key/signature encoding is selected.
- **C0.2j / C0.2k:** C0.2j selects collision-resistant K credential identity
  and grant binding. C0.2k widens `CTX` to bind that exact identity and author
  sequence, rederives all dependent arithmetic and inverses, and supplies
  bounded model evidence. O-06c must still falsify the combined construction.
- **O-15/O-16:** lifecycle/profile succession and finality/stability remain open;
  v0 is version-pinned and no irreversible-effect claim follows.

Reopen O-06b-2 if the written inverse fails, O-06c finds a counterexample, the
selected runtime cannot support bounded safe hashing/randomness, O-08 cannot
choose viable bounds, O-11 requires context-bound interior witnesses, SHA-256
is withdrawn/materially weakened, or a future protocol version requires a new
commitment family. A preference for HMAC triggers the explicit three-part reopen
and renewed-ratification path in section 9.1; it is never an executor choice.

After this amendment, C0.2k is selected but does not close O-06. O-06c remains
mandatory over the combined C0.2j/C0.2k construction. K-11 still gates any
normative corpus file, and C0.3 remains `NO-GO`.
