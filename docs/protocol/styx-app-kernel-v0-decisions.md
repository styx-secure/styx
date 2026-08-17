# Styx application-event semantic kernel — v0 decision registry

- **Status:** non-stable decision registry; not a protocol specification.
- **Authority:** Issue #205 and ADR-0007.
- **Evidence base:** C0.1 at `2815cd5891ca2233bd60e91cb7858d8a8f9777df`.
- **Language:** English is canonical for external, language-neutral protocol
  review. Translations are optional and non-normative.
- **Ratification:** every `DECIDED` entry below is proposed until the product
  owner ratifies this exact document on the final PR HEAD.

This registry decides only the minimum rules justified by current evidence. It
does not define wire bytes, a persistence format, an executable corpus or a
supported product profile. Dart and JavaScript are observations, not oracles.

## 1. Evidence and interpretation rules

The C0.1 corpus contains 36 cases: 25 `MATCH`, 9 `DIVERGENCE` and 2
`UNSUPPORTED`. A match proves only that the related implementations currently
agree. It does not make their common behavior normative. The characterization
and machine-readable evidence are in:

- `docs/architecture/spikes/2026-08-17-application-protocol-c0-characterization.md`;
- `conformance/application-protocol/c0-characterization/cases.json`;
- `conformance/application-protocol/c0-characterization/report.json`.

Independent, retained probes also established three security-relevant classes:

- different current event interpretations can share a hash and signature when
  field boundaries are erased;
- current signatures do not cover every field later used for causality,
  ordering or fork handling; and
- current 32-bit vector serialization can wrap and invert observed causality.

The exact witness inputs are deliberately not committed. The bounded public
record is `docs/security/2026-08-17-ledger-preimage-and-signature-coverage-findings.md`.

The words **MUST**, **MUST NOT**, **SHALL**, **SHALL NOT** and **REJECT** below
express decisions intended to constrain the later specification. They do not
claim that current code conforms.

## 2. Decided rules

### K-01 — Authenticated-semantics completeness

- **Status:** `DECIDED`.
- **Rule:** every field read by a conforming validator, authorization rule,
  convergence rule, fork or replay detector, or deterministic ordering rule
  MUST be authenticated by the signed transcript or MUST be a deterministic
  function of that transcript. A mutable convenience field MUST NOT influence
  protocol acceptance or ordering.
- **Required inventory before C0.3:** protocol version; application and case
  context; author or credential binding; causal metadata; previous or parent
  references; event type; schema and policy identifiers; payload commitment;
  optional clock semantics; and event/content identifier semantics. Each field
  requires an include, derive or exclude decision with rationale.
- **Rationale/evidence:** the current event object carries `eventId`,
  `vectorClock`, `senderPubkey` and other fields that are absent from the
  current hash input (`styx-js/src/ledger/event.js:19-58`,
  `styx-js/src/ledger/event-factory.js:47-68`). Current deterministic ordering
  consumes vector totals and sender keys (`styx-js/src/ledger/fork-merge.js:110-123`).
  Independent probes confirmed that changing causal metadata does not invalidate
  the existing signature.
- **Rejected alternative:** authenticating only the existing
  `previousHash || eventType || payload || hlcBytes` projection.
- **Security/privacy:** this rule prevents validation and convergence from
  trusting unauthenticated semantics. It does not prove that an authenticated
  key is authorized for an application, case or role.
- **Residual/reopen condition:** reopen if a later profile demonstrates a field
  that must influence acceptance without being public or transcript-bound; the
  replacement must provide an equivalent cryptographic commitment.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-02 — Versioned, domain-separated, framed transcripts

- **Status:** `DECIDED`.
- **Rule:** each cryptographic object kind MUST have a fixed, versioned domain
  tag and a TLS-presentation-style transcript consisting only of fixed-width or
  explicitly length-framed validated fields. Raw concatenation without field
  boundaries is forbidden. The transcript is regenerated for hashing and
  signature verification; it is not a generic wire document to parse.
- **Rationale/evidence:** `HASH-004` and `HASH-005` show that current composite
  hashing erases boundaries and empty-segment presence. Current event factories
  feed those unframed segments directly to the hash
  (`styx-js/src/ledger/event-factory.js:109-127`,
  `packages/ledger_engine/lib/src/event_factory.dart:112-141`).
- **Rejected alternatives:** boundaryless concatenation; relying on field
  content to make boundaries “obvious”; using one domain tag for events,
  genesis, receipts and future merge objects.
- **Security/privacy:** framing prevents cross-field reinterpretation; distinct
  tags prevent cross-object replay. It does not select the wire or storage
  encoding.
- **Residual/reopen condition:** deterministic CBOR may be reconsidered only if
  self-description or extension requirements justify a separately reviewed
  dependency and decoder surface. That does not reopen domain separation or
  unambiguous framing.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-03 — Cryptographic inputs are bytes, not ambient text

- **Status:** `DECIDED`.
- **Rule:** JSON, locale-dependent text comparison and implementation-native
  string/code-unit projection MUST NOT be cryptographic or consensus inputs.
  Text admitted by a later schema MUST have a pinned scalar grammar and byte
  encoding before it enters a transcript. Invalid or non-canonical input MUST
  be rejected; a decoder MUST NOT repair, truncate, clamp or normalize it.
- **Rationale/evidence:** `HLC-003`, `HLC-007` and `HLC-008` expose incompatible
  and colliding text-to-byte projections; `HLC-004` and `HLC-005` expose
  permissive/inconsistent parsing; `ORDER-002` and `ORDER-005` expose different
  collation behavior. Dart currently serializes HLC text through code units
  (`packages/ledger_engine/lib/src/hlc.dart:110-120`).
- **Rejected alternatives:** JSON Canonicalization as the event signature
  transcript; `localeCompare`; silently retaining low code-unit bytes; parsing
  an invalid number into a sentinel such as `NaN`.
- **Security/privacy:** strict bytes reduce ambiguous interpretation and parser
  differentials. They do not hide metadata.
- **Residual/reopen condition:** a future text format may be added only with an
  exact grammar, encoding, canonicality rules and adversarial vectors.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-04 — Exact numeric domains and fail-closed arithmetic

- **Status:** `DECIDED`.
- **Rule:** every integer field MUST declare signedness, width and valid range.
  A producer or consumer MUST reject forbidden negative values, overflow,
  precision loss and non-integer input before serialization or state change.
  Wrapping is forbidden.
- **Rationale/evidence:** `VC-002`, `VC-003` and `VC-004` show current signedness
  ambiguity and wrapping. Independent reproduction showed that incrementing a
  maximum current counter and serializing it can restore as zero and reverse a
  causal relation. Current Dart writes signed 32-bit values
  (`packages/ledger_engine/lib/src/vector_clock.dart:75-80`); JavaScript funnels
  unrestricted numbers through 32-bit helpers
  (`styx-js/src/ledger/vector-clock.js:23-26,96-102`).
- **Rejected alternative:** modulo serialization or language-default coercion.
- **Security/privacy:** prevents rollback-like causal corruption and
  cross-runtime numeric disagreement.
- **Residual/reopen condition:** exact widths remain open until the selected
  causal and clock representations provide a justified lifetime bound.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-05 — Conditional physical-time unit

- **Status:** `DECIDED`.
- **Rule:** if v1 carries a physical-time field, its unit SHALL be integer
  microseconds. A source with coarser resolution SHALL fill unavailable low
  digits with zero and MUST NOT fabricate precision. Input outside the later
  declared epoch, width or range MUST be rejected rather than truncated or
  clamped.
- **Rationale/evidence:** `HLC-002` demonstrates a real microsecond value that
  Dart preserves and JavaScript truncates. Microseconds avoid gratuitous loss
  for native profiles while allowing millisecond clocks to project exactly.
- **Rejected alternative:** fixing the protocol unit to the first browser
  clock's resolution, or accepting silent precision loss.
- **Security/privacy:** zero-filled low digits may fingerprint a runtime class.
  C0.3 remains blocked until the specification decides whether precision is
  declared, inferable or hidden, and whether physical time belongs in the
  signed kernel at all.
- **Residual/reopen condition:** reopen the unit only if a bounded precision,
  lifetime or privacy analysis demonstrates that microseconds cannot be
  represented consistently. Width, epoch and range are still `OPEN`.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-06 — Causality precedes deterministic total order

- **Status:** `DECIDED`.
- **Rule:** a conforming implementation MUST determine causal relationship
  before applying a total order. Events proven concurrent SHALL use a bytewise,
  locale-independent tiebreak derived from authenticated event content. Exact
  identifier equality is deduplication, not an ordering tie. A vector-component
  sum is neither causal evidence nor authority.
- **Rationale/evidence:** the current merge orders first by `vectorClock.total`
  and then locale-sensitive sender text
  (`styx-js/src/ledger/fork-merge.js:110-123`). `ORDER-002`, `ORDER-004` and
  `ORDER-005` show divergence or incomplete tie behavior. Current causal fields
  are not fully signature-bound.
- **Rejected alternatives:** `vectorClock.total` as primary order; sender text
  with local collation; comparator equality for distinct events.
- **Security/privacy:** the tiebreak cannot be manipulated through unsigned
  metadata. This rule does not decide the causal representation or application
  conflict policy.
- **Residual/reopen condition:** the exact authenticated content identifier is
  `OPEN`; C0.3 cannot begin until it is defined.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-07 — Ordering and application conflict policy are separate

- **Status:** `DECIDED`.
- **Rule:** deterministic replica order MUST NOT be interpreted as universal
  domain conflict resolution. Application schemas and policies decide whether
  a concurrent action is valid, rejected, superseded, combined or escalated.
- **Rationale/evidence:** ADR-0007 assigns state-transition rules to the
  language-neutral application protocol and workflows/policy to verticals.
  Accounting and case-management operations cannot safely share one semantic
  “last writer wins” rule.
- **Rejected alternative:** treating stable byte order as authorization or
  business truth.
- **Security/privacy:** prevents deterministic transport mechanics from
  bypassing role and workflow rules.
- **Residual/reopen condition:** none for the separation; each vertical still
  needs its own policy corpus.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-08 — Empty, uninitialized and valid are distinct

- **Status:** `DECIDED`.
- **Rule:** empty or uninitialized history MUST produce a distinct classified
  outcome and MUST NOT be reported as a valid initialized chain.
- **Rationale/evidence:** `CHAIN-001` shows that both current validators accept
  an empty list; JavaScript returns success immediately
  (`styx-js/src/ledger/chain-validator.js:21-28`). C0.1 explicitly marks this as
  unspecified, not endorsed.
- **Rejected alternative:** `null`/no-error as both “empty” and “valid”.
- **Security/privacy:** prevents missing state from silently satisfying a
  validation gate.
- **Residual/reopen condition:** exact stable error codes remain `OPEN`.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-09 — Fresh genesis and deterministic clock injection

- **Status:** `DECIDED`.
- **Rule:** neither current genesis projection is inherited. The later
  specification MUST define a fresh deterministic initialization object and
  MUST make all time-dependent inputs injectable for normative vectors.
- **Rationale/evidence:** `EVENT-002` records different current payloads and
  initial clocks; `EVENT-003` is unsupported because neither public factory
  accepts the required clock. The current JS genesis serializes JSON while
  Dart serializes a different literal (`styx-js/src/ledger/event-factory.js:74-105`,
  `packages/ledger_engine/lib/src/event_factory.dart:76-109`).
- **Rejected alternatives:** selecting either implementation's genesis or
  recording wall-clock-dependent expected hashes.
- **Security/privacy:** deterministic initialization makes context separation
  and independent conformance testable. Genesis contents remain `OPEN`.
- **Residual/reopen condition:** none for freshness/injection; exact fields must
  follow the context, identity and causality decisions.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-10 — Legacy hard cut and integration prohibition

- **Status:** `DECIDED`.
- **Rule:** current behavior is labelled `styx-legacy-c0` and is evidence only.
  A v1 validator MUST NOT accept it as v1, and a supported adapter MUST NOT
  persist or claim support for current ledger objects before the normative
  corpus is green. No dual acceptance or migration is invented without evidence
  of an installed population.
- **Rationale/evidence:** ADR-0007 states that the ledger is not integrated in a
  supported end-to-end pipeline. The hard cut is therefore presently cheaper
  and safer than carrying ambiguous behavior into v1.
- **Rejected alternatives:** silently blessing all 25 matches; maintaining a
  compatibility mode for hypothetical users.
- **Security/privacy:** prevents vulnerable legacy semantics from crossing a
  product boundary. This is a governance prohibition, not runtime remediation.
- **Residual/reopen condition:** any evidence of persisted production data or a
  supported consumer immediately reopens this decision and requires a migration
  contract.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-11 — Licensing sequence for the future corpus

- **Status:** `DECIDED`.
- **Rule:** this registry and future specification text remain under the
  repository `AGPL-3.0-or-later` default. Future synthetic normative vectors
  are intended for the Apache-2.0 exception model, but no future path is
  pre-approved. Before C0.3 creates any corpus file, a separate task MUST
  inventory and approve every exact path and amend `LICENSING.md` and
  `REUSE.toml` under independent review.
- **Rationale/evidence:** `LICENSING.md` permits no broad exception and requires
  explicit approval for each new Apache-2.0 path. This preserves a reusable
  conformance surface without mixing licensing changes into protocol decisions.
- **Rejected alternatives:** directory globs; retroactive relicensing after a
  large corpus exists; bundling the amendment with rule-making.
- **Security/privacy:** no direct security property; clean provenance makes
  independent implementations and audits easier to trust.
- **Residual/reopen condition:** the exact corpus inventory is not yet known and
  remains unlicensed under Apache-2.0 until the separate amendment lands.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

## 3. Explicitly rejected current behavior

The following observations are not promises and MUST NOT be copied into v1:

| Behavior | Evidence | Disposition |
| --- | --- | --- |
| Boundaryless composite hashing | `HASH-004`, `HASH-005` | `REJECTED` |
| HLC/string text as authoritative crypto bytes | `HLC-003`, `HLC-007`, `HLC-008` | `REJECTED` |
| Free-form or ambiguously parsed node identifiers | `HLC-005`, `HLC-008` | `REJECTED` |
| Permissive counter parsing, including non-numbers | `HLC-004` | `REJECTED` |
| Silent time-precision truncation | `HLC-002` | `REJECTED` |
| Signed or wrapping causal counters | `VC-002`, `VC-003`, `VC-004` | `REJECTED` |
| Fixed two-party topology as kernel by default | `VC-007` | `REJECTED` |
| `vectorClock.total` as authority/order key | current merge + independent signature probe | `REJECTED` |
| Locale-sensitive sender ordering | `ORDER-002`, `ORDER-005` | `REJECTED` |
| Comparator equality for distinct events | `ORDER-004` | `REJECTED` |
| Empty-chain success | `CHAIN-001` | `REJECTED` |
| Either current genesis | `EVENT-002`, `EVENT-003` | `VERSIONED_AWAY` |
| Unsigned UUID or metadata influencing validation | independent signature probe | `REJECTED` |

## 4. Open questions and minimum evidence

All entries in this section block C0.3 when they affect normative bytes or
expected validation outcomes.

| ID | Status | Question | Minimum evidence task | Depends on / risk |
| --- | --- | --- | --- | --- |
| O-01 | `OPEN` | Sparse/dotted version vector, authenticated parent-hash DAG or another causal representation? | Adversarial convergence probe comparing dynamic membership, offline forks, missing-parent recovery, checkpoint/pruning behavior, byte growth and participant enumeration under the capability threat model. | Blocks causal bytes, identifiers and ordering vectors. |
| O-02 | `OPEN` | How are authors represented per context, rotated and proven authorized? | Threat-model and transcript-inventory exercise covering case-ephemeral, organization-role and device credentials, including cross-context negative tests on paper. | Blocks author/context transcript fields; avoids confusing key possession with role authorization. |
| O-03 | `OPEN` | What is the application/case context identifier and how is it bound to genesis? | Collision, uniqueness, unlinkability and context-replay analysis against §5.1/§5.3 of the capability model. | Blocks domain separation and genesis. |
| O-04 | `OPEN` | Does the payload enter raw or as digest plus length; can it be detached? | Retention/pruning/GDPR design comparing verifiability after payload removal, substitution resistance and bounded parsing. | Blocks payload transcript field and pruning. |
| O-05 | `OPEN` | Does HLC remain in the signed kernel, move to a profile, or yield to per-author sequence plus parent links? | Evaluate authorization needs, clock-skew attacks, deterministic replay, privacy and overlap with O-01. | Blocks clock field presence. |
| O-06 | `OPEN` | What are the event/content identifier semantics? | Compare content hash, signed-object hash and separate random id for deduplication, references and privacy; every influential id must satisfy K-01. | Blocks ordering tiebreak and fork references. |
| O-07 | `OPEN` | What exactly is genesis? | Derive fields only after O-01 through O-06; prove deterministic construction and cross-context rejection. | Blocks initialization vectors. |
| O-08 | `OPEN` | What clock skew, first-profile cardinality and N-party activation bounds apply? | Runtime-envelope and vertical-role analysis with explicit exhaustion and denial-of-service cases. | Profile choice; must not leak into the kernel by inertia. |
| O-09 | `OPEN` | Is the specification factored into one kernel plus profiles, and which obligations belong to each? | Responsibility matrix across application protocol, secure session, runtime and vertical policy; reject duplicate or ownerless rules. | Blocks conformance target structure. |
| O-10 | `OPEN` | Is the protocol error taxonomy closed, and which distinctions are stable? | Enumerate all rejection sites after other fields are decided; collapse only errors that do not affect safe recovery or caller behavior. | Blocks negative-vector expectations. |
| O-11 | `OPEN` | What is the wire/storage encoding? | Separate dependency and decoder-surface decision after transcript fields are fixed; compare strict custom framing and deterministic CBOR profiles. | Does not reopen K-02 transcript discipline. |

### Deferred legacy hardening

- **Status:** `DEFERRED`.
- **Decision:** strict current HLC and `previousHash` grammar could narrow one
  ambiguity class without changing the current hash layout, but it would leave
  unauthenticated causal and fork fields. It will not be shipped while there is
  no supported legacy consumer. If a consumer appears before replacement, a
  separate emergency hardening contract must reassess disclosure and cannot
  describe that partial fix as a secure protocol.
- **Missing evidence:** an inventory showing an installed data population or a
  supported consumer that cannot make the v1 hard cut.
- **Dependent artifact:** any temporary `styx-legacy-c0` validator, migration or
  product-admission rule. No such artifact is authorized by this registry.
- **Smallest bounded follow-up:** if the missing evidence appears, inventory the
  exact consumers and stored formats, then choose migration, read-only export or
  temporary strict validation in a separately reviewed contract.

## 5. Non-normative worked examples

These examples explain decisions; they are not vectors and MUST NOT be copied
as expected protocol bytes.

### Example A — framing

`type = "ab", payload = "c"` and `type = "a", payload = "bc"` must generate
different transcripts because the type and payload are length-framed. Concatenating
the two strings before hashing is forbidden.

### Example B — authenticated semantics

If a validator uses a causal parent to decide that an operation follows another,
then that parent reference must be in the signed transcript or derived from it.
Changing the causal parent without invalidating the signature must be impossible.

### Example C — context authorization

A signature that verifies under a supplied public key proves possession of the
matching private key. It does not by itself prove that the key may approve an
investigation step in a particular case. That authorization relationship must
also be transcript-bound and locally evaluated under the application's policy.

## 6. Gate for C0.3 and exact next sequence

**C0.3 verdict: `NO-GO`.** O-01 through O-10 contain choices required to derive
normative bytes or adversarial expectations. Starting the corpus now would
freeze guesses and create cost pressure on later human decisions.

The smallest safe sequence is:

1. decide O-02, O-03 and O-09 through a signed-envelope responsibility and
   identity/context threat-model task;
2. run the adversarial causal-topology probe for O-01, coordinated with O-05,
   O-06 and the privacy conclusions from step 1;
3. close payload, genesis, clock, cardinality and error questions O-04 through
   O-10 without implementation authority;
4. approve the exact Apache-2.0 path inventory for the future corpus;
5. execute C0.3: specification-derived adversarial corpus plus a third
   implementation written only from the specification;
6. align JavaScript in C0.4; align or freeze the minimum Dart surface only if it
   remains useful as independent evidence.

No supported Phase B adapter may persist current application-ledger objects
while this `NO-GO` remains in force.

## 7. Non-claims and residual risk

This registry does not define exact bytes, establish conformance,
interoperability, anonymity, compliance, audit coverage, production readiness
or suitability for sensitive data. The current experimental implementations
retain the documented defects until a later implementation increment. The
integration prohibition is governance, not a runtime security boundary.

C0.1 is finite and does not cover authorization, payload commitment,
checkpointing, retention or every causal topology. Independent implementation,
formal modeling, fuzzing, migration and product testing remain necessary.
