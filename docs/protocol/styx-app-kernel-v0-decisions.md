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

Security-critical evidence fields below use only C0.1 case identifiers and
these retained private-review references. A reference identifies an immutable
local artifact by filename and SHA-256; it does not disclose its witness:

| Reference | Retained private-review artifact | SHA-256 |
| --- | --- | --- |
| `PRIV-01` | `README_OPUS5_20260817T063953Z.md` | `beff559ed88bda3d1cbbbdfdb3686f84003b6d9d8640c25e505d5fc36e831003` |
| `PRIV-02` | `README_QWEN38_20260817T064405Z.md` | `320234c8afe9ea22b54c24164ab1a8e8e77b3c3af6d4e2ff4f544fe0b3286606` |
| `PRIV-03` | `README_OPUS5_RECONCILE_20260817T070100Z.md` | `51f027211f231803ddb93f40dabe898673c7ddba2bea8498d774e1deb9d81ec0` |
| `PRIV-04` | `README_QWEN38_RECONCILE_20260817T070100Z.md` | `4594818fb528e797c74e9eca4e1ffa0ea62988be9c5a539a77f0a3c1d9d6844d` |

Separate `Normative rationale` and `Public inspection pointer (non-witness)`
fields may cite public repository documents. They contain no witness material
and never substitute for the security-critical evidence field above.

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
- **Rationale/evidence:** `PRIV-01`, `PRIV-02`, `PRIV-03` and `PRIV-04`
  confirm that changing causal metadata can leave the existing signature valid
  while downstream protocol behavior consumes that metadata.
- **Public inspection pointer (non-witness):** the affected public source
  surfaces are listed in `docs/security/2026-08-17-ledger-preimage-and-signature-coverage-findings.md`
  under *Affected paths and evidence*; the retained references above establish
  the complete-event reproduction without publishing its witness.
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
  signature verification; it is not a generic wire document to parse. Here,
  “TLS-presentation-style” names only the framing property: every field is
  fixed-width or an explicitly length-prefixed variable-width value. It does
  not import a TLS record grammar or select the exact transcript or wire
  encoding, which remain later specification decisions.
- **Rationale/evidence:** `HASH-004`, `HASH-005`, `PRIV-01`, `PRIV-02`,
  `PRIV-03` and `PRIV-04` establish boundary erasure at the primitive and
  complete-event/signature levels.
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
  collation behavior.
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
  ambiguity and wrapping. Retained private reproductions (`PRIV-02`, `PRIV-03`,
  `PRIV-04`) show that incrementing a maximum current counter and serializing it
  can restore as zero and reverse a causal relation.
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
  represented consistently. Width, epoch, range and precision representation
  remain `OPEN` under O-12.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-06 — Causality precedes deterministic total order

- **Status:** `DECIDED`.
- **Rule:** a conforming implementation MUST determine causal relationship
  before applying a total order. Events proven concurrent SHALL use a bytewise,
  locale-independent tiebreak derived from authenticated event content. Exact
  identifier equality is deduplication, not an ordering tie. A vector-component
  sum is neither causal evidence nor authority.
- **Rationale/evidence:** `ORDER-002`, `ORDER-004`, `ORDER-005`, `PRIV-01`,
  `PRIV-03` and `PRIV-04` show divergent or incomplete tie behavior and that
  current causal/order inputs are not fully signature-bound.
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
- **Rationale/evidence:** `PRIV-01`, `PRIV-03` and `PRIV-04` distinguish
  deterministic convergence from application authorization and conflict
  policy.
- **Normative rationale:** §1 of
  `docs/architecture/decisions/ADR-0007-application-protocol-authority.md`
  assigns language-neutral state-transition rules to the application protocol,
  while §5 assigns workflows and policy to verticals. Accounting and case-
  management operations therefore cannot safely inherit one universal conflict
  rule from replica ordering. Section 5.10 of
  `docs/platform/application-capability-model.md` independently requires the
  application to declare its conflict policy rather than treating deterministic
  replica order as a universal merge rule.
- **Rejected alternative:** treating stable byte order as authorization or
  business truth.
- **Security/privacy:** prevents deterministic transport mechanics from
  bypassing role and workflow rules.
- **Residual/reopen condition:** reopen if a vertical demonstrates that a
  conflict rule is both application-independent and required for safe kernel
  convergence; otherwise each vertical still needs its own policy corpus.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-08 — Empty, uninitialized and valid are distinct

- **Status:** `DECIDED`.
- **Rule:** empty or uninitialized history MUST produce a distinct classified
  outcome and MUST NOT be reported as a valid initialized chain.
- **Rationale/evidence:** `CHAIN-001` shows that both current validators accept
  an empty list; C0.1 explicitly marks this as unspecified, not endorsed.
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
  accepts the required clock.
- **Rejected alternatives:** selecting either implementation's genesis or
  recording wall-clock-dependent expected hashes.
- **Security/privacy:** deterministic initialization makes context separation
  and independent conformance testable. Genesis contents remain `OPEN`.
- **Residual/reopen condition:** reopen if a required initialization or time
  input cannot be injected without weakening transcript determinism or security;
  exact fields must follow the context, identity and causality decisions.
- **Human ratification:** pending final-HEAD approval by `maverde73`.

### K-10 — Legacy hard cut and integration prohibition

- **Status:** `DECIDED`.
- **Rule:** current behavior is labelled `styx-legacy-c0` and is evidence only.
  A v1 validator MUST NOT accept it as v1, and a supported adapter MUST NOT
  persist or claim support for current ledger objects before the normative
  corpus is green. No dual acceptance or migration is invented without evidence
  of an installed population.
- **Rationale/evidence:** `PRIV-01`, `PRIV-03` and `PRIV-04` record the current
  non-integration condition and the resulting hard-cut rationale.
- **Normative rationale:** §2 of
  `docs/architecture/decisions/ADR-0007-application-protocol-authority.md`
  records that the ledger is not yet integrated into a supported end-to-end
  product pipeline. In the absence of an installed population, a hard cut is
  safer than carrying ambiguous legacy behavior into v1.
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
| `vectorClock.total` as authority/order key | `ORDER-004`, `ORDER-005`, `PRIV-01`, `PRIV-03`, `PRIV-04` | `REJECTED` |
| Locale-sensitive sender ordering | `ORDER-002`, `ORDER-005` | `REJECTED` |
| Comparator equality for distinct events | `ORDER-004` | `REJECTED` |
| Empty-chain success | `CHAIN-001` | `REJECTED` |
| Either current genesis | `EVENT-002`, `EVENT-003` | `VERSIONED_AWAY` |
| Unsigned UUID or metadata influencing validation | `PRIV-01`, `PRIV-02`, `PRIV-03`, `PRIV-04` | `REJECTED` |

## 4. Open questions and minimum evidence

An `OPEN` status is an explicit decision not to guess. Each entry below blocks
C0.3 when it affects normative transcript bytes or expected validation
outcomes.

### O-01 — Causal representation

- **Status:** `OPEN`.
- **Question:** sparse/dotted version vector, authenticated parent-hash DAG or
  another bounded causal representation?
- **Rationale/evidence:** `VC-007`, `ORDER-004`, `PRIV-01`, `PRIV-03` and
  `PRIV-04` show that current topology and ordering behavior do not answer the
  protocol question safely.
- **Rejected alternatives:** inheriting the fixed two-party vector; selecting a
  DAG or vector by implementation familiarity; treating a counter sum as
  causality.
- **Security/privacy:** the choice affects self-authentication, fork evidence,
  participant enumeration, linkability, denial of service and convergence.
- **Missing evidence:** an adversarial comparison over all required dimensions.
- **Dependent artifact:** causal transcript fields, event identifiers and
  ordering vectors.
- **Smallest bounded follow-up:** compare self-authentication, dynamic
  membership, offline concurrency, fork evidence, missing-parent recovery,
  checkpoint/pruning behavior, byte growth, participant enumeration and
  linkability, and deterministic convergence against the requirements in
  `docs/platform/application-capability-model.md`, especially §5.10, §5.5 and
  §5.3.
- **Residual/closure condition:** close only when one bounded representation
  satisfies the comparison and its failure modes are explicit.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-02 — Author, rotation and authorization binding

- **Status:** `OPEN`.
- **Question:** how are authors represented per context, rotated and proven
  authorized?
- **Rationale/evidence:** `PRIV-01`, `PRIV-03` and `PRIV-04` distinguish key
  possession from authorization and show why author semantics must be bound.
- **Normative rationale:** identity profiles, authorization and delegation, and
  compromise-response requirements are defined in §5.2, §5.6 and §5.13 of
  `docs/platform/application-capability-model.md`.
- **Rejected alternatives:** treating a supplied verification key as sufficient
  role authority; unauthenticated author metadata; one globally linkable
  identity by default.
- **Security/privacy:** a wrong choice permits role escalation, impersonation or
  cross-context linkage.
- **Missing evidence:** a credential, rotation and revocation threat model for
  case-ephemeral, organization-role and device identities.
- **Dependent artifact:** author and credential-binding transcript fields.
- **Smallest bounded follow-up:** produce the threat model and transcript
  inventory, including cross-context negative cases on paper.
- **Residual/closure condition:** close only when possession, authorization,
  rotation, revocation and linkability have separate verified rules.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-03 — Application/case context and genesis binding

- **Status:** `OPEN`.
- **Question:** what is the application/case context identifier and how is it
  bound to genesis?
- **Rationale/evidence:** `PRIV-01`, `PRIV-03` and `PRIV-04` corroborate the need
  for explicit context separation; C0.1 contains no sufficient context-
  identifier evidence.
- **Normative rationale:** the application-context and unlinkability
  requirements are defined in §5.1 and §5.3 of
  `docs/platform/application-capability-model.md`.
- **Rejected alternatives:** an ambient database name; an unsigned label;
  reusing an account identifier as the case identifier without the required
  uniqueness, replay and linkability analysis.
- **Security/privacy:** the construction controls cross-context replay,
  uniqueness and linkability.
- **Missing evidence:** collision, uniqueness, unlinkability and replay analysis.
- **Dependent artifact:** domain tag, context field and genesis transcript.
- **Smallest bounded follow-up:** analyze candidate identifiers against the
  application-context and unlinkability requirements in §5.1 and §5.3 of
  `docs/platform/application-capability-model.md`.
- **Residual/closure condition:** close only with deterministic binding and
  explicit cross-context rejection rules.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-04 — Payload commitment and detachment

- **Status:** `OPEN`.
- **Question:** does the payload enter the transcript as raw bytes or as digest
  plus length, and can it be detached?
- **Rationale/evidence:** `PRIV-01`, `PRIV-03` and `PRIV-04` identify retention
  and pruning as unresolved; C0.1 does not characterize detached payloads.
- **Normative rationale:** attachment commitment and retention/deletion
  requirements are defined in §5.12 and §5.15 of
  `docs/platform/application-capability-model.md`.
- **Rejected alternatives:** choosing raw bytes because current factories do;
  digest-only commitment without length or substitution analysis.
- **Security/privacy:** the choice affects substitution resistance, erasure,
  retained evidence and parser exposure.
- **Missing evidence:** a retention/pruning design and adversarial substitution
  analysis.
- **Dependent artifact:** payload transcript field, pruning and detached-object
  rules.
- **Smallest bounded follow-up:** compare raw and digest-plus-length designs for
  verification after payload removal, substitution resistance and bounded
  parsing.
- **Residual/closure condition:** close only when removal and verification
  semantics are simultaneously defined.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-05 — Clock placement

- **Status:** `OPEN`.
- **Question:** does HLC remain in the signed kernel, move to a profile, or yield
  to per-author sequence plus parent links?
- **Rationale/evidence:** `HLC-002` through `HLC-005`, `HLC-007`, `HLC-008` and
  `PRIV-01` show that current clock representations are not safe authority.
- **Rejected alternatives:** retaining HLC by inertia; trusting wall time for
  authorization; repairing malformed clock input.
- **Security/privacy:** time can enable skew attacks, runtime fingerprinting and
  unwanted activity correlation.
- **Missing evidence:** authorization, replay, skew and privacy analysis
  coordinated with O-01.
- **Dependent artifact:** clock-field presence and ordering semantics.
- **Smallest bounded follow-up:** compare the three placements under adversarial
  replay, deterministic execution and the selected causal representation.
- **Residual/closure condition:** close only when the clock has a necessary,
  bounded role not duplicated by causality.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-06 — Event/content identifier semantics

- **Status:** `OPEN`.
- **Question:** what are the event and content identifier semantics?
- **Rationale/evidence:** `ORDER-004`, `PRIV-01`, `PRIV-03` and `PRIV-04` show
  that identifiers and fork inputs cannot remain mutable conveniences.
- **Rejected alternatives:** unsigned random identifiers influencing protocol
  behavior; treating a content hash and signed-object hash as interchangeable.
- **Security/privacy:** identifiers affect deduplication, replay, fork evidence,
  reference integrity and correlation.
- **Missing evidence:** comparison of content hash, signed-object hash and a
  separate random identifier.
- **Dependent artifact:** event identifier, ordering tiebreak and fork
  references.
- **Smallest bounded follow-up:** compare the candidates for every use and apply
  K-01 to each influential identifier.
- **Residual/closure condition:** close only when each identifier has one stated
  purpose and authenticated derivation or binding.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-07 — Genesis content

- **Status:** `OPEN`.
- **Question:** what exactly is genesis?
- **Rationale/evidence:** `EVENT-002` and `EVENT-003` show divergent current
  initialization and missing deterministic clock injection.
- **Rejected alternatives:** inheriting either current genesis; embedding an
  ambient wall clock; leaving context or initial membership implicit.
- **Security/privacy:** genesis anchors context, initial authority and replay
  separation.
- **Missing evidence:** the outputs of O-01 through O-06.
- **Dependent artifact:** initialization transcript and genesis vectors.
- **Smallest bounded follow-up:** derive genesis only after those inputs close,
  then prove deterministic construction and cross-context rejection.
- **Residual/closure condition:** close only when every genesis field is
  necessary, authenticated and independently reproducible.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-08 — Profile skew, cardinality and activation bounds

- **Status:** `OPEN`.
- **Question:** what clock-skew policy, first-profile actor cardinality and
  N-party activation bounds apply?
- **Rationale/evidence:** `VC-007`, `HLC-002` through `HLC-005`, `HLC-007` and
  `HLC-008` show that current two-party and clock behavior is not a safe profile
  definition.
- **Rejected alternatives:** promoting current limits to kernel rules; unbounded
  actors or skew; silent degradation outside tested profiles.
- **Security/privacy:** bounds affect denial of service, metadata exposure and
  whether a runtime can enforce the profile safely.
- **Missing evidence:** runtime-envelope and vertical-role capacity analysis.
- **Dependent artifact:** first supported profile and any later N-party profile.
- **Smallest bounded follow-up:** evaluate explicit exhaustion, skew and denial-
  of-service cases without leaking profile choices into the kernel.
- **Residual/closure condition:** close only with enforceable limits and explicit
  out-of-profile rejection.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-09 — Kernel/profile responsibility split

- **Status:** `OPEN`.
- **Question:** is the specification factored into one kernel plus profiles, and
  which obligations belong to each?
- **Rationale/evidence:** `PRIV-01`, `PRIV-03` and `PRIV-04` corroborate the need
  to separate protocol, secure-session, runtime and vertical authority.
- **Normative rationale:** §1, §3, §4 and §5 of
  `docs/architecture/decisions/ADR-0007-application-protocol-authority.md`
  already assign application-protocol, secure-session, runtime and vertical
  authorities at the architectural level. What remains open is the
  specification-level obligation matrix within and across those layers, which
  must prevent duplicate or ownerless rules.
- **Rejected alternatives:** duplicate ownership; ownerless rules; allowing a
  runtime or product vertical to redefine kernel acceptance.
- **Security/privacy:** misplaced rules create bypasses and inconsistent
  security claims across runtimes.
- **Missing evidence:** a complete responsibility matrix.
- **Dependent artifact:** conformance target structure and profile documents.
- **Smallest bounded follow-up:** assign every known obligation to exactly one
  layer and reject overlaps or gaps.
- **Residual/closure condition:** close only when every normative rule has one
  owner and explicit cross-layer inputs.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-10 — Stable protocol-error taxonomy

- **Status:** `OPEN`.
- **Question:** is the protocol-error taxonomy closed, and which distinctions
  are stable?
- **Rationale/evidence:** `CHAIN-001`, `HLC-004`, `HLC-005`, `VC-002`, `VC-003`
  and `VC-004` demonstrate outcomes that future consumers must not collapse into
  generic success or implementation-native failure.
- **Rejected alternatives:** exception strings as protocol API; one error for
  states requiring different safe recovery; exposing unstable parser details.
- **Security/privacy:** error distinctions affect fail-closed recovery and may
  also become side channels if over-detailed.
- **Missing evidence:** the complete rejection-site inventory after other fields
  close.
- **Dependent artifact:** negative-vector expectations and consumer recovery
  contract.
- **Smallest bounded follow-up:** enumerate rejection sites and collapse only
  distinctions that cannot alter safe caller behavior.
- **Residual/closure condition:** close only with a bounded stable taxonomy and
  privacy review of observable errors.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-11 — Wire/storage encoding

- **Status:** `OPEN`.
- **Question:** what is the wire/storage encoding?
- **Rationale/evidence:** C0.1 contains no language-neutral wire/storage
  characterization; K-02 deliberately separates regenerated transcripts from
  transport representation.
- **Rejected alternatives:** treating an existing convenience JSON projection
  as normative by inertia; selecting a decoder dependency before its attack
  surface and canonical profile are known.
- **Security/privacy:** decoder complexity, canonicality and resource bounds can
  create malleability or denial-of-service risks.
- **Missing evidence:** dependency, canonicality and decoder-surface comparison.
- **Dependent artifact:** wire/storage specification, not the C0.3 regenerated-
  transcript corpus.
- **Smallest bounded follow-up:** compare strict custom framing and deterministic
  CBOR profiles after transcript fields are fixed.
- **Residual/closure condition:** not C0.3-blocking; close before any supported
  persistence or remote admission. It does not reopen K-02.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-12 — Physical-time width, epoch, range and precision privacy

- **Status:** `OPEN`.
- **Question:** if physical time is retained, what are its exact width, epoch
  and range, and how is source precision represented without needlessly
  fingerprinting a runtime class?
- **Rationale/evidence:** `HLC-002`, `HLC-003`, `HLC-007` and `HLC-008` show
  precision loss and runtime-dependent projections.
- **Rejected alternatives:** implicit language-native ranges; inferring source
  precision from zero-filled digits without privacy analysis; fabricated
  precision.
- **Security/privacy:** the field affects overflow, lifetime, linkability and
  runtime fingerprinting.
- **Missing evidence:** precision, lifetime and privacy analysis across the
  declared runtime envelopes.
- **Dependent artifact:** clock transcript field and its adversarial vectors.
- **Smallest bounded follow-up:** decide whether precision is declared, inferred
  or hidden and assess linkability, coordinated with O-05.
- **Residual/closure condition:** close only if physical time remains and all
  numeric and privacy properties are bounded.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### D-01 — Deferred legacy hardening

- **Status:** `DEFERRED`.
- **Decision:** strict current HLC and `previousHash` grammar could narrow one
  ambiguity class without changing the current hash layout, but it would leave
  unauthenticated causal and fork fields. It will not be shipped while there is
  no supported legacy consumer.
- **Rationale/evidence:** `HLC-004`, `HLC-005`, `PRIV-01`, `PRIV-03` and
  `PRIV-04` show both the narrowable parser defects and the larger signature-
  coverage gap that such hardening would not repair.
- **Rejected alternatives:** presenting strict parsing as complete remediation;
  shipping a compatibility validator for hypothetical consumers.
- **Security/privacy:** partial hardening could create false confidence while
  unauthenticated causal and fork semantics remain exploitable if integrated.
- **Missing evidence:** an installed data population or supported consumer that
  cannot make the v1 hard cut.
- **Dependent artifact:** any temporary `styx-legacy-c0` validator, migration or
  product-admission rule; none is authorized here.
- **Smallest bounded follow-up:** if the missing evidence appears, inventory the
  exact consumers and stored formats, then choose migration, read-only export or
  temporary strict validation under a separately reviewed contract.
- **Residual/reopen condition:** a consumer appearing before replacement
  immediately reopens the deferral and disclosure posture.
- **Human ratification:** pending final-HEAD acceptance of this deferral.

## 5. NON-NORMATIVE worked examples

These examples explain decisions; they are not vectors and MUST NOT be copied
as expected protocol bytes.

### Example A — framing

Every variable-width semantic field is length-framed. Consequently, changing
field assignments cannot preserve the transcript merely because the raw bytes
would concatenate to the same sequence.

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
normative bytes or adversarial expectations. O-12 is additionally blocking if
v1 retains a physical-time field in any signed object, whether in the kernel or
in a profile; only if O-05 removes physical time entirely does O-12 become
inapplicable and contribute no transcript field. O-11 intentionally does not
block a transcript-only C0.3 corpus. Starting that corpus now would freeze the
remaining guesses and create cost pressure on later human decisions.

The smallest safe sequence is:

1. decide O-02, O-03 and O-09 through a signed-envelope responsibility and
   identity/context threat-model task;
2. run the adversarial causal-topology probe for O-01, coordinated with O-05,
   O-06 and the privacy conclusions from step 1;
3. close payload, genesis, clock, cardinality and error questions O-04 through
   O-10, plus O-12 unless O-05 removes physical time entirely, without
   implementation authority; retain O-11 for the later wire/storage decision;
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
