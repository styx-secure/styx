# Styx application-event semantic kernel — v0 decision registry

- **Status:** non-stable decision registry; not a protocol specification.
- **Authority:** Issue #205 and ADR-0007.
- **Evidence base:** C0.1 at `2815cd5891ca2233bd60e91cb7858d8a8f9777df`.
- **C0.2a boundary model:**
  `docs/security/STYX-THREAT-MODEL.md` and
  `docs/protocol/styx-app-kernel-v0-responsibility-matrix.md`.
- **C0.2b identity/context analysis:**
  `docs/protocol/styx-app-kernel-v0-identity-context-analysis.md`.
- **C0.2c causal-topology analysis:**
  `docs/protocol/styx-app-kernel-v0-causal-topology-analysis.md`.
- **C0.2d causal falsification evidence:**
  `docs/protocol/styx-app-kernel-v0-causal-falsification-report.md`.
- **C0.2e payload-commitment analysis:**
  `docs/protocol/styx-app-kernel-v0-payload-commitment-analysis.md`.
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
| `PRIV-05` | `README_GLM53_20260818T210430Z.md` | `1d15836846916d17e98f167c2a7a9512e92adcdc8757cfd0d30398223e345ad0` |
| `PRIV-06` | `README_QWEN38_MAX_20260818T210430Z.md` | `8974e0db317db217dcbf16fbfb5c6d8cb99fd64b83a042fa48ff11ae388c1243` |
| `PRIV-07` | `README_OPUS5_20260818T210430Z.md` | `bf6257ed2f5bf787cf20c3ae6e9c6fd4016a08e65c3b5dde56177641345a0109` |
| `PRIV-08` | `README_GLM53_RECONCILE_20260818T210430Z.md` | `f38d9b5169b48d545582199c5e4f8349c091a782bad998fdccedcd6ee24fc01e` |
| `PRIV-09` | `README_QWEN38_MAX_RECONCILE_20260818T210430Z.md` | `d8e2b9b1afe9126d02679b7b317ba52026d3dcc269580f4c18501129a5215c77` |
| `PRIV-10` | `README_OPUS5_RECONCILE_20260818T210430Z.md` | `ae22765850f2ff21263c3ff1cfece34c4b0bc23f9183235711727bd6b0c2f313` |
| `PRIV-11` | `README_GLM53_ROUND3_20260819.md` | `3e2525d9717388d02106f22ff7f1af5412cda19a4fc96b338e8be93d9c775b69` |
| `PRIV-12` | `README_QWEN38_MAX_ROUND3_20260819.md` | `3312f16064f290a17faa9abf7cc67ba379f31319fda7a6f57c7344ad67d3a5d7` |
| `PRIV-13` | `README_OPUS5_ROUND3_20260819.md` | `b952f89dcea5b93fd7a8a57a58448cfe3eecf5bf411a581a503471389ac79c73` |
| `PRIV-14` | `README_GLM53_ROUND4_20260819.md` | `9478633efa461c84c3effad1881250f1da8a8314da4cf2e1e713b16e6ced2980` |
| `PRIV-15` | `README_QWEN38_MAX_ROUND4_20260819.md` | `945a6a4899c879e830778655de21630d87aa2b68ea5093bb3afc795c44b5493a` |
| `PRIV-16` | `README_OPUS5_ROUND4_20260819.md` | `f9a912e8ed6a1af6ba11d24a4bcd304f112adb2a84231d90efcf277ec965bf26` |
| `PRIV-17` | `README_GLM53_ROUND5_20260819.md` | `0cc4fda73cdef1a07b74846fda0f2df5ca9d04e82b0e8c671f34f0a7e4f86c5a` |
| `PRIV-18` | `README_QWEN38_MAX_ROUND5_20260819.md` | `d010dd698bdd5afcd26e30834129e194bf463889e2f6dc2873a6e9ef928d3a98` |
| `PRIV-19` | `README_OPUS5_ROUND5_20260819.md` | `c657154575f3e389a2555ab30f066411eb748c729027e30121f1ac6ea6e80f9c` |

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

- **Status:** `DECIDED`.
- **Rule:** every non-genesis event SHALL authenticate a strictly increasing,
  non-wrapping per-credential author sequence (zero for the first event and
  incremented by exactly one thereafter), its separate direct author
  predecessor and a canonical profile-bounded antichain of maximal causal-
  parent event references; the parent frontier excludes the separately encoded
  author predecessor. The first event has no author predecessor and causally
  descends from its credential grant. Transitive reachability over both link
  classes defines happens-before; absence of reachability in either direction
  defines concurrency. Duplicate, missing-parent, stale and same-author
  fork/equivocation outcomes are classified before AP evaluation.
  Arrival order, relay order, storage order and wall time MUST NOT determine
  causality. Among ready concurrent events, K-06 bytewise event-reference order
  produces the deterministic replay schedule; `AP` alone decides semantic
  conflict outcomes. That schedule is set-relative, not append-only finality: a
  late admitted concurrent event can invalidate a previously projected suffix,
  which a future implementation must replay or update with an algorithm proven
  equivalent to full replay. Arrival order cannot freeze the old position, and
  the current replay position alone proves neither authorization nor an
  irreversible external effect. Graph diagnostics are set-relative, while each
  `K → AP` transition in a full or incremental replay is prefix-scoped: it
  contains the prefix-visible classification, authenticated grant reference,
  and only causal/fork/live-revocation facts actionable at that position in the
  canonical replay. A newly replayed event introduces later-discovered facts;
  an unchanged prefix is reusable only when its handoffs are byte-identical to
  those produced by a fresh full replay. Set-relative diagnostics do not
  retroactively become AP transitions, while checkpoint authority outside the
  live prefix remains explicit checkpoint/AP input.
- **Rationale/evidence:** `VC-007`, `ORDER-004`, `PRIV-01`, `PRIV-03` and
  `PRIV-04` show that current topology and ordering behavior do not answer the
  protocol question safely. C0.2c compares four concrete families and selects
  the only candidate that combines dynamic endpoint credentials, concrete
  authenticated parents and explicit per-author fork/gap evidence without a
  stable participant vector.
- **Rejected alternatives:** fixed/sparse vector; dotted vector; parent DAG
  without an author chain; trusted sequencer, consensus, blockchain, counter
  sum, arrival order or wall time as kernel causality.
- **Security/privacy:** parent/frontier width and valid sibling fan-out require
  profile limits. References reveal graph structure to authorized recipients
  but need not enumerate inactive participants. A malicious author can omit an
  observed cross-author parent, and a relay can conceal a branch; signatures
  make claims attributable but not truthful.
- **Dependent artifact:** author sequence, direct predecessor, canonical parent
  frontier, derived event reference, causal/fork classifications and affected-
  suffix replay semantics. O-04/O-07 define checkpoint/genesis evidence; O-08
  bounds resources; O-10 names outcomes; O-06 still selects the exact digest
  registry/bytes.
- **Executable falsification evidence:** the bounded, implementation-independent
  C0.2d model and report in
  `docs/protocol/styx-app-kernel-v0-causal-falsification-report.md` find no
  counterexample within their declared envelope. They distinguish set-relative
  graph diagnostics from prefix-scoped AP replay and do not constitute a proof
  or conformance claim.
- **Residual/reopen condition:** reopen if the executable causal model finds
  delivery-order divergence, bounded frontiers cannot preserve required
  causality, incremental handoffs diverge from full prefix-scoped replay,
  rotation/revocation cannot reject stale authority, or checkpoints cannot
  retain required fork evidence within a supported runtime envelope.
- **Human ratification:** C0.2c topology approved under Issue #211; the C0.2d
  executable evidence and prefix-scoped replay clarification remain pending
  exact-final-HEAD approval under Issue #213.

### O-02 — Author, rotation and authorization binding

- **Status:** `DECIDED`.
- **Rule:** every authoring endpoint SHALL use a distinct context-local signing
  credential. Its authenticated grant binds one credential identifier and
  verification key to one application-context tuple and bounded application
  authority. `K` verifies the signed binding; `AP` evaluates authority in the
  authenticated predecessor state. Key possession, signature validity, MLS
  membership, Nostr identity, durability, delivery and human assignment MUST
  NOT substitute for application authorization. Persistent-account proofs and
  anonymous return capabilities are optional profile inputs, not universal
  authors. Rotation creates a new credential and retires the old one through an
  authorized transition; recovery MUST NOT resurrect revoked authority.
- **Rationale/evidence:** `PRIV-01`, `PRIV-03` and `PRIV-04` distinguish key
  possession from authorization. The C0.2b analysis compares five
  constructions and selects the only candidate that preserves endpoint-specific
  revocation, transport/session neutrality and case-ephemeral profiles while
  keeping application authority explicit.
- **Normative rationale:** identity profiles, authorization and delegation, and
  compromise-response requirements are defined in §5.2, §5.6 and §5.13 of
  `docs/platform/application-capability-model.md`; owned boundaries are defined
  by `OB-AP02`, `OB-AP09`, `OB-K01`, `OB-SS01` and `OB-RS01`.
- **External boundary evidence:** RFC 9420 §5.3 leaves application identifiers
  and reference-identifier policy to the application. The exact pinned Marmot
  account-identity proof binds a Nostr account to an MLS leaf key but explicitly
  does not authorize group admission or continued membership. Neither defines
  Styx application authority.
- **Rejected alternatives:** durable account key as universal author; MLS leaf
  or immediate session sender as application author; self-asserted key plus role
  text; bearer capability as the general author.
- **Security/privacy:** context-local credentials limit normal key reuse and
  allow independent device revocation, but do not prevent linkability through
  routing, storage, recovery, notifications or user behavior. A compromised
  valid credential retains its granted authority until revocation becomes
  effective.
- **Dependent artifact:** credential identifier, verification-key/algorithm
  binding, grant/state reference and negative vectors. O-01 defines concurrent
  and stale ordering; O-05/O-12 gate physical expiry; O-06 defines references;
  O-07 defines initial authority; O-08 bounds resources; O-10 names failures.
- **Residual/reopen condition:** reopen if O-01 cannot express safe
  rotation/revocation, a required profile cannot use context-local credentials,
  the `AP → K` split permits an authorization bypass, or an approved anonymous
  profile requires bearer-only authorship.
- **Human ratification:** pending exact-final-HEAD approval under Issue #209.

### O-03 — Application/case context and genesis binding

- **Status:** `DECIDED`.
- **Rule:** the authoritative application/case context SHALL be the tuple of
  Styx protocol version, application-profile identifier,
  application-profile version and an exactly 32-byte fresh random context
  identifier generated by the declared runtime CSPRNG. The random identifier
  MUST NOT be derived from identity, personal data, time, transport, session,
  storage names or counters and MUST NOT be reused. Genesis and every later
  authoritative object MUST authenticate the complete tuple; every later object
  also authenticates an unambiguous reference or commitment to that genesis.
  Cross-tuple objects are rejected.
- **Rationale/evidence:** `PRIV-01`, `PRIV-03` and `PRIV-04` corroborate the need
  for explicit context separation. The C0.2b comparison rejects ambient,
  account, organization, MLS, Nostr and complete-genesis-derived identifiers;
  the selected tuple separates protocol/profile versioning from opaque random
  case uniqueness without exposing a global identity.
- **Normative rationale:** the application-context and unlinkability
  requirements are defined in §5.1 and §5.3 of
  `docs/platform/application-capability-model.md`; `OB-K08`, `OB-K09`,
  `OB-AP03`, `OB-RS02` and `OB-TR02` retain their separate ownership.
- **Rejected alternatives:** ambient account, organization, database or
  deployment identifiers; MLS group IDs or Nostr/routing handles; the complete
  genesis hash as the context identifier; a raw random value without explicit
  protocol and application-profile separation.
- **Security/privacy:** 32 random bytes make accidental collision negligible
  under the declared CSPRNG assumption, not impossible. The tuple is not an
  anonymity mechanism if exposed, logged or reused as a routing handle. A
  compromised RNG or external metadata mapping remains outside this rule.
- **Dependent artifact:** the context tuple enters the genesis and application
  object transcripts. O-06 chooses the exact genesis-reference semantics; O-07
  completes genesis content. `SS`, `RS` and `TR` bind their own namespaces and
  MUST NOT silently publish or substitute the application tuple.
- **Residual/reopen condition:** reopen if O-06/O-07 cannot provide an
  unambiguous authenticated genesis binding, a supported runtime cannot provide
  the required random input, a supported discovery profile requires a public
  deterministic context handle, or negative vectors accept cross-profile or
  cross-context replay.
- **Human ratification:** pending exact-final-HEAD approval under Issue #209.

### O-04 — Payload commitment and detachment

- **Status:** `DECIDED`; the C0.2f executable falsification gate passed within
  its declared bounds and remains mandatory to rerun after dependent changes.
- **Rule:** every authoritative event authenticates exactly one bounded content
  descriptor. `content_class` is one of `NONE`, `REQUIRED` or `DETACHABLE`.
  For content-bearing classes the descriptor authenticates a closed content-
  type identifier, exact length, commitment suite/shape, full commitment and
  any bounded chunk geometry. The commitment binds at least its suite
  identifier, the complete O-03 tuple, content type, exact length,
  shape/geometry, exact K-boundary application octets and fresh opening
  randomizer. The K transcript contains the descriptor but never the content
  bytes or opening. V0 does not
  permit deterministic, transcript-randomized or keyed K commitment modes.
  Production randomizer generation uses the supported runtime CSPRNG and fails
  closed; conformance-vector injection is not a production fallback.
- **Removal rule:** availability, binding, retention and replay readiness are
  separate typed properties. Removal is a later authenticated, AP-authorized
  event targeting the original event reference and commitment; it never
  rewrites the target. Directives against `NONE` or `REQUIRED` are inapplicable;
  consumer target absence affects readiness only and never directive validity,
  references, causality, order or duplicate identity. Re-presented bytes after
  valid removal remain removed and are classified separately as verified,
  unverifiable or substituted according to the retained opening and binding
  result; none becomes active. Physical destruction of the last local
  copy/opening is gated by O-13 and MUST NOT be inferred from replay position,
  timeout, retry/peer count, relay/provider/transport response, quota/storage
  pressure, cache eviction, private-mode teardown or session end.
- **Replay/reconstruction:** unavailable `REQUIRED` content keeps the event
  valid and parent-usable but stops the canonical AP replay suffix until its
  complete opening verifies. No timeout, retry, peer-count, relay response or
  causal independence skips the halt. In v0 `DETACHABLE` is permitted only when
  retained events/descriptors/directives reconstruct current AP state without
  the bytes. Checkpoints do not substitute; checkpoint-based AP-state
  reconstruction is suspended. Causal compaction remains possible, but
  `REQUIRED` content/openings are non-releasable AP-replay dependencies and
  fresh replicas require all of them in horizon.
- **Rationale/evidence:** `PRIV-05` through `PRIV-19` independently analyzed and
  reconciled the design; `HASH-004`, `HASH-005`, `PRIV-01`, `PRIV-03` and
  `PRIV-04` reject boundaryless legacy behavior. The complete decision,
  alternatives, attack analysis and minority findings are in
  `docs/protocol/styx-app-kernel-v0-payload-commitment-analysis.md`. The C0.2f
  model evaluated all sixteen required obligations and returned
  `NO_COUNTEREXAMPLE_WITHIN_BOUNDS`; exact bounds and residual risks are in
  `docs/protocol/styx-app-kernel-v0-payload-state-falsification-report.md`.
- **Rejected alternatives:** raw payload in the transcript; deterministic bare
  digest-plus-length; randomizer in the transcript; keyed commitment as the K
  default; committing SS/TR/RS ciphertext; unauthenticated `isPruned`-style
  state; rewriting historical events; a profile-selectable v0 cryptographic
  mode family.
- **Security/privacy:** descriptor-only history remains bounded and supports
  retained verification evidence. With a destroyed opening, the retained
  ledger alone is not intended to expose a practical equality/dictionary oracle
  under the future O-06 suite assumptions. Length, type and commitment remain
  correlatable; randomizer reuse is an honest-producer obligation; authorized
  recipients and copies remain outside any erasure claim. A single withheld or
  lost `REQUIRED` opening can halt a context indefinitely. Rollback past a
  removal directive may re-expose quarantined content under the OB-RS09
  non-claim. Randomized openings intentionally forfeit stable K-level cross-
  replica content deduplication; storage-level deduplication is outside K and
  can reintroduce equality leakage. K cannot verify at runtime that an AP
  profile's `DETACHABLE` declaration satisfies its reconstruction contract.
  Authority-bearing data classified as `REQUIRED` has no authorized removal or
  destruction path in v0; closing O-13 alone does not change that rule.
- **Dependent artifact:** O-06 selects exact domain tags, algorithms, widths and
  transcript bytes and prevents cross-event leaf equality; O-07 owns the
  suspended checkpoint authentication/acceptance/substitution contract; O-08
  sets resource and custody bounds; O-10 assigns rich local outcomes plus one
  opaque remote fetch result; O-11 chooses wire/storage/fetch encoding; O-13
  gates irreversible effects. C0.2f supplied bounded executable evidence for
  availability-sensitive replay, typed outcomes, checkpoint non-substitution
  and fresh reconstruction; dependent semantic changes require rerunning it.
- **Residual/reopen condition:** reopen on a C0.2f counterexample; an O-06 suite
  unable to meet the bounded binding/privacy contract; a profile requiring
  deterministic, keyed, provably hiding or chunk-partial-redaction semantics;
  infeasible atomic content/opening custody; unauthenticated implementation
  input; unreconstructable detachable state; any checkpoint AP-state
  substitution or change to its authentication/authority/acceptance/horizon/
  equivocation/late-admission contract; or an installed legacy population
  requiring migration.
- **Human ratification:** pending exact-final-HEAD approval under Issue #215.

### O-05 — Clock placement

- **Status:** `DECIDED`.
- **Rule:** v1 has no HLC or physical-time field in the semantic kernel. The
  O-01 per-credential sequence and authenticated causal parents are the kernel
  logical clock. An application profile may define an authenticated physical-
  time claim for one named AP purpose, but that claim MUST NOT influence kernel
  causality, deterministic order, credential authorization or freshness by
  itself.
- **Rationale/evidence:** `HLC-002` through `HLC-005`, `HLC-007`, `HLC-008` and
  `PRIV-01` show that current clock representations are not safe authority. The
  C0.2c comparison finds no kernel purpose not already served by sequence and
  reachability.
- **Rejected alternatives:** retaining HLC by inertia; trusting wall time for
  authorization, freshness, causality or universal order; repairing malformed
  clock input.
- **Security/privacy:** removing kernel physical time eliminates skew authority
  and one precision fingerprint. A profile that retains time still exposes its
  declared precision/source and remains subject to K-05 and O-12.
- **Dependent artifact:** author sequence and parent fields replace HLC in K.
  O-12 applies only to profiles retaining a physical-time claim.
- **Residual/reopen condition:** reopen only if a kernel invariant demonstrably
  requires physical time and cannot be expressed through O-01 causality or AP
  policy; convenience, display and arrival order are insufficient.
- **Human ratification:** pending exact-final-HEAD approval under Issue #211.

### O-06 — Event/content identifier semantics

- **Status:** `OPEN`.
- **Question:** which exact digest registry, transcript bytes and output width
  complete the decided identifier-role separation?
- **Selected semantic roles:** the event reference is a domain-separated digest
  derived from the canonical signed semantic transcript, excluding signature
  bytes and any carried identifier. After signature validation it serves only
  as parent reference, exact duplicate key and K-06 concurrent tiebreak. O-04
  owns the distinct payload/content commitment. An AP idempotency key, TR
  routing identifier and RS storage key remain separate owned values and MUST
  NOT substitute for event identity.
- **Rationale/evidence:** `ORDER-004`, `PRIV-01`, `PRIV-03` and `PRIV-04` show
  that identifiers and fork inputs cannot remain mutable conveniences. C0.2c
  establishes a non-circular semantic derivation and one purpose per identifier
  without authorizing exact bytes or an algorithm choice.
- **Rejected alternatives:** unsigned random identifiers influencing protocol
  behavior; treating payload/content, event, idempotency, routing and storage
  identifiers as interchangeable; including signature bytes in event identity.
- **Security/privacy:** identifiers affect deduplication, replay, fork evidence,
  reference integrity and correlation. Event references stay inside protected
  application objects unless a later profile explicitly accepts disclosure.
- **Missing evidence:** exact K-02 transcript bytes, digest algorithm registry,
  output width and executable negative vectors. O-04 now fixes the one-way
  descriptor-to-event-reference interaction without selecting bytes.
- **Dependent artifact:** exact event-reference derivation and negative vectors.
- **Smallest bounded follow-up:** specify and adversarially test the exact
  non-circular event-reference and payload-commitment domains, bytes, suites and
  registry.
- **Residual/closure condition:** close only when semantically distinct valid
  events cannot share a reference under the selected registry and every exact
  field has one unambiguous derivation.
- **Human ratification:** pending exact-final-HEAD acceptance under Issue #211
  that the semantic roles are fixed while exact derivation remains open.

### O-07 — Genesis and checkpoint evidence

- **Status:** `OPEN`.
- **Question:** what exactly is genesis, and what authenticates a checkpoint and
  makes it accepted for each permitted use?
- **Rationale/evidence:** `EVENT-002` and `EVENT-003` show divergent current
  initialization and missing deterministic clock injection.
- **Rejected alternatives:** inheriting either current genesis; embedding an
  ambient wall clock; leaving context or initial membership implicit; treating
  C0.2d's trusted synthetic `CheckpointEvidence` input as a production trust
  rule; allowing a checkpoint to substitute for AP replay in v0.
- **Security/privacy:** genesis anchors context, initial authority and replay
  separation. Checkpoint acceptance can replace self-verification with trust in
  a producer, expose possession at a horizon, admit rollback/equivocation and
  become invalid under late forks or revocations.
- **Missing evidence:** the outputs of O-01 through O-06; checkpoint
  authentication, AP-authorized producer/threshold and acceptance rules;
  anti-rollback/freshness, exact horizon, predecessor/equivocation, profile and
  suite-version binding, and late-admission recovery. No producer trust model is
  justified today.
- **Dependent artifact:** initialization transcript and genesis vectors;
  production checkpoint evidence and negative vectors. The checkpoint portion
  is a suspended gate for O-04 checkpoint-based `DETACHABLE` reconstruction and
  any `REQUIRED`-content substitution.
- **Smallest bounded follow-up:** derive genesis only after its inputs close.
  Separately determine whether any checkpoint substitution model is sound; if
  so, define K authentication/binding with AP authorization inputs, reopen
  O-01/O-04 (and O-02 if a new authority class is introduced), amend the threat
  model and rerun C0.2f/C0.3. The decision may keep substitution unsupported.
- **Residual/closure condition:** close only when every genesis field is
  necessary, authenticated and independently reproducible and every supported
  checkpoint use has one explicit authenticator, owner, acceptance rule,
  rollback/equivocation behavior and late-evidence response. Closing genesis
  alone MUST NOT silently close the checkpoint portion.
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
- **Missing evidence:** C0.2a assigns activation bounds to the application
  profile and requires capability/resource envelopes from the other layers.
  Concrete runtime-envelope and vertical-role capacity measurements are still
  missing.
- **Dependent artifact:** first supported profile and any later N-party profile.
- **Smallest bounded follow-up:** measure the intended runtime/session/transport
  envelopes, then evaluate explicit exhaustion, skew and denial-of-service
  cases without leaking profile choices into the kernel.
- **Residual/closure condition:** close only with enforceable limits and explicit
  out-of-profile rejection.
- **Human ratification:** pending final-HEAD acceptance that this remains open.

### O-09 — Kernel/profile responsibility split

- **Status:** `DECIDED`.
- **Rule:** the specification SHALL be factored into one Styx application
  semantic kernel plus separately versioned application, secure-session,
  runtime/storage, transport/routing and product/organizational profiles. Every
  normative obligation MUST have exactly one owning layer and explicit
  cross-layer inputs and outputs. A profile MUST NOT weaken or redefine a
  kernel invariant, and a success signal from one layer MUST NOT satisfy a
  different layer's gate.
- **Rationale/evidence:** `PRIV-01`, `PRIV-03` and `PRIV-04` corroborate the need
  to separate protocol, secure-session, runtime and vertical authority.
- **Normative rationale:** §1, §3, §4 and §5 of
  `docs/architecture/decisions/ADR-0007-application-protocol-authority.md`
  assign application-protocol, secure-session, runtime and vertical authority
  at the architectural level. The C0.2a responsibility matrix completes the
  specification-level allocation and the threat model supplies its adversary
  and trust-boundary inputs.
- **Evidence:**
  `docs/protocol/styx-app-kernel-v0-responsibility-matrix.md` assigns the known
  obligations to one owner and defines the required boundary contracts;
  `docs/security/STYX-THREAT-MODEL.md` defines the assets, adversaries,
  assumptions, visible information and required failure outcomes that the
  allocation must cover.
- **Rejected alternatives:** a monolithic core; duplicate ownership; ownerless
  rules; allowing a runtime or product vertical to redefine kernel acceptance;
  treating session membership, signature validity, durable storage or relay
  publication as application authorization or human delivery.
- **Security/privacy:** misplaced rules create bypasses and inconsistent
  security claims across runtimes. The one-owner rule prevents lower-layer
  success from bypassing application validation while keeping product policy
  out of the semantic kernel.
- **Dependent artifact:** conformance target structure and profile documents.
- **Residual/reopen condition:** reopen if a future obligation cannot be
  assigned without violating the one-owner invariant, a new trust boundary
  requires another normative owner, or implementation evidence shows that the
  required validation/state-change order cannot be preserved.
- **Human ratification:** pending final-HEAD approval by `maverde73` and
  independent approval by `manexada` under Issue #207.

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

### O-13 — Irreversible-effect authorization for content destruction

- **Status:** `OPEN`. This is a coordinating decision record, not a kernel
  object, transcript field or validation outcome. It does not block O-04
  semantic closure, C0.2f or the transcript-only C0.3 corpus.
- **Decision owner:** `AP` for authorization semantics only.
- **Referenced one-owner obligations:** AP owns the authorization policy and
  authenticated evidence; RS owns execution, custody and typed-loss behavior;
  PV owns operational/user disclosure. K supplies retention/removal evidence
  and owns no physical-destruction rule. This follows the O-02 split-obligation
  precedent and creates no aggregate multi-owner rule.
- **Question:** which authenticated evidence, if any, is sufficient to authorize
  destruction of the last local content copy or opening?
- **Interim rule:** until closure, destruction authority MUST NOT be triggered
  or inferred from replay position, timeout, retry/peer count,
  relay/provider/transport response, quota or storage pressure, cache expiry or
  eviction, private-mode teardown, session end or any runtime-convenience path.
  Logical removal, quarantine and withholding are the only permitted effects.
  RS reports loss of the last copy/opening as a typed durability failure, never
  as removal, and MUST NOT present eviction as erasure.
- **Profile consequence:** no supported profile may promise deletion, erasure or
  post-removal unlinkability until O-13 closes. PV presents removal as
  deletion-pending and discloses that quarantined bytes may remain locally.
  Closing O-13 does not make `REQUIRED` content removable: authority-bearing
  personal data in that class remains without an authorized logical-removal or
  destruction path unless O-04 is separately reopened.
- **Candidate-evidence bound:** any candidate using an accepted checkpoint,
  declared horizon or checkpoint-bound authority is unevaluable until O-07's
  checkpoint-authentication/acceptance contract closes.
- **Gate:** no implementation increment capable of destroying the last local
  content copy/opening may proceed before closure.
- **Closure:** requires the AP authorization rule, the linked RS and PV
  obligations and conformance evidence, plus explicit non-claims for other
  replicas, peers, backups and physical media.
- **Residual/reopen condition:** reopen if a rule permits destruction on
  evidence invalidated by a later fork/revocation, contradicts O-04 or the
  quarantine interim, or proves operationally infeasible.
- **Human ratification:** pending under a separate approved decision that closes
  this record; Issue #215 only creates and constrains it.

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

**C0.3 verdict: `NO-GO`.** The C0.2f payload-state falsification gate required
by O-04 has passed within its declared bounds, but O-06 through O-08 and O-10
still contain choices required to derive normative bytes or adversarial
expectations; O-07 explicitly includes the previously deferred checkpoint-
authentication contract. O-12 is
additionally blocking for any profile that retains a physical-time claim; it is
inapplicable only to profiles that omit physical time. O-11 intentionally does
not block a transcript-only C0.3 corpus. Starting that corpus now would freeze
the remaining guesses and create cost pressure on later human decisions.

The smallest safe sequence is:

1. preserve the completed O-09 responsibility split and the C0.2b O-02/O-03
   separation of application authority, author credentials, session identity,
   routing identity and context identifiers;
2. preserve the C0.2c O-01 chain/frontier topology, O-05 clock placement and
   O-06 semantic identifier-role separation;
3. retain and extend the bounded C0.2d causal-flow falsification model whenever
   later choices change its inputs; its current small-state run found no
   counterexample within bounds and does not replace formal proof;
4. preserve and rerun the completed C0.2f gate when its inputs change, then
   close exact identifier derivation, genesis/checkpoint evidence, cardinality
   and error questions O-06 through O-10, plus O-12 for any time-bearing
   profile, without product implementation authority; retain O-11 for the later
   wire/storage decision;
5. approve the exact Apache-2.0 path inventory for the future corpus;
6. execute C0.3: specification-derived adversarial corpus plus a third
   implementation written only from the specification;
7. align JavaScript in C0.4; align or freeze the minimum Dart surface only if it
   remains useful as independent evidence.

O-13 does not block transcript-only C0.3, but no destruction-capable increment
or deletion/erasure/unlinkability claim may proceed until it closes.

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
