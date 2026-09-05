# APP-CORE-IFACE-0 hostile-atom derivation candidate

Status: pre-ratification working candidate. This file is not repository
authority and authorizes no implementation.

## Purpose

Freeze the size and derivation of the APP-core hostile inventory before
implementation. Review may amend the schema or rules, but it cannot add
unbounded prose categories after ratification or let the executor choose which
fields are “relevant”.

## Exact current source cardinalities

The current candidates mechanically yield:

| Source | Cardinality |
| --- | ---: |
| property-bearing object schemas | 78 |
| direct `$defs` property-bearing objects | 73 |
| inline/union-arm property-bearing objects | 5 |
| declared object properties | 323 |
| directly required property occurrences | 322 |
| semantic rules | 83 |
| custom-keyword occurrences | 26 |

Conditional `required` predicates inside `ApplicationEventProjectionV0` do not
enter the direct omission count. They are exercised by the literal 13-row
conditional branch matrix. This prevents an `if` predicate from being mistaken
for an unconditional field requirement.

## Structural atom derivation

Given the exact schema, derive the structural relation from
`APP-CORE-IFACE-0-STRUCTURAL-AXES-CANDIDATE.json`. It covers every
property-bearing object schema, including five inline/union-arm objects, and
reconciles every assertion/applicator keyword used by the schema. No keyword
may be treated as covered merely because a standards-compliant validator is
expected to implement it.

The 24 closed structural rule families include omission and null substitution,
raw duplicate and unknown properties, type and `$ref` target violations,
`const`/`enum`/pattern/cardinality boundaries, array-item, `maxItems` and uniqueness
violations, positive and negative union-arm coverage, every `allOf` arm, the
literal conditional matrix, `not` and `maxProperties`.

Current structural cardinality:

```text
1,450 structural execution instances
```

Stable instance IDs concatenate the structural rule ID with the canonical
schema-keyword/property pointer or literal conditional-row ID. No
normalization, truncation or hash alias is permitted. A structural mutant is
killed only by its corresponding instance, not by a crash, unrelated semantic
rule or outer malformed fixture.

The structural-axis registry also fixes the perturbation kind and expected
disposition for every rule family. Request carriers execute as blind input;
response carriers execute only as post-output mutation with the oracle
withheld. Rejecting request instances must expose no response bytes and
rejecting response instances must be stopped before release. The thirteen
conditional rows derive `ACCEPT` or `REJECT` only from their literal
`_ACCEPTS`/`_REJECTS` suffix; any other suffix fails closed. A witness registry
cannot substitute a different perturbation or disposition while retaining the
same instance ID.

Exactly one keyword occurrence is declared logically redundant rather than
falsely reported as a target-only mutant kill: `maxProperties: 0` on the closed
empty `DescribeProfileInputV0` shape. It retains a live rejection observation
and a separate validator self-test, and requires explicit human ratification.
The other 1,449 instances use target-only counterfactual isolation.

## Canonical seed registry

The executable increment must contain one machine-readable seed registry with
exactly 78 rows. Each row contains at least:

```text
objectSchemaId
objectSchemaPointer
objectSchemaSha256
carrierCaseId
carrierDirection
disclosureClass
operation
carrierFile
carrierSha256
targetJsonPointer
targetCanonicalJsonSha256
positiveObservationId
structuralFamilyIds
```

`carrierCaseId` selects one otherwise valid operation request or response.
`targetJsonPointer` selects exactly one occurrence validating against that
object-schema pointer. The extracted canonical object bytes must match its
digest before mutation. A seed cannot serve a different schema by structural similarity,
and no seed may come from expected-output bytes disclosed only after the blind
freeze. Response-only definitions are exercised in the reference/interface
increment; the independent blind kit supplies their schemas but not expected
seed bytes before output freeze.

The seed verifier rejects a missing/extra/duplicate object-schema pointer,
unresolved pointer, wrong schema, digest mismatch or an object that does not
validate before mutation. The exact schema is
`APP-CORE-IFACE-0-SEED-REGISTRY-SCHEMA-CANDIDATE.json`.

## Semantic atom families

Every row in
`APP-CORE-IFACE-0-SEMANTIC-CONSTRAINTS-CANDIDATE.json` contributes exactly one
top-level semantic atom family:

```text
SEM-<rule id>
```

The row's exact scenario and mutant IDs are mandatory. A family is not
necessarily one execution. Any rule quantified over targets, union arms,
relation rows, leaf positions or forbidden-value families expands into a
finite set of execution instances before the inventory can be frozen.

## Exact ordered-family identities

```text
structural rule families: 24
SHA-256: 9624a24ff7a5b748afc66eca1c59e8deaf6db9cf37598523dd1d8ef8efdb450a

semantic families: 83
SHA-256: 78f4ebf3956a851f3b90b0bb97944100e608a575b8c27a96772f86ba186754a0

combined rule families: 107
SHA-256: b0a4d4ee1a657b84e850c13e9c51363006be21ebb23cc71613019625c5b907dc
```

Each digest is over the lexicographically sorted UTF-8 identifiers, one
identifier plus one LF per row. The family count is derived only after exact
equality of:

- schema object/property/keyword-occurrence sets;
- ownership coverage;
- semantic rule/scenario/mutant sets;
- custom-keyword coverage; and
- canonical seed object-schema-pointer set.

A count or family digest alone is not execution evidence. The validator
compares the complete ordered family relation, expands every quantified family
through the ratified instance-axis registry, and requires one observation per
resulting instance in both the reference and independent interface
implementations where the owning phase permits it.

## Quantified execution instances

The schema currently expands to these exact unique terminal positions:

| Root | All terminal paths | String terminal paths | Sorted string-path SHA-256 |
| --- | ---: | ---: | --- |
| `InterfaceRequestV0` | 272 | 217 | `3af5513dff8078bbbaed3e3153dcf9204c0f49608b2925c491d5ceb194fde337` |
| `InterfaceResponseV0` | 444 | 377 | `ae9149055d83b3c1960d6f0ec6db796a4e9b019551632e70dc86571b8f90c3a0` |

Paths use definition-qualified union-arm labels and `*` for one bounded array
item. The digest is over the sorted unique path plus LF relation. A duplicate
path, unresolved `$ref`, schema cycle or count/digest mismatch fails closed.

At minimum:

- `ACV-049` expands to the Cartesian product of all 377 response string paths
  and the ten literal provenance families in its parameters: 3,770 distinct
  execution instances;
- `ACV-050` expands to all 26 custom-keyword occurrences plus one unknown-keyword
  negative control: 27 distinct execution instances; and
- `ACV-048` expands all nine forbidden authority/runtime/cross-plane field
  families across the 78 property-bearing object schemas: 702 distinct
  execution instances; and
- `ACV-066` expands the six reserved reason rows and the independently
  prohibited `referenceVerification = REJECTED` observation into seven
  post-output mutation instances whose row-coherent responses must be rejected
  solely by the reserved-reachability detector; and
- `ACV-067` expands the bounded signature carrier into one O-08
  pre-decode/pre-allocation limit instance; and
- `ACV-068` expands the exact 17-row candidate-only, standalone and genesis
  signature-verification path relation into 17 blind-input instances; and
- `ACV-069` expands the exact 33-row terminal-predicate relation into 33
  distinct reachability and gate-order instances; and
- multi-target, union-arm, field-by-field, exact-row and full-replay rules use
  the literal axis assigned by
  `APP-CORE-IFACE-0-INSTANCE-AXES-CANDIDATE.json`. They cannot be reported as
  one aggregate pass.

The current exact expansion is:

```text
1,450 structural instances
+ 5,149 semantic instances
= 6,599 total structural-plus-semantic execution instances
```

The 83-row instance-axis registry has no unresolved axis and has SHA-256
`04fd304ac6b23add64033b45282ac0d46fe09d44f92651881995f4727c9e0832`.

## Derived interface maxima

`derive_interface_maxima.py` symbolically enumerates all twelve carrier roots,
applies the exact scalar widths and all 27 concrete array-use bounds, and
accounts for content-domain coverage, alias-group disjointness and
purpose-keyed evidence deduplication. The exact V5 literals are:

| Quantity | Octets | Maximizing root |
| --- | ---: | --- |
| `OUTER_REQUEST_OCTETS` | 138499357 | `REQUEST-EVALUATE_CANDIDATE` |
| `OUTER_RESPONSE_OCTETS` | 71052634 | `RESPONSE-EVALUATE_CANDIDATE` |
| `MAX_RETAINED_DECODED_OCTETS` | 35284168 | `REQUEST-EVALUATE_CANDIDATE` |

The manifest embeds the deterministic component breakdowns for both distinct
maximizing roots and binds the complete twelve-root measurement relation by
SHA-256 `3ead04f4d3c35e159baa69bb44ec6cd1221c1f736a275306271057994279258a`.
Exact duplicate evidence increases canonical request bytes but is compared and
merged without retaining a second decoded copy.

Its execution-phase partition is the working
`APP-CORE-IFACE-0-EXECUTION-PHASES-CANDIDATE.json`, SHA-256
`7dad552e9bcde710205302f72c81aac7ac98e350fc31cb4a11007739428cc0ed`.
It prevents a response-only hygiene mutation or validator self-test from being
misreported as an oracle-free blind-input comparison. The exact ACV-048 phase
counts remain derived from the future 78-row seed-carrier directions.
Its literal semantic relations contain 23 content-axis rows, the 25-row F13
candidate relation with exact O-10 stage, ten fork/join-label rows, 16
authority-projection dimensions, 11 graph-admission dimensions, 16 transcript
result rows, 17 genesis result rows and 33 terminal-predicate rows; the relation artifact has
SHA-256
`ae285b0f5d760993017f56e500889a6d18475f9a33e9b30f6aa3d570564b812f`.

The still-to-be-generated 78-row positive seed registry has a closed row schema
in `APP-CORE-IFACE-0-SEED-REGISTRY-SCHEMA-CANDIDATE.json`, SHA-256
`8b98b69ee88bdbf59f5de1fc20e4008aaedd97c3f09a6c615869997501eeb2ef`.
Exact carriers are implementation outputs derived from Base
`16274cc194cd2f8f7b631332687a252bad92ce02`; the schema does not fabricate
them or relax that dependency.

The carrier relation itself must conform to
`APP-CORE-IFACE-0-POSITIVE-CARRIER-INVENTORY-SCHEMA-CANDIDATE.json`, SHA-256
`8e469d88234e7194d8612f43491f3ea43c1c0d6a4b1becaa4be844e1ff75949f`.
It closes all twelve direction/operation roots, all 78 object schemas and all
54 literal `oneOf` arms while withholding response bytes until output freeze.

The complete mechanically derived carrier-reachability relation is
`APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json`, SHA-256
`6ead453a551472a87ca00ef812a8952ebaeb76d5cdbbe1e6dcf10279f32147ca`.
It is regenerated by `derive_app_core_carrier_reachability.py`, SHA-256
`a349019ca273d88016f45b09e40afe6fcee71654617e230ef1dcebde9a5c92b4`,
from the interface schema alone. Every remaining `$defs` entry is reachable
from at least one of the twelve direction/operation roots. The removed
`DescribeProfileRequestV0`, `OperationV0` and `TranscriptCandidateV0`
definitions were unused aliases/meta-types and therefore could not honestly
carry schema assertions or conformance evidence.

The structural axis registry has SHA-256
`7e41ee90d6407d61d1369a978b5583a171277e47c5b27a4370cf65bdb3a62369`.
Its 1,450 count is frozen only after a populated witness registry maps every
instance to an exact positive carrier, target pointer, perturbation and expected
observation. Until then it is a closed derivation candidate, not execution
evidence.

The human-ratified V21+V22+V23+V24 structural-isolation relation is
`APP-CORE-IFACE-0-STRUCTURAL-ISOLATION-RELATION-CANDIDATE.json`, SHA-256
`7cfdeb97ab4dae27a8a5ca03cb0def4d5b87b1d0b28439a3dd40d2d38793b87d`.
It binds the exact 31 carrier reselections and the literal Appendix B/C/D/E
partition. Counts or family-wide defaults cannot substitute for that relation.

The bounded mutation search is now explicit in
`APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json`, SHA-256
`db8ebfaf3d34a8d47dae6c1996eb4cadc91d737f13a9278a75c2ea441ebea9d8`.
It contains one ordered recipe for each of the 24 perturbation kinds; palette
exhaustion is a failure, not permission to invent a convenient value.

All 93 pairwise `oneOf` arm relations are already explicit in
`APP-CORE-IFACE-0-ONEOF-DISJOINTNESS-CANDIDATE.json`, SHA-256
`eb992a044c5a5c53b4ea0c01b743adfd5846896d30f9274e4f26a5927f193382`:
91 use disjoint literal constraints, one uses a required property forbidden by
the other closed shape, and the root request/response pair expands all 36
nested arm combinations. The 1,450-row witness registry must conform to
`APP-CORE-IFACE-0-STRUCTURAL-WITNESS-SCHEMA-CANDIDATE.json`, SHA-256
`0d8b046f34c3c678804e976cffa2e88d8bcd9136d163762a9ed73531f5a6cd3c`.

`GenesisEvaluationReasonV0` deliberately omits
`STANDALONE_VERIFICATION_KEY_REJECTED`: the genesis request has no standalone
verification-key input, so admitting that literal would describe an
unreachable result rather than a valid interface outcome. This moves one
structural instance from the `$ref` axis to the `enum` axis. The later
reachability correction separately removed seven unreachable structural
assertions. V5 then adds the capability projection and its structural axes,
producing the exact total of 1,450 instances.

This exact count remains a pre-ratification candidate: review may amend a
semantic relation, but any amendment must change the literal relation, expected
count and digest together. It cannot append an unbounded prose category.

## Cross-purpose substitution reconciliation

The previously listed supplement is not an additional open-ended inventory.
It maps exactly to existing families:

| Required substitution | Existing family or structural relation |
| --- | --- |
| ceremony capability/verdict in serializable data | `ACV-048` plus `STR-UNKNOWN_PROPERTY-*` |
| O-10 primary in transcript/genesis rejection | `ACV-043`, `ACV-044`, `ACV-045` |
| candidate K-retention/primary in evidence update | `ACV-037` |
| O-11 mutation/commit material in APP-core JSON | `ACV-048` plus `STR-UNKNOWN_PROPERTY-*` |
| SS membership/decryption as K/AP authority | `ACV-040`, `ACV-041`, `ACV-048` |
| Nostr/transport identity, order or acknowledgement as semantic evidence | `ACV-016`, `ACV-020`, `ACV-023`, `ACV-032`, `ACV-048` |
| caller-selected parser/profile fallback | `ACV-013`, `ACV-016`, `ACV-047` |
| snapshot/delta digest as prior/successor authority | `ACV-018`, `ACV-019`, `ACV-034`, `ACV-036`, `ACV-048` |
| runtime provenance in output | quantified `ACV-049` |

No new semantic family is therefore added by this reconciliation. A reviewer
may challenge a mapping, but must identify the exact missing construction; the
executor cannot add a prose category or silently reuse an aggregate scenario.

## Blind-conformance split

Input-side structural and semantic atoms enter the oracle-free blind kit.
Response-only schema atoms are generated only after the independent output
freeze so they cannot disclose expected response shapes beyond the already
public schema. Mutation results remain withheld until freeze.

Pre-dispatch invalid request atoms expect no response bytes and harness
`REQUEST_REJECTED`. Operation-level atoms expect one exact operation response.
Timeout, crash, empty output for an operation-level case, extra bytes or a
generic exception is failure.
