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
| property-bearing object schemas | 87 |
| direct `$defs` property-bearing objects | 82 |
| inline/union-arm property-bearing objects | 5 |
| declared object properties | 347 |
| directly required property occurrences | 344 |
| semantic rules | 84 |
| custom-keyword occurrences | 25 |

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
1,553 structural execution instances
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
The other 1,552 instances use target-only counterfactual isolation unless a
retained, provider-ratified co-constraint row explicitly classifies them
otherwise.

## Canonical seed registry

The executable increment must contain one machine-readable seed registry with
exactly 87 rows. Each row contains at least:

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
SHA-256: 637580c267eaf8632b744922c2376bc10c142b4e20169e08a4ad4629c8943f64

combined rule families: 107
SHA-256: c472e8996aa682f1c5fa079ca068dd0a404d5a4cedfab2e37b0b1c50d9780de5
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
| `InterfaceRequestV0` | 301 | 248 | `586433f51ab810b2467452486c4a48412faefbbabd1408ed4edb0db9c9cdb2d4` |
| `InterfaceResponseV0` | 473 | 406 | `cdd2f3f325800fffd08b23c08ab51d3b3ba6a3eb949af10ad488d72a854e5fe4` |

Paths use definition-qualified union-arm labels and `*` for one bounded array
item. The digest is over the sorted unique path plus LF relation. A duplicate
path, unresolved `$ref`, schema cycle or count/digest mismatch fails closed.

At minimum:

- `ACV-049` expands to the Cartesian product of all 406 response string paths
  and the ten literal provenance families in its parameters: 4,060 distinct
  execution instances;
- `ACV-050` expands to all 25 custom-keyword occurrences plus one unknown-keyword
  negative control: 26 distinct execution instances; and
- `ACV-048` expands all nine forbidden authority/runtime/cross-plane field
  families across the 87 property-bearing object schemas: 783 distinct
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
1,553 structural instances
+ 5,535 semantic instances
= 7,088 total structural-plus-semantic execution instances
```

The 84-row instance-axis registry has no unresolved axis and has SHA-256
`20e3a07558fbe5fb0f95c52eb31f6b24b69f8a6137a69b858260d70c60576201`.

## Derived interface maxima

`derive_interface_maxima.py` symbolically enumerates all twelve carrier roots,
applies the exact scalar widths and all 30 concrete array-use bounds, and
accounts for content-domain coverage, alias-group disjointness and
purpose-keyed evidence deduplication. The exact V5 literals are:

| Quantity | Octets | Maximizing root |
| --- | ---: | --- |
| `OUTER_REQUEST_OCTETS` | 138547674 | `REQUEST-EVALUATE_EVIDENCE_UPDATE` |
| `OUTER_RESPONSE_OCTETS` | 71096500 | `RESPONSE-EVALUATE_CANDIDATE` |
| `MAX_RETAINED_DECODED_OCTETS` | 35300616 | `REQUEST-EVALUATE_CANDIDATE` |

The manifest embeds the deterministic component breakdowns for both distinct
maximizing roots and binds the complete twelve-root measurement relation by
SHA-256 `098c010fa03e22d87dd8a42e28e7068396f44139a5d3981dcc10b33d9897b239`.
Exact duplicate evidence increases canonical request bytes but is compared and
merged without retaining a second decoded copy.

Its execution-phase partition is the working
`APP-CORE-IFACE-0-EXECUTION-PHASES-CANDIDATE.json`, SHA-256
`9fc0c3929d252bab7fb435f657b69dd8e7f2d5c0d169d7b946f4eeaf402fc820`.
It prevents a response-only hygiene mutation or validator self-test from being
misreported as an oracle-free blind-input comparison. The exact ACV-048 phase
counts remain derived from the future 87-row seed-carrier directions.
Its literal semantic relations contain 23 content-axis rows, the 25-row F13
candidate relation with exact O-10 stage, ten fork/join-label rows, 16
authority-projection dimensions, 11 graph-admission dimensions, 16 transcript
result rows, 17 genesis result rows and 33 terminal-predicate rows; the relation artifact has
SHA-256
`ae285b0f5d760993017f56e500889a6d18475f9a33e9b30f6aa3d570564b812f`.

The still-to-be-generated 87-row positive seed registry has a closed row schema
in `APP-CORE-IFACE-0-SEED-REGISTRY-SCHEMA-CANDIDATE.json`, SHA-256
`14bc332e90ae7d7730098279f2b4c99054dd0c1e6768aeb4b55620f8282f5cf2`.
Exact carriers are implementation outputs derived from the combined-remediation Base
`e0af4e1e2173deb2481eabdb24d8622282b33455`; the schema does not fabricate
them or relax that dependency.

The carrier relation itself must conform to
`APP-CORE-IFACE-0-POSITIVE-CARRIER-INVENTORY-SCHEMA-CANDIDATE.json`, SHA-256
`8e469d88234e7194d8612f43491f3ea43c1c0d6a4b1becaa4be844e1ff75949f`.
It closes all twelve direction/operation roots, all 87 object schemas and all
57 literal `oneOf` arms while withholding response bytes until output freeze.

The complete mechanically derived carrier-reachability relation is
`APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json`, SHA-256
`b3e33bdf0a07fa7d9f08c9158e20a4ce912df0c32d9dfadd6f29a7a422695208`.
It is regenerated by `derive_app_core_carrier_reachability.py`, SHA-256
`06297a28f6959c47b4d5558a89d776fc2d124c3f2c76072796dbf02935c89480`,
from the interface schema alone. Every remaining `$defs` entry is reachable
from at least one of the twelve direction/operation roots. The removed
`DescribeProfileRequestV0`, `OperationV0` and `TranscriptCandidateV0`
definitions were unused aliases/meta-types and therefore could not honestly
carry schema assertions or conformance evidence.

The structural axis registry has SHA-256
`61f6d5c359604e7d194525d013b5ac5ddd2eb1e4725c3e0b0f90d182e8642227`.
Its 1,553 count is frozen only after a populated witness registry maps every
instance to an exact positive carrier, target pointer, perturbation and expected
observation. Until then it is a closed derivation candidate, not execution
evidence.

The V3 structural-isolation relation, mechanically migrated by exact source
identity under the provider-ratified combined-remediation authority, is
`APP-CORE-IFACE-0-STRUCTURAL-ISOLATION-RELATION-CANDIDATE.json`, SHA-256
`7fd65f6a1348b361b745df29a48573d5df9d97dd180ae609195db8a711317177`.
It binds the exact carrier reselections and the source-identity-preserved
Appendix B/C/D/E partition. Counts or family-wide defaults cannot substitute
for that relation.

The bounded mutation search is now explicit in
`APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json`, SHA-256
`db8ebfaf3d34a8d47dae6c1996eb4cadc91d737f13a9278a75c2ea441ebea9d8`.
It contains one ordered recipe for each of the 24 perturbation kinds; palette
exhaustion is a failure, not permission to invent a convenient value.

All 101 pairwise `oneOf` arm relations are already explicit in
`APP-CORE-IFACE-0-ONEOF-DISJOINTNESS-CANDIDATE.json`, SHA-256
`9f37ed686591b22514450e1ee8fa31d9d24a0c6fd336904fd92a51877abde204`:
99 use disjoint literal constraints, one uses a required property forbidden by
the other closed shape, and the root request/response pair expands all 36
nested arm combinations. The 1,553-row witness registry must conform to
`APP-CORE-IFACE-0-STRUCTURAL-WITNESS-SCHEMA-CANDIDATE.json`, SHA-256
`b7073e8826f905362e0bec8d1d5e9678da1615a4629affe1657717d8b2584013`.

`GenesisEvaluationReasonV0` deliberately omits
`STANDALONE_VERIFICATION_KEY_REJECTED`: the genesis request has no standalone
verification-key input, so admitting that literal would describe an
unreachable result rather than a valid interface outcome. This moves one
structural instance from the `$ref` axis to the `enum` axis. The later
reachability correction separately removed seven unreachable structural
assertions. V5 then adds the capability projection and its structural axes,
producing the exact total of 1,553 instances.

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
