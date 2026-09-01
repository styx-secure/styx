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
| declared object properties | 307 |
| directly required property occurrences | 306 |
| semantic rules | 66 |
| custom-keyword occurrences | 24 |

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

The 23 closed structural rule families include omission and null substitution,
raw duplicate and unknown properties, type and `$ref` target violations,
`const`/`enum`/pattern/cardinality boundaries, array-item and uniqueness
violations, positive and negative union-arm coverage, every `allOf` arm, the
literal conditional matrix, `not` and `maxProperties`.

Current structural cardinality:

```text
1,400 structural execution instances
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
The other 1,399 instances use target-only counterfactual isolation.

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
structural rule families: 23
SHA-256: 5c552a6a1217a914c84731ddd1b116429c00af4a37a762fee620ee5bae04204b

semantic families: 66
SHA-256: b9c4ea3bdb3f61b8f7d759ad81ce57d5c5fa7e763aef26cc27fb47a2e5e25983

combined rule families: 89
SHA-256: f63b75c97efc2af0abc25ffbe5922fbc1e92fabb79446fc24e127c348b5f2d3f
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
| `InterfaceRequestV0` | 268 | 215 | `8d9b999904ad96748742acc9c1f998fa3976eddc3d7bdfb397dd76358d116df7` |
| `InterfaceResponseV0` | 423 | 359 | `1e76b649c0c5e74f9ae3b49ab88a6e443dfc3be396be04fe07a7703886057c90` |

Paths use definition-qualified union-arm labels and `*` for one bounded array
item. The digest is over the sorted unique path plus LF relation. A duplicate
path, unresolved `$ref`, schema cycle or count/digest mismatch fails closed.

At minimum:

- `ACV-049` expands to the Cartesian product of all 359 response string paths
  and the ten literal provenance families in its parameters: 3,590 distinct
  execution instances;
- `ACV-050` expands to all 24 custom-keyword occurrences plus one unknown-keyword
  negative control: 25 distinct execution instances; and
- `ACV-048` expands all nine forbidden authority/runtime/cross-plane field
  families across the 78 property-bearing object schemas: 702 distinct
  execution instances; and
- `ACV-066` expands the two reserved reason rows and the independently
  prohibited `referenceVerification = REJECTED` observation into three
  post-output mutation instances whose row-coherent responses must be rejected
  solely by the reserved-reachability detector; and
- multi-target, union-arm, field-by-field, exact-row and full-replay rules use
  the literal axis assigned by
  `APP-CORE-IFACE-0-INSTANCE-AXES-CANDIDATE.json`. They cannot be reported as
  one aggregate pass.

The current exact expansion is:

```text
1,400 structural instances
+ 4,831 semantic instances
= 6,231 total structural-plus-semantic execution instances
```

The 66-row instance-axis registry has no unresolved axis and has SHA-256
`192e81c48f5596b01bbbf35914443c6b61b212675127db96a52d597980faf815`.

## Derived interface maxima

`derive_interface_maxima.py` symbolically enumerates all twelve carrier roots,
applies the exact scalar widths and all 27 concrete array-use bounds, and
accounts for content-domain coverage, alias-group disjointness and
purpose-keyed evidence deduplication. The exact V5 literals are:

| Quantity | Octets | Maximizing root |
| --- | ---: | --- |
| `OUTER_REQUEST_OCTETS` | 138642769 | `REQUEST-EVALUATE_CANDIDATE` |
| `OUTER_RESPONSE_OCTETS` | 71196086 | `RESPONSE-EVALUATE_CANDIDATE` |
| `MAX_RETAINED_DECODED_OCTETS` | 35351200 | `REQUEST-EVALUATE_CANDIDATE` |

The manifest embeds the deterministic component breakdowns for both distinct
maximizing roots and binds the complete twelve-root measurement relation by
SHA-256 `aef675a27fb8f69d75a1c452a3a9f0ef8c35175d4c0c97fdf2ce2bceaccad4df`.
Exact duplicate evidence increases canonical request bytes but is compared and
merged without retaining a second decoded copy.

Its execution-phase partition is the working
`APP-CORE-IFACE-0-EXECUTION-PHASES-CANDIDATE.json`, SHA-256
`fe5fb5477cc7f28424861f59b5bf2776b07d70f051dd1af2766648f463fae4a1`.
It prevents a response-only hygiene mutation or validator self-test from being
misreported as an oracle-free blind-input comparison. The exact ACV-048 phase
counts remain derived from the future 78-row seed-carrier directions.
Its literal semantic relations contain 23 content-axis rows, the 25-row F13
candidate relation with exact O-10 stage, 14 transcript result rows and 16
genesis result rows; the relation artifact has
SHA-256
`dd1408447de14e5617224d18c84d3f04230690f523b1fe6a4a31fb8ad35a41a3`.

The still-to-be-generated 78-row positive seed registry has a closed row schema
in `APP-CORE-IFACE-0-SEED-REGISTRY-SCHEMA-CANDIDATE.json`, SHA-256
`8b98b69ee88bdbf59f5de1fc20e4008aaedd97c3f09a6c615869997501eeb2ef`.
Exact carriers are implementation outputs derived from Base
`16274cc194cd2f8f7b631332687a252bad92ce02`; the schema does not fabricate
them or relax that dependency.

The carrier relation itself must conform to
`APP-CORE-IFACE-0-POSITIVE-CARRIER-INVENTORY-SCHEMA-CANDIDATE.json`, SHA-256
`17dc0123dc8df3dff6b0e78ec372d93d5375dc1fd610a0d40e542d6eb1f17665`.
It closes all twelve direction/operation roots, all 78 object schemas and all
54 literal `oneOf` arms while withholding response bytes until output freeze.

The complete mechanically derived carrier-reachability relation is
`APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json`, SHA-256
`b6bf05336c46d9e23c78adb9e283b3b05c0238730aa38d3d78337ffdf05afc6f`.
It is regenerated by `derive_app_core_carrier_reachability.py`, SHA-256
`a349019ca273d88016f45b09e40afe6fcee71654617e230ef1dcebde9a5c92b4`,
from the interface schema alone. Every remaining `$defs` entry is reachable
from at least one of the twelve direction/operation roots. The removed
`DescribeProfileRequestV0`, `OperationV0` and `TranscriptCandidateV0`
definitions were unused aliases/meta-types and therefore could not honestly
carry schema assertions or conformance evidence.

The structural axis registry has SHA-256
`86676cf5bab87d1eaf7de0a776fa4e94cf2b3fdfebb0605452af523d73bb65ee`.
Its 1,400 count is frozen only after a populated witness registry maps every
instance to an exact positive carrier, target pointer, perturbation and expected
observation. Until then it is a closed derivation candidate, not execution
evidence.

The bounded mutation search is now explicit in
`APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json`, SHA-256
`2fb0d6d55a86965624cd6fb0e077e72c10586eecb2e0c66562c0fa7006428620`.
It contains one ordered recipe for each of the 23 perturbation kinds; palette
exhaustion is a failure, not permission to invent a convenient value.

All 93 pairwise `oneOf` arm relations are already explicit in
`APP-CORE-IFACE-0-ONEOF-DISJOINTNESS-CANDIDATE.json`, SHA-256
`f65ef4f70bd082e769abbe08d397c56550edeb48f66a407d746808e56abea97b`:
91 use disjoint literal constraints, one uses a required property forbidden by
the other closed shape, and the root request/response pair expands all 36
nested arm combinations. The 1,400-row witness registry must conform to
`APP-CORE-IFACE-0-STRUCTURAL-WITNESS-SCHEMA-CANDIDATE.json`, SHA-256
`3ae8047d474241e3d3e5c4500e7c8f21dc62e47fd1cab283edb11177111b3d78`.

`GenesisEvaluationReasonV0` deliberately omits
`STANDALONE_VERIFICATION_KEY_REJECTED`: the genesis request has no standalone
verification-key input, so admitting that literal would describe an
unreachable result rather than a valid interface outcome. This moves one
structural instance from the `$ref` axis to the `enum` axis. The later
reachability correction separately removed seven unreachable structural
assertions. V5 then adds the capability projection and its structural axes,
producing the exact total of 1,400 instances.

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
