# APP-CORE-IFACE-0 witness-generation contract candidate

Status: pre-ratification working candidate. This file is not repository
authority and authorizes no implementation.

## Objective

Define how the future 78-row positive seed registry and 1,450-row structural
witness registry are generated without executor-selected coverage, convenient
fixtures or disclosed response oracles. The generated registries are evidence;
they are not protocol authority and are never runtime adapter inputs.

## Frozen inputs

Generation receives only provider-bound exact bytes for:

1. the ratified interface schema and ownership registry;
2. the ratified structural-axis and `oneOf` disjointness registries;
3. the ratified seed and witness registry schemas;
4. the closed positive request-case inventory;
5. the independently generated, withheld positive response-case inventory;
6. the selected O-08 envelope and native protocol dependencies; and
7. the reference validator used only to establish positive carrier validity.

Every file is verified before parsing. A missing, extra, duplicate, remote or
mutable dependency fails closed. Generation receives no expected hostile
result, hand-authored coverage exception, wildcard, `N/A`, runtime identity or
fallback parser/profile selector.

The exact bounded search authority is
`APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json`, SHA-256
`db8ebfaf3d34a8d47dae6c1996eb4cadc91d737f13a9278a75c2ea441ebea9d8`.
That digest must be replaced only by a new reviewed and human-ratified contract
version.

The exact V21+V22+V23+V24 isolation authority is
`APP-CORE-IFACE-0-STRUCTURAL-ISOLATION-RELATION-CANDIDATE.json`, SHA-256
`7cfdeb97ab4dae27a8a5ca03cb0def4d5b87b1d0b28439a3dd40d2d38793b87d`.
The generator must reproduce its carrier reselections and Appendix B/C/D/E
relations by literal equality; it may not infer exceptions from aggregate
counts.

The positive-case inventory must conform to
`APP-CORE-IFACE-0-POSITIVE-CARRIER-INVENTORY-SCHEMA-CANDIDATE.json`, SHA-256
`8e469d88234e7194d8612f43491f3ea43c1c0d6a4b1becaa4be844e1ff75949f`.
The populated inventory receives its own digest in the executable Issue after
the carrier bytes produced from exact Base
`16274cc194cd2f8f7b631332687a252bad92ce02` are frozen.

Carrier eligibility is derived from the exact reachability relation in
`APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json`, SHA-256
`6ead453a551472a87ca00ef812a8952ebaeb76d5cdbbe1e6dcf10279f32147ca`.
The relation is regenerated from the schema by
`derive_app_core_carrier_reachability.py`, SHA-256
`a349019ca273d88016f45b09e40afe6fcee71654617e230ef1dcebde9a5c92b4`.
The generator must reproduce byte-identical output and prove that every
remaining definition, object schema and union arm is reachable from at least
one of the twelve operation/direction roots. An unreachable definition is a
schema defect and cannot be waived by a synthetic carrier or coverage note.

## Canonical enumeration

The object-schema relation is the lexicographically sorted sequence of the 78
canonical JSON Pointers in the ownership registry. The structural-instance
relation preserves the literal rule order in the structural-axis registry and,
within each rule, sorts its canonical source pointer or literal relation-row ID
by UTF-8 byte order.

For each rule, instance IDs are assigned from one using four decimal digits:

```text
<structuralRuleId>--0001
<structuralRuleId>--0002
...
```

No global renumbering, hash alias, truncation or normalization is allowed. The
validator recomputes the complete ordered relation and its digest rather than
trusting stored IDs or counts.

## Positive carrier closure

A positive carrier is eligible only when all of the following hold:

1. its complete raw request or response is canonical and validates against the
   exact root plus the selected operation arm, and that root lists the target
   in the ratified reachability relation;
2. the target JSON Pointer resolves exactly once;
3. the target validates against the exact object-schema subtree;
4. all applicable semantic preconditions pass;
5. request bytes originate in the closed blind-input case inventory;
6. response bytes originate in the independently generated withheld oracle and
   are unavailable to the independent reader until its output is frozen; and
7. its carrier, target and schema-subtree digests match recomputation.

For each object-schema pointer, choose the lexicographically first eligible
tuple:

```text
(direction-order, operation-order, carrierCaseId, targetJsonPointer,
 carrierSha256, targetCanonicalJsonSha256)
```

where request precedes response and operation order is exactly
`DESCRIBE_PROFILE`, `VALIDATE_TRANSCRIPT`, `EVALUATE_GENESIS`,
`REPLAY_CONTEXT`, `EVALUATE_CANDIDATE`, `EVALUATE_EVIDENCE_UPDATE`. If any
object schema has no eligible carrier, generation fails; structural similarity
to another schema is not a substitute.

The inventory validator also requires `caseCount == len(cases)`, unique case
IDs, all twelve direction-by-operation root cases, exact coverage of the 78
object-schema pointers and exact coverage of the 54 literal `oneOf` arms.
Every response case must name an existing request case of the same operation
and the exact reference-execution report that produced it. Twelve cases are the
minimum and 144 is the closed maximum obtained by assigning separate cases to
all twelve roots, 78 object schemas and 54 union arms; overlap may reduce the
actual ratified count but cannot reduce any coverage relation.

## Deterministic hostile synthesis

Each structural instance uses the perturbation kind and disposition fixed by
its structural-axis row. The generator enumerates a literal, versioned bounded
candidate palette for that perturbation kind and selects the first candidate
that satisfies the isolation proof below. The palette is part of the eventual
ratified executable Issue and its digest is provider-bound; an implementation
cannot reorder, extend or prune it.

The palette must include canonical representatives for JSON scalar/container
types, empty and one-item collections, shortest boundary strings, nearest
integer boundaries, an unknown member name outside every declared property,
and operation/profile literals outside every declared `const`/`enum`. Large
lengths are represented by bounded header/length witnesses and must never cause
proportional allocation.

Raw duplicate-member perturbations operate on canonical token spans before a
host-language object is constructed. Every other perturbation operates on a
deep copy of the canonical parsed carrier and is reserialized exactly once.
Mutation never changes the baseline carrier or a second target.

## Per-instance isolation proof

A negative instance is admitted to the registry only when:

1. the unmodified complete carrier passes;
2. the perturbed carrier reaches the owning validation phase without an earlier
   unrelated rejection;
3. the exact validator rejects with the structural-axis observation;
4. a test-only validator mutant that weakens only the targeted keyword,
   applicator, raw duplicate check or conditional branch admits that same
   perturbed carrier;
5. all other source mutants remain unmodified; and
6. reference and independent implementations agree after oracle release.

The one declared exception is the `DescribeProfileInputV0` occurrence of
`maxProperties: 0`, which is logically redundant with
`additionalProperties: false` and an empty property set. Removing that keyword
alone cannot change acceptance on the exact schema. Its live hostile carrier
must still be rejected, but mutant isolation is recorded as
`RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST`: a separately derived public schema
self-test demonstrates `maxProperties` support and cannot satisfy an adapter
behavior instance. No other occurrence may use this mode, and it is valid only
after the executable Issue names and human-ratifies this exact redundancy.

A positive union-arm instance is admitted only when the carrier passes, the
exact selected arm matches, the required exclusivity/membership relation holds,
and a mutant that disables only that selected arm changes the result required
by the rule. `STR-ANY-OF-ALL-ARMS` instead requires one carrier independently
validated by every literal arm. The 93-row `oneOf` registry remains a separate
complete pairwise proof and cannot be replaced by positive examples.

For conditional rows, the literal row suffix is the only disposition oracle:
`_ACCEPTS` means `ACCEPT`, `_REJECTS` means `REJECT`, and any other suffix fails
closed. For a row containing `_SKIPS_` and ending in `_ACCEPTS`, the assertion
records the inactive `if` predicate and the absence of a selected branch. Its
source mutant forces only the named target branch active against the otherwise
unchanged carrier and must invert `ACCEPT` to `REJECT`. Every other conditional
row records the active `if` predicate and selected `then`/`else` branch. An
inactive branch outside the exact `_SKIPS_..._ACCEPTS` relation cannot kill a
mutant.

Crash, timeout, silence, exception, wrong-phase rejection, two changed targets,
equivalent/unreachable mutant or an accepted malformed report fails the
instance. It is never counted as a killed mutant.

## Derived row fields

The generator does not freely author witness control fields. They are derived:

```text
structuralRuleId      := owning structural-axis row
perturbationKind      := structural-axis perturbationKind
isolationMode         := structural-axis isolationMode or the registry-wide
                        TARGET_ONLY_COUNTERFACTUAL default
expectedDisposition  := structural-axis disposition, resolving only a literal
                        conditional suffix when required
carrierDirection      := selected seed row
disclosureClass       := REQUEST -> BLIND_INPUT;
                         RESPONSE -> WITHHELD_ORACLE
executionPhase        := REQUEST -> BLIND_INPUT_EXECUTION;
                         RESPONSE -> POST_OUTPUT_MUTATION
expectedObservation   := direction × disposition through executionContract
assertionId           := AST-<rule-suffix>--<four-digit-index>
mutationId            := MUT-<rule-suffix>--<four-digit-index>
detectorId            := DET-<rule-suffix>--<four-digit-index>
```

The stable-ID suffix is the structural rule ID without its leading `STR-`.
Every derived ID is unique. A stored value that differs from recomputation
fails before any hostile case executes.

## Two-reader and report requirements

The reference generator and independent JavaScript reader run in distinct clean
exact-HEAD checkouts. They independently:

- recompute all 78 seed rows and 1,450 instance rows;
- execute every request instance before seeing expected response bytes;
- freeze response output before withheld-oracle release;
- execute post-output response mutations only after the freeze;
- kill the exact per-instance source mutant; and
- emit canonical reports with no path, host, user, PID, time, duration,
  environment, exception or repository identity.

The final gate requires byte-identical registries and reports, exact set
equality, all baseline positives passing, all negative observations matching,
all positive observations matching and all 1,450 mutants killed by their named
detectors. Aggregate counts or suite-level `PASS` are insufficient.

## Remaining closure

This contract fixes generation and isolation rules but does not fabricate the
exact-Base carrier inventories. Before ratification, the executable Issue must
bind the exact candidate palette and positive case inventories. Before APP-core
conformance can close, the implementation must populate the 78 seed rows and
1,450 witnesses, execute both readers and pass independent review plus the
human gate.
