# O-08 resource-envelope falsification report

Status: replacement final-gate evidence in progress for Issue #250. The prior
selection is superseded because its selection HEAD contained a cross-runtime
response-shape mismatch exposed by the final gate. A positive result remains
falsification evidence, not proof or product conformance.

## Evidence identity

- Base: `ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3`.
- Superseded selection HEAD: `16c379fba756516edb173ab3ba722bbf97bfacab`.
- Replacement selection HEAD: pending the clean gate-fix commit.
- Candidate-set digest:
  `12f9e068ca02b965062859fc98d922722e44909efbe819771ab7e3d5aaba040f`.
- Superseded selected envelope: `balanced`, digest
  `317206449117fcad351f0338c719085a8eb623605d7768327e27d26fd48256fd`.
- Superseded provider object: GitHub Issue-comment `5431295833`, created through the
  `maverde73` ForgeRelay selection request.
- Python: `3.14.4`; Node: `v24.18.0`.

## Results

| Evidence family | Result |
| --- | --- |
| Source inventory | PASS: 69 unique dimensions, 12 groups and 28 exact pre-existing anchors |
| Scope partition | LOCAL PASS: 46 semantic maxima, four capability minima, one structural exact capability-key declaration, two exact-zero entries, eleven post-C0.3 and five evidence-only dimensions |
| Integer-field coverage | LOCAL PASS: closed field-specific relation; no generic representability fallback |
| O-08→O-10 handoff | LOCAL PASS: 66 unique rows (`S0=9`, `S3=22`, `S4=10`, `S5=15`, `S6=10`) and no stable code |
| Boundary probes | IMPLEMENTED: closed-set and scalar adjacent cases with observable pre/post state; replacement selected run pending |
| Combined matrix | LOCAL PASS: 16 rows with checked arithmetic; 13 execute and three remain explicitly post-C0.3 |
| Independent runtimes | LOCAL PASS after response-shape correction: Python/Node state, disposition, coupling and exact maximum-antichain agreement; replacement selected run pending |
| Structural authority family | LOCAL PASS: exact `B4(P)` dominates the actual C0.2j fold; Python and independent Node cover all six control kinds, non-genesis depth, two/three-sibling and repeated joins, cross-owner substitution, causal cross-edges, W301, W1211 and retained width boundaries |
| Mutations | IMPLEMENTED: 53 gate-skip mutants, twelve exact-B4 mutations and one weakened replay-coupling mutation are independently killed; replacement selected run pending |
| Unit/negative controls | LOCAL PASS: all nine required test modules remain non-empty; replacement suite currently passes |
| Selection measurements | PENDING replacement six-report cycle, comparison and immutable ForgeRelay decision |

The cross-runtime suite carries values outside JavaScript's exact integer range
as decimal strings and compares through `BigInt`; selected runtime-oracle values
themselves remain below `2^53-1`.

## Hostile coverage

The model exercises scalar underflow/overflow, signed conversion, nested and
cumulative geometry, many-small-object floods, valid credential and signature
work floods, fork/alias/lineage steering, exact authority-poset antichain width
and `B4(P)`, descendant/fork-join killer closure, authority state/transition exhaustion,
pending-root amplification, missing-opening replay spans, abstract
storage/custody insufficiency, profile skew, capability downgrade and jointly
maximal traces. Failure precedes protected work and never leaves partial
authoritative mutation.

Negative controls reject missing/duplicate/unknown dimensions, stale Base,
unknown roles, duplicate stages, removed enforcement gates, role promotion,
post-C0.3/evidence promotion, non-canonical selected JSON, profile downgrade,
ambient fields and runtime provenance in canonical reports.

## Residual limits

Host timing and RSS are machine-specific selection observations and are excluded
from canonical two-checkout equality. The package models deterministic S6
capacity accounting, not persistence I/O. It does not exercise product/runtime
adapters and does not close O-10, the corpus-path gate or the retained combined
O-14→O-06c rerun. C0.3 therefore remains `NO-GO`.
