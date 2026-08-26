# O-08 resource-envelope falsification report

Status: remediation evidence in progress for Issue #250. The previous selected
candidate and its reports are superseded. A positive result remains
falsification evidence, not proof or product conformance.

## Evidence identity

- Base: `ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3`.
- Selection HEAD: pending the clean replacement implementation commit.
- Selected envelope digest and provider object: none; a new six-report
  measurement cycle and immutable ForgeRelay decision are required.
- Python: `3.14.4`; Node: `v24.18.0`.

## Results

| Evidence family | Result |
| --- | --- |
| Source inventory | PASS: 68 unique dimensions, 12 groups and 28 exact pre-existing anchors |
| Scope partition | LOCAL PASS: 46 semantic maxima, four capability minima, one structural exact capability-key declaration, two exact-zero entries, eleven post-C0.3 and four evidence-only dimensions |
| Integer-field coverage | LOCAL PASS: closed field-specific relation; no generic representability fallback |
| O-08→O-10 handoff | LOCAL PASS: 66 unique rows (`S0=9`, `S3=21`, `S4=10`, `S5=16`, `S6=10`) and no stable code |
| Boundary probes | IMPLEMENTED: closed-set and scalar adjacent cases with observable pre/post state; final selected run pending |
| Combined matrix | LOCAL PASS: 16 rows with checked arithmetic; 13 execute and three remain explicitly post-C0.3 |
| Independent runtimes | IMPLEMENTED: Python/Node state, disposition, coupling and exact maximum-antichain agreement; final selected run pending |
| Structural authority family | LOCAL PASS: actual C0.2j fold covers GRANT grids, chained controls, cyclic revoke, mixed controls, fork/join concentration and width boundaries; the retained witness remains 4,033 states/14,556 transitions and is rejected pre-DP by all candidates |
| Mutations | IMPLEMENTED: 53 executed gate-skip mutants with intended-failure and passing controls; final selected run pending |
| Unit/negative controls | LOCAL PASS: all nine required test modules remain non-empty; replacement suite currently passes |
| Selection measurements | PENDING: new selection HEAD, six reports, comparison and ForgeRelay decision |

The cross-runtime suite carries values outside JavaScript's exact integer range
as decimal strings and compares through `BigInt`; selected runtime-oracle values
themselves remain below `2^53-1`.

## Hostile coverage

The model exercises scalar underflow/overflow, signed conversion, nested and
cumulative geometry, many-small-object floods, valid credential and signature
work floods, fork/alias/lineage steering, exact authority-poset antichain width,
authority state/transition exhaustion,
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
