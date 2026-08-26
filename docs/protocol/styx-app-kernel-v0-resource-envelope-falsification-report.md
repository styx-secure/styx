# O-08 resource-envelope falsification report

Status: bounded evidence for Issue #250. A positive result is falsification
evidence, not proof or product conformance.

## Evidence identity

- Base: `ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3`.
- Selection HEAD: `aed184aa3424225c343fbadfd1a7031a1c7e925a`.
- Selected envelope digest:
  `de5032e66efdad9eefb0af4b7a113510368c9f02b8790361a053a509b4898daa`.
- Provider object: `https://api.github.com/repos/styx-secure/styx/issues/comments/5425570807`.
- Python: `3.14.4`; Node: `v24.18.0`.

## Results

| Evidence family | Result |
| --- | --- |
| Source inventory | PASS: 67 unique dimensions, 12 groups and 28 exact pre-existing anchors |
| Scope partition | PASS: 46 semantic maxima, five activation inputs, two exact-zero entries, eleven post-C0.3 and three evidence-only dimensions |
| O-08→O-10 handoff | PASS: 66 unique rows (`S0=9`, `S3=22`, `S4=10`, `S5=15`, `S6=10`) and no stable code |
| Boundary probes | PASS: minus one, exact and plus one for every entry/stage; negative/signed and JavaScript precision boundaries included |
| Combined matrix | PASS: exactly 16 rows; 13 C0.3 rows execute and three post-C0.3 rows remain explicitly unexecuted |
| Independent runtimes | PASS: Python and dependency-independent Node agree on every C0.3 boundary case and safe disposition |
| Mutations | PASS: 53 independently reachable gate-skip mutants killed, zero survivors, one passing control per mutant |
| Unit/negative controls | PASS: all nine required test modules are non-empty; 20 tests pass |
| Selection measurements | PASS: three candidates × two capability profiles × five cold/five warm repetitions; report-set validator passes |

The cross-runtime suite specifically carries `SEQUENCE_VALUE + 1` as a decimal
string and compares it with JavaScript `BigInt`, preventing IEEE-754 rounding
from converting an out-of-profile value into an accepted boundary value.

## Hostile coverage

The model exercises scalar underflow/overflow, signed conversion, nested and
cumulative geometry, many-small-object floods, valid credential and signature
work floods, fork/alias/lineage steering, authority state/transition exhaustion,
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
