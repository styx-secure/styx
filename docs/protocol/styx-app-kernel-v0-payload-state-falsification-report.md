# Styx application protocol v0: bounded payload-state falsification report

Status: C0.2f executable evidence; bounded, non-production, non-proof

Base: `e232c2c1c4687fa09ca12594c90e0aafc67b4ebb`

Model: `styx.causal-flow-simulator/v1`

Report schema: `styx.causal-flow-falsification-report/v1`

Machine report SHA-256: `e4fbd276cfedbc6f7d59b8fc83e6abbe43ab2e90b3d0ce65e4c6eb741a765367`

The exact final candidate HEAD is recorded in immutable PR evidence and in the
independent exact-HEAD review reports; a tracked file cannot self-identify the
SHA of the commit that contains that same text.

Issue: [#217](https://github.com/styx-secure/styx/issues/217)

## 1. Outcome and claim boundary

The dependency-free C0.2d/C0.2f reference model found no counterexample within
its declared small-state envelope. The required run performed 75 invariant
evaluations over 37 hostile scenario families, 78 causal/payload exploration
traces and 54 explicit payload-axis cases. All sixteen obligations in §9 of the
[O-04 analysis](styx-app-kernel-v0-payload-commitment-analysis.md) are present
as machine-readable passed records.

This result supports the selected O-04 payload-state semantics. It is not a
formal proof, cryptographic-suite selection, implementation-conformance result,
audit, deletion guarantee, anonymity claim or production-readiness verdict.
Any future counterexample reopens O-04.

## 2. Model boundary

The C0.2f extension consumes the already validated causal order produced by the
C0.2d model and adds:

- one authenticated symbolic content descriptor per admitted/fork event;
- closed `NONE`, `REQUIRED` and `DETACHABLE` content classes;
- explicit per-replica availability and binding observations;
- independent retention, replay-readiness and presentation classifications;
- append-only removal claims with explicit AP authorization input;
- checkpoint classification without consumer-side AP-state substitution,
  including fail-closed `STALE_EVIDENCE` for payload dependencies represented
  only by causal-compaction evidence;
- ideal symbolic commitment and chunk-leaf terms with injected randomizers;
  and
- scalar resource checks performed before symbolic expansion.

The simulator does not select O-06 algorithms, widths, domain tags, randomizer
sizes or transcript bytes. It does not implement O-07 checkpoint authority,
O-08 production limits, O-10 normative error codes, O-11 wire/storage formats
or O-13 irreversible-effect authorization.

## 3. Security-relevant semantics exercised

- Availability never changes event validity, references, graph edges, ready
  sets, fork classification or canonical causal order.
- Missing or unverified `REQUIRED` content stops the complete canonical AP
  replay suffix; no independent later event or checkpoint bypasses the halt.
- `DETACHABLE` availability changes presentation only, not authoritative AP
  replay order.
- Logical removal never mutates the target and applies only to an explicitly
  authorized directive against a causal-ancestor `DETACHABLE` target whose
  commitment matches.
- Removed-but-presented verified, unverifiable and substituted states remain
  distinct and never silently become active.
- Checkpoint contents derive only from retained descriptors and removal claims.
  Availability can make a producer ineligible, but checkpoint evidence never
  supplies missing application state to a consumer. A current event whose
  non-authority dependency exists only in causal-compaction evidence halts
  before every AP effect because v0 cannot recover the absent payload class or
  state.
- Supplying bytes for an event authenticated as `NONE` produces a typed rejected
  presentation; it cannot turn that event into a content-bearing transition.
- Incremental replay validates its old evaluation before reusing a prefix and
  equals a fresh full replay for the exercised state changes.
- Symbolic chunk leaves bind context, suite, content type, ordinal, exact part
  length, part symbol and injected event randomizer. This tests the required
  structure without pretending to instantiate the future O-06 suite.

## 4. Bounded search envelope

The causal bounds remain those recorded by the
[C0.2d report](styx-app-kernel-v0-causal-falsification-report.md). The C0.2f
payload profile additionally uses:

| Dimension | Bound |
| --- | ---: |
| Payload records | 9 |
| Removal directives | 4 |
| Declared content length | 1,024 bytes |
| Chunk size | 256 bytes |
| Chunks | 8 |
| Commitment/reference bytes | 64 |
| Injected randomizer bytes | 64 |
| Symbolic part bytes | 64 |
| UTF-8 bytes per payload text identifier | 64 |
| Payload-checkpoint references | 9 |
| Aggregate payload input | 8,192 bytes |
| Payload exploration budget | 512 |
| Explicitly explored payload-axis cases | 54 |

These are falsification bounds, not O-08 production limits.

## 5. Machine obligations and result

The report contains one record for every identifier `C0.2f-01` through
`C0.2f-16`. Obligations 2, 5, 10, 12 and 15 each have two independent checks,
obligation 16 has three, and every other obligation has at least one. All
records report `passed: true`.

The final machine verdict is:

```text
NO_COUNTEREXAMPLE_WITHIN_BOUNDS
```

The suite retains at most one deterministic globally smallest observed failing
trace; all failing invariant results remain listed separately. No failing trace
was produced in this run.

## 6. Reproduction

From repository root, with Python 3 and no third-party package installation:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools/causal-flow-simulator/tests -p 'test_*.py'

report_a="$(mktemp /tmp/styx-c02f-a.XXXXXX.json)"
report_b="$(mktemp /tmp/styx-c02f-b.XXXXXX.json)"
PYTHONDONTWRITEBYTECODE=1 python3 \
  tools/causal-flow-simulator/causal_flow_simulator.py \
  --suite required --output "$report_a"
PYTHONDONTWRITEBYTECODE=1 python3 \
  tools/causal-flow-simulator/causal_flow_simulator.py \
  --suite required --output "$report_b"
cmp "$report_a" "$report_b"
sha256sum "$report_a"
```

The two JSON files must be byte-identical and the digest must match the value
at the top of this report for the exact reviewed candidate.

## 7. Residual risks and next gate

Bounded exploration cannot establish correctness outside the declared profile.
The model assumes authenticated causal input and explicit AP authorization; it
does not prove those mechanisms. Symbolic commitment inequality is an ideal
model assumption until O-06 selects exact primitives and negative vectors.
Network omission, endpoint compromise, rollback beyond available evidence,
physical destruction, opening custody, traffic analysis and legal compliance
remain outside this result.

C0.2f removes only the executable payload-state blocker. C0.3 remains
`NO-GO` until O-06, O-07, O-08 and O-10 close, plus O-12 for any profile that
retains a physical-time claim. O-11 and O-13 remain later gates in the scopes
already recorded by the decision registry.
