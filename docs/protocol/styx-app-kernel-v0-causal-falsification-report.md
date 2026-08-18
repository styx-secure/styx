# Styx application protocol v0: bounded causal falsification report

Status: C0.2d executable evidence; bounded, non-production, non-proof

Base: `7de409fae2b88edb9d95bec7022764319e9d3236`

Machine report SHA-256: `0d336a897459cd0259a2fbb611ea04690290d21108a29a8c4053f5a818e11255`

The exact final candidate HEAD is recorded in immutable PR evidence and in the
independent exact-HEAD review report; a tracked file cannot self-identify the
SHA of the commit that contains that same text.

Issue: [#213](https://github.com/styx-secure/styx/issues/213)

## 1. Outcome and claim boundary

The dependency-free C0.2d reference model found no counterexample within its
declared small-state envelope after 52 invariant evaluations over 22 hostile
scenario families and 24 explicitly enumerated delivery/prefix traces. This is
evidence supporting the C0.2c causal-topology hypothesis; it is not a formal
proof, implementation conformance result, cryptographic test, audit, anonymity
claim or production-readiness verdict.

The model uses synthetic caller-supplied bytes as event references. It does not
select canonical transcript bytes, a hash or signature algorithm, wire/storage
encoding, numeric production profile, persistence, transport, or application
policy. Existing Dart, JavaScript and Phase B implementations were not imported
and were not used as semantic oracles.

## 2. Important falsification result during construction

The first implementation run failed incremental/full handoff equivalence. The initial model
incorrectly made every per-event `K → AP` handoff describe relationships to the
entire final event set. A late concurrent event therefore retroactively changed
an unchanged earlier handoff even when canonical order retained that event in
an exact prefix.

That failure was a simulator defect, not a surviving counterexample to the
selected chain/frontier topology. It nevertheless exposed a necessary
normative clarification:

- graph validation and diagnostic classification are set-relative; but
- a replay handoff is prefix-scoped and contains only facts actionable at that
  position in the canonical replay.

The late event supplies the new concurrency, fork or revocation fact when it is
replayed. If it sorts before an old event, replay begins at the changed order
position and recomputes the suffix. If it sorts after the exact old prefix, the
new event is the first new transition and can cause `AP` to revise or quarantine
earlier reversible state. A full replay uses the same prefix-scoped handoff
semantics, so it is byte-for-byte equivalent to incremental replay.

This does not permit an irreversible external effect based on a current replay
position. C0.2c already forbids that inference without separately approved
finality/effect evidence. A late fork or revocation can require application
state to be revised even when the old order remains an exact prefix.

The failing prototype trace was retained outside the repository during
development. The committed suite adds explicit higher/lower late-fork and late-
revocation cases so a future change cannot silently restore the global-handoff
mistake.

## 3. Model boundary

The model represents one closed application context with:

- context-local credential authority and grant references;
- non-wrapping per-credential sequence and direct author predecessor;
- sorted, unique, bounded causal-parent frontier;
- available events, checkpoint-proven references and known-pruned/stale
  references;
- authority revocation references;
- synthetic deterministic event-reference bytes; and
- explicit event, parent, reference, sequence and exploration limits.

Validation distinguishes admitted, fork, gap, deferred, stale and invalid
events. Duplicate observations are retained separately without creating a
second graph node or AP handoff. Same-sequence and same-predecessor siblings are
both retained as attributable fork evidence; byte order never resolves the
fork.

The graph includes only admitted/fork events. Ready sets and topological replay
are derived without arrival, relay, storage or wall-clock inputs. Among ready
events the lowest unsigned byte reference is selected. Each AP handoff contains
the prefix-visible classification, validated event/context facts,
authenticated credential/grant authority, prior replay references, causal
relations to that prefix, visible fork peers and relevant live revocation
relations. It does not contain an application accept/reject result,
delivery/finality assertion or external-effect authorization.

## 4. Bounded search envelope

The required suite uses:

| Dimension | Bound |
| --- | ---: |
| Observations per evaluation | 9 |
| Credential authorities | 8 |
| Causal parents per event | 4 |
| Checkpoint/evidence references | 32 |
| Synthetic reference length | 8 bytes |
| UTF-8 bytes per text field | 64 |
| Aggregate supplied input | 4,096 bytes |
| Author sequence | 0–255 |
| Delivery/prefix trace budget | 720 |
| Explicitly explored traces | 24 |
| Invariant evaluations | 52 |

These are simulator search bounds, not selected O-08 production values.
Increasing them may expose a counterexample and must not be described as a
backwards-compatible production-profile change.

## 5. Hostile coverage and results

| Family | Evidence/result |
| --- | --- |
| Three-author mixed causal/concurrent graph | Same graph, ready sets, order and handoffs across all six deliveries |
| Lower-reference late concurrency | Boundary is first changed order position; suffix equals full replay |
| Higher-reference exact-prefix insertion | Boundary is old length; new transition extends the prefix |
| All prefixes of all three-event deliveries | Incremental projection equals fresh full replay |
| Child before parent | Deferred with no handoff; admitted after evidence arrives |
| Duplicate/replay | One graph node and one handoff; duplicate observation recorded |
| Reference collision | Invalid, never treated as duplication |
| Same-author fork/equivocation | Both siblings retained and flagged; higher/lower late cases covered |
| Author gap | Distinct `gap` result |
| Missing parent | Distinct recoverable `deferred` result, no handoff |
| Known-pruned parent without proof | Distinct `stale` result, no handoff |
| Checkpoint-proven author head | Bounded continuation admitted only on exact head/sequence match |
| Cross-context parent | Invalid before AP handoff |
| Duplicate/redundant/excess parents | Canonicality or resource failure before AP handoff |
| Synthetic cycle | Defensive rejection, no graph order |
| Revocation race | Concurrent relation handed to AP; causal post-revocation action rejected |
| Malicious causal omission | No causal edge is invented; omission remains indistinguishable from concurrency |
| Rollback/checkpoint limit | Proven, stale and unknown states remain distinct; no global detection claim |
| AP/K ownership | Handoff is fact-only and contains no business or external-effect verdict |

## 6. Checkpoint and rollback interpretation

Checkpoint evidence in this model is deliberately minimal. It can prove a
retained boundary reference and an exact per-credential author head, or record
that a required reference is known to be pruned without sufficient proof. This
allows bounded continuation, gap detection and explicit stale/deferred states.

It cannot prove that a relay or peer never concealed a branch, detect restoration
of both local state and its local head, or select production checkpoint bytes,
retention, authentication or persistence. Those remain O-04/O-07/O-08/O-11 and
runtime/storage work.

## 7. Reproduction

Run from the exact candidate worktree:

```bash
python3 -m unittest discover -s tools/causal-flow-simulator/tests -p 'test_*.py'
python3 tools/causal-flow-simulator/causal_flow_simulator.py \
  --suite required --output /tmp/styx-causal-flow-report-1.json
python3 tools/causal-flow-simulator/causal_flow_simulator.py \
  --suite required --output /tmp/styx-causal-flow-report-2.json
cmp /tmp/styx-causal-flow-report-1.json /tmp/styx-causal-flow-report-2.json
sha256sum /tmp/styx-causal-flow-report-1.json
```

Expected bounded verdict:

```text
NO_COUNTEREXAMPLE_WITHIN_BOUNDS
```

The unit/adversarial suite contains 30 tests. The canonical machine report
digest must equal the SHA-256 recorded at the top of this document.

The two JSON outputs must be byte-identical. A future `FAIL` is blocking and
must retain the smallest observed trace and reopen the affected decision rather
than weaken the invariant.

## 8. Decision effect

Subject to exact-final-HEAD independent review, C0.2d supplies the executable
falsification evidence required by the O-01 residual/reopen condition. O-01 can
remain `DECIDED` only with the explicit graph-set/replay-prefix distinction in
§2. The initial simulator defect did not falsify the topology, while Amendment
1 makes its previously implicit handoff-scope condition normative. O-05 remains
unaffected. O-06 remains `OPEN` for exact transcript bytes, digest registry,
width and O-04 interaction; synthetic model references do not close it.

## 9. Residual risks and reopen conditions

- Bounded exploration may miss failures requiring larger graphs, deeper
  histories, wider frontiers or different checkpoint horizons.
- Prefix-scoped replay requires AP transitions to handle a newly disclosed fork
  or revocation by revising reversible state. It does not authorize an
  irreversible effect before stronger evidence.
- The model assumes authenticated fields and reference collision resistance;
  C0.3 must test the selected transcript and cryptographic registry.
- Malicious omission can look like concurrency; signatures attribute claims but
  do not make an endpoint truthful.
- Checkpoint substitution, storage rollback and split views still require
  independently authenticated evidence and remain bounded non-claims.
- Any future encoding, checkpoint, authorization or application-policy choice
  that changes model inputs requires targeted re-falsification.
