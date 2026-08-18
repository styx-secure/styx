# Styx causal-flow simulator

Status: bounded C0.2d falsification model; not production code or conformance

Issue: [#213](https://github.com/styx-secure/styx/issues/213)

## Purpose

This dependency-free Python tool attempts to falsify the causal-topology
hypothesis selected in C0.2c before Styx freezes transcript bytes or implements
the application kernel. It is written from the English protocol documents and
does not import the Dart ledger, JavaScript ledger, MLS graph, product code or
network/storage adapters.

The model accepts closed synthetic contexts, credential authority, checkpoint
evidence and events with caller-supplied byte references. It classifies input,
constructs the admitted causal graph, records ready sets, derives the
deterministic topological order, emits fact-only AP handoffs, and calculates the
earliest affected replay boundary for late events.

Graph decisions are set-relative, while each replay handoff is deliberately
prefix-scoped: it contains relations and fork evidence available at that point
in the canonical replay. A later event supplies any newly actionable relation;
it does not retroactively add future facts to an unchanged earlier handoff. If
the late event sorts earlier, the affected suffix is replayed and those facts
are recomputed. This distinction is required for incremental replay to remain
equivalent to a fresh full replay.

## Run

From the repository root:

```bash
python3 -m unittest discover -s tools/causal-flow-simulator/tests -p 'test_*.py'
python3 tools/causal-flow-simulator/causal_flow_simulator.py \
  --suite required --output /tmp/styx-causal-flow-report.json
```

The CLI uses exit `0` only when every bounded invariant passes, `1` when it
finds a counterexample, and `2` for invalid invocation or output failure. JSON
is canonicalized with sorted keys, compact separators and one terminal newline;
identical runs are byte-identical.

## Output

The report contains:

- a model and report schema version;
- the explicit exploration/profile bounds;
- scenario-family and delivery-trace counts;
- a machine-readable result for every invariant;
- retained counterexamples with the smallest observed failing prefix/trace; and
- explicit non-claims and a bounded verdict.

The default profile also fails closed above 9 event observations, 8 credential
authorities, 4 causal parents per event, 32 checkpoint/evidence references,
8 bytes per synthetic reference, 64 UTF-8 bytes per text field, 255 as the
largest sequence value, 4,096 aggregate input bytes, or 720 explored delivery
traces. Aggregate bytes include repeated observations and all supplied context,
authority, checkpoint and event fields; integer sequences are charged as eight
bytes. These are exploration limits, not proposed production limits.

`NO_COUNTEREXAMPLE_WITHIN_BOUNDS` is not a proof. Any `FAIL` result is blocking:
the affected C0.2c decision must return to `OPEN`; a caller must not suppress the
trace or weaken the model merely to obtain green output.

## Semantic boundary

Synthetic event-reference bytes let the model exercise ordering and graph
semantics without choosing a hash, signature, canonical transcript, wire
encoding or storage format. Checkpoint evidence distinguishes proven boundary
references, known-pruned references and unknown references, but cannot prove
that a remote branch was never hidden.

`K` output is limited to validated facts: prefix-visible classification,
context/credential identity, authenticated grant reference, causal relations,
fork evidence and live revocation relations. It intentionally contains no
business accept/reject decision, delivery assertion, finality claim or
authorization for an external effect; those remain application-policy (`AP`)
responsibilities. Checkpoint authority outside the live replay prefix remains
explicit checkpoint/AP input instead of being emitted as a new live relation.

## Limitations

- Exploration is exhaustive only inside the declared small profile.
- Signatures and reference derivation are assumed, not implemented.
- Application authorization and business conflict policy are not modeled.
- Network omission, endpoint compromise, traffic analysis and global rollback
  detection remain outside this tool.
- Future O-04/O-07/O-08/O-10/O-11 decisions may require the model to be
  extended and the affected invariants to be run again.
