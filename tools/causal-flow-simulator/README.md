# Styx causal-flow simulator

Status: bounded C0.2d/C0.2f falsification model; not production code or conformance

Issues: [#213](https://github.com/styx-secure/styx/issues/213),
[#217](https://github.com/styx-secure/styx/issues/217)

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
earliest affected replay boundary for late events. The C0.2f extension then
folds authenticated content descriptors, per-replica availability/binding
observations, AP authorization of logical removal, and checkpoint evidence over
that validated causal order.

Graph decisions are set-relative, while each replay handoff is deliberately
prefix-scoped: it contains relations and fork evidence available at that point
in the canonical replay. A later event supplies any newly actionable relation;
it does not retroactively add future facts to an unchanged earlier handoff. If
the late event sorts earlier, the affected suffix is replayed and those facts
are recomputed. This distinction is required for incremental replay to remain
equivalent to a fresh full replay.

The payload model keeps content class, availability, binding, retention, replay
readiness and presentation as separate closed axes. A missing `REQUIRED`
opening halts the entire canonical suffix. `DETACHABLE` availability changes
presentation only. Logical removal is an append-only, explicitly authorized
directive and never mutates the target event. Checkpoints derive descriptors
and removal claims from retained records and can make a producer ineligible,
but never substitute for application state at a consumer. If a current event
depends on causal history represented only by checkpoint evidence, the v0
payload projection reports `STALE_EVIDENCE` and applies no AP effect: the model
cannot infer the absent dependency's content class or reconstruct its payload
state. Bytes unexpectedly presented for a `NONE` event are likewise rejected
as an explicit typed presentation rather than silently ignored.

Commitments are ideal symbolic terms. Injected randomizers, context, content
type, exact length, shape, chunk geometry, part ordinal and part length are
modeled; no digest, signature, transcript byte encoding or O-06 cryptographic
suite is selected here.

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
- scenario-family, causal-delivery and payload-axis exploration counts;
- a machine-readable result for each of the sixteen C0.2f obligations;
- a fail-closed invariant over the exact, non-empty sixteen-obligation registry;
- a machine-readable result for every invariant;
- the single deterministic smallest observed failing prefix/trace; and
- explicit non-claims and a bounded verdict.

The causal profile fails closed above 9 event observations, 8 credential
authorities, 4 causal parents per event, 32 checkpoint/evidence references,
8 bytes per synthetic reference, 64 UTF-8 bytes per text field, 255 as the
largest sequence value, 4,096 aggregate input bytes, or 720 explored delivery
traces. Aggregate bytes include repeated observations and all supplied context,
authority, checkpoint and event fields; integer sequences are charged as eight
bytes. These are exploration limits, not proposed production limits.

The payload profile independently fails closed above 9 records, 4 removal
directives, 1,024 bytes declared content length, 256-byte chunk size, 8 chunks,
64-byte commitment/reference values, 64-byte injected randomizers or part
symbols, 64 UTF-8 bytes per payload text identifier, 9 checkpoint references,
8 KiB aggregate input, or 512 payload exploration cases. Scalar bounds are
checked before symbolic part expansion, and each published payload-profile
scalar bound has an independently asserted adversarial check.
These too are model bounds, not production defaults; O-08 remains responsible
for supported runtime limits.

`NO_COUNTEREXAMPLE_WITHIN_BOUNDS` is not a proof. Any `FAIL` result is blocking:
the affected decision must return to `OPEN` (O-04 for a payload-state
counterexample); a caller must not suppress the trace or weaken the model merely
to obtain green output.

## Semantic boundary

Synthetic event-reference and commitment bytes let the model exercise ordering
and graph semantics without choosing a hash, signature, canonical transcript,
wire encoding or storage format. Checkpoint evidence distinguishes proven
boundary references, known-pruned references and unknown references, but cannot
prove that a remote branch was never hidden.

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
- Removal authorization is supplied as explicit AP input; the authorization
  policy and all other business conflict rules are not modeled.
- Network omission, endpoint compromise, traffic analysis and global rollback
  detection remain outside this tool.
- Checkpoint authentication is classified but not provided by this model, and
  accepted checkpoints never replace consumer-side payload verification. A
  checkpoint's canonical horizon references are expanded to their retained
  causal-ancestor closure for contents and producer-eligibility assessment.
- O-06/O-07/O-08/O-10/O-11 decisions may require this model and its affected
  invariants to be extended and rerun.

## O-06c exact combined-construction package

`o06c/` is a separate standard-library-only evidence package added by Issue
#243. It does not import this historical model, `v2/`, `v3/`, `c02k/` or product
code. It independently models the frozen O-06b-1/O-06b-2/C0.2j/C0.2k byte
construction, encodes it in Python and dependency-free JavaScript, exercises
written inverses, runs directed witnesses, challenges complete objects and
scalars, kills a closed source-mutant registry, verifies the six frozen sections
and reruns the exact seven-entry historical evidence registry from fresh staged
copies.

Its six canonical JSON reports are caller-selected external outputs and are
never tracked as vectors or corpus files. Candidate commit/tree/final-diff
identity belongs in immutable PR evidence rather than a generated report whose
digest is recorded in normative text. The package's positive verdict is
`NO_COUNTEREXAMPLE_WITHIN_BOUNDS`; it is not a proof, conformance suite,
production implementation, resource bound or readiness authorization. Use the
exact environment and command block recorded by Issue #243 and the human report
at `docs/protocol/styx-app-kernel-v0-identifier-commitment-falsification-report.md`.

## O-14 signature-suite evidence package

`o14/` is an isolated, standard-library-controlled evidence package for Issue
#246. It defines the closed semantic registry for suite `0x0001`, implements a
verification-only standard-derived Ed25519 oracle, generates hostile canonical,
small-order and mixed-order witnesses, records raw Dart/JavaScript/WebCrypto
behavior, evaluates explicitly enumerated guarded adapters and kills a closed
source-mutant registry. `scope_guard_o14.py` enforces the exact Issue #246 path
and named-region contract against its ratified base.

Run the exact commands and temporary-runtime provisioning block in Issue #246.
Every JSON report is written only to a caller-selected temporary directory and
must reproduce byte-identically in two fresh worktrees. The positive verdict is
bounded negative evidence, not a proof, production verifier, conformance suite,
runtime support claim, interoperability claim or authority to create C0.3.
Dart/browser adapter evidence and the separately ratified O-06c
placeholder-substitution rerun remain explicit downstream gates.

## O-07 genesis and checkpoint-boundary evidence package

`o07/` is the isolated, standard-library-only evidence package for Issue #248.
It instantiates the frozen O-06b-1 genesis domains and the O-14 `0x0001`
signature suite with one exact seven-field genesis transcript. It models the
abstract local ceremony Boundary, its opaque domain/Boundary-bound capability
and mechanically separate creator-local state. It validates each candidate
only after local capability validation, fixes one context root atomically,
treats an exact duplicate as idempotent, rejects copied, reconstructed or
foreign capabilities and every distinct same-context root and descendant, and
keeps grant references distinct from the genesis credential identifier. The
deterministic Boundary is test-only; no production ceremony transport,
credential, witness, trusted path or persistence mechanism is selected.

The closed inventory contains 287 exact atom/scenario relations: 229 semantic
instances executed independently in Python and JavaScript plus 58 separate
repository, reproducibility, external-review and human gates. The package also exercises the v0 checkpoint boundary: ordinary replay retains
its live authority transcripts and `REQUIRED` openings, while any attempt to
populate checkpoint evidence is rejected before projection. The Python model
and dependency-free Node adapter must agree on all 229 relations, and every
registered source mutant must be killed. `scope_guard_o07.py` enforces the
exact Issue #248 paths, validator-literal deltas, copy/rename prohibition,
predecessor-test integrity, test-authenticator isolation, closed report schemas
and approved normative artifacts against the ratified base.

Run the exact deterministic command block in Issue #248. Generated JSON belongs
only in a caller-selected temporary directory and must reproduce byte-for-byte
in two fresh worktrees. A positive result is bounded falsification evidence,
not a proof, product implementation, durable ceremony, recovery mechanism,
checkpoint capability, availability guarantee, conformance claim or authority
to begin C0.3.
