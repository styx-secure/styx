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

## O-07 canonical evidence hygiene

The final Git bundle is created once before any O-07 report. Its SHA-256 is
locked as an external execution input, and every canonical-report producer
requires both the bundle path and that locked digest. Before serialization each
producer verifies the exact Base and candidate, both Git trees, the
binary/full-index diff, the complete bundle and its digest, then validates its
closed v3 report schema. Full repository identities and every prefix of seven
or more characters are forbidden in report keys and values, as are absolute
paths, provenance-labelled runtime identities, timestamps, process identifiers
and elapsed-time values. Bundle and runtime identities remain in raw external
logs only.

`o07/verify_final_evidence_hygiene.py` accepts two named, distinct, clean
checkout roots and two distinct external evidence roots. It validates the exact
inventory, observations, dispositions and mutant outcomes for all four report
families, requires byte-identical results between runs, and independently
regenerates every report in a gate-owned temporary directory before accepting
the submitted bytes. Anonymous reports, synthetic counts, reused paths,
same-root runs, dirty checkouts, symlinks and changed bundle bytes fail closed.

The flat final package is checked by `o07/verify_flat_package.py`. Its manifest
must name exactly every regular artifact and no directory, symlink, special,
duplicate, missing or extra entry; only after that exact-set check does the tool
run plain `sha256sum -c`. These gates complement, rather than replace, the raw
Issue/PR evidence and the complete two-run historical regression artifacts.

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

## O-14/O-06c integrated rerun

`o06c/integrated_*.py` is the Issue #260 evidence layer that replaces the
historical signature placeholder with the frozen O-14 suite and preserves the
frozen O-07 provenance, O-08 envelope and O-10 outcome boundaries. Its
observable order is fixed: O-08 preflight; canonical O-06b transcript;
authenticated O-07 genesis or C0.2j grant binding; one O-14 verifier; AP use;
O-06c projection; then O-10 local/remote classification.

The candidate evidence contains 115 fixed/transcript/candidate-envelope witnesses, consumes all
69 O-08 dispositions and 66 O-08-to-O-10 handoffs, emits 154 boundary
observations and kills seven integration-order mutants. The frozen O-07, O-08,
O-10 and O-14 suites remain authoritative and are rerun separately by the final
gate; the integration harness does not copy or replace their oracles. Its
JavaScript interchange is `TEST_ONLY_NOT_O11` and selects no wire, storage,
product or Dart/browser-conformance claim. The exact-final two-clean-checkout
technical evidence passes; independent review and human gates are still
required before C0.3 can move from `NO_GO`.

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

## O-08 bounded resource envelope

`o08/` contains the isolated transcript-only resource-envelope evidence for
Issue #250. It preserves all 68 discovered dimensions and compares 53 C0.3
entry values across three candidates, keeps eleven post-C0.3 and four
evidence-only dimensions non-authoritative, and hands 66 safe-recovery rows to
O-10 without assigning stable codes. Python and dependency-independent Node
exercise every boundary; the combined matrix and per-dimension mutants detect
cross-dimensional amplification and skipped gates. The exact width of the
authority-control poset is independently recomputed in Python and Node before
the actual C0.2j DP fold. No candidate is selected
until the replacement measurement and ForgeRelay gate completes. The package is conformance
evidence only and makes no product/runtime, persistence, transport, session,
recovery or availability claim.

## O-10 bounded outcome taxonomy

`o10/` owns the closed trusted-local taxonomy selected by Issue #252. Its
literal 102-row inventory joins all 36 Base review-model citations to the 66
frozen O-08 handoff rows. A Python reference and dependency-independent Node
adapter exercise every primary, precedence edge, overlap, recovery class and
privacy collapse; mutation evidence must kill every registered mutant. The
scope guard permits exactly the ratified model anchors, O-10 blocker status,
validator function and inside-`try` registration. The final gate regenerates
all reports in two clean `git clone --no-local` checkouts.

This package names local evidence for safe caller behavior. It does not define
wire values, remote acknowledgements, persistence, recovery success, delivery,
freshness, rollback protection or product behavior, and does not authorize
C0.3 by itself.

## SS-0 bounded secure-session profile

`ss0/` is the evidence-only secure-session model authorized by Issue #285. It
binds the exact OpenMLS, Marmot and MDK proof pins, MLS ciphersuite `0x0001`,
the two recorded member profiles and the five-past-epoch observation boundary.
It models only the selected two-member direct-session behavior: opaque bounded
application bytes, staged session mutation behind an abstract RS tri-state,
independent retention and replay handling, the bounded two-candidate
same-parent convergence rule, framed non-last-resort onboarding and explicit
restore/non-claim boundaries.

The Python reference and independently authored JavaScript projection execute
one closed hostile-scenario inventory. Their inputs carry no oracle or expected
disposition. A separate source-mutant registry challenges every `SSD-01`–
`SSD-11` decision and the required cross-rule substitutions. Canonical reports
exclude repository identity, paths, runtime provenance, timing and sensitive
values. The scope guard preserves every Gate-A-frozen byte, the historical
O-10/C0.3 validator relation and C0.3 `NO_GO` while enforcing the ratified
review-model projection.

`ss0/final_gate.py` requires two distinct clean clones at the exact final HEAD.
It invokes the byte-frozen Gate-A verifier inside each clone before reading or
regenerating Phase-B evidence, regenerates all six canonical report families
outside both repositories and requires submitted and regenerated bytes to be
identical across both runs.

A positive SS-0 result is bounded negative evidence, not a proof of MLS or the
upstream implementations. It selects no adapter or SDK API, wire or persisted
format, production storage, recovery, rollback detection, physical erasure,
general convergence, multi-device behavior, delivery, metadata privacy or
product support. Issue #293 adds a six-file, fully synthetic conformance corpus
with 20 owners, 60 atoms, 56 witnesses, 104 relations, 14 valid vectors, 18
invalid vectors, 24 state-machine scenarios, 44 source-mutation records split
41/3, 28 corpus-data mutants and 56 expected traces. Generate, validate and
blindly replay it with:

```bash
python3 tools/causal-flow-simulator/ss0/corpus/generate_corpus.py \
  --repo-root . --output-dir conformance/secure-session/ss0 --check
python3 tools/causal-flow-simulator/ss0/corpus/validate_corpus.py \
  --repo-root . --corpus-dir conformance/secure-session/ss0
python3 tools/causal-flow-simulator/ss0/corpus/replay_corpus.py \
  --repo-root . --node "$(command -v node)" \
  --corpus-dir conformance/secure-session/ss0 --output /tmp/ss0-replay.json
python3 tools/causal-flow-simulator/ss0/corpus/run_mutations.py \
  --repo-root . --node "$(command -v node)" \
  --corpus-dir conformance/secure-session/ss0 --output /tmp/ss0-mutations.json
```

The generator never executes either reader. Python and JavaScript receive only
the bare candidate input; their raw observations are frozen before expected
traces are opened. Agreement therefore demonstrates corpus transport fidelity
and non-regression from the already-frozen Base agreement, not a second
independent semantic corroboration. The 44 source mutants exercise only the
Python reference reader; no JavaScript mutation-sensitivity claim is made. The
final evidence roots include replay, mutation, scope and review-model reports
from both clean checkouts. Reproduction also requires fetching
`refs/pull/286/head`, which supplies the two historical PR commits frozen by the
scope guard but absent from default `main` history. SS-CORPUS-0 does not
authorize SS-1, SS-2, an adapter, SDK, application demo, product work or C0.3
activation.
