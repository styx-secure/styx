# C0.3 transcript-only conformance corpus

This isolated package generates and falsifies the six-file, language-neutral
application-protocol corpus authorized by Issue #264. It is evidence for the
transcript-only C0.3 entry gate, not a product implementation.

The generator reads every normative input from the contract Base commit. The
Python and Node.js readers independently parse, verify and replay ordinary
corpus inputs; expected results are compared only after execution. The mutation
runner requires both implementations to kill the complete closed registry.
The tracked package currently contains 17 transcript-conformant, 36
local-negative and three
AP-expectation-only transcript vectors, 128
state/flow/counterexample/vector/invariant/history/dependency scenarios, three
positive connected K graphs with 18 observations, 17 hostile connected graphs
with 66 observations, and 522 mutations. Transcript bytes and signatures are evaluated
independently in Python and JavaScript. Identity-bearing trace digests remain
separate from semantic-observation digests that exclude scenario bookkeeping.
The mutation registry separates 36 hostile-input mutations, 21 independently
pinned one-to-one invariant-witness substitutions, four legal
expected-result substitutions, 442 exact source-relation removals and five
manifest-digest substitutions, plus fourteen source-anchored checks for O-10,
checkpoint ordering, commitment geometry and layered K/AP results.
Source-relation and manifest mutations are
materialized and rejected by the same validators used for the unmodified
corpus; they are evidence-integrity tests and are not credited as semantic
invariant witnesses.

O-10 source coverage is row-exact. Each of the 102 pinned source rows is
partitioned as produced, AP-owned-excluded or transcript-profile-unreachable.
A produced row names its exact evaluator input and scenario. Joint attribution
is explicit and is allowed only when the same input necessarily violates rows
with the same primary and stage; sharing a generic same-outcome scenario is not
coverage.

The 47 `TRANSCRIPT_PROFILE_UNREACHABLE` source rows are bounded arguments from
the selected transcript-only profile, not a mechanical proof that no future
implementation could ever reach them. Their exact cardinality detects drift in
this selected partition; it cannot detect a reachability gap that was already
present when the partition was frozen.

From the repository root:

```bash
export PYTHONDONTWRITEBYTECODE=1
unset PYTHONOPTIMIZE
tmp="$(mktemp -d)"
python3 tools/causal-flow-simulator/c03/generate_corpus.py \
  --repo-root . --output "$tmp/generated"
python3 tools/causal-flow-simulator/c03/validate_corpus.py \
  --repo-root . --corpus conformance/application-protocol/c03 \
  --output "$tmp/validate.json"
python3 tools/causal-flow-simulator/c03/replay_corpus.py \
  --repo-root . --corpus conformance/application-protocol/c03 \
  --output "$tmp/replay.json"
node tools/causal-flow-simulator/c03/node_adapter.mjs \
  --repo-root . --corpus conformance/application-protocol/c03 \
  --output "$tmp/node.json"
python3 tools/causal-flow-simulator/c03/run_cross_runtime.py \
  --repo-root . --corpus conformance/application-protocol/c03 \
  --output "$tmp/cross.json"
python3 tools/causal-flow-simulator/c03/run_mutations.py \
  --repo-root . --corpus conformance/application-protocol/c03 \
  --output "$tmp/mutations.json"
diff -ru conformance/application-protocol/c03 "$tmp/generated"
```

The public blind-kit workflow is intentionally separate from ordinary corpus
replay. `build_blind_projection.py build-kit` exports opaque inputs without
publishing their exact cardinality and includes the
eight required specification sources without official identifiers, expected
results, traces or integration mappings. A newly authored kit-only reader is
then frozen before the withheld integration map is created. Finally,
`compare_clean_room.py compare` requires exact agreement between Python,
JavaScript and that frozen third reader for 68 valid observations and all 36
local-negative classifications, plus all 84 observations from the 20 connected
graphs. The AP transition table is outside this blind
claim.

The first shape-complete clean-room comparison on Issue #266 is diagnostic,
not counted final evidence. It exposed four public-input/semantic-contract gaps
that can be corrected without changing a valid transcript: selected profile
state was copied from hostile bytes, reference-collision state was not
observable, missing detachable content was conflated with a missing opening,
and O-08 stage ownership was underspecified. It also exposed a separate open
contradiction: `vec-control-rotate` and `vec-control-recover` carry fresh-GRANT
references that are neither their direct predecessor nor a member of their
encoded causal-parent frontier, although the frozen transcript profile requires
one of those signed relations. Local admission metadata cannot repair that
transcript relation. Those two records must not be treated as corroborated K
admissions unless a separately authorized resolution preserves the frozen
contract honestly. No reader output is coerced to hide this finding.

All vector bytes and keys are public deterministic test material. The package
does not claim a production ceremony, recovery, persistence, transport, wire
format, implementation alignment, audit, demo readiness or sensitive-use
safety. C0.3 remains `NO_GO` for `demo`, `implementation_alignment`, `product`
and `sensitive_use`.
