# C0.3 transcript-only conformance corpus

This isolated package generates and falsifies the six-file, language-neutral
application-protocol corpus authorized by Issue #264. It is evidence for the
transcript-only C0.3 entry gate, not a product implementation.

The generator reads every normative input from the contract Base commit. The
Python and Node.js readers independently parse, verify and replay ordinary
corpus inputs; expected results are compared only after execution. The mutation
runner requires both implementations to kill the complete closed registry.
The tracked package currently contains 17 valid and 26 invalid transcript
vectors, 114 state/flow/counterexample/vector/invariant/history scenarios and
497 mutations. Transcript bytes and signatures are evaluated independently in
Python and JavaScript. The mutation registry separates 26 hostile-input
mutations, 21 one-to-one invariant-witness substitutions, three legal
expected-result substitutions, 442 exact source-relation removals and five
manifest-digest substitutions. Source-relation and manifest mutations are
materialized and rejected by the same validators used for the unmodified
corpus; they are evidence-integrity tests and are not credited as semantic
invariant witnesses.

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

All vector bytes and keys are public deterministic test material. The package
does not claim a production ceremony, recovery, persistence, transport, wire
format, implementation alignment, audit, demo readiness or sensitive-use
safety. C0.3 remains `NO_GO` for `demo`, `implementation_alignment`, `product`
and `sensitive_use`.
