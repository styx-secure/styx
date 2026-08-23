# C0.2j credential-succession simulator (v3)

This directory contains an independently authored, bounded symbolic model for
the C0.2j credential-succession decision. It does not import, copy or modify the
historical v1/v2 simulators.

The model exercises:

- grant-rooted, context-local credential identifiers;
- exact K-level binding lookup and fail-closed mismatch handling;
- Pass0 `May0`/`Must0` evaluation over every bounded causal linearization,
  followed by the first eligible contested reduction slot per actor;
- transitive provenance containment and non-resurrection;
- credential-lineage fork quarantine with independent-authority continuation;
- retained C0.2i pending/no-substitution/checkpoint-stale properties;
- full-replay convergence under every delivery permutation within the envelope;
- 30 semantic mutants tied bidirectionally to hostile witnesses, with each
  declared detector executed under its named mutation rather than inferred from
  unrelated assertion failure.

Run it with:

```bash
python3 -m unittest discover -s tools/causal-flow-simulator/v3/tests -p 'test_*.py'
python3 tools/causal-flow-simulator/v3/causal_flow_simulator_v3.py \
  --suite required --output /tmp/styx-c02j-v3.json
python3 tools/causal-flow-simulator/v3/mutation_harness_v3.py \
  --suite required --output /tmp/styx-c02j-v3-mutants.json
```

The JSON reports are canonical (`sort_keys`, compact separators, one trailing
newline). Identical source and runtime inputs therefore produce byte-identical
evidence. Bounds in the report are experiment bounds, not production limits.
