# APP-CORE-IFACE-0 conformance model

This directory implements the bounded, language-neutral APP-core evidence
interface ratified by Issue #295.  It is a conformance model only: none of the
objects or reports produced here is an accepted context, authority capability,
durable commit, wire format, storage record, or supported runtime adapter.

The immutable `contract/` directory contains the manifest plus the exact 26
ratified inputs.  The current Python reference model evaluates the six pure
operations and enforces the V9 replay, authority, pending/content, F13 and
closed collection-bound relations covered by its tests.  The independent
JavaScript reader currently checks reserved reachability, fork/join labels,
graph, credential and authority projections, exact event/context outcome
precedence, and the same closed collection bounds.

The complete blind corpus, populated positive-carrier/seed registries,
1,450-row structural witness execution, semantic mutation campaign, canonical
two-reader reports and two-clean-worktree `final_gate.py` are still required.
Until those artifacts exist and pass, this directory is an implementation in
progress rather than complete conformance evidence.

The six operations are:

- `DESCRIBE_PROFILE`
- `VALIDATE_TRANSCRIPT`
- `EVALUATE_GENESIS`
- `REPLAY_CONTEXT`
- `EVALUATE_CANDIDATE`
- `EVALUATE_EVIDENCE_UPDATE`

Every operation is pure and data-only.  A future supported adapter must
re-establish the authenticated K/AP/RS boundaries and authoritative prior
independently; passing this model can never create those capabilities.

Run the local package and inventory checks with:

```bash
python3 -m unittest discover \
  -s tools/causal-flow-simulator/app_core_iface0/tests -p 'test_*.py'
python3 tools/causal-flow-simulator/app_core_iface0/validate_inventory.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --output /tmp/app-core-inventory.json
```

Generated reports belong outside the repository and must never be committed.
