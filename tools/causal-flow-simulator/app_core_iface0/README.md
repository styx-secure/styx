# APP-CORE-IFACE-0 conformance model

This directory implements the bounded, language-neutral APP-core evidence
interface ratified by Issue #295.  It is a conformance model only: none of the
objects or reports produced here is an accepted context, authority capability,
durable commit, wire format, storage record, or supported runtime adapter.

The immutable `contract/` directory contains the manifest plus the exact 26
ratified inputs.  The surrounding Python implementation and independent
JavaScript reader regenerate the finite structural and semantic inventories,
evaluate blind request cases, mutate withheld response cases only after output
freeze, and emit canonical reports.  `final_gate.py` compares complete evidence
from two clean exact-HEAD worktrees.

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

