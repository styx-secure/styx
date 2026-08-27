# O-10 stable outcome taxonomy

This package is the executable evidence boundary for Issue #252.  It models
local transcript-only outcomes; it is not a product API, wire protocol, storage
format, acknowledgement scheme, or production recovery mechanism.

The normative inputs are the ratified Issue, the 24-outcome Base review model,
and the selected O-08 66-row handoff.  The checked-in inventory has exactly 102
source rows: 36 Base citations and 66 O-08 `(dimension, stage)` rows.  Of these,
99 are positive mappings and three are explicit non-emittable records.

`taxonomy.py` and `node_adapter.mjs` intentionally own separate precedence,
recovery, and remote-collapse tables.  They share only ordinary scenario input
and identifier spelling.  Expected results live in the harness, never in an
adapter input.

All output reports use canonical UTF-8 JSON with LF.  Reports exclude repository
identity, runtime identity, paths, timestamps, durations, process identifiers,
environment ordering, and raw measurements.

Run the package tests from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools/causal-flow-simulator/o10/tests -p 'test_*.py'
```

The final gate is deliberately stronger than a report comparison: it creates
two clean `git clone --no-local` checkouts, regenerates every O-10 report, and
requires byte-identical results.
