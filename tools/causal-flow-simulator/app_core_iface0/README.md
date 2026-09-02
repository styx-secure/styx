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

Phase A now generates the closed 65-request blind population, 15 withheld
reference responses, the 80-row positive-carrier inventory and exact package
manifest outside the repository. Of the 65 requests, 56 are schema-object
coverage carriers that stop at profile selection and nine are semantic fixtures
that reach the evaluator; none of the attempted `oneOf` carriers survives
canonical-byte de-duplication as a distinct request. Six of the 15 distinct
responses are profile rejections. The reference probe freezes all 65 outputs
before reading response bytes. Only after that local freeze, the JavaScript
reader independently applies response-schema, canonical-JSON and reserved-row
release checks to the 15 withheld response carriers; it does not evaluate the
65 request semantics and cannot authorize provider-bound oracle release.
Phase-A package mutations are required to fail through their named detectors.
Exact-final-head two-clean-checkout evidence, independent acceptance and
provider-bound human ratification are still required before the carrier
inventory becomes Phase-B input.

Phase B remains unimplemented: it must bind that ratification, populate and
execute the 1,450 structural witnesses and 5,149 semantic instances, kill every
named source mutant and obtain byte-identical Python/JavaScript reports. Until
both phases pass, this directory is an implementation in progress rather than
complete conformance evidence.

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

python3 tools/causal-flow-simulator/app_core_iface0/generate_seed_registry.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --prove-reference-round-trip

python3 tools/causal-flow-simulator/app_core_iface0/generate_seed_registry.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --prove-positive-carrier-closure

# Evidence paths must be outside the repository and initially absent.
python3 tools/causal-flow-simulator/app_core_iface0/generate_seed_registry.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --generate-phase-a \
  --evidence-root /external/path/app-core-phase-a

python3 tools/causal-flow-simulator/app_core_iface0/run_probe.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --evidence-root /external/path/app-core-phase-a \
  --output /external/path/reference-probe.json

python3 tools/causal-flow-simulator/app_core_iface0/run_cross_runtime.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --evidence-root /external/path/app-core-phase-a \
  --javascript node \
  --output /external/path/javascript-release.json

python3 tools/causal-flow-simulator/app_core_iface0/run_mutations.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --evidence-root /external/path/app-core-phase-a \
  --output /external/path/phase-a-mutations.json
```

The first seed command produces and evaluates one structural blind request per
operation and validates the six resulting responses before release. It is a
round-trip prerequisite, not the still-missing complete positive-carrier or
withheld-response inventory.

The closure proof expands the blind request population with deterministic
semantic requests, obtains every response from the reference evaluator, and
validates each response before release. The current proof closes all 12 roots,
78 property-bearing object schemas and 54 `oneOf` arms without synthesizing a
response carrier. It deliberately writes no case IDs, inventory or seed rows;
those remain governed generated artifacts rather than implementation choices.

Generated reports belong outside the repository and must never be committed.
