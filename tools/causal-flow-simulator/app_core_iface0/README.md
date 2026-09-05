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

Phase A now generates the closed 77-request blind population, 19 withheld
reference responses, the 96-row positive-carrier inventory and exact package
manifest outside the repository. Of the 77 requests, 64 are schema-object
coverage carriers that stop at profile selection and thirteen are semantic
fixtures that reach the evaluator; none of the attempted `oneOf` carriers
survives canonical-byte de-duplication as a distinct request. Three semantic
fixtures exercise the otherwise impractical reference/commitment collision
branches through an evidence-only oracle selected outside the public request.
The oracle is bound to exact primitive inputs, produces no result directly and
is restored after each execution. The reference probe freezes all 77 outputs
before reading response bytes. Only after that local freeze, the JavaScript
reader independently applies response-schema, canonical-JSON and reserved-row
release checks to the 19 withheld response carriers; it does not evaluate the
77 request semantics and cannot authorize provider-bound oracle release.
Phase-A package mutations are required to fail through their named detectors.
Exact-final-head two-clean-checkout evidence, independent acceptance and
provider-bound human ratification are still required before the carrier
inventory becomes Phase-B input.

Phase B remains incomplete. Its deterministic registry derivation maps all
1,553 structural instances to Phase-A carriers and preflights both target
reachability and isolated perturbation. The earlier V24 isolation relation is
being mapped by exact source identity onto the amended schema before the
production-faithful V1 canonical boundary and whole-V2 validator run in Python
and the cross-runtime runner requires byte-identical JavaScript observations.
Phase B must still complete and freeze that two-runtime report. The semantic
preflight now derives the exact 5,535-row execution relation from the real
87-row seed registry,
including the carrier-dependent ACV-048 partition, but deliberately labels the
result `PRESELECTION_EVIDENCE`: it neither ratifies those carriers nor claims
that all semantic rows or their source mutants have executed. ACV-048
additionally executes all 783 cross-plane field-smuggling instances and their
isolated schema mutants in Python and JavaScript, while retaining the same
preselection status. Phase B must still execute the other 4,752 semantic
instances and kill every remaining named source mutant.
Until both phases pass, this directory is an implementation in progress rather
than complete conformance evidence.

ACV-049 is intentionally not counted as executed. Its preflight expands the
current 4,060 candidate pairs, identifies non-string `const` paths, classifies
literal versus schema-admissible encoded provenance, records which paths exist
in the fifteen frozen outputs using their exact labelled `oneOf` branch, and
runs only live negative controls. It returns
`AMEND_REQUIRED` and claims zero mutant kills because the current target-only
isolation model is equivalent to existing schema rejection.

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

python3 tools/causal-flow-simulator/app_core_iface0/run_semantic_preflight.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --evidence-root /external/path/app-core-phase-a \
  --output /external/path/semantic-preflight.json

python3 tools/causal-flow-simulator/app_core_iface0/run_semantic_acv048.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --evidence-root /external/path/app-core-phase-a \
  --python-output /external/path/semantic-acv048-python.json \
  --javascript-output /external/path/semantic-acv048-javascript.json

python3 tools/causal-flow-simulator/app_core_iface0/run_semantic_acv049.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --evidence-root /external/path/app-core-phase-a \
  --output /external/path/semantic-acv049-preflight.json

python3 tools/causal-flow-simulator/app_core_iface0/generate_structural_witnesses.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --evidence-root /external/path/app-core-phase-a \
  --preflight-targets \
  --output /external/path/structural-target-preflight.json

# Validate the exact V21+V22+V23+V24 structural-isolation relation.  The report
# derives the closed 1469/82/1/1 partition and all 29 carrier reselections.
python3 tools/causal-flow-simulator/app_core_iface0/generate_structural_witnesses.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --evidence-root /external/path/app-core-phase-a \
  --preflight-isolation \
  --output /external/path/carrier-search-isolation-preflight.json

python3 tools/causal-flow-simulator/app_core_iface0/run_structural_cross_runtime.py \
  --repo-root . \
  --contract tools/causal-flow-simulator/app_core_iface0/contract \
  --evidence-root /external/path/app-core-phase-a \
  --python-output /external/path/structural-python.json \
  --javascript-output /external/path/structural-javascript.json
```

The first seed command produces and evaluates one structural blind request per
operation and validates the six resulting responses before release. It is a
round-trip prerequisite, not the still-missing complete positive-carrier or
withheld-response inventory.

The closure proof expands the blind request population with deterministic
semantic requests, obtains every response from the reference evaluator, and
validates each response before release. The current proof closes all 12 roots,
87 property-bearing object schemas and 57 `oneOf` arms without synthesizing a
response carrier. It deliberately writes no case IDs, inventory or seed rows;
those remain governed generated artifacts rather than implementation choices.

Generated reports belong outside the repository and must never be committed.
