# APP-CORE-IFACE-0 conformance model

This directory implements the bounded, language-neutral APP-core evidence
interface ratified by Issue #295.  It is a conformance model only: none of the
objects or reports produced here is an accepted context, authority capability,
durable commit, wire format, storage record, or supported runtime adapter.

The immutable `contract/` directory contains the manifest plus the exact 27
ratified inputs.  The current Python reference model evaluates the six pure
operations and enforces the V9 replay, authority, pending/content, F13 and
closed collection-bound relations covered by its tests.  The independent
JavaScript reader currently checks reserved reachability, fork/join labels,
graph, credential and authority projections, exact event/context outcome
precedence, and the same closed collection bounds.

Phase A now generates the closed 77-request blind population, 19 withheld
reference responses, the 96-row positive-carrier inventory, an exact
request-only review manifest and the package report outside the repository.
The request-only manifest is pinned to the independently reviewed digest and
contains carrier bytes, coverage and first-retained synthesis provenance, but
no response identity, response digest or semantic outcome. Of the 77 requests,
64 are schema-object
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

For the combined H12/H3 increment, provider identity is the exact commit plus
`refs/heads/task/295-c03-h12-h3-combined-remediation`. PR #296 is unrelated to
this terminal check and can neither satisfy nor veto it.

Phase B remains incomplete. Its deterministic registry derivation maps all
1,553 structural instances to Phase-A carriers and preflights both target
reachability and isolated perturbation. The earlier V24 isolation relation is
being mapped by exact source identity onto the amended schema before the
production-faithful V1 canonical boundary and whole-V2 validator run in Python
and the cross-runtime runner requires byte-identical JavaScript observations.
Phase B must still complete and freeze that two-runtime report. The semantic
preflight now derives the exact 2,359-row execution relation from the real
87-row seed registry,
including the carrier-dependent ACV-048 partition, but deliberately labels the
result `PRESELECTION_EVIDENCE`: it neither ratifies those carriers nor claims
that all semantic rows or their source mutants have executed. ACV-048
additionally executes all 783 cross-plane field-smuggling instances and their
isolated schema mutants in Python and JavaScript, while retaining the same
preselection status. Phase B must still execute every remaining semantic
instance and kill every remaining named source mutant.
Until both phases pass, this directory is an implementation in progress rather
than complete conformance evidence.

The implementation scope of this increment is exactly
`tools/causal-flow-simulator/app_core_iface0/**`. Reports from C0.3, SS0 and the
protocol review model are final-gate regression inputs; naming them here does
not authorize changes outside that APP-core subtree.

ACV-049 remains a partial execution rather than a closure claim. Its ratified
884-row relation now executes all 401 literal, 101 singleton, five non-string
and 77 blind-request rows. The E baseline is run twice under distinct mutant
channels by the outer gate: Python emits reader jobs, Node evaluates them, and
Python validates the independently produced results. A closed static source
scan and a runtime provenance monitor are conjunctive. The runtime monitor
records manifest-bound filesystem reads and the exact permitted validator/Git
spawn tree, rejects every other provenance source, and runs negative controls
for every allowlisted environment name in both Python and Node. The remaining
300 P rows and their source-mutant kills are not yet claimed.

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

# Run from a third controller checkout at the exact candidate: it must be clean,
# distinct from both evidence worktrees, and have HEAD == $CANDIDATE.
# The literal final mode is selected only when none of --phase-a,
# --phase-b-entry, or --acv049-e-baseline is present and all seven flags below
# are supplied. Exit 0 means every family is PASS; MISSING or any gate error is
# exit 2 with phaseBComplete=false. Only the 14 filenames fixed by Required
# verification form the evidence-root set. PHASE_A, HOSTILE_OBSERVATIONS,
# ACV049_RECONCILIATION, SOURCE_MUTANT_KILLS and SCOPE_AND_REGRESSIONS remain
# MISSING with reason UNPRESCRIBED_EVIDENCE until authority prescribes the
# missing report bindings and schemas.
CANDIDATE=0cb46fc6d77c93ad0fae068f37cca45ccacf1113
python3 tools/causal-flow-simulator/app_core_iface0/final_gate.py \
  --base e0af4e1e2173deb2481eabdb24d8622282b33455 \
  --candidate "$CANDIDATE" \
  --worktree-1 /clean/checkout-one \
  --evidence-1 /external/evidence-one \
  --worktree-2 /clean/checkout-two \
  --evidence-2 /external/evidence-two \
  --output /external/final/final-gate.json

# ACV-049 E is orchestrated only by the outer gate.  The Python evaluator and
# JavaScript reader never spawn one another.  Both checkouts must be clean,
# distinct clones of the exact candidate HEAD and both evidence roots must be
# byte-identical Phase-A packages.  /usr/bin/strace is required to prove that
# no evaluator or validator descendant escapes the monitored spawn tree.
python3 tools/causal-flow-simulator/app_core_iface0/final_gate.py \
  --acv049-e-baseline \
  --repo-root-one /clean/checkout-one \
  --repo-root-two /clean/checkout-two \
  --evidence-root-one /external/phase-a-one \
  --evidence-root-two /external/phase-a-two \
  --selection-head 0000000000000000000000000000000000000000 \
  --node /absolute/path/to/node

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

## Executable-review sandbox

Cross-vendor reviewers must execute each proposed counterexample before they
report the finding. `review_sandbox.py` creates a self-contained detached clone
at the exact candidate commit, runs it with a minimal read-only system root and
no network through
`bubblewrap`, runs the complete APP-core unit suite plus both deterministic seed
generator proofs, and only then runs the reviewer's probe. The JSON report must
also be outside the repository.

The sandbox clears the host environment, creates private `/dev`, `/proc`,
`/tmp` and writable scratch filesystems, and does not mount the host home.
Absolute regular-file arguments, such as the external probe script in the
example below, are mounted individually read-only; a probe must be
self-contained or use files from the checkout.

A probe runs with the detached checkout as its current directory. It must exit
zero and write exactly one canonical JSON object (sorted keys, compact encoding,
one final LF) to stdout:

```json
{"reproduced":true,"summary":"minimal counterexample reaches the claimed branch"}
```

Example invocation:

```bash
CANDIDATE=$(git rev-parse HEAD)
python3 tools/causal-flow-simulator/app_core_iface0/review_sandbox.py \
  --repo-root . \
  --revision "$CANDIDATE" \
  --finding-id REVIEW-HIGH-01 \
  --severity HIGH \
  --output /external/review/REVIEW-HIGH-01.json \
  -- python3 /external/review/probe-high-01.py
```

Copy this rule into every review prompt:

> For each candidate finding, first write a minimal executable counterexample
> outside the repository and run it through `review_sandbox.py` at the exact
> reviewed commit. Report the finding at its proposed severity only when the
> sandbox report says `CONFIRMED`. If it says
> `DOWNGRADED_NOT_REPRODUCED`, downgrade it to `NOTE` and label it
> unconfirmed; do not present it as a blocking finding. If it says
> `INVALID_BASELINE` or `INVALID_PROBE`, stop the review. Cite the report path,
> candidate commit, probe summary and output digest for every finding.

The sandbox rejects probe stdout above 16 KiB, gives each validation command a
two-hour timeout by default (override with `--timeout-seconds`), requires a typed
`reproduced`/`summary` result, records command digests and tails, and verifies
that the detached checkout remains clean. A probe that fails to execute or
emits an invalid result is `INVALID_PROBE`, never a false non-reproduction.
The parsing-refactor gate and its
inventory are in `IMPACT-ANALYSIS-PARSING.md`.

## M1 O-04 known deviations

Follow-up issue [#312](https://github.com/styx-secure/styx/issues/312) owns the
deferred protocol reconciliation. M1 makes no reachability-conformance claim
for CAR-004, CAR-007, CAR-010 or CAR-017.

The v0 evidence plane still collapses these payload-commitment §5.4 local
observations instead of carrying availability and binding independently:

- opening-only;
- complete bytes without an opening;
- partial bytes without an opening;
- partial bytes with an opening; and
- content bytes and an opening presented in separate attempts.

Those well-formed incomplete attempts are dropped. An evidence-update batch
containing only such attempts reports the existing `EMPTY_ADDITION_SET` token
until a separately authorized `INCOMPLETE_EVIDENCE` result exists. Replay uses
the single `EVIDENCE_NONCANONICAL` token for both signed-length overflow and an
exact complete value whose opening fails commitment verification.

M1 also admits a DETACHABLE event without an opening. That behavior conflicts
with R7/C0.3 and the ratified O-10 `OPENING_MISSING` primary (F13R-015, closure
row 76), for which APP-core has no producer in M1. CAR-010 and CAR-017 are
witnessed only for `REPLAY_CONTEXT`; no witness for another operation is
claimed.
