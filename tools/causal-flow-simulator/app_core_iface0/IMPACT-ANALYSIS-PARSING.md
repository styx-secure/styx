# IMPACT ANALYSIS: single typed parsing boundary

Status: STOP before implementation. The proposed refactor cannot preserve every
ratified behaviour and public call shape at `73a0dd245046a0972acc6fa04433cc0c211a34e4`.
This document records the required analysis; it does not authorize a parsing
refactor.

## Inventory at the baseline

An AST inventory over production Python below `app_core_iface0/**` (excluding
`tests/**`) found 149 conversion calls in 19 files at the baseline commit:

| conversion | sites |
|---|---:|
| `int(...)` | 65 |
| `bytes.fromhex(...)` | 29 |
| `json.loads(...)` | 31 |
| an imported `loads(...)` | 22 |
| the imported strict alias `canonical_loads(...)` | 2 |
| `float(...)` | 0 |

The independent JavaScript reader has 10 `JSON.parse(...)` sites in
`node_adapter.mjs`. Tests contain another 110 Python conversion calls in 12
files. The inventory is syntactic and intentionally over-inclusive: many sites
convert already validated values, schema indexes, generated fixtures, local
reports, GitHub API responses, or subprocess output rather than untrusted wire
input.

Production Python sites by file:

| file | sites | role / real input |
|---|---:|---|
| `interface_model.py` | 42 | canonical request bytes, validated request members, contract JSON, signatures, commitments and evidence segments |
| `generate_seed_registry.py` | 25 | trusted schema constraints and generated hex fixtures |
| `final_gate.py` | 20 | evidence reports, GitHub/API authority records, subprocess output and numeric report leaves |
| `run_semantic_acv049.py` | 19 | AST locations, schema constraints, reports, stdin jobs and mutant manifests |
| `generate_structural_witnesses.py` | 16 | JSON pointers, canonical evidence and deliberate duplicate-member differentials |
| contract derivation/validation scripts | 8 | checked-in contract files, GitHub output and schema indexes |
| remaining runners, inventory and canonical report modules | 19 | checked-in JSON, generated reports and Node subprocess output |

## Existing boundaries and callers

1. Untrusted Python request bytes already have an ordered boundary:
   `read_bounded_request` applies the octet limit, then
   `admit_canonical_request` calls `canonical_json.loads`, maps every parse
   failure to an opaque `RequestRejected`, and requires an object. Its docstring
   explicitly says that no parser diagnostic is released.
2. `evaluate_interface_request(authority, request: dict)` is also a public model
   entry point. Callers construct dictionaries directly, then
   `validate_request_structure` applies the complete schema and closed bounds.
   Evidence conversion occurs later, after regex/schema guards. For example,
   offsets must match `0|[1-9][0-9]{0,19}` before `int`, then must be at most
   `2^64-1`.
3. `node_adapter.mjs` is intentionally an independent cross-runtime reader. It
   parses stdin jobs, checked-in schemas and generated evidence without using
   Python code.
4. The generators and final gate are controllers, not one wire boundary. Their
   inputs include checked-in authority, generated canonical reports, CLI/stdin,
   GitHub JSON, Git object data and child-process JSON; each currently maps
   failures to a role-specific exception or gate result.
5. Some direct conversions are detector controls, not accidental parsing. In
   particular the V1 detector mutant in `interface_model.py` deliberately uses
   permissive `json.loads`, and structural-witness code compares strict and
   permissive duplicate-member behaviour.

## Proposed design if a new authority ratifies the changes

A future change could introduce `parsing.py` with:

- one closed `ParseError(code, location)` internal type;
- bounded constructors such as `UInt64Decimal`, `Hex32`, `NonEmptyHex` and
  `CanonicalDocument`;
- byte-limit -> strict UTF-8/canonical JSON -> schema -> bounded constructor
  ordering;
- adapters that deliberately map `ParseError` back to each existing public
  rejection taxonomy;
- a separate JavaScript boundary with the same vectors, because replacing the
  independent reader with Python would invalidate cross-runtime independence;
- an AST lint that forbids the four conversion families outside the boundary,
  with explicit, reviewed exemptions for mutation/differential controls and
  tests.

Before implementation, the authority would need to decide whether the public
model accepts only a new parsed request type or continues accepting dictionaries,
and whether all controller errors must preserve their current types/messages.
Golden tests would have to freeze both questions first.

## Behaviour changes that block implementation on this card

The requested literal design (one module, one typed `ParseError`, and a lint
forbidding conversions elsewhere) conflicts with ratified behaviour:

- Replacing opaque `RequestRejected` with an observable `ParseError` changes the
  request rejection contract. Mapping it back preserves the external result but
  no longer satisfies the literal single-error surface.
- Requiring bounded parsed types changes the callable shape of
  `evaluate_interface_request`, which currently accepts ordinary dictionaries.
- Moving or forbidding the permissive parser used by V1 and duplicate-member
  detector mutants removes the independent negative controls those ratified
  tests exercise.
- Removing JavaScript parsing destroys the independent-reader property; keeping
  it violates the literal single-boundary lint.
- Collapsing controller-specific failures (`HarnessFailure`,
  `InterfaceModelError`, canonical/report errors, gate failures and contract
  validation errors) into `ParseError` changes final-gate and evidence semantics.
- Applying the lint to tests would also reject 110 intentional fixture/oracle
  conversions; exempting them means the requested global prohibition is not
  literal.

Therefore no parsing module or AST prohibition is implemented here. The safe
increment is limited to this inventory and proposal. A later authority may
ratify an exception policy and exact error/API compatibility contract, then
implement the migration vertically with boundary-specific RED/GREEN tests.
