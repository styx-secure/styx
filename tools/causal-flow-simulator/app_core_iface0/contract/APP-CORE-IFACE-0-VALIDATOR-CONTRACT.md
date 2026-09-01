# APP-CORE-IFACE-0 validator contract candidate

Status: pre-ratification working candidate. This file is not repository
authority and authorizes no implementation.

## Objective

Define one deterministic fail-closed validation pipeline for the six-operation
APP-core data interface. The pipeline validates conformance evidence only. It
does not accept a context, perform an application transition, persist state,
create a local capability or authorize a future adapter operation.

The eventual repository increment must implement this contract twice: once in
the reference implementation and once in an independently authored JavaScript
reader. Equality of the two is conformance evidence, not authority.

## Frozen logical inputs

One invocation receives exactly:

1. raw request octets;
2. the exact ratified interface schema;
3. the exact ownership registry;
4. the exact semantic-constraint registry;
5. the exact semantic-instance-axis registry;
6. the exact structural-axis registry;
7. the exact 93-row `oneOf` pairwise-disjointness registry;
8. the exact mechanically generated twelve-root carrier-reachability relation;
9. the exact 76-row canonical object-schema seed registry for hostile generation;
10. the populated per-instance structural witness registry;
11. read-only pinned native artifacts and their provider-bound SHA-256 values;
12. the exact selected O-08 resource-envelope artifact; and
13. for test execution only, one named oracle-free scenario package.

The invocation receives no expected result, ceremony decision/capability,
accepted-state handle, AP-authority verdict, SS state, RS result, clock,
filesystem path, transport fact, product state, random value or parser/profile
selector outside the request's exact closed fields.

## Closed harness disposition

The harness emits exactly one of:

```text
REQUEST_REJECTED
RESPONSE_EMITTED
HARNESS_FAILURE
```

`REQUEST_REJECTED` has zero interface-response octets and no public reason,
diagnostic, echoed discriminator or exception text. `RESPONSE_EMITTED` has
exactly one canonical `InterfaceResponseV0`. `HARNESS_FAILURE` is evidence that
the run failed and can never be compared as an application outcome.

Timeout, crash, signal, non-zero child status, silence where a response is
required, extra stdout bytes, stderr diagnostics, malformed output or unknown
disposition is `HARNESS_FAILURE`, never a green skip.

## Mandatory ordered phases

### V0 — authority and environment preflight

Before request parsing:

- verify all provider-bound path/digest pairs byte-for-byte;
- verify the schema meta-schema and resolve every local `$ref`;
- regenerate the carrier-reachability relation and require exact equality,
  including all twelve roots, 112 definitions, 76 object schemas and 54
  `oneOf` arms; reject every dead definition or unreachable assertion;
- reject a schema cycle, remote reference, unknown vocabulary or unknown
  `x-styx-*` keyword;
- verify exact equality of object/property/schema-keyword, ownership,
  structural-axis, semantic-rule, custom-keyword and instance-axis relations;
- derive and compare the ordered hostile-family and terminal-path digests;
- verify the selected O-08 candidate ID/digest and every projected interface
  limit against the pinned O-08 artifact; and
- verify that no test scenario input contains expected output or mutation
  survivor data.

Any failure is `HARNESS_FAILURE`; it is not a malformed caller request.

### V1 — raw envelope admission

Apply the ratified outer request-octet limit before copying, decoding or
allocating proportional to a declared value. Then:

1. require strict UTF-8 with no BOM;
2. tokenize JSON while retaining member occurrences;
3. reject duplicate keys before constructing a host-language object;
4. reject non-object top-level JSON, trailing bytes and non-JSON numeric
   tokens; and
5. reject any representation outside `STYX_CANONICAL_EVIDENCE_JSON_V0`.

A V1 failure produces `REQUEST_REJECTED` and no interface bytes. Host parser
exceptions and locations are not observable output.

### V2 — closed dispatch and structural schema

Read `interfaceVersion` and `operation` only after V1. Require exact literals
and select exactly one of the six request arms. There is no shape inference,
fallback, version negotiation, case folding or migration.

Validate the selected arm with Draft 2020-12 plus the ratified closed custom
vocabulary. Unknown/missing/null/mistyped fields, operation/shape mismatch and
all custom scalar/limit failures reject the whole request.

A V2 failure produces `REQUEST_REJECTED` and no interface bytes. The validator
must not echo an unvalidated operation or profile.

### V3 — ownership and source validation

For every admitted request field:

- resolve exactly one ownership row;
- enforce its source token;
- reject any caller-supplied derived projection, verification/admission/
  authorization/freshness/persistence verdict, capability representation,
  trusted digest or cross-plane state;
- treat raw transcript/evidence bytes only as candidate material; and
- never infer their source from a field name or successful parse.

Closed structural validation does not prove trusted provenance. Where source
cannot be established in this data plane, the field remains a non-authoritative
candidate and the trusted composition plane must re-establish it independently.

### V4 — operation-independent native binding

Reconstruct the exact profile descriptor from pinned native authority. Compare
the request profile field-by-field with the selected O-03/profile relation.
Never accept caller-selected suite, resource envelope, transcript grammar or
outcome taxonomy.

Unsupported/mismatched profile selection yields the exact operation-specific
terminal relation only when the request itself passed V1/V2. It never falls
back to another profile.

### V5 — operation evaluation

Dispatch exactly one operation:

1. `DESCRIBE_PROFILE` reconstructs and returns the immutable descriptor; it
   does not probe runtime availability or manufacture a capability.
2. `VALIDATE_TRANSCRIPT` checks bounds, canonical framing, reference and
   signature in the ratified order. It returns only the exact transcript
   validated/rejected union and reachable observations.
3. `EVALUATE_GENESIS` reuses the transcript checks, compares the expected
   context and root position, and returns either one complete non-authoritative
   proposal or one exact genesis-terminal result. It consumes no ceremony
   verdict or capability.
4. `REPLAY_CONTEXT` revalidates the complete genesis/raw candidate/evidence
   closure, orders candidates by recomputed canonical reference and returns
   ready only if every supplied distinct candidate belongs to the retained
   closure. Otherwise it selects the first canonical failing candidate or one
   replay-input terminal; it never silently drops input.
5. `EVALUATE_CANDIDATE` revalidates the complete prior, evaluates the candidate
   under the exact 25-row F13 relation and returns a terminal result or one
   complete successor proposal. The successor must equal complete replay. It
   copies the exact O-10 stage/mutation tuple and keeps deterministic O-08 S6
   reachable only on the would-be `APPLIED` path; all successor publication is
   deferred to the separate adapter/RS lifecycle.
6. `EVALUATE_EVIDENCE_UPDATE` revalidates the complete prior and permits only a
   non-empty monotone addition for known events. It returns the distinct
   rejected/idempotent/ready union, never K-retention or an O-10 primary. A
   ready successor must equal complete replay. The supplied prior is evidence
   input, never online-update authority; the future adapter must source and
   revalidate the authoritative prior before commit.

No operation mutates its input, writes storage, accesses a network, commits a
state, returns a secret or exposes an internal exception.

### V6 — response reconstruction and canonical serialization

Construct the response discriminator/profile from the validated operation and
pinned descriptor; never copy them blindly from request or evaluator output.
Validate the complete object against `InterfaceResponseV0` and all semantic
constraints before serialization.

Serialize once using the ratified evidence JSON profile. Reparse the emitted
bytes through V1/V2 response validation and require field-for-field equality
with the pre-serialization object. Reject any floating point, alternate numeric
form, non-lowercase hex, unknown field, unstable collection order or extra
bytes.

Only then emit `RESPONSE_EMITTED` and the exact bytes.

### V7 — canonical report hygiene

Canonical reports contain only closed IDs, counts, dispositions and digests
explicitly permitted by the report schema. Before report serialization:

- expand the ratified semantic-instance axes;
- require one observation per exact instance;
- validate all 344 response string positions against each of the ten forbidden
  runtime-provenance families;
- reject absolute paths, host/user/PID/time/duration/environment/exception/
  stack material in every string position;
- reject repository, Base/HEAD/tree/diff/bundle and runtime identities in any
  forbidden location; and
- require exact equality with the independently regenerated report.

External identity evidence may carry provider-bound commit/diff/bundle values;
canonical semantic reports may not silently inherit them.

## No-partial-result rule

An operation produces zero or one complete interface response. There is no
streaming, warning channel, partial observation response or best-effort
projection. If a post-dispatch invariant fails, the harness records
`HARNESS_FAILURE`; it must not reinterpret an implementation defect as a
protocol rejection.

## Mutation obligations

Each validator phase has at least one source mutant that weakens only that
phase. Structural families use one generated decoder/schema mutant per exact
schema-keyword/property instance. Semantic families use the ratified instance axis and
one named detector per instance. A mutant is killed only when:

1. its exact hostile instance runs;
2. the intended assertion observes the wrong behavior;
3. reference and independent implementations agree on the required behavior;
4. the unmutated negative control passes; and
5. no crash, timeout or unrelated earlier rejection masks the mutant.

Surviving, equivalent, unreachable, multiply modified or wrong-detector mutants
fail the campaign.

## Evidence identities

The executable Issue must replace every logical filename with a repository path
and literal SHA-256 after PR #294 merges. It must provider-bind:

- exact Base and Issue-body digest;
- schema, ownership, structural-axis, structural-witness, semantic,
  instance-axis, execution-phase and seed
  registries;
- all native transcript/O-03/O-04/O-07/O-08/O-10/O-14/C0.3 artifacts;
- reference and independent source identities;
- oracle-free kit and withheld-oracle identities;
- mutant source relation;
- tool/runtime versions; and
- the two-clean-checkout final package manifest.

A local file, README assertion, aggregate count or prior review cannot replace
provider-bound exact bytes.

## Remaining pre-ratification closures

The schema, 55-row semantic-instance-axis registry, 23-row content-axis,
25-row F13 primary/axis, 14-row transcript and 16-row genesis relations are now
literal working candidates. The relation expands the nine ACV-048 forbidden
families through all 76 property-bearing object schemas. Together with the
closed structural-keyword relation it derives 5,991 structural-plus-semantic
execution instances. They all require independent review and human ratification.

Two literal execution outputs cannot exist before the repository increment
supplies valid carriers: the canonical 76-row seed registry and the
per-instance structural witness registry. Their row shape, equality rules and
hostile derivation are already fixed; only exact carrier case IDs, JSON
pointers and object-byte digests remain to be generated from Base
`16274cc194cd2f8f7b631332687a252bad92ce02`. They are deliverables, not choices
that the executor may redefine.

The row shape is frozen by the working
`APP-CORE-IFACE-0-SEED-REGISTRY-SCHEMA-CANDIDATE.json`. The executable
validator must additionally enforce relations that JSON Schema alone cannot:

1. the seed registry binds the exact positive-carrier inventory digest; that
   inventory has unique case IDs, covers all twelve direction/operation roots,
   all 76 object-schema pointers and all 54 literal `oneOf` arms, and every
   withheld response binds its generating request and reference report;
2. the sorted `objectSchemaPointer` set equals exactly the 76 property-bearing
   object schemas in the pinned interface schema, including the five inline
   objects, with one row per pointer;
3. each `objectSchemaId` is unique and stable, and `objectSchemaSha256` is the
   digest of that canonical schema subtree;
4. each carrier is a listed regular file with exact octet count and digest;
5. the full carrier parses canonically and validates against the declared
   request/response root and operation arm;
6. the JSON pointer resolves exactly once, its canonical target bytes match the
   target digest and the target validates against the declared object schema;
7. request carriers are `BLIND_INPUT`, response carriers are
   `WITHHELD_ORACLE`, and no withheld carrier enters the pre-freeze kit;
8. the union of `structuralFamilyIds` equals the structural relation assigned
   to object seeds, without missing, extra or duplicate ownership; and
9. changing a carrier, pointer, object schema, direction, disclosure class or
   operation without updating every bound digest fails closed.

The structural witness registry additionally has exact-set equality with all
1,367 structural instances. Every row binds one instance ID to a seed row,
target pointer, deterministic perturbation, expected disposition, observation
ID and source-mutant detector. It also proves positive coverage of all 54
`oneOf` arms and pairwise arm disjointness; an aggregate validator result or
one witness reused as the sole evidence for another instance fails closed.

For each row, `perturbationKind` and `expectedDisposition` must equal the
owning structural-axis rule. `FROM_RELATION_SUFFIX` is resolved exclusively
from the literal conditional-row suffix. `executionPhase`, `disclosureClass`
and `expectedObservationId` are derived exclusively from the carrier direction
and the structural-axis execution contract. These values are not authored by
the witness generator. A mismatch between the derived tuple and any stored
row is a registry failure before execution.

`isolationMode` is likewise derived. Exactly one source occurrence may use
`RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST`: the empty `DescribeProfileInputV0`
object's `maxProperties: 0`, which is logically implied by its closed empty
shape. It still requires a live rejection observation and a separate public
validator self-test, but cannot claim a target-only mutant kill. Any second
exception, unratified redundancy or self-test reported as implementation
agreement fails closed.

Review may amend a candidate relation, but must change its literal rows, count
and digest together. No amendment may add a seventh operation, authority
effect, implicit migration or fallback path without a new human-ratified
contract decision.
