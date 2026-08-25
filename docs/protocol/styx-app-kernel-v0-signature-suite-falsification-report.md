# Styx O-14 signature-suite falsification report

- **Status:** `NO_COUNTEREXAMPLE_WITHIN_BOUNDS` for the selected candidate.
- **Authority:** bounded evidence only; normative meaning remains in the
  decision registry and protocol profiles.
- **Contract:** Issue #246, exact base
  `94f0a9b2781d45324199e6588629d23babedf746`.
- **Selected candidate:** internal suite `0x0001`,
  `STYX-ED25519-PRIMEORDER-RFC8032-V1`.

## 1. Verdict

No counterexample was found in the declared O-14 envelope. The standard-library
oracle and semantic boundary passed 53 directed checks; 26/26 required mutants
were killed with exact non-empty detector-set equality; and two non-oracle
guarded adapters matched all 29 runtime vectors. Raw backend disagreement was
observed and retained rather than counted as success.

This supports only a condition-bearing O-14 decision. It does not prove the
primitive, product conformance, constant-time behavior, portability, browser
coverage, Dart support, interoperability, anonymity, availability, erasure,
finality, compliance, audit readiness or sensitive-use suitability. C0.3
remains `NO_GO`.

## 2. Deterministic generated evidence

Generated JSON lives only outside the repository. Two fresh directories
produced byte-identical canonical reports:

| Report | Result | SHA-256 |
| --- | --- | --- |
| semantic/oracle probe | `PASS` (53 checks, 29 runtime vectors) | `9556fe7c405a5c5effa7edd3cbcd4ed63c227a7e9340dc0bf26400a42587fd0c` |
| cross-runtime gate | `PASS` (2 non-oracle compliant adapters) | `51b68d6247c3db87ab5b9ca529d35969163b3c4b7440c4db6f4b13da80204c5c` |
| mutation gate | `ALL_REQUIRED_MUTANTS_KILLED` (26/26) | `1a8ee16aacf7f241aea3489280a9a9f0da1fcdbd6758bb75c0f299d434c6d429` |

The final scope-report digest, candidate commit/tree and canonical diff SHA-256
are immutable PR evidence and are intentionally not self-referential tracked
inputs. The current CI does not execute this runtime-resolving gate. The exact
digests and a second clean-worktree reproduction are mandatory task evidence.

## 3. Accepted-language evidence

The oracle independently implements strict and ZIP-215 decoding, cofactored and
cofactorless equations and the selected prime-order guard. It is verification-
only, non-constant-time, confined to the evidence package and forbidden to
product code. It does not select semantics by itself.

Directed witnesses cover empty, one-octet, representative and bounded-maximum
transcripts; zero/exact-minus-one/exact/exact-plus-one and attacker-declared
oversized key/signature lengths; canonical and invalid points, including a
non-canonical `R`; `S == L`, `S > L` and `S + L`; mutations
of both signature halves; transcript/context/credential/sequence/key/suite
changes; positive and negative same-key credential aliases; revocation,
rotation, recovery, historical-verification-without-current-authority and AP denial; transport,
session and carrying-`GRANT` substitution; non-canonical ZIP-215 acceptance;
cofactored-only mixed-order signatures; cofactorless-valid mixed-order
signatures; and small-order `R`.

The mixed-order pair is important: it prevents either equation from being
mistaken for a subgroup check. One witness is accepted by the cofactored
equation but rejected by the cofactorless equation; another is valid under the
cofactorless equation while its `A` is mixed-order. Both are rejected by the
selected prime-order language.

## 4. Runtime evidence and remediation

The exact run measured:

- `@noble/ed25519@2.3.0` from the npm URL and integrity pinned in the repository;
- `cryptography@2.9.0` from pub.dev archive SHA-256
  `3eda3029d34ec9095a27a198ac9785630fe525c0eb6a49f3d575272f8e792ef0`;
- Node `v24.18.0`, OpenSSL `3.5.7`; and
- Dart SDK `3.10.8`, provider `DartEd25519`.

Compliant adapters were non-empty and included:

- Noble point guards plus one Noble `{zip215:false}` verify; and
- the same Noble point guards plus one Node WebCrypto verify.

Raw Noble default, Noble strict, Node WebCrypto and Dart each diverged on at
least one hostile input. None is silently called conforming. The exact raw
divergences and every per-vector result are in the cross-runtime report.

Bounded JS/Node remediation is the declared guard-plus-single-verifier
construction. Dart has no conforming public subgroup-validation surface in the
pinned dependency; `O14-DART-PROFILE-NONCONFORMANCE` blocks a Dart support claim
until a separate ratified dependency/profile gate supplies and reviews one.
`O14-BROWSER-PROVIDER-MATRIX` blocks generalizing Node/OpenSSL results to any
browser. Upgrade of a guard or verifier dependency triggers complete replay.

Batch, aggregate and multi-signature verification remain prohibited. No
accepted-language equivalence proof for a batch equation was attempted.

## 5. Mutation result

All required mutants executed and were killed by exactly their declared
detectors. They cover:

- unknown/zero/reserved suite acceptance and retry fallback;
- event or carrying-`GRANT` suite/key substitution;
- key/signature length and scalar checks;
- ZIP-215 default use and removal of both prime-order guards;
- event-reference substitution for the full transcript;
- context, credential, author-sequence and revocation bypass;
- transport/session substitution and AP exposure before verification;
- treating signature validity as AP authorization;
- acceptance without an authenticated binding;
- reuse of suite `0x0001` with changed semantics;
- `DECIDED` status without evidence and C0.3 dependency drift;
- an allow-list guard and per-vector special case; and
- replacement of the per-event verifier by a batch call.

The status/dependency source mutants alter an in-memory copy loaded from the
actual review-model source and are rejected by source-backed invariants. The
suite-reuse, allow-list, per-vector, retry and batch mutants execute distinct
mutated verification paths; no mutant is killed merely by comparing its own
identifier or by a fabricated result tuple.

Detector sets must be non-empty and exactly equal to the declared sets. Extra,
missing, skipped or unexecuted detection fails the gate.

## 6. Reopen and residual-risk disposition

None of the six numbered O-06b-1 section 8 predicates is met: transcript and
prehash stay unchanged; bounded arbitrary octets remain supported; the suite is
credential-derived; the SHA-256 reference basis is unchanged; no new material
production primitive is needed for the proven Noble adapter; and suite
`0x0001` has one enforceable canonical 32-octet key encoding.

C0.2j's tail/key predicate is not met. O-12 is not reopened because the selected
profile has no time-bearing validity. O-06's fallback/different-basis predicate
is not met.

The O-06c placeholder-substituted rerun remains outstanding. The six O-06c
modules executed here test the unchanged placeholder only. Condition
`O14-O06C-PLACEHOLDER-RERUN` requires a separate human-ratified task to integrate
the selected semantics into the complete O-06c construction and rerun all its
evidence before any C0.3 corpus authorization. Claiming this task discharged
that duty is prohibited.

Residual assumptions and non-claims include Ed25519/SHA-512 and SHA-256
security, correctness of pinned dependencies and runtimes, side-channel and
supply-chain behavior, absence of browser evidence, Dart nonconformance, and
the availability cost of rejecting an input another ecosystem accepts. These
conditions reopen O-14 evidence when their pinned basis changes.

Both measured JavaScript adapters share the same Noble subgroup guard;
`O14-SINGLE-GUARD-DEPENDENCY` forbids treating their agreement as independent
guard validation. Per-event subgroup validation of attacker-supplied `R` also
creates an availability cost; `O14-GUARD-COST-O08` assigns operational limits
and cost measurement to O-08 without permitting a weaker verification language.

## 7. C0.3 and decision effect

On exact-final success, O-14 may change from `OPEN` to condition-bearing
`DECIDED`. Its reason begins `CONDITION-BEARING:` and cites this analysis and
report. No blocker edge changes. C0.3 retains exact dependencies
`{C0.3_CORPUS_PATH_APPROVAL, O-06c, O-07, O-08, O-10, O-14}`, all five blocked
capabilities and status `NO_GO`. O-07, O-08, O-10 and corpus-path approval stay
open. `application_event.signature` remains unresolved because O-11 owns
carriage.

The pre-existing condition-bearing O-06c record is not retrofitted with the new
prefix; its condition remains represented by its reason and
`INV_O06C_BOUNDED_EVIDENCE`. No new invariant or residual-risk model record is
added because the frozen validator region deliberately forbids that larger pin
mutation.
