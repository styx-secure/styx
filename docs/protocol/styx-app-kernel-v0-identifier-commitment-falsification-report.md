# Styx O-06c identifier/commitment falsification report

- **Status:** `NO_COUNTEREXAMPLE_WITHIN_BOUNDS`.
- **Scope:** exact combined O-06b-1/O-06b-2/C0.2j/C0.2k construction selected
  before C0.3; bounded executable evidence, not a proof or implementation.
- **Authority:** evidence only. Normative meaning remains in the decision
  registry, transcript/commitment profiles, responsibility matrix and threat
  model.
- **Contract:** Issue #243, base
  `3f439189e0cbe4071f642c693dbb196b477a48ea`.
- **Candidate identity:** exact commit, tree object and canonical final-diff
  SHA-256 are immutable evidence on PR #244. They are intentionally absent from
  tracked generated reports so the report digests below are non-self-referential.

## 1. Verdict and bounded meaning

No counterexample was found within the declared O-06c registry. The frozen
six-section gate passed, the independent Python and JavaScript encoders agreed
on complete bytes and full-width SHA-256 values, all required directed witnesses
passed, all 16 declared source-mutant classes were killed by their exact detector
sets, all seven historical evidence entries reproduced, and exhaustive selected-
object mutation produced no third accepted disposition.

This result supports condition-bearing closure of O-06/O-06c only. It does not
prove SHA-256, protocol completeness, parser or product implementation
conformance, interoperability, anonymity, erasure, availability, finality,
audit readiness, production fitness or suitability for sensitive use. C0.3
remains `NO-GO`.

## 2. Canonical generated evidence

The six standard-library-only JSON reports are generated outside the repository
and are byte-identical across two successful runs at the exact final candidate:

| Report | Verdict | SHA-256 |
| --- | --- | --- |
| Scope | `PASS` | `__O06C_SCOPE_SHA256__` |
| Frozen sections | `PASS` (6/6) | `8614f80f1434353ef96a786a93c2736c7a1d09542c9a4f92af808ff2ad9e5c8a` |
| Combined machine probe | `NO_COUNTEREXAMPLE_WITHIN_BOUNDS` (25 witnesses) | `0ccc8cdfd9c28411fdc7dbb9d6356ba3b4bb8b87f2c48627437c2a909dd3158a` |
| Directed mutation | `ALL_REQUIRED_MUTANTS_KILLED` (16/16) | `bc4cb83510cba472fd1814976160a3199734b591aa9e7b21d34c6f098d03a9fe` |
| Cross-language | `PASS` (9 events) | `8ed61a94432c79efba5da818d6933d7794a6b0dc71f51aed5ae8362ec1f3e450` |
| Historical evidence | `PASS` (7/7) | `153a64cd660a29f2d90d16cb70e2bb8c45a32627a4f9c34145183d0775c16114` |

The scope and frozen reports record
`candidate_identity_location=immutable_pr_evidence`. Their digest was verified
stable across a commit that changed their implementation without changing the
canonical changed-path relation or frozen bytes. This prevents the tracked
digest registry from depending on the commit that contains that registry.

## 3. Coverage

The independent model covers all seven domain roles, event roles ordinary
`0x00`, logical removal `0x01` and credential control `0x02`, and all six
credential-control kinds: `GRANT`, `REVOKE`, `ROTATE`, `RECOVER`, `POLICY` and
`CLOSURE`. Positive non-genesis credential identifiers are derived from a fully
encoded `GRANT` event reference and are absent from their own preimage.
Changing the test-only genesis reference propagates through the grant reference,
credential identifier, leaf/commitment contexts and final commitments.

The exhaustive registry contains 32 complete objects and 7,074 selected octet
positions. Each octet is independently challenged with XOR `0x01`, `0x80` and
`0xff` (21,222 operations). The 254 selected scalar mutation entries cover
adjacent values and boundaries with checked arithmetic. Every accepted mutation
is either a typed rejection or a canonical semantic reassignment whose
independent re-encoding equals the mutated bytes and whose derived identifier
changes where applicable. There were zero invalid dispositions.

The closed source-mutant registry covers transcript domain/role, transcript
length, credential-control tail, 84-octet context, credential binding, author
sequence, leaf preimage, node preimage, complete commitment, parser geometry,
authority `Must0`, pending-authority retention, lineage-scoped fork effect,
frozen-section enforcement, historical-registry enforcement and C0.3 capability
retention. A mutant passes only when the mutated path executes and its observed
non-empty detector set equals the declared set exactly.

## 4. Work and availability observations

The combined probe reports deterministic counters for parsing, inverse,
serialization, transcript regeneration, reference/leaf/node/commitment hashing,
graph construction, opening verification and replay. Its aggregate stage counts
include 58 parses, 7 inverse operations, 2 serializations, 2 transcript
regenerations, 10 leaf hashes, 6 interior-node hashes, 4 commitment hashes,
4 graph constructions, one opening verification and 2 replay operations.

The sequence-change rehash witness recomputes one leaf plus one commitment for
`SINGLE` (348 hashed octets) and four leaves, three interior nodes and one
commitment for `TREE` (1,102 hashed octets). These are exploration observations,
not production maxima or availability guarantees.

## 5. Placeholders, assumptions and rerun triggers

| Owner | Test-only placeholder/non-claim | Mandatory rerun or reopen trigger |
| --- | --- | --- |
| O-07 | fixed opaque genesis reference; grant-rooted credentials only | selected genesis/checkpoint contents, genesis-authored credential rule or checkpoint substitution contract |
| O-08 | chunk sizes `{1,2,3,4,7,8,15,16,31,32,63,64}`; `65` rejected only as exploration-envelope mismatch | selected production bounds, cardinalities or resource envelope |
| O-10 | internal witness/detector labels are not public outcome codes | selected stable public outcomes or combination rules |
| O-11 | complete-object verification only; no inclusion-proof context | selected inclusion-proof, wire, storage or fetch encoding |
| O-14 | opaque suite/key bytes; no production signature verification | selected signature registry, key/signature encoding or downgrade rule |
| AP/C0.3 | arbitrary opaque AP-transition bytes exercise only the frozen outer `opaque_u32` boundary | selected canonical AP-transition schema or semantic injectivity rule |

SHA-256 collision and second-preimage resistance remain assumptions. A supplied
distinct-preimage/equal-digest condition is rejected rather than treated as a
successful collision test. Knowledgeable recomputation, same-slot sibling
evidence, randomizer misuse, indefinite withholding, grinding, bounded-state
exhaustion and lineage-local forks remain residual availability or operational
risks. No signature, commitment, event reference, replay position or historical
durability proves truth, originality, authority, possession at commit time,
priority, finality or permission for irreversible effects.

## 6. Reproduction

Use the exact `Required verification` block in Issue #243 from a clean worktree
at the final PR HEAD with Python `3.14.4`, Node `v24.18.0`, locale `C`, timezone
`UTC`, `SOURCE_DATE_EPOCH=0`, `PYTHONHASHSEED=0` and
`O06C_MODEL_SEED=o06c-v1-deterministic-test-seed`. Run the complete block twice
from distinct fresh worktrees. Generated JSON, vectors and workspaces remain
outside the repository.

Any report mismatch, counterexample, newly selected placeholder input, changed
frozen byte, changed hash/runtime basis, missing historical entry or weakened
C0.3 capability edge reopens O-06/O-06c and blocks C0.3 until the affected
evidence is rerun and independently ratified.
