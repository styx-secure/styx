# C0.2k commitment-context falsification report

- **Status:** bounded evidence passed; exact-final review and human ratification
  remain mandatory.
- **Date:** 2026-08-24.
- **Issue:** #239.
- **Base:** `745de6d8954a39ad3a39e9ccc5303ba08fa8508c`.
- **Scope:** the C0.2k credential/sequence amendment to the O-06b-2
  commitment context only.
- **Language:** English is canonical for language-neutral review.

## 1. Question and bounded verdict

C0.2j selected a grant-rooted 32-octet credential identifier and unsigned
big-endian `u64` author sequence, but the selected O-06b-2 commitment context
did not bind either field. C0.2k asks whether one exact amendment can prevent an
unchanged commitment/opening from being copied across those contexts without
changing the frozen interior-node format or making broader security claims.

The selected construction is:

```text
CTX = commitment_suite_id:u16
   || styx_protocol_version:u16
   || application_profile_id:u32
   || application_profile_version:u32
   || context_identifier:opaque32
   || credential_identifier:opaque32
   || author_sequence:u64
```

All integers are unsigned big-endian. `CTX` is exactly 84 octets. It is included
unchanged in both `B_L` and `B_C`; `B_N` remains unchanged. The isolated required
suite passed 43 assertions in 13 hostile-witness families. The mutation harness
killed all 18 required semantic/framing mutants with at least one declared
detector and no survivor.

The bounded verdict is `BOUNDED_FALSIFICATION_PASSED`. This is not an O-06c
verdict and does not close O-06 or authorize C0.3.

## 2. Candidate analysis

| Candidate | Disposition | Reason |
| --- | --- | --- |
| Retain the 44-octet baseline | Rejected | Does not bind credential identifier or author sequence. |
| Append raw authenticated credential and sequence fields | **Selected** | Binds the exact C0.2j fields directly with one fixed inverse and no derived identifier. |
| Credential only | Rejected | Same-credential cross-sequence copy remains possible. |
| Sequence only | Rejected | Cross-credential copy at equal sequence remains possible. |
| Hash-compressed binding | Rejected | Adds an unnecessary derived identifier and assumption surface. |
| Bind only `B_C` | Rejected | Leaf preimages remain context-copyable. |
| Bind only `B_L` | Rejected | The outer commitment body omits the selected author context. |
| Bind only one commitment shape | Rejected | The other shape retains the defect. |
| Bind containing event reference | Rejected | The event reference authenticates the descriptor, creating a derivation cycle. |
| Bump protocol/suite/domain identifiers now | Rejected for this pre-corpus amendment | There is no released corpus, supported consumer or persisted population; the former grammar is never accepted. |

The v1 identifier retention is therefore a one-time pre-corpus supersession, not
a compatibility precedent. Only the 84-octet grammar is active. The 44-octet
grammar, mixed profiles, alternate parsers and fallback are invalid. Any later
incompatible post-corpus change requires new protocol/profile, suite and domain
registry identifiers.

### 2.1 Cross-candidate security and operational consequences

The short dispositions above are backed by the following explicit comparison.
`old_CTX` denotes the exact 44-octet baseline. The hash-compressed row evaluates
the strongest representative of that family,
`old_CTX || SHA256(D_BIND || credential_identifier || author_sequence)`, where
the inputs retain their 32- and 8-octet canonical encodings; selecting it would
also require allocating and reviewing `D_BIND`.

| Family | Exact bytes and inverse | Downgrade, copy and same-slot behavior | Streaming, arithmetic and allocation | Identifier/migration consequence, dependencies and residuals |
| --- | --- | --- | --- | --- |
| 44-octet baseline | `old_CTX`; existing fixed-offset inverse | Accepts unchanged copy across credentials and sequences; same-slot behavior is not distinguished | Existing 92-octet leaf prefix and 121/137-octet commitment bodies | No migration, but fails the C0.2k security objective; rejected. |
| Selected raw-field extension | `old_CTX || credential_identifier:opaque32 || author_sequence:u64`; exactly 84 octets with fixed offsets and exact end | Rejects unchanged cross-credential and cross-sequence copy in both `B_L` and `B_C`; same credential/sequence siblings remain fork evidence | Adds 40 octets to every leaf and final commitment body; 132-octet leaf prefix and 4,294,967,163-octet representational leaf ceiling; no payload-sized allocation is needed to validate a declared length | One-time pre-corpus supersession under protocol/suite v1; no legacy decoder or migration population. O-07/O-08/O-11/O-14 remain open. Lowest complete complexity; does not stop knowledgeable recomputation or prove authority/truth. |
| Credential only | `old_CTX || credential_identifier:opaque32`; 76 octets with fixed inverse | Rejects cross-credential copy but accepts cross-sequence copy; same-slot ambiguity remains | Adds 32 octets per leaf/commitment; 124-octet leaf prefix and 4,294,967,171-octet representational ceiling | Would still require a pre-corpus supersession while leaving the stated defect open; rejected. |
| Sequence only | `old_CTX || author_sequence:u64`; 52 octets with fixed inverse | Rejects cross-sequence copy but accepts equal-sequence cross-credential copy | Adds 8 octets per leaf/commitment; 100-octet leaf prefix and 4,294,967,195-octet representational ceiling | Would still require a pre-corpus supersession while leaving the stated defect open; rejected. |
| Hash-compressed binding | `old_CTX || SHA256(D_BIND || credential_identifier || author_sequence)`; 76 octets, but inversion yields only a digest and verification requires the original fields | Can detect both unchanged-copy families if recomputed from authenticated fields; same-slot behavior remains fork evidence | Adds one digest invocation and 32 stored octets per leaf/commitment, plus a new domain and implementation path | Adds a primitive/domain dependency and loses direct inverse without reducing any required authenticated input; O-14 review surface grows. No migration benefit; rejected. |
| Bind only `B_C` | `B_C` uses the 84-octet selected context while `B_L` retains 44 octets | Final commitment changes across contexts, but leaf preimages remain copyable and the roles have incompatible context semantics | Mixed 132/92-octet leaf-prefix assumptions become possible between producers and verifiers | Creates an ambiguous partial profile rather than a migration; violates role completeness and complicates O-11; rejected. |
| Bind only `B_L` | `B_L` uses 84 octets while `B_C` retains 44 octets | Leaves change, but the final commitment body itself omits the selected author context | Mixed body widths and two context rules complicate streaming and inverse validation | Creates an ambiguous partial profile and weaker outer evidence; rejected. |
| Bind only one shape | The selected 84-octet context is used for only `SINGLE` or only `TREE`; the other shape retains 44 octets | One commitment shape still accepts both substitution families | Shape-dependent widths introduce a downgrade surface selected by authenticated geometry | Splits one suite into incompatible semantic profiles without a version boundary; rejected. |
| Containing event reference | `old_CTX || event_reference:opaque32`; nominally 76 octets | Would distinguish event transcripts and same-slot siblings if it could be produced | Cannot stream or hash the commitment before the reference exists | The reference already authenticates the descriptor containing the commitment, so construction is circular and has no valid inverse/production order; rejected before migration analysis. |
| New protocol/suite/domain identifiers with selected bytes | Same 84-octet context and inverse, with newly allocated identifiers/domains | Same substitution and same-slot properties as the selected construction; strongest explicit downgrade boundary | Same widths and work as selected, plus parallel registry and vector work | Technically sound but unnecessary before any released corpus, consumer or persisted population. Mandatory for a later incompatible post-corpus change; rejected for this one-time amendment only. |

All families leave genesis/checkpoint semantics to O-07, supported resource
limits to O-08, partial/inclusion-proof formats to O-11 and signature suites to
O-14. None provides originality, exclusive possession, application authority,
truth or finality.

## 3. Exact arithmetic and inverse

| Quantity | Selected value |
| --- | ---: |
| `CTX` | 84 octets |
| fixed `B_L` prefix | 132 octets |
| complete leaf-preimage overhead | 152 octets |
| maximum len32-safe leaf/chunk | 4,294,967,163 octets |
| `B_C`, single | 161 octets |
| `B_C`, tree | 177 octets |
| complete commitment preimage, single | 181 octets |
| complete commitment preimage, tree | 197 octets |
| `B_N` | 74 octets, unchanged |
| complete node preimage | 94 octets, unchanged |

The context inverse accepts exactly 84 octets, reads the fields at fixed offsets,
validates the derived suite and protocol version, and requires exact end. The
leaf inverse reads the 132-octet fixed prefix and then exactly `leaf_length`
terminal octets. The commitment inverse reads the 84-octet context, common fixed
fields, a shape-selected zero- or 16-octet geometry arm, root, randomizer and
exact end. Sequence zero and `2^64 - 1` are structurally representable;
`2^64` is rejected without wrapping.

## 4. Evidence implementation and determinism

The standard-library-only evidence lives in:

- `tools/causal-flow-simulator/c02k/commitment_context_model.py`;
- `tools/causal-flow-simulator/c02k/scenarios_c02k.py`;
- `tools/causal-flow-simulator/c02k/commitment_context_probe.py`;
- `tools/causal-flow-simulator/c02k/mutation_harness_c02k.py`;
- `tools/causal-flow-simulator/c02k/tests/`.

Two byte-identical probe runs produced SHA-256:

```text
fc170b5e1bd1b5b4b5dc4f561b12371e46f6863863422f07e88615e01b92f1dd
```

Two byte-identical mutation runs produced SHA-256:

```text
2bd8fd4bff6f73d79766e2b82d99315bfffc59540e7a7db7406a7fd6a8ce29c0
```

These are candidate-worktree report digests. The final PR records and rechecks
them on the exact final HEAD; a later model change invalidates these values until
reproduced.

Work counters have exact units:

- `digest_invocations`: one SHA-256 call;
- `bytes_hashed`: octets supplied to SHA-256;
- `leaf_visits`: one constructed leaf preimage;
- `node_visits`: one constructed interior-node preimage.

The deterministic six-leaf sample measured 12 digest invocations, 1,618 bytes
hashed, six leaf visits and five node visits. These measured values describe the
bounded sample, not an O-08 production maximum.

## 5. Required witness families

The required suite exercises all of the following families:

1. exact context bytes and inverse;
2. credential and sequence binding;
3. legacy/downgrade rejection;
4. leaf/commitment and single/tree role completeness;
5. exact dependent widths and len32 ceilings;
6. single and tree round trips, including empty single and a short final chunk;
7. same-slot fork classification;
8. malicious recomputation boundary;
9. sequence and credential boundary values;
10. geometry and measured-work bounds;
11. unchanged interior-node format;
12. content-free control/removal non-expansion; and
13. fail-closed suite selection.

The suite observed every required family through 43 directed assertions and
reported no failed assertion. The exact-context family independently mutates
every one of the 84 context octets, rejects every strict prefix and exercises
semantically distinct adjacent-field reorderings. The boundary families also
cover unknown protocol and suite identifiers, negative and maximum sequences,
mixed legacy/current bodies, exact interior-node inverse, minimum two-leaf
trees, and the len32 ceiling without allocating attacker-declared payloads.

## 6. Mutation evidence

| Mutant | Required property that killed it |
| --- | --- |
| `M01_OMIT_CREDENTIAL` | canonical context plus credential binding in both roles/shapes |
| `M02_OMIT_SEQUENCE` | canonical context plus full-sequence binding in both roles |
| `M03_REORDER_FIELDS` | exact canonical context vector |
| `M04_LITTLE_ENDIAN_SEQUENCE` | exact big-endian context vector |
| `M05_TRUNCATE_SEQUENCE_U32` | high-limb sequence distinction |
| `M06_ACCEPT_SEQUENCE_WRAP` | rejection above `2^64 - 1` |
| `M07_ACCEPT_LEGACY_CONTEXT` | exact rejection of 44-octet input |
| `M08_BIND_ONLY_COMMITMENT` | leaf credential binding for both shapes |
| `M09_BIND_ONLY_LEAF` | outer commitment credential binding for both shapes |
| `M10_BIND_ONLY_SINGLE` | tree-shape role completeness |
| `M11_BIND_ONLY_TREE` | single-shape role completeness |
| `M12_RETAIN_OLD_WIDTHS` | exact derived-width table |
| `M13_ACCEPT_TRAILING_BYTES` | exact-end framing rejection |
| `M14_EQUAL_COMMITMENT_IS_DUPLICATE` | distinct same-slot event references remain fork evidence |
| `M15_CHANGE_NODE_FORMAT` | unchanged 74/94-octet interior-node format |
| `M16_INFER_AUTHORSHIP_ORIGINALITY` | verification returns only the context-binding claim |
| `M17_SELECT_UNTRUSTED_SUITE` | carried unknown suite fails closed |
| `M18_CONTROL_NONE_HAS_COMMITMENT` | `NONE` control/removal events gain no content commitment |

All 18 mutants were killed. The harness requires a failing assertion declared
for that mutant; unrelated failures do not count as a kill.

## 7. Counterexamples retained as boundaries

The model deliberately preserves these counterexamples to stronger claims:

- A party holding content and opening can recompute a fresh valid commitment
  under a different credential or sequence. C0.2k prevents unchanged-copy reuse,
  not knowledgeable recomputation.
- Two distinct event references at the same credential and author sequence are
  same-author fork evidence even when their commitment values happen to match.
  The commitment does not select a winner or collapse them as a duplicate.
- Successful commitment verification proves only correspondence among the
  authenticated context, content, opening and commitment. It proves no truth,
  originality, exclusive possession, application authorization or finality.
- Interior nodes remain context-free. Their safety claim is limited to complete
  whole-object recomputation; O-11 must revisit them before inclusion proofs.
- Representable integer ceilings are not supported resource limits. O-08 still
  owns production maxima and denial-of-service envelopes.

## 8. Assumptions and residual risks

This evidence inherits the O-06b-2 SHA-256 collision, second-preimage and hiding
assumptions and the producer/runtime randomizer obligations. It does not test the
cryptographic primitive, a runtime CSPRNG, signatures, persistent storage,
transport, rollback, availability, metadata privacy, deletion or implementation
side channels.

The context still excludes the O-07 genesis reference. O-07 must define genesis
and checkpoint evidence before C0.3. O-08 still owns supported bounds, O-10
stable errors, O-14 signature suites, O-13 irreversible effects and O-16
finality. Endpoint compromise, valid-key abuse, unavailable openings,
randomizer misuse, rollback and denial of service remain residual risks.

## 9. Disposition and next gate

C0.2k may be ratified only on an exact final HEAD with deterministic reruns,
unchanged historical v1/v2/v3 evidence, synchronized normative/derived
documents, independent exact-final review, green CI and both required human
gates. A passing C0.2k does not close O-06. The next ordered protocol task is
O-06c independent falsification over the combined C0.2j/C0.2k construction.
C0.3, demos, product work and sensitive use remain blocked.
