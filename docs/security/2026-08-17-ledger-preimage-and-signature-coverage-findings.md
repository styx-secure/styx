<!-- claims-lint: allow -->
# Experimental ledger preimage and authenticated-semantics findings

- **Date:** 2026-08-17.
- **Status:** confirmed; remediation deferred to the specification-led
  implementation increment.
- **Affected surface:** experimental Dart and JavaScript application ledgers.
- **Product exposure at the reviewed base:** no supported end-to-end product
  pipeline, per ADR-0007 §2.
- **Disclosure:** bounded class-level record. Exact witness inputs and
  reconstruction steps are retained outside the public repository.
- **Compatibility:** this note is not conformance-ready and creates no stable
  compatibility commitment.

## Summary

Independent analysis and reproduction confirmed three related integrity
defects in the current experimental application-ledger formats:

1. event fields are concatenated without authenticated boundaries, allowing
   different semantic segmentations to share the same current hash input;
2. the current signed transcript omits fields later used for causal ordering,
   fork handling or identity interpretation; and
3. current fixed-width vector serialization accepts values that wrap, which can
   reverse an observed causal relationship after serialization.

These are findings in legacy experimental code. They are not evidence that MLS,
OpenMLS, the vault, Nostr or the secure-session profile is broken. They also do
not establish that an external attacker can reach the ledger through a
supported product path at the reviewed base.

## Affected paths and evidence

| Surface | Repository evidence | Impact class |
| --- | --- | --- |
| JavaScript event construction | `styx-js/src/ledger/event-factory.js:47-68,109-127` | Boundaryless hash input and incomplete signed semantics. |
| JavaScript validation | `styx-js/src/ledger/chain-validator.js:54-126` | Reconstructs the same incomplete transcript; empty input is also accepted at lines 21-28. |
| JavaScript event model | `styx-js/src/ledger/event.js:19-58` | Carries identifiers, causal state, sender and other fields not all present in the transcript. |
| JavaScript merge ordering | `styx-js/src/ledger/fork-merge.js:110-123` | Reads vector total and sender text for ordering. |
| JavaScript vector serialization | `styx-js/src/ledger/vector-clock.js:18-26,39-46,96-102` | Unbounded numbers are coerced into a fixed 32-bit representation. |
| Dart event construction | `packages/ledger_engine/lib/src/event_factory.dart:23-73,112-141` | Same boundaryless field sequence and incomplete signed semantics. |
| Dart vector serialization | `packages/ledger_engine/lib/src/vector_clock.dart:20-38,61-80` | Signed 32-bit projection can wrap out-of-range values. |
| Dart HLC byte projection | `packages/ledger_engine/lib/src/hlc.dart:82-120` | Implementation-native text/code-unit projection is not a language-neutral cryptographic encoding. |

C0.1 provides public, non-exploit-specific evidence in `HASH-004`, `HASH-005`,
`HLC-002` through `HLC-005`, `HLC-007`, `HLC-008`, `VC-002` through `VC-004`,
`ORDER-002`, `ORDER-004`, `ORDER-005` and `CHAIN-001`. The independent witness
material extends those observations to a complete event and signature, but is
not committed here.

## Confirmed impact

- **Semantic ambiguity:** a signature over the current byte sequence does not
  necessarily select one unique interpretation of the unframed fields.
- **Authenticated-state gap:** changing a causal/order field that is absent from
  the current transcript need not invalidate the existing signature, even
  though downstream logic may consume that field.
- **Causal corruption:** a value that wraps during serialization can return as a
  smaller value and alter before/after/concurrent interpretation.
- **Fail-open composition risk:** if a future adapter persisted or admitted
  these objects as supported protocol state, the defects could cross from
  experimental code into authorization and convergence decisions.

This note does not claim remote exploitability through the present product, key
recovery, plaintext disclosure, signature-key extraction or compromise of the
secure-session cryptography.

## Severity and priority

The technical integrity impact is **high for any system that treats these
objects as adversarially supplied authoritative state**. Current product
exposure is **contained by non-integration**, not by a runtime fix. Remediation
therefore remains mandatory before supported persistence or remote admission.

Sanitization is a coordination measure, not containment. Public C0.1 material
already reveals much of the defect class; withholding the compact witness only
delays easy reconstruction and must not lower remediation priority.

## Disposition

1. The current behavior is labelled `styx-legacy-c0` and is never v1 protocol
   authority.
2. A supported Phase B adapter must not persist or accept current ledger objects
   until the normative kernel corpus is green.
3. C0.2 defines the replacement invariants; C0.3 will derive adversarial vectors
   only after all byte-affecting decisions are closed; C0.4 will align the active
   JavaScript implementation.
4. Strict current HLC and previous-hash validation is not treated as complete
   remediation because it does not authenticate causal/order fields.
5. Discovery of a supported consumer or installed data population before the
   replacement lands requires immediate reassessment of disclosure, migration
   and temporary hardening.

## Retained evidence

Custodian: `maverde73`. Algorithm: SHA-256. The following immutable reports are
retained in the maintainer-controlled private local review-run archive:

| Retained filename | SHA-256 |
| --- | --- |
| `README_OPUS5_20260817T063953Z.md` | `beff559ed88bda3d1cbbbdfdb3686f84003b6d9d8640c25e505d5fc36e831003` |
| `README_QWEN38_20260817T064405Z.md` | `320234c8afe9ea22b54c24164ab1a8e8e77b3c3af6d4e2ff4f544fe0b3286606` |
| `README_OPUS5_RECONCILE_20260817T070100Z.md` | `51f027211f231803ddb93f40dabe898673c7ddba2bea8498d774e1deb9d81ec0` |
| `README_QWEN38_RECONCILE_20260817T070100Z.md` | `4594818fb528e797c74e9eca4e1ffa0ea62988be9c5a539a77f0a3c1d9d6844d` |
| `README_OPUS5_CONTRACT_FINAL_20260817.md` | `726869249ff5fb9fc46a2f332e35441641f0cc41bf5dad0423fa2d5c563bdbce` |
| `README_QWEN38_CONTRACT_FINAL_20260817.md` | `39b967840d212a09932f884e6bcdcfaeb694a5c51ca36f7eb135c5fc00c1e9b5` |

The two `CONTRACT_FINAL` reports are retained contract-review custody records.
They are not `PRIV` evidence used to justify an individual registry decision;
the four decision-bearing reports are mapped explicitly as `PRIV-01` through
`PRIV-04` in the registry.

The exact witness may be disclosed after remediation or under a separately
approved disclosure decision. A digest proves correspondence only while the
custodian preserves the referenced artifact; it is not a substitute for public
reproducibility.

## Residual risk

- The affected code remains unchanged in this increment.
- Non-integration is a governance and architecture boundary, not an execution
  guard inside every legacy API.
- Other semantic ambiguities may exist outside the finite C0.1 corpus.
- The future protocol still requires an independently derived specification,
  adversarial corpus, third implementation, formal/fuzz testing and security
  review before sensitive use.
