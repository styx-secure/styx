# C0 application-protocol characterization

Date: 2026-08-17  
Status: completed characterization; non-normative  
Base: `f0f7c35fa030477f56ea3b29efa1381f0d2dc972`

## Decision question

Before drafting a language-neutral application protocol, C0.1 asks what the
current Dart reference ledger and JavaScript browser ledger actually do when
given the same synthetic inputs. It does not ask which implementation is
correct. Neither runtime is an oracle.

The evidence is in
`conformance/application-protocol/c0-characterization/`. Its corpus and
hypotheses were committed before the first runtime observations. Both adapters
import production APIs without modifying or reproducing their algorithms.

## Result

The 29-case corpus produced:

| Classification | Cases | Meaning |
| --- | ---: | --- |
| `MATCH` | 21 | Equal current observations; not automatically normative semantics. |
| `DIVERGENCE` | 6 | Both runtimes express the case but produce different semantic values. |
| `UNSUPPORTED` | 2 | At least one runtime cannot express the case without production changes. |

Two preregistered hypotheses, `VC-003` and `VC-004`, were disproved. Dart
3.10.8 `ByteData.setInt32` and the current JavaScript encoding both wrap the
tested out-of-range values to the same 32-bit bytes. The expectation changes
were recorded separately after the original hypotheses, rather than rewriting
the initial evidence.

## Divergences that C0.2 must resolve

| Area | Cases | Current difference | Protocol question |
| --- | --- | --- | --- |
| HLC precision | `HLC-002` | Dart preserves microseconds; JavaScript truncates to milliseconds. | Select an exact timestamp precision and rejection rule. |
| HLC bytes | `HLC-003` | Dart projects string code units; JavaScript emits UTF-8. | Define a language-neutral byte encoding and allowed node identifiers. |
| HLC parsing | `HLC-004`, `HLC-005` | Malformed counters and dashed node IDs are parsed or rejected differently. | Define a grammar and fail-closed validation behavior. |
| Genesis projection | `EVENT-002` | Payload and initial vector clock differ. | Define whether genesis is protocol data and, if so, its exact preimage. |
| Sender ordering | `ORDER-002` | Dart code-unit ordering differs from JavaScript locale collation. | Define a locale-independent byte ordering. |

The two unsupported cases expose separate design limits:

- `VC-007`: both public vector-clock APIs are fixed to two participants;
- `EVENT-003`: neither public genesis factory accepts an injected clock, so a
  deterministic genesis hash cannot be characterized without production work.

## Matches that are not yet promises

The JavaScript ledger descends from the Dart implementation and was previously
checked against Dart-generated vectors. A match demonstrates port fidelity,
not independent corroboration. In particular:

- `HASH-004` confirms that both composite hashes erase segment boundaries;
- `ORDER-004` observes equal-comparator ordering without a shared stability
  guarantee;
- `CHAIN-001` observes that both validators accept an empty chain.

These cases are explicitly marked as unspecified behavior. C0.2 must not turn
them into normative requirements accidentally.

## Evidence boundary

The report is deterministic and each runtime test validates and byte-checks its
own envelope. The local comparator validates both envelopes, their corpus
digest, case identity and preregistered classifications. The cross-runtime
comparator is not yet a required CI job; that is a residual verification risk,
not a green CI claim.

Event-object JSON projection is deliberately excluded because Dart exposes no
equivalent public contract. Browser convenience serialization must not become
a persisted or wire format by accident.

## Consequence for C0.2

C0.2 can now specify a small semantic kernel from measured evidence instead of
choosing one implementation wholesale. It should resolve the six divergences,
decide whether the three unspecified matches are retained or rejected, and
state whether the two-party vector clock is a protocol constraint or only a
current profile constraint. Implementations can then be tested against the
specification and its corpus rather than against each other.

This characterization does not establish interoperability, security,
anonymity, compliance, audit coverage, production readiness or suitability for
sensitive data.
