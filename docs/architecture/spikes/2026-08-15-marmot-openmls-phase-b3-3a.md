# Phase B3.3a: exact-profile durable application traffic

Date: 2026-08-15

Issue: #185

Stage: **Stage 1 source candidate; human tuple approval pending**

Disposition: **candidate implementation reaches bounded development GO; no
installed-artifact or Stage 2 conclusion yet**

## Question and scope

B3.3a asks whether the exact B3.2a Styx member and the pinned MDK founder can
exchange synthetic MLS application events in both directions while preserving
write-ahead ratchet durability across a real process restart. It deliberately
excludes every Commit and epoch-transition operation reserved for B3.3b.

The candidate is isolated from product code. It does not change the PWA,
vault, transport, Nostr, push, media, dependencies, ciphersuite, frozen member
profiles or historical persisted formats.

## Frozen inputs

| Boundary | Exact value |
| --- | --- |
| Styx base commit | `1404d05ed2604195e3b697caeccad9133a6cdc34` |
| Styx base tree | `7d0ee0078385f3f7a85e1f8f23e11adc347cddf8` |
| OpenMLS source commit / tree | `09e92777dba0528d3d29e2e5e681b7e91637c7be` / `fde242458abe5594fbebf2556dca0a135367a817` |
| Marmot commit / tree | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` / `10d941f358de5d9fe4ee1db75581f3e5363f5e92` |
| MDK commit / tree | `9396adb6aa6b95b521a7979facd5ea7040c07288` / `a1145de604e616634dae9a1ef6bf5033c9c9e879` |
| Vendored Cargo lock SHA-256 | `33964e33f6a48e8b9982c5894c4a7e9ddc5ee2e5157c763596393a08c607672b` |
| External MDK Cargo lock SHA-256 | `edb8c706e12934b8d94239203f73d24a2d480033c3ec6830f19d06c85a247b09` |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`) |

## Candidate architecture

The Rust boundary consumes the loaded group and private Provider at operation
start. It validates the exact ciphersuite, active state, two-member roster,
GroupContext, member profile and local identity binding before and after each
operation. Only private application messages at the current group id and epoch
can reach plaintext extraction. Authenticated sender identity and signature key
are projected from the processed message and exact roster.

The JavaScript adapter treats the resulting bytes as uncommitted until its
authoritative journal CAS succeeds. The outbound CAS covers the post-send state
and ciphertext record; the inbound CAS additionally covers plaintext and
authenticated sender evidence. Both paths read the committed bytes back before
returning a copy to the orchestrator. All local scratch copies are cleared on
success and failure.

The file journal uses immutable content-addressed blobs, an exclusive
fail-closed lock, atomic head replacement and directory synchronization. A
stale lock is never broken automatically. This is isolated evidence, not a
claim of product-grade crash recovery or physical erasure.

## Current Stage 1 evidence

- Native wrapper tests cover durable bidirectional traffic and restart,
  malformed input, wrong group and epoch, replay, own echo, public proposal and
  Commit rejection, wrong identity locators, profile hybrids/supersets, a third
  member, canonical serialization stability and one-use releases.
- JavaScript tests cover one-time activation, write-ahead ordering, memory and
  file restart, duplicate request/ciphertext, inbound/outbound persistence
  failure, CAS races, non-release, inner-event sender/id validation and strict
  cross-format readers.
- The pinned MDK adapter uses only its public send, ingest, durable-store and
  event-drain APIs. A mutation-boundary failure quarantines the process.
- One development execution completed 24 hash-linked operations, committed two
  events in each direction, restarted both peers in fresh processes, rejected
  both first-message replays without a second plaintext/event, continued in
  both directions and deleted private state.

The final source commit/tree, patch digest and reproducible five-file candidate
tuple will be recorded only after Stage 1 implementation and independent review
are complete. Earlier development tuples are intentionally not approved or
installed.

## Remaining gates

1. Complete final hostile and full-regression verification.
2. Produce two clean byte-identical builds from the final Stage 1 source.
3. Obtain independent exact-candidate reviews from Fable 5 and DeepSeek V4
   Flash and resolve every finding.
4. Obtain owner approval binding the exact source commit/tree, patch digest,
   Cargo lock digest and five-file tuple.
5. Install only that tuple in Stage 2, rerun every required check and execute
   two fresh, disjoint exact interop runs.

## Residual risks and non-claims

- The Styx-authored Rust/JavaScript boundary remains unaudited.
- `extensions-draft` remains a pinned experimental upstream surface.
- Application traffic does not establish Commit lifecycle or convergence.
- Direct synthetic transport establishes no Nostr, anonymity or metadata
  privacy property.
- File-backed evidence is not the browser vault or a production persistence
  profile.
- No real user data, security certification, general Marmot compatibility,
  legal-evidence or production-suitability claim is made.
