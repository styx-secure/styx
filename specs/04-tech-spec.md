---
spec_version: "2.0"
spec_type: "tech-spec"
project: "Styx"
last_updated: "2026-07-18T00:00:00Z"
status: "draft"
---

# Styx — Technical Specification (synthesis)

## Sintesi (IT)

Sintesi dell'architettura esistente: due stack paralleli con lo stesso taglio
a cinque livelli (crypto → storage → ledger → transport → facade), crypto WASM
vendored e pinnata come confine di sicurezza, trasporto su relay Nostr, bridge
push separato. Il dettaglio normativo vive nei documenti canonici linkati;
in caso di divergenza vincono quelli.

## Architecture — two stacks, one layering

| Layer | `styx-js/` (active product) | `packages/` (Dart reference) |
|---|---|---|
| crypto | vendored `openmls-wasm`, `styx-kdf-wasm` | `crypto_core` |
| storage | IndexedDB vault, MLS state envelope | `storage` |
| ledger | signed-event ledger | `ledger_engine` |
| transport | Nostr relays (WebRTC experimental) | `transport` |
| facade | `StyxChat` / library API | `styx` |

The two stacks implement the same conceptual split and are **not
cryptographically interoperable** (`CLAUDE.md`); the Dart stack is the
reference implementation (ADR-0003). Feature parity is tracked with
Dart-generated interop vectors on the non-crypto surfaces.

## Security boundaries

1. **Vendored WASM artifacts are the crypto boundary.**
   - `vendor/openmls-wasm` — pinned commit descending from `openmls-v0.8.1`
     (ahead of the tag; includes the S3-7 MAC-truncation fix and persisted
     storage-format changes). **Do not downgrade to the release tag**; see
     `vendor/openmls-wasm/PROVENANCE.md`.
   - `vendor/styx-kdf-wasm` — deliberately a separate artifact, because the
     MLS state envelope pins the digest of `openmls-wasm` and the KDF must
     evolve independently.
   - CI: `WASM integrity gate` (artifact checks, reproducible rebuild, KATs).
2. **Persisted formats are fail-closed.** The MLS state envelope
   (`docs/superpowers/specs/2026-07-12-mls-state-envelope.md`) versions all
   persisted state; unknown formats produce structured errors, never silent
   loss. Format changes are a mandatory human gate (`AGENTS.md`).
3. **Trust model, stated honestly.** Relays transport opaque ciphertext but
   observe transport metadata; the push bridge is a stateless, documented
   exception. The system is not a zero-metadata or "serverless" design and
   documentation must not claim otherwise (CI-enforced).

## Services

- **PWA chat** — `styx-js/apps/chat`: React PWA, strict CSP
  (`wasm-unsafe-eval` required by OpenMLS; documented `style-src` exception),
  production builds hard-fail without the real crypto module.
- **Push bridge** — `push_bridge/` (Node) and `push_bridge_server/` (Go,
  APNs/FCM): delivery only, no message plaintext.

## CI reality (unchanged by this spec)

Required gates on `main`: `Dart reference stack gate`, `styx-js web gate`,
`WASM integrity gate`, `Analyze (javascript-typescript)` (CodeQL). Advisory:
`Agent scope evidence`, `Doc claims lint`. Path detectors may green-skip
irrelevant heavy jobs; detector failure is never a green skip.

## Key decisions (normative elsewhere)

| Decision | Where |
|---|---|
| Canonical product stack | `docs/architecture/decisions/ADR-0001` |
| Monorepo strategy | ADR-0002 |
| Dart stack = reference implementation | ADR-0003 |
| Licensing (AGPL model) | ADR-0004 + `LICENSING.md` |
| Mobile client strategy | ADR-0005 |
| MLS design, envelope, vault, push | `docs/superpowers/specs/**` |
| Workflow governance (MUCC adoption) | `docs/governance/adr/ADR-0006` |

## Constraints for implementers

- No root `package.json`/lockfile: JS workspace lives under `styx-js/`,
  Dart uses melos; `packages/themis_survey` is Flutter and CI-excluded
  (needs the Flutter SDK).
- Crypto code, test vectors, vendored WASM and persisted formats are
  human-gate areas: agent tasks must not touch them without an explicitly
  approved Issue.
- Design docs are primarily Italian; `specs/` is English-first with an
  Italian synthesis per file (maintainer decision, 2026-07-18).
