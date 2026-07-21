---
spec_version: "2.0"
spec_type: "vision"
project: "Styx"
last_updated: "2026-07-18T00:00:00Z"
status: "draft"
---

# Styx — Vision

## Sintesi (IT)

Styx è una piattaforma di comunicazione sovrana e cifrata end-to-end: chat
E2EE su MLS distribuita come PWA, con identità auto-custodita e senza account
centralizzati. I relay trasportano solo blob opachi ma **osservano i metadati
di trasporto**: il prodotto non promette proprietà "zero-knowledge" né
"serverless" — promette minimizzazione onesta della fiducia nei server. Il
prodotto resta **sperimentale** finché i blocker di sicurezza H1/H2 sono
aperti. Due stack convivono: `styx-js` (attivo, prodotto) e `packages/` Dart
(implementazione di riferimento), non interoperabili a livello crittografico.

## Vision Statement

Styx is the sovereign communication stack that lets privacy-conscious people
exchange end-to-end-encrypted messages through untrusted relays, with
self-custodied identity, no central accounts, and honestly stated limits.

## Strategic Objectives

1. **Close the open security blockers.** H1/H2 (see
   `docs/security/2026-07-10-styx-chat-security-report.md`) gate every
   "production-ready" statement; the product is experimental until they close.
2. **Ship the E2EE chat PWA on the MLS design** — group state, persistence
   envelope, vault and push delivery per the canonical designs under
   `docs/superpowers/specs/`.
3. **Keep the supply chain verifiable** — vendored, pinned WASM crypto
   artifacts with reproducible-build and integrity gates in CI (Blocco 1).
4. **State security properties honestly.** Relays observe transport metadata;
   the product is not a zero-metadata or "serverless" system and must never be
   marketed as one (policy: `CLAUDE.md`, enforced by the Doc claims lint).

## Target Users

### User 1 — Privacy-conscious individual
- **Role**: person who needs confidential 1:1 and small-group messaging.
- **Pain point**: mainstream messengers require accounts, phone numbers and
  trust in a provider's servers.
- **Expectation**: E2EE by default, self-custodied identity, delivery through
  relays that see only opaque ciphertext, clear statement of what metadata
  remains observable.

### User 2 — Security reviewer / integrator
- **Role**: engineer auditing or embedding the Styx libraries.
- **Pain point**: crypto products that overclaim and hide their trust model.
- **Expectation**: pinned, verifiable crypto artifacts; documented threat
  model; a reference implementation to check behaviour against.

## Product boundaries

- **Active product**: `styx-js/` — JavaScript/TypeScript E2EE chat (MLS via
  vendored OpenMLS WASM, Nostr transport, React PWA) plus the push bridge
  services.
- **Reference implementation**: `packages/` — Dart sovereign-ledger stack
  (ADR-0003). The two stacks are **not cryptographically interoperable**.
- **Out of scope** while H1/H2 are open: production claims, unaudited crypto
  changes, and any marketing that is not honest about the trust model (no "serverless", no "zero-knowledge" wording).

## Normative sources

- `docs/superpowers/specs/2026-07-09-styx-chat-mls-design.md`
- `docs/security/2026-07-10-styx-chat-security-report.md`
- `docs/architecture/decisions/ADR-0001…0005`
- `docs/piano-utente.md` (phased product plan)
