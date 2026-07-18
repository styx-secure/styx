---
spec_version: "2.0"
spec_type: "prd"
project: "Styx"
last_updated: "2026-07-18T00:00:00Z"
status: "draft"
---

# Styx — Product Requirements (synthesis)

## Sintesi (IT)

PRD di sintesi del prodotto esistente, organizzato per epic. Ogni epic rimanda
al documento canonico che ne è la fonte normativa: questo file è la mappa,
non il territorio. Le user story con contract block arriveranno con la PR di
adozione del backlog (vedi `specs/README.md`).

> **Authority note.** Each epic links its canonical design document. Where
> this synthesis and the canonical document disagree, the canonical document
> wins (`specs/README.md`).

## E1 — MLS group messaging

E2EE 1:1 and small-group chat built on MLS (RFC 9420) through the vendored
`openmls-wasm` artifact. Self-custodied identity, no central accounts.
- **Canonical**: `docs/superpowers/specs/2026-07-09-styx-chat-mls-design.md`
- **Status**: active development; experimental while H1/H2 are open.
- **Note**: the design document predates the claim cleanup and uses early
  wording for the transport model; the honest framing in `01-vision.md`
  prevails.

## E2 — MLS state envelope and persistence

Versioned, fail-closed envelope for persisted MLS state: format detection,
compatibility cases, structured errors, no silent data loss.
- **Canonical**: `docs/superpowers/specs/2026-07-12-mls-state-envelope.md`
- **Status**: designed; storage-path issues #24–#27 track hardening.

## E3 — Styx Vault

Encrypted local vault for keys and state: IndexedDB persistence, Argon2id
KDF (dedicated `styx-kdf-wasm` artifact), crypto isolated in a worker.
- **Canonical**: `docs/superpowers/specs/2026-07-12-styx-vault-design.md`,
  plan `docs/superpowers/plans/2026-07-12-styx-vault-implementation-plan.md`,
  spikes `2026-07-12-argon2id.md`, `2026-07-12-crypto-worker.md`,
  `2026-07-12-indexeddb-vault.md`.
- **Status**: design approved; implementation staged. PR #39 (isolated vault
  worker runtime) belongs to this epic and is untouched by the workflow
  migration.

## E4 — Push notifications

Delivery of encrypted-payload notifications to the PWA through the push
bridge (`push_bridge/` Node + `push_bridge_server/` Go, APNs/FCM). The
bridge is a deliberate, stateless exception in the trust model and is
documented as such.
- **Canonical**: `docs/superpowers/specs/2026-07-10-pwa-push-notifications-design.md`,
  plan `docs/superpowers/plans/2026-07-10-pwa-phase2-push-bridge.md`

## E5 — Read receipts

Read receipts inside the MLS channel, without leaking metadata to relays
beyond what transport already exposes.
- **Canonical**: `docs/superpowers/specs/2026-07-10-read-receipts-design.md`

## E6 — Channel authentication (Phase A)

Authenticated pairing/channel establishment.
- **Canonical**: `docs/superpowers/plans/2026-07-10-phase-a-channel-authentication.md`

## E7 — WASM hardening and risk reduction

Supply-chain integrity for the vendored crypto artifacts: pinned commits,
reproducible rebuilds, KATs, CI integrity gates; claim cleanup and risk
reduction (Blocco 2).
- **Canonical**: `docs/superpowers/plans/2026-07-11-blocco1-wasm-hardening.md`,
  `docs/superpowers/plans/2026-07-11-blocco2-risk-reduction.md`
- **Hard constraint**: the `openmls-wasm` pin descends from `openmls-v0.8.1`
  and carries fixes absent from that tag — moving back to the tag would be a
  downgrade **and** a persisted-format break. Never "bump to the release tag"
  without reading `vendor/openmls-wasm/PROVENANCE.md` first.

## Cross-cutting requirements

- **Honest claims** (all epics): never use affirmative "serverless" / "zero-knowledge" / zero-metadata wording; relays observe transport
  metadata. Enforced by the `Doc claims lint` CI check.
- **Fail-closed persistence**: storage-format changes require explicit
  migration paths (E2) and are a mandatory human-gate area (`AGENTS.md`).
- **Crypto changes** are human-gated: no agent may alter crypto code, test
  vectors or persisted formats without an explicitly approved Issue.

## Deferred

User stories with contract blocks (`03-user-stories.md`) and the sprint plan
(`05-sprint-plan.md`) arrive with the backlog-adoption PR — see
`specs/README.md` for the reason.
