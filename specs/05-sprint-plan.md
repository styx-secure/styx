---
spec_version: "2.0"
spec_type: "sprint-plan"
project: "Styx"
last_updated: "2026-07-21T00:00:00Z"
status: "planned"
---

# Styx — Sprint plan

## Sintesi (IT)

Sprint 1 adotta il backlog prodotto esistente (Issue #24–#27) come story
`US-001…US-004` — vedi `03-user-stories.md` per il contenuto completo e la
tabella di mappatura. Le righe di descrizione di ogni story qui sotto sono
**esattamente** ciò che `/dev-issue-sync` proietta nei corpi delle Issue
(SPEC v0.36 §5.4): sintetiche, con provenienza e puntatori canonici. Questo
file è letto da `parse-sprint.ts` del commit MUCC pinnato in
`.mucc/upstream-lock.json`.

## Sprint 1 — Adopted brownfield backlog (storage & chat UI hardening)

Total SP: 13. All stories originate from the residual items of PR #23
(`docs/security/2026-07-12-review-mls-state-envelope.md`). Human gate per
Epic #65: every PR is human-reviewed; no unattended execution.

### US-001 — Map structured MLS state errors to safe user-facing messages

**SP**: 3
**Status**: todo

Adopted from Issue #24 (residual item 3 of
`docs/security/2026-07-12-review-mls-state-envelope.md`). Full story and
acceptance criteria: `specs/03-user-stories.md` (US-001) — the file owns spec
content; this Issue body is a generated projection. Map stable `MLS_STATE_*`
codes to user-facing messages; technical details only in development logs;
never any payload or MLS material in messages; controlled exposure of the
structured recovery `actions` of `MLS_STATE_OPENMLS_INCOMPATIBLE`.

### US-002 — Replace spread-based Uint8Array to Base64 conversion on the persistence path

**SP**: 5
**Status**: todo

Adopted from Issue #25 (residual item 2 of
`docs/security/2026-07-12-review-mls-state-envelope.md`). Full story and
acceptance criteria: `specs/03-user-stories.md` (US-002) — the file owns spec
content; this Issue body is a generated projection. `bytesToBase64`
(`styx-js/src/utils.js`) hits the engine argument-count limit far below the
16 MiB parser cap. Resolve in Blocco 3 via chunked conversion, streaming
conversion, or (preferred) removing Base64 entirely with the IndexedDB
vault's native binary values. No production change during the spikes.

### US-003 — Allowlist for MlsStateError.details fields

**SP**: 3
**Status**: todo

Adopted from Issue #26 (residual item 1 of
`docs/security/2026-07-12-review-mls-state-envelope.md`). Full story and
acceptance criteria: `specs/03-user-stories.md` (US-003) — the file owns spec
content; this Issue body is a generated projection. Define an explicit
allowlist of publishable `details` fields (error code, envelope version,
schema version, OpenMLS revisions, artifact digests, ciphersuites, suggested
actions); `causeMessage` is never propagated automatically — development
logs only, or a stable sub-code.

### US-004 — Document the operational limits of localStorage vs the 16 MiB parser cap

**SP**: 2
**Status**: todo

Adopted from Issue #27 (operational-limit record requested at the Fase D
gate of PR #23). Full story and acceptance criteria:
`specs/03-user-stories.md` (US-004) — the file owns spec content; this Issue
body is a generated projection. State explicitly that `MAX_PAYLOAD_BYTES` is
the parser's defensive cap, not backend capacity; Base64 and JSON overhead
push 16 MiB beyond typical localStorage quotas; browser quotas differ; the
Blocco 3 IndexedDB vault replaces this limit; quota errors must remain
fail-closed and non-destructive (legacy value + backup intact,
`MLS_STATE_MIGRATION_FAILED` raised — tested property to preserve).

## Sprint 2 — Blocco 3 vault core (engine, lifecycle, canary)

Total SP: 21. All stories mirror sections B3.4–B3.6 of
`docs/superpowers/plans/2026-07-12-styx-vault-implementation-plan.md` (the
canonical plan, which wins on any disagreement). Sequential dependencies:
US-006 depends on US-005, US-007 on US-006. Human gate per Epic #65: every
PR is human-reviewed; the US-006 merge additionally takes the
irreversible-contract decision of plan §16.13 (wrapper v1 / manifest v1 /
record v1).

### US-005 — Vault IndexedDB engine inside the worker

**SP**: 8
**Status**: todo

From plan section B3.4 (PR‑4). Full story and acceptance criteria:
`specs/03-user-stories.md` (US-005) — the file owns spec content; this Issue
body is a generated projection. `src/storage/vault-db.js` inside the vault
worker: schema v1 with the ten frozen stores, multi-store transactions on
`oncomplete`, strict durability where supported, bounded blocked-open retry,
fail-closed quota and upgrades, handled destroy, single-tab Web Lock.
Synthetic records only (`styx-vault-test-*`). Depends on the merged PR #39
worker runtime; rollback R0; the transactional semantics freeze at merge.
Acceptance: spike probes P1–P12 ported and green on Chromium and Firefox
in CI.

### US-006 — Lifecycle of a new empty vault

**SP**: 8
**Status**: todo

From plan section B3.5 (PR‑5). Full story and acceptance criteria:
`specs/03-user-stories.md` (US-006) — the file owns spec content; this Issue
body is a generated projection. `src/storage/vault.js`: spec §3 state
machine (`CREATE_VAULT/UNLOCK/LOCK/STATUS/CHANGE_PASSWORD/REWRAP/DESTROY`);
Root Key never derived, persisted in cleartext or exported; KEK only from
validated Argon2id; §7.2 re-wrap with one valid wrapper at every instant;
`VAULT_WRONG_PASSWORD` non-destructive and oracle-free (§16.8); an
incompatible well-formed wrapper fails closed with structured recovery
actions; no localStorage migration. First real use of wrapper v1 and
manifest v1; rollback R1 (flag off, DESTROY for dev vaults). Introduces
`src/config/vault-stage.js` and revises the PR‑3 anti-bundle test. Merge
takes the §16.13 irreversible-contract decision (wrapper v1 / manifest v1 /
record v1).

### US-007 — Canary namespace end-to-end

**SP**: 5
**Status**: todo

From plan section B3.6 (PR‑6). Full story and acceptance criteria:
`specs/03-user-stories.md` (US-007) — the file owns spec content; this Issue
body is a generated projection. The `canary` namespace, synthetic records
only, exercised end-to-end from the app behind `styx.vault.stage`:
encryption, AAD, persistence, reopen, wrong password, bit-flip corruption,
crash, re-wrap, password change, reset, trial v1→v2 upgrade on canary only,
SW update while UNLOCKED, simulated eviction. Rollback R1; gate: only after
this story may later stories touch real product data. Acceptance: full spec
§13 matrix on the canary in CI.
