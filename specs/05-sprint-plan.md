---
spec_version: "2.0"
spec_type: "sprint-plan"
project: "Styx"
last_updated: "2026-07-19T00:00:00Z"
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
