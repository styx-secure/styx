# Governance ADRs

This directory holds Architecture Decision Records for **repository governance and
process** decisions — how the project is developed, coordinated and gated.

## Two independent ADR series

This repository keeps **two separate ADR series**, numbered independently:

| Series | Location | Scope |
|---|---|---|
| **Architecture** | `docs/architecture/decisions/` | Product and technical architecture (canonical stack, monorepo strategy, licensing, …) |
| **Governance** | `docs/governance/adr/` (this directory) | Development workflow, coordination, migration and process decisions |

The two series **do not share a numbering space**. A number that appears in one
series may also appear in the other with an unrelated meaning. This is deliberate:
each series is owned and evolves on its own, and `docs/architecture/**` is a
CODEOWNERS-protected, human-gate area under `AGENTS.md` that governance work does
not touch.

To avoid confusion, always cite a governance ADR with its full path or as
"governance ADR-000N", never by bare number alone.

## Index

- [`ADR-0006-adopt-mucc-multidev.md`](ADR-0006-adopt-mucc-multidev.md) — Adopt MUCC
  Multidev as the target operational workflow and defer the Styx agent platform.
  (Epic #65.)

### Notes on ADR-0006

- **Number.** It reuses `0006` intentionally: the architecture series ends at
  `ADR-0005`, so `0006` was the next free number when this series was opened, but
  the two series remain independent (see above). A future *architecture* ADR-0006
  would be a different, unrelated decision.
- **Language.** ADR-0006 is written in **English**, matching its governance-directory
  neighbours, whereas the architecture ADRs (0001–0005) are in Italian. This
  divergence is deliberate and recorded here so it is not mistaken for drift.
