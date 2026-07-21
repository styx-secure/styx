# specs/ — MUCC operational entry point

## Sintesi (IT)

Questa directory è l'**ingresso operativo** del workflow MUCC (governance
ADR-0006). Le spec qui dentro sono *sintesi*: il dettaglio tecnico normativo
resta nei documenti canonici sotto `docs/superpowers/**` e
`docs/architecture/decisions/**`, che questa directory **non** sostituisce.
`03-user-stories.md` e `05-sprint-plan.md` sono volutamente assenti — arrivano
con la PR di adozione del backlog. L'inglese è la lingua primaria; ogni file
apre con una sintesi italiana come questa.

## Authority model — read this first

This directory is the **operational entry point** for the MUCC workflow adopted
by governance [ADR-0006](../docs/governance/adr/ADR-0006-adopt-mucc-multidev.md).
Authority transfers **gradually**:

| Content | Authoritative source |
|---|---|
| Vision, PRD, tech-spec *synthesis* | `specs/` (this directory) |
| Normative technical detail (MLS design, vault, envelope, push, plans, spikes) | `docs/superpowers/**` — canonical, untouched |
| Product architecture decisions | `docs/architecture/decisions/` (ADR-0001…0005) |
| Governance and workflow decisions | `docs/governance/adr/` |

When a synthesis here and a canonical document disagree, **the canonical
document wins** and the synthesis must be corrected. Full authority moves to
`specs/` only when the MUCC workflow actually exercises it in real sprints.

## Backlog adoption (Epic #65, task 5)

- **`03-user-stories.md`** and **`05-sprint-plan.md`** exist since Task #84:
  they adopt product Issues #24–#27 as stories `US-001…US-004`. The
  duplication trap is disarmed by pre-labelling those four Issues with their
  `us-id:*` key **before** the first sync, so `/dev-issue-sync` updates them
  instead of creating parallel ones. After the sync, the files own spec
  content and the Issue bodies are generated projections (SPEC v0.36 §5.4);
  pre-adoption bodies remain in the GitHub Issue edit history.
- **Permanently outside the adoption perimeter:** Issues #45, #61 and #62
  (Styx task contracts in their bodies), Epic #65 and the migration task
  Issues. They must never receive a `us-id:*` label.
- Phase files `06`–`08` follow the sprints that produce them.

## Honesty constraints

Every document in this directory is subject to the claim policy of
`CLAUDE.md` and to the `Doc claims lint` CI check: the product must **not** be
described with "serverless", "zero-knowledge" or equivalent affirmative claims
while H1/H2 remain open. Relays observe transport metadata — say so.
