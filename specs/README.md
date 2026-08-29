# specs/ — product direction and MUCC planning

This directory is the English-canonical operational entry point for Styx
product direction and the MUCC planning workflow adopted in governance
[ADR-0006](../docs/governance/adr/ADR-0006-adopt-mucc-multidev.md). Translations
are optional aids; they do not replace the English requirement.

## Authority model — read this first

Repository work follows the authority order in [`AGENTS.md`](../AGENTS.md): an
approved GitHub Issue and its native dependencies; `AGENTS.md`; normative
specifications, ADRs, and active plans; then tool adapters and local notes.
GitHub remains the operational source of truth for task status and approval.

Within that hierarchy, the files here have different maturity:

| File | Role and current status |
|---|---|
| [`01-vision.md`](01-vision.md) | Approved product direction from #124/#125. It does not claim production readiness. |
| [`02-prd.md`](02-prd.md) | Draft product-requirement synthesis; the future language-neutral protocol and conformance corpus will be the application authority. |
| [`03-user-stories.md`](03-user-stories.md) | Adopted brownfield MUCC story source for its declared adoption perimeter. |
| [`04-tech-spec.md`](04-tech-spec.md) | Draft architectural synthesis and map to detailed technical evidence. |
| [`05-sprint-plan.md`](05-sprint-plan.md) | MUCC planning projection. Its story status can lag merged GitHub work and must not be used as the live delivery dashboard. |

Detailed vault, MLS, transport, security, governance, and historical decisions
remain in their named documents under `docs/`. They are authoritative only for
the scope and maturity each document declares. When two sources conflict, do
not silently choose one: apply the repository authority order and correct the
lower-authority or stale synthesis through an approved task.

## Backlog adoption boundary

`03-user-stories.md` and `05-sprint-plan.md` were added in Task #84. Their
declared adopted stories use `us-id:*` labels so `/dev-issue-sync` updates the
existing GitHub Issues instead of creating duplicates. Issue bodies generated
from an adopted story are projections; the pre-adoption bodies remain in
GitHub history.

Issues #45, #61, and #62, Epic #65, and migration/governance task Issues are
outside that adoption perimeter and must not receive `us-id:*` labels. New
strategic work such as the Styx application protocol, Marmot evaluation, and
Flegias requires its own approved contractual Issues rather than being inserted
silently into the historical sprint plan.

## Documentation and claims

English is canonical. Security and maturity claims must link evidence and name
the applicable runtime and threat model. Current builds are experimental;
relays and push infrastructure can observe metadata; upstream audits do not
audit Styx. The `Doc claims lint` CI check rejects prohibited affirmative
claims, but passing that linter is not a security review.
