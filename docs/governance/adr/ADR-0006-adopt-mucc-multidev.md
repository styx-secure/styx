# ADR-0006 — Adopt MUCC Multidev and defer the Styx agent platform

- **Status:** Accepted (2026-07-17)
- **Epic:** #65
- **Task:** #66
- **Baseline:** `7815949e49e4a2d376161e8324b8eed5e1a7ce11`
- **Preservation tag:** `styx-agent-platform-v0.1-deferred-2026-07-17`

## Context

`styx-secure/styx` built its own agentic development platform: an issue-bound fail-closed
runner (`tools/agent-runner`), a report-only scope guard used in CI
(`tools/agent-enforcement`), a test orchestrator, a review/remediation gate, a restricted
operation broker, ten evidence JSON Schemas, and four layers of blocking Claude Code hooks.
It works, and it encodes a real governance model: contract, claim, allowed paths, handoff,
human gate.

It is also expensive to carry. The enforcement is Linux-bound, deny-by-default, and hostile
to any workflow that is not `/styx-run`. A second team member on macOS cannot run it
(Issue #61 exists precisely because of that gap).

MUCC Multidev (`MaxGiu67/plugin-MUCC`) offers a portable alternative: coordination over
GitHub Issues, logical isolation instead of OS isolation, and enforcement on the server side.
It is mature — multidev coordination reached GA in v0.36.2 — and it runs unchanged on Linux,
macOS and Windows.

There is an uncomfortable fact to state plainly rather than paper over. **MUCC was designed
with Styx as its explicit negative example.** `ADR-002-coordination-backend-adapter.md:93`
rejects the Styx model by name:

> **Sandbox OS per isolare gli esecutori (modello Styx).** Scartata: **lock-in Linux
> (bubblewrap), ergonomia deny-by-default disastrosa verificata sul campo**

and `SPEC-dev-multidev-coordination-v0.36.0.md:59-61` formalises it as non-goal NG-A
("NO sandbox OS"), while line 317 credits `styx-secure/styx` as the structural source whose
"lezioni negative" became anti-goals. Adopting MUCC into Styx therefore means adopting a
design that names this repository as what not to do.

That is survivable, and this ADR takes it seriously rather than ignoring it. See
*Decision*, point 7.

## Decision

1. **MUCC Multidev is the target operational workflow** for this repository.

2. **`specs/` will own spec content** in the future, and **GitHub will own execution state**
   (claims, status labels, assignees, milestones), per MUCC ADR-002 §4. Neither is true yet.

3. **Authority transfers only in a later pull request.** This ADR records a decision; it does
   not enact it. Nothing in this pull request changes runtime behaviour.

4. **The Styx tools remain present but inactive.** `tools/agent-runner`,
   `tools/agent-enforcement`, `tools/test-orchestrator`, `tools/review-gate`,
   `tools/restricted-broker` and `docs/governance/schemas` stay in the tree, at this baseline,
   reachable from the preservation tag.

5. **No component is deleted.** Deferred means inactive, not removed. Any future
   deactivation is a reversible git operation on tracked files.

6. **MUCC updates only by pinned commit, through a reviewed pull request.**
   `.mucc/upstream-lock.json` pins `21ecfdc84afc65395033b56c9b86f8d514c3e80a`
   (marketplace 2.12.1, dev-methodology 0.40.1) with
   `update_policy: explicit-reviewed-pull-request-only`. The pin is by SHA because
   marketplace `v2.12.1` carries **no git tag** upstream — only `v2.12.0` is tagged — so the
   commit is the only authoritative reference.

7. **The deferred Styx work returns as an executor profile plus deployment layer, not as a
   workflow adapter.** This is the reconciliation of the conflict described above. MUCC
   rejects the OS sandbox *inside the workflow* (NG-A), but `SPEC-dev-executor-profiles-v0.38.0.md:36`
   keeps it as a *deployment* concern: sandboxing is "raccomandazione di deployment", and
   ADR-003 §4 lists a dedicated machine or container as a non-negotiable precondition for
   unattended workers. The slot MUCC genuinely leaves open is therefore the executor profile
   and the deployment substrate — not the loop itself. Styx returns as `styx-hardened`:
   the runner, broker and sandbox as *how an executor is deployed*, while the workflow stays
   portable and unmodified.

   Honest caveat: the same SPEC (NG-E, line 36) states that profiles beyond `human` and `bot`
   are future work. `styx-hardened` is not a slot MUCC offers today; it is one this repository
   would have to propose upstream. That is PR 9, not now.

8. **No unattended worker** until the human pilot and CI are both green.

9. **No self-merge.**

10. **PR #39 and the product backlog are unaffected.** This is an infrastructure migration.
    It authorizes no product change by implication.

## Consequences

**Positive.** The workflow becomes portable — the macOS gap that motivates Issue #61 stops
being a blocker for the *workflow*, independently of whether the Styx runner ever gains macOS
support. Enforcement moves to the server side, where it is harder to bypass than a local hook.
Contributors get one documented way to work.

**Negative, and load-bearing.**

- **Human review is policy, not enforcement.** The active ruleset on `main` (id 18814814)
  sets `required_approving_review_count: 0`, and `Agent scope evidence` is not among its
  required checks (`Dart reference stack gate`, `styx-js web gate`, `WASM integrity gate`,
  `Analyze (javascript-typescript)` are). The no-self-approve rule this ADR declares is
  currently upheld by discipline alone. Rulesets are outside the authority of this Epic;
  a proposal belongs to PR 4 and must be applied by a human.
- **Prevention degrades to detection.** Styx blocks a bad write before it happens. MUCC
  observes the diff afterwards and relies on the merge gate. That is a real reduction in
  guarantee, accepted deliberately in exchange for portability, and only sound if the
  merge gate above is actually enforced.
- **Backlog duplication risk.** MUCC's `issue-sync` recognises only Issues labelled
  `us-id:*`; the existing Styx backlog is invisible to it and would be duplicated rather
  than adopted. Mitigation belongs to PR 5. No label collision exists today: MUCC uses
  `us-id:*`, `status:*`, `claimed`, `autonomy-blocked`; Styx uses `type:*`, `risk:*`,
  `area:*`, `gate:*`, `executor:*`, `origin:*`.
- **One-way door.** MUCC's own SPEC §9.3 calls `--adopt` a "percorso a senso unico
  consigliato". Return to monodev is technically possible and practically discouraged.

**Derogations recorded here because their directories are outside this task's allowed paths.**

- **Schema-id without a schema.** All ten existing `styx.*` identifiers have a matching file
  in `docs/governance/schemas/` with a canonical `$id`. `styx.mucc-upstream-lock/v1` will not.
  `docs/governance/schemas/**` is not in this task's allowed paths. The schema is scheduled
  for PR 2.
- **ADR numbering collision.** ADRs 0001–0005 live in `docs/architecture/decisions/`. This
  file opens a *second* series in `docs/governance/adr/` rather than continuing the first,
  so a future architecture ADR could also claim 0006. `docs/architecture/**` is outside
  allowed paths (and is a human-gate area under `AGENTS.md`), so the cross-reference that
  would resolve this is deferred to PR 2.
- **Language divergence.** ADRs 0001–0005 are written in Italian, per `AGENTS.md:140`
  ("Design docs are primarily Italian"). This ADR is in English to match its directory
  neighbours in `docs/governance/`, which are English. Deliberate; revisit in PR 2.

## Rejected alternatives

1. **Delete the Styx agent platform.** Rejected: it encodes a governance model that took real
   work to build, three open Issues depend on it, and deletion is irreversible in practice
   even when reversible in git. Deferral costs nothing but tree weight.

2. **Keep Styx and ignore MUCC.** Rejected: the platform is Linux-only and deny-by-default.
   The macOS gap (#61) is structural, not incidental, and a second contributor cannot work.

3. **Reintegrate Styx as a MUCC workflow adapter** (a coordination backend or an alternative
   scope guard inside the loop). Rejected: in direct tension with NG-A. MUCC's isolation is
   logical by design, and pushing the sandbox back into the workflow would re-import exactly
   the lock-in that MUCC rejected — while forking away from upstream. See *Decision*, point 7
   for the accepted framing.

4. **Adopt MUCC by running `/dev-init` or `/dev-issue-sync` now.** Rejected: `/dev-init` is a
   greenfield scaffolder that writes twelve-plus spec files and appends to `CLAUDE.md`;
   `issue-sync` would duplicate the existing backlog. Both are out of scope here and are
   sequenced as PR 2 and PR 5.

5. **Change the ruleset now to make review enforceable.** Rejected: not authorized. Rulesets,
   branch protection and CODEOWNERS are human-gate areas under `AGENTS.md`. Recorded as a
   residual risk and deferred to PR 4.
