# MUCC migration plan — PR 2 to PR 9

- **Epic:** #65 · **Decision:** [ADR-0006](../adr/ADR-0006-adopt-mucc-multidev.md) · **Inventory:** [deferred components](../deferred/styx-agent-platform-inventory.md)
- **Baseline:** `7815949e49e4a2d376161e8324b8eed5e1a7ce11`
- **Preservation tag:** `styx-agent-platform-v0.1-deferred-2026-07-17`

PR 1 (Task #66) is documentation only. It changes no runtime behaviour. Everything below is
**planned, not authorized** — each pull request needs its own Task Issue with a complete
contract, and each must be reviewed and merged by a human before the next begins.

**Rules that hold for every pull request in this plan:** small and single-purpose · squash
merge · human review · no self-approve · no unattended worker until PR 7 · no product change
by implication (PR #39 and the product backlog stay untouched throughout).

---

## PR 2 — Brownfield specs and MUCC config

**Purpose.** Introduce `specs/` with the existing Styx product specification imported into
MUCC's structure, and add `.mucc/config.json`. Close the three conformance debts PR 1 could
not.

**Allowed paths (planned).** `specs/**`, `.mucc/config.json`,
`docs/governance/schemas/mucc-upstream-lock-v1.schema.json`, `docs/governance/adr/**`.

**Inherited from PR 1** — these are outside PR 1's allowed paths and must land here:
1. Create the schema for `styx.mucc-upstream-lock/v1`, closing the derogation (all ten other
   `styx.*` identifiers have one).
2. Reconcile the ADR-0006 numbering collision between `docs/governance/adr/` and
   `docs/architecture/decisions/`.
3. Decide whether ADR-0006's language (English) should align with ADRs 0001–0005 (Italian).

**Do not.** Do not run `/dev-init` — it is a greenfield scaffolder that writes twelve-plus
files and appends a methodology section to the root `CLAUDE.md`, which is a forbidden path.
Author the spec tree by hand instead.

**Human gate.** Review. `CLAUDE.md` must not be touched.

**Rollback.** Revert; `specs/` and `.mucc/config.json` are new files with no consumer yet.
Note that `coordination.mode` absent or unparsable means monodev — MUCC fails soft here, so a
partial config cannot break anything.

---

## PR 3 — Claude Code and hook compatibility

**Purpose.** Replace the active Styx hooks with a MUCC-compatible profile.

**Allowed paths (planned).** `.claude/**`.

**The hard part — four independent blocking layers**, all of which must be handled:

1. `styx_guard.py:401-403` — every Write/Edit/MultiEdit is denied without an active
   `/styx-run` task.
2. `styx_guard.py:362-379` — Bash is restricted to a read-only allowlist; `git add`,
   `git commit`, `git branch`, `git checkout` are absent, so a commit is impossible.
   `read_only_guard.py` additionally denies `find` and `sed` unconditionally, in every session.
3. `.claude/settings.json:176-183` — `denyWrite: ["."]` with `failIfUnavailable: true` and
   `network.deniedDomains: ["*"]`. The project directory itself is deny-write.
4. `styx_guard.py:464-467` — the `Stop` hook blocks session termination when no Styx task
   reached a terminal state. An unrelated agent session cannot even finish.

**Design note.** MUCC's hooks are all `decision: warn` and never block, and MUCC explicitly
does not depend on them: `SPEC-dev-multidev-coordination-v0.36.0.md` §6.5.2 states that no
guarantee rests on Claude Code hooks, because Codex has none. Enforcement lives in explicit
scripts and server-side GitHub. So this PR removes a *blocker*, not a guarantee.

Keep the project-level `.claude/settings.json` permission allowlist: MUCC expects the project
to own it as the agent permission boundary, CODEOWNERS-protected and reviewed as code.

**Human gate.** `.claude/**` is a human-gate area under `AGENTS.md`. **Mandatory.**

**Rollback.** All five files under `.claude/` are tracked; revert restores them exactly. Trap:
`.gitignore` contains `.claude/`, so the files were force-added. If they are ever removed from
the index, re-adding needs `git add -f`.

---

## PR 4 — CI and repository integration

**Purpose.** Add MUCC's scope and test checks to CI. Propose the ruleset that makes human
review actually enforceable.

**Allowed paths (planned).** `.github/workflows/**`, plus a ruleset proposal as documentation.

**Two things to settle.**

- **`agent-scope-evidence.yml` vs MUCC's `scope-guard.ts`.** They overlap. Decide: keep Styx's
  (its contract parser is stricter), adopt MUCC's, or run both. Whatever is chosen,
  `tools/agent-enforcement` stays — `contract_inputs.py:60` imports from it at runtime, and
  deleting it turns the check red.
- **The ruleset gap.** Today `main`'s ruleset (id 18814814) has
  `required_approving_review_count: 0` and does not require `Agent scope evidence`. MUCC's
  `github-setup.md` §1 requires review plus "review from someone other than the last pusher",
  and §3 calls the CI scope check "l'enforcement VERO". ADR-003 is blunt that a PAT cannot
  restrict pushes to `task/*` — only rulesets can. **Until this lands, the whole
  no-self-approve model is honour-based.**

**Human gate.** `.github/workflows/**` is a human-gate area. Rulesets **cannot be changed by
an agent at all** — this PR proposes; a human applies.

**Rollback.** Revert the workflow. A ruleset change is reverted by a human in the UI.

---

## PR 5 — Backlog adoption

**Purpose.** Adopt the existing backlog into MUCC without duplicating Issues.

**The trap, stated precisely.** `issue-sync` looks Issues up **only** by the `us-id:*` label
(`github.ts` `syncStory`). Every pre-existing Styx Issue is invisible to it. Running an export
against a populated backlog creates a **parallel, duplicate** set of Issues — duplication of
meaning, which the tool cannot detect. MUCC has no adoption or matching pass: reconciliation
was explicitly ruled out as non-goal NG-B.

**Mitigation.** Pre-label the existing Issues with `us-id:US-xxx` by hand *before* the first
sync, so `syncStory` finds and edits them instead of creating new ones. Be aware this
**overwrites their bodies** — the file wins over the Issue by design (SPEC §5.4). Weigh that
against the existing contracts before doing it.

**Two smaller hazards.** `ensureLabels` uses `gh label create --force`, which repaints any
colliding label. No collision exists today — MUCC uses `us-id:*`, `status:*`, `claimed`,
`autonomy-blocked`; Styx uses `type:*`, `risk:*`, `area:*`, `gate:*`, `executor:*`,
`origin:*` — but re-check before running. And `--dry-run` only lists story IDs; it does
**not** show create-vs-update, so it will not reveal duplication before it happens.

**Do not.** Do not run `/dev-issue-sync` on this repository until this PR is explicitly
authorized. Do not close or rewrite #45, #61 or #62.

**Human gate.** Review, plus explicit authorization to touch the backlog at all.

**Rollback.** Config-only in principle (`coordination.mode` back to `monodev`, Issues left as
an archive), but duplicated Issues must be cleaned up by hand. MUCC's SPEC §9.3 calls
`--adopt` a "percorso a senso unico consigliato". **Treat this as the least reversible step
in the plan.**

---

## PR 6 — Ubuntu/macOS human pilot

**Purpose.** Run a real multidev sprint with two human executors, one Ubuntu, one macOS. No
bots.

**Why it matters.** This is the step that proves the migration was worth it: the macOS gap
that Issue #61 exists for should simply not appear, because MUCC's workflow is portable by
design (G5). If it does appear, the premise of ADR-0006 is wrong and that must be said out
loud rather than worked around.

**Expect.** Dependent stories serialize through the human merge gate — a story is claimable
only when its dependencies are merged (SPEC §6.2). Parallelism exists only between independent
stories. Throughput is bounded by reviewer capacity, not by executor count.

**Human gate.** The pilot is humans only, by definition.

**Rollback.** Nothing to roll back — no code changes, only a real sprint run.

---

## PR 7 — Supervised worker

**Purpose.** Enable one MUCC worker, supervised, never unattended.

**Preconditions, none of which hold today.** Ruleset with review ≠ last pusher (PR 4) ·
`scope-guard` and `test` as required checks · `**Autonomy**: allowed` declared by a human per
story · `**Exact tests**` mandatory and **runnable without a database**, or the publisher
blocks every story · dedicated machine or user with no other secrets · workspace trust flag
set in `~/.claude.json`, or headless silently ignores the whole project allowlist · dedicated
API key with a budget cap · dedicated PAT, never `administration`.

**Note.** MUCC's separate-publisher rule (v0.38 G2 — the agent process holds no GitHub
credentials; only the worker publishes) is the same principle Styx's `restricted-broker`
already implements. That is the natural place for the broker to return.

**Human gate.** Every worker PR is merged by a human — MUCC calls this "IL gate del sistema,
non si delega".

**Rollback.** `.mucc/worker.pause` is a kill switch. Stop the worker; nothing else changes.

---

## PR 8 — Unattended worker evaluation

**Purpose.** Evaluate, not enable. Decide whether unattended is worth it at all.

**Sober note.** MUCC's `--unattended` is live-fire, not settled: at the pinned commit the most
recent upstream commits are worker and coordination bugfixes from an in-progress collaudo
(quarantine bug, HTML API responses killing the preflight, a 15-minute assignee staleness in
GitHub's search index). ADR-003 §4 makes a container or VM a non-negotiable precondition.

**Human gate.** Explicit decision. The default is **no**.

**Rollback.** n/a — evaluation only.

---

## PR 9 — Secure-execution reintegration

**Purpose.** Bring the deferred Styx components back as the `styx-hardened` executor profile
plus deployment layer, per ADR-0006 §7.

**Scope.** `tools/agent-runner` → deployment substrate · `tools/restricted-broker` →
implementation of MUCC's separate publisher · `tools/test-orchestrator` → derivation of Exact
tests · `tools/review-gate` → structured evidence beneath MUCC's evidence flow ·
`docs/governance/schemas` → formal evidence contracts, which MUCC lacks. Issues #45, #61 and
#62 are the input.

**Two obstacles to name now rather than discover later.**

1. **NG-E.** `SPEC-dev-executor-profiles-v0.38.0.md:36` says profiles beyond `human` and `bot`
   are future work. `styx-hardened` is not a slot MUCC offers — it has to be proposed
   upstream, and upstream may decline.
2. **The macOS problem is unsolved.** The sandbox is `bubblewrap`, i.e. Linux-only. This is
   literally MUCC's "lock-in Linux" objection (ADR-002:93). Issue #61 must land first, and
   `fbdbfd5` — if it still exists — is its input.

**Preconditions.** PR 6 and PR 7 green. `fbdbfd5` archived via bundle or archive branch
**before any rebase**, or accepted as lost.

**Human gate.** Full architecture review. This re-opens the decision ADR-0006 made.

**Rollback.** Revert to the profile-free state; MUCC keeps working with `human` and `bot`.
