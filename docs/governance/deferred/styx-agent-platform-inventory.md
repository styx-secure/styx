# Deferred Styx agent platform — inventory and recovery plan

- **Status:** deferred, not deleted (2026-07-17)
- **Baseline:** `7815949e49e4a2d376161e8324b8eed5e1a7ce11`
- **Preservation tag:** `styx-agent-platform-v0.1-deferred-2026-07-17` → `7815949e49e4a2d376161e8324b8eed5e1a7ce11`
- **Decision:** [ADR-0006](../adr/ADR-0006-adopt-mucc-multidev.md) · **Epic:** #65 · **Task:** #66

Every component below is **present in the tree at this baseline and reachable from the
preservation tag**. Nothing here has been deleted, moved or rewritten. "Deferred" means the
component stays where it is and stops being the active workflow — it does not mean removed.

Recovery, in general: `git checkout styx-agent-platform-v0.1-deferred-2026-07-17 -- <path>`
restores any component byte-for-byte. Because nothing is deleted by the migration, recovery is
normally unnecessary — the files simply remain.

---

## `tools/agent-runner`

| Field | Value |
|---|---|
| **Status** | Present, inactive. Never invoked by CI. |
| **Baseline** | `7815949e` |
| **Function** | Issue-bound fail-closed local runner. Creates a private worktree and branch outside the repo, writes `active.json` and a status report, drives one approved task to `BLOCKED_BROKER_UNAVAILABLE`. Entry point `styx-agent` (shim → `isolated_git.apply` + `security_hardening.apply` + `review_hardening.apply` → `styx_agent.main()`). Python 3, stdlib only. |
| **Deferral reason** | Linux-bound and deny-by-default. Invoked only via the `/styx-run` skill and whitelisted in `sandbox.excludedCommands`; both live in `.claude/**`, which the migration will neutralise in PR 3. |
| **Future MUCC destination** | Core of the `styx-hardened` executor profile: the deployment substrate that runs a MUCC executor, not a workflow layer (ADR-0006 §7). |
| **Reactivation condition** | PR 9, and only after the human pilot (PR 6) and a supervised worker (PR 7) are green, and after `styx-hardened` is accepted upstream as a profile — MUCC NG-E currently limits profiles to `human` and `bot`. |
| **Rollback** | Files are tracked and untouched. Revert the PR that neutralises `.claude/**` to restore the runner as the active path. |

## `tools/agent-enforcement`

| Field | Value |
|---|---|
| **Status** | Present, **active in CI** — the only deferred component that is. |
| **Baseline** | `7815949e` |
| **Function** | Strict parser for the v1 task contract plus a report-only Git scope guard. Emits canonical `styx.task-scope-report/v1`. Exit codes: 0 PASS, 2 FAIL, 3 ERROR. CLIs: `scope_guard.py`, `ci_adapter.py`. |
| **Deferral reason** | Not deferred in this task. It keeps running and, in fact, **validates this very migration**: the Draft PR for Task #66 carries a `Styx-Task:` reference so the guard checks the diff against the contract. |
| **Future MUCC destination** | Overlaps MUCC's `scope-guard.ts`. PR 4 decides whether Styx's guard becomes the required check, is replaced, or both run. Its contract parser is the stricter of the two and is worth keeping. |
| **Reactivation condition** | n/a — active. |
| **Rollback** | n/a. |

> **Runtime coupling — do not miss this.** `.github/workflows/agent-scope-evidence.yml` runs
> on `pull_request_target` and calls `python3 tools/agent-enforcement/ci_adapter.py run`.
> `tools/test-orchestrator/contract_inputs.py:60` also imports `parse_contract` from it by
> path at runtime. Deleting or moving this directory turns the check red and breaks the
> orchestrator. It is not in this task's allowed paths, and it must not be touched without
> the workflow being handled first — and `.github/workflows/**` is a human-gate area under
> `AGENTS.md`.

## `tools/test-orchestrator`

| Field | Value |
|---|---|
| **Status** | Present, inactive. Not in CI. |
| **Baseline** | `7815949e` |
| **Function** | Derives a `styx.test-plan/v1` from trusted inputs, executes it, emits `styx.test-report/v1`. Evidence is written outside the repository. Entry point `orchestrator.py` (`plan` / `execute` / `eligibility`). |
| **Deferral reason** | Invoked manually or by the runner; both paths become inactive. |
| **Future MUCC destination** | Maps onto MUCC's **Exact tests** contract field, which v0.38 makes mandatory before a bot publishes. The orchestrator's plan-derivation is a stronger version of the same idea. |
| **Reactivation condition** | PR 9. Note MUCC's constraint: Exact tests for a worker must run **without a database**, otherwise the publisher blocks every story. |
| **Rollback** | Files tracked and untouched. |
| **Dependency** | Imports `parse_contract` from `tools/agent-enforcement` at runtime (`contract_inputs.py:60`). |

## `tools/review-gate`

| Field | Value |
|---|---|
| **Status** | Present, inactive. Not in CI. Manual, documented in `docs/governance/review-remediation.md`. |
| **Baseline** | `7815949e` |
| **Function** | Isolated review gate: validates an evidence pair → `styx.review-report/v1`; `remediate` → `styx.remediation-request/v1`. Never runs tests, git or network; requires `--repo-root`. |
| **Deferral reason** | Manual entry point, superseded in the interim by MUCC's human gates (`/dev-hq`) and the GitHub review flow. |
| **Future MUCC destination** | Structured-evidence layer beneath MUCC's mandatory evidence flow. MUCC's own SPEC v0.40 makes an evidence pass compulsory before any merge action but does not formalise its schema — this does. |
| **Reactivation condition** | PR 9. |
| **Rollback** | Files tracked and untouched. R0/R1 rollback procedures already documented at `docs/governance/review-remediation.md:410`. |

## `tools/restricted-broker`

| Field | Value |
|---|---|
| **Status** | Present, inactive. Never wired to CI. |
| **Baseline** | `7815949e` |
| **Function** | Sole authoritative orchestrator for the only two allowed privileged operations: `push_task_branch` and `open_draft_pr`. Idempotency ledger, one audit record per attempt, fail-closed audit. Consumes `styx.agent-runner-status/v1` and requires `scope_guard.verdict == "PASS"`. |
| **Deferral reason** | Depends on the runner, which becomes inactive. |
| **Future MUCC destination** | **The closest convergence in the whole inventory.** MUCC v0.38's separate-publisher rule (G2: "Zero credenziali GitHub nel processo agente bot") is the same principle this broker already implements: the agent never holds credentials; a separate authority publishes. The broker is a candidate implementation of MUCC's publisher, not a competitor to it. |
| **Reactivation condition** | PR 7 at the earliest (supervised worker), realistically PR 9. |
| **Rollback** | Files tracked and untouched. |

## `docs/governance/schemas`

| Field | Value |
|---|---|
| **Status** | Present, inactive as contracts; **actively used** by `agent-enforcement` output. |
| **Baseline** | `7815949e` |
| **Function** | Ten JSON Schemas — the evidence contracts: `agent-runner-status-v1`, `task-scope-report-v1`, `test-plan-v1`, `test-report-v1`, `test-failure-v1`, `review-report-v1`, `remediation-request-v1`, `restricted-broker-request-v1`, `restricted-broker-response-v1`, `restricted-broker-audit-v1`. |
| **Deferral reason** | The producers of most of these evidence types become inactive. The schemas themselves remain valid and cost nothing to keep. |
| **Future MUCC destination** | Reusable as-is. MUCC is evidence-first but has **no formal evidence schema** — this is a genuine asset Styx brings to the merge, not a liability. |
| **Reactivation condition** | Per schema, as each producer returns. |
| **Rollback** | Files tracked and untouched. |

> **Convention note.** All ten `styx.*` identifiers have a matching schema file here. The new
> `styx.mucc-upstream-lock/v1` does **not** — this directory is outside Task #66's allowed
> paths. The derogation is recorded in ADR-0006 and the schema is scheduled for PR 2.

---

## Issue #45 — [Epic] Phase 2: Agent enforcement and restricted-operation broker

| Field | Value |
|---|---|
| **Status** | **OPEN.** Not closed, contract not rewritten. Informational comment added 2026-07-17. |
| **Baseline** | `7815949e` |
| **Function** | Epic covering the enforcement and broker work. |
| **Deferral reason** | Superseded as the *active* workflow by the MUCC adoption, not cancelled. |
| **Future MUCC destination** | PR 9 — its components return as `styx-hardened`. |
| **Reactivation condition** | When PR 9 opens. |
| **Rollback** | n/a — nothing was changed. No authorization exists to close it. |

## Issue #61 — [Task] macOS arm64 support for the issue-bound agent runner

| Field | Value |
|---|---|
| **Status** | **OPEN.** Not closed, contract not rewritten. Informational comment added 2026-07-17. |
| **Baseline** | `7815949e` |
| **Function** | Adds first-class macOS arm64 support to the runner. |
| **Deferral reason** | Partly **resolved by the migration itself**: MUCC's workflow is portable by design (G5, multi-platform NFR), so the macOS contributor is unblocked at the *workflow* level without this task. What remains is macOS support for the *runner*, which is a PR 9 concern. |
| **Future MUCC destination** | Prerequisite for `styx-hardened` on macOS — and a hard one, since the sandbox is `bubblewrap`, i.e. Linux-only. This is the concrete form of MUCC's "lock-in Linux" objection. |
| **Reactivation condition** | PR 9. |
| **Rollback** | n/a — nothing was changed. |

## Issue #62 — [Task] Risk-based runner profiles and checkpoint enforcement

| Field | Value |
|---|---|
| **Status** | **OPEN.** Not closed, contract not rewritten. Informational comment added 2026-07-17. |
| **Baseline** | `7815949e` |
| **Function** | Risk-based runner profiles and checkpoint enforcement. |
| **Deferral reason** | Conceptually overlaps MUCC's executor profiles (v0.38), which arrive with the adoption. Deferring avoids building the same abstraction twice, in two incompatible shapes. |
| **Future MUCC destination** | Merge into MUCC's profile model rather than parallel to it. Styx's risk-based dimension is the natural argument for a third profile beyond `human`/`bot` — which is exactly what NG-E currently defers. |
| **Reactivation condition** | PR 9, as the upstream proposal for `styx-hardened`. |
| **Rollback** | n/a — nothing was changed. |

---

## macOS candidate `fbdbfd5` — ⚠️ unreachable, at risk

| Field | Value |
|---|---|
| **Status** | **NOT REACHABLE from this session or from CI. Not archived. At risk of permanent loss.** |
| **Baseline** | Unknown — not an ancestor of `7815949e` as far as can be determined here. |
| **Function** | Local macOS arm64 candidate for Issue #61, on Massimiliano's Mac. |
| **Deferral reason** | Never pushed. It exists only on one machine. |
| **Future MUCC destination** | Input to PR 9, **if it survives**. |
| **Reactivation condition** | Must be archived first. It cannot be reactivated from anywhere else. |
| **Rollback** | **None. There is no recovery path from this side.** |

Verified on 2026-07-17 from this session:

```
$ git cat-file -t fbdbfd5
fatal: Not a valid object name fbdbfd5
$ git ls-remote origin | grep -i fbdbfd5
(no match)
```

It has **not** been reconstructed, invented or substituted, and it must not be.

**Required action, before any rebase, branch deletion or `gc` on that machine:**

```bash
git bundle create styx-61-macos-candidate.bundle <branch-or-sha>
# or push an archive branch
git push origin <sha>:refs/heads/archive/issue-61-macos-candidate
```

Two honest caveats. First, the short SHA `fbdbfd5` comes from the migration briefing, **not
from Issue #61's body** — the Issue never recorded it, so the abbreviation is uncorroborated
by this repository and the real ref should be confirmed on the Mac before archiving. Second,
the comment on #61 is a warning, not a protection: nothing in this repository can prevent the
loss. If that work has value, archive it now.
