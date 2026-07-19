# Ruleset proposal — make human review enforcement, not policy

- **Task:** #82 · **Epic:** #65 · **Plan:** [migration-plan.md](migration-plan.md) (Task 4)
- **Target:** ruleset `main branch protection`, id `18814814`
- **Applied by:** a human, in the GitHub UI or via `gh api`. Agents must never
  change rulesets, in any direction, at any time.

## Why

Since ADR-0006 the declared rules are: mandatory human review, squash merge
only, no self-approve. Today the ruleset enforces only part of that:
`required_approving_review_count` is `0` and `Agent scope evidence
(observation)` is not a required status check. Review and scope compliance are
therefore **policy upheld by discipline, not enforced by the repository** — the
residual risk recorded in Epic #65, Task #66 and Task #80. MUCC's
`github-setup.md` §1 requires approvals ≥ 1 plus review from someone other
than the last pusher, and §3 calls the server-side CI scope check "the real
enforcement". This proposal closes that gap.

## Current state (verified 2026-07-19 via `gh api repos/styx-secure/styx/rulesets/18814814`)

| Setting | Value today |
|---|---|
| enforcement | `active`, on `refs/heads/main` |
| bypass_actors | none |
| deletion / non_fast_forward / required_linear_history | protected |
| allowed_merge_methods | `squash` only |
| required_approving_review_count | **0** |
| require_last_push_approval | **false** |
| required_review_thread_resolution | true |
| required status checks (strict policy) | `Dart reference stack gate` · `styx-js web gate` · `WASM integrity gate` · `Analyze (javascript-typescript)` |

## Proposed changes — exactly three

1. `required_approving_review_count`: `0` → **`1`**
2. `require_last_push_approval`: `false` → **`true`** — the reviewer must be
   someone other than the last pusher. This is the setting that makes
   no-self-approve real: all executors share the operator's `gh` identity, so
   only a server-side rule can force a second pair of eyes.
3. Add **`Agent scope evidence (observation)`** (integration_id `15368`) to
   `required_status_checks`. The context string must match the job name in
   `agent-scope-evidence.yml` verbatim — it is a frozen interface; renaming
   the job silently detaches this entry.

Nothing else changes: squash-only, linear history, thread resolution, no
bypass actors, and the strict up-to-date policy all stay as they are.

## Choose the application profile first — solo-operator caveat

GitHub never lets the author of a pull request approve it, and every task PR
in this repository is authored under the operator's own `gh` identity (the
executors share it — SPEC §7 threat model). Consequences:

- With `required_approving_review_count: 1`, **self-authored task PRs become
  unmergeable for a solo operator**: the author cannot approve, nobody else
  exists, and the ruleset binds admins too (`bypass_actors` is empty).
  Dependabot PRs stay mergeable (their author is the bot).
- MUCC's model in `github-setup.md` §1 implicitly assumes **at least two human
  identities**. Decide which profile applies before touching anything:

**Profile A — two identities (full MUCC model).** A second account with Write
access reviews and approves task PRs from a clean context. Apply all three
changes. This is the only profile in which "no self-approve" is truly
enforced.

**Profile B — solo operator.** Apply **only change 3** (make the scope check
required); leave `required_approving_review_count` at `0` and
`require_last_push_approval` at `false`. Scope compliance becomes real
server-side enforcement; review remains policy. Record that the review-gap
residual risk of Epic #65 stays open until a second identity exists, and
upgrade to Profile A then — the payload below applies unchanged.

## Application order — mandatory

**Merge the Task #82 pull request first, apply this ruleset second.**

The workflow change in that PR gates the scope check to `task/*` branches.
Before it, every non-task PR (all dependabot PRs, `fix/*`, `feat/*`) fails the
scope check with `E_CI_ISSUE_REFERENCE_MISSING` — at the time of writing, PRs
#77, #78 and #79 are all red on it. Making the check required before the
filter is merged would block every maintenance PR in the repository.

Open PRs self-heal: `pull_request_target` runs the workflow definition from
`main`, and the strict up-to-date policy forces a synchronize before merge
anyway, so their next run uses the filtered workflow and turns to skip.

## How to apply

UI: *Settings → Rules → Rulesets → main branch protection*, set the three
values above.

CLI (single idempotent update; re-run `gh api repos/styx-secure/styx/rulesets/18814814`
first and abort if the current state no longer matches the table above). The
payload below is **Profile A**; for **Profile B** keep
`"require_last_push_approval": false` and
`"required_approving_review_count": 0` and change only the status-check list:

```bash
gh api --method PUT repos/styx-secure/styx/rulesets/18814814 --input - <<'EOF'
{
  "name": "main branch protection",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    {
      "type": "pull_request",
      "parameters": {
        "allowed_merge_methods": ["squash"],
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": true,
        "required_approving_review_count": 1,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "do_not_enforce_on_create": false,
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "Dart reference stack gate", "integration_id": 15368 },
          { "context": "styx-js web gate", "integration_id": 15368 },
          { "context": "WASM integrity gate", "integration_id": 15368 },
          { "context": "Analyze (javascript-typescript)", "integration_id": 15368 },
          { "context": "Agent scope evidence (observation)", "integration_id": 15368 }
        ]
      }
    }
  ]
}
EOF
```

Rollback: re-apply the same payload with the three values reverted to the
"Current state" table above.

## Residual bypass, analysed and accepted

A PR from a branch not named `task/*` skips the scope check by design: GitHub
counts a skipped required check as satisfied — the same green-skip convention
the four existing gates already rely on. Consequences:

- An agent could open a PR from a non-task branch and present no scope
  evidence. It cannot merge it alone: `require_last_push_approval` puts a
  human reviewer in front of every merge, and `AGENTS.md` requires agent work
  to happen on task branches — a reviewer seeing agent work without scope
  evidence has, by policy, a reason to reject.
- Dependabot and human maintenance PRs keep working exactly as today, with
  one human review now enforced.

## Decisions settled by Task 4 (from the migration plan)

1. **Scope check: Styx's `agent-scope-evidence` stays; MUCC's `scope-guard.ts`
   is not vendored.** The Styx contract parser is stricter, it is wired to
   Issue contracts, and `tools/agent-enforcement` is imported at runtime by
   `tools/test-orchestrator/contract_inputs.py`. MUCC's guard reads contract
   blocks from story files under `specs/` that will not exist before the
   backlog adoption task; the branch namespaces (`task/N-*` vs `task/US-*`)
   let both run side by side if that task decides to add it.
2. **Test checks: the four existing required gates satisfy MUCC's test
   requirement.** No database in this repository, so the v0.39
   ephemeral-Postgres and migration-head-check notes do not apply.

## Recommended human follow-up (out of scope here)

MUCC's `github-setup.md` §2 recommends a `CODEOWNERS` file for the human-gate
areas (`.github/workflows/`, `.claude/`, `tools/agent-enforcement/`,
lockfiles). Creating or changing `CODEOWNERS` is a human-only operation under
the standing mandate and is intentionally not part of any agent task.
