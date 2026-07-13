---
name: styx-run
description: Execute one explicit approved Styx Issue locally until a human, administrator, authentication, or restricted-broker gate is reached.
argument-hint: "#<issue-number>"
disable-model-invocation: true
disallowed-tools: AskUserQuestion
---

Execute exactly one issue-bound Styx task. The invocation argument is `$ARGUMENTS`.

1. Before invoking any tool, reject unless the argument is exactly one local reference matching `#[1-9][0-9]*`. Do not infer, search for, rank, or select another task.
2. Read `AGENTS.md` and `CLAUDE.md`. They remain authoritative.
3. Extract the decimal digits as `N`. Execute exactly one simple Bash command from the repository root, replacing both `N` placeholders with those digits and adding no shell operators, substitutions, redirects, quoting tricks, or extra commands:
   ```text
   python3 tools/agent-runner/styx-agent run --issue N --execution-id issue-N
   ```
   A status `READY_FOR_IMPLEMENTATION` with exit `0` means the local phase is prepared, not complete. Any non-zero exit is a mandatory stop until its documented remediation is satisfied.
4. From the runner JSON, use the returned worktree path. Read the authoritative execution manifest at `${STYX_AGENT_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}}/styx-agent-runner/active.json`. Work only in that manifest worktree and branch. Do not modify the source checkout.
5. Implement only the allowed paths. Forbidden paths win. Do not broaden scope, alter dependencies, install system software, invoke `sudo`, or perform any GitHub or network operation.
6. Run the exact tests from the manifest while developing. Commit small coherent changes with English messages containing `Refs #<issue>`.
7. When the worktree is clean and committed, execute the same single runner command again from the read-only source repository root, without shell chaining.
8. Continue correcting only in-scope failures until the runner reports verified tests and scope evidence.
9. Stop successfully only at `BLOCKED_BROKER_UNAVAILABLE`. Report the branch, worktree, commit SHA, tests, scope verdict, status-report path, and the two broker operations required: `push_task_branch` and `open_draft_pr`.
10. For any other exit `2`, report the exact human/admin/authentication remediation. For exit `3`, stop and report the failure evidence. Never bypass a hook, permission rule, contract check, or human gate.

Never push, create or modify an Issue/PR, approve, mark Ready, enable auto-merge, enter Merge Queue, or merge.
