---
name: styx-run
description: Execute one explicit approved Styx Issue locally until a human, administrator, authentication, or restricted-broker gate is reached.
argument-hint: "#<issue-number>"
disable-model-invocation: true
disallowed-tools: AskUserQuestion
---

Execute exactly one issue-bound Styx task. The invocation argument is `$ARGUMENTS`.

1. Reject unless the argument is exactly one local reference matching `#[1-9][0-9]*`. Do not infer, search for, rank, or select another task.
2. Read `AGENTS.md` and `CLAUDE.md`. They remain authoritative.
3. From the repository root, derive the numeric Issue exactly once and run:
   ```bash
   ISSUE_REF='$ARGUMENTS'
   case "$ISSUE_REF" in
     \#*) ;;
     *) echo "invalid Styx Issue reference" >&2; exit 3 ;;
   esac
   ISSUE_NUMBER="${ISSUE_REF#\#}"
   case "$ISSUE_NUMBER" in
     ""|0*|*[!0-9]*) echo "invalid Styx Issue reference" >&2; exit 3 ;;
   esac
   python3 tools/agent-runner/styx-agent check --execution-id "issue-${ISSUE_NUMBER}-check"
   python3 tools/agent-runner/styx-agent provision --execution-id "issue-${ISSUE_NUMBER}-provision"
   python3 tools/agent-runner/styx-agent verify --execution-id "issue-${ISSUE_NUMBER}-verify"
   python3 tools/agent-runner/styx-agent run --issue "$ISSUE_NUMBER" --execution-id "issue-${ISSUE_NUMBER}"
   ```
   A status `READY_FOR_IMPLEMENTATION` with exit `0` means the local phase is prepared, not complete.
4. Read the generated execution manifest and authoritative Issue. Work only in the manifest worktree and branch. Do not modify the source checkout.
5. Implement only the allowed paths. Forbidden paths win. Do not broaden scope, alter dependencies, install system software, invoke `sudo`, or perform any GitHub write.
6. Run the exact tests from the manifest while developing. Commit small coherent changes with English messages containing `Refs #<issue>`.
7. When the worktree is clean and committed, rerun:
   ```bash
   python3 tools/agent-runner/styx-agent run --issue "$ISSUE_NUMBER" --execution-id "issue-${ISSUE_NUMBER}"
   ```
8. Continue correcting only in-scope failures until the runner reports verified tests and scope evidence.
9. Stop successfully only at `BLOCKED_BROKER_UNAVAILABLE`. Report the branch, worktree, commit SHA, tests, scope verdict, status-report path, and the two broker operations required: `push_task_branch` and `open_draft_pr`.
10. For any other exit `2`, report the exact human/admin/authentication remediation. For exit `3`, stop and report the failure evidence. Never bypass a hook, permission rule, contract check, or human gate.

Never push, create or modify an Issue/PR, approve, mark Ready, enable auto-merge, enter Merge Queue, or merge.
