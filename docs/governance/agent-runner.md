# Styx issue-bound agent runner

## Purpose

The runner turns one approved GitHub Issue into a deterministic local execution
boundary for Claude Code. GitHub remains authoritative. The runner does not
discover work, claim work, push, open a pull request, approve, mark Ready, queue,
or merge.

The supported interactive entrypoint is:

```text
/styx-run #50
```

The equivalent local commands are:

```bash
python3 tools/agent-runner/styx-agent check
python3 tools/agent-runner/styx-agent provision
python3 tools/agent-runner/styx-agent verify
python3 tools/agent-runner/styx-agent run --issue 50
```

## Supported environment

The v1 runner supports Ubuntu 26.04 on x86_64. It records the resolved executable
path and detected version for every required tool. Baseline requirements are:

- Python 3.11 or newer;
- Git 2.39 or newer;
- GitHub CLI 2.x with read authentication;
- Claude Code 2.1.195 or newer;
- task-specific tools inferred from the Issue's exact test commands.

Missing or incompatible system tools produce `BLOCKED_ADMIN_PROVISIONING`.
The runner never invokes `sudo`, APT, Snap, systemd, a remote shell installer, or
a system daemon.

## User-space provisioning

`provision` creates only a verified launcher in the runner-owned XDG data
directory:

```text
$XDG_DATA_HOME/styx-agent-runner/bin/styx-agent
```

The launcher is written atomically, mode `0700`, and verified by SHA-256.
Existing non-matching bytes are never overwritten. No shell profile or persistent
`PATH` is changed.

Runner-owned directories can be overridden for isolated automation:

```text
STYX_AGENT_DATA_DIR
STYX_AGENT_CACHE_DIR
STYX_AGENT_STATE_DIR
STYX_AGENT_WORKTREE_ROOT
```

Each value is treated as a parent directory; the runner appends
`styx-agent-runner` to the first three.

## Issue contract

`run --issue N` accepts one positive integer only. It retrieves exactly
`styx-secure/styx#N` through `gh api --method GET`, preserves the Issue body as
UTF-8 bytes, and invokes the existing `styx-task-contract:v1` parser.

The Base section must contain exactly:

```text
`main @ <lowercase-full-40-hex-SHA>`
```

Only dependencies declared with this exact syntax are blocking:

```text
- Required closed Issue: #46.
```

The period is optional only when it is outside the strict declaration line; the
recommended declaration is without punctuation:

```text
- Required closed Issue: #46
```

Required tests come from the single fenced block under `Required tests` or
`Required verification`. Commands containing system administration or GitHub
write operations are rejected before execution.

## Lifecycle

On the first valid `run`:

1. the source checkout must be clean, point to `styx-secure/styx`, and have
   `HEAD` and local `main` at the Issue's exact base SHA;
2. declared dependencies must be closed Issues;
3. the environment must verify;
4. the base objects are copied into a runner-owned bare Git store under the XDG
   state directory; its default remote is removed;
5. a linked worktree and branch are created from that private store under the
   runner state directory, leaving the source repository and its `.git` metadata
   read-only;
6. the branch is named `task/<issue>-<slug>`;
7. an execution manifest and status report are written;
8. terminal status is `READY_FOR_IMPLEMENTATION`, exit `0`.

Claude then works only inside that worktree. After the implementation is clean
and committed, the same `run` command:

1. re-fetches the Issue and rejects contract drift;
2. verifies the task branch descends from the original base;
3. runs every exact required test;
4. creates a temporary clean trusted-base worktree from the private object
   store and invokes the trusted scope guard there, while inspecting the task
   head only as Git object data;
5. removes that temporary guard worktree;
6. requires verdict `PASS`;
7. emits `BLOCKED_BROKER_UNAVAILABLE`, exit `2`.

That final exit `2` is the expected successful local handoff. A future restricted
broker must perform only:

```text
push_task_branch
open_draft_pr
```

## Status and evidence

Canonical status reports use:

```text
styx.agent-runner-status/v1
```

and are written to:

```text
$XDG_STATE_HOME/styx-agent-runner/runs/
```

Scope reports and preserved Issue bytes are under the runner-owned evidence
directory. Reports contain hashes of test stdout/stderr, not their raw content.
Known token formats, authorization headers, userinfo URLs, and secret-valued
environment variables are redacted from error text.

Exit classes:

- `0`: the currently authorized local phase completed;
- `2`: a human, administrator, authentication, or broker gate is required;
- `3`: contract, drift, environment, evidence, or internal failure.

## Claude Code controls

`.claude/settings.json` does not grant any new permission. It disables bypass
permissions mode, makes the source checkout read-only in the sandbox, allows
writes only in the runner-owned XDG directories, denies direct GitHub/network
clients and system administration, denies direct Claude Read access to common
GitHub/SSH credential files, and registers standard-library hooks.

The PreToolUse hook rejects:

- writes without an active issue-bound task;
- file-tool writes outside the active worktree;
- paths outside the Issue allowlist or inside its forbidden list;
- Git network/ref-administration operations such as push, fetch, remotes,
  worktrees, submodules and update-ref;
- every direct `gh` invocation; the runner performs the only permitted read-only
  GitHub request internally;
- direct curl, wget and SSH-family clients;
- common GitHub CLI, SSH, netrc and Git credential-file paths;
- approval, Ready, auto-merge, Merge Queue, and merge operations;
- `sudo`, package-manager and service-manager commands;
- obvious absolute shell write targets outside the worktree and runner-owned XDG
  directories.

The Stop hook blocks completion while an active task lacks committed work,
mandatory PASS tests, or PASS scope evidence. Hooks fail closed on malformed
state. They reduce accidental misuse but are not a security boundary against a
compromised host. This increment also does not claim hostile task-code
containment: exact test commands run on the same developer host inside Claude's
configured sandbox, so only human-approved Issue contracts and repositories may
be executed.

## Headless use

A non-interactive caller may invoke Claude with the project skill, but must
preconfigure only the minimum permissions needed for local work. Do not use
`--dangerously-skip-permissions` on the developer host.

The caller should interpret `BLOCKED_BROKER_UNAVAILABLE` as the expected local
completion boundary and surface the status-report path to the operator.

## Cleanup

Cleanup is always explicit. Before removing a runner worktree, inspect it:

```bash
STATE_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/styx-agent-runner"
git --git-dir="$STATE_ROOT/git/styx.git" worktree list
git -C "$STATE_ROOT/worktrees/issue-N" status --short
```

After confirming that its commits are preserved elsewhere:

```bash
git --git-dir="$STATE_ROOT/git/styx.git" worktree remove \
  "$STATE_ROOT/worktrees/issue-N"
git --git-dir="$STATE_ROOT/git/styx.git" branch -d task/N-slug
```

Runner-owned state may then be removed selectively:

```bash
rm -rf "$XDG_STATE_HOME/styx-agent-runner"
rm -rf "$XDG_CACHE_HOME/styx-agent-runner"
rm -rf "$XDG_DATA_HOME/styx-agent-runner"
```

Never delete an unrelated worktree, branch, XDG directory, credential store, or
user shell file.

## Human and broker gates

The runner cannot satisfy:

- authentication setup;
- administrator/system provisioning;
- contract or scope expansion;
- settings/hook security acceptance;
- Ready-for-review authorization;
- merge authorization;
- automatic task selection or claim;
- any GitHub write before the restricted broker exists.
