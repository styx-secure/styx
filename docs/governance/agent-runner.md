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
python3 tools/agent-runner/styx-agent run --issue 50 --execution-id issue-50
```

The project defaults Claude Code to `dontAsk` mode, declares the runner worktree
root as an additional directory, and pre-approves only the bounded local tool
classes. The normal task loop therefore does not pause for permission prompts.
Hooks and the operating-system sandbox still deny operations outside the Issue
contract.

## Supported environment

The v1 runner supports Ubuntu 26.04 on x86_64. It records the resolved executable
path and detected version for every required tool. Baseline requirements are:

- Python 3.11 or newer;
- Git 2.39 or newer;
- Claude Code 2.1.195 or newer;
- bubblewrap 0.8 or newer;
- task-specific tools inferred from the Issue's exact test commands.

GitHub CLI and GitHub credentials are not required. Public Issue and dependency
reads use a standard-library HTTPS client with a fixed `api.github.com` endpoint,
GET only, no redirects, no token, strict response validation, and a one-MiB size
limit.

Missing or incompatible system tools produce `BLOCKED_ADMIN_PROVISIONING`. The
runner never invokes `sudo`, APT, Snap, systemd, a remote shell installer, or a
system daemon. On Ubuntu, installation of bubblewrap is an operator action, for
example:

```bash
sudo apt install bubblewrap
```

Run that command outside Claude, review the package transaction, then rerun the
Styx command.

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
STYX_AGENT_TRUST_DIR
```

The first three values are treated as parent directories and receive the
`styx-agent-runner` suffix. `STYX_AGENT_TRUST_DIR` is a separate trusted hook
location and must never be placed inside a task-writable directory.

## Issue contract

`run --issue N` accepts one positive integer only. It retrieves exactly
`styx-secure/styx#N` through the anonymous public reader, preserves the Issue body
as UTF-8 bytes, and invokes the existing `styx-task-contract:v1` parser.

The Base section must contain exactly:

```text
`main @ <lowercase-full-40-hex-SHA>`
```

Only dependencies declared with this exact syntax are blocking:

```text
- Required closed Issue: #46
```

Required tests come from the single fenced block under `Required tests` or
`Required verification`. Commands containing system administration, GitHub
operations, direct network clients, or credential paths are rejected before
execution.

## Lifecycle

On the first valid `run`:

1. the source checkout must be clean, point to `styx-secure/styx`, and have
   `HEAD` and local `main` at the Issue's exact base SHA;
2. the Issue and declared dependencies are read anonymously and validated;
3. the environment, including bubblewrap, must verify;
4. the base objects are copied into a runner-owned bare Git store under the XDG
   state directory; its default remote is removed;
5. a linked worktree and branch are created from that private store under the
   runner state directory, leaving the source repository and its `.git` metadata
   read-only;
6. the branch is named `task/<issue>-<slug>`;
7. an execution manifest and status report are written;
8. a dedicated integrity hook verifies that the worktree `.git` pointer is a
   regular file resolving only into the private bare store and that Git's common
   directory and toplevel match the declared task worktree;
9. the PostToolUse hook writes a trusted hash attestation outside all task-write
   paths;
10. terminal status is `READY_FOR_IMPLEMENTATION`, exit `0`.

Claude then works only inside that worktree. The Claude Bash sandbox has no
network and may write only the task worktree and the private Git object store
needed for commits. It cannot write `active.json`, runner reports, scope evidence,
temporary guard worktrees, or hook attestations.

After the implementation is clean and committed, the same `run` command:

1. re-fetches the Issue anonymously and rejects contract drift;
2. verifies the task branch descends from the original base;
3. runs every exact required test inside a nested bubblewrap sandbox;
4. gives that test sandbox no network, a read-only root filesystem, a writable
   task worktree, ephemeral caches, and masked GitHub/SSH/netrc/Git credential
   locations;
5. creates a temporary clean trusted-base worktree from the private object store
   and invokes the trusted scope guard there, while inspecting the task head only
   as Git object data;
6. removes that temporary guard worktree;
7. requires every test and the scope verdict to be `PASS`;
8. emits `BLOCKED_BROKER_UNAVAILABLE`, exit `2`;
9. the PostToolUseFailure hook, which handles the expected non-zero handoff exit,
   independently hashes and attests the final state, report, scope report, branch,
   HEAD, clean status, changed paths, and private Git metadata.

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

Trusted hook attestations use:

```text
styx.agent-hook-attestation/v1
```

and are stored by default at:

```text
$HOME/.local/state/styx-agent-runner-trust/active-attestation.json
```

The task sandbox cannot read or write this location. A trusted hook compares the
attestation against the real regular files and Git state before each mutating
tool call, after each tool call or batch, and at Stop. Symlinked evidence,
duplicate JSON keys, path escape, changed `.git` metadata, state/report changes,
dirty final worktrees, non-PASS tests, non-PASS scope evidence, or a different
HEAD fail closed.

Exit classes:

- `0`: the currently authorized local phase completed;
- `2`: a human, administrator, authentication, or broker gate is required;
- `3`: contract, drift, environment, evidence, or internal failure.

## Claude Code controls

`.claude/settings.json` disables bypass mode and selects `dontAsk` so the bounded
workflow is non-interactive. It registers the external worktree root in
`permissions.additionalDirectories`. `Bash` and worktree file tools are
pre-approved, but remain constrained by deny rules, standard-library hooks, and
the operating-system sandbox.

The settings enforce:

- source checkout read-only;
- task writes only to the dedicated worktree and its private Git store;
- runner state, reports, evidence, guard worktrees, and trust attestations not
  task-writable;
- task network denied;
- direct reads of GitHub CLI, SSH, netrc, Git credential files, and the trust
  directory denied;
- direct `gh`, curl, wget, SSH-family tools, socket tools, Git publication/ref
  administration, `sudo`, package managers, and service managers denied;
- only the exact `styx-agent run --issue N --execution-id issue-N` family excluded
  from the Claude Bash sandbox, with the PreToolUse hook accepting one exact
  unchained command from the project root.

The PreToolUse hooks reject malformed or chained runner commands, another Issue,
writes without an active task, file-tool writes outside the worktree, forbidden
paths, dangerous commands, source-checkout commands, repointed/symlinked `.git`
metadata, and any continuation after state or evidence no longer matches its
trusted attestation.

PostToolUse and PostToolBatch inspect the real Git diff plus untracked files, not
shell syntax. An out-of-scope path or symlink blocks the next agent step. The Stop
hook accepts completion only at the final broker handoff with a matching trusted
attestation and freshly verified Git/evidence state.

Hooks run with the user's privileges and are therefore trusted code, not task
code. They reduce accidental or model-driven misuse but are not a security
boundary against a compromised operating system or human account.

## Headless use

The project setting uses `permissions.defaultMode: dontAsk`, so the same skill can
run non-interactively without `--dangerously-skip-permissions`. Do not enable
bypass mode on the developer host.

A caller should interpret `BLOCKED_BROKER_UNAVAILABLE` as the expected local
completion boundary and surface the status-report path, task branch, HEAD, test
results, and scope verdict to the operator.

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
rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/styx-agent-runner"
rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/styx-agent-runner"
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/styx-agent-runner"
rm -rf "$HOME/.local/state/styx-agent-runner-trust"
```

Never delete an unrelated worktree, branch, XDG directory, credential store, or
user shell file.

## Human and broker gates

The runner cannot satisfy:

- administrator/system provisioning such as installing bubblewrap;
- private-repository authentication or an unavailable public GitHub API;
- contract or scope expansion;
- settings/hook security acceptance;
- Ready-for-review authorization;
- merge authorization;
- automatic task selection or claim;
- any GitHub write before the restricted broker exists.
