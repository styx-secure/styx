# Claude Code project profile

This directory holds the project-level Claude Code configuration for
`styx-secure/styx`. Since Task #80 it is a **MUCC-compatible profile**: it never
blocks, and it keeps the project-owned permission boundary that MUCC expects to
be reviewed as code.

## What is active

`settings.json` declares:

- `disableBypassPermissionsMode: "disable"` — permission bypass stays off.
- `defaultMode: "default"` — anything not explicitly allowed prompts the human
  instead of running silently. This is intentional: with the Styx hook layers
  deregistered, silent auto-approval would remove the human from the loop.
- A deny list for credential reads (`~/.ssh`, `~/.aws`, `~/.gnupg`, gh/git
  config, `~/.netrc`, …), privilege escalation (`sudo`, package managers,
  service managers) and raw network channels (`curl`, `wget`, `ssh`, `nc`, …).

No hooks are registered here and no OS sandbox is declared. MUCC's own hooks
live at the user level (`~/.claude/settings.json`, merged by MUCC's
`install.sh`), are all `decision: warn`, and MUCC rests no guarantee on Claude
Code hooks (SPEC-dev-multidev-coordination-v0.36.0 §6.5.2). Enforcement lives
in explicit scripts and server-side GitHub configuration, not in this profile.

## What is preserved, inactive

The Styx agent-platform hook scripts and skill are **deferred, not removed**:

- `hooks/read_only_guard.py`
- `hooks/styx_guard.py`
- `hooks/worktree_integrity.py`
- `skills/styx-run/SKILL.md`

They are no longer registered in `settings.json`, so they never run, but they
remain tracked and byte-identical to their last active state. Context:

- Decision: `docs/governance/adr/ADR-0006-adopt-mucc-multidev.md`
- Inventory: `docs/governance/deferred/styx-agent-platform-inventory.md`
- Preservation point: tag `styx-agent-platform-v0.1-deferred-2026-07-17`
  (commit `7815949e49e4a2d376161e8324b8eed5e1a7ce11`)

## Reactivation and the force-add trap

To restore the blocking Styx profile, revert the Task #80 change to
`settings.json`; the hook scripts need no restoration because they never left
the tree.

Trap to remember: the repository `.gitignore` lists `.claude/`, so every file
in this directory was force-added. If any of these files is ever deleted from
the index, re-adding it requires `git add -f` — a plain `git add` will silently
do nothing.

`.claude/**` is a human-gate area under `AGENTS.md`: every change here requires
human review before merge.
