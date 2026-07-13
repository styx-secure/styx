#!/usr/bin/env python3
"""Validate that the active task worktree still belongs to the private Git store."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Mapping


class IntegrityError(Exception):
    pass


def _state_root(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    home = Path(env.get("HOME", str(Path.home())))
    base = Path(env.get("STYX_AGENT_STATE_DIR", env.get("XDG_STATE_HOME", str(home / ".local/state"))))
    return (base / "styx-agent-runner").resolve()


def _worktree_root(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    return Path(env.get("STYX_AGENT_WORKTREE_ROOT", str(_state_root(env) / "worktrees"))).resolve()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _regular_bytes(path: Path, *, limit: int) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise IntegrityError(f"required file is unavailable: {path.name}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise IntegrityError(f"required file is not a regular file: {path.name}")
    if info.st_size > limit:
        raise IntegrityError(f"required file exceeds its size limit: {path.name}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise IntegrityError(f"unable to read required file: {path.name}") from exc


def _load_active() -> dict[str, Any] | None:
    path = _state_root() / "active.json"
    if not path.exists():
        return None
    try:
        value = json.loads(_regular_bytes(path, limit=4_194_304).decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError("active runner state is malformed") from exc
    if not isinstance(value, dict):
        raise IntegrityError("active runner state has an invalid shape")
    return value


def _git_path(worktree: Path, args: list[str]) -> Path:
    environment = os.environ.copy()
    for key in tuple(environment):
        if key == "GIT_CONFIG_COUNT" or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key, None)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    try:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", *args],
            cwd=worktree,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise IntegrityError("unable to verify worktree Git metadata") from exc
    if result.returncode != 0 or not result.stdout.strip():
        raise IntegrityError("Git rejected the active worktree metadata")
    value = Path(result.stdout.strip())
    return (worktree / value).resolve() if not value.is_absolute() else value.resolve()


def verify_active_worktree() -> None:
    state = _load_active()
    if state is None:
        return
    raw_worktree = state.get("worktree")
    if not isinstance(raw_worktree, str) or not raw_worktree:
        raise IntegrityError("active state is missing the worktree")
    worktree = Path(raw_worktree).resolve(strict=False)
    if not _inside(worktree, _worktree_root()):
        raise IntegrityError("active worktree escapes the configured worktree root")
    if not worktree.is_dir():
        raise IntegrityError("active worktree does not exist")

    git_file = worktree / ".git"
    raw = _regular_bytes(git_file, limit=4096)
    try:
        line = raw.decode("utf-8", "strict").strip()
    except UnicodeError as exc:
        raise IntegrityError("worktree .git pointer is not UTF-8") from exc
    if "\n" in line or not line.startswith("gitdir: "):
        raise IntegrityError("worktree .git pointer has an invalid shape")
    pointer_text = line[len("gitdir: "):]
    if not pointer_text:
        raise IntegrityError("worktree .git pointer is empty")
    pointer = Path(pointer_text)
    pointer = (worktree / pointer).resolve() if not pointer.is_absolute() else pointer.resolve()

    private_store = (_state_root() / "git" / "styx.git").resolve()
    private_worktrees = (private_store / "worktrees").resolve()
    if not _inside(pointer, private_worktrees):
        raise IntegrityError("worktree .git pointer escapes the private Git store")
    try:
        pointer_info = pointer.lstat()
    except OSError as exc:
        raise IntegrityError("worktree Git directory is unavailable") from exc
    if stat.S_ISLNK(pointer_info.st_mode) or not stat.S_ISDIR(pointer_info.st_mode):
        raise IntegrityError("worktree Git directory is not a real directory")

    git_dir = _git_path(worktree, ["rev-parse", "--git-dir"])
    common_dir = _git_path(worktree, ["rev-parse", "--git-common-dir"])
    top = _git_path(worktree, ["rev-parse", "--show-toplevel"])
    if git_dir != pointer:
        raise IntegrityError("Git resolved a different worktree metadata directory")
    if common_dir != private_store:
        raise IntegrityError("Git common directory is not the private object store")
    if top != worktree:
        raise IntegrityError("Git toplevel does not match the active worktree")


def _deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    mode = argv[0] if argv else "pre"
    try:
        verify_active_worktree()
        return 0
    except IntegrityError as exc:
        output = _deny(str(exc)) if mode == "pre" else {"decision": "block", "reason": str(exc)}
        print(json.dumps(output, separators=(",", ":")))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
