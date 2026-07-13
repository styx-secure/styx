#!/usr/bin/env python3
"""Fail-closed Claude Code hooks for the active Styx task runner."""

from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
from typing import Any, Mapping

WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
DANGEROUS_BASH = (
    re.compile(r"(^|[;&|()])\s*(sudo|apt|apt-get|dpkg|snap|systemctl|service)\b", re.I),
    re.compile(r"\bgit\s+push\b", re.I),
    re.compile(r"\bgh\s+(?:pr|issue|release|repo)\s+(?:create|edit|comment|close|reopen|delete|merge|ready|review)\b", re.I),
    re.compile(r"\bgh\s+api\b.*(?:--method|-X)\s+(?!GET\b)", re.I),
    re.compile(r"\bgh\s+api\s+graphql\b.*\bmutation\b", re.I),
    re.compile(r"(curl|wget)[^|;\n]*\|\s*(?:ba)?sh\b", re.I),
)
REDIRECT_RE = re.compile(r"(?:^|[\s;|&])(?:>|>>|2>|2>>|tee(?:\s+-a)?)\s*([\"']?)(/[^\s\"']+)\1")
COPY_TARGET_RE = re.compile(r"(?:^|[;&|]\s*|\s)(?:cp|mv|install)\b[^\n;|&]*\s([\"']?)(/[^\s\"']+)\1")


class HookError(Exception):
    pass


def _state_root(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    home = Path(env.get("HOME", str(Path.home())))
    base = Path(env.get("STYX_AGENT_STATE_DIR", env.get("XDG_STATE_HOME", str(home / ".local/state"))))
    return (base / "styx-agent-runner").resolve()


def _load_state(env: Mapping[str, str] | None = None) -> dict[str, Any] | None:
    path = _state_root(env) / "active.json"
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HookError("active runner state is unreadable") from exc
    if not isinstance(value, dict):
        raise HookError("active runner state has an invalid shape")
    return value


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _valid_repo_path(path: str) -> bool:
    if not path or path.startswith("/") or "\\" in path:
        return False
    parts = path.split("/")
    return all(part not in {"", ".", ".."} for part in parts) and str(PurePosixPath(path)) == path


def pattern_matches(pattern: str, path: str) -> bool:
    if not _valid_repo_path(path):
        return False
    pattern_parts = pattern.split("/")
    path_parts = path.split("/")
    total = len(path_parts)
    suffix = [index == total for index in range(total + 1)]
    for segment in reversed(pattern_parts):
        if segment == "**":
            reachable = suffix[total]
            folded = [False] * (total + 1)
            folded[total] = reachable
            for index in range(total - 1, -1, -1):
                reachable = reachable or suffix[index]
                folded[index] = reachable
        else:
            folded = [False] * (total + 1)
            for index in range(total):
                folded[index] = suffix[index + 1] and fnmatch.fnmatchcase(path_parts[index], segment)
        suffix = folded
    return suffix[0]


def _path_allowed(path: Path, state: Mapping[str, Any]) -> tuple[bool, str]:
    worktree = Path(str(state.get("worktree", ""))).resolve(strict=False)
    if not _inside(path, worktree):
        return False, "write target is outside the active task worktree"
    try:
        relative = path.resolve(strict=False).relative_to(worktree).as_posix()
    except ValueError:
        return False, "unable to normalize write target"
    allowed = tuple(str(v) for v in state.get("allowed_patterns", []))
    forbidden = tuple(str(v) for v in state.get("forbidden_patterns", []))
    if not any(pattern_matches(pattern, relative) for pattern in allowed):
        return False, f"path is outside the task allowlist: {relative}"
    if any(pattern_matches(pattern, relative) for pattern in forbidden):
        return False, f"forbidden path overrides allowlist: {relative}"
    return True, relative


def _deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _bash_absolute_write_targets(command: str) -> list[Path]:
    targets: list[Path] = []
    for pattern in (REDIRECT_RE, COPY_TARGET_RE):
        for match in pattern.finditer(command):
            targets.append(Path(match.group(2)).resolve(strict=False))
    return targets


def _safe_before_state(command: str) -> bool:
    if any(token in command for token in ("\n", ";", "&&", "||", "|", "`", "$(", ">", "<")):
        return False
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return False
    if not parts:
        return False
    simple = {"pwd", "ls", "find", "grep", "sed", "cat", "head", "tail", "wc", "stat", "sha256sum", "which"}
    if parts[0] in simple:
        return True
    if parts[:2] == ["command", "-v"] and len(parts) >= 3:
        return True
    if parts[0] == "git" and len(parts) >= 2:
        if parts[1] in {"status", "diff", "show", "log", "rev-parse", "cat-file", "ls-tree"}:
            return True
        if parts[1:3] == ["worktree", "list"]:
            return True
        if parts[1:3] == ["branch", "--show-current"]:
            return True
    if parts[0] == "gh" and len(parts) >= 3:
        if parts[1:3] in (["issue", "view"], ["pr", "view"], ["pr", "checks"], ["auth", "status"]):
            return True
        if parts[1] == "api" and "--method" in parts:
            index = parts.index("--method")
            return index + 1 < len(parts) and parts[index + 1] == "GET"
    if len(parts) >= 3 and parts[0] == "python3" and parts[1] == "tools/agent-runner/styx-agent":
        return parts[2] in {"check", "provision", "verify", "run"}
    return False


def inspect_pre_tool(payload: Mapping[str, Any], state: Mapping[str, Any] | None) -> str | None:
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return "tool input is missing or malformed"
    if tool in WRITE_TOOLS:
        if state is None:
            return "writes require an active /styx-run task"
        raw = tool_input.get("file_path")
        if not isinstance(raw, str) or not raw:
            return "write tool did not provide a file path"
        candidate = Path(raw)
        if not candidate.is_absolute():
            return "write tool path must be absolute"
        allowed, reason = _path_allowed(candidate, state)
        return None if allowed else reason
    if tool != "Bash":
        return None
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return "Bash command is missing"
    for pattern in DANGEROUS_BASH:
        if pattern.search(command):
            return "command is prohibited by the Styx agent contract"
    cwd = Path(str(payload.get("cwd") or os.getcwd())).resolve(strict=False)
    if state is None:
        if not _safe_before_state(command):
            return "only read-only inspection and the Styx runner are allowed before /styx-run creates a worktree"
        return None
    worktree = Path(str(state.get("worktree", ""))).resolve(strict=False)
    state_root = _state_root()
    data_root = Path(os.environ.get("STYX_AGENT_DATA_DIR", str(Path.home() / ".local/share"))).resolve() / "styx-agent-runner"
    cache_root = Path(os.environ.get("STYX_AGENT_CACHE_DIR", str(Path.home() / ".cache"))).resolve() / "styx-agent-runner"
    if not any(_inside(cwd, root) for root in (worktree, state_root, data_root, cache_root)):
        if not _safe_before_state(command):
            return "command cwd is outside the active worktree and runner-owned XDG directories"
    for target in _bash_absolute_write_targets(command):
        if not any(_inside(target, root) for root in (worktree, state_root, data_root, cache_root)):
            return f"absolute write target is outside allowed roots: {target}"
    return None


def _git_head(worktree: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "rev-parse", "HEAD"],
            cwd=worktree,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def inspect_stop(state: Mapping[str, Any] | None) -> str | None:
    if state is None:
        return None
    terminal = state.get("terminal_status")
    if terminal == "BLOCKED_BROKER_UNAVAILABLE":
        report_path = Path(str(state.get("status_report", "")))
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "final runner report is missing or malformed"
        tests = report.get("tests")
        scope = report.get("scope_guard")
        if not isinstance(tests, list) or not tests or any(not isinstance(item, dict) or item.get("state") != "PASS" for item in tests):
            return "mandatory test evidence is absent or not PASS"
        if not isinstance(scope, dict) or scope.get("verdict") != "PASS" or scope.get("exit_code") != 0:
            return "scope-guard evidence is absent or not PASS"
        return None
    worktree = Path(str(state.get("worktree", "")))
    expected_base = state.get("base_sha")
    current = _git_head(worktree) if worktree.is_dir() else None
    if terminal == "READY_FOR_IMPLEMENTATION" and current == expected_base:
        return "active task has not produced a committed implementation"
    return "active task has not reached the verified broker handoff"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    mode = argv[0] if argv else "pre"
    try:
        payload = json.load(sys.stdin) if mode == "pre" else {}
        state = _load_state()
        if mode == "pre":
            reason = inspect_pre_tool(payload, state)
            if reason:
                print(json.dumps(_deny(reason), separators=(",", ":")))
            return 0
        if mode == "stop":
            reason = inspect_stop(state)
            if reason:
                print(json.dumps({"decision": "block", "reason": reason}, separators=(",", ":")))
            return 0
        raise HookError(f"unsupported hook mode: {mode}")
    except (HookError, OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if mode == "pre":
            print(json.dumps(_deny(f"Styx hook failed closed: {exc}"), separators=(",", ":")))
        else:
            print(json.dumps({"decision": "block", "reason": f"Styx hook failed closed: {exc}"}, separators=(",", ":")))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
