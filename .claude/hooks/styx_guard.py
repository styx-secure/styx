#!/usr/bin/env python3
"""Fail-closed Claude Code hooks for the active Styx task runner."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping

WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
RUNNER_RE = re.compile(
    r"^python3 tools/agent-runner/styx-agent run --issue ([1-9][0-9]*) "
    r"--execution-id issue-\1$"
)
DANGEROUS_BASH = (
    re.compile(r"(^|[;&|()])\s*(sudo|apt|apt-get|dpkg|snap|systemctl|service)\b", re.I),
    re.compile(r"(^|[;&|()])\s*(curl|wget|ssh|scp|sftp|nc|ncat|socat)\b", re.I),
    re.compile(r"\bgh\b", re.I),
    re.compile(r"\bgit\s+(?:push|send-pack|http-push|fetch|pull|clone|remote|submodule|worktree|update-ref|config)\b", re.I),
    re.compile(r"\bgit\s+(?:checkout|switch)\s+(?:--[^ ]+\s+)*(?:main|master)\b", re.I),
)
SENSITIVE_REFERENCE_RE = re.compile(
    r"(?:~|\$HOME|\$\{HOME\}|\$XDG_CONFIG_HOME|\$\{XDG_CONFIG_HOME\})/"
    r"(?:\.config/gh|\.ssh|\.git-credentials|\.netrc)"
    r"|(?:^|[\s/])(?:\.git-credentials|\.netrc)(?:$|[\s/])",
    re.I,
)
ATTESTATION_SCHEMA = "styx.agent-hook-attestation/v1"
FINAL_STATUS = "BLOCKED_BROKER_UNAVAILABLE"


class HookError(Exception):
    pass


def _state_root(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    home = Path(env.get("HOME", str(Path.home())))
    base = Path(env.get("STYX_AGENT_STATE_DIR", env.get("XDG_STATE_HOME", str(home / ".local/state"))))
    return (base / "styx-agent-runner").resolve()


def _worktree_root(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    return Path(env.get("STYX_AGENT_WORKTREE_ROOT", str(_state_root(env) / "worktrees"))).resolve()


def _trust_root(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    home = Path(env.get("HOME", str(Path.home())))
    return Path(
        env.get(
            "STYX_AGENT_TRUST_DIR",
            str(home / ".local/state/styx-agent-runner-trust"),
        )
    ).resolve()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _regular_bytes(path: Path, *, root: Path | None = None, limit: int = 4_194_304) -> bytes:
    if root is not None and not _inside(path, root):
        raise HookError(f"evidence path escapes its trusted root: {path}")
    try:
        info = path.lstat()
    except OSError as exc:
        raise HookError(f"required evidence is unavailable: {path.name}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise HookError(f"required evidence is not a regular file: {path.name}")
    if info.st_size > limit:
        raise HookError(f"required evidence exceeds the size limit: {path.name}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise HookError(f"unable to read required evidence: {path.name}") from exc


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    def no_duplicates(pairs):
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise HookError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=no_duplicates)
    except HookError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HookError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise HookError(f"{label} has an invalid shape")
    return value


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_state(env: Mapping[str, str] | None = None) -> tuple[dict[str, Any], bytes] | None:
    root = _state_root(env)
    path = root / "active.json"
    if not path.exists():
        return None
    raw = _regular_bytes(path, root=root)
    return _json_object(raw, "active runner state"), raw


def _git(worktree: Path, args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
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
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
        cwd=worktree,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if check and result.returncode != 0:
        raise HookError("Git verification failed")
    return result


def _valid_repo_path(path: str) -> bool:
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
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


def _state_fields(state: Mapping[str, Any]) -> tuple[Path, str, str, int, str]:
    worktree_text = state.get("worktree")
    branch = state.get("branch")
    base_sha = state.get("base_sha")
    issue = state.get("issue_number")
    terminal = state.get("terminal_status")
    if not isinstance(worktree_text, str) or not worktree_text:
        raise HookError("active state is missing the worktree")
    worktree = Path(worktree_text).resolve(strict=False)
    if not _inside(worktree, _worktree_root()):
        raise HookError("active worktree escapes the configured worktree root")
    if not isinstance(issue, int) or issue <= 0:
        raise HookError("active state has an invalid Issue number")
    if not isinstance(branch, str) or not branch.startswith(f"task/{issue}-"):
        raise HookError("active state has an invalid branch")
    if not isinstance(base_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        raise HookError("active state has an invalid base SHA")
    if not isinstance(terminal, str) or not terminal:
        raise HookError("active state has an invalid terminal status")
    return worktree, branch, base_sha, issue, terminal


def _changed_paths(worktree: Path, base_sha: str) -> tuple[str, ...]:
    raw = _git(worktree, ["diff", "--name-only", "-z", "--no-ext-diff", base_sha, "--"]).stdout
    raw += _git(worktree, ["ls-files", "--others", "--exclude-standard", "-z"]).stdout
    paths: set[str] = set()
    for token in raw.split(b"\0"):
        if not token:
            continue
        try:
            path = token.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise HookError("Git returned a non-UTF-8 path") from exc
        if not _valid_repo_path(path):
            raise HookError("Git returned an unsafe repository path")
        paths.add(path)
    return tuple(sorted(paths))


def _scope_violations(state: Mapping[str, Any]) -> list[str]:
    worktree, _, base_sha, _, _ = _state_fields(state)
    allowed = tuple(value for value in state.get("allowed_patterns", []) if isinstance(value, str))
    forbidden = tuple(value for value in state.get("forbidden_patterns", []) if isinstance(value, str))
    if not allowed:
        return ["active state has no allowlist"]
    violations: list[str] = []
    for path in _changed_paths(worktree, base_sha):
        if not any(pattern_matches(pattern, path) for pattern in allowed):
            violations.append(f"path is outside the task allowlist: {path}")
        if any(pattern_matches(pattern, path) for pattern in forbidden):
            violations.append(f"forbidden path overrides allowlist: {path}")
        if (worktree / path).is_symlink():
            violations.append(f"symlink changes are forbidden: {path}")
    return violations


def _snapshot(state: Mapping[str, Any], state_raw: bytes) -> dict[str, Any]:
    state_root = _state_root()
    worktree, branch, base_sha, issue, terminal = _state_fields(state)
    status_path_text = state.get("status_report")
    if not isinstance(status_path_text, str):
        raise HookError("active state is missing the status report")
    status_path = Path(status_path_text).resolve(strict=False)
    status_raw = _regular_bytes(status_path, root=state_root / "runs")
    status = _json_object(status_raw, "runner status report")
    if status.get("terminal_status") != terminal:
        raise HookError("status report terminal state does not match active state")
    issue_value = status.get("issue")
    base_value = status.get("base")
    worktree_value = status.get("worktree")
    if not isinstance(issue_value, dict) or issue_value.get("number") != issue:
        raise HookError("status report Issue does not match active state")
    if not isinstance(base_value, dict) or base_value.get("declared_sha") != base_sha:
        raise HookError("status report base does not match active state")
    if not isinstance(worktree_value, dict) or worktree_value.get("path") != str(worktree):
        raise HookError("status report worktree does not match active state")
    if worktree_value.get("branch") != branch:
        raise HookError("status report branch does not match active state")

    snapshot: dict[str, Any] = {
        "schema": ATTESTATION_SCHEMA,
        "issue_number": issue,
        "terminal_status": terminal,
        "active_state_sha256": _sha256(state_raw),
        "status_report": str(status_path),
        "status_report_sha256": _sha256(status_raw),
        "worktree": str(worktree),
        "branch": branch,
        "base_sha": base_sha,
    }
    if terminal != FINAL_STATUS:
        return snapshot

    if _git(worktree, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]).stdout:
        raise HookError("final task worktree is not clean")
    actual_branch = _git(worktree, ["symbolic-ref", "--short", "HEAD"]).stdout.decode().strip()
    head_sha = _git(worktree, ["rev-parse", "HEAD"]).stdout.decode().strip()
    if actual_branch != branch or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise HookError("final branch or HEAD does not match active state")
    if _git(worktree, ["merge-base", "--is-ancestor", base_sha, head_sha], check=False).returncode != 0:
        raise HookError("final HEAD does not descend from the declared base")
    violations = _scope_violations(state)
    if violations:
        raise HookError(violations[0])

    tests = status.get("tests")
    scope = status.get("scope_guard")
    if not isinstance(tests, list) or not tests:
        raise HookError("final status has no mandatory test evidence")
    if any(not isinstance(item, dict) or item.get("state") != "PASS" or item.get("exit_code") != 0 for item in tests):
        raise HookError("final status contains non-PASS test evidence")
    if not isinstance(scope, dict) or scope.get("verdict") != "PASS" or scope.get("exit_code") != 0:
        raise HookError("final status contains non-PASS scope evidence")
    scope_path_text = scope.get("report_path")
    if not isinstance(scope_path_text, str):
        raise HookError("final scope report path is missing")
    scope_path = Path(scope_path_text).resolve(strict=False)
    scope_raw = _regular_bytes(scope_path, root=state_root / "evidence")
    if scope.get("report_sha256") != _sha256(scope_raw):
        raise HookError("final scope report hash does not match the status report")
    scope_report = _json_object(scope_raw, "scope report")
    if scope_report.get("verdict") != "PASS" or scope_report.get("head_sha") != head_sha:
        raise HookError("final scope report does not attest the current HEAD")
    snapshot.update(
        {
            "head_sha": head_sha,
            "scope_report": str(scope_path),
            "scope_report_sha256": _sha256(scope_raw),
            "changed_paths": list(_changed_paths(worktree, base_sha)),
        }
    )
    return snapshot


def _attestation_path() -> Path:
    return _trust_root() / "active-attestation.json"


def write_attestation(state: Mapping[str, Any], state_raw: bytes) -> None:
    _atomic_write(_attestation_path(), _canonical(_snapshot(state, state_raw)))


def verify_attestation(state: Mapping[str, Any], state_raw: bytes) -> None:
    expected = _canonical(_snapshot(state, state_raw))
    actual = _regular_bytes(_attestation_path(), root=_trust_root())
    if actual != expected:
        raise HookError("runner state/evidence changed after trusted attestation")


def _runner_command(command: str) -> int | None:
    match = RUNNER_RE.fullmatch(command)
    return int(match.group(1)) if match else None


def _safe_read_only(command: str) -> bool:
    if any(token in command for token in ("\n", ";", "&&", "||", "|", "`", "$(", ">", "<")):
        return False
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return False
    if not parts:
        return False
    if parts[0] in {"pwd", "ls", "find", "grep", "sed", "cat", "head", "tail", "wc", "stat", "sha256sum", "which"}:
        return True
    if parts[:2] == ["command", "-v"] and len(parts) >= 3:
        return True
    if parts[0] == "git" and len(parts) >= 2 and parts[1] in {
        "status", "diff", "show", "log", "rev-parse", "cat-file", "ls-tree",
    }:
        return True
    return False


def _sensitive(command: str) -> bool:
    if SENSITIVE_REFERENCE_RE.search(command):
        return True
    home = Path.home().resolve(strict=False)
    config = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config"))).resolve(strict=False)
    return any(str(path) in command for path in (config / "gh", home / ".ssh", home / ".git-credentials", home / ".netrc"))


def inspect_pre_tool(payload: Mapping[str, Any], loaded: tuple[dict[str, Any], bytes] | None) -> str | None:
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return "tool input is missing or malformed"
    state = loaded[0] if loaded else None
    if loaded:
        try:
            verify_attestation(*loaded)
        except HookError as exc:
            return str(exc)
    if tool in WRITE_TOOLS:
        if state is None:
            return "writes require an active /styx-run task"
        if state.get("terminal_status") == FINAL_STATUS:
            return "verified task is frozen at the broker handoff"
        raw = tool_input.get("file_path")
        if not isinstance(raw, str) or not raw:
            return "write tool did not provide a file path"
        candidate = Path(raw)
        if not candidate.is_absolute():
            return "write tool path must be absolute"
        worktree, _, _, _, _ = _state_fields(state)
        if not _inside(candidate, worktree):
            return "write target is outside the active task worktree"
        relative = candidate.resolve(strict=False).relative_to(worktree).as_posix()
        allowed = tuple(value for value in state.get("allowed_patterns", []) if isinstance(value, str))
        forbidden = tuple(value for value in state.get("forbidden_patterns", []) if isinstance(value, str))
        if not any(pattern_matches(pattern, relative) for pattern in allowed):
            return f"path is outside the task allowlist: {relative}"
        if any(pattern_matches(pattern, relative) for pattern in forbidden):
            return f"forbidden path overrides allowlist: {relative}"
        return None
    if tool != "Bash":
        return None
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return "Bash command is missing"
    command = command.strip()
    issue = _runner_command(command)
    cwd = Path(str(payload.get("cwd") or os.getcwd())).resolve(strict=False)
    project = Path(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())).resolve(strict=False)
    if issue is not None:
        if cwd != project:
            return "the Styx runner must execute from the read-only project root"
        if state is not None and state.get("issue_number") != issue:
            return "runner Issue does not match the active task"
        return None
    if _sensitive(command):
        return "commands may not read credential or authentication files"
    for pattern in DANGEROUS_BASH:
        if pattern.search(command):
            return "command is prohibited by the Styx agent contract"
    if state is None:
        return None if _safe_read_only(command) else "only read-only inspection or the exact Styx runner command is allowed before /styx-run"
    if state.get("terminal_status") == FINAL_STATUS:
        return None if _safe_read_only(command) else "verified task is frozen at the broker handoff"
    worktree, _, _, _, _ = _state_fields(state)
    if not _inside(cwd, worktree):
        return "active task commands must execute inside the dedicated worktree"
    return None


def inspect_current(loaded: tuple[dict[str, Any], bytes] | None) -> str | None:
    if loaded is None:
        return None
    try:
        verify_attestation(*loaded)
        violations = _scope_violations(loaded[0])
        return violations[0] if violations else None
    except HookError as exc:
        return str(exc)


def inspect_stop(loaded: tuple[dict[str, Any], bytes] | None) -> str | None:
    if loaded is None:
        return "no issue-bound Styx task reached a terminal state"
    try:
        verify_attestation(*loaded)
        if loaded[0].get("terminal_status") != FINAL_STATUS:
            return "active task has not reached the verified broker handoff"
        violations = _scope_violations(loaded[0])
        return violations[0] if violations else None
    except HookError as exc:
        return str(exc)


def _deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _block(reason: str) -> dict[str, Any]:
    return {"decision": "block", "reason": reason}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    mode = argv[0] if argv else "pre"
    try:
        payload = json.load(sys.stdin) if mode in {"pre", "post"} else {}
        loaded = _load_state()
        if mode == "pre":
            reason = inspect_pre_tool(payload, loaded)
            if reason:
                print(json.dumps(_deny(reason), separators=(",", ":")))
            return 0
        if mode == "post":
            command = ""
            if isinstance(payload, dict) and payload.get("tool_name") == "Bash":
                tool_input = payload.get("tool_input")
                if isinstance(tool_input, dict) and isinstance(tool_input.get("command"), str):
                    command = tool_input["command"].strip()
            loaded = _load_state()
            if _runner_command(command) is not None and loaded is not None:
                write_attestation(*loaded)
            reason = inspect_current(loaded)
            if reason:
                print(json.dumps(_block(reason), separators=(",", ":")))
            return 0
        if mode == "batch":
            reason = inspect_current(loaded)
            if reason:
                print(json.dumps(_block(reason), separators=(",", ":")))
            return 0
        if mode == "stop":
            reason = inspect_stop(loaded)
            if reason:
                print(json.dumps(_block(reason), separators=(",", ":")))
            return 0
        raise HookError(f"unsupported hook mode: {mode}")
    except (HookError, OSError, json.JSONDecodeError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        output = _deny(f"Styx hook failed closed: {exc}") if mode == "pre" else _block(f"Styx hook failed closed: {exc}")
        print(json.dumps(output, separators=(",", ":")))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
