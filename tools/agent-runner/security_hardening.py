#!/usr/bin/env python3
"""Security hardening adapters for the issue-bound Styx runner."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Iterable, Mapping, Sequence
import urllib.error
import urllib.request

API_ROOT = "https://api.github.com"
ENDPOINT_RE = re.compile(r"^repos/styx-secure/styx/issues/([1-9][0-9]*)$")
MAX_RESPONSE_BYTES = 1_048_576
PROHIBITED_TEST_RE = re.compile(
    r"(^|[;&|()])\s*(curl|wget|ssh|scp|sftp|nc|ncat|socat|gh)\b"
    r"|(?:~|\$HOME|\$\{HOME\})/(?:\.config/gh|\.ssh|\.git-credentials|\.netrc)",
    re.IGNORECASE,
)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so the fixed public endpoint cannot be changed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _reject_duplicate_keys(pairs):
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def anonymous_github_get(runner: Any, endpoint: str, *, opener=None) -> dict[str, Any]:
    """Read one public local Issue with no token, redirect, or arbitrary URL."""

    if not ENDPOINT_RE.fullmatch(endpoint):
        raise runner.EnvironmentError("public GitHub reader rejected a non-Issue endpoint")
    request = urllib.request.Request(
        f"{API_ROOT}/{endpoint}",
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "styx-agent-runner/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    if any(key.lower() == "authorization" for key, _ in request.header_items()):
        raise runner.EnvironmentError("public GitHub reader must not send authorization")
    client = opener or urllib.request.build_opener(NoRedirectHandler())
    try:
        response = client.open(request, timeout=30)
        with response:
            status = getattr(response, "status", response.getcode())
            if status != 200:
                raise runner.EnvironmentError(f"public GitHub reader returned HTTP {status}")
            content_type = response.headers.get_content_type()
            if content_type not in {"application/json", "application/vnd.github+json"}:
                raise runner.EnvironmentError("public GitHub reader returned an unexpected content type")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise runner.EnvironmentError("public GitHub Issue was not found") from exc
        if exc.code == 403:
            raise runner.EnvironmentError("public GitHub read was rate-limited or forbidden") from exc
        raise runner.EnvironmentError(f"public GitHub reader returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise runner.EnvironmentError("public GitHub reader is unavailable") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise runner.EnvironmentError("public GitHub response exceeded the size limit")
    try:
        payload = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise runner.EnvironmentError("public GitHub reader returned malformed JSON") from exc
    if not isinstance(payload, dict):
        raise runner.EnvironmentError("public GitHub reader returned an unexpected response shape")
    return payload


def _safe_test_environment(runner: Any, worktree: Path) -> dict[str, str]:
    source = runner.sanitized_env()
    home = Path(source.get("HOME", str(Path.home()))).resolve()
    return {
        "PATH": source.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(home),
        "USER": source.get("USER", "styx"),
        "LOGNAME": source.get("LOGNAME", source.get("USER", "styx")),
        "SHELL": "/bin/bash",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "CI": "1",
        "TMPDIR": "/tmp",
        "XDG_CACHE_HOME": "/tmp/xdg-cache",
        "npm_config_cache": "/tmp/npm-cache",
        "GOCACHE": "/tmp/go-cache",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "PYTHONDONTWRITEBYTECODE": "1",
        "STYX_TASK_WORKTREE": str(worktree),
    }


def _bwrap_command(bwrap: str, worktree: Path, command: str, environment: Mapping[str, str]) -> list[str]:
    home = Path(environment["HOME"]).resolve()
    args = [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--bind", str(worktree), str(worktree),
    ]
    for directory in (home / ".config/gh", home / ".ssh"):
        if directory.exists():
            args.extend(["--tmpfs", str(directory)])
    for file_path in (home / ".git-credentials", home / ".netrc"):
        if file_path.exists():
            args.extend(["--ro-bind", "/dev/null", str(file_path)])
    args.append("--clearenv")
    for key, value in sorted(environment.items()):
        args.extend(["--setenv", key, value])
    args.extend(["--chdir", str(worktree), "/bin/bash", "--noprofile", "--norc", "-lc", command])
    return args


def secure_run_tests(runner: Any, worktree: Path, commands: Sequence[str]):
    """Run required tests in a no-network, worktree-only bubblewrap sandbox."""

    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise runner.AdminProvisioningRequired(
            "bubblewrap is required for isolated task tests",
            remediation="install the Ubuntu bubblewrap package, then rerun the Styx runner",
        )
    environment = _safe_test_environment(runner, worktree)
    results: list[dict[str, Any]] = []
    for command in commands:
        if runner.DANGEROUS_TEST_RE.search(command) or PROHIBITED_TEST_RE.search(command):
            raise runner.ContractError(f"required test became prohibited: {command}")
        try:
            completed = subprocess.run(
                _bwrap_command(bwrap, worktree, command, environment),
                cwd=worktree,
                env=runner.sanitized_env(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=1800,
                check=False,
            )
            stdout, stderr, exit_code = completed.stdout, completed.stderr, completed.returncode
            state = "PASS" if exit_code == 0 else "FAIL"
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            exit_code, state = 124, "ERROR"
        result = {
            "command": command,
            "state": state,
            "exit_code": exit_code,
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8", "replace")).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.encode("utf-8", "replace")).hexdigest(),
        }
        results.append(result)
        if state != "PASS":
            detail = runner.redact_text((stderr or stdout).strip())
            return results, f"required test {state.lower()}: {command}: {detail}"
    return results, None


def apply(runner: Any) -> None:
    """Install anonymous reads, bwrap test isolation, and remove the gh dependency."""

    if getattr(runner, "_STYX_SECURITY_HARDENING_APPLIED", False):
        return
    original_required = runner.required_tool_names
    original_check = runner.check_environment

    def required_tool_names(tests: Iterable[str]):
        return tuple(name for name in original_required(tests) if name != "gh")

    def check_environment(tests=(), *, os_release=None, machine=None, which=shutil.which):
        checks, problems = original_check(
            tests,
            os_release=os_release,
            machine=machine,
            which=which,
        )
        path = which("bwrap")
        if path is None:
            checks.append(runner.ToolCheck("bwrap", True, "administrator-required", None, None, "0.8.0", "missing"))
            problems.append(
                runner.AdminProvisioningRequired(
                    "required tool is missing: bwrap",
                    remediation="install the Ubuntu bubblewrap package, then rerun verify",
                )
            )
        else:
            result = runner.run_command([path, "--version"], cwd=Path.cwd(), check=False, timeout=20)
            detected = runner.parse_version((result.stdout or result.stderr).strip())
            if detected is None or detected < (0, 8, 0):
                checks.append(runner.ToolCheck("bwrap", True, "administrator-required", str(Path(path).resolve()), None, "0.8.0", "incompatible"))
                problems.append(
                    runner.AdminProvisioningRequired(
                        "required tool is incompatible: bwrap",
                        remediation="install bubblewrap >= 0.8.0, then rerun verify",
                    )
                )
            else:
                checks.append(runner.ToolCheck("bwrap", True, "available", str(Path(path).resolve()), ".".join(map(str, detected)), "0.8.0", "compatible"))
        return checks, problems

    runner.required_tool_names = required_tool_names
    runner.check_environment = check_environment
    runner._gh_api = lambda repo, endpoint: anonymous_github_get(runner, endpoint)
    runner.run_tests = lambda worktree, commands: secure_run_tests(runner, worktree, commands)
    runner._STYX_SECURITY_HARDENING_APPLIED = True
