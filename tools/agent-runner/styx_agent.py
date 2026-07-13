#!/usr/bin/env python3
"""Issue-bound, fail-closed local agent runner for Styx."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable, Iterable, Mapping, Sequence

SCHEMA_ID = "styx.agent-runner-status/v1"
TOOL_VERSION = "0.1.0"
REPOSITORY = "styx-secure/styx"
EXIT_OK = 0
EXIT_BLOCKED = 2
EXIT_ERROR = 3
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ISSUE_REF_RE = re.compile(r"^#([1-9][0-9]*)$")
BASE_RE = re.compile(r"`([A-Za-z0-9._/-]+) @ ([0-9a-f]{40})`")
DEP_RE = re.compile(r"(?m)^- Required closed Issue: #([1-9][0-9]*)[ \t]*$")
HEADING_RE = re.compile(r"^##[ \t]+(.+?)[ \t]*$")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
DANGEROUS_TEST_RE = re.compile(
    r"(^|[;&|()])\s*(sudo|apt|apt-get|dpkg|snap|systemctl|service)\b"
    r"|\bgit\s+push\b|\bgh\s+(?:pr|issue|release|repo)\s+"
    r"(?:create|edit|comment|close|reopen|delete|merge|ready|review)\b"
    r"|\bgh\s+api\b.*(?:--method|-X)\s+(?!GET\b)",
    re.IGNORECASE,
)
SECRET_KEY_RE = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|AUTHORIZATION|CREDENTIAL)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(
    r"(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+"
    r"|\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
)
VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


class RunnerError(Exception):
    code = "E_INTERNAL"
    exit_code = EXIT_ERROR

    def __init__(self, message: str, *, remediation: str | None = None):
        super().__init__(message)
        self.message = message
        self.remediation = remediation


class BlockedError(RunnerError):
    exit_code = EXIT_BLOCKED


class ContractError(RunnerError):
    code = "E_CONTRACT"


class RepositoryError(RunnerError):
    code = "E_REPOSITORY"


class EnvironmentError(RunnerError):
    code = "E_ENVIRONMENT"


class EvidenceError(RunnerError):
    code = "E_EVIDENCE"


class BrokerUnavailable(BlockedError):
    code = "BLOCKED_BROKER_UNAVAILABLE"


class AdminProvisioningRequired(BlockedError):
    code = "BLOCKED_ADMIN_PROVISIONING"


class AuthenticationRequired(BlockedError):
    code = "BLOCKED_AUTHENTICATION"


@dataclasses.dataclass(frozen=True)
class ToolCheck:
    name: str
    required: bool
    disposition: str
    path: str | None
    version: str | None
    minimum: str | None
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class TaskContract:
    issue_number: int
    title: str
    body_bytes: bytes
    body_sha256: str
    base_branch: str
    base_sha: str
    dependencies: tuple[int, ...]
    allowed_patterns: tuple[str, ...]
    forbidden_patterns: tuple[str, ...]
    required_tests: tuple[str, ...]
    sections: Mapping[str, str]


@dataclasses.dataclass(frozen=True)
class Paths:
    repo: Path
    data: Path
    cache: Path
    state: Path
    worktrees: Path

    @classmethod
    def from_repo(cls, repo: Path, env: Mapping[str, str] | None = None) -> "Paths":
        env = os.environ if env is None else env
        home = Path(env.get("HOME", str(Path.home())))
        data = Path(env.get("STYX_AGENT_DATA_DIR", env.get("XDG_DATA_HOME", str(home / ".local/share"))))
        cache = Path(env.get("STYX_AGENT_CACHE_DIR", env.get("XDG_CACHE_HOME", str(home / ".cache"))))
        state = Path(env.get("STYX_AGENT_STATE_DIR", env.get("XDG_STATE_HOME", str(home / ".local/state"))))
        data = (data / "styx-agent-runner").resolve()
        cache = (cache / "styx-agent-runner").resolve()
        state = (state / "styx-agent-runner").resolve()
        worktrees = Path(env.get("STYX_AGENT_WORKTREE_ROOT", str(state / "worktrees"))).resolve()
        return cls(repo.resolve(), data, cache, state, worktrees)

    def ensure(self) -> None:
        for path in (self.data, self.cache, self.state, self.worktrees, self.state / "runs", self.state / "evidence"):
            path.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(OSError):
                path.chmod(0o700)


def redact_text(value: str, env: Mapping[str, str] | None = None) -> str:
    text = SECRET_VALUE_RE.sub(lambda m: (m.group(1) if m.lastindex else "") + "[REDACTED]", value)
    text = re.sub(
        r"(?i)\b(https?://)[^\s/@:]+:[^\s/@]+@",
        lambda match: match.group(1) + "[REDACTED]@",
        text,
    )
    env = os.environ if env is None else env
    secrets = sorted(
        {v for k, v in env.items() if v and len(v) >= 8 and SECRET_KEY_RE.search(k)},
        key=len,
        reverse=True,
    )
    for secret in secrets:
        text = text.replace(secret, "[REDACTED]")
    return text


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def sanitized_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    source = os.environ if env is None else env
    result = dict(source)
    for key in tuple(result):
        if SECRET_KEY_RE.search(key) or key in {
            "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        } or key == "GIT_CONFIG_COUNT" or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            result.pop(key, None)
    result.update({
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "GIT_OPTIONAL_LOCKS": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    return result


def run_command(
    args: Sequence[str],
    *,
    cwd: Path,
    timeout: int = 120,
    check: bool = True,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(args),
            cwd=cwd,
            env=sanitized_env(env),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise EnvironmentError(f"executable not found: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise EvidenceError(f"command timed out: {shlex.join(args)}") from exc
    if check and result.returncode != 0:
        detail = redact_text((result.stderr or result.stdout).strip())
        raise EvidenceError(f"command failed ({result.returncode}): {shlex.join(args)}: {detail}")
    return result


def git(repo: Path, args: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run_command(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
        cwd=repo,
        check=check,
    )


def parse_issue_reference(value: str) -> int:
    match = ISSUE_REF_RE.fullmatch(value.strip())
    if not match:
        raise ContractError("task reference must be exactly one local '#<positive-integer>' reference")
    return int(match.group(1))


def _scan_sections(body: str) -> dict[str, str]:
    lines = body.splitlines(keepends=True)
    headings: list[tuple[str, int]] = []
    offset = 0
    fence_char: str | None = None
    fence_len = 0
    for line in lines:
        logical = line.rstrip("\r\n")
        if fence_char:
            if re.fullmatch(rf" {{0,3}}{re.escape(fence_char)}{{{fence_len},}}[ \t]*", logical):
                fence_char = None
                fence_len = 0
        else:
            opened = FENCE_RE.match(logical)
            if opened:
                token = opened.group(1)
                fence_char, fence_len = token[0], len(token)
            elif not logical.startswith(("    ", "\t")):
                match = HEADING_RE.fullmatch(logical)
                if match:
                    headings.append((match.group(1).strip(), offset))
        offset += len(line)
    if fence_char:
        raise ContractError("unterminated fenced code block")
    result: dict[str, str] = {}
    for index, (name, start) in enumerate(headings):
        if name in result:
            raise ContractError(f"duplicate heading: {name}")
        content_start = body.find("\n", start)
        content_start = len(body) if content_start == -1 else content_start + 1
        content_end = headings[index + 1][1] if index + 1 < len(headings) else len(body)
        result[name] = body[content_start:content_end]
    return result


def _single_fenced_lines(section: str, heading: str) -> tuple[str, ...]:
    blocks: list[list[str]] = []
    current: list[str] | None = None
    char: str | None = None
    size = 0
    for line in section.splitlines():
        if current is None:
            opened = FENCE_RE.match(line)
            if opened:
                token = opened.group(1)
                char, size = token[0], len(token)
                current = []
        else:
            assert char is not None
            if re.fullmatch(rf" {{0,3}}{re.escape(char)}{{{size},}}[ \t]*", line):
                blocks.append(current)
                current = None
                char = None
            else:
                current.append(line)
    if current is not None or len(blocks) != 1:
        raise ContractError(f"'{heading}' must contain exactly one closed fenced block")
    values = tuple(line for line in blocks[0] if line.strip())
    if not values:
        raise ContractError(f"'{heading}' must not be empty")
    return values


def _load_existing_parser(repo: Path) -> Callable[[bytes], Any]:
    module_dir = repo / "tools/agent-enforcement"
    if not (module_dir / "contract.py").is_file():
        raise ContractError("trusted task-contract parser is missing")
    previous = list(sys.path)
    modules = {name: sys.modules.get(name) for name in ("contract", "model")}
    try:
        sys.path.insert(0, str(module_dir))
        for name in ("contract", "model"):
            sys.modules.pop(name, None)
        module = importlib.import_module("contract")
        return module.parse_contract
    except Exception as exc:
        raise ContractError(f"unable to load trusted task-contract parser: {redact_text(str(exc))}") from exc
    finally:
        sys.path[:] = previous
        for name, old in modules.items():
            sys.modules.pop(name, None)
            if old is not None:
                sys.modules[name] = old


def validate_issue_contract(
    repo: Path,
    issue_number: int,
    title: str,
    body_bytes: bytes,
    *,
    parser: Callable[[bytes], Any] | None = None,
) -> TaskContract:
    parse = parser or _load_existing_parser(repo)
    try:
        parsed = parse(body_bytes)
    except Exception as exc:
        raise ContractError(f"trusted contract parser rejected Issue #{issue_number}: {redact_text(str(exc))}") from exc
    try:
        body = body_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ContractError("Issue body is not valid UTF-8") from exc
    sections = _scan_sections(body)
    base_section = sections.get("Base")
    if base_section is None:
        raise ContractError("missing Base section")
    base_matches = BASE_RE.findall(base_section)
    if len(base_matches) != 1:
        raise ContractError("Base must contain exactly one '`branch @ 40-hex-sha`' declaration")
    base_branch, base_sha = base_matches[0]
    if base_branch != "main" or not SHA_RE.fullmatch(base_sha):
        raise ContractError("only exact lowercase full-SHA 'main' bases are supported")
    dependency_section = sections.get("Native dependencies", "")
    dependencies = tuple(sorted({int(v) for v in DEP_RE.findall(dependency_section)}))
    test_section = sections.get("Required tests") or sections.get("Required verification")
    if test_section is None:
        raise ContractError("missing required tests section")
    tests = _single_fenced_lines(test_section, "Required tests")
    for command in tests:
        if DANGEROUS_TEST_RE.search(command):
            raise ContractError(f"required test contains a prohibited operation: {command}")
    return TaskContract(
        issue_number=issue_number,
        title=title,
        body_bytes=body_bytes,
        body_sha256=hashlib.sha256(body_bytes).hexdigest(),
        base_branch=base_branch,
        base_sha=base_sha,
        dependencies=dependencies,
        allowed_patterns=tuple(parsed.allowed_patterns),
        forbidden_patterns=tuple(parsed.forbidden_patterns),
        required_tests=tests,
        sections=sections,
    )


def normalize_remote(url: str) -> str | None:
    value = url.strip()
    patterns = (
        r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
        r"^ssh://git@github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
        r"^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, value)
        if match:
            return f"{match.group(1)}/{match.group(2)}"
    return None


def verify_repository(repo: Path, contract: TaskContract | None = None, *, require_clean: bool = True) -> dict[str, str]:
    repo = repo.resolve()
    top = Path(git(repo, ["rev-parse", "--show-toplevel"]).stdout.strip()).resolve()
    if top != repo:
        raise RepositoryError("runner must be invoked from the Git worktree root")
    remote = git(repo, ["remote", "get-url", "origin"]).stdout.strip()
    normalized = normalize_remote(remote)
    if normalized != REPOSITORY:
        raise RepositoryError(f"unexpected origin repository: {redact_text(remote)}")
    head = git(repo, ["rev-parse", "HEAD"]).stdout.strip()
    if require_clean and git(repo, ["status", "--porcelain=v1", "--untracked-files=all"]).stdout:
        raise RepositoryError("source checkout is dirty")
    result = {"repository": normalized, "head_sha": head, "remote": redact_text(remote)}
    if contract is not None:
        main_sha = git(repo, ["rev-parse", f"refs/heads/{contract.base_branch}"]).stdout.strip()
        if main_sha != contract.base_sha:
            raise RepositoryError(
                f"base drift: refs/heads/{contract.base_branch} is {main_sha}, expected {contract.base_sha}"
            )
        if git(repo, ["cat-file", "-e", f"{contract.base_sha}^{{commit}}"], check=False).returncode != 0:
            raise RepositoryError("declared base SHA is not available locally")
        result["verified_base_sha"] = main_sha
    return result


def read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, raw = line.split("=", 1)
            values[key] = raw.strip().strip('"')
    except OSError as exc:
        raise EnvironmentError(f"unable to read {path}: {exc}") from exc
    return values


def parse_version(text: str) -> tuple[int, int, int] | None:
    match = VERSION_RE.search(text)
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def required_tool_names(tests: Iterable[str]) -> tuple[str, ...]:
    names = {"python3", "git", "gh", "claude"}
    joined = "\n".join(tests)
    probes = {
        "npm": r"\bnpm\b",
        "node": r"\bnode\b|\bnpm\b",
        "dart": r"\bdart\b|\bmelos\b|\bflutter\b",
        "melos": r"\bmelos\b",
        "flutter": r"\bflutter\b",
        "go": r"\bgo\b",
        "docker": r"\bdocker\b",
    }
    for name, pattern in probes.items():
        if re.search(pattern, joined):
            names.add(name)
    return tuple(sorted(names))


def check_environment(
    tests: Iterable[str] = (),
    *,
    os_release: Mapping[str, str] | None = None,
    machine: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> tuple[list[ToolCheck], list[RunnerError]]:
    release = dict(read_os_release() if os_release is None else os_release)
    machine = platform.machine() if machine is None else machine
    problems: list[RunnerError] = []
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "26.04" or machine not in {"x86_64", "amd64"}:
        problems.append(
            EnvironmentError(
                f"unsupported platform: ID={release.get('ID')} VERSION_ID={release.get('VERSION_ID')} arch={machine}"
            )
        )
    minimums = {
        "python3": (3, 11, 0),
        "git": (2, 39, 0),
        "gh": (2, 0, 0),
        "claude": (2, 1, 195),
        "node": (20, 0, 0),
        "npm": (10, 0, 0),
        "dart": (3, 0, 0),
        "melos": (6, 0, 0),
        "flutter": (3, 0, 0),
        "go": (1, 22, 0),
        "docker": (24, 0, 0),
    }
    version_args = {
        "python3": ["--version"], "git": ["--version"], "gh": ["--version"], "claude": ["--version"],
        "node": ["--version"], "npm": ["--version"], "dart": ["--version"], "melos": ["--version"],
        "flutter": ["--version"], "go": ["version"], "docker": ["--version"],
    }
    checks: list[ToolCheck] = []
    for name in required_tool_names(tests):
        path = which(name)
        minimum = minimums[name]
        if path is None:
            checks.append(ToolCheck(name, True, "administrator-required", None, None, ".".join(map(str, minimum)), "missing"))
            problems.append(AdminProvisioningRequired(
                f"required tool is missing: {name}",
                remediation=f"install a compatible {name} using the documented operator procedure, then rerun verify",
            ))
            continue
        try:
            result = run_command([path, *version_args[name]], cwd=Path.cwd(), check=False, timeout=20)
            output = (result.stdout or result.stderr).strip().splitlines()[0] if (result.stdout or result.stderr).strip() else ""
            detected = parse_version(output)
        except RunnerError as exc:
            output, detected = exc.message, None
        if detected is None or detected < minimum:
            checks.append(ToolCheck(name, True, "administrator-required", str(Path(path).resolve()), redact_text(output), ".".join(map(str, minimum)), "incompatible"))
            problems.append(AdminProvisioningRequired(
                f"required tool is incompatible: {name}: {redact_text(output)}",
                remediation=f"install {name} >= {'.'.join(map(str, minimum))}, then rerun verify",
            ))
        else:
            checks.append(ToolCheck(name, True, "available", str(Path(path).resolve()), ".".join(map(str, detected)), ".".join(map(str, minimum)), "compatible"))
    return checks, problems


def provision_launcher(paths: Paths, repo: Path, python_executable: str = sys.executable) -> ToolCheck:
    paths.ensure()
    target = paths.data / "bin" / "styx-agent"
    expected = (
        "#!/bin/sh\n"
        "set -eu\n"
        f"exec {shlex.quote(python_executable)} {shlex.quote(str((repo / 'tools/agent-runner/styx-agent').resolve()))} \"$@\"\n"
    ).encode("utf-8")
    if target.exists():
        existing = target.read_bytes()
        if existing != expected:
            raise EnvironmentError(
                f"refusing to replace non-matching launcher at {target}",
                remediation=f"inspect and remove only {target}, then rerun provision",
            )
        disposition = "already-provisioned"
    else:
        atomic_write(target, expected, 0o700)
        disposition = "provisioned"
    if hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(expected).digest():
        raise EnvironmentError("launcher checksum verification failed")
    return ToolCheck("styx-agent-launcher", True, disposition, str(target), TOOL_VERSION, TOOL_VERSION, "verified sha256")


def _gh_api(repo: Path, endpoint: str) -> dict[str, Any]:
    result = run_command(["gh", "api", "--method", "GET", endpoint], cwd=repo, check=False, timeout=60)
    if result.returncode != 0:
        text = redact_text((result.stderr or result.stdout).strip())
        if "authentication" in text.lower() or "401" in text:
            raise AuthenticationRequired("GitHub read authentication is unavailable", remediation="run `gh auth login`, then retry")
        raise EnvironmentError(f"read-only GitHub API request failed: {text}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise EnvironmentError("GitHub API returned malformed JSON") from exc
    if not isinstance(payload, dict):
        raise EnvironmentError("GitHub API returned an unexpected response shape")
    return payload


def fetch_issue(repo: Path, issue_number: int, api: Callable[[str], dict[str, Any]] | None = None) -> tuple[str, bytes, str]:
    api = (lambda endpoint: _gh_api(repo, endpoint)) if api is None else api
    payload = api(f"repos/{REPOSITORY}/issues/{issue_number}")
    if "pull_request" in payload:
        raise ContractError(f"#{issue_number} is a pull request, not an Issue")
    if payload.get("state") != "open":
        raise ContractError(f"Issue #{issue_number} is not open")
    title, body = payload.get("title"), payload.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        raise ContractError("Issue title/body is missing or malformed")
    return title, body.encode("utf-8"), str(payload.get("html_url") or "")


def verify_dependencies(repo: Path, dependencies: Iterable[int], api: Callable[[str], dict[str, Any]] | None = None) -> None:
    api = (lambda endpoint: _gh_api(repo, endpoint)) if api is None else api
    for number in dependencies:
        payload = api(f"repos/{REPOSITORY}/issues/{number}")
        if "pull_request" in payload or payload.get("state") != "closed":
            raise ContractError(f"required dependency #{number} is not a closed Issue")


def slugify(title: str) -> str:
    value = re.sub(r"^\[[^\]]+\]\s*", "", title.strip())
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (value or "task")[:48].rstrip("-")


def _worktree_entries(repo: Path) -> list[dict[str, str]]:
    raw = git(repo, ["worktree", "list", "--porcelain"]).stdout
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in raw.splitlines():
        if not line:
            if current:
                entries.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        current[key] = value
    if current:
        entries.append(current)
    return entries


def prepare_worktree(paths: Paths, contract: TaskContract) -> tuple[Path, str, str]:
    verify_repository(paths.repo, contract, require_clean=True)
    paths.ensure()
    branch = f"task/{contract.issue_number}-{slugify(contract.title)}"
    worktree = (paths.worktrees / f"issue-{contract.issue_number}").resolve()
    existing = _worktree_entries(paths.repo)
    branch_ref = f"refs/heads/{branch}"
    branch_result = git(paths.repo, ["show-ref", "--verify", "--hash", branch_ref], check=False)
    branch_sha = branch_result.stdout.strip() if branch_result.returncode == 0 else None
    matching = [e for e in existing if Path(e.get("worktree", "")).resolve() == worktree]
    if worktree.exists() or matching or branch_sha is not None:
        if len(matching) != 1:
            raise RepositoryError("branch/worktree collision requires operator cleanup")
        entry = matching[0]
        if entry.get("branch") != branch_ref:
            raise RepositoryError("existing worktree is attached to a different branch")
        current = git(worktree, ["rev-parse", "HEAD"]).stdout.strip()
        if git(paths.repo, ["merge-base", "--is-ancestor", contract.base_sha, current], check=False).returncode != 0:
            raise RepositoryError("existing task branch does not descend from the declared base")
        return worktree, branch, current
    result = git(paths.repo, ["worktree", "add", "-b", branch, str(worktree), contract.base_sha], check=False)
    if result.returncode != 0:
        raise RepositoryError(f"unable to create task worktree: {redact_text(result.stderr.strip())}")
    return worktree, branch, contract.base_sha


def manifest_for(contract: TaskContract, worktree: Path, branch: str, execution_id: str) -> dict[str, Any]:
    return {
        "schema": "styx.agent-execution-manifest/v1",
        "repository": REPOSITORY,
        "issue_number": contract.issue_number,
        "issue_body_sha256": contract.body_sha256,
        "base_branch": contract.base_branch,
        "base_sha": contract.base_sha,
        "execution_id": execution_id,
        "worktree": str(worktree),
        "branch": branch,
        "allowed_patterns": list(contract.allowed_patterns),
        "forbidden_patterns": list(contract.forbidden_patterns),
        "required_tests": list(contract.required_tests),
        "non_goals": contract.sections.get("Non-goals", "").strip(),
        "human_gates": contract.sections.get("Human gates", "").strip(),
        "broker_operations": ["push_task_branch", "open_draft_pr"],
    }


def write_active_state(paths: Paths, manifest: Mapping[str, Any], status_report: Path, terminal_status: str) -> None:
    payload = dict(manifest)
    payload.update({"status_report": str(status_report), "terminal_status": terminal_status})
    atomic_write(paths.state / "active.json", canonical_json_bytes(payload), 0o600)


def build_status(
    *,
    command: str,
    execution_id: str,
    paths: Paths,
    contract: TaskContract | None = None,
    repo_info: Mapping[str, str] | None = None,
    tools: Sequence[ToolCheck] = (),
    worktree: Path | None = None,
    branch: str | None = None,
    tests: Sequence[Mapping[str, Any]] = (),
    scope_guard: Mapping[str, Any] | None = None,
    phase: str,
    terminal_status: str,
    blocking_code: str | None = None,
    remediation: str | None = None,
    prohibited_attempts: Sequence[str] = (),
) -> dict[str, Any]:
    return {
        "schema": SCHEMA_ID,
        "tool_version": TOOL_VERSION,
        "command": command,
        "execution_id": execution_id,
        "repository": {
            "expected": REPOSITORY,
            "verified": None if repo_info is None else repo_info.get("repository"),
            "source_root": str(paths.repo),
        },
        "issue": None if contract is None else {
            "number": contract.issue_number,
            "body_sha256": contract.body_sha256,
        },
        "base": None if contract is None else {
            "branch": contract.base_branch,
            "declared_sha": contract.base_sha,
            "verified_sha": None if repo_info is None else repo_info.get("verified_base_sha"),
        },
        "environment": {"tools": [item.as_dict() for item in tools]},
        "worktree": None if worktree is None else {"path": str(worktree), "branch": branch},
        "contract": {"valid": contract is not None},
        "tests": list(tests),
        "scope_guard": scope_guard,
        "phase": phase,
        "terminal_status": terminal_status,
        "blocking": None if blocking_code is None else {
            "code": blocking_code,
            "remediation": redact_text(remediation or ""),
        },
        "prohibited_operation_attempts": [redact_text(item) for item in prohibited_attempts],
    }


def write_status(paths: Paths, execution_id: str, status: Mapping[str, Any]) -> Path:
    paths.ensure()
    path = paths.state / "runs" / f"{execution_id}.json"
    atomic_write(path, canonical_json_bytes(status), 0o600)
    return path


def _result_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def run_tests(worktree: Path, commands: Sequence[str]) -> tuple[list[dict[str, Any]], str | None]:
    results: list[dict[str, Any]] = []
    for command in commands:
        if DANGEROUS_TEST_RE.search(command):
            raise ContractError(f"required test became prohibited: {command}")
        try:
            completed = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-lc", command],
                cwd=worktree,
                env=sanitized_env(),
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
            "stdout_sha256": _result_hash(stdout),
            "stderr_sha256": _result_hash(stderr),
        }
        results.append(result)
        if state != "PASS":
            detail = redact_text((stderr or stdout).strip())
            return results, f"required test {state.lower()}: {command}: {detail}"
    return results, None


def run_scope_guard(
    paths: Paths,
    contract: TaskContract,
    worktree: Path,
    head_sha: str,
    execution_id: str,
) -> tuple[dict[str, Any], str | None]:
    del worktree
    evidence_dir = paths.state / "evidence" / execution_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    body_path = evidence_dir / "issue-body.md"
    report_path = evidence_dir / "task-scope-report.json"
    atomic_write(body_path, contract.body_bytes, 0o600)
    # Execute only the guard from the clean trusted-base source checkout. The task
    # head is inspected as Git object data through the shared object database.
    guard = paths.repo / "tools/agent-enforcement/scope_guard.py"
    try:
        completed = run_command(
            [
                sys.executable, str(guard),
                "--issue-number", str(contract.issue_number),
                "--issue-body-file", str(body_path),
                "--base-sha", contract.base_sha,
                "--head-sha", head_sha,
                "--worktree-sha", contract.base_sha,
                "--execution-id", execution_id,
                "--output", str(report_path),
                "--repo", str(paths.repo),
            ],
            cwd=paths.repo,
            check=False,
            timeout=600,
        )
        exit_code = completed.returncode
    except RunnerError as exc:
        exit_code = EXIT_ERROR
        result = {
            "exit_code": exit_code,
            "verdict": "ERROR",
            "report_path": str(report_path),
            "report_sha256": None,
        }
        return result, exc.message
    report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest() if report_path.is_file() else None
    verdict = None
    if report_path.is_file():
        try:
            parsed = json.loads(report_path.read_text(encoding="utf-8"))
            verdict = parsed.get("verdict")
        except (OSError, json.JSONDecodeError):
            verdict = None
    result = {
        "exit_code": exit_code,
        "verdict": verdict,
        "report_path": str(report_path),
        "report_sha256": report_sha,
    }
    if exit_code != 0 or verdict != "PASS":
        return result, f"scope guard did not PASS: exit={exit_code} verdict={verdict}"
    return result, None


class BrokerOperations:
    """Versioned deny-by-default placeholder for the future restricted broker."""

    version = "v1"

    def request(self, operation: str, payload: Mapping[str, Any] | None = None) -> None:
        del payload
        raise BrokerUnavailable(
            f"broker operation is unavailable in this increment: {operation}",
            remediation=f"an authorized operator or future restricted broker must perform `{operation}`",
        )


def _load_existing_manifest(paths: Paths, issue_number: int) -> dict[str, Any] | None:
    path = paths.state / "active.json"
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RepositoryError("active runner state is malformed") from exc
    if value.get("issue_number") != issue_number:
        raise RepositoryError("another task is already active in this runner state")
    return value


def _finalize_if_ready(
    paths: Paths,
    contract: TaskContract,
    manifest: Mapping[str, Any],
    execution_id: str,
    tools: Sequence[ToolCheck],
    repo_info: Mapping[str, str],
) -> tuple[dict[str, Any], int]:
    worktree = Path(str(manifest["worktree"])).resolve()
    branch = str(manifest["branch"])
    if not worktree.is_dir():
        raise RepositoryError("active worktree no longer exists")
    current_branch = git(worktree, ["symbolic-ref", "--short", "HEAD"]).stdout.strip()
    if current_branch != branch:
        raise RepositoryError("active worktree branch changed")
    head_sha = git(worktree, ["rev-parse", "HEAD"]).stdout.strip()
    if head_sha == contract.base_sha:
        status = build_status(
            command="run", execution_id=execution_id, paths=paths, contract=contract, repo_info=repo_info,
            tools=tools, worktree=worktree, branch=branch, phase="implementation",
            terminal_status="READY_FOR_IMPLEMENTATION",
        )
        path = write_status(paths, execution_id, status)
        write_active_state(paths, manifest, path, "READY_FOR_IMPLEMENTATION")
        return status, EXIT_OK
    if git(worktree, ["merge-base", "--is-ancestor", contract.base_sha, head_sha], check=False).returncode != 0:
        raise RepositoryError("task head no longer descends from declared base")
    if git(worktree, ["status", "--porcelain=v1", "--untracked-files=all"]).stdout:
        raise EvidenceError("task worktree has uncommitted changes")
    test_results, test_failure = run_tests(worktree, contract.required_tests)
    if test_failure is not None:
        status = build_status(
            command="run", execution_id=execution_id, paths=paths, contract=contract, repo_info=repo_info,
            tools=tools, worktree=worktree, branch=branch, tests=test_results, scope_guard=None,
            phase="error", terminal_status="ERROR", blocking_code="E_EVIDENCE",
            remediation=test_failure,
        )
        path = write_status(paths, execution_id, status)
        write_active_state(paths, manifest, path, "ERROR")
        return status, EXIT_ERROR
    scope_result, scope_failure = run_scope_guard(paths, contract, worktree, head_sha, execution_id)
    if scope_failure is not None:
        status = build_status(
            command="run", execution_id=execution_id, paths=paths, contract=contract, repo_info=repo_info,
            tools=tools, worktree=worktree, branch=branch, tests=test_results, scope_guard=scope_result,
            phase="error", terminal_status="ERROR", blocking_code="E_EVIDENCE",
            remediation=scope_failure,
        )
        path = write_status(paths, execution_id, status)
        write_active_state(paths, manifest, path, "ERROR")
        return status, EXIT_ERROR
    status = build_status(
        command="run", execution_id=execution_id, paths=paths, contract=contract, repo_info=repo_info,
        tools=tools, worktree=worktree, branch=branch, tests=test_results, scope_guard=scope_result,
        phase="handoff", terminal_status="BLOCKED_BROKER_UNAVAILABLE",
        blocking_code="BLOCKED_BROKER_UNAVAILABLE",
        remediation="restricted broker must push the task branch and open a Draft PR; no local agent has that authority",
    )
    path = write_status(paths, execution_id, status)
    write_active_state(paths, manifest, path, "BLOCKED_BROKER_UNAVAILABLE")
    return status, EXIT_BLOCKED


def command_check(args: argparse.Namespace, paths: Paths) -> tuple[dict[str, Any], int]:
    execution_id = args.execution_id or "check"
    checks, problems = check_environment(())
    blocking = next((p for p in problems if isinstance(p, BlockedError)), None)
    error = next((p for p in problems if not isinstance(p, BlockedError)), None)
    terminal = "ERROR" if error else ("BLOCKED_ADMIN_PROVISIONING" if blocking else "CHECKED")
    selected = error or blocking
    status = build_status(
        command="check", execution_id=execution_id, paths=paths, tools=checks, phase="environment",
        terminal_status=terminal,
        blocking_code=None if selected is None else selected.code,
        remediation=None if selected is None else (selected.remediation or selected.message),
    )
    write_status(paths, execution_id, status)
    return status, (selected.exit_code if selected else EXIT_OK)


def command_provision(args: argparse.Namespace, paths: Paths) -> tuple[dict[str, Any], int]:
    execution_id = args.execution_id or "provision"
    launcher = provision_launcher(paths, paths.repo)
    status = build_status(
        command="provision", execution_id=execution_id, paths=paths, tools=[launcher],
        phase="environment", terminal_status="PROVISIONED",
    )
    write_status(paths, execution_id, status)
    return status, EXIT_OK


def command_verify(args: argparse.Namespace, paths: Paths) -> tuple[dict[str, Any], int]:
    execution_id = args.execution_id or "verify"
    repo_info = verify_repository(paths.repo, require_clean=True)
    checks, problems = check_environment(())
    if problems:
        raise problems[0]
    status = build_status(
        command="verify", execution_id=execution_id, paths=paths, repo_info=repo_info,
        tools=checks, phase="environment", terminal_status="VERIFIED",
    )
    write_status(paths, execution_id, status)
    return status, EXIT_OK


def command_run(
    args: argparse.Namespace,
    paths: Paths,
    *,
    issue_api: Callable[[str], dict[str, Any]] | None = None,
    parser: Callable[[bytes], Any] | None = None,
) -> tuple[dict[str, Any], int]:
    issue_number = args.issue
    execution_id = args.execution_id or f"issue-{issue_number}"
    title, body_bytes, _ = fetch_issue(paths.repo, issue_number, issue_api)
    contract = validate_issue_contract(paths.repo, issue_number, title, body_bytes, parser=parser)
    repo_info = verify_repository(paths.repo, contract, require_clean=True)
    verify_dependencies(paths.repo, contract.dependencies, issue_api)
    checks, problems = check_environment(contract.required_tests)
    if problems:
        raise problems[0]
    provision_launcher(paths, paths.repo)
    existing = _load_existing_manifest(paths, issue_number)
    if existing is None:
        worktree, branch, _ = prepare_worktree(paths, contract)
        manifest = manifest_for(contract, worktree, branch, execution_id)
        manifest_path = paths.state / "runs" / f"{execution_id}-manifest.json"
        atomic_write(manifest_path, canonical_json_bytes(manifest), 0o600)
        status = build_status(
            command="run", execution_id=execution_id, paths=paths, contract=contract, repo_info=repo_info,
            tools=checks, worktree=worktree, branch=branch, phase="implementation",
            terminal_status="READY_FOR_IMPLEMENTATION",
        )
        status_path = write_status(paths, execution_id, status)
        write_active_state(paths, manifest, status_path, "READY_FOR_IMPLEMENTATION")
        return status, EXIT_OK
    if existing.get("issue_body_sha256") != contract.body_sha256:
        raise ContractError("Issue contract changed after execution state was created")
    return _finalize_if_ready(paths, contract, existing, execution_id, checks, repo_info)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="styx-agent", description="Issue-bound local runner for Styx")
    result.add_argument("--repo", type=Path, default=Path.cwd())
    sub = result.add_subparsers(dest="command", required=True)
    for name in ("check", "provision", "verify"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--execution-id")
    run = sub.add_parser("run")
    run.add_argument("--issue", type=int, required=True)
    run.add_argument("--execution-id")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if getattr(args, "issue", 1) <= 0:
        print("styx-agent: --issue must be a positive integer", file=sys.stderr)
        return EXIT_ERROR
    paths = Paths.from_repo(args.repo)
    try:
        paths.ensure()
        if args.command == "check":
            status, code = command_check(args, paths)
        elif args.command == "provision":
            status, code = command_provision(args, paths)
        elif args.command == "verify":
            status, code = command_verify(args, paths)
        else:
            status, code = command_run(args, paths)
    except RunnerError as exc:
        execution_id = getattr(args, "execution_id", None) or (
            f"issue-{getattr(args, 'issue')}" if hasattr(args, "issue") else args.command
        )
        blocked = isinstance(exc, BlockedError)
        status = build_status(
            command=args.command, execution_id=execution_id, paths=paths,
            phase="blocked" if blocked else "error",
            terminal_status=exc.code if blocked else "ERROR",
            blocking_code=exc.code,
            remediation=exc.remediation or exc.message,
        )
        with contextlib.suppress(OSError):
            write_status(paths, execution_id, status)
        print(f"styx-agent: {exc.code}: {redact_text(exc.message)}", file=sys.stderr)
        print(canonical_json_bytes(status).decode("utf-8"), end="")
        return exc.exit_code
    print(canonical_json_bytes(status).decode("utf-8"), end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
