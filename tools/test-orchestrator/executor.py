"""Constrained local executor for ``styx.test-plan/v1`` documents.

The executor re-validates everything before running anything:

- the plan must be byte-identical to its canonical JSON form, closed-shape,
  free of unknown fields and duplicate keys, and every command must satisfy
  the offline safety policy again at execution time;
- the plan must still bind to the exact inputs: Issue body hash, scope
  report hash, declared base and the exact repository HEAD. Any drift is a
  plan invalidation and can only produce an ERROR report, never a PASS.

Checks run without a shell, with a sanitized environment whose HOME points
at an empty scratch directory (masking credential paths), and inside a
network-denying bubblewrap namespace when bubblewrap is available.
GENERATED checks additionally run against a pristine ``git archive`` copy
of HEAD so they can never touch the primary worktree.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import tempfile
import threading
import time
from typing import Any, Mapping, Sequence

from contract_inputs import ScopeReport
from model import (
    EXECUTION_CLASSES,
    FAILURE_SCHEMA_ID,
    ISOLATION_MODES,
    ORIGINS,
    PLAN_SCHEMA_ID,
    PlanError,
    REPORT_SCHEMA_ID,
    RepositoryStateError,
    SHA256_RE,
    SHA_RE,
    SandboxError,
    canonical_json_bytes,
    generation_stanza,
    load_strict_json,
    redact_command,
)
from safety import (
    CommandPolicyError,
    command_policy_sha256,
    validate_command,
    validate_python_path_token,
    validate_resource_policy,
)

GIT_TIMEOUT_SECONDS = 120
SANDBOX_PROBE_TIMEOUT_SECONDS = 60
STREAM_CHUNK_BYTES = 65536
DRAIN_JOIN_SECONDS = 30
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

CHECK_FIELDS = frozenset(
    {
        "id",
        "origin",
        "purpose",
        "execution_class",
        "head_sha",
        "command",
        "cwd",
        "timeout_seconds",
        "max_output_bytes",
        "network",
        "isolation",
        "discard_stdout",
    }
)
PLAN_FIELDS = frozenset(
    {
        "schema",
        "tool_version",
        "issue_number",
        "execution_id",
        "base_sha",
        "head_sha",
        "issue_body_sha256",
        "scope_report_sha256",
        "command_policy_sha256",
        "checks",
        "rejected_proposals",
        "generation",
    }
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PlanError(message)


def validate_plan_document(raw_bytes: bytes) -> dict[str, Any]:
    """Strict structural validation; returns the parsed plan."""

    plan = load_strict_json(raw_bytes, source="test plan")
    _require(isinstance(plan, dict), "test plan must be a JSON object")
    _require(canonical_json_bytes(plan) == raw_bytes, "test plan is not in canonical JSON form")
    _require(set(plan) == PLAN_FIELDS, "test plan has missing or unknown fields")
    _require(plan["schema"] == PLAN_SCHEMA_ID, "test plan has an unexpected schema identifier")
    _require(
        isinstance(plan["tool_version"], str) and plan["tool_version"].count(".") == 2,
        "test plan tool_version is malformed",
    )
    _require(
        isinstance(plan["issue_number"], int)
        and not isinstance(plan["issue_number"], bool)
        and plan["issue_number"] >= 1,
        "test plan issue_number must be a positive integer",
    )
    _require(
        isinstance(plan["execution_id"], str) and plan["execution_id"] != "",
        "test plan execution_id must be a non-empty string",
    )
    for field in ("base_sha", "head_sha"):
        _require(
            isinstance(plan[field], str) and SHA_RE.fullmatch(plan[field]) is not None,
            f"test plan {field} must be a full lowercase commit SHA",
        )
    for field in ("issue_body_sha256", "scope_report_sha256", "command_policy_sha256"):
        _require(
            isinstance(plan[field], str) and SHA256_RE.fullmatch(plan[field]) is not None,
            f"test plan {field} must be a sha256 digest",
        )
    _require(plan["generation"] == generation_stanza(), "test plan generation stanza is unexpected")

    rejected = plan["rejected_proposals"]
    _require(isinstance(rejected, list), "rejected_proposals must be an array")
    for item in rejected:
        _require(
            isinstance(item, dict) and set(item) == {"index", "reason"},
            "rejected proposal entries must contain exactly index and reason",
        )
        _require(
            isinstance(item["index"], int) and not isinstance(item["index"], bool) and item["index"] >= 0,
            "rejected proposal index must be a non-negative integer",
        )
        _require(
            isinstance(item["reason"], str) and item["reason"] != "",
            "rejected proposal reason must be a non-empty string",
        )

    checks = plan["checks"]
    _require(isinstance(checks, list) and len(checks) >= 1, "test plan must contain at least one check")
    seen_ids: set[str] = set()
    mandatory = 0
    for check in checks:
        _require(isinstance(check, dict), "checks must be JSON objects")
        _require(set(check) == CHECK_FIELDS, "check has missing or unknown fields")
        _require(check["origin"] in ORIGINS, "check origin is not recognised")
        _require(
            isinstance(check["purpose"], str) and check["purpose"] != "",
            "check purpose must be a non-empty string",
        )
        _require(check["execution_class"] in EXECUTION_CLASSES, "check execution_class is not recognised")
        _require(check["head_sha"] == plan["head_sha"], "check is not bound to the plan HEAD")
        _require(check["cwd"] == ".", "check cwd must be the repository root")
        _require(check["network"] == "denied", "check network policy must be denied")
        _require(check["isolation"] in ISOLATION_MODES, "check isolation mode is not recognised")
        _require(isinstance(check["discard_stdout"], bool), "check discard_stdout must be a boolean")
        _require(
            isinstance(check["command"], list) and check["command"], "check command must be a non-empty array"
        )
        try:
            validate_command(check["command"])
            validate_resource_policy(check["timeout_seconds"], check["max_output_bytes"])
        except CommandPolicyError as exc:
            raise PlanError(f"check violates the command policy: {exc.message}") from exc
        if check["execution_class"] == "GENERATED":
            _require(check["isolation"] == "archive", "GENERATED checks must use archive isolation")
        expected_id = _check_identifier(check)
        _require(check["id"] == expected_id, "check identifier does not match its deterministic content")
        _require(check["id"] not in seen_ids, "check identifiers must be unique")
        seen_ids.add(check["id"])
        if check["execution_class"] == "MANDATORY":
            mandatory += 1
    _require(mandatory >= 1, "test plan must contain at least one MANDATORY check")
    return plan


def _check_identifier(check: Mapping[str, Any]) -> str:
    material = canonical_json_bytes(
        {
            "command": list(check["command"]),
            "discard_stdout": check["discard_stdout"],
            "execution_class": check["execution_class"],
            "head_sha": check["head_sha"],
            "isolation": check["isolation"],
            "origin": check["origin"],
            "purpose": check["purpose"],
        }
    )
    return hashlib.sha256(material).hexdigest()


def _run_git(repo: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=GIT_TIMEOUT_SECONDS,
    )


def verify_binding(
    plan: Mapping[str, Any],
    *,
    repo: Path,
    issue_body_bytes: bytes,
    scope_report: ScopeReport,
) -> None:
    """Exact-HEAD and input binding; any drift invalidates the plan."""

    if plan["command_policy_sha256"] != command_policy_sha256():
        raise RepositoryStateError("command policy changed after planning; the plan is invalidated")
    if hashlib.sha256(issue_body_bytes).hexdigest() != plan["issue_body_sha256"]:
        raise RepositoryStateError("Issue body changed after planning; the plan is invalidated")
    if scope_report.sha256 != plan["scope_report_sha256"]:
        raise RepositoryStateError("scope report changed after planning; the plan is invalidated")
    if scope_report.verdict != "PASS":
        raise RepositoryStateError(
            f"scope report verdict is {scope_report.verdict}; execution requires PASS"
        )
    if scope_report.base_sha != plan["base_sha"] or scope_report.head_sha != plan["head_sha"]:
        raise RepositoryStateError("scope report binds a different base/head; the plan is invalidated")
    head = _run_git(repo, ["rev-parse", "HEAD"])
    if head.returncode != 0:
        raise RepositoryStateError("unable to resolve repository HEAD")
    if head.stdout.decode("ascii", "replace").strip() != plan["head_sha"]:
        raise RepositoryStateError("repository HEAD is not the exact planned commit; the plan is invalidated")
    status = _run_git(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if status.returncode != 0:
        raise RepositoryStateError("unable to inspect repository status")
    if status.stdout != b"":
        raise RepositoryStateError("repository worktree is not clean; evidence must bind to a committed HEAD")


def locate_bwrap() -> str | None:
    return shutil.which("bwrap")


class ExecutionEnvironment:
    """Scratch HOME/TMP plus optional bubblewrap network denial."""

    def __init__(self, repo: Path, head_sha: str):
        # bubblewrap rejects relative bind/chdir paths, so the sandbox must
        # always be built from the resolved repository location.
        self.repo = repo.resolve()
        self.head_sha = head_sha
        self._temp = tempfile.TemporaryDirectory(prefix="styx-test-orchestrator-")
        self.root = Path(self._temp.name)
        self.home = self.root / "home"
        self.tmp = self.root / "tmp"
        self.home.mkdir()
        self.tmp.mkdir()
        self.bwrap = locate_bwrap()
        self._archive_dir: Path | None = None
        self._sandbox_ok: bool | None = None

    def cleanup(self) -> None:
        self._temp.cleanup()

    def ensure_sandbox(self) -> None:
        """Fail closed: no check may run without network-denied isolation.

        Probes bubblewrap once per environment; a missing binary or a probe
        that cannot establish the namespace makes every execution an ERROR,
        with no unsandboxed fallback.
        """

        if self.bwrap is None:
            raise SandboxError("bubblewrap is required for network-denied execution and was not found")
        if self._sandbox_ok is None:
            probe = [
                self.bwrap,
                "--die-with-parent",
                "--new-session",
                "--unshare-net",
                "--ro-bind", "/", "/",
                "--dev", "/dev",
                "--proc", "/proc",
                "--tmpfs", "/tmp",
                "--chdir", "/",
                "/bin/true",
            ]
            try:
                result = subprocess.run(
                    probe,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=SANDBOX_PROBE_TIMEOUT_SECONDS,
                )
            except (OSError, subprocess.TimeoutExpired):
                self._sandbox_ok = False
            else:
                self._sandbox_ok = result.returncode == 0
        if not self._sandbox_ok:
            raise SandboxError("bubblewrap cannot establish the network-denied sandbox")

    def environment(self) -> dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(self.home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TMPDIR": str(self.tmp),
            "XDG_CACHE_HOME": str(self.tmp / "xdg-cache"),
            "XDG_CONFIG_HOME": str(self.tmp / "xdg-config"),
            "CI": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
        }

    def archive_workdir(self) -> Path:
        """Materialise a pristine copy of HEAD for isolated generated checks."""

        if self._archive_dir is not None:
            return self._archive_dir
        archive_path = self.root / "head.tar"
        with open(archive_path, "wb") as handle:
            result = subprocess.run(
                ["git", "-C", str(self.repo), "archive", "--format=tar", self.head_sha],
                stdout=handle,
                stderr=subprocess.PIPE,
                check=False,
                timeout=GIT_TIMEOUT_SECONDS,
            )
        if result.returncode != 0:
            raise RepositoryStateError("unable to archive the planned HEAD for isolated execution")
        workdir = self.root / "archive"
        workdir.mkdir()
        with tarfile.open(archive_path) as archive:
            archive.extractall(workdir, filter="data")
        archive_path.unlink()
        self._archive_dir = workdir
        return workdir

    def command_prefix(self, workdir: Path) -> list[str]:
        if self.bwrap is None:
            raise SandboxError("bubblewrap is required for network-denied execution and was not found")
        # The repository stays read-only inside the sandbox: checks may read
        # tracked content and .git metadata but can never mutate the primary
        # worktree. Only the orchestrator scratch root is writable.
        return [
            self.bwrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-net",
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            "--bind", str(self.root), str(self.root),
            "--ro-bind", str(self.repo), str(self.repo),
            "--chdir", str(workdir),
        ]


def _ensure_python_paths_within(command: Sequence[str], workdir: Path) -> None:
    """Runtime containment check applied immediately before execution.

    The syntactic policy already rejects absolute paths and ``..``; this
    resolves every existing path argument (following symlinks) and rejects
    anything whose real location escapes the execution root, so a committed
    symlink cannot reach the primary worktree or the wider filesystem.
    """

    if command[0] != "python3":
        return
    root = workdir.resolve()
    for token in command[3:]:
        validate_python_path_token(token)
        material = token.split("=", 1)[1] if token.startswith("-") and "=" in token else token
        if material.startswith("-"):
            continue
        candidate = root / material
        if not candidate.exists() and not candidate.is_symlink():
            continue
        resolved = candidate.resolve()
        if resolved != root and not resolved.is_relative_to(root):
            raise CommandPolicyError(f"path escapes the execution root: {token!r}")


def run_check(check: Mapping[str, Any], environment: ExecutionEnvironment) -> dict[str, Any]:
    """Run one validated check and classify the outcome."""

    if environment.bwrap is None:
        return _outcome("ERROR", "sandbox_unavailable", b"", b"", truncated=False)

    if check["isolation"] == "archive":
        workdir = environment.archive_workdir()
    else:
        workdir = environment.repo

    try:
        _ensure_python_paths_within(check["command"], workdir)
    except CommandPolicyError:
        return _outcome("ERROR", "rejected_command", b"", b"", truncated=False)

    env = environment.environment()
    executable = shutil.which(check["command"][0], path=env["PATH"])
    if executable is None:
        return _outcome("ERROR", "missing_tool", b"", b"", truncated=False)

    argv = [*environment.command_prefix(workdir), executable, *check["command"][1:]]
    return _run_bounded(
        argv,
        workdir=workdir,
        env=env,
        timeout_seconds=check["timeout_seconds"],
        cap=check["max_output_bytes"],
        discard_stdout=check["discard_stdout"],
    )


def _drain_stream(stream: Any, cap: int, state: dict[str, Any], limit: threading.Event) -> None:
    """Incremental bounded reader: never accumulates more than ``cap`` bytes."""

    descriptor = stream.fileno()
    try:
        while True:
            try:
                chunk = os.read(descriptor, STREAM_CHUNK_BYTES)
            except OSError:
                break
            if not chunk:
                break
            state["observed"] += len(chunk)
            captured: bytearray = state["captured"]
            if len(captured) < cap:
                captured.extend(chunk[: cap - len(captured)])
            if state["observed"] > cap:
                limit.set()
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _kill_process_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except OSError:
            pass


def _run_bounded(
    argv: list[str],
    *,
    workdir: Path,
    env: dict[str, str],
    timeout_seconds: int,
    cap: int,
    discard_stdout: bool,
) -> dict[str, Any]:
    """Run argv with streaming output caps, a deadline and group teardown.

    stdout/stderr are read incrementally into per-stream buffers bounded by
    ``cap``; exceeding either limit kills the whole process group (checks
    run in their own session, and bubblewrap adds ``--die-with-parent`` for
    its children), as does the deadline. Hashes cover exactly the captured,
    possibly truncated, content.
    """

    try:
        process = subprocess.Popen(
            argv,
            cwd=workdir,
            env=env,
            stdout=subprocess.DEVNULL if discard_stdout else subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        return _outcome("ERROR", "internal_error", b"", b"", truncated=False)

    limit = threading.Event()
    states = {
        "stdout": {"captured": bytearray(), "observed": 0},
        "stderr": {"captured": bytearray(), "observed": 0},
    }
    readers: list[threading.Thread] = []
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        if stream is None:
            continue
        thread = threading.Thread(
            target=_drain_stream, args=(stream, cap, states[name], limit), daemon=True
        )
        thread.start()
        readers.append(thread)

    observed_class: str | None = None
    deadline = time.monotonic() + timeout_seconds
    while True:
        if limit.is_set():
            observed_class = "output_limit_exceeded"
            _kill_process_group(process)
            break
        if time.monotonic() >= deadline:
            observed_class = "timeout"
            _kill_process_group(process)
            break
        if process.poll() is not None and all(not thread.is_alive() for thread in readers):
            break
        time.sleep(0.01)

    process.wait()
    for thread in readers:
        thread.join(timeout=DRAIN_JOIN_SECONDS)

    stdout_state = states["stdout"]
    stderr_state = states["stderr"]
    if observed_class is None and (stdout_state["observed"] > cap or stderr_state["observed"] > cap):
        observed_class = "output_limit_exceeded"
    truncated = stdout_state["observed"] > cap or stderr_state["observed"] > cap

    stdout = bytes(stdout_state["captured"])
    stderr = bytes(stderr_state["captured"])
    if observed_class in ("output_limit_exceeded", "timeout"):
        verdict = "ERROR"
    elif process.returncode != 0:
        verdict, observed_class = "FAIL", "nonzero_exit"
    else:
        verdict, observed_class = "PASS", None
    return _outcome(
        verdict,
        observed_class,
        stdout,
        stderr,
        truncated=truncated,
        cap=cap,
        stdout_bytes=stdout_state["observed"],
        stderr_bytes=stderr_state["observed"],
    )


def _outcome(
    verdict: str,
    observed_class: str | None,
    stdout: bytes,
    stderr: bytes,
    *,
    truncated: bool,
    cap: int | None = None,
    stdout_bytes: int | None = None,
    stderr_bytes: int | None = None,
) -> dict[str, Any]:
    bounded_stdout = stdout if cap is None else stdout[:cap]
    bounded_stderr = stderr if cap is None else stderr[:cap]
    return {
        "verdict": verdict,
        "observed_class": observed_class,
        "stdout_sha256": hashlib.sha256(bounded_stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(bounded_stderr).hexdigest(),
        "stdout_bytes": len(stdout) if stdout_bytes is None else stdout_bytes,
        "stderr_bytes": len(stderr) if stderr_bytes is None else stderr_bytes,
        "output_truncated": truncated,
    }


def _failure_entry(check: Mapping[str, Any], outcome: Mapping[str, Any], plan_sha256: str) -> dict[str, Any]:
    return {
        "schema": FAILURE_SCHEMA_ID,
        "test_id": check["id"],
        "category": check["execution_class"],
        "expected_outcome": "PASS",
        "observed_class": outcome["observed_class"],
        "verdict": outcome["verdict"],
        "reproduction": {
            "plan_sha256": plan_sha256,
            "check_id": check["id"],
            "command": redact_command(check["command"]),
        },
        "stdout_sha256": outcome["stdout_sha256"],
        "stderr_sha256": outcome["stderr_sha256"],
        "stdout_bytes": outcome["stdout_bytes"],
        "stderr_bytes": outcome["stderr_bytes"],
        "output_truncated": outcome["output_truncated"],
    }


def _plan_level_failure(plan_sha256: str, observed_class: str) -> dict[str, Any]:
    return {
        "schema": FAILURE_SCHEMA_ID,
        "test_id": "plan",
        "category": "PLAN",
        "expected_outcome": "PASS",
        "observed_class": observed_class,
        "verdict": "ERROR",
        "reproduction": {"plan_sha256": plan_sha256, "check_id": "plan", "command": []},
        "stdout_sha256": EMPTY_SHA256,
        "stderr_sha256": EMPTY_SHA256,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "output_truncated": False,
    }


def _class_verdict(outcomes: list[str]) -> str:
    if not outcomes:
        return "NOT_RUN"
    if "ERROR" in outcomes:
        return "ERROR"
    if "FAIL" in outcomes:
        return "FAIL"
    return "PASS"


def _overall_verdict(class_verdicts: Mapping[str, str]) -> str:
    values = list(class_verdicts.values())
    if "ERROR" in values:
        return "ERROR"
    if "FAIL" in values:
        return "FAIL"
    if class_verdicts["MANDATORY"] != "PASS":
        return "ERROR"
    return "PASS"


def execute_plan(
    plan: Mapping[str, Any],
    plan_sha256: str,
    *,
    repo: Path,
    issue_body_bytes: bytes,
    scope_report: ScopeReport,
    environment: ExecutionEnvironment | None = None,
) -> dict[str, Any]:
    """Run every planned check and build the ``styx.test-report/v1`` document."""

    class_outcomes: dict[str, list[str]] = {name: [] for name in EXECUTION_CLASSES}
    failures: list[dict[str, Any]] = []
    blocked = False
    try:
        verify_binding(plan, repo=repo, issue_body_bytes=issue_body_bytes, scope_report=scope_report)
    except RepositoryStateError:
        blocked = True
        failures.append(_plan_level_failure(plan_sha256, "plan_invalidated"))

    if not blocked:
        owned_environment = environment is None
        run_environment = environment or ExecutionEnvironment(repo, plan["head_sha"])
        try:
            try:
                run_environment.ensure_sandbox()
            except SandboxError:
                blocked = True
                failures.append(_plan_level_failure(plan_sha256, "sandbox_unavailable"))
            if not blocked:
                for check in plan["checks"]:
                    try:
                        outcome = run_check(check, run_environment)
                    except (RepositoryStateError, SandboxError):
                        outcome = _outcome("ERROR", "internal_error", b"", b"", truncated=False)
                    class_outcomes[check["execution_class"]].append(outcome["verdict"])
                    if outcome["verdict"] != "PASS":
                        failures.append(_failure_entry(check, outcome, plan_sha256))
        finally:
            if owned_environment:
                run_environment.cleanup()

    class_verdicts = {name: _class_verdict(class_outcomes[name]) for name in EXECUTION_CLASSES}
    verdict = "ERROR" if blocked else _overall_verdict(class_verdicts)
    return {
        "schema": REPORT_SCHEMA_ID,
        "issue_number": plan["issue_number"],
        "execution_id": plan["execution_id"],
        "base_sha": plan["base_sha"],
        "head_sha": plan["head_sha"],
        "issue_body_sha256": plan["issue_body_sha256"],
        "plan_sha256": plan_sha256,
        "scope_report_sha256": plan["scope_report_sha256"],
        "command_policy_sha256": plan["command_policy_sha256"],
        "mandatory_verdict": class_verdicts["MANDATORY"],
        "regression_verdict": class_verdicts["REGRESSION"],
        "generated_verdict": class_verdicts["GENERATED"],
        "adversarial_verdict": class_verdicts["ADVERSARIAL"],
        "static_verdict": class_verdicts["STATIC"],
        "rollback_verdict": class_verdicts["ROLLBACK"],
        "failures": failures,
        "generation": generation_stanza(),
        "verdict": verdict,
    }


def review_eligible(
    test_report: Mapping[str, Any],
    scope_report: Mapping[str, Any],
    candidate_head_sha: str,
) -> bool:
    """The frozen review-eligibility rule from the task contract."""

    return (
        test_report.get("schema") == REPORT_SCHEMA_ID
        and scope_report.get("schema") == "styx.task-scope-report/v1"
        and test_report.get("verdict") == "PASS"
        and test_report.get("head_sha") == candidate_head_sha
        and scope_report.get("verdict") == "PASS"
        and scope_report.get("head_sha") == candidate_head_sha
    )
