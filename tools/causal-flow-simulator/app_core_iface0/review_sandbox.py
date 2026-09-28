#!/usr/bin/env python3
"""Run reviewer counterexamples against a clean, read-only APP-core checkout."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

sys.dont_write_bytecode = True

from canonical_json import CanonicalJsonError, loads as canonical_loads

SUBTREE = Path("tools/causal-flow-simulator/app_core_iface0")
MAX_PROBE_OUTPUT_BYTES = 16 * 1024
DEFAULT_TIMEOUT_SECONDS = 7200
SEVERITIES = frozenset({"BLOCKER", "HIGH", "MEDIUM", "LOW", "NOTE"})


class ReviewSandboxError(ValueError):
    """A review sandbox input or invariant is invalid."""


@dataclass(frozen=True)
class ProbeResult:
    reproduced: bool
    summary: str


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    durationSeconds: float
    exitCode: int
    stdoutSha256: str
    stderrSha256: str
    stdoutTail: str
    stderrTail: str


def parse_probe_output(raw: bytes) -> ProbeResult:
    if len(raw) > MAX_PROBE_OUTPUT_BYTES:
        raise ReviewSandboxError("probe output exceeds 16384 bytes")
    try:
        value = canonical_loads(raw)
    except CanonicalJsonError as error:
        raise ReviewSandboxError("probe output must be canonical JSON") from error
    if not isinstance(value, dict) or set(value) != {"reproduced", "summary"}:
        raise ReviewSandboxError("probe output must contain exactly reproduced and summary")
    reproduced = value["reproduced"]
    summary = value["summary"]
    if not isinstance(reproduced, bool):
        raise ReviewSandboxError("probe reproduced must be boolean")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 1000:
        raise ReviewSandboxError("probe summary must be 1..1000 characters")
    return ProbeResult(reproduced=reproduced, summary=summary)


def classify_finding(severity: str, *, reproduced: bool) -> dict[str, str]:
    if severity not in SEVERITIES:
        raise ReviewSandboxError(f"unsupported severity: {severity}")
    if reproduced:
        return {"disposition": "CONFIRMED", "effectiveSeverity": severity}
    return {
        "disposition": "DOWNGRADED_NOT_REPRODUCED",
        "effectiveSeverity": "NOTE",
    }


def required_validation_commands(checkout: Path) -> list[list[str]]:
    app = checkout / SUBTREE
    contract = app / "contract"
    return [
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            str(app / "tests"),
            "-p",
            "test_*.py",
        ],
        [
            sys.executable,
            str(app / "generate_seed_registry.py"),
            "--repo-root",
            str(checkout),
            "--contract",
            str(contract),
            "--prove-reference-round-trip",
        ],
        [
            sys.executable,
            str(app / "generate_seed_registry.py"),
            "--repo-root",
            str(checkout),
            "--contract",
            str(contract),
            "--prove-positive-carrier-closure",
        ],
    ]


def run_read_only(
    checkout: Path,
    scratch: Path,
    argv: Sequence[str],
    *,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[bytes]:
    checkout = checkout.resolve()
    scratch = scratch.resolve()
    if not checkout.is_dir() or not scratch.is_dir():
        raise ReviewSandboxError("checkout and scratch must exist")
    system_mounts: list[str] = []
    for path in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"):
        if Path(path).exists():
            system_mounts.extend(("--ro-bind", path, path))
    node = shutil.which("node")
    if node is None:
        candidates = sorted(
            (Path.home() / ".nvm" / "versions" / "node").glob("*/bin/node")
        )
        node = str(candidates[-1]) if candidates else None
    runtime_mounts: list[str] = []
    if node is not None:
        runtime_mounts.extend(
            (
                "--dir",
                "/review-bin",
                "--ro-bind",
                str(Path(node).resolve()),
                "/review-bin/node",
            )
        )
    external_files: list[Path] = []
    for argument in argv:
        candidate = Path(argument)
        if candidate.is_absolute() and candidate.is_file():
            resolved = candidate.resolve()
            if not any(
                resolved.is_relative_to(Path(root))
                for root in (
                    "/usr",
                    "/bin",
                    "/sbin",
                    "/lib",
                    "/lib64",
                    "/etc",
                )
            ):
                external_files.append(resolved)
    external_mounts: list[str] = []
    parents = {
        parent
        for path in external_files
        for parent in path.parents
        if parent != Path("/")
    }
    for parent in sorted(parents, key=lambda item: len(item.parts)):
        external_mounts.extend(("--dir", str(parent)))
    for path in external_files:
        external_mounts.extend(("--ro-bind", str(path), str(path)))
    command = [
        "bwrap",
        "--die-with-parent",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        *system_mounts,
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        *runtime_mounts,
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        str(checkout),
        "/media",
        "--bind",
        str(scratch),
        "/run",
        *external_mounts,
        "--chdir",
        "/media",
        "--clearenv",
        "--setenv",
        "HOME",
        "/run",
        "--setenv",
        "TMPDIR",
        "/run",
        "--setenv",
        "PYTHONDONTWRITEBYTECODE",
        "1",
        "--setenv",
        "STYX_REVIEW_SANDBOX",
        "1",
        "--setenv",
        "PATH",
        "/review-bin:/usr/local/bin:/usr/bin:/bin",
        "--",
        *argv,
    ]
    return subprocess.run(
        command,
        capture_output=True,
        check=False,
        timeout=timeout_seconds,
    )


def _command_result(
    checkout: Path,
    scratch: Path,
    argv: Sequence[str],
    timeout_seconds: int,
) -> CommandResult:
    started = time.monotonic()
    completed = run_read_only(
        checkout, scratch, argv, timeout_seconds=timeout_seconds
    )
    duration = time.monotonic() - started
    return CommandResult(
        argv=list(argv),
        durationSeconds=round(duration, 3),
        exitCode=completed.returncode,
        stdoutSha256=hashlib.sha256(completed.stdout).hexdigest(),
        stderrSha256=hashlib.sha256(completed.stderr).hexdigest(),
        stdoutTail=completed.stdout[-4000:].decode("utf-8", "replace"),
        stderrTail=completed.stderr[-4000:].decode("utf-8", "replace"),
    )


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    ).stdout.strip()


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def run_review(
    *,
    repo_root: Path,
    revision: str,
    finding_id: str,
    severity: str,
    probe_argv: Sequence[str],
    output: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    if not finding_id.strip() or len(finding_id) > 200:
        raise ReviewSandboxError("finding id must be 1..200 characters")
    if not probe_argv:
        raise ReviewSandboxError("a counterexample command is required after --")
    if severity not in SEVERITIES:
        raise ReviewSandboxError(f"unsupported severity: {severity}")
    if shutil.which("bwrap") is None:
        raise ReviewSandboxError("bwrap is required")
    repo_root = repo_root.resolve()
    output = output.resolve()
    try:
        output.relative_to(repo_root)
    except ValueError:
        pass
    else:
        raise ReviewSandboxError("output must be outside the repository")
    commit = _git(repo_root, "rev-parse", "--verify", f"{revision}^{{commit}}")
    with tempfile.TemporaryDirectory(prefix="styx-review-") as temporary:
        temporary_root = Path(temporary)
        checkout = temporary_root / "checkout"
        scratch = temporary_root / "scratch"
        scratch.mkdir()
        subprocess.run(
            [
                "git",
                "clone",
                "--no-hardlinks",
                "--no-checkout",
                "--quiet",
                str(repo_root),
                str(checkout),
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        subprocess.run(
            ["git", "-C", str(checkout), "checkout", "--detach", "--quiet", commit],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        try:
            if _git(checkout, "status", "--porcelain"):
                raise ReviewSandboxError("detached review checkout is not clean")
            validation: list[CommandResult] = []
            for command in required_validation_commands(Path("/media")):
                result = _command_result(
                    checkout, scratch, command, timeout_seconds
                )
                validation.append(result)
                if result.exitCode != 0:
                    report = {
                        "schema": "styx-review-execution-v1",
                        "commit": commit,
                        "findingId": finding_id,
                        "reportedSeverity": severity,
                        "disposition": "INVALID_BASELINE",
                        "validation": [asdict(item) for item in validation],
                    }
                    _write_report(output, report)
                    return report
            probe_completed = run_read_only(
                checkout,
                scratch,
                probe_argv,
                timeout_seconds=timeout_seconds,
            )
            probe_error: str | None = None
            try:
                if probe_completed.returncode != 0:
                    raise ReviewSandboxError("counterexample command failed")
                probe = parse_probe_output(probe_completed.stdout)
            except ReviewSandboxError as error:
                probe = ProbeResult(False, str(error))
                probe_error = str(error)
            classification = (
                {"disposition": "INVALID_PROBE"}
                if probe_error is not None
                else classify_finding(severity, reproduced=probe.reproduced)
            )
            report = {
                "schema": "styx-review-execution-v1",
                "commit": commit,
                "findingId": finding_id,
                "reportedSeverity": severity,
                **classification,
                "probe": {
                    "argv": list(probe_argv),
                    "exitCode": probe_completed.returncode,
                    "reproduced": probe.reproduced,
                    "summary": probe.summary,
                    "stdoutSha256": hashlib.sha256(
                        probe_completed.stdout
                    ).hexdigest(),
                    "stderrSha256": hashlib.sha256(
                        probe_completed.stderr
                    ).hexdigest(),
                    "stderrTail": probe_completed.stderr[-4000:].decode(
                        "utf-8", "replace"
                    ),
                },
                "validation": [asdict(item) for item in validation],
            }
            if _git(checkout, "status", "--porcelain"):
                raise ReviewSandboxError("review command changed the checkout")
            _write_report(output, report)
            return report
        finally:
            shutil.rmtree(checkout, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--severity", choices=sorted(SEVERITIES), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS
    )
    parser.add_argument("probe", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    probe = arguments.probe
    if probe and probe[0] == "--":
        probe = probe[1:]
    try:
        report = run_review(
            repo_root=arguments.repo_root,
            revision=arguments.revision,
            finding_id=arguments.finding_id,
            severity=arguments.severity,
            probe_argv=probe,
            output=arguments.output,
            timeout_seconds=arguments.timeout_seconds,
        )
    except (
        OSError,
        ReviewSandboxError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"review sandbox failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["disposition"] not in {"INVALID_BASELINE", "INVALID_PROBE"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
