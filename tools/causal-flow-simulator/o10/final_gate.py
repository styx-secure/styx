#!/usr/bin/env python3
"""Regenerate O-10 and frozen evidence in two clean, non-local clones."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from canonical_report import ReportError, store_report
from scope_guard import BASE_SHA


REPORT_FIELDS = frozenset(
    {"report_digests", "schema", "suite_counts", "verdict", "worktree_count"}
)
EXPECTED_COUNTS = {
    "o06c": 29,
    "o07": 51,
    "o08": 37,
    "o10": 13,
    "o14": 15,
    "review_base": 28,
    "review_full": 39,
}


class GateError(ValueError):
    """A clean-checkout regeneration or frozen suite failed."""


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int = 180,
    allow_empty: bool = False,
) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise GateError("required command timed out") from exc
    if completed.returncode != 0:
        raise GateError("required command failed")
    if not allow_empty and not completed.stdout.strip():
        raise GateError("required command produced empty output")
    if re.search(r"skipped\s*=\s*[1-9]|OK \(skipped=[1-9]", completed.stdout):
        raise GateError("required suite skipped tests")
    return completed.stdout


def _unittest_count(output: str) -> int:
    match = re.search(r"Ran (\d+) tests?", output)
    if match is None or "OK" not in output:
        raise GateError("unittest result is not an unskipped success")
    return int(match.group(1))


def _clone(source: Path, destination: Path, candidate: str, env: dict[str, str]) -> None:
    _run(
        ["git", "clone", "--no-local", "--no-checkout", str(source), str(destination)],
        cwd=destination.parent,
        env=env,
    )
    _run(["git", "checkout", "--detach", candidate], cwd=destination, env=env)
    head = _run(["git", "rev-parse", "HEAD"], cwd=destination, env=env).strip()
    if head != candidate:
        raise GateError("clone HEAD mismatch")
    _run(
        ["git", "merge-base", "--is-ancestor", BASE_SHA, candidate],
        cwd=destination,
        env=env,
        allow_empty=True,
    )
    if _status(destination, env):
        raise GateError("clone is not initially clean")


def _status(repo: Path, env: dict[str, str]) -> str:
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repo,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise GateError("cannot inspect checkout status")
    return completed.stdout


def _regenerate(
    clone: Path, output: Path, base: str, candidate: str, javascript: str, env: dict[str, str]
) -> tuple[dict[str, bytes], dict[str, int]]:
    python = sys.executable
    reports = {
        "probe": output / "probe.json",
        "runtime": output / "runtime.json",
        "mutations": output / "mutations.json",
        "scope": output / "scope.json",
    }
    _run(
        [python, "tools/causal-flow-simulator/o10/validate_test_inventory.py", "--repo-root", "."],
        cwd=clone,
        env=env,
    )
    _run(
        [python, "tools/causal-flow-simulator/o10/validate_inventory.py", "--repo-root", "."],
        cwd=clone,
        env=env,
    )
    _run(
        [python, "tools/causal-flow-simulator/o10/run_taxonomy_probe.py", "--repo-root", ".", "--output", str(reports["probe"])],
        cwd=clone,
        env=env,
    )
    _run(
        [python, "tools/causal-flow-simulator/o10/run_cross_runtime.py", "--repo-root", ".", "--javascript", javascript, "--output", str(reports["runtime"])],
        cwd=clone,
        env=env,
    )
    _run(
        [python, "tools/causal-flow-simulator/o10/run_mutations.py", "--repo-root", ".", "--javascript", javascript, "--output", str(reports["mutations"])],
        cwd=clone,
        env=env,
    )
    _run(
        [python, "tools/causal-flow-simulator/o10/scope_guard.py", "--repo-root", ".", "--base", base, "--candidate", candidate, "--mode", "strict", "--output", str(reports["scope"])],
        cwd=clone,
        env=env,
    )

    suite_commands = {
        "o06c": [python, "-m", "unittest", "discover", "-s", "tools/causal-flow-simulator/o06c/tests", "-p", "test_*.py"],
        "o07": [python, "-m", "unittest", "discover", "-s", "tools/causal-flow-simulator/o07/tests", "-p", "test_*.py"],
        "o08": [python, "-m", "unittest", "discover", "-s", "tools/causal-flow-simulator/o08/tests", "-p", "test_*.py"],
        "o10": [python, "-m", "unittest", "discover", "-s", "tools/causal-flow-simulator/o10/tests", "-p", "test_*.py"],
        "o14": [python, "-m", "unittest", "discover", "-s", "tools/causal-flow-simulator/o14/tests", "-p", "test_*.py"],
    }
    counts = {
        name: _unittest_count(_run(command, cwd=clone, env=env))
        for name, command in suite_commands.items()
    }
    base_modules = ("test_validate.py", "test_o14_scope.py", "test_o06c_capability_gates.py")
    counts["review_base"] = sum(
        _unittest_count(
            _run(
                [python, "-m", "unittest", "discover", "-s", "tools/protocol-review-model/tests", "-p", module],
                cwd=clone,
                env=env,
            )
        )
        for module in base_modules
    )
    counts["review_full"] = _unittest_count(
        _run(
            [python, "-m", "unittest", "discover", "-s", "tools/protocol-review-model/tests", "-p", "test_*.py"],
            cwd=clone,
            env=env,
        )
    )
    if counts != EXPECTED_COUNTS:
        raise GateError("suite count drift")

    model_output = output / "review-model.json"
    _run(
        [python, "tools/protocol-review-model/validate.py", "--repo-root", ".", "--schema", "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json", "--model", "docs/protocol/review/styx-app-kernel-v0-review-model.json", "--output", str(model_output)],
        cwd=clone,
        env=env,
    )
    _run(
        [python, "tools/causal-flow-simulator/o08/validate_inventory.py", "--repo-root", ".", "--output", str(output / "o08-inventory.json")],
        cwd=clone,
        env=env,
    )
    _run([python, "tools/docs-claims-lint/claims_lint.py", "--scan", "docs", "specs", "--exclude", "docs/superpowers", "docs/security", "docs/archive", "docs/piano-utente.md"], cwd=clone, env=env)
    _run([python, "tools/docs-translation-sync/check.py", "--manifest", "docs/platform/translation-pairs.json"], cwd=clone, env=env)
    _run(["reuse", "lint"], cwd=clone, env=env)
    _run(["git", "diff", "--check"], cwd=clone, env=env, allow_empty=True)
    if _status(clone, env):
        raise GateError("producer changed a clean checkout")
    return ({name: path.read_bytes() for name, path in reports.items()}, counts)


def build_report(repo: Path, base: str, candidate: str, javascript: str) -> dict[str, Any]:
    if base != BASE_SHA:
        raise GateError("contract Base mismatch")
    if shutil.which(javascript) is None:
        raise GateError("JavaScript runtime is unavailable")
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    with tempfile.TemporaryDirectory(prefix="styx-o10-final-") as directory:
        root = Path(directory)
        clone_a = root / "clone-a"
        clone_b = root / "clone-b"
        _clone(repo, clone_a, candidate, environment)
        _clone(repo, clone_b, candidate, environment)
        if clone_a.resolve() == clone_b.resolve():
            raise GateError("clone roots are not distinct")
        first, first_counts = _regenerate(clone_a, root / "out-a", base, candidate, javascript, environment)
        second, second_counts = _regenerate(clone_b, root / "out-b", base, candidate, javascript, environment)
        if first_counts != second_counts:
            raise GateError("suite counts differ between clones")
        if set(first) != set(second) or any(first[name] != second[name] for name in first):
            raise GateError("canonical reports differ between clones")
        digests = {name: hashlib.sha256(payload).hexdigest() for name, payload in sorted(first.items())}
    return {
        "report_digests": digests,
        "schema": "styx.o10-final-gate-report.v1",
        "suite_counts": dict(sorted(first_counts.items())),
        "verdict": "PASS",
        "worktree_count": 2,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--javascript", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(
            args.repo_root.resolve(), args.base, args.candidate, args.javascript
        )
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (OSError, ValueError, ReportError) as exc:
        print(f"O-10 final gate: FAIL: {exc}", file=sys.stderr)
        return 2
    print("O-10 final gate: PASS worktrees=2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
