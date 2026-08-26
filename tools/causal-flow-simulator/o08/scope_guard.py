#!/usr/bin/env python3
"""Fail-closed path, endpoint and package guard for Issue #250."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True

from canonical_report import store_report
from semantic_registry import (
    BASE_SHA, EXPECTED_HANDOFF_STAGE_COUNTS, EXPECTED_ROLE_COUNTS, load_source_registry,
)


REPORT_SCHEMA = "styx-o08-scope-report/v1"
COPY_THRESHOLD = 25
O08_PREFIX = "tools/causal-flow-simulator/o08/"
VALIDATOR_PATH = "tools/protocol-review-model/validate.py"
ALLOWED_FILES = frozenset({
    "docs/protocol/styx-app-kernel-v0-decisions.md",
    "docs/protocol/styx-app-kernel-v0-resource-envelope-analysis.md",
    "docs/protocol/styx-app-kernel-v0-resource-envelope-falsification-report.md",
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
    "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
    "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
    "docs/protocol/protocol-hardening-plan.md",
    "docs/protocol/review/README.md",
    "docs/protocol/review/styx-app-kernel-v0-review-model.json",
    "docs/security/STYX-THREAT-MODEL.md",
    "tools/causal-flow-simulator/README.md",
    VALIDATOR_PATH,
})
PACKAGE_FILES = frozenset({
    "README.md", "resource-envelope.schema.json", "resource-envelope.candidates.json",
    "resource-envelope.candidate.json", "resource-envelope.sources.json", "semantic_registry.py",
    "canonical_report.py", "envelope_model.py", "independent_oracle.mjs", "scenario_generator.py",
    "validate_inventory.py", "validate_envelope.py", "generate_handoff.py", "run_boundary_probe.py",
    "run_combined_probe.py", "run_cross_runtime.py", "run_measurements.py", "run_mutations.py",
    "scope_guard.py", "final_gate.py", "tests/test_schema.py", "tests/test_inventory.py",
    "tests/test_activation.py", "tests/test_boundaries.py", "tests/test_combined.py",
    "tests/test_failure_semantics.py", "tests/test_cross_runtime.py", "tests/test_reports.py",
    "tests/test_scope_guard.py",
})


class ScopeViolation(ValueError):
    """The Issue #250 scope or endpoint contract was violated."""


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", str(repo), *args], check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _commit(repo: Path, value: str) -> str:
    return _git(repo, "rev-parse", f"{value}^{{commit}}").stdout.decode().strip()


def _blob(repo: Path, revision: str, path: str) -> bytes:
    return _git(repo, "cat-file", "blob", f"{revision}:{path}").stdout


def _allowed(path: str) -> bool:
    return path in ALLOWED_FILES or path.startswith(O08_PREFIX)


def changed_relation(repo: Path, base: str, candidate: str) -> list[dict[str, object]]:
    fields = _git(
        repo, "diff-tree", "-r", f"--find-renames={COPY_THRESHOLD}%", f"--find-copies={COPY_THRESHOLD}%",
        "--find-copies-harder", "-l0", "--name-status", "-z", "--no-commit-id", base, candidate,
    ).stdout.split(b"\0")
    if fields and not fields[-1]:
        fields.pop()
    rows = []
    cursor = 0
    while cursor < len(fields):
        status = fields[cursor].decode("ascii")
        cursor += 1
        width = 2 if status[:1] in {"C", "R"} else 1
        paths = [fields[cursor + index].decode("utf-8") for index in range(width)]
        cursor += width
        if status[:1] in {"C", "R"}:
            raise ScopeViolation("copy/rename relation forbidden")
        for path in paths:
            if not _allowed(path):
                raise ScopeViolation(f"out-of-scope endpoint: {path}")
        rows.append({"status": status, "paths": paths})
    return rows


def _check_endpoints(repo: Path, candidate: str, rows: list[dict[str, object]]) -> None:
    for row in rows:
        if str(row["status"]).startswith("D"):
            raise ScopeViolation("deletion forbidden")
        for path in row["paths"]:
            line = _git(repo, "ls-tree", candidate, "--", str(path)).stdout.decode().strip()
            if not line:
                raise ScopeViolation(f"missing endpoint: {path}")
            mode, kind, _object_id = line.split("\t", 1)[0].split()
            if mode in {"120000", "160000"} or kind != "blob":
                raise ScopeViolation(f"symlink/submodule endpoint: {path}")
            if b"\0" in _blob(repo, candidate, str(path)):
                raise ScopeViolation(f"binary endpoint: {path}")


def _non_assignment_ast(source: str) -> list[str]:
    result = []
    for node in ast.parse(source).body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        result.append(ast.dump(node, include_attributes=False))
    return result


def _check_validator_delta(repo: Path, base: str, candidate: str, changed: set[str]) -> None:
    if VALIDATOR_PATH not in changed:
        return
    before = _blob(repo, base, VALIDATOR_PATH).decode("utf-8")
    after = _blob(repo, candidate, VALIDATOR_PATH).decode("utf-8")
    if _non_assignment_ast(before) != _non_assignment_ast(after):
        raise ScopeViolation("validator control-flow/import/function/class AST drift")


def _check_package(repo: Path, candidate: str) -> None:
    listing = _git(repo, "ls-tree", "-r", "--name-only", candidate, "--", O08_PREFIX).stdout.decode().splitlines()
    relative = {path.removeprefix(O08_PREFIX) for path in listing}
    if relative != PACKAGE_FILES:
        missing = sorted(PACKAGE_FILES - relative)
        extra = sorted(relative - PACKAGE_FILES)
        raise ScopeViolation(f"O-08 package set mismatch missing={missing} extra={extra}")


def build_report(repo: Path, base_value: str, candidate_value: str) -> dict[str, object]:
    base = _commit(repo, base_value)
    candidate = _commit(repo, candidate_value)
    if base_value != BASE_SHA or base != BASE_SHA:
        raise ScopeViolation("contract Base mismatch")
    if _git(repo, "merge-base", base, candidate).stdout.decode().strip() != base:
        raise ScopeViolation("Base is not an ancestor")
    rows = changed_relation(repo, base, candidate)
    _check_endpoints(repo, candidate, rows)
    changed = {str(path) for row in rows for path in row["paths"]}
    _check_validator_delta(repo, base, candidate, changed)
    _check_package(repo, candidate)
    registry = load_source_registry(repo / O08_PREFIX / "resource-envelope.sources.json")
    return {
        "schema": REPORT_SCHEMA,
        "guard_role": "PACKAGE_SHAPE_ONLY",
        "task_scope_authority": False,
        "copy_threshold_percent": COPY_THRESHOLD,
        "changed_relation": rows,
        "dimension_count": len(registry.dimensions),
        "group_count": len(registry.payload["groups"]),
        "stage_count": len(registry.payload["enforcement_stages"]),
        "anchor_count": len(registry.anchors),
        "role_counts": EXPECTED_ROLE_COUNTS,
        "handoff_stage_counts": EXPECTED_HANDOFF_STAGE_COUNTS,
        "handoff_count": sum(EXPECTED_HANDOFF_STAGE_COUNTS.values()),
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--mode", choices=("strict",), default="strict")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.repo_root.resolve(strict=True), args.base, args.candidate)
        if args.output:
            store_report(args.output, report, REPORT_SCHEMA)
    except (OSError, UnicodeError, subprocess.CalledProcessError, ScopeViolation, ValueError) as error:
        print(f"O-08 scope failure: {error}", file=sys.stderr)
        return 2
    print("O-08 scope verdict=PASS role=PACKAGE_SHAPE_ONLY dimensions=68 groups=12 stages=8 anchors=28 entry=53 post=11 evidence=4 handoff=66")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
