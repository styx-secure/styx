#!/usr/bin/env python3
"""Fail-closed path and package-shape guard for Issue #266."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from canonical_json import store  # noqa: E402


BASE_SHA = "a4fa1286b57b2ee79b3c580fdce0d1fb3bf9cd40"
COPY_THRESHOLD = 25
CORPUS_PREFIX = "conformance/application-protocol/c03/"
TOOL_PREFIX = "tools/causal-flow-simulator/c03/"
CORPUS_FILES = frozenset({
    "manifest.json", "valid-transcript-vectors.json", "invalid-transcript-vectors.json",
    "state-machine-scenarios.json", "adversarial-mutations.json", "expected-traces.json",
})
TOOL_FILES = frozenset({
    "README.md", "build_blind_projection.py", "canonical_json.py", "compare_clean_room.py",
    "corpus-inventory.json", "corpus-source-map.json",
    "corpus_model.py", "generate_corpus.py", "validate_corpus.py", "replay_corpus.py",
    "node_adapter.mjs", "run_cross_runtime.py", "run_mutations.py", "scope_guard.py",
    "tests/test_blind_projection.py", "tests/test_compare_clean_room.py",
    "tests/test_canonical_json.py", "tests/test_coverage.py", "tests/test_generation.py",
    "tests/test_manifest.py", "tests/test_mutations.py", "tests/test_replay.py",
    "tests/test_scope_guard.py", "tests/test_cross_runtime.py",
    "h1_h2_relation.py", "tests/test_h1_h2_relation.py",
})
SYNC_FILES = frozenset({
    "docs/PROJECT_BRIEF.md", "docs/protocol/protocol-hardening-plan.md",
    "docs/protocol/review/README.md", "docs/protocol/review/styx-app-kernel-v0-review-model.json",
    "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json",
    "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
    "docs/protocol/styx-app-kernel-v0-decisions.md",
    "tools/protocol-review-model/validate.py",
    "tools/causal-flow-simulator/o10/scope_guard.py",
    "tools/protocol-review-model/tests/test_c03_corpus_path_approval.py",
    "tools/protocol-review-model/tests/test_c03_entry_authorization.py",
    "tools/protocol-review-model/tests/test_o10_outcome_taxonomy.py",
})


class ScopeViolation(ValueError):
    pass


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout


def commit(repo: Path, value: str) -> str:
    return git(repo, "rev-parse", f"{value}^{{commit}}").decode().strip()


def allowed(path: str) -> bool:
    if path.startswith(CORPUS_PREFIX):
        return path.removeprefix(CORPUS_PREFIX) in CORPUS_FILES
    if path.startswith(TOOL_PREFIX):
        return path.removeprefix(TOOL_PREFIX) in TOOL_FILES
    return path in SYNC_FILES


def changed_relation(repo: Path, base: str, candidate: str) -> list[dict[str, Any]]:
    fields = git(
        repo, "diff-tree", "-r", f"--find-renames={COPY_THRESHOLD}%",
        f"--find-copies={COPY_THRESHOLD}%", "--find-copies-harder", "-l0",
        "--name-status", "-z", "--no-commit-id", base, candidate,
    ).split(b"\0")
    if fields and not fields[-1]:
        fields.pop()
    rows: list[dict[str, Any]] = []
    cursor = 0
    while cursor < len(fields):
        status = fields[cursor].decode("ascii")
        cursor += 1
        width = 2 if status[:1] in {"C", "R"} else 1
        paths = [fields[cursor + offset].decode("utf-8") for offset in range(width)]
        cursor += width
        if status[:1] in {"C", "R"}:
            raise ScopeViolation("copy/rename relation forbidden")
        if status.startswith("D"):
            raise ScopeViolation("deletion forbidden")
        for path in paths:
            if not allowed(path):
                raise ScopeViolation(f"out-of-scope endpoint: {path}")
        rows.append({"paths": paths, "status": status})
    return rows


def tree_files(repo: Path, candidate: str, prefix: str) -> set[str]:
    return {
        path.removeprefix(prefix)
        for path in git(repo, "ls-tree", "-r", "--name-only", candidate, "--", prefix).decode().splitlines()
    }


def check_endpoints(repo: Path, candidate: str, rows: list[dict[str, Any]]) -> None:
    for row in rows:
        for path in row["paths"]:
            line = git(repo, "ls-tree", candidate, "--", path).decode().strip()
            if not line:
                raise ScopeViolation(f"missing endpoint: {path}")
            metadata = line.split("\t", 1)[0].split()
            if metadata[0] in {"120000", "160000"} or metadata[1] != "blob":
                raise ScopeViolation(f"symlink/submodule endpoint: {path}")
            blob = git(repo, "cat-file", "blob", f"{candidate}:{path}")
            if b"\0" in blob:
                raise ScopeViolation(f"binary endpoint: {path}")
            if "__pycache__" in path or path.endswith((".pyc", ".pyo")):
                raise ScopeViolation(f"cache endpoint: {path}")


def build_report(repo: Path, base_value: str, candidate_value: str) -> dict[str, Any]:
    base, candidate = commit(repo, base_value), commit(repo, candidate_value)
    if base_value != BASE_SHA or base != BASE_SHA:
        raise ScopeViolation("contract Base mismatch")
    if git(repo, "merge-base", base, candidate).decode().strip() != base:
        raise ScopeViolation("Base is not an ancestor")
    rows = changed_relation(repo, base, candidate)
    check_endpoints(repo, candidate, rows)
    if tree_files(repo, candidate, CORPUS_PREFIX) != CORPUS_FILES:
        raise ScopeViolation("corpus package set mismatch")
    if tree_files(repo, candidate, TOOL_PREFIX) != TOOL_FILES:
        raise ScopeViolation("tool package set mismatch")
    return {
        "changedRelation": rows,
        "copyThresholdPercent": COPY_THRESHOLD,
        "corpusFiles": len(CORPUS_FILES),
        "result": "PASS",
        "toolFiles": len(TOOL_FILES),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--mode", choices=("strict",), default="strict")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        store(args.output.resolve(), build_report(args.repo_root.resolve(), args.base, args.candidate))
    except (OSError, UnicodeError, subprocess.CalledProcessError, ScopeViolation, ValueError) as error:
        print(f"c03_scope_failure={error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
