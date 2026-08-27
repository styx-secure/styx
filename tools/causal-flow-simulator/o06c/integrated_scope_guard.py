#!/usr/bin/env python3
"""Fail-closed path, copy, mode, and frozen-input guard for Issue #260."""

from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import stat
import subprocess
import sys

sys.dont_write_bytecode = True

from integrated_probe import PINNED_INPUTS, _verify_execution_identity
from integrated_registry import SCOPE_SCHEMA
from o10.canonical_report import store_report
from verify_frozen_sections import extract_raw_section


BASE_SHA = "25be9abc0d8c1bce8821a750616e13d245abc356"
TRANSCRIPT_PROFILE = "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md"
ALLOWED_EXACT = frozenset(
    {
        "docs/protocol/protocol-hardening-plan.md",
        "docs/protocol/styx-app-kernel-v0-decisions.md",
        "docs/protocol/styx-app-kernel-v0-o14-o06c-integration-falsification-report.md",
        "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
        TRANSCRIPT_PROFILE,
        "docs/protocol/review/README.md",
        "docs/protocol/review/styx-app-kernel-v0-review-model.json",
        "docs/security/STYX-THREAT-MODEL.md",
        "tools/causal-flow-simulator/README.md",
        "tools/causal-flow-simulator/o06c/integrated_model.py",
        "tools/causal-flow-simulator/o06c/integrated_registry.py",
        "tools/causal-flow-simulator/o06c/integrated_probe.py",
        "tools/causal-flow-simulator/o06c/integrated_cross_runtime.py",
        "tools/causal-flow-simulator/o06c/integrated_mutation_harness.py",
        "tools/causal-flow-simulator/o06c/integrated_scope_guard.py",
        "tools/causal-flow-simulator/o06c/integrated_final_gate.py",
        "tools/causal-flow-simulator/o06c/tests/test_integrated_model.py",
        "tools/causal-flow-simulator/o06c/tests/test_integrated_registry.py",
        "tools/causal-flow-simulator/o06c/tests/test_integrated_probe.py",
        "tools/causal-flow-simulator/o06c/tests/test_integrated_cross_runtime.py",
        "tools/causal-flow-simulator/o06c/tests/test_integrated_mutation_harness.py",
        "tools/causal-flow-simulator/o06c/tests/test_integrated_scope_guard.py",
        "tools/causal-flow-simulator/o06c/tests/test_integrated_final_gate.py",
    }
)
FROZEN_TREES = (
    "tools/causal-flow-simulator/o07",
    "tools/causal-flow-simulator/o08",
    "tools/causal-flow-simulator/o10",
    "tools/causal-flow-simulator/o14",
)
PROTECTED_SECTIONS = {
    b"## 4.": "5b6bc4041b028ead4821cd7d33bb102255d7df728309e2e8bef232f16c9e3fb3",
    b"## 5.": "f3f074befc0d258345b2e067f97a0eabbb08069591fb30b7c508f2ff56d5d8c1",
}
REPORT_FIELDS = frozenset(
    {
        "changed_relation",
        "frozen_input_count",
        "frozen_tree_count",
        "protected_sections",
        "record_count",
        "schema",
        "verdict",
    }
)


class ScopeError(ValueError):
    """The candidate differs from the ratified Issue #260 scope."""


def _git(repo: Path, *arguments: str, check: bool = True) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and completed.returncode != 0:
        raise ScopeError("git evidence command failed")
    return completed.stdout


def _blob(repo: Path, revision: str, path: str) -> bytes:
    return _git(repo, "cat-file", "blob", f"{revision}:{path}")


def _mode(repo: Path, revision: str, path: str) -> str:
    raw = _git(repo, "ls-tree", revision, "--", path).decode("utf-8")
    if not raw:
        raise ScopeError("changed endpoint is absent from its revision")
    return raw.split(None, 1)[0]


def _changed_records(repo: Path, base: str, candidate: str) -> list[dict[str, object]]:
    raw = _git(
        repo,
        "diff-tree",
        "-r",
        "-M25%",
        "-C25%",
        "--find-copies-harder",
        "-l0",
        "--name-status",
        "-z",
        "--no-commit-id",
        base,
        candidate,
    )
    fields = raw.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    records: list[dict[str, object]] = []
    index = 0
    while index < len(fields):
        status_code = fields[index].decode("ascii")
        index += 1
        endpoint_count = 2 if status_code[:1] in {"R", "C"} else 1
        if index + endpoint_count > len(fields):
            raise ScopeError("truncated change relation")
        paths = [fields[index + offset].decode("utf-8") for offset in range(endpoint_count)]
        index += endpoint_count
        if status_code[:1] in {"R", "C"}:
            raise ScopeError("rename or copy relation is forbidden")
        for path in paths:
            if path not in ALLOWED_EXACT:
                raise ScopeError("out-of-scope change endpoint")
        records.append({"paths": paths, "status": status_code})
    return records


def _verify_text_endpoints(
    repo: Path,
    base: str,
    candidate: str,
    records: list[dict[str, object]],
) -> None:
    for record in records:
        status_code = str(record["status"])
        path = str(record["paths"][0])
        endpoints: list[tuple[str, str]]
        if status_code.startswith("D"):
            endpoints = [(base, path)]
        elif status_code.startswith("A"):
            endpoints = [(candidate, path)]
        else:
            endpoints = [(base, path), (candidate, path)]
        for revision, endpoint in endpoints:
            if _mode(repo, revision, endpoint) != "100644":
                raise ScopeError("non-regular changed endpoint")
            payload = _blob(repo, revision, endpoint)
            if b"\0" in payload:
                raise ScopeError("binary changed endpoint")
            try:
                payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ScopeError("non-UTF-8 changed endpoint") from error


def _verify_frozen_inputs(repo: Path, base: str, candidate: str) -> None:
    for tree in FROZEN_TREES:
        completed = subprocess.run(
            ["git", "-C", str(repo), "diff", "--quiet", base, candidate, "--", tree],
            check=False,
        )
        if completed.returncode != 0:
            raise ScopeError("frozen source tree changed")
    for path, expected in PINNED_INPUTS.items():
        if sha256(_blob(repo, base, path)).hexdigest() != expected:
            raise ScopeError("pinned Base input drift")
        if _blob(repo, candidate, path) != _blob(repo, base, path):
            raise ScopeError("pinned candidate input drift")


def _verify_protected_sections(repo: Path, candidate: str) -> list[dict[str, str]]:
    document = _blob(repo, candidate, TRANSCRIPT_PROFILE)
    records = []
    for heading, expected in PROTECTED_SECTIONS.items():
        actual = sha256(extract_raw_section(document, heading)).hexdigest()
        if actual != expected:
            raise ScopeError("protected transcript section drift")
        records.append({"heading": heading.decode("ascii"), "status": "PASS"})
    return records


def build_report(repo: Path, base: str, candidate: str) -> dict[str, object]:
    if base != BASE_SHA:
        raise ScopeError("contract Base mismatch")
    if _git(repo, "rev-parse", f"{candidate}^{{commit}}").decode().strip() != candidate:
        raise ScopeError("candidate is not an exact commit identity")
    ancestry = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", base, candidate],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if ancestry.returncode != 0:
        raise ScopeError("candidate does not descend from Base")
    records = _changed_records(repo, base, candidate)
    _verify_text_endpoints(repo, base, candidate, records)
    _verify_frozen_inputs(repo, base, candidate)
    sections = _verify_protected_sections(repo, candidate)
    return {
        "changed_relation": sorted(records, key=lambda row: str(row["paths"])),
        "frozen_input_count": len(PINNED_INPUTS),
        "frozen_tree_count": len(FROZEN_TREES),
        "protected_sections": sections,
        "record_count": len(records),
        "schema": SCOPE_SCHEMA,
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--mode", required=True, choices=("strict",))
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        repo = args.repo_root.resolve()
        _verify_execution_identity(
            repo,
            args.base,
            args.candidate,
            args.bundle.resolve(),
            args.bundle_sha256,
        )
        report = build_report(repo, args.base, args.candidate)
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (OSError, ScopeError, stat.error, subprocess.CalledProcessError, ValueError) as error:
        print(f"integrated scope guard failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(f"INTEGRATED SCOPE verdict=PASS records={report['record_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
