"""Compare Python and independent JavaScript on every hostile fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from canonical_report import ReportError, canonical_bytes, store_report
from fixtures import cases
from taxonomy import TrustedBoundaryFailure, evaluate


REPORT_FIELDS = frozenset(
    {
        "case_count",
        "fail_closed_case_count",
        "family_counts",
        "fixture_digest",
        "schema",
        "verdict",
    }
)


def _node(adapter: Path, executable: str, scenario: dict[str, object]) -> bytes:
    completed = subprocess.run(
        [executable, str(adapter)],
        input=canonical_bytes(scenario, allowed_fields=frozenset(scenario)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    if completed.returncode != 0 or not completed.stdout:
        raise ValueError("JavaScript adapter failed closed")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("JavaScript output is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("JavaScript output root must be an object")
    return canonical_bytes(value, allowed_fields=frozenset(value))


def _node_fails_closed(
    adapter: Path, executable: str, scenario: dict[str, object]
) -> bool:
    completed = subprocess.run(
        [executable, str(adapter)],
        input=canonical_bytes(scenario, allowed_fields=frozenset(scenario)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    return completed.returncode != 0 and completed.stdout == b""


def _validate_static_isolation(adapter: Path) -> None:
    source = adapter.read_text(encoding="utf-8")
    forbidden = (
        "taxonomy.py",
        "source-inventory",
        "hostile-scenarios",
        "expected_primary",
        "python",
        "child_process",
    )
    if any(token in source for token in forbidden):
        raise ValueError("JavaScript adapter shares a semantic oracle")
    imports = [line.strip() for line in source.splitlines() if line.startswith("import ")]
    if imports != ['import fs from "node:fs";']:
        raise ValueError("JavaScript adapter import boundary drift")


def build_report(repo: Path, javascript: str) -> dict[str, object]:
    adapter = repo / "tools/causal-flow-simulator/o10/node_adapter.mjs"
    _validate_static_isolation(adapter)
    literal_path = repo / "tools/causal-flow-simulator/o10/hostile-scenarios.json"
    literal = json.loads(literal_path.read_bytes())
    expected_literal = {"cases": cases(), "schema": "styx.o10-hostile-fixtures.v1"}
    if literal != expected_literal:
        raise ValueError("hostile fixture corpus drift")
    family_counts: Counter[str] = Counter()
    for case in literal["cases"]:
        python_bytes = canonical_bytes(
            evaluate(case["input"]).as_dict(),
            allowed_fields=frozenset(evaluate(case["input"]).as_dict()),
        )
        javascript_bytes = _node(adapter, javascript, case["input"])
        if javascript_bytes != python_bytes:
            raise ValueError(f"cross-runtime mismatch: {case['input']['id']}")
        family_counts[case["family"]] += 1
    unprovable = cases()[0]["input"].copy()
    unprovable["id"] = "fail-closed-mutation-unprovable"
    unprovable["mutation_provable"] = False
    try:
        evaluate(unprovable)
    except TrustedBoundaryFailure:
        pass
    else:
        raise ValueError("Python accepted an unprovable mutation disposition")
    if not _node_fails_closed(adapter, javascript, unprovable):
        raise ValueError("JavaScript accepted an unprovable mutation disposition")
    return {
        "case_count": len(literal["cases"]),
        "fail_closed_case_count": 1,
        "family_counts": dict(sorted(family_counts.items())),
        "fixture_digest": hashlib.sha256(literal_path.read_bytes()).hexdigest(),
        "schema": "styx.o10-cross-runtime-report.v1",
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--javascript", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.repo_root.resolve(), args.javascript)
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (OSError, ValueError, ReportError, subprocess.TimeoutExpired) as exc:
        print(f"O-10 cross-runtime: FAIL: {exc}", file=sys.stderr)
        return 2
    print(f"O-10 cross-runtime: PASS cases={report['case_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
