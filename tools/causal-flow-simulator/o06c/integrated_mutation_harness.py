#!/usr/bin/env python3
"""Execute the closed integrated O-14/O-06c mutant relation."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True

from integrated_model import IntegratedMutation
from integrated_probe import _verify_execution_identity, build_report as build_probe
from integrated_registry import MUTATION_SCHEMA, MutantSpec, required_mutants
from o10.canonical_report import store_report


REPORT_FIELDS = frozenset(
    {
        "killed_count",
        "mutant_count",
        "results",
        "schema",
        "survivor_count",
        "verdict",
    }
)
_PROBE_FAMILIES = (
    "witness_results",
    "dispositions",
    "handoff_results",
    "boundary_results",
)


class MutationHarnessError(ValueError):
    """The closed mutation relation is incomplete or inconsistent."""


def _observed_detectors(report: dict[str, object]) -> tuple[str, ...]:
    observed: list[str] = []
    for family in _PROBE_FAMILIES:
        rows = report.get(family)
        if not isinstance(rows, list):
            raise MutationHarnessError("mutated probe omitted a report family")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise MutationHarnessError("mutated probe emitted an invalid row")
            if row.get("passed") is not True:
                observed.append(row["id"])
    if len(observed) != len(set(observed)):
        raise MutationHarnessError("mutated probe emitted duplicate detectors")
    return tuple(sorted(observed))


def evaluate_mutant(spec: MutantSpec) -> dict[str, object]:
    report = build_probe(IntegratedMutation(spec.identifier))
    observed = _observed_detectors(report)
    declared = tuple(sorted(spec.detectors))
    killed = bool(declared) and observed == declared and report.get("verdict") == "FAIL"
    return {
        "declared_detectors": list(declared),
        "id": spec.identifier,
        "killed": killed,
        "observed_detectors": list(observed),
        "source_family": spec.source_family,
    }


def build_report() -> dict[str, object]:
    mutants = required_mutants()
    results = [evaluate_mutant(spec) for spec in mutants]
    survivors = [row["id"] for row in results if not row["killed"]]
    return {
        "killed_count": len(results) - len(survivors),
        "mutant_count": len(results),
        "results": results,
        "schema": MUTATION_SCHEMA,
        "survivor_count": len(survivors),
        "verdict": "ALL_REQUIRED_MUTANTS_KILLED" if not survivors else "MUTANT_SURVIVED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        _verify_execution_identity(
            args.repo_root.resolve(),
            args.base,
            args.candidate,
            args.bundle.resolve(),
            args.bundle_sha256,
        )
        report = build_report()
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (OSError, MutationHarnessError, subprocess.CalledProcessError, ValueError) as error:
        print(f"integrated mutation harness failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(
        f"INTEGRATED MUTANTS verdict={report['verdict']} "
        f"killed={report['killed_count']} survivors={report['survivor_count']}"
    )
    return 0 if report["verdict"] == "ALL_REQUIRED_MUTANTS_KILLED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
