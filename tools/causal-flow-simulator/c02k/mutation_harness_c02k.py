#!/usr/bin/env python3
"""Evaluate the closed C0.2k mutant-to-witness relation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from commitment_context_model import Mutation
from scenarios_c02k import REQUIRED_MUTANTS, declared_mutation_coverage, run_required_suite


REPORT_SCHEMA = "styx-commitment-context-mutation-report/v1"
REQUIRED_SUITE = "c0.2k-required-mutants-v1"


def _evaluate_one(
    identifier: str, declared: dict[str, tuple[str, ...]]
) -> dict[str, object]:
    """Return evidence for one mutant, counting only declared detectors."""

    execution = run_required_suite(Mutation(identifier))
    failing = frozenset(
        check.identifier for check in execution.checks if not check.passed
    )
    expected = tuple(declared[identifier])
    observed = tuple(sorted(failing.intersection(expected)))
    return {
        "id": identifier,
        "killed": bool(expected) and bool(observed),
        "declared_detectors": list(expected),
        "observed_declared_detectors": list(observed),
        "all_failing_assertions": sorted(failing),
    }


def build_report() -> tuple[dict[str, object], bool]:
    """Run every required mutant and emit one closed deterministic report."""

    declared = declared_mutation_coverage()
    required = tuple(sorted(REQUIRED_MUTANTS))
    results = tuple(_evaluate_one(identifier, declared) for identifier in required)
    survivors = tuple(item["id"] for item in results if not item["killed"])
    complete = len(results) == len(required) and not survivors
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "suite": REQUIRED_SUITE,
        "required_mutants": list(required),
        "results": list(results),
        "killed": len(results) - len(survivors),
        "survived": list(survivors),
        "verdict": (
            "ALL_REQUIRED_MUTANTS_KILLED" if complete else "MUTANT_SURVIVED"
        ),
    }
    return report, complete


def canonical_bytes(value: dict[str, object]) -> bytes:
    rendered = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return f"{rendered}\n".encode("utf-8")


def _parse_arguments(argv: list[str] | None) -> argparse.Namespace:
    command = argparse.ArgumentParser(
        description="Run the required C0.2k mutation gate"
    )
    command.add_argument("--suite", required=True, choices=("required",))
    command.add_argument("--output", required=True, type=Path)
    return command.parse_args(argv)


def _persist(output: Path, report: dict[str, object]) -> bool:
    try:
        output.write_bytes(canonical_bytes(report))
    except OSError as error:
        print(f"output failure: {error}", file=sys.stderr)
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    arguments = _parse_arguments(argv)
    report, complete = build_report()
    if not _persist(arguments.output, report):
        return 2
    print(
        f"C0.2k MUTANTS verdict={report['verdict']} "
        f"killed={report['killed']} survived={len(report['survived'])}"
    )
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
