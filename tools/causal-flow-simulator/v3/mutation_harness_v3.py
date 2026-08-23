#!/usr/bin/env python3
"""Execute every C0.2j semantic mutant against the closed v3 witness suite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from protocol_model_v3 import Mutation
from scenarios_v3 import (
    REQUIRED_MUTANTS,
    declared_mutation_coverage,
    mutation_coverage,
    run_required_suite,
)


SCHEMA = "styx-credential-succession-mutation-report/v3"
SUITE_ID = "c0.2j-required-mutants-v1"


def build_report() -> tuple[dict[str, object], bool]:
    declared = declared_mutation_coverage()
    observed = mutation_coverage()
    results: list[dict[str, object]] = []
    for identifier in sorted(REQUIRED_MUTANTS):
        suite = run_required_suite(Mutation(identifier))
        failed = sorted(item.identifier for item in suite.checks if not item.passed)
        declared_detectors = list(declared[identifier])
        observed_detectors = list(observed[identifier])
        killed = bool(declared_detectors) and set(observed_detectors) == set(
            declared_detectors
        )
        results.append(
            {
                "id": identifier,
                "killed": killed,
                "declared_detectors": declared_detectors,
                "observed_declared_detectors": observed_detectors,
                "observed_failing_assertions": failed,
            }
        )
    passed = len(results) == len(REQUIRED_MUTANTS) and all(
        item["killed"] for item in results
    )
    return (
        {
            "schema": SCHEMA,
            "suite": SUITE_ID,
            "required_mutants": sorted(REQUIRED_MUTANTS),
            "results": results,
            "killed": sum(bool(item["killed"]) for item in results),
            "survived": sorted(item["id"] for item in results if not item["killed"]),
            "verdict": "ALL_REQUIRED_MUTANTS_KILLED" if passed else "MUTANT_SURVIVED",
        },
        passed,
    )


def canonical_bytes(value: dict[str, object]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=("required",), required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    report, passed = build_report()
    try:
        Path(args.output).write_bytes(canonical_bytes(report))
    except OSError as error:
        print(f"output failure: {error}", file=sys.stderr)
        return 2
    print(
        f"C0.2j MUTANTS verdict={report['verdict']} "
        f"killed={report['killed']} survived={len(report['survived'])}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
