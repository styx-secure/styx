#!/usr/bin/env python3
"""Kill every mandatory C0.2k semantic/framing mutant."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from commitment_context_model import Mutation
from scenarios_c02k import REQUIRED_MUTANTS, declared_mutation_coverage, run_required_suite


SCHEMA = "styx-commitment-context-mutation-report/v1"
SUITE = "c0.2k-required-mutants-v1"


def build_report() -> tuple[dict[str, object], bool]:
    declared = declared_mutation_coverage()
    results: list[dict[str, object]] = []
    for identifier in sorted(REQUIRED_MUTANTS):
        suite = run_required_suite(Mutation(identifier))
        failed = sorted(item.identifier for item in suite.checks if not item.passed)
        detectors = list(declared[identifier])
        observed = sorted(set(failed).intersection(detectors))
        killed = bool(detectors) and bool(observed)
        results.append(
            {
                "id": identifier,
                "killed": killed,
                "declared_detectors": detectors,
                "observed_declared_detectors": observed,
                "all_failing_assertions": failed,
            }
        )
    passed = len(results) == len(REQUIRED_MUTANTS) and all(item["killed"] for item in results)
    return (
        {
            "schema": SCHEMA,
            "suite": SUITE,
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
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report, passed = build_report()
    try:
        args.output.write_bytes(canonical_bytes(report))
    except OSError as error:
        print(f"output failure: {error}", file=sys.stderr)
        return 2
    print(
        f"C0.2k MUTANTS verdict={report['verdict']} "
        f"killed={report['killed']} survived={len(report['survived'])}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
