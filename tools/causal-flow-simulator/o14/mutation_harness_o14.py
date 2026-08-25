#!/usr/bin/env python3
"""Execute the closed O-14 mutant-to-witness relation."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from common import write_report
from scenarios import DECLARED_DETECTORS, REQUIRED_MUTANTS, execute_suite
from semantic_registry import Mutation


SCHEMA = "styx-o14-mutation-report/v1"
MUTANT_BRANCHES = {
    "M_ACCEPT_UNKNOWN_SUITE": "mutant:unknown-suite-accepted",
    "M_TRUST_EVENT_SUITE": "mutant:event-suite",
    "M_TRUST_EVENT_KEY": "mutant:event-key",
    "M_TRUST_GRANT_FIELDS": "mutant:grant-fields",
    "M_RETRY_FALLBACK": "mutant:fallback",
    "M_REMOVE_KEY_LENGTH": "mutant:key-length-removed",
    "M_REMOVE_SIGNATURE_LENGTH": "mutant:signature-length-removed",
    "M_REMOVE_SCALAR_GUARD": "mutant:scalar-reduced",
    "M_LIBRARY_DEFAULT_ZIP215": "mutant:zip215-default",
    "M_REMOVE_PRIME_ORDER_GUARD": "mutant:no-prime-order-guard",
    "M_VERIFY_EVENT_REFERENCE": "mutant:event-reference",
    "M_TRUST_TRANSPORT": "mutant:transport-substitution",
    "M_TRUST_SESSION": "mutant:session-substitution",
    "M_AP_BEFORE_VERIFY": "mutant:ap-before-verify",
    "M_REUSE_SUITE_ID_SEMANTICS": "mutant:reuse-suite-id-semantics",
    "M_STATUS_WITHOUT_EVIDENCE": "mutant:status-without-evidence",
    "M_C03_DEPENDENCY_DRIFT": "mutant:c03-dependency-drift",
    "M_ALLOWLIST_GUARD": "mutant:allowlist-guard",
    "M_PER_VECTOR_SPECIAL_CASE": "mutant:per-vector-special-case",
    "M_BATCH_VERIFIER": "mutant:batch-verifier",
}


def build_report() -> tuple[dict[str, object], bool]:
    required = sorted(REQUIRED_MUTANTS)
    if set(required) != set(DECLARED_DETECTORS):
        raise ValueError("mutant and detector registries differ")
    results = []
    for identifier in required:
        execution = execute_suite(Mutation(identifier))
        observed = tuple(sorted(item["id"] for item in execution if not item["passed"]))
        declared = tuple(sorted(DECLARED_DETECTORS[identifier]))
        branch = MUTANT_BRANCHES.get(identifier)
        executed = True
        if branch is not None:
            executed = any(branch in item["executed_branches"] for item in execution)
        exact = bool(declared) and observed == declared and executed
        results.append(
            {
                "id": identifier,
                "declared_detectors": list(declared),
                "observed_detectors": list(observed),
                "mutated_branch_executed": executed,
                "killed": exact,
            }
        )
    survivors = [item["id"] for item in results if not item["killed"]]
    report = {
        "schema": SCHEMA,
        "required_mutants": required,
        "results": results,
        "killed": len(results) - len(survivors),
        "survived": survivors,
        "verdict": "ALL_REQUIRED_MUTANTS_KILLED" if not survivors else "MUTANT_SURVIVED",
    }
    return report, not survivors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    report, passed = build_report()
    write_report(args.output, report)
    print(
        f"O-14 MUTANTS verdict={report['verdict']} "
        f"killed={report['killed']} survived={len(report['survived'])}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
