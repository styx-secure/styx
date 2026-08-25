#!/usr/bin/env python3
"""Execute the closed O-14 mutant-to-witness relation."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from evidence_io import CanonicalJsonReport, public_failure
from scenarios import DECLARED_DETECTORS, REQUIRED_MUTANTS, execute_suite
from semantic_registry import Mutation
from source_invariants import evaluate_source_invariants


SCHEMA = "styx-o14-mutation-report/v1"
MUTANT_BRANCHES = {
    "M_ACCEPT_UNKNOWN_SUITE": "mutant:unknown-suite-accepted",
    "M_TRUST_EVENT_SUITE": "mutant:event-suite",
    "M_TRUST_EVENT_KEY": "mutant:event-key",
    "M_TRUST_GRANT_FIELDS": "mutant:grant-fields",
    "M_RETRY_FALLBACK": "mutant:fallback-retry",
    "M_REMOVE_KEY_LENGTH": "mutant:key-length-removed",
    "M_REMOVE_SIGNATURE_LENGTH": "mutant:signature-length-removed",
    "M_REMOVE_SCALAR_GUARD": "mutant:scalar-reduced",
    "M_LIBRARY_DEFAULT_ZIP215": "mutant:zip215-default",
    "M_REMOVE_PRIME_ORDER_GUARD": "mutant:no-prime-order-guard",
    "M_VERIFY_EVENT_REFERENCE": "mutant:event-reference",
    "M_BYPASS_CONTEXT": "mutant:context-bypassed",
    "M_BYPASS_CREDENTIAL_ID": "mutant:credential-id-bypassed",
    "M_BYPASS_SEQUENCE": "mutant:sequence-bypassed",
    "M_BYPASS_REVOCATION": "mutant:inactive-state-bypassed",
    "M_TRUST_TRANSPORT": "mutant:transport-substitution",
    "M_TRUST_SESSION": "mutant:session-substitution",
    "M_AP_BEFORE_VERIFY": "mutant:ap-before-verify",
    "M_TREAT_VERIFY_AS_AUTHORIZATION": "mutant:authorization-bypassed",
    "M_ACCEPT_MISSING_BINDING": "mutant:missing-binding-accepted",
    "M_REUSE_SUITE_ID_SEMANTICS": "mutant:reuse-suite-id-semantics",
    "M_STATUS_WITHOUT_EVIDENCE": "mutant:status-without-evidence",
    "M_C03_DEPENDENCY_DRIFT": "mutant:c03-dependency-drift",
    "M_ALLOWLIST_GUARD": "mutant:allowlist-guard",
    "M_PER_VECTOR_SPECIAL_CASE": "mutant:per-vector-special-case",
    "M_BATCH_VERIFIER": "mutant:batch-verifier",
}


def build_report(repo_root: Path | None = None) -> tuple[dict[str, object], bool]:
    root = repo_root or Path(__file__).resolve().parents[3]
    required = sorted(REQUIRED_MUTANTS)
    if len(required) != 26:
        raise ValueError("mandatory O-14 mutant inventory drift")
    if set(required) != set(DECLARED_DETECTORS):
        raise ValueError("mutant and detector registries differ")
    results = []
    for identifier in required:
        mutation = Mutation(identifier)
        if identifier in {"M_STATUS_WITHOUT_EVIDENCE", "M_C03_DEPENDENCY_DRIFT"}:
            execution = evaluate_source_invariants(root, mutation)
        else:
            execution = execute_suite(mutation)
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
        "required_mutant_count": len(required),
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
    try:
        report, passed = build_report(args.repo_root.resolve())
        CanonicalJsonReport.store(args.output, report)
    except (OSError, KeyError, ValueError) as error:
        print(f"O-14 mutation harness failed: {public_failure(error)}", file=sys.stderr)
        return 2
    print(
        f"O-14 MUTANTS verdict={report['verdict']} "
        f"killed={report['killed']} survived={len(report['survived'])}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
