#!/usr/bin/env python3
"""Execute the closed semantic inventory and enumerate every separate gate."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True

O07_ROOT = Path(__file__).resolve().parent
SIMULATOR_ROOT = O07_ROOT.parent
for entry in (O07_ROOT, SIMULATOR_ROOT):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from inventory import validate_inventory  # noqa: E402
from o14.evidence_io import CanonicalJsonReport, public_failure  # noqa: E402
from report_schema import (  # noqa: E402
    PROBE_SCHEMA,
    final_evidence_hygiene_context,
    validate_canonical_report,
)
from test_helpers.scenario_engine import evaluate_semantic_scenario  # noqa: E402


SCHEMA = PROBE_SCHEMA
BASE_SHA = "86c3f2dbd630e445d737a25c09889de2777ee185"


def build_report() -> tuple[dict[str, object], bool]:
    inventory = validate_inventory()
    cases = []
    failed = []
    for entry in inventory.semantic_entries:
        result = evaluate_semantic_scenario(entry["atom_instance_id"])
        passed = result["disposition"] == entry["expected_disposition"]
        case = {
            "atom_instance_id": entry["atom_instance_id"],
            "scenario_instance_id": entry["scenario_instance_id"],
            "assertion_id": entry["assertion_id"],
            "observation_id": entry["observation_id"],
            "expected_disposition": entry["expected_disposition"],
            "observed_disposition": result["disposition"],
            "observation": result["observation"],
            "passed": passed,
        }
        cases.append(case)
        if not passed:
            failed.append(entry["atom_instance_id"])

    external_gates = [
        {
            "atom_instance_id": entry["atom_instance_id"],
            "gate_instance_id": entry["scenario_instance_id"],
            "state": "REQUIRED_SEPARATE_GATE",
        }
        for entry in inventory.gate_entries
    ]
    report = {
        "schema": SCHEMA,
        "inventory_relation_count": len(inventory.entries),
        "semantic_atom_count": len(cases),
        "external_gate_count": len(external_gates),
        "semantic_cases": cases,
        "external_gates": external_gates,
        "failed_semantic_atoms": failed,
        "semantic_verdict": "PASS" if not failed else "FAIL",
        "final_o07_gate": "NOT_EVALUATED_BY_THIS_PROBE",
    }
    return report, not failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report, passed = build_report()
        hygiene = final_evidence_hygiene_context(
            args.repo_root,
            BASE_SHA,
            "HEAD",
            bundle=args.bundle,
            bundle_sha256=args.bundle_sha256,
        )
        validate_canonical_report(report, hygiene_context=hygiene)
        CanonicalJsonReport.store(args.output, report)
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        print(f"O-07 probe failed: {public_failure(error)}", file=sys.stderr)
        return 2
    print(
        f"O-07 PROBE semantic={report['semantic_verdict']} "
        f"atoms={report['semantic_atom_count']} external_gates={report['external_gate_count']} "
        f"bundle_sha256={args.bundle_sha256}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
