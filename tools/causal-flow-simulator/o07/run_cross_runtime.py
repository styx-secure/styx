#!/usr/bin/env python3
"""Compare all closed O-07 semantic scenarios in independent runtimes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
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
    CROSS_RUNTIME_SCHEMA,
    final_evidence_hygiene_context,
    validate_canonical_report,
)


SCHEMA = CROSS_RUNTIME_SCHEMA
INPUT_SCHEMA = "styx-o07-adapter-input/v2"
BASE_SHA = "86c3f2dbd630e445d737a25c09889de2777ee185"


def _adapter_input() -> dict[str, object]:
    inventory = validate_inventory()
    return {
        "schema": INPUT_SCHEMA,
        "runtime_config": {"runtime_body_limit": 4096},
        "scenarios": [
            {
                "atom_instance_id": entry["atom_instance_id"],
                "scenario_instance_id": entry["scenario_instance_id"],
            }
            for entry in inventory.semantic_entries
        ],
    }


def _run(command: list[str], *, cwd: Path) -> dict[str, object]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("adapter output schema mismatch")
    return payload


def _by_relation(payload: dict[str, object]) -> dict[tuple[str, str], dict[str, object]]:
    results = payload["results"]
    assert isinstance(results, list)
    mapped: dict[tuple[str, str], dict[str, object]] = {}
    for item in results:
        if not isinstance(item, dict) or set(item) != {
            "atom_instance_id",
            "scenario_instance_id",
            "disposition",
            "observation",
        }:
            raise ValueError("adapter result schema mismatch")
        relation = (str(item["atom_instance_id"]), str(item["scenario_instance_id"]))
        if relation in mapped:
            raise ValueError("duplicate adapter result")
        if not item["observation"]:
            raise ValueError("empty adapter observation")
        mapped[relation] = item
    return mapped


def build_report(
    repo_root: Path,
    workspace: Path,
    javascript: str,
) -> tuple[dict[str, object], bool]:
    workspace.mkdir(parents=True, exist_ok=False)
    inventory = validate_inventory()
    input_path = workspace / "adapter-input.json"
    input_path.write_bytes(CanonicalJsonReport.encode(_adapter_input()))

    node = shutil.which(javascript)
    if node is None:
        raise ValueError("required JavaScript runtime unavailable")
    python_payload = _run(
        [
            sys.executable,
            str(O07_ROOT / "test_helpers/python_adapter.py"),
            str(input_path),
        ],
        cwd=workspace,
    )
    javascript_payload = _run(
        [node, str(O07_ROOT / "node_adapter.mjs"), str(input_path)],
        cwd=workspace,
    )
    python_results = _by_relation(python_payload)
    javascript_results = _by_relation(javascript_payload)

    expected_relation = {
        (entry["atom_instance_id"], entry["scenario_instance_id"])
        for entry in inventory.semantic_entries
    }
    if set(python_results) != expected_relation or set(javascript_results) != expected_relation:
        raise ValueError("adapter result relation is not exact")

    comparisons = []
    failed = []
    for entry in inventory.semantic_entries:
        relation = (entry["atom_instance_id"], entry["scenario_instance_id"])
        python_result = python_results[relation]
        javascript_result = javascript_results[relation]
        expected = entry["expected_disposition"]
        exact = (
            python_result["disposition"] == expected
            and javascript_result["disposition"] == expected
            and python_result["disposition"] == javascript_result["disposition"]
        )
        comparison = {
            "atom_instance_id": relation[0],
            "scenario_instance_id": relation[1],
            "assertion_id": entry["assertion_id"],
            "observation_id": entry["observation_id"],
            "expected_disposition": expected,
            "python": {
                "disposition": python_result["disposition"],
                "observation": python_result["observation"],
            },
            "javascript": {
                "disposition": javascript_result["disposition"],
                "observation": javascript_result["observation"],
            },
            "exact": exact,
        }
        comparisons.append(comparison)
        if not exact:
            failed.append(relation[0])

    report = {
        "schema": SCHEMA,
        "adapter_count": 2,
        "semantic_atom_count": len(comparisons),
        "comparisons": comparisons,
        "failed": failed,
        "verdict": "PASS" if not failed else "FAIL",
    }
    return report, not failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--javascript", required=True)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report, passed = build_report(
            args.repo_root.resolve(), args.workspace, args.javascript
        )
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
        print(f"O-07 cross-runtime failed: {public_failure(error)}", file=sys.stderr)
        return 2
    print(
        f"O-07 RUNTIME verdict={report['verdict']} "
        f"semantic_atoms={report['semantic_atom_count']} "
        f"bundle_sha256={args.bundle_sha256}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
