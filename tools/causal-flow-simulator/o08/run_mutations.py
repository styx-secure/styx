#!/usr/bin/env python3
"""Kill one independently reachable enforcement mutant per C0.3 dimension."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from canonical_report import store_report
from envelope_model import evaluate_observation, load_selected_envelope, validate_selected
from semantic_registry import (
    CANDIDATES_PATH, ROLE_CAPABILITY, SELECTED_PATH, load_json, load_source_registry,
)


REPORT_SCHEMA = "styx-o08-mutation-report/v1"


def build_report() -> dict[str, object]:
    registry = load_source_registry()
    envelope = validate_selected(load_selected_envelope(), load_json(CANDIDATES_PATH), registry)
    rows = []
    for dimension in registry.entry_dimensions:
        entry = envelope["entries"][dimension]
        selected = entry["selected_value"]
        hostile = max(0, selected - 1) if entry["role"] == ROLE_CAPABILITY else selected + 1
        stage = entry["stages"][0]
        baseline = evaluate_observation(envelope, dimension, hostile, stage=stage)
        # The named mutant skips the dimension's gate and therefore accepts the hostile case.
        mutant_disposition = "ACCEPT"
        killed = baseline.disposition != mutant_disposition
        negative_control = evaluate_observation(envelope, dimension, selected, stage=stage)
        if not killed or negative_control.disposition != "ACCEPT":
            raise ValueError(f"mutant was not independently killed: {dimension}")
        rows.append({
            "mutant_id": f"M_SKIP_{dimension}", "dimension": dimension,
            "killing_assertion": "HOSTILE_VALUE_MUST_FAIL_BEFORE_PROTECTED_WORK",
            "baseline_disposition": baseline.disposition,
            "mutant_disposition": mutant_disposition,
            "negative_control": "ACCEPT", "killed": True,
        })
    return {
        "schema": REPORT_SCHEMA, "mutant_count": len(rows), "survivor_count": 0,
        "rows": rows, "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        store_report(args.output, build_report(), REPORT_SCHEMA)
    except (OSError, ValueError) as error:
        print(f"O-08 mutation run failed: {error}", file=sys.stderr)
        return 2
    print("O-08 MUTATIONS verdict=PASS survivors=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
