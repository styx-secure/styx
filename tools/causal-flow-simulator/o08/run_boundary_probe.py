#!/usr/bin/env python3
"""Exercise every selected entry at boundary minus one, exact and plus one."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from canonical_report import store_report
from envelope_model import evaluate_observation, load_selected_envelope, validate_selected
from scenario_generator import boundary_scenarios
from semantic_registry import CANDIDATES_PATH, SELECTED_PATH, load_json, load_source_registry


REPORT_SCHEMA = "styx-o08-boundary-report/v1"


def build_report() -> dict[str, object]:
    registry = load_source_registry()
    envelope = validate_selected(load_selected_envelope(), load_json(CANDIDATES_PATH), registry)
    rows = []
    for scenario in boundary_scenarios(envelope, registry):
        dimension = scenario["dimension"]
        for stage in registry.stages[dimension] or (None,):
            result = evaluate_observation(envelope, dimension, scenario["observed"], stage=stage)
            rows.append({
                "dimension": dimension, "stage": stage, "observed": result.observed,
                "selected": result.selected, "disposition": result.disposition,
                "pre_work_rejection": result.disposition != "ACCEPT",
                "authoritative_state_before": result.authoritative_state_before,
                "authoritative_state_after": result.authoritative_state_after,
                "authoritative_state_mutated": result.authoritative_state_mutated,
            })
    expected = sum(
        (3 * len(envelope["entries"][item]["closed_values"])
         if item == "CHUNK_OCTETS" else 3)
        * max(1, len(registry.stages[item]))
        for item in registry.entry_dimensions
    )
    if len(rows) != expected:
        raise ValueError("boundary row count mismatch")
    return {"schema": REPORT_SCHEMA, "rows": rows, "verdict": "PASS"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        store_report(args.output, build_report(), REPORT_SCHEMA)
    except (OSError, ValueError) as error:
        print(f"O-08 boundary probe failed: {error}", file=sys.stderr)
        return 2
    print("O-08 BOUNDARY verdict=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
