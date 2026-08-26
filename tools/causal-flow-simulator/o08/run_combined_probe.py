#!/usr/bin/env python3
"""Exercise the closed 16-row cross-dimensional measurement matrix."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from canonical_report import store_report
from envelope_model import load_selected_envelope, validate_selected
from scenario_generator import combined_scenarios
from semantic_registry import CANDIDATES_PATH, SELECTED_PATH, load_json, load_source_registry


REPORT_SCHEMA = "styx-o08-combined-report/v1"
POST_ROWS = {"POST_TRANSPORT", "POST_SESSION", "POST_DELIVERY"}


def build_report() -> dict[str, object]:
    registry = load_source_registry()
    envelope = validate_selected(load_selected_envelope(), load_json(CANDIDATES_PATH), registry)
    rows = combined_scenarios(envelope, registry)
    if len(rows) != 16 or {row["scenario_id"] for row in rows if row["disposition"] == "POST_C03_NOT_EXECUTED"} != POST_ROWS:
        raise ValueError("combined matrix disposition mismatch")
    return {"schema": REPORT_SCHEMA, "rows": rows, "verdict": "PASS"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        store_report(args.output, build_report(), REPORT_SCHEMA)
    except (OSError, ValueError) as error:
        print(f"O-08 combined probe failed: {error}", file=sys.stderr)
        return 2
    print("O-08 COMBINED verdict=PASS rows=16")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
