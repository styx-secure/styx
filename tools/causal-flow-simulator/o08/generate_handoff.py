#!/usr/bin/env python3
"""Generate the exhaustive semantic O-08 to O-10 handoff."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from canonical_report import store_report
from semantic_registry import (
    ENTRY_ROLES, EXPECTED_HANDOFF_STAGE_COUNTS, load_source_registry,
    recovery_for, scope_for,
)


REPORT_SCHEMA = "styx-o08-o10-handoff/v1"


def build_report() -> dict[str, object]:
    registry = load_source_registry()
    rows = []
    counts = {key: 0 for key in EXPECTED_HANDOFF_STAGE_COUNTS}
    for dimension in registry.dimensions:
        role = registry.roles[dimension]
        if role not in ENTRY_ROLES:
            continue
        for stage in registry.stages[dimension]:
            counts[stage] += 1
            rows.append({
                "dimension": dimension,
                "stage": stage,
                "scope": scope_for(dimension),
                "recovery_class": recovery_for(dimension, stage, role),
            })
    if len(rows) != 66 or counts != EXPECTED_HANDOFF_STAGE_COUNTS:
        raise ValueError("handoff relation mismatch")
    if len({(row["dimension"], row["stage"]) for row in rows}) != len(rows):
        raise ValueError("duplicate handoff relation")
    return {"schema": REPORT_SCHEMA, "rows": rows, "stage_counts": counts, "verdict": "PASS"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        store_report(args.output, build_report(), REPORT_SCHEMA)
    except (OSError, ValueError) as error:
        print(f"O-08 handoff failed: {error}", file=sys.stderr)
        return 2
    print("O-08 HANDOFF verdict=PASS rows=66")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
