#!/usr/bin/env python3
"""Validate the SS-0 literal inventory and immutable Phase-B anchors."""

from __future__ import annotations

import argparse
from pathlib import Path

from canonical_report import store
from inventory import load_unique, validate_anchor, validate_inventory


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve(strict=True)
    package = root / "tools/causal-flow-simulator/ss0"
    inventory = load_unique(package / "source-inventory.json")
    anchor = load_unique(package / "phase-b-anchor.json")
    cases = validate_inventory(inventory)
    validate_anchor(root, anchor)
    store(
        {
            "case_count": len(cases),
            "decision_count": 11,
            "obligation_count": 9,
            "result": "PASS",
            "schema": "styx.ss0.inventory-report.v1",
        },
        arguments.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
