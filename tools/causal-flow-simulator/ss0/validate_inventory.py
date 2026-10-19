#!/usr/bin/env python3
"""Validate the SS-0 literal inventory and immutable Phase-B anchors."""

from __future__ import annotations

import argparse
from pathlib import Path

from canonical_report import store
from inventory import (
    load_unique,
    validate_anchor,
    validate_inventory,
    validate_public_reader_inputs,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve(strict=True)
    package = root / "tools/causal-flow-simulator/ss0"
    inventory = load_unique(package / "source-inventory.json")
    anchor = load_unique(package / "phase-b-anchor.json")
    validated = validate_inventory(inventory)
    validate_anchor(root, anchor)
    projection_count = validate_public_reader_inputs(root)
    store(
        {
            "atom_count": len(validated["atoms"]),
            "decision_count": 11,
            "obligation_count": 9,
            "public_projection_count": projection_count,
            "relation_count": len(validated["relations"]),
            "result": "PASS",
            "schema": "styx.ss0.inventory-report.v2",
            "shared_witness_count": sum(
                1
                for witness in validated["witnesses"]
                if sum(
                    row["witness"] == witness["id"]
                    for row in validated["relations"]
                )
                > 1
            ),
            "witness_count": len(validated["witnesses"]),
        },
        arguments.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
