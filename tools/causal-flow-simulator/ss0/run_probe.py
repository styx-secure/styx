#!/usr/bin/env python3
"""Execute every SS-0 inventory scenario in the Python reference model."""

from __future__ import annotations

import argparse
from pathlib import Path

from canonical_report import store
from inventory import load_unique, validate_anchor, validate_inventory, validate_public_reader_inputs
from model import evaluate


def build_report(root: Path) -> dict[str, object]:
    package = root / "tools/causal-flow-simulator/ss0"
    inventory = validate_inventory(load_unique(package / "source-inventory.json"))
    validate_anchor(root, load_unique(package / "phase-b-anchor.json"))
    validate_public_reader_inputs(root)
    observations: list[dict[str, object]] = []
    for witness in inventory["witnesses"]:
        observed = evaluate(witness["input"])
        if observed != witness["expected"]:
            raise ValueError(f"witness failed: {witness['id']}")
        observations.append(
            {
                "id": witness["id"],
                "observation": observed,
            }
        )
    return {
        "atom_witness_relation": inventory["relations"],
        "observations": observations,
        "result": "PASS",
        "schema": "styx.ss0.probe-report.v2",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    store(build_report(arguments.root.resolve(strict=True)), arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
