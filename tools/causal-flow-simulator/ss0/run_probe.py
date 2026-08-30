#!/usr/bin/env python3
"""Execute every SS-0 inventory scenario in the Python reference model."""

from __future__ import annotations

import argparse
from pathlib import Path

from canonical_report import store
from inventory import load_unique, validate_anchor, validate_inventory
from model import evaluate


def build_report(root: Path) -> dict[str, object]:
    package = root / "tools/causal-flow-simulator/ss0"
    cases = validate_inventory(load_unique(package / "source-inventory.json"))
    validate_anchor(root, load_unique(package / "phase-b-anchor.json"))
    observations: list[dict[str, object]] = []
    for case in cases:
        observed = evaluate(case["input"])
        if observed["disposition"] != case["expected"]:
            raise ValueError(f"scenario failed: {case['id']}")
        observations.append(
            {
                "assertion": case["assertion"],
                "disposition": observed["disposition"],
                "id": case["id"],
                "kind": case["kind"],
                "owner": case["owner"],
            }
        )
    return {
        "observations": observations,
        "result": "PASS",
        "schema": "styx.ss0.probe-report.v1",
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
