#!/usr/bin/env python3
"""Independent Python adapter for the closed O-07 semantic inventory."""

from __future__ import annotations

import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

O07_ROOT = Path(__file__).resolve().parents[1]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from inventory import validate_inventory  # noqa: E402
from test_helpers.scenario_engine import (  # noqa: E402
    RUNTIME_BODY_LIMIT,
    evaluate_semantic_scenario,
)


INPUT_SCHEMA = "styx-o07-adapter-input/v2"
OUTPUT_SCHEMA = "styx-o07-python-adapter-output/v2"


def _load_input(path: Path) -> tuple[dict[str, object], ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "runtime_config",
        "scenarios",
    }:
        raise ValueError("adapter input schema mismatch")
    if payload["schema"] != INPUT_SCHEMA:
        raise ValueError("adapter input version mismatch")
    runtime = payload["runtime_config"]
    if runtime != {"runtime_body_limit": RUNTIME_BODY_LIMIT}:
        raise ValueError("unapproved runtime configuration")
    scenarios = payload["scenarios"]
    if not isinstance(scenarios, list):
        raise ValueError("scenario array required")
    normalized: list[dict[str, object]] = []
    for scenario in scenarios:
        if not isinstance(scenario, dict) or set(scenario) != {
            "atom_instance_id",
            "scenario_instance_id",
        }:
            raise ValueError("scenario input contains an oracle or unknown field")
        normalized.append(scenario)
    return tuple(normalized)


def evaluate_input(path: Path) -> dict[str, object]:
    scenarios = _load_input(path)
    inventory = validate_inventory()
    required = {
        (entry["atom_instance_id"], entry["scenario_instance_id"])
        for entry in inventory.semantic_entries
    }
    observed = {
        (entry["atom_instance_id"], entry["scenario_instance_id"])
        for entry in scenarios
    }
    if len(scenarios) != len(observed) or observed != required:
        raise ValueError("semantic scenario relation is not exact")

    results = []
    for scenario in scenarios:
        atom_id = str(scenario["atom_instance_id"])
        result = evaluate_semantic_scenario(atom_id)
        results.append(
            {
                "atom_instance_id": atom_id,
                "scenario_instance_id": scenario["scenario_instance_id"],
                "disposition": result["disposition"],
                "observation": result["observation"],
            }
        )
    return {"schema": OUTPUT_SCHEMA, "results": results}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python_adapter.py INPUT", file=sys.stderr)
        return 2
    try:
        output = evaluate_input(Path(sys.argv[1]))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"O-07 Python adapter failed: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
