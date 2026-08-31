#!/usr/bin/env python3
"""Compare the independent Python and JavaScript SS-0 projections."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

from canonical_report import store
from inventory import load_unique, validate_anchor, validate_inventory
from model import PROFILE, evaluate


def supplemental_inputs() -> list[tuple[str, dict[str, object]]]:
    reordered_profile = {key: PROFILE[key] for key in reversed(PROFILE)}
    boolean_numeric_candidate = {
        "account": "1" * 64,
        "app_witness_score": False,
        "authenticated": True,
        "depth": True,
        "parent": "parent-a",
        "proposal_free": True,
        "tip_priority": "ordinary",
    }
    ordinary_candidate = {
        **boolean_numeric_candidate,
        "account": "2" * 64,
        "app_witness_score": "0",
        "depth": "1",
    }
    float_numeric_candidate = {
        **ordinary_candidate,
        "account": "1" * 64,
        "app_witness_score": 0.0,
        "depth": 1.0,
    }
    float_depth_candidate = {
        **ordinary_candidate,
        "account": "1" * 64,
        "depth": 1.0,
    }
    float_app_witness_candidate = {
        **ordinary_candidate,
        "account": "1" * 64,
        "app_witness_score": 0.0,
    }
    return [
        (
            "X-BOOLEAN-NUMERIC-CANDIDATE-FIELDS",
            {
                "candidates": [boolean_numeric_candidate, ordinary_candidate],
                "operation": "convergence",
                "profile": PROFILE,
            },
        ),
        (
            "X-REORDERED-PROFILE-KEYS",
            {"operation": "profile", "profile": reordered_profile},
        ),
        (
            "X-FLOAT-NUMERIC-CANDIDATE-FIELDS",
            {
                "candidates": [float_numeric_candidate, ordinary_candidate],
                "operation": "convergence",
                "profile": PROFILE,
            },
        ),
        (
            "X-FLOAT-DEPTH-CANDIDATE-FIELD",
            {
                "candidates": [float_depth_candidate, ordinary_candidate],
                "operation": "convergence",
                "profile": PROFILE,
            },
        ),
        (
            "X-FLOAT-APP-WITNESS-CANDIDATE-FIELD",
            {
                "candidates": [float_app_witness_candidate, ordinary_candidate],
                "operation": "convergence",
                "profile": PROFILE,
            },
        ),
        (
            "X-COMMA-COLLIDING-TOP-LEVEL-KEY",
            {
                "operation": "profile",
                "operation,profile": "forbidden-key-collision",
                "profile": PROFILE,
            },
        ),
        (
            "X-UNHASHABLE-RS-RESULT",
            {
                "authoritative": True,
                "operation": "mutation",
                "profile": PROFILE,
                "rs_result": [],
                "staged": True,
            },
        ),
        (
            "X-UNKNOWN-CANDIDATE-FIELD",
            {
                "operation": "profile",
                "profile": PROFILE,
                "scenario_variant": "forbidden-inert-discriminator",
            },
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve(strict=True)
    package = root / "tools/causal-flow-simulator/ss0"
    inventory = validate_inventory(load_unique(package / "source-inventory.json"))
    validate_anchor(root, load_unique(package / "phase-b-anchor.json"))
    witnesses = inventory["witnesses"]
    supplemental = supplemental_inputs()
    input_rows = [(witness["id"], witness["input"]) for witness in witnesses]
    input_rows.extend(supplemental)
    inputs = [candidate for _, candidate in input_rows]
    completed = subprocess.run(
        [str(arguments.node.resolve(strict=True)), str(package / "node_adapter.mjs")],
        input=json.dumps(inputs),
        text=True,
        capture_output=True,
        check=False,
        cwd=root,
        env={"PATH": f"{arguments.node.resolve(strict=True).parent}:/usr/bin:/bin"},
    )
    if completed.returncode != 0:
        raise ValueError("JavaScript adapter failed")
    javascript = json.loads(completed.stdout)
    python = [evaluate(value) for value in inputs]
    if javascript != python or len(javascript) != len(input_rows):
        raise ValueError("cross-runtime observation mismatch")
    version = subprocess.run(
        [str(arguments.node.resolve(strict=True)), "--version"],
        text=True,
        capture_output=True,
        check=True,
        env={"PATH": f"{arguments.node.resolve(strict=True).parent}:/usr/bin:/bin"},
    ).stdout.strip()
    match = re.fullmatch(r"v(\d+)\.(\d+)\.\d+", version)
    if match is None:
        raise ValueError("unsupported Node capability label")
    rows = [
        {"id": identity, "observation": value}
        for (identity, _), value in zip(input_rows, python, strict=True)
    ]
    store(
        {
            "capability": f"node-{match.group(1)}.{match.group(2)}",
            "observations": rows,
            "result": "PASS",
            "runtimes": ["javascript", "python"],
            "schema": "styx.ss0.cross-runtime-report.v2",
        },
        arguments.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
