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
from model import evaluate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve(strict=True)
    package = root / "tools/causal-flow-simulator/ss0"
    cases = validate_inventory(load_unique(package / "source-inventory.json"))
    validate_anchor(root, load_unique(package / "phase-b-anchor.json"))
    inputs = [case["input"] for case in cases]
    completed = subprocess.run(
        [str(arguments.node.resolve(strict=True)), str(package / "node_adapter.mjs")],
        input=json.dumps(inputs, sort_keys=True),
        text=True,
        capture_output=True,
        check=False,
        cwd=root,
        env={"PATH": "/usr/bin:/bin"},
    )
    if completed.returncode != 0:
        raise ValueError("JavaScript adapter failed")
    javascript = json.loads(completed.stdout)
    python = [evaluate(value) for value in inputs]
    if javascript != python or len(javascript) != len(cases):
        raise ValueError("cross-runtime observation mismatch")
    version = subprocess.run(
        [str(arguments.node.resolve(strict=True)), "--version"],
        text=True,
        capture_output=True,
        check=True,
        env={"PATH": "/usr/bin:/bin"},
    ).stdout.strip()
    match = re.fullmatch(r"v(\d+)\.(\d+)\.\d+", version)
    if match is None:
        raise ValueError("unsupported Node capability label")
    rows = [
        {"disposition": value["disposition"], "id": case["id"]}
        for case, value in zip(cases, python, strict=True)
    ]
    store(
        {
            "capability": f"node-{match.group(1)}.{match.group(2)}",
            "observations": rows,
            "result": "PASS",
            "runtimes": ["javascript", "python"],
            "schema": "styx.ss0.cross-runtime-report.v1",
        },
        arguments.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
