#!/usr/bin/env python3
"""Run the closed C0.2d causal-flow falsification suite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

sys.dont_write_bytecode = True

from scenarios import run_required_suite


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the bounded, offline Styx causal-flow falsification model."
    )
    parser.add_argument("--suite", choices=("required",), required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not args.output.is_absolute():
        print("causal-flow-simulator: output path must be absolute", file=sys.stderr)
        return 2
    report = run_required_suite()
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json_bytes(report))
    except OSError:
        print("causal-flow-simulator: unable to write output", file=sys.stderr)
        return 2
    print(
        "CAUSAL FLOW FALSIFICATION "
        f"verdict={report['verdict']} "
        f"invariants={len(report['invariants'])} "
        f"traces={report['explored_delivery_traces']} "
        f"counterexamples={len(report['counterexamples'])}"
    )
    return 1 if report["counterexamples"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
