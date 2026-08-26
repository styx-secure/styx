#!/usr/bin/env python3
"""Require Python and dependency-independent JavaScript semantic agreement."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True

from canonical_report import store_report
from envelope_model import evaluate_observation, load_selected_envelope, validate_selected
from scenario_generator import boundary_scenarios, combined_scenarios
from semantic_registry import CANDIDATES_PATH, SELECTED_PATH, load_json, load_source_registry


REPORT_SCHEMA = "styx-o08-cross-runtime-report/v1"


def build_report(javascript: str) -> dict[str, object]:
    registry = load_source_registry()
    envelope = validate_selected(load_selected_envelope(), load_json(CANDIDATES_PATH), registry)
    cases = []
    expected = []
    for scenario in boundary_scenarios(envelope, registry):
        dimension = scenario["dimension"]
        for stage in registry.stages[dimension] or (None,):
            observed = scenario["observed"]
            wire_observed: int | str = str(observed) if abs(observed) > 9_007_199_254_740_991 else observed
            item = {"dimension": dimension, "stage": stage, "observed": wire_observed}
            result = evaluate_observation(envelope, dimension, scenario["observed"], stage=stage)
            cases.append(item)
            expected.append({
                **item, "selected": result.selected, "disposition": result.disposition,
                "authoritative_state_before": result.authoritative_state_before,
                "authoritative_state_after": result.authoritative_state_after,
                "authoritative_state_mutated": result.authoritative_state_mutated,
            })
    coupling_names = {
        "AUTHORITY_WIDTH_STRUCTURAL_CAPACITY", "AUTHORITY_TRANSITION_CAPACITY",
        "DIRECT_EDGE_REPLAY_WORK", "EVENT_SIGNATURE_WORK", "FRESH_REPLAY_WORK_CAPACITY",
    }
    couplings = [
        predicate
        for row in combined_scenarios(envelope, registry)
        for predicate in row["predicates"]
        if predicate["observation"] in coupling_names
    ]
    request = {
        "schema": "styx-o08-oracle-request/v1", "envelope": envelope,
        "cases": cases, "include_couplings": True,
    }
    completed = subprocess.run(
        [javascript, str(Path(__file__).with_name("independent_oracle.mjs"))],
        input=json.dumps(request, separators=(",", ":")), text=True,
        capture_output=True, check=False, timeout=60,
    )
    if completed.returncode != 0:
        raise ValueError(f"JavaScript oracle failed: {completed.stderr.strip()}")
    response = json.loads(completed.stdout)
    if response != {
        "schema": "styx-o08-oracle-response/v1", "results": expected,
        "couplings": couplings, "poset_widths": [], "verdict": "PASS",
    }:
        raise ValueError("Python/JavaScript semantic disagreement")
    rows = [
        {"dimension": item["dimension"], "stage": item["stage"], "observed": item["observed"],
         "disposition": item["disposition"]}
        for item in expected
    ]
    return {
        "schema": REPORT_SCHEMA, "case_count": len(rows), "rows": rows,
        "coupling_count": len(couplings), "couplings": couplings, "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--javascript", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        store_report(args.output, build_report(args.javascript), REPORT_SCHEMA)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"O-08 cross-runtime failed: {error}", file=sys.stderr)
        return 2
    print("O-08 CROSS_RUNTIME verdict=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
