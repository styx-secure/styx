#!/usr/bin/env python3
"""Measure and validate the three non-authoritative O-08 candidate envelopes."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import resource
import statistics
import sys
import time

sys.dont_write_bytecode = True

from envelope_model import (
    CAPABILITY_PROFILE_IDS, CANDIDATE_IDS, candidate_identity, materialize_candidate,
    validate_candidate_set,
)
from scenario_generator import boundary_scenarios, combined_scenarios
from semantic_registry import CANDIDATES_PATH, canonical_bytes, load_json, load_source_registry


REPORT_SCHEMA = "styx-o08-host-measurement/v1"
COMPARISON_SCHEMA = "styx-o08-measurement-comparison/v1"
CAPABILITY_KEYS = {
    "DURABLE_REQUIRED_OCTETS": "durable_required_octets",
    "DURABLE_RECORDS": "durable_records",
    "CUSTODY_REDUNDANCY": "custody_redundancy",
    "TRANSIENT_MEMORY_CAPABILITY": "transient_memory_octets",
}


def _percentile(values: list[int], fraction: float) -> int:
    return sorted(values)[max(0, min(len(values) - 1, int((len(values) - 1) * fraction + 0.999999)))]


def _single(candidate: dict[str, object], profile: dict[str, int]) -> tuple[int, dict[str, int]]:
    registry = load_source_registry()
    envelope = materialize_candidate(candidate, registry)
    boundary = boundary_scenarios(envelope, registry)
    combined = combined_scenarios(envelope, registry)
    retained = len(canonical_bytes({"boundary": boundary, "combined": combined}))
    counters = {
        "framing_materialization_octets": len(canonical_bytes(candidate)) + len(canonical_bytes(envelope)),
        "complete_buffer_crypto_octets": candidate["values"]["GENESIS_BODY_OCTETS"],
        "commitment_tree_octets": candidate["values"]["CHUNKS_PER_CONTENT"] * candidate["values"]["PART_SYMBOL_OCTETS"],
        "graph_closure_octets": candidate["values"]["ANCESTRY_RELATIONS"] * candidate["values"]["REFERENCE_OCTETS"],
        "authority_dp_octets": candidate["values"]["AUTHORITY_STATES"] * 64,
    }
    aggregate = sum(counters.values())
    if aggregate > candidate["values"]["TRANSIENT_MEMORY_CAPABILITY"]:
        raise ValueError("candidate aggregate transient working set exceeds its envelope")
    if aggregate > profile["transient_memory_octets"]:
        raise ValueError("host profile cannot sustain measured aggregate transient working set")
    return retained, counters


def _activation_outcome(candidate: dict[str, object], profile: dict[str, int]) -> str:
    if set(profile) != set(CAPABILITY_KEYS.values()):
        return "PROFILE_ACTIVATION_UNSUPPORTED"
    return "PASS" if all(
        profile[profile_key] >= candidate["values"][dimension]
        for dimension, profile_key in CAPABILITY_KEYS.items()
    ) else "PROFILE_ACTIVATION_UNSUPPORTED"


def measure(candidate_id: str, profile_id: str, cold: int, warm: int) -> dict[str, object]:
    registry = load_source_registry()
    payload = load_json(CANDIDATES_PATH)
    candidates = validate_candidate_set(payload, registry)
    if candidate_id not in CANDIDATE_IDS or profile_id not in CAPABILITY_PROFILE_IDS:
        raise ValueError("unknown measurement candidate or profile")
    candidate = next(item for item in candidates if item["id"] == candidate_id)
    profile = payload["capability_profiles"][profile_id]
    wall: list[int] = []
    cpu: list[int] = []
    retained = 0
    counters: dict[str, int] = {}
    for _ in range(cold + warm):
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        retained, counters = _single(candidate, profile)
        cpu.append(time.process_time_ns() - cpu_start)
        wall.append(time.perf_counter_ns() - wall_start)
    return {
        "schema": REPORT_SCHEMA,
        "candidate_id": candidate_id,
        "candidate_digest": candidate_identity(candidate),
        "candidate_set_sha256": sha256(CANDIDATES_PATH.read_bytes()).hexdigest(),
        "capability_profile": profile_id,
        "repetitions": {"cold": cold, "warm": warm},
        "cpu_ns": {"median": int(statistics.median(cpu)), "p95": _percentile(cpu, .95), "maximum": max(cpu)},
        "wall_ns": {"median": int(statistics.median(wall)), "p95": _percentile(wall, .95), "maximum": max(wall)},
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "retained_output_octets": retained,
        "transient_memory_counters": counters,
        "semantic_outcome": _activation_outcome(candidate, profile),
    }


def _load_host_report(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != REPORT_SCHEMA:
        raise ValueError("invalid measurement report")
    return value


def validate_set(paths: list[Path], selection_head: str) -> dict[str, object]:
    if len(selection_head) != 40:
        raise ValueError("selection HEAD must be exact")
    payload = load_json(CANDIDATES_PATH)
    candidates = validate_candidate_set(payload)
    reports = [_load_host_report(path) for path in paths]
    pairs = {(item["candidate_id"], item["capability_profile"]) for item in reports}
    expected = {(candidate, profile) for candidate in CANDIDATE_IDS for profile in CAPABILITY_PROFILE_IDS}
    if len(reports) != 6 or pairs != expected:
        raise ValueError("six-report candidate/profile matrix mismatch")
    identities = {item["id"]: candidate_identity(item) for item in candidates}
    for report in reports:
        candidate = next(item for item in candidates if item["id"] == report["candidate_id"])
        profile = payload["capability_profiles"][report["capability_profile"]]
        if report["candidate_digest"] != identities[report["candidate_id"]] or report["semantic_outcome"] != _activation_outcome(candidate, profile):
            raise ValueError("measurement report identity or outcome mismatch")
    alternatives = {
        dimension: [candidate["values"][dimension] for candidate in candidates]
        for dimension in load_source_registry().entry_dimensions
    }
    frozen = {
        dimension for dimension, values in alternatives.items()
        if len(set(values)) == 1
    }
    expected_frozen = {
        "REFERENCE_OCTETS", "TEXT_FIELD_OCTETS", "TREE_FAN_OUT",
        "COMMITMENT_VALUE_OCTETS", "RANDOMIZER_OCTETS", "PART_SYMBOL_OCTETS",
        "SIGNATURE_OCTETS", "VERIFICATION_KEY_OCTETS", "PROFILE_VERSION_SKEW",
        "CHECKPOINT_REFERENCES", "PHYSICAL_TIME_SKEW", "ACTIVATION_CAPABILITY_SET",
    }
    if frozen != expected_frozen:
        raise ValueError(f"candidate alternatives are not exact: frozen={sorted(frozen)}")
    return {
        "schema": COMPARISON_SCHEMA,
        "selection_head": selection_head,
        "candidate_set_sha256": sha256(CANDIDATES_PATH.read_bytes()).hexdigest(),
        "candidate_reports": [
            {"candidate_id": item["candidate_id"], "capability_profile": item["capability_profile"],
             "report_sha256": sha256(path.read_bytes()).hexdigest()}
            for item, path in sorted(zip(reports, paths), key=lambda pair: (pair[0]["candidate_id"], pair[0]["capability_profile"]))
        ],
        "alternatives": alternatives,
        "closed_set_alternatives": {
            candidate["id"]: candidate["closed_sets"] for candidate in candidates
        },
        "frozen_value_rationale": {
            "dimensions": sorted(frozen),
            "reason": "Profile-fixed widths, unsupported-zero entries and the structural capability key set are derived rather than selected.",
        },
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--candidate-id")
    parser.add_argument("--capability-profile")
    parser.add_argument("--cold-repetitions", type=int, default=5)
    parser.add_argument("--warm-repetitions", type=int, default=5)
    parser.add_argument("--validate-report-set", action="store_true")
    parser.add_argument("--candidate-set", type=Path)
    parser.add_argument("--selection-head")
    parser.add_argument("--report", action="append", type=Path, default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate_set(args.report, args.selection_head) if args.validate_report_set else measure(
            args.candidate_id, args.capability_profile, args.cold_repetitions, args.warm_repetitions
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_bytes(result))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"O-08 measurement failed: {error}", file=sys.stderr)
        return 2
    print("O-08 MEASUREMENT verdict=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
