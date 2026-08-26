#!/usr/bin/env python3
"""Measure and validate the three non-authoritative O-08 candidate envelopes."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import resource
import re
import statistics
import subprocess
import sys
import time
from typing import Any

sys.dont_write_bytecode = True

from envelope_model import (
    CAPABILITY_PROFILE_IDS, CANDIDATE_IDS, candidate_identity, materialize_candidate,
    validate_candidate_set,
)
from scenario_generator import boundary_scenarios, combined_scenarios, maximum_antichain_width
from semantic_registry import CANDIDATES_PATH, canonical_bytes, load_json, load_source_registry


REPORT_SCHEMA = "styx-o08-host-measurement/v1"
COMPARISON_SCHEMA = "styx-o08-measurement-comparison/v1"
STRUCTURAL_SET_SCHEMA = "styx-o08-structural-measurement-set/v1"
CAPABILITY_KEYS = {
    "DURABLE_REQUIRED_OCTETS": "durable_required_octets",
    "DURABLE_RECORDS": "durable_records",
    "CUSTODY_REDUNDANCY": "custody_redundancy",
    "TRANSIENT_MEMORY_CAPABILITY": "transient_memory_octets",
}
STRUCTURAL_SCHEMA = "styx-o08-authority-structural-evidence/v1"
DIGEST_RE = re.compile(r"[0-9a-f]{64}")


def _next_power_of_two(value: int) -> int:
    if value < 1:
        raise ValueError("positive value required for ceiling derivation")
    return 1 << (value - 1).bit_length()


def _load_v3(repo_root: Path):
    v3 = repo_root / "tools/causal-flow-simulator/v3"
    if not v3.is_dir():
        raise ValueError("v3 authority model is unavailable")
    sys.path.insert(0, str(v3))
    try:
        import protocol_model_v3 as model
        import scenarios_v3 as scenarios
    finally:
        sys.path.pop(0)
    return model, scenarios


def _actors(scenarios, count: int, label: str):
    return [
        scenarios.genesis(f"o08-{label}-{index}", f"{32 + index:02x}")
        for index in range(count)
    ]


def _grant_grid(model, scenarios, width: int, controls: int, label: str):
    actors = _actors(scenarios, width, label)
    events = []
    remaining = controls
    for actor_index, actor in enumerate(actors):
        chain = remaining // (width - actor_index)
        remaining -= chain
        predecessor = None
        for sequence in range(chain):
            event = scenarios.control(
                f"o08-{label}-{actor_index}-{sequence}", actor, model.Kind.GRANT,
                sequence=sequence, predecessor=predecessor,
                grantee_key=f"{96 + actor_index * controls + sequence:02x}"[-2:] * 32,
            )
            events.append(event)
            predecessor = event.reference
    return model.Scenario(tuple(events), tuple(actors))


def _revoke_cycle(model, scenarios, width: int, label: str):
    actors = _actors(scenarios, width, label)
    events = [
        scenarios.control(
            f"o08-{label}-{index}", actor, model.Kind.REVOKE,
            target_id=actors[(index + 1) % width].credential_id,
        )
        for index, actor in enumerate(actors)
    ]
    return model.Scenario(tuple(events), tuple(actors))


def _mixed_grid(model, scenarios, width: int, label: str):
    actors = _actors(scenarios, width, label)
    events = []
    for index, actor in enumerate(actors):
        grant = scenarios.control(
            f"o08-{label}-grant-{index}", actor, model.Kind.GRANT,
            grantee_key=f"{128 + index:02x}" * 32,
        )
        revoke = scenarios.control(
            f"o08-{label}-revoke-{index}", actor, model.Kind.REVOKE,
            sequence=1, predecessor=grant.reference,
            target_id=actors[(index + 1) % width].credential_id,
        )
        events.extend((grant, revoke))
    return model.Scenario(tuple(events), tuple(actors))


def _policy_chain(model, scenarios, controls: int, label: str):
    actor = _actors(scenarios, 1, label)[0]
    events = []
    predecessor = None
    for sequence in range(controls):
        event = scenarios.control(
            f"o08-{label}-{sequence}", actor, model.Kind.POLICY,
            sequence=sequence, predecessor=predecessor,
        )
        events.append(event)
        predecessor = event.reference
    return model.Scenario(tuple(events), (actor,))


def _fork_concentration(model, scenarios, sibling_count: int, label: str):
    actor = _actors(scenarios, 1, label)[0]
    control = scenarios.control(f"o08-{label}-control", actor, model.Kind.POLICY)
    siblings = tuple(
        scenarios.make_event(
            f"o08-{label}-sibling-{index}", actor,
            sequence=1, predecessor=control.reference,
            declared_subject_id=f"subject-{index}",
        )
        for index in range(sibling_count)
    )
    return model.Scenario((control, *siblings), (actor,))


def _retained_fork_witness(model, scenarios):
    actors = _actors(scenarios, 6, "retained")
    events = []
    for index, actor in enumerate(actors):
        events.extend((
            scenarios.control(
                f"o08-retained-revoke-{index}", actor, model.Kind.REVOKE,
                target_id=actors[(index + 1) % len(actors)].credential_id,
            ),
            scenarios.make_event(f"o08-retained-left-{index}", actor),
            scenarios.make_event(
                f"o08-retained-right-{index}", actor,
                declared_subject_id=f"retained-{index}",
            ),
        ))
    return model.Scenario(tuple(events), tuple(actors))


def _authority_poset(model, scenario) -> tuple[dict[str, frozenset[str]], int, int]:
    """Structurally validate the closed generator family without running DP."""

    model._validate_envelope(scenario)
    raw = {event.reference: event for event in scenario.events}
    if len(raw) != len(scenario.events):
        raise ValueError("structural witness reference collision")
    ancestors = model._causal_ancestors(scenario.events)
    genesis = {binding.credential_id: binding for binding in scenario.genesis_bindings}
    admitted: dict[str, Any] = {}
    for event in sorted(scenario.events, key=lambda item: (item.sequence, item.reference)):
        if model.derive_event_reference(event) != event.reference:
            raise ValueError("structural witness reference mismatch")
        if not model._dependencies(event) <= admitted.keys():
            raise ValueError("structural witness dependency is not admitted")
        if not model._valid_author_chain(
            event, raw, ancestors, frozenset(genesis), model.Mutation()
        ):
            raise ValueError("structural witness author chain is invalid")
        actor = genesis.get(event.actor_id)
        if actor is None or actor.suite_id != event.actor_suite or actor.verification_key != event.actor_key:
            raise ValueError("structural witness actor binding mismatch")
        if event.role is model.Role.CREDENTIAL_CONTROL and not model._valid_control_tail(
            event, admitted, model.Mutation()
        ):
            raise ValueError("structural witness control tail is invalid")
        admitted[event.reference] = event
    joins, _, _ = model._fork_joins(admitted, ancestors, model.Mutation())
    controls = tuple(
        event for event in admitted.values()
        if event.role is model.Role.CREDENTIAL_CONTROL
    )
    predecessors = dict(model._authority_predecessors(
        controls, joins, ancestors, model.Mutation()
    ))
    return predecessors, len(controls), len(joins)


def _structural_specs(model, scenarios, candidate: dict[str, Any]):
    values = candidate["values"]
    width = values["AUTHORITY_CONCURRENT_CONTROLS"]
    controls = values["CONTROL_EVENTS"]
    specs = []
    for current_width in range(1, width + 1):
        grant_controls = min(
            controls, values["CREDENTIALS"] - current_width
        )
        if grant_controls < current_width:
            raise ValueError("candidate cannot represent one GRANT per covered width")
        specs.append((
            f"GRANT_GRID_WIDTH_{current_width}",
            _grant_grid(
                model, scenarios, current_width, grant_controls,
                f"grant-{current_width}",
            ),
            "COVERED",
        ))
    specs.extend((
        ("CHAINED_MAX_CONTROLS", _policy_chain(model, scenarios, controls, "chain-max"), "COVERED"),
        ("CYCLIC_CROSS_CREDENTIAL_REVOKE", _revoke_cycle(model, scenarios, width, "revoke-cycle"), "COVERED"),
        ("MIXED_GRANT_REVOKE", _mixed_grid(model, scenarios, width, "mixed"), "COVERED"),
        (
            "SAME_CREDENTIAL_FORK_JOIN_CONCENTRATION",
            _fork_concentration(model, scenarios, values["SIBLINGS_PER_FORK"], "fork-concentration"),
            "COVERED",
        ),
        ("BOUNDARY_MINUS_ONE", _grant_grid(model, scenarios, max(1, width - 1), max(1, width - 1), "boundary-minus"), "COVERED"),
        ("BOUNDARY", _grant_grid(model, scenarios, width, width, "boundary"), "COVERED"),
        ("BOUNDARY_PLUS_ONE", _grant_grid(model, scenarios, width + 1, width + 1, "boundary-plus"), "WIDTH_UNSUPPORTED"),
        ("RETAINED_4033_STATE_WITNESS", _retained_fork_witness(model, scenarios), "WIDTH_UNSUPPORTED"),
    ))
    return specs


def structural_evidence(
    repo_root: Path, candidate: dict[str, Any], implementation_head: str,
    javascript: str,
) -> dict[str, Any]:
    model, scenarios = _load_v3(repo_root)
    original_limits = (
        model.MAX_EVENTS, model.MAX_CONTROL_EVENTS, model.MAX_FORK_SLOTS,
        model.MAX_CREDENTIALS,
    )
    model.MAX_EVENTS = model.MAX_CONTROL_EVENTS = model.MAX_FORK_SLOTS = model.MAX_CREDENTIALS = 4096
    rows = []
    posets = []
    try:
        for witness_id, scenario, expected in _structural_specs(model, scenarios, candidate):
            predecessors, control_count, join_count = _authority_poset(model, scenario)
            width = maximum_antichain_width(predecessors)
            posets.append({
                "witness_id": witness_id,
                "predecessors": {
                    reference: sorted(required)
                    for reference, required in sorted(predecessors.items())
                },
            })
            selected_width = candidate["values"]["AUTHORITY_CONCURRENT_CONTROLS"]
            if width > selected_width:
                observed = {
                    "disposition": "AUTHORITY_PROJECTION_UNAVAILABLE",
                    "dp_invoked": False,
                    "reachable_states": None,
                    "transitions": None,
                    "ordinary_prefix_queries": 0,
                    "replayed_event_work": 0,
                }
            else:
                projection = model.project(
                    scenario,
                    authority_state_limit=candidate["values"]["AUTHORITY_STATES"],
                    authority_transition_limit=candidate["values"]["AUTHORITY_TRANSITIONS"],
                )
                if not projection.authority_available:
                    raise ValueError(f"covered structural witness exhausted authority: {witness_id}")
                if projection.replayed_event_work > candidate["values"]["REPLAYED_EVENT_WORK"]:
                    raise ValueError(f"covered structural witness exceeded replay work: {witness_id}")
                observed = {
                    "disposition": "ACCEPT",
                    "dp_invoked": True,
                    "reachable_states": projection.reachable_authority_states,
                    "transitions": projection.authority_transitions,
                    "ordinary_prefix_queries": projection.ordinary_probe_transitions,
                    "replayed_event_work": projection.replayed_event_work,
                }
            expected_observed = "WIDTH_UNSUPPORTED" if width > selected_width else "COVERED"
            if expected_observed != expected:
                raise ValueError(f"structural witness disposition drift: {witness_id}")
            row = {
                "witness_id": witness_id,
                "expected": expected,
                "authority_controls": control_count,
                "fork_joins": join_count,
                "exact_width": width,
                **observed,
            }
            if witness_id == "RETAINED_4033_STATE_WITNESS":
                reference = model.project(
                    scenario, authority_state_limit=100_000,
                    authority_transition_limit=1_000_000,
                )
                characterization = {
                    "lane": "NON_AUTHORITATIVE_REFERENCE_CHARACTERIZATION",
                    "reachable_states": reference.reachable_authority_states,
                    "transitions": reference.authority_transitions,
                    "ordinary_prefix_queries": reference.ordinary_probe_transitions,
                    "replayed_event_work": reference.replayed_event_work,
                }
                if (
                    characterization["reachable_states"] != 4_033
                    or characterization["transitions"] != 14_556
                ):
                    raise ValueError("retained authority witness drift")
                row["reference_characterization"] = characterization
            rows.append(row)
    finally:
        (
            model.MAX_EVENTS, model.MAX_CONTROL_EVENTS, model.MAX_FORK_SLOTS,
            model.MAX_CREDENTIALS,
        ) = original_limits
    oracle_request = {
        "schema": "styx-o08-oracle-request/v1", "cases": [], "posets": posets,
    }
    completed = subprocess.run(
        [javascript, str(repo_root / "tools/causal-flow-simulator/o08/independent_oracle.mjs")],
        input=json.dumps(oracle_request, separators=(",", ":")), text=True,
        capture_output=True, timeout=60,
    )
    if completed.returncode != 0:
        raise ValueError(f"independent width oracle failed: {completed.stderr.strip()}")
    oracle = json.loads(completed.stdout)
    expected_widths = [
        {"witness_id": row["witness_id"], "exact_width": row["exact_width"]}
        for row in rows
    ]
    if oracle != {
        "schema": "styx-o08-oracle-response/v1", "results": [],
        "couplings": [], "poset_widths": expected_widths, "verdict": "PASS",
    }:
        raise ValueError("Python/JavaScript maximum-antichain disagreement")
    covered = [row for row in rows if row["expected"] == "COVERED"]
    maximum_states = max(row["reachable_states"] for row in covered)
    maximum_transitions = max(row["transitions"] for row in covered)
    maximum_work = max(row["replayed_event_work"] for row in covered)
    values = candidate["values"]
    structural_margin = (
        values["AUTHORITY_CONCURRENT_CONTROLS"] * values["CONTROL_EVENTS"]
    )
    derived_states = _next_power_of_two(maximum_states + structural_margin)
    derived_transitions = _next_power_of_two(maximum_transitions + structural_margin)
    derived_work = _next_power_of_two(max(
        maximum_work,
        values["ANCESTRY_RELATIONS"],
        values["EVENTS_ADMITTED"] * values["SIGNATURE_ATTEMPTS"],
        derived_transitions * (1 + values["ORDINARY_PREFIX_QUERIES"]),
    ))
    if (
        values["AUTHORITY_STATES"] != derived_states
        or values["AUTHORITY_TRANSITIONS"] != derived_transitions
        or values["REPLAYED_EVENT_WORK"] != derived_work
    ):
        raise ValueError("candidate S5 ceilings do not match the ratified structural derivation")
    value = {
        "schema": STRUCTURAL_SCHEMA,
        "candidate_id": candidate["id"],
        "candidate_digest": candidate_identity(candidate),
        "implementation_head": implementation_head,
        "generator_version": "O08_AUTHORITY_WITNESS_FAMILY_V1",
        "independent_oracle_agreement": True,
        "ceiling_derivation": {
            "rule": "NEXT_POWER_OF_TWO_AFTER_WIDTH_TIMES_CONTROL_MARGIN",
            "maximum_observed_states": maximum_states,
            "maximum_observed_transitions": maximum_transitions,
            "maximum_observed_replayed_event_work": maximum_work,
            "structural_margin": structural_margin,
            "derived_authority_states": derived_states,
            "derived_authority_transitions": derived_transitions,
            "derived_replayed_event_work": derived_work,
        },
        "rows": rows,
        "verdict": "PASS",
    }
    return {**value, "structural_identity": sha256(canonical_bytes(value)).hexdigest()}


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
        "direct_edge_octets": candidate["values"]["ANCESTRY_RELATIONS"] * candidate["values"]["REFERENCE_OCTETS"],
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


def _git_head(repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    )
    value = completed.stdout.strip()
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("implementation HEAD is invalid")
    return value


def _require_clean_repo(repo_root: Path) -> None:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "status", "--porcelain=v1", "--untracked-files=all"],
        check=True, capture_output=True, text=True,
    )
    if completed.stdout:
        raise ValueError("measurement checkout is not clean")


def measure(
    repo_root: Path, candidate_id: str, profile_id: str,
    selection_head: str, cold: int, warm: int, javascript: str,
) -> dict[str, object]:
    registry = load_source_registry()
    payload = load_json(CANDIDATES_PATH)
    candidates = validate_candidate_set(payload, registry)
    if candidate_id not in CANDIDATE_IDS or profile_id not in CAPABILITY_PROFILE_IDS:
        raise ValueError("unknown measurement candidate or profile")
    candidate = next(item for item in candidates if item["id"] == candidate_id)
    profile = payload["capability_profiles"][profile_id]
    implementation_head = _git_head(repo_root)
    _require_clean_repo(repo_root)
    if implementation_head != selection_head:
        raise ValueError("measurement checkout does not equal selection HEAD")
    structural = structural_evidence(repo_root, candidate, implementation_head, javascript)
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
        "selection_head": selection_head,
        "implementation_head": implementation_head,
        "deterministic_structural_evidence": structural,
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
    raw = path.read_bytes()
    value = json.loads(raw)
    required = {
        "schema", "candidate_id", "candidate_digest", "candidate_set_sha256",
        "selection_head", "implementation_head", "deterministic_structural_evidence",
        "capability_profile", "repetitions", "cpu_ns", "wall_ns", "peak_rss_kib",
        "retained_output_octets", "transient_memory_counters", "semantic_outcome",
    }
    if (
        not isinstance(value, dict) or set(value) != required
        or value.get("schema") != REPORT_SCHEMA or raw != canonical_bytes(value)
    ):
        raise ValueError("invalid measurement report")
    for field in ("candidate_digest", "candidate_set_sha256"):
        if not isinstance(value[field], str) or DIGEST_RE.fullmatch(value[field]) is None:
            raise ValueError(f"invalid measurement digest: {field}")
    for field in ("selection_head", "implementation_head"):
        if not isinstance(value[field], str) or re.fullmatch(r"[0-9a-f]{40}", value[field]) is None:
            raise ValueError(f"invalid measurement commit: {field}")
    repetitions = value["repetitions"]
    if (
        not isinstance(repetitions, dict) or set(repetitions) != {"cold", "warm"}
        or any(not isinstance(item, int) or isinstance(item, bool) or item < 1 for item in repetitions.values())
    ):
        raise ValueError("measurement repetitions are invalid")
    for field in ("cpu_ns", "wall_ns"):
        metric = value[field]
        if (
            not isinstance(metric, dict) or set(metric) != {"median", "p95", "maximum"}
            or any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in metric.values())
            or not metric["median"] <= metric["p95"] <= metric["maximum"]
        ):
            raise ValueError(f"invalid host metric: {field}")
    expected_counters = {
        "framing_materialization_octets", "complete_buffer_crypto_octets",
        "commitment_tree_octets", "direct_edge_octets", "authority_dp_octets",
    }
    counters = value["transient_memory_counters"]
    if (
        not isinstance(counters, dict) or set(counters) != expected_counters
        or any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in counters.values())
        or any(
            not isinstance(value[field], int) or isinstance(value[field], bool) or value[field] < 0
            for field in ("peak_rss_kib", "retained_output_octets")
        )
    ):
        raise ValueError("invalid host memory observation")
    return value


def validate_set(
    repo_root: Path, paths: list[Path], selection_head: str,
    candidate_set_path: Path, javascript: str,
) -> dict[str, object]:
    if len(selection_head) != 40 or any(character not in "0123456789abcdef" for character in selection_head):
        raise ValueError("selection HEAD must be exact")
    expected_path = (repo_root / "tools/causal-flow-simulator/o08/resource-envelope.candidates.json").resolve(strict=True)
    if candidate_set_path.resolve(strict=True) != expected_path:
        raise ValueError("candidate set must come from the verified checkout")
    payload = load_json(expected_path)
    candidates = validate_candidate_set(payload)
    reports = [_load_host_report(path) for path in paths]
    pairs = {(item["candidate_id"], item["capability_profile"]) for item in reports}
    expected = {(candidate, profile) for candidate in CANDIDATE_IDS for profile in CAPABILITY_PROFILE_IDS}
    if len(reports) != 6 or pairs != expected:
        raise ValueError("six-report candidate/profile matrix mismatch")
    identities = {item["id"]: candidate_identity(item) for item in candidates}
    regenerated_structural = {
        candidate["id"]: structural_evidence(
            repo_root, candidate, selection_head, javascript
        )
        for candidate in candidates
    }
    for report in reports:
        candidate = next(item for item in candidates if item["id"] == report["candidate_id"])
        profile = payload["capability_profiles"][report["capability_profile"]]
        structural = report.get("deterministic_structural_evidence")
        retained, counters = _single(candidate, profile)
        if (
            report.get("selection_head") != selection_head
            or report.get("implementation_head") != selection_head
            or report["candidate_digest"] != identities[report["candidate_id"]]
            or report["semantic_outcome"] != _activation_outcome(candidate, profile)
            or not isinstance(structural, dict)
            or structural.get("candidate_digest") != report["candidate_digest"]
            or structural.get("implementation_head") != selection_head
            or structural.get("verdict") != "PASS"
            or report.get("candidate_set_sha256") != sha256(expected_path.read_bytes()).hexdigest()
            or report.get("capability_profile") not in CAPABILITY_PROFILE_IDS
            or report.get("semantic_outcome") not in {"PASS", "PROFILE_ACTIVATION_UNSUPPORTED"}
            or structural != regenerated_structural[report["candidate_id"]]
            or report.get("retained_output_octets") != retained
            or report.get("transient_memory_counters") != counters
        ):
            raise ValueError("measurement report identity or outcome mismatch")
        structural_without_identity = dict(structural)
        structural_identity = structural_without_identity.pop("structural_identity", None)
        if structural_identity != sha256(canonical_bytes(structural_without_identity)).hexdigest():
            raise ValueError("deterministic structural identity mismatch")
    for candidate_id in CANDIDATE_IDS:
        identities_for_candidate = {
            report["deterministic_structural_evidence"]["structural_identity"]
            for report in reports if report["candidate_id"] == candidate_id
        }
        if len(identities_for_candidate) != 1:
            raise ValueError("host profiles disagree on deterministic structural evidence")
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
        "CUSTODY_REDUNDANCY",
    }
    if frozen != expected_frozen:
        raise ValueError(f"candidate alternatives are not exact: frozen={sorted(frozen)}")
    return {
        "schema": COMPARISON_SCHEMA,
        "selection_head": selection_head,
        "candidate_set_sha256": sha256(expected_path.read_bytes()).hexdigest(),
        "candidate_envelope_digests": identities,
        "candidate_reports": [
            {"candidate_id": item["candidate_id"], "capability_profile": item["capability_profile"],
             "report_sha256": sha256(path.read_bytes()).hexdigest()}
            for item, path in sorted(zip(reports, paths), key=lambda pair: (pair[0]["candidate_id"], pair[0]["capability_profile"]))
        ],
        "alternatives": alternatives,
        "closed_set_alternatives": {
            candidate["id"]: candidate["closed_sets"] for candidate in candidates
        },
        "deterministic_structural_identities": {
            candidate_id: next(
                report["deterministic_structural_evidence"]["structural_identity"]
                for report in reports if report["candidate_id"] == candidate_id
            )
            for candidate_id in CANDIDATE_IDS
        },
        "frozen_value_rationale": {
            "dimensions": sorted(frozen),
            "reason": "Profile-fixed widths, unsupported-zero entries and the structural capability key set are derived rather than selected.",
        },
        "verdict": "PASS",
    }


def regenerate_structural_set(
    repo_root: Path, selection_head: str, javascript: str,
) -> dict[str, object]:
    payload = load_json(CANDIDATES_PATH)
    candidates = validate_candidate_set(payload)
    current_head = _git_head(repo_root)
    _require_clean_repo(repo_root)
    ancestor = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", selection_head, current_head],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if ancestor != selection_head:
        raise ValueError("selection HEAD is not an ancestor of structural regeneration")
    changed = subprocess.run(
        [
            "git", "-C", str(repo_root), "diff", "--name-only",
            f"{selection_head}...{current_head}", "--", "tools/causal-flow-simulator/o08",
        ],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if changed not in {"", "tools/causal-flow-simulator/o08/resource-envelope.candidate.json"}:
        raise ValueError("post-selection O-08 implementation drift")
    evidence = {
        candidate["id"]: structural_evidence(
            repo_root, candidate, selection_head, javascript
        )
        for candidate in candidates
    }
    return {
        "schema": STRUCTURAL_SET_SCHEMA,
        "selection_head": selection_head,
        "candidate_set_sha256": sha256(CANDIDATES_PATH.read_bytes()).hexdigest(),
        "structural_identities": {
            candidate_id: value["structural_identity"]
            for candidate_id, value in evidence.items()
        },
        "evidence": evidence,
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
    parser.add_argument("--regenerate-structural-set", action="store_true")
    parser.add_argument("--candidate-set", type=Path)
    parser.add_argument("--selection-head")
    parser.add_argument("--javascript", default="node")
    parser.add_argument("--report", action="append", type=Path, default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if not args.validate_report_set and not args.regenerate_structural_set:
            if args.cold_repetitions < 1 or args.warm_repetitions < 1:
                raise ValueError("cold and warm repetitions must both be positive")
        if args.validate_report_set and args.regenerate_structural_set:
            raise ValueError("measurement modes are mutually exclusive")
        result = validate_set(
            args.repo_root, args.report, args.selection_head, args.candidate_set,
            args.javascript,
        ) if args.validate_report_set else regenerate_structural_set(
            args.repo_root, args.selection_head, args.javascript
        ) if args.regenerate_structural_set else measure(
            args.repo_root, args.candidate_id, args.capability_profile,
            args.selection_head, args.cold_repetitions, args.warm_repetitions,
            args.javascript,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_bytes(result))
    except (OSError, ValueError, TypeError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"O-08 measurement failed: {error}", file=sys.stderr)
        return 2
    print("O-08 MEASUREMENT verdict=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
