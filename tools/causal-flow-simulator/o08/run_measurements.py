#!/usr/bin/env python3
"""Measure and validate the three non-authoritative O-08 candidate envelopes."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import random
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
from scenario_generator import (
    boundary_scenarios, combined_scenarios, evaluate_contention_bound,
    items_from_model, maximum_antichain_width, static_trace_bound,
)
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


def _seeded_delivery(model, scenario, seed: int):
    """Return one deterministic hostile delivery order for a fixed trace."""

    events = list(scenario.events)
    random.Random(seed).shuffle(events)
    return model.Scenario(tuple(events), scenario.genesis_bindings)


def _succession_witness(model, scenarios, kind, label: str):
    retired, issuer = _actors(scenarios, 2, label)
    replacement_grant = scenarios.control(
        f"o08-{label}-replacement", issuer, model.Kind.GRANT,
        grantee_key="d1" * 32,
    )
    succession = scenarios.control(
        f"o08-{label}-{kind.value.lower()}", issuer, kind,
        sequence=1, predecessor=replacement_grant.reference,
        target_id=retired.credential_id,
        target_reference=replacement_grant.reference,
    )
    return _seeded_delivery(
        model,
        model.Scenario((replacement_grant, succession), (retired, issuer)),
        0xC03B4001 if kind is model.Kind.ROTATE else 0xC03B4002,
    )


def _deep_lineage_policy_closure(model, scenarios):
    root = _actors(scenarios, 1, "deep-lineage")[0]
    child_grant = scenarios.control(
        "o08-deep-lineage-child", root, model.Kind.GRANT,
        grantee_key="d2" * 32,
    )
    child = model.grant_binding(child_grant)
    grandchild_grant = scenarios.control(
        "o08-deep-lineage-grandchild", child, model.Kind.GRANT,
        parents=(child_grant.reference,), grantee_key="d3" * 32,
    )
    grandchild = model.grant_binding(grandchild_grant)
    policy = scenarios.control(
        "o08-deep-lineage-policy", grandchild, model.Kind.POLICY,
        parents=(grandchild_grant.reference,),
    )
    closure = scenarios.control(
        "o08-deep-lineage-closure", grandchild, model.Kind.CLOSURE,
        sequence=1, predecessor=policy.reference,
    )
    return _seeded_delivery(
        model,
        model.Scenario(
            (child_grant, grandchild_grant, policy, closure), (root,),
        ),
        0xC03B4003,
    )


def _repeated_join_witness(model, scenarios):
    actor = _actors(scenarios, 1, "repeated-join")[0]
    start = scenarios.control(
        "o08-repeated-join-start", actor, model.Kind.POLICY,
    )
    first = tuple(
        scenarios.make_event(
            f"o08-repeated-join-first-{index}", actor,
            sequence=1, predecessor=start.reference,
            declared_subject_id=f"first-{index}",
        )
        for index in range(3)
    )
    resume = scenarios.control(
        "o08-repeated-join-resume", actor, model.Kind.CLOSURE,
        sequence=2, predecessor=first[0].reference,
        parents=tuple(event.reference for event in first[1:]),
    )
    second = tuple(
        scenarios.make_event(
            f"o08-repeated-join-second-{index}", actor,
            sequence=3, predecessor=resume.reference,
            declared_subject_id=f"second-{index}",
        )
        for index in range(2)
    )
    return _seeded_delivery(
        model,
        model.Scenario((start, *first, resume, *second), (actor,)),
        0xC03B4004,
    )


def _cross_owner_substitution_witness(model, scenarios):
    left, right = _actors(scenarios, 2, "cross-owner")
    left_policy = scenarios.control(
        "o08-cross-owner-left-policy", left, model.Kind.POLICY,
    )
    right_closure = scenarios.control(
        "o08-cross-owner-right-closure", right, model.Kind.CLOSURE,
        parents=(left_policy.reference,),
    )
    forged = scenarios.make_event(
        "o08-cross-owner-substitution", left,
        role=model.Role.CREDENTIAL_CONTROL, kind=model.Kind.POLICY,
        claimed_actor_key=right.verification_key,
    )
    return _seeded_delivery(
        model,
        model.Scenario((left_policy, right_closure, forged), (left, right)),
        0xC03B4005,
    )


APPENDIX_WITNESS_IDENTITIES = {
    "W301": "68e72021e9f2882c7110dc07aac78faff05e917bc50b2707462f000b61a7e062",
    "W1211": "5e57b51b54df348adb7768eab9d8f3cedcbed83bac8632a43a19ccba19707ad1",
}
APPENDIX_EXPECTED = {
    "W301": {"fork_joins": 0, "maximum_antichain_width": 3, "reachable_states": 301, "transitions": 708},
    "W1211": {"fork_joins": 0, "maximum_antichain_width": 3, "reachable_states": 1211, "transitions": 2298},
}


def _appendix_witness_payload(witness_id: str) -> dict[str, Any]:
    if witness_id == "W301":
        credentials = [{"slot": f"G{index}", "type": "GENESIS"} for index in range(3)]
        events = []
        for actor in range(3):
            for sequence in range(4):
                events.append({
                    "actor": f"G{actor}", "additional_parents": [], "kind": "REVOKE",
                    "predecessor": None if sequence == 0 else f"E{actor}-{sequence - 1}",
                    "sequence": sequence, "slot": f"E{actor}-{sequence}",
                    "target": f"G{(actor + 1) % 3}",
                })
    elif witness_id == "W1211":
        credentials = (
            [{"slot": f"G{index}", "type": "GENESIS"} for index in range(6)]
            + [{"slot": f"S{index}", "type": "GENESIS_SPARE"} for index in range(8)]
        )
        events = [
            {"actor": "G0", "additional_parents": [], "kind": "REVOKE", "predecessor": None, "sequence": 0, "slot": "E0-0", "target": "S1"},
            {"actor": "G1", "additional_parents": ["E0-0"], "kind": "REVOKE", "predecessor": None, "sequence": 0, "slot": "E1-0", "target": "G2"},
            {"actor": "G2", "additional_parents": [], "kind": "REVOKE", "predecessor": None, "sequence": 0, "slot": "E2-0", "target": "G3"},
            {"actor": "G3", "additional_parents": [], "kind": "REVOKE", "predecessor": None, "sequence": 0, "slot": "E3-0", "target": "G0"},
            {"actor": "G3", "additional_parents": [], "kind": "REVOKE", "predecessor": "E3-0", "sequence": 1, "slot": "E3-1", "target": "S5"},
            {"actor": "G3", "additional_parents": [], "kind": "REVOKE", "predecessor": "E3-1", "sequence": 2, "slot": "E3-2", "target": "G4"},
            {"actor": "G4", "additional_parents": ["E1-0"], "kind": "REVOKE", "predecessor": None, "sequence": 0, "slot": "E4-0", "target": "G5"},
            {"actor": "G4", "additional_parents": [], "kind": "REVOKE", "predecessor": "E4-0", "sequence": 1, "slot": "E4-1", "target": "S3"},
            {"actor": "G5", "additional_parents": ["E2-0"], "kind": "REVOKE", "predecessor": None, "sequence": 0, "slot": "E5-0", "target": "S0"},
            {"actor": "G5", "additional_parents": [], "kind": "REVOKE", "predecessor": "E5-0", "sequence": 1, "slot": "E5-1", "target": "G1"},
            {"actor": "G5", "additional_parents": [], "kind": "REVOKE", "predecessor": "E5-1", "sequence": 2, "slot": "E5-2", "target": "S2"},
            {"actor": "G5", "additional_parents": [], "kind": "REVOKE", "predecessor": "E5-2", "sequence": 3, "slot": "E5-3", "target": "S4"},
        ]
    else:
        raise ValueError(f"unknown appendix witness: {witness_id}")
    return {
        "credentials": credentials, "events": events,
        "expected": APPENDIX_EXPECTED[witness_id],
        "schema": "styx-o08-adversarial-trace/v1",
    }


def _appendix_witness(model, scenarios, witness_id: str):
    payload = _appendix_witness_payload(witness_id)
    identity = sha256(canonical_bytes(payload).removesuffix(b"\n")).hexdigest()
    if identity != APPENDIX_WITNESS_IDENTITIES[witness_id]:
        raise ValueError(f"appendix witness identity drift: {witness_id}")
    bindings = {
        row["slot"]: scenarios.genesis(
            f"o08-{witness_id.lower()}-{row['slot'].lower()}",
            f"{32 + index:02x}"[-2:],
        )
        for index, row in enumerate(payload["credentials"])
    }
    references: dict[str, str] = {}
    events = []
    for row in payload["events"]:
        event = scenarios.control(
            f"o08-{witness_id.lower()}-{row['slot'].lower()}",
            bindings[row["actor"]], model.Kind[row["kind"]],
            sequence=row["sequence"],
            predecessor=references.get(row["predecessor"]),
            parents=tuple(references[parent] for parent in row["additional_parents"]),
            target_id=bindings[row["target"]].credential_id,
        )
        references[row["slot"]] = event.reference
        events.append(event)
    return model.Scenario(tuple(events), tuple(bindings.values())), identity


def _contention_inputs(model, scenario, projection):
    raw = {event.reference: event for event in scenario.events}
    ancestors = model._causal_ancestors(scenario.events)
    admitted = {
        reference: raw[reference]
        for reference in projection.admitted
        if reference in raw
    }
    joins, _, _ = model._fork_joins(admitted, ancestors, model.Mutation())
    controls = tuple(
        event for event in admitted.values()
        if event.role is model.Role.CREDENTIAL_CONTROL
    )
    predecessors = dict(model._authority_predecessors(
        controls, joins, ancestors, model.Mutation()
    ))
    issuer_by_credential = {
        credential_id: binding.issuer_id
        for credential_id, binding in projection.bindings.items()
    }
    return predecessors, controls, joins, issuer_by_credential


def _authority_evidence(model, scenario):
    """Derive P only from the frozen model's exact admission result."""

    projection = model.project(
        scenario, authority_state_limit=1_000_000,
        authority_transition_limit=10_000_000,
    )
    if not projection.authority_available:
        raise ValueError("reference authority projection unexpectedly exhausted")
    predecessors, controls, joins, issuer_by_credential = _contention_inputs(
        model, scenario, projection
    )
    bound = evaluate_contention_bound(
        items_from_model(model, controls, joins, predecessors),
        issuer_by_credential,
    )
    if projection.reachable_authority_states > bound.value:
        raise ValueError("B4 understates reachable authority states")
    if projection.authority_transitions > bound.width * bound.value:
        raise ValueError("B4 width product understates authority transitions")
    return predecessors, controls, joins, projection, bound


def _canonical_trace(scenario) -> dict[str, Any]:
    """Serialize only raw trace material; no derived poset or oracle answer."""

    return {
        "schema": "styx-o08-authority-trace/v1",
        "context_id": scenario.context_id,
        "genesis_bindings": [
            {
                "credential_id": binding.credential_id,
                "genesis": binding.genesis,
                "grant_reference": binding.grant_reference,
                "issuer_id": binding.issuer_id,
                "suite_id": binding.suite_id,
                "verification_key": binding.verification_key,
            }
            for binding in scenario.genesis_bindings
        ],
        "events": [
            {
                "actor_id": event.actor_id,
                "actor_key": event.actor_key,
                "actor_suite": event.actor_suite,
                "content_class": event.content_class.value,
                "context_id": event.context_id,
                "declared_subject_id": event.declared_subject_id,
                "grantee_key": event.grantee_key,
                "grantee_suite": event.grantee_suite,
                "kind": event.kind.value,
                "malformed_tail": event.malformed_tail,
                "name": event.name,
                "parents": list(event.parents),
                "predecessor": event.predecessor,
                "reference": event.reference,
                "role": event.role.value,
                "sequence": event.sequence,
                "target_id": event.target_id,
                "target_reference": event.target_reference,
            }
            for event in scenario.events
        ],
    }


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
        ("SEEDED_ROTATE_FRESH_REPLACEMENT", _succession_witness(model, scenarios, model.Kind.ROTATE, "rotate"), "COVERED"),
        ("SEEDED_RECOVER_FRESH_REPLACEMENT", _succession_witness(model, scenarios, model.Kind.RECOVER, "recover"), "COVERED"),
        ("SEEDED_NON_GENESIS_DEEP_LINEAGE", _deep_lineage_policy_closure(model, scenarios), "COVERED"),
        ("SEEDED_THREE_SIBLING_REPEATED_JOINS", _repeated_join_witness(model, scenarios), "COVERED"),
        ("SEEDED_CROSS_OWNER_AND_CAUSAL_EDGE", _cross_owner_substitution_witness(model, scenarios), "COVERED"),
    ))
    for witness_id in ("W301", "W1211"):
        scenario, _ = _appendix_witness(model, scenarios, witness_id)
        specs.append((
            witness_id, scenario,
            "COVERED" if width >= APPENDIX_EXPECTED[witness_id]["maximum_antichain_width"] else "WIDTH_UNSUPPORTED",
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
    traces = []
    coverage = {
        "admitted_control_kinds": set(),
        "causal_cross_owner_edge": False,
        "cross_owner_substitution_rejected": False,
        "maximum_lineage_depth": 0,
        "maximum_siblings_per_join": 0,
        "repeated_join_trace": False,
    }
    try:
        for witness_id, scenario, expected in _structural_specs(model, scenarios, candidate):
            predecessors, controls, joins, reference, bound = _authority_evidence(
                model, scenario
            )
            control_count = len(controls)
            join_count = len(joins)
            coverage["admitted_control_kinds"].update(
                event.kind.value for event in controls
            )
            raw = {event.reference: event for event in scenario.events}
            for event in controls:
                if any(
                    parent in raw and raw[parent].actor_id != event.actor_id
                    for parent in event.parents
                ):
                    coverage["causal_cross_owner_edge"] = True
            if witness_id == "SEEDED_CROSS_OWNER_AND_CAUSAL_EDGE":
                forged = next(
                    event for event in scenario.events
                    if event.name == "o08-cross-owner-substitution"
                )
                coverage["cross_owner_substitution_rejected"] = (
                    forged.reference not in reference.admitted
                )
            for credential_id in reference.bindings:
                depth = 0
                cursor = credential_id
                seen = set()
                while (
                    cursor in reference.bindings
                    and reference.bindings[cursor].issuer_id is not None
                ):
                    if cursor in seen:
                        raise ValueError("lineage cycle in admitted structural witness")
                    seen.add(cursor)
                    depth += 1
                    cursor = reference.bindings[cursor].issuer_id
                coverage["maximum_lineage_depth"] = max(
                    coverage["maximum_lineage_depth"], depth
                )
            coverage["maximum_siblings_per_join"] = max(
                coverage["maximum_siblings_per_join"],
                max((len(join.sibling_references) for join in joins), default=0),
            )
            if witness_id == "SEEDED_THREE_SIBLING_REPEATED_JOINS":
                coverage["repeated_join_trace"] = join_count >= 2
            width = maximum_antichain_width(predecessors)
            if width != bound.width:
                raise ValueError(f"Python width implementations disagree: {witness_id}")
            if witness_id in APPENDIX_EXPECTED:
                appendix = APPENDIX_EXPECTED[witness_id]
                if (
                    join_count != appendix["fork_joins"]
                    or width != appendix["maximum_antichain_width"]
                    or reference.reachable_authority_states != appendix["reachable_states"]
                    or reference.authority_transitions != appendix["transitions"]
                ):
                    raise ValueError(f"appendix witness characterization drift: {witness_id}")
            traces.append({
                "witness_id": witness_id,
                "limits": {
                    "authority_states": candidate["values"]["AUTHORITY_STATES"],
                    "authority_transitions": candidate["values"]["AUTHORITY_TRANSITIONS"],
                    "authority_width": candidate["values"]["AUTHORITY_CONCURRENT_CONTROLS"],
                },
                "trace": _canonical_trace(scenario),
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
                observed = {
                    "disposition": (
                        "ACCEPT" if projection.authority_available
                        and projection.replayed_event_work <= candidate["values"]["REPLAYED_EVENT_WORK"]
                        else "AUTHORITY_PROJECTION_UNAVAILABLE"
                    ),
                    "dp_invoked": True,
                    "reachable_states": projection.reachable_authority_states,
                    "transitions": projection.authority_transitions,
                    "ordinary_prefix_queries": projection.ordinary_probe_transitions,
                    "replayed_event_work": projection.replayed_event_work,
                }
            retained_expectation = "WIDTH_UNSUPPORTED" if width > selected_width else "COVERED"
            if retained_expectation != expected:
                raise ValueError(f"structural witness disposition drift: {witness_id}")
            proof_region = (
                width <= selected_width
                and bound.value <= candidate["values"]["AUTHORITY_STATES"]
                and width * bound.value <= candidate["values"]["AUTHORITY_TRANSITIONS"]
            )
            if proof_region and observed["disposition"] != "ACCEPT":
                raise ValueError(f"proved-region witness exhausted authority: {witness_id}")
            row = {
                "witness_id": witness_id,
                "retained_expectation": expected,
                "proof_region": "PROVED" if proof_region else "GREY_OR_OUTSIDE",
                "authority_controls": control_count,
                "fork_joins": join_count,
                "exact_width": width,
                "admitted_references": list(reference.admitted),
                **bound.canonical_view(),
                **observed,
            }
            if witness_id in APPENDIX_WITNESS_IDENTITIES:
                row["canonical_witness_sha256"] = APPENDIX_WITNESS_IDENTITIES[witness_id]
                row["reference_characterization"] = {
                    "lane": "CANONICAL_ADVERSARIAL_REFERENCE",
                    "reachable_states": reference.reachable_authority_states,
                    "transitions": reference.authority_transitions,
                }
            if witness_id == "RETAINED_4033_STATE_WITNESS":
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
    required_kinds = {
        "REVOKE", "ROTATE", "GRANT", "RECOVER", "POLICY", "CLOSURE",
    }
    if coverage["admitted_control_kinds"] != required_kinds:
        raise ValueError("adversarial control-kind coverage is incomplete")
    if (
        coverage["maximum_lineage_depth"] < 2
        or coverage["maximum_siblings_per_join"] < 3
        or not coverage["repeated_join_trace"]
        or not coverage["causal_cross_owner_edge"]
        or not coverage["cross_owner_substitution_rejected"]
    ):
        raise ValueError("adversarial structural coverage is incomplete")
    oracle_request = {
        "schema": "styx-o08-oracle-request/v1", "cases": [], "authority_traces": traces,
    }
    completed = subprocess.run(
        [javascript, str(repo_root / "tools/causal-flow-simulator/o08/independent_oracle.mjs")],
        input=json.dumps(oracle_request, separators=(",", ":")), text=True,
        capture_output=True, timeout=60,
    )
    if completed.returncode != 0:
        raise ValueError(f"independent width oracle failed: {completed.stderr.strip()}")
    oracle = json.loads(completed.stdout)
    oracle_rows = oracle.get("authority_traces") if isinstance(oracle, dict) else None
    if (
        oracle.get("schema") != "styx-o08-oracle-response/v1"
        or oracle.get("results") != [] or oracle.get("couplings") != []
        or oracle.get("poset_widths") != [] or oracle.get("verdict") != "PASS"
        or not isinstance(oracle_rows, list) or len(oracle_rows) != len(rows)
    ):
        raise ValueError("invalid independent authority oracle response")
    by_witness = {row["witness_id"]: row for row in oracle_rows}
    for row in rows:
        independent = by_witness.get(row["witness_id"])
        if independent is None or any(
            independent.get(field) != row[field]
            for field in (
                "admitted_references", "authority_contention_bound",
                "authority_ideal_count", "contended_actors",
                "contended_controls", "exact_width", "fork_joins",
                "proof_region", "static_trace_bound",
            )
        ):
            raise ValueError("Python/JavaScript authority evidence disagreement")
    covered = [row for row in rows if row["retained_expectation"] == "COVERED"]
    maximum_states = max(row["reachable_states"] for row in covered)
    maximum_transitions = max(row["transitions"] for row in covered)
    maximum_work = max(row["replayed_event_work"] for row in covered)
    values = candidate["values"]
    tuple_static_bound = static_trace_bound(
        values["AUTHORITY_CONCURRENT_CONTROLS"],
        values["CONTROL_EVENTS"], values["FORK_SLOTS"],
    )
    value = {
        "schema": STRUCTURAL_SCHEMA,
        "candidate_id": candidate["id"],
        "candidate_digest": candidate_identity(candidate),
        "implementation_head": implementation_head,
        "generator_version": "O08_AUTHORITY_WITNESS_FAMILY_V1",
        "independent_oracle_agreement": True,
        "adversarial_coverage": {
            **coverage,
            "admitted_control_kinds": sorted(coverage["admitted_control_kinds"]),
            "deterministic_seed_family": "O08_C03_B4_SEED_V1",
        },
        "ceiling_derivation": {
            "rule": "EXACT_B4_PROOF_REGION_WITH_EXPLICIT_GREY_ZONE",
            "maximum_observed_states": maximum_states,
            "maximum_observed_transitions": maximum_transitions,
            "maximum_observed_replayed_event_work": maximum_work,
            "tuple_static_contention_bound": tuple_static_bound,
            "selected_authority_states": values["AUTHORITY_STATES"],
            "selected_authority_transitions": values["AUTHORITY_TRANSITIONS"],
            "selected_replayed_event_work": values["REPLAYED_EVENT_WORK"],
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
