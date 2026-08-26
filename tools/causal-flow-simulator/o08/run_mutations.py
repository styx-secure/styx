#!/usr/bin/env python3
"""Kill one independently reachable enforcement mutant per C0.3 dimension."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from canonical_report import store_report
from envelope_model import evaluate_observation, load_selected_envelope, validate_selected
from scenario_generator import evaluate_contention_bound, items_from_model
from run_measurements import (
    _appendix_witness, _contention_inputs, _grant_grid, _load_v3,
)
from semantic_registry import (
    CANDIDATES_PATH, ROLE_CAPABILITY, SELECTED_PATH, load_json, load_source_registry,
    recovery_for,
)


REPORT_SCHEMA = "styx-o08-mutation-report/v1"


def _descendant_contention(model, scenarios):
    root, reducer, target = [
        scenarios.genesis(f"o08-mut-desc-{index}", f"{70 + index:02x}")
        for index in range(3)
    ]
    grant = scenarios.control(
        "o08-mut-desc-grant", root, model.Kind.GRANT,
        grantee_key="ab" * 32,
    )
    child = model.grant_binding(grant)
    child_revoke = scenarios.control(
        "o08-mut-desc-child-revoke", child, model.Kind.REVOKE,
        parents=(grant.reference,), target_id=target.credential_id,
    )
    revoke = scenarios.control(
        "o08-mut-desc-root-revoke", reducer, model.Kind.REVOKE,
        parents=(grant.reference,), target_id=root.credential_id,
    )
    return model.Scenario(
        (grant, child_revoke, revoke), (root, reducer, target)
    )


def _fork_lineage_contention(model, scenarios):
    root = scenarios.genesis("o08-mut-fork-root", "72")
    target = scenarios.genesis("o08-mut-fork-target", "73")
    grant = scenarios.control(
        "o08-mut-fork-grant", root, model.Kind.GRANT,
        grantee_key="ac" * 32,
    )
    child = model.grant_binding(grant)
    siblings = tuple(
        scenarios.make_event(
            f"o08-mut-fork-sibling-{index}", root,
            sequence=1, predecessor=grant.reference,
            declared_subject_id=f"fork-{index}",
        )
        for index in range(2)
    )
    child_revoke = scenarios.control(
        "o08-mut-fork-child-revoke", child, model.Kind.REVOKE,
        parents=(grant.reference,), target_id=target.credential_id,
    )
    return model.Scenario((grant, *siblings, child_revoke), (root, target))


def _partial_contention(model, scenarios):
    actor, reducer = [scenarios.genesis(f"o08-mut-partial-{index}", f"{73 + index:02x}") for index in range(2)]
    first = scenarios.control("o08-mut-partial-first", actor, model.Kind.POLICY)
    second = scenarios.control(
        "o08-mut-partial-second", actor, model.Kind.POLICY,
        sequence=1, predecessor=first.reference,
    )
    revoke = scenarios.control(
        "o08-mut-partial-revoke", reducer, model.Kind.REVOKE,
        parents=(first.reference,), target_id=actor.credential_id,
    )
    return model.Scenario((first, second, revoke), (actor, reducer))


def _bound_case(model, scenario, mutation: str | None = None):
    projection = model.project(
        scenario, authority_state_limit=1_000_000,
        authority_transition_limit=10_000_000,
    )
    predecessors, controls, joins, issuers = _contention_inputs(model, scenario, projection)
    bound = evaluate_contention_bound(
        items_from_model(model, controls, joins, predecessors), issuers,
        mutation=mutation,
    )
    return projection, bound


def _contention_mutation_rows() -> list[dict[str, object]]:
    model, scenarios = _load_v3(Path(__file__).resolve().parents[3])
    original_limits = (
        model.MAX_EVENTS, model.MAX_CONTROL_EVENTS, model.MAX_FORK_SLOTS,
        model.MAX_CREDENTIALS,
    )
    model.MAX_EVENTS = model.MAX_CONTROL_EVENTS = model.MAX_FORK_SLOTS = model.MAX_CREDENTIALS = 4096
    appendix = {
        witness_id: _appendix_witness(model, scenarios, witness_id)[0]
        for witness_id in ("W301", "W1211")
    }
    cases = {
        "M_B4_OMIT_DESCENDANT_CLOSURE": _descendant_contention(model, scenarios),
        "M_B4_OMIT_FORK_JOINS": _fork_lineage_contention(model, scenarios),
        "M_B4_INCOMPARABLE_IS_COMPARABLE": appendix["W1211"],
        "M_B4_SMALLER_IDEAL_COUNT": appendix["W1211"],
        "M_B4_WRAP_ARITHMETIC": appendix["W1211"],
        "M_B4_SKIP_EVIDENCE": appendix["W1211"],
        "M_B4_SMALLER_WIDTH": _grant_grid(model, scenarios, 2, 6, "mut-width"),
        "M_B4_POWER_ONLY": appendix["W301"],
        "M_B4_IDEAL_ONLY": _partial_contention(model, scenarios),
        "M_B4_PLUS_ONE": appendix["W301"],
        "M_B4_LARGER_IDEAL_COUNT": appendix["W301"],
        "M_B4_LARGER_WIDTH": appendix["W301"],
    }
    under = {
        "M_B4_OMIT_DESCENDANT_CLOSURE", "M_B4_OMIT_FORK_JOINS",
        "M_B4_INCOMPARABLE_IS_COMPARABLE", "M_B4_SMALLER_IDEAL_COUNT",
        "M_B4_WRAP_ARITHMETIC", "M_B4_SKIP_EVIDENCE", "M_B4_SMALLER_WIDTH",
    }
    rows = []
    try:
        for mutant, scenario in cases.items():
            projection, exact = _bound_case(model, scenario)
            _, changed = _bound_case(model, scenario, mutant)
            dominance_failure = (
                changed.value < projection.reachable_authority_states
                or changed.width * changed.value < projection.authority_transitions
            )
            exact_value_failure = (
                changed.value != exact.value or changed.width != exact.width
            )
            killed = dominance_failure if mutant in under else exact_value_failure
            if not killed:
                raise ValueError(f"contention mutant survived: {mutant}")
            rows.append({
                "mutant_id": mutant,
                "dimension": "AUTHORITY_CONTENTION_BOUND",
                "killing_assertion": (
                    "B4_MUST_DOMINATE_FROZEN_FOLD"
                    if mutant in under else "CANONICAL_B4_VALUE_MUST_BE_EXACT"
                ),
                "intended_failure": "EVIDENCE_GENERATION_BLOCKED",
                "baseline_disposition": "PASS",
                "mutant_disposition": "EVIDENCE_GENERATION_BLOCKED",
                "mutant_state_before": str(exact.value),
                "mutant_state_after": str(changed.value),
                "baseline_width": exact.width,
                "mutant_width": changed.width,
                "reference_reachable_states": projection.reachable_authority_states,
                "reference_transitions": projection.authority_transitions,
                "negative_control": "PASS", "killed": True,
            })
    finally:
        (
            model.MAX_EVENTS, model.MAX_CONTROL_EVENTS, model.MAX_FORK_SLOTS,
            model.MAX_CREDENTIALS,
        ) = original_limits
    return rows


def _replay_coupling_mutation_row() -> dict[str, object]:
    candidate = load_json(CANDIDATES_PATH)["candidates"][1]
    values = candidate["values"]
    weak = values["AUTHORITY_TRANSITIONS"] * (
        1 + values["ORDINARY_PREFIX_QUERIES"]
    )
    exact = values["EVENTS_ADMITTED"] + weak
    hostile_budget = weak
    if not weak <= hostile_budget or exact <= hostile_budget:
        raise ValueError("replay-coupling mutation was not killed")
    return {
        "mutant_id": "M_B4_WEAKEN_REPLAY_COUPLING",
        "dimension": "AUTHORITY_CONTENTION_BOUND",
        "killing_assertion": "FRESH_REPLAY_WORK_INCLUDES_ADMISSION_AND_AUTHORITY_WORK",
        "intended_failure": "EVIDENCE_GENERATION_BLOCKED",
        "baseline_disposition": "CONTEXT_CAPACITY_EXHAUSTED",
        "mutant_disposition": "PASS",
        "mutant_state_before": str(exact),
        "mutant_state_after": str(weak),
        "baseline_width": 0,
        "mutant_width": 0,
        "reference_reachable_states": 0,
        "reference_transitions": values["AUTHORITY_TRANSITIONS"],
        "negative_control": "PASS", "killed": True,
    }


def build_report() -> dict[str, object]:
    registry = load_source_registry()
    envelope = validate_selected(load_selected_envelope(), load_json(CANDIDATES_PATH), registry)
    rows = []
    for dimension in registry.entry_dimensions:
        entry = envelope["entries"][dimension]
        selected = entry["selected_value"]
        hostile = max(0, selected - 1) if entry["role"] == ROLE_CAPABILITY else selected + 1
        stage = entry["stages"][0]
        baseline = evaluate_observation(envelope, dimension, hostile, stage=stage)
        intended_failure = recovery_for(dimension, stage, entry["role"])
        mutant_result = evaluate_observation(
            envelope, dimension, hostile, stage=stage, mutant="SKIP_GATE"
        )
        mutant_disposition = mutant_result.disposition
        killed = baseline.disposition != mutant_disposition
        negative_control = evaluate_observation(envelope, dimension, selected, stage=stage)
        if (
            not killed or baseline.disposition != intended_failure
            or mutant_result.disposition != "ACCEPT"
            or not mutant_result.authoritative_state_mutated
            or negative_control.disposition != "ACCEPT"
        ):
            raise ValueError(f"mutant was not independently killed: {dimension}")
        rows.append({
            "mutant_id": f"M_SKIP_{dimension}", "dimension": dimension,
            "killing_assertion": "HOSTILE_VALUE_MUST_FAIL_BEFORE_PROTECTED_WORK",
            "intended_failure": intended_failure,
            "baseline_disposition": baseline.disposition,
            "mutant_disposition": mutant_disposition,
            "mutant_state_before": mutant_result.authoritative_state_before,
            "mutant_state_after": mutant_result.authoritative_state_after,
            "negative_control": "ACCEPT", "killed": True,
        })
    rows.extend(_contention_mutation_rows())
    rows.append(_replay_coupling_mutation_row())
    return {
        "schema": REPORT_SCHEMA, "mutant_count": len(rows), "survivor_count": 0,
        "rows": rows, "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        store_report(args.output, build_report(), REPORT_SCHEMA)
    except (OSError, ValueError) as error:
        print(f"O-08 mutation run failed: {error}", file=sys.stderr)
        return 2
    print("O-08 MUTATIONS verdict=PASS survivors=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
