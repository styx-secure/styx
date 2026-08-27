"""Literal hostile scenario families; expected values stay outside adapters."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from taxonomy import EVENT_PRECEDENCE, K_PRECEDENCE, PRIMARY_ROWS


def baseline(identifier: str) -> dict[str, Any]:
    return {
        "authority_projection_unavailable": False,
        "authorized": True,
        "delivery_order": ["candidate"],
        "duplicate": False,
        "event_failures": [],
        "id": identifier,
        "k_failures": [],
        "mutation_provable": True,
        "profile_activation_unsupported": False,
        "s4_failures": [],
        "s6_failures": [],
        "stale_evidence": False,
    }


def primary_scenario(primary: str, identifier: str | None = None) -> dict[str, Any]:
    if primary not in PRIMARY_ROWS:
        raise ValueError("unknown primary fixture")
    scenario = baseline(identifier or f"primary-{primary.lower()}")
    if primary == "APPLIED":
        return scenario
    if primary == "PROFILE_ACTIVATION_UNSUPPORTED":
        scenario["profile_activation_unsupported"] = True
    elif primary in K_PRECEDENCE:
        scenario["k_failures"] = [primary]
    elif primary == "DUPLICATE":
        scenario["duplicate"] = True
    elif primary == "STALE_EVIDENCE":
        scenario["stale_evidence"] = True
    elif primary in {"CONTEXT_CAPACITY_EXHAUSTED", "DEPENDENCY_DEFERRED"}:
        scenario["s4_failures"] = [primary]
    elif primary == "AUTHORITY_PROJECTION_UNAVAILABLE":
        scenario["authority_projection_unavailable"] = True
    elif primary == "AUTHENTIC_BUT_UNAUTHORIZED":
        scenario["authorized"] = False
    elif primary in EVENT_PRECEDENCE:
        scenario["event_failures"] = [primary]
    else:
        raise ValueError("primary has no fixture construction")
    return scenario


def _combine(identifier: str, higher: str, lower: str, *, reverse: bool) -> dict[str, Any]:
    first = primary_scenario(higher)
    second = primary_scenario(lower)
    result = baseline(identifier)
    result["delivery_order"] = [lower, higher] if reverse else [higher, lower]
    for name in ("k_failures", "event_failures", "s4_failures", "s6_failures"):
        merged = list(first[name]) + list(second[name])
        result[name] = list(reversed(merged)) if reverse else merged
    for name in (
        "profile_activation_unsupported",
        "duplicate",
        "stale_evidence",
        "authority_projection_unavailable",
    ):
        result[name] = bool(first[name] or second[name])
    result["authorized"] = bool(first["authorized"] and second["authorized"])
    return result


def cases() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for primary in sorted(PRIMARY_ROWS):
        result.append(
            {
                "expected_primary": primary,
                "family": "primary",
                "input": primary_scenario(primary),
            }
        )

    edges = [
        ("PROFILE_ACTIVATION_UNSUPPORTED", "STRUCTURAL_REJECTION"),
        *zip(K_PRECEDENCE, K_PRECEDENCE[1:]),
        ("INVALID", "DUPLICATE"),
        ("DUPLICATE", "STALE_EVIDENCE"),
        ("STALE_EVIDENCE", "CONTEXT_CAPACITY_EXHAUSTED"),
        ("CONTEXT_CAPACITY_EXHAUSTED", "DEPENDENCY_DEFERRED"),
        ("DEPENDENCY_DEFERRED", "AUTHORITY_PROJECTION_UNAVAILABLE"),
        ("AUTHORITY_PROJECTION_UNAVAILABLE", "FORK_EVIDENCE"),
        *zip(EVENT_PRECEDENCE, EVENT_PRECEDENCE[1:]),
    ]
    for index, (higher, lower) in enumerate(edges):
        for reverse in (False, True):
            suffix = "reverse" if reverse else "forward"
            if higher in EVENT_PRECEDENCE and lower in EVENT_PRECEDENCE:
                scenario = baseline(f"edge-{index:02d}-{suffix}")
                failures = [higher, lower]
                scenario["event_failures"] = (
                    list(reversed(failures)) if reverse else failures
                )
                scenario["delivery_order"] = list(scenario["event_failures"])
            else:
                scenario = _combine(
                    f"edge-{index:02d}-{suffix}", higher, lower, reverse=reverse
                )
            result.append(
                {
                    "expected_primary": higher,
                    "family": "precedence",
                    "input": scenario,
                }
            )

    authorization_edges = (
        ("LINEAGE_QUARANTINED", "AUTHENTIC_BUT_UNAUTHORIZED"),
        ("AUTHENTIC_BUT_UNAUTHORIZED", "CONTEXT_CAPACITY_EXHAUSTED"),
    )
    for index, (higher, lower) in enumerate(authorization_edges, start=len(edges)):
        for reverse in (False, True):
            scenario = baseline(
                f"edge-{index:02d}-{'reverse' if reverse else 'forward'}"
            )
            scenario["authorized"] = False
            if higher == "LINEAGE_QUARANTINED":
                scenario["event_failures"] = [higher]
            else:
                scenario["s6_failures"] = [lower]
            scenario["delivery_order"] = (
                [lower, higher] if reverse else [higher, lower]
            )
            result.append(
                {
                    "expected_primary": higher,
                    "family": "precedence",
                    "input": scenario,
                }
            )

    for stage in ("s4_failures", "s6_failures"):
        for reverse in (False, True):
            scenario = baseline(f"tie-{stage}-{'reverse' if reverse else 'forward'}")
            failures = ["CONTEXT_CAPACITY_EXHAUSTED", "DEPENDENCY_DEFERRED"]
            scenario[stage] = list(reversed(failures)) if reverse else failures
            scenario["delivery_order"] = list(scenario[stage])
            result.append(
                {
                    "expected_primary": "CONTEXT_CAPACITY_EXHAUSTED",
                    "family": "overlap",
                    "input": scenario,
                }
            )

    privacy_sources = (
        "STRUCTURAL_REJECTION",
        "OPENING_MISSING",
        "FORK_EVIDENCE",
        "DEPENDENCY_DEFERRED",
    )
    for primary in privacy_sources:
        scenario = primary_scenario(primary, f"privacy-{primary.lower()}")
        scenario["delivery_order"] = ["diagnostic-a", "diagnostic-b"]
        result.append(
            {
                "expected_primary": primary,
                "expected_remote": "OPAQUE_REMOTE_FAILURE",
                "family": "privacy",
                "input": scenario,
            }
        )

    identifiers = [item["input"]["id"] for item in result]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("fixture identifiers are not unique")
    return deepcopy(result)
