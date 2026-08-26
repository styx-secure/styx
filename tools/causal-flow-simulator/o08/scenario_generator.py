"""Deterministically derive boundary and combined O-08 scenarios."""

from __future__ import annotations

from typing import Any

from envelope_model import boundary_observations
from semantic_registry import ENTRY_ROLES, ROLE_CAPABILITY, SourceRegistry


COMBINED_SCENARIOS = (
    ("MAX_GRAPH", ("EVENTS_ADMITTED", "PARENTS_PER_EVENT", "ANCESTRY_RELATIONS")),
    ("MAX_AUTHORITY", ("CONTROL_EVENTS", "FORK_SLOTS", "SIBLINGS_PER_FORK", "CREDENTIALS")),
    ("MAX_AUTHORITY_DP", ("AUTHORITY_STATES", "AUTHORITY_TRANSITIONS", "ORDINARY_PREFIX_QUERIES")),
    ("MAX_PENDING", ("PENDING_ROOTS", "PENDING_DESCENDANTS", "HALTED_REPLAY_SPAN")),
    ("MAX_CONTENT", ("RECORDS", "CONTENT_EXACT_OCTETS", "CHUNKS_PER_CONTENT", "REMOVAL_DIRECTIVES")),
    ("MAX_DURABLE", ("DURABLE_REQUIRED_OCTETS", "DURABLE_RECORDS", "CUSTODY_REDUNDANCY")),
    ("MAX_GENESIS", ("GENESIS_BODY_OCTETS", "GENESIS_ATTEMPTS", "SIGNATURE_ATTEMPTS")),
    ("MAX_ACTORS", ("ACTORS", "CREDENTIALS", "LINEAGE_DEPTH", "ROLE_ASSIGNMENTS")),
    ("POST_TRANSPORT", ("TRANSPORT_ENVELOPE_OCTETS", "TRANSPORT_DESTINATIONS")),
    ("JOINT_WORK", ("REPLAYED_EVENT_WORK", "ANCESTRY_RELATIONS", "AUTHORITY_TRANSITIONS")),
    ("POST_SESSION", ("SESSION_MEMBERS", "SESSION_PENDING_TRANSITIONS", "SESSION_REPLAY_WINDOW", "KEY_PACKAGES_PENDING")),
    ("POST_DELIVERY", ("OUTBOX_ITEMS", "TRANSPORT_DESTINATIONS", "DELIVERY_ATTEMPTS", "DIAGNOSTIC_OCTETS")),
    ("MAX_TRANSIENT", ("DURABLE_REQUIRED_OCTETS", "RECORDS", "CUSTODY_REDUNDANCY", "TRANSIENT_MEMORY_CAPABILITY")),
    ("MAX_STEERING", ("EVIDENCE_PER_CREDENTIAL", "FORK_SLOTS", "AUTHORITY_STATES", "AUTHORITY_TRANSITIONS")),
    ("MAX_EXPANSION", ("FRAMING_OBJECT_OCTETS", "AP_EXPANDED_CONTENT_OCTETS", "CONTENT_EXACT_OCTETS", "TRANSIENT_MEMORY_CAPABILITY")),
    ("POST_DIAGNOSTICS", ("CONTENT_EXACT_OCTETS", "DIAGNOSTIC_OCTETS")),
)


def boundary_scenarios(envelope: dict[str, Any], registry: SourceRegistry) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    for dimension in registry.entry_dimensions:
        entry = envelope["entries"][dimension]
        selected = entry["selected_value"]
        if not isinstance(selected, int):
            raise ValueError(f"selected value missing: {dimension}")
        for observed in boundary_observations(selected):
            scenarios.append(
                {
                    "dimension": dimension,
                    "observed": observed,
                    "relation": "CAPABILITY" if entry["role"] == ROLE_CAPABILITY else "MAXIMUM",
                }
            )
    return scenarios


def combined_scenarios(envelope: dict[str, Any], registry: SourceRegistry) -> list[dict[str, Any]]:
    result = []
    for scenario_id, dimensions in COMBINED_SCENARIOS:
        values = {
            dimension: envelope["entries"][dimension]["selected_value"]
            for dimension in dimensions
            if registry.roles[dimension] in ENTRY_ROLES
        }
        disposition = "EXECUTE" if values else "POST_C03_NOT_EXECUTED"
        result.append({"scenario_id": scenario_id, "values": values, "disposition": disposition})
    return result
