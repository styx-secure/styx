"""Deterministically derive boundary and combined O-08 scenarios."""

from __future__ import annotations

from typing import Any

from envelope_model import boundary_observations
from semantic_registry import ENTRY_ROLES, ROLE_CAPABILITY, SourceRegistry


COMBINED_SCENARIOS = (
    ("MAX_GRAPH", ("CONTEXT_LIFETIME_EVENTS", "PARENTS_PER_EVENT", "ANCESTRY_RELATIONS")),
    ("MAX_AUTHORITY", ("CONTROL_EVENTS", "FORK_SLOTS", "SIBLINGS_PER_FORK", "CREDENTIALS", "AUTHORITY_CONCURRENT_CONTROLS")),
    ("MAX_AUTHORITY_DP", ("AUTHORITY_CONCURRENT_CONTROLS", "AUTHORITY_STATES", "AUTHORITY_TRANSITIONS", "ORDINARY_PREFIX_QUERIES", "REPLAYED_EVENT_WORK")),
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

MAX_U64 = (1 << 64) - 1


def maximum_antichain_width(predecessors: dict[str, frozenset[str]]) -> int:
    """Return the exact width of a finite poset using Dilworth matching.

    ``predecessors`` may contain direct or transitive predecessors.  The
    transitive closure is computed deterministically before maximum bipartite
    matching, so the result is independent of input and arrival order.
    """

    vertices = tuple(sorted(predecessors))
    if any(not required <= set(vertices) for required in predecessors.values()):
        raise ValueError("authority poset references an unknown predecessor")
    closure = {vertex: set(predecessors[vertex]) for vertex in vertices}
    changed = True
    while changed:
        changed = False
        for vertex in vertices:
            expanded = set(closure[vertex])
            for predecessor in tuple(closure[vertex]):
                expanded.update(closure[predecessor])
            if vertex in expanded:
                raise ValueError("authority poset is cyclic")
            if expanded != closure[vertex]:
                closure[vertex] = expanded
                changed = True

    matched_right: dict[str, str] = {}

    def augment(left: str, seen: set[str]) -> bool:
        for right in sorted(
            vertex for vertex in vertices if left in closure[vertex]
        ):
            if right in seen:
                continue
            seen.add(right)
            incumbent = matched_right.get(right)
            if incumbent is None or augment(incumbent, seen):
                matched_right[right] = left
                return True
        return False

    matching = sum(augment(vertex, set()) for vertex in vertices)
    return len(vertices) - matching


def _checked_add(*values: int) -> int:
    result = 0
    for value in values:
        if value < 0 or result > MAX_U64 - value:
            raise ValueError("combined addition overflow")
        result += value
    return result


def _checked_mul(*values: int) -> int:
    result = 1
    for value in values:
        if value < 0 or (value and result > MAX_U64 // value):
            raise ValueError("combined multiplication overflow")
        result *= value
    return result


def _predicate(name: str, lhs: int, operator: str, rhs: int) -> dict[str, Any]:
    passed = lhs <= rhs if operator == "<=" else lhs == rhs
    return {"observation": name, "lhs": lhs, "operator": operator, "rhs": rhs, "passed": passed}


def _selected(envelope: dict[str, Any], dimension: str) -> int:
    value = envelope["entries"][dimension]["selected_value"]
    if not isinstance(value, int):
        raise ValueError(f"entry value unavailable for combined predicate: {dimension}")
    return value


def _transient_components(envelope: dict[str, Any]) -> tuple[int, ...]:
    return (
        _checked_add(_selected(envelope, "FRAMING_OBJECT_OCTETS"), _selected(envelope, "GENESIS_BODY_OCTETS")),
        _selected(envelope, "GENESIS_BODY_OCTETS"),
        _checked_mul(_selected(envelope, "CHUNKS_PER_CONTENT"), _selected(envelope, "PART_SYMBOL_OCTETS")),
        _checked_mul(_selected(envelope, "ANCESTRY_RELATIONS"), _selected(envelope, "REFERENCE_OCTETS")),
        _checked_mul(_selected(envelope, "AUTHORITY_STATES"), 64),
    )


def boundary_scenarios(envelope: dict[str, Any], registry: SourceRegistry) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    for dimension in registry.entry_dimensions:
        entry = envelope["entries"][dimension]
        selected = entry["selected_value"]
        if not isinstance(selected, int):
            raise ValueError(f"selected value missing: {dimension}")
        boundaries = (
            tuple(
                observed
                for member in entry["closed_values"]
                for observed in boundary_observations(member)
            )
            if dimension == "CHUNK_OCTETS"
            else boundary_observations(selected)
        )
        for observed in boundaries:
            scenarios.append(
                {
                    "dimension": dimension,
                    "observed": observed,
                    "relation": entry["comparison"],
                }
            )
    return scenarios


def combined_scenarios(envelope: dict[str, Any], registry: SourceRegistry) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for scenario_id, dimensions in COMBINED_SCENARIOS:
        values = {
            dimension: envelope["entries"][dimension]["selected_value"]
            for dimension in dimensions
            if registry.roles[dimension] in ENTRY_ROLES
        }
        if not values:
            result.append({
                "scenario_id": scenario_id, "values": {}, "predicates": [],
                "disposition": "POST_C03_NOT_EXECUTED",
            })
            continue
        predicates: list[dict[str, Any]]
        if scenario_id == "MAX_GRAPH":
            predicates = [
                _predicate(
                    "DIRECT_EDGE_CAPACITY",
                    _checked_mul(_selected(envelope, "CONTEXT_LIFETIME_EVENTS"), _selected(envelope, "PARENTS_PER_EVENT")),
                    "<=", _selected(envelope, "ANCESTRY_RELATIONS"),
                ),
                _predicate(
                    "DIRECT_EDGE_REPLAY_WORK",
                    _selected(envelope, "ANCESTRY_RELATIONS"), "<=",
                    _selected(envelope, "REPLAYED_EVENT_WORK"),
                ),
            ]
        elif scenario_id == "MAX_AUTHORITY":
            predicates = [
                _predicate(
                    "FORK_SIBLING_CONTROL_CAPACITY",
                    _checked_mul(_selected(envelope, "FORK_SLOTS"), _selected(envelope, "SIBLINGS_PER_FORK")),
                    "<=", _selected(envelope, "CONTROL_EVENTS"),
                ),
                _predicate(
                    "AUTHORITY_WIDTH_STRUCTURAL_CAPACITY",
                    _selected(envelope, "AUTHORITY_CONCURRENT_CONTROLS"), "<=",
                    _checked_add(_selected(envelope, "CREDENTIALS"), _selected(envelope, "FORK_SLOTS")),
                ),
            ]
        elif scenario_id == "MAX_AUTHORITY_DP":
            predicates = [
                _predicate(
                    "AUTHORITY_TRANSITION_CAPACITY", _selected(envelope, "AUTHORITY_TRANSITIONS"), "<=",
                    _checked_mul(_selected(envelope, "AUTHORITY_STATES"), _selected(envelope, "AUTHORITY_CONCURRENT_CONTROLS")),
                ),
                _predicate(
                    "FRESH_REPLAY_WORK_CAPACITY",
                    _checked_mul(
                        _selected(envelope, "AUTHORITY_TRANSITIONS"),
                        _checked_add(1, _selected(envelope, "ORDINARY_PREFIX_QUERIES")),
                    ), "<=", _selected(envelope, "REPLAYED_EVENT_WORK"),
                ),
            ]
        elif scenario_id == "MAX_PENDING":
            predicates = [_predicate(
                "PENDING_DESCENDANT_REPLAY_CAPACITY", _selected(envelope, "PENDING_DESCENDANTS"), "<=",
                _checked_mul(_selected(envelope, "PENDING_ROOTS"), _selected(envelope, "HALTED_REPLAY_SPAN")),
            )]
        elif scenario_id == "MAX_CONTENT":
            chunk_min = min(envelope["entries"]["CHUNK_OCTETS"]["closed_values"])
            predicates = [
                _predicate(
                    "CONTENT_CHUNK_GEOMETRY", _selected(envelope, "CONTENT_EXACT_OCTETS"), "<=",
                    _checked_mul(chunk_min, _selected(envelope, "CHUNKS_PER_CONTENT")),
                ),
                _predicate(
                    "REMOVAL_RECORD_CAPACITY", _selected(envelope, "REMOVAL_DIRECTIVES"), "<=",
                    _selected(envelope, "RECORDS"),
                ),
            ]
        elif scenario_id in {"MAX_DURABLE", "MAX_TRANSIENT"}:
            predicates = [
                _predicate(
                    "DURABLE_REFERENCE_ENVELOPE", _checked_mul(
                        _selected(envelope, "DURABLE_RECORDS"),
                        _selected(envelope, "REFERENCE_OCTETS"),
                        _selected(envelope, "CUSTODY_REDUNDANCY"),
                    ), "<=", _selected(envelope, "DURABLE_REQUIRED_OCTETS"),
                ),
                _predicate(
                    "DURABLE_RECORD_COUNT", _selected(envelope, "RECORDS"), "<=",
                    _selected(envelope, "DURABLE_RECORDS"),
                ),
            ]
        elif scenario_id == "MAX_GENESIS":
            predicates = [
                _predicate(
                    "GENESIS_SIGNATURE_WORK", _checked_mul(
                        _selected(envelope, "GENESIS_ATTEMPTS"), _selected(envelope, "SIGNATURE_ATTEMPTS")
                    ), "<=", _selected(envelope, "REPLAYED_EVENT_WORK"),
                ),
                _predicate(
                    "EVENT_SIGNATURE_WORK", _checked_mul(
                        _selected(envelope, "EVENTS_ADMITTED"), _selected(envelope, "SIGNATURE_ATTEMPTS")
                    ), "<=", _selected(envelope, "REPLAYED_EVENT_WORK"),
                ),
            ]
        elif scenario_id == "MAX_ACTORS":
            predicates = [
                _predicate(
                    "ACTOR_CREDENTIAL_ROLE_CAPACITY", _selected(envelope, "ROLE_ASSIGNMENTS"), "<=",
                    _checked_mul(_selected(envelope, "ACTORS"), _selected(envelope, "CREDENTIALS")),
                ),
                _predicate(
                    "CREDENTIAL_LINEAGE_STATE_CAPACITY", _checked_mul(
                        _selected(envelope, "CREDENTIALS"), _selected(envelope, "LINEAGE_DEPTH")
                    ), "<=", _selected(envelope, "AUTHORITY_STATES"),
                ),
            ]
        elif scenario_id == "JOINT_WORK":
            predicates = [_predicate(
                "AGGREGATE_TRANSIENT_WORKING_SET", _checked_add(*_transient_components(envelope)), "<=",
                _selected(envelope, "TRANSIENT_MEMORY_CAPABILITY"),
            )]
        elif scenario_id == "MAX_STEERING":
            predicates = [
                _predicate(
                    "EVIDENCE_FORK_STATE_CAPACITY", _checked_mul(
                        _selected(envelope, "EVIDENCE_PER_CREDENTIAL"), _selected(envelope, "FORK_SLOTS")
                    ), "<=", _selected(envelope, "AUTHORITY_STATES"),
                ),
                _predicate(
                    "STEERING_TRANSITION_CAPACITY", _selected(envelope, "AUTHORITY_TRANSITIONS"), "<=",
                    _checked_mul(_selected(envelope, "AUTHORITY_STATES"), _selected(envelope, "AUTHORITY_CONCURRENT_CONTROLS")),
                ),
            ]
        elif scenario_id == "MAX_EXPANSION":
            predicates = [_predicate(
                "FRAMING_EXPANSION_CONTENT_CAPACITY", _checked_add(
                    _selected(envelope, "FRAMING_OBJECT_OCTETS"),
                    _selected(envelope, "AP_EXPANDED_CONTENT_OCTETS"),
                ), "<=", _selected(envelope, "CONTENT_EXACT_OCTETS"),
            )]
        elif scenario_id == "POST_DIAGNOSTICS":
            predicates = [_predicate(
                "TRANSCRIPT_CONTENT_WITHIN_TRANSIENT_CAPABILITY",
                _selected(envelope, "CONTENT_EXACT_OCTETS"), "<=",
                _selected(envelope, "TRANSIENT_MEMORY_CAPABILITY"),
            )]
        else:
            raise ValueError(f"combined scenario has no executable predicate: {scenario_id}")
        if not predicates or not all(item["passed"] for item in predicates):
            raise ValueError(f"combined scenario failed: {scenario_id}")
        result.append({
            "scenario_id": scenario_id, "values": values, "predicates": predicates,
            "disposition": "EXECUTE",
        })
    return result
