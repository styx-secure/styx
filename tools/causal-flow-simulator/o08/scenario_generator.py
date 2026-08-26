"""Deterministically derive boundary and combined O-08 scenarios."""

from __future__ import annotations

from dataclasses import dataclass
from math import comb
from typing import Any, Iterable, Mapping, Sequence

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
JAVASCRIPT_SAFE_INTEGER = (1 << 53) - 1
REDUCTION_KINDS = frozenset({"REVOKE", "ROTATE"})


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


class ContentionBoundError(ValueError):
    """The admitted authority input is malformed or exceeds the exact domain."""


@dataclass(frozen=True)
class AuthorityItem:
    reference: str
    item_type: str
    predecessors: frozenset[str]
    actor_id: str | None = None
    control_kind: str | None = None
    target_id: str | None = None
    credential_id: str | None = None


@dataclass(frozen=True)
class ContentionBound:
    value: int
    ideal_count: int
    width: int
    contended_controls: tuple[str, ...]
    contended_actors: tuple[str, ...]
    static_trace_bound: int

    def canonical_view(self) -> dict[str, object]:
        return {
            "authority_contention_bound": self.value,
            "authority_ideal_count": self.ideal_count,
            "contended_actors": list(self.contended_actors),
            "contended_controls": list(self.contended_controls),
            "exact_width": self.width,
            "static_trace_bound": self.static_trace_bound,
        }


def _checked_exact(value: int, label: str) -> int:
    if value < 0 or value > JAVASCRIPT_SAFE_INTEGER:
        raise ContentionBoundError(
            f"{label} exceeds the exact cross-runtime integer domain"
        )
    return value


def _contention_closure(
    items: Mapping[str, AuthorityItem],
) -> dict[str, frozenset[str]]:
    references = set(items)
    result = {reference: set(item.predecessors) for reference, item in items.items()}
    if any(not required <= references for required in result.values()):
        raise ContentionBoundError("authority item references an unknown predecessor")
    changed = True
    while changed:
        changed = False
        for reference in sorted(result):
            expanded = set(result[reference])
            for predecessor in tuple(expanded):
                expanded.update(result[predecessor])
            if reference in expanded:
                raise ContentionBoundError("authority poset is cyclic")
            if expanded != result[reference]:
                result[reference] = expanded
                changed = True
    return {reference: frozenset(values) for reference, values in result.items()}


def _ideal_masks(
    references: Sequence[str], closure: Mapping[str, frozenset[str]],
) -> tuple[int, ...]:
    index = {reference: position for position, reference in enumerate(references)}
    predecessor_masks = {
        reference: sum(1 << index[item] for item in closure[reference])
        for reference in references
    }
    seen = {0}
    frontier = [0]
    while frontier:
        mask = frontier.pop()
        for position, reference in enumerate(references):
            bit = 1 << position
            if mask & bit or predecessor_masks[reference] & ~mask:
                continue
            candidate = mask | bit
            if candidate not in seen:
                seen.add(candidate)
                frontier.append(candidate)
    return tuple(sorted(seen))


def _lineage_descendants(
    issuer_by_credential: Mapping[str, str | None], roots: Iterable[str],
) -> frozenset[str]:
    descendants = set(roots)
    changed = True
    while changed:
        changed = False
        for credential_id, issuer_id in issuer_by_credential.items():
            if issuer_id in descendants and credential_id not in descendants:
                descendants.add(credential_id)
                changed = True
    return frozenset(descendants)


def static_trace_bound(width: int, control_count: int, fork_slot_count: int) -> int:
    if min(width, control_count, fork_slot_count) < 0:
        raise ContentionBoundError("negative static-bound input")
    vertices = control_count + fork_slot_count
    antichains = sum(
        comb(vertices, rank) for rank in range(min(width, vertices) + 1)
    )
    return _checked_exact(antichains * (1 << control_count), "static trace bound")


def evaluate_contention_bound(
    items: Sequence[AuthorityItem],
    issuer_by_credential: Mapping[str, str | None],
    *,
    mutation: str | None = None,
) -> ContentionBound:
    by_reference = {item.reference: item for item in items}
    if len(by_reference) != len(items) or any(not item.reference for item in items):
        raise ContentionBoundError("authority item references must be unique")
    controls = tuple(item for item in items if item.item_type == "CONTROL")
    joins = tuple(item for item in items if item.item_type == "FORK_JOIN")
    if len(controls) + len(joins) != len(items):
        raise ContentionBoundError("unknown authority item type")
    if any(not item.actor_id or not item.control_kind for item in controls):
        raise ContentionBoundError("control actor and kind are required")
    if any(not item.credential_id for item in joins):
        raise ContentionBoundError("fork join credential is required")

    references = tuple(sorted(by_reference))
    index = {reference: position for position, reference in enumerate(references)}
    closure = _contention_closure(by_reference)
    ideals = _ideal_masks(references, closure)
    width = maximum_antichain_width({
        reference: item.predecessors for reference, item in by_reference.items()
    })
    descendants_cache: dict[str, frozenset[str]] = {}

    def descendants(credential_id: str) -> frozenset[str]:
        if credential_id not in descendants_cache:
            descendants_cache[credential_id] = (
                frozenset({credential_id})
                if mutation == "M_B4_OMIT_DESCENDANT_CLOSURE"
                else _lineage_descendants(issuer_by_credential, {credential_id})
            )
        return descendants_cache[credential_id]

    killers_by_actor: dict[str, set[str]] = {}
    actors = sorted({str(item.actor_id) for item in controls})
    for actor in actors:
        killers = {
            item.reference for item in controls
            if item.control_kind in REDUCTION_KINDS
            and item.target_id is not None
            and actor in descendants(item.target_id)
        }
        if mutation != "M_B4_OMIT_FORK_JOINS":
            killers.update(
                join.reference for join in joins
                if actor in descendants(str(join.credential_id))
            )
        killers_by_actor[actor] = killers

    def incomparable(left: str, right: str) -> bool:
        return (
            mutation != "M_B4_INCOMPARABLE_IS_COMPARABLE"
            and left != right and left not in closure[right]
            and right not in closure[left]
        )

    contended = {
        item.reference for item in controls
        if any(
            incomparable(item.reference, killer)
            for killer in killers_by_actor[str(item.actor_id)]
        )
    }
    contended_actors = tuple(sorted({
        str(item.actor_id) for item in controls if item.reference in contended
    }))
    actor_masks = {
        actor: sum(
            1 << index[item.reference] for item in controls
            if item.actor_id == actor
        )
        for actor in contended_actors
    }
    contended_masks = {
        actor: sum(
            1 << index[item.reference] for item in controls
            if item.actor_id == actor and item.reference in contended
        )
        for actor in contended_actors
    }
    ideal_cache: dict[int, int] = {}

    def induced_ideal_count(mask: int) -> int:
        if mask not in ideal_cache:
            selected = tuple(
                reference for position, reference in enumerate(references)
                if mask & (1 << position)
            )
            selected_set = set(selected)
            induced = {
                reference: frozenset(closure[reference] & selected_set)
                for reference in selected
            }
            ideal_cache[mask] = len(_ideal_masks(selected, induced))
        return ideal_cache[mask]

    value = 0
    for ideal in ideals:
        factor = 1
        for actor in contended_actors:
            actor_mask = ideal & actor_masks[actor]
            contended_count = (ideal & contended_masks[actor]).bit_count()
            actor_ideals = induced_ideal_count(actor_mask)
            if mutation == "M_B4_SMALLER_IDEAL_COUNT":
                actor_ideals = max(0, actor_ideals - 1)
            elif mutation == "M_B4_LARGER_IDEAL_COUNT":
                actor_ideals += 1
            power = 1 << contended_count
            actor_factor = (
                power if mutation == "M_B4_POWER_ONLY"
                else actor_ideals if mutation == "M_B4_IDEAL_ONLY"
                else min(power, actor_ideals) + 1
                if mutation == "M_B4_PLUS_ONE"
                else min(power, actor_ideals)
            )
            product = factor * actor_factor
            factor = (
                product % 256 if mutation == "M_B4_WRAP_ARITHMETIC"
                else _checked_exact(product, "contention factor")
            )
        total = value + factor
        value = (
            total % 256 if mutation == "M_B4_WRAP_ARITHMETIC"
            else _checked_exact(total, "authority contention bound")
        )
    if mutation == "M_B4_SKIP_EVIDENCE":
        value = 0
    if mutation == "M_B4_SMALLER_WIDTH":
        width = max(0, width - 1)
    elif mutation == "M_B4_LARGER_WIDTH":
        width = min(len(references), width + 1)
    return ContentionBound(
        value=value,
        ideal_count=len(ideals),
        width=width,
        contended_controls=tuple(sorted(contended)),
        contended_actors=contended_actors,
        static_trace_bound=static_trace_bound(width, len(controls), len(joins)),
    )


def items_from_model(
    model: Any, controls: Sequence[Any], joins: Sequence[Any],
    predecessors: Mapping[str, frozenset[str]],
) -> tuple[AuthorityItem, ...]:
    result = [AuthorityItem(
        reference=event.reference, item_type="CONTROL",
        predecessors=frozenset(predecessors[event.reference]),
        actor_id=event.actor_id, control_kind=event.kind.value,
        target_id=event.target_id,
    ) for event in controls]
    result.extend(AuthorityItem(
        reference=join.reference, item_type="FORK_JOIN",
        predecessors=frozenset(predecessors[join.reference]),
        credential_id=join.credential_id,
    ) for join in joins)
    return tuple(sorted(result, key=lambda item: item.reference))


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
                    _checked_add(
                        _selected(envelope, "EVENTS_ADMITTED"),
                        _checked_mul(
                            _selected(envelope, "AUTHORITY_TRANSITIONS"),
                            _checked_add(1, _selected(envelope, "ORDINARY_PREFIX_QUERIES")),
                        ),
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
