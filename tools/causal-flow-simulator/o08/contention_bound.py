"""Exact evidence-only authority-contention bound for O-08.

The module consumes the authority items and bindings obtained from the frozen
C0.2j admission result.  It does not alter, short-circuit, or replace the
authority fold.  All arithmetic is exact and every ordering is canonical.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import comb
from typing import Any, Iterable, Mapping, Sequence


JAVASCRIPT_SAFE_INTEGER = (1 << 53) - 1
REDUCTION_KINDS = frozenset({"REVOKE", "ROTATE"})


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


def _checked(value: int, label: str) -> int:
    if value < 0 or value > JAVASCRIPT_SAFE_INTEGER:
        raise ContentionBoundError(f"{label} exceeds the exact cross-runtime integer domain")
    return value


def _closure(items: Mapping[str, AuthorityItem]) -> dict[str, frozenset[str]]:
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
    references: Sequence[str], closure: Mapping[str, frozenset[str]]
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


def _maximum_antichain_width(
    references: Sequence[str], closure: Mapping[str, frozenset[str]]
) -> int:
    matched_right: dict[str, str] = {}

    def augment(left: str, seen: set[str]) -> bool:
        for right in references:
            if left not in closure[right] or right in seen:
                continue
            seen.add(right)
            if right not in matched_right or augment(matched_right[right], seen):
                matched_right[right] = left
                return True
        return False

    matching = sum(augment(left, set()) for left in references)
    return len(references) - matching


def _lineage_descendants(
    issuer_by_credential: Mapping[str, str | None], roots: Iterable[str]
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


def _induced_ideal_count(
    actor_mask: int,
    references: Sequence[str],
    closure: Mapping[str, frozenset[str]],
    cache: dict[int, int],
) -> int:
    if actor_mask in cache:
        return cache[actor_mask]
    selected = tuple(
        reference
        for position, reference in enumerate(references)
        if actor_mask & (1 << position)
    )
    selected_set = set(selected)
    induced = {
        reference: frozenset(closure[reference] & selected_set)
        for reference in selected
    }
    count = len(_ideal_masks(selected, induced))
    cache[actor_mask] = count
    return count


def static_trace_bound(width: int, control_count: int, fork_slot_count: int) -> int:
    if min(width, control_count, fork_slot_count) < 0:
        raise ContentionBoundError("negative static-bound input")
    vertices = control_count + fork_slot_count
    value = sum(comb(vertices, rank) for rank in range(min(width, vertices) + 1))
    return _checked(value * (1 << control_count), "static trace bound")


def evaluate_contention_bound(
    items: Sequence[AuthorityItem],
    issuer_by_credential: Mapping[str, str | None],
    *,
    mutation: str | None = None,
) -> ContentionBound:
    by_reference = {item.reference: item for item in items}
    if len(by_reference) != len(items) or any(not item.reference for item in items):
        raise ContentionBoundError("authority item references must be unique and non-empty")
    if any(item.item_type not in {"CONTROL", "FORK_JOIN"} for item in items):
        raise ContentionBoundError("unknown authority item type")
    controls = tuple(item for item in items if item.item_type == "CONTROL")
    joins = tuple(item for item in items if item.item_type == "FORK_JOIN")
    if any(not item.actor_id or not item.control_kind for item in controls):
        raise ContentionBoundError("control actor and kind are required")
    if any(not item.credential_id for item in joins):
        raise ContentionBoundError("fork join credential is required")

    references = tuple(sorted(by_reference))
    index = {reference: position for position, reference in enumerate(references)}
    closure = _closure(by_reference)
    ideals = _ideal_masks(references, closure)
    width = _maximum_antichain_width(references, closure)

    descendant_cache: dict[str, frozenset[str]] = {}

    def descendants(credential_id: str) -> frozenset[str]:
        if credential_id not in descendant_cache:
            descendant_cache[credential_id] = (
                frozenset({credential_id})
                if mutation == "M_B4_OMIT_DESCENDANT_CLOSURE"
                else _lineage_descendants(issuer_by_credential, {credential_id})
            )
        return descendant_cache[credential_id]

    killer_by_actor: dict[str, set[str]] = {}
    actors = sorted({str(item.actor_id) for item in controls})
    for actor in actors:
        killers: set[str] = set()
        for item in controls:
            if (
                item.control_kind in REDUCTION_KINDS
                and item.target_id is not None
                and actor in descendants(item.target_id)
            ):
                killers.add(item.reference)
        if mutation != "M_B4_OMIT_FORK_JOINS":
            for join in joins:
                if actor in descendants(str(join.credential_id)):
                    killers.add(join.reference)
        killer_by_actor[actor] = killers

    def incomparable(left: str, right: str) -> bool:
        if mutation == "M_B4_INCOMPARABLE_IS_COMPARABLE":
            return False
        return (
            left != right
            and left not in closure[right]
            and right not in closure[left]
        )

    contended = {
        item.reference
        for item in controls
        if any(
            incomparable(item.reference, killer)
            for killer in killer_by_actor[str(item.actor_id)]
        )
    }
    contended_actors = tuple(sorted({
        str(item.actor_id) for item in controls if item.reference in contended
    }))
    actor_control_masks = {
        actor: sum(
            1 << index[item.reference]
            for item in controls if item.actor_id == actor
        )
        for actor in contended_actors
    }
    contended_masks = {
        actor: sum(
            1 << index[item.reference]
            for item in controls
            if item.actor_id == actor and item.reference in contended
        )
        for actor in contended_actors
    }
    ideal_count_cache: dict[str, dict[int, int]] = {
        actor: {} for actor in contended_actors
    }

    value = 0
    for ideal in ideals:
        factor = 1
        for actor in contended_actors:
            actor_mask = ideal & actor_control_masks[actor]
            contended_count = (ideal & contended_masks[actor]).bit_count()
            actor_ideals = _induced_ideal_count(
                actor_mask, references, closure, ideal_count_cache[actor]
            )
            if mutation == "M_B4_SMALLER_IDEAL_COUNT":
                actor_ideals = max(0, actor_ideals - 1)
            elif mutation == "M_B4_LARGER_IDEAL_COUNT":
                actor_ideals += 1
            power = 1 << contended_count
            actor_factor = (
                power if mutation == "M_B4_POWER_ONLY"
                else actor_ideals if mutation == "M_B4_IDEAL_ONLY"
                else min(power, actor_ideals) + 1 if mutation == "M_B4_PLUS_ONE"
                else min(power, actor_ideals)
            )
            product = factor * actor_factor
            factor = (
                product % 256
                if mutation == "M_B4_WRAP_ARITHMETIC"
                else _checked(product, "contention factor")
            )
        total = value + factor
        value = (
            total % 256
            if mutation == "M_B4_WRAP_ARITHMETIC"
            else _checked(total, "authority contention bound")
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
    model: Any,
    controls: Sequence[Any],
    joins: Sequence[Any],
    predecessors: Mapping[str, frozenset[str]],
) -> tuple[AuthorityItem, ...]:
    """Translate exact frozen-model admission output without re-deriving it."""

    result: list[AuthorityItem] = []
    for event in controls:
        result.append(AuthorityItem(
            reference=event.reference,
            item_type="CONTROL",
            predecessors=frozenset(predecessors[event.reference]),
            actor_id=event.actor_id,
            control_kind=event.kind.value,
            target_id=event.target_id,
        ))
    for join in joins:
        result.append(AuthorityItem(
            reference=join.reference,
            item_type="FORK_JOIN",
            predecessors=frozenset(predecessors[join.reference]),
            credential_id=join.credential_id,
        ))
    return tuple(sorted(result, key=lambda item: item.reference))
