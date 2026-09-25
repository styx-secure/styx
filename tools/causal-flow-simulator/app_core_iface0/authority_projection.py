"""Independent bounded Pass-0 authority projection for APP-CORE-IFACE-0.

The input consists only of already K-admitted, parsed event facts.  This module
does no parsing, signature verification, persistence or product authorization;
it implements the set-valued O-02 fold selected in the pinned decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


REDUCTIONS = frozenset({"REVOKE", "ROTATE"})
EXPANSIONS = frozenset({"GRANT", "RECOVER", "POLICY", "CLOSURE"})


class AuthorityProjectionError(ValueError):
    """The admitted closure contradicts the selected bounded authority model."""


class AuthorityProjectionUnavailable(RuntimeError):
    """The selected reachable-state or transition envelope was crossed."""


@dataclass(frozen=True)
class AuthorityEvent:
    reference: str
    actor: str
    sequence: int
    kind: str
    dependencies: frozenset[str]
    ancestors: frozenset[str]
    target_credential: str | None = None


@dataclass(frozen=True)
class ForkSlot:
    internal_id: str
    credential: str
    sequence: int
    siblings: tuple[str, ...]
    closure: frozenset[str]


@dataclass(frozen=True)
class AuthorityState:
    processed: frozenset[str]
    authority: frozenset[str]
    revoked: frozenset[str]
    forked: frozenset[str]


@dataclass(frozen=True)
class AuthorityFold:
    accepted_controls: frozenset[str]
    reduction_standing: Mapping[str, str]
    event_authority: Mapping[str, str]
    possible_terminal_authority: frozenset[str]
    necessary_terminal_authority: frozenset[str]
    terminal_authority: frozenset[str]
    revoked: frozenset[str]
    terminated: frozenset[str]
    forked_credentials: frozenset[str]
    fork_slots: tuple[ForkSlot, ...]
    reachable_state_count: int
    transition_count: int
    max_concurrent_controls: int
    ordinary_prefix_query_max: int
    replayed_event_work: int


def lineage_descendants(
    lineage: Mapping[str, tuple[str | None, str]], roots: set[str] | frozenset[str]
) -> frozenset[str]:
    result = set(roots)
    changed = True
    while changed:
        changed = False
        for credential, (issuer, _) in lineage.items():
            if issuer in result and credential not in result:
                result.add(credential)
                changed = True
    return frozenset(result)


def build_events(
    records: Sequence[Mapping[str, Any]],
    ancestors: Mapping[str, frozenset[str]],
) -> tuple[AuthorityEvent, ...]:
    events = []
    for record in records:
        fields = record["fields"]
        tail = fields.get("tail", {})
        kind = (
            tail.get("kind", "ACTION")
            if fields["eventRole"] == "CREDENTIAL"
            else "REMOVE"
            if fields["eventRole"] == "REMOVAL"
            else "ACTION"
        )
        target = None
        if kind == "REVOKE":
            target = tail["targetCredentialHex"]
        elif kind == "ROTATE":
            target = tail["retiringCredentialHex"]
        dependencies = set(fields["causalParents"])
        if fields["directPredecessorHex"] is not None:
            dependencies.add(fields["directPredecessorHex"])
        events.append(
            AuthorityEvent(
                reference=record["reference"],
                actor=fields["credentialIdentifierHex"],
                sequence=fields["authorSequence"],
                kind=kind,
                dependencies=frozenset(dependencies),
                ancestors=ancestors[record["reference"]],
                target_credential=target,
            )
        )
    return tuple(events)


def build_fork_slots(
    events: Sequence[AuthorityEvent],
    fork_relation: Mapping[tuple[str, int], tuple[str, ...]],
) -> tuple[ForkSlot, ...]:
    by_reference = {event.reference: event for event in events}
    result = []
    for ordinal, ((credential, sequence), siblings) in enumerate(
        sorted(fork_relation.items())
    ):
        closure = set(siblings)
        for reference in siblings:
            closure.update(by_reference[reference].ancestors)
        # Internal only.  The released conformance-plane label is deliberately
        # left to the separately reviewed APP-core label relation.
        internal_id = f"@fork/{ordinal}/{credential}/{sequence}"
        result.append(
            ForkSlot(
                internal_id,
                credential,
                sequence,
                siblings,
                frozenset(closure),
            )
        )
    return tuple(result)


def _predecessors(
    controls: Sequence[AuthorityEvent], forks: Sequence[ForkSlot]
) -> dict[str, frozenset[str]]:
    control_references = {event.reference for event in controls}
    result: dict[str, set[str]] = {}
    for event in controls:
        required = set(event.ancestors) & control_references
        for fork in forks:
            if set(fork.siblings) <= set(event.ancestors):
                required.add(fork.internal_id)
        result[event.reference] = required
    for fork in forks:
        required = set(fork.closure) & control_references
        for other in forks:
            if other is not fork and set(other.siblings) <= set(fork.closure):
                required.add(other.internal_id)
        result[fork.internal_id] = required
    return {key: frozenset(value) for key, value in result.items()}


def authority_ready_width(
    events: Sequence[AuthorityEvent],
    fork_relation: Mapping[tuple[str, int], tuple[str, ...]],
) -> tuple[int, int]:
    """Measure the authority-item poset before any protected state fold.

    The result is ``(maximum ready width, processed-item down-set count)``.
    Neither value depends on an authority decision, and deriving it separately
    preserves V9's Branch-B first-failure order.
    """

    controls = tuple(
        event for event in events if event.kind in EXPANSIONS | REDUCTIONS
    )
    forks = build_fork_slots(events, fork_relation)
    predecessors = _predecessors(controls, forks)
    item_references = frozenset(predecessors)
    frontier = {frozenset()}
    reachable = set(frontier)
    maximum = 0
    for _ in range(len(item_references)):
        following: set[frozenset[str]] = set()
        for processed in frontier:
            ready = {
                reference
                for reference in item_references - processed
                if predecessors[reference] <= processed
            }
            maximum = max(maximum, len(ready))
            following.update(processed | {reference} for reference in ready)
        if not following:
            raise AuthorityProjectionError("authority item graph is cyclic")
        reachable.update(following)
        frontier = following
    if any(len(processed) != len(item_references) for processed in frontier):
        raise AuthorityProjectionError("authority item poset ended incompletely")
    return maximum, len(reachable)


def _advance(
    state: AuthorityState,
    item: AuthorityEvent | ForkSlot,
    lineage: Mapping[str, tuple[str | None, str]],
) -> tuple[AuthorityState, bool | None]:
    authority = set(state.authority)
    revoked = set(state.revoked)
    forked = set(state.forked)
    reference = item.internal_id if isinstance(item, ForkSlot) else item.reference
    if isinstance(item, ForkSlot):
        forked.add(item.credential)
        authority -= set(lineage_descendants(lineage, {item.credential}))
        actor_authorized = None
    else:
        terminated = lineage_descendants(lineage, revoked | forked)
        actor_authorized = item.actor in authority and item.actor not in terminated
        if actor_authorized:
            if item.kind == "GRANT":
                authority.add(item.reference)
            elif item.kind in REDUCTIONS and item.target_credential is not None:
                revoked.add(item.target_credential)
                authority -= set(
                    lineage_descendants(lineage, {item.target_credential})
                )
    return (
        AuthorityState(
            processed=state.processed | {reference},
            authority=frozenset(authority),
            revoked=frozenset(revoked),
            forked=frozenset(forked),
        ),
        actor_authorized,
    )


def _explore(
    controls: Sequence[AuthorityEvent],
    forks: Sequence[ForkSlot],
    lineage: Mapping[str, tuple[str | None, str]],
    root_authority: frozenset[str],
    *,
    state_limit: int,
    transition_limit: int,
    concurrent_limit: int | None,
) -> tuple[
    frozenset[AuthorityState],
    Mapping[str, frozenset[bool]],
    frozenset[frozenset[str]],
    int,
    int,
]:
    items: dict[str, AuthorityEvent | ForkSlot] = {
        event.reference: event for event in controls
    }
    items.update({fork.internal_id: fork for fork in forks})
    predecessors = _predecessors(controls, forks)
    initial = AuthorityState(
        frozenset(), root_authority, frozenset(), frozenset()
    )
    frontier = {initial}
    reachable = {initial}
    observations: dict[str, set[bool]] = {
        event.reference: set() for event in controls
    }
    transitions = 0
    max_concurrent = 0
    for _ in range(len(items)):
        following: set[AuthorityState] = set()
        for state in frontier:
            ready = sorted(
                reference
                for reference in items
                if reference not in state.processed
                and predecessors[reference] <= state.processed
            )
            max_concurrent = max(max_concurrent, len(ready))
            if concurrent_limit is not None and len(ready) > concurrent_limit:
                raise AuthorityProjectionUnavailable(
                    "AUTHORITY_CONCURRENT_CONTROLS"
                )
            for reference in ready:
                transitions += 1
                if transitions > transition_limit:
                    raise AuthorityProjectionUnavailable("AUTHORITY_TRANSITIONS")
                successor, actor_authorized = _advance(
                    state, items[reference], lineage
                )
                if actor_authorized is not None:
                    observations[reference].add(actor_authorized)
                following.add(successor)
        if not following:
            raise AuthorityProjectionError("authority item graph is cyclic")
        reachable.update(following)
        if len(reachable) > state_limit:
            raise AuthorityProjectionUnavailable("AUTHORITY_STATES")
        frontier = following
    if any(len(state.processed) != len(items) for state in frontier):
        raise AuthorityProjectionError("authority fold ended incompletely")
    return (
        frozenset(reachable),
        {
            reference: frozenset(values)
            for reference, values in observations.items()
        },
        frozenset(state.authority for state in frontier),
        transitions,
        max_concurrent,
    )


def fold_authority(
    events: Sequence[AuthorityEvent],
    lineage: Mapping[str, tuple[str | None, str]],
    root_credential: str,
    fork_relation: Mapping[tuple[str, int], tuple[str, ...]],
    *,
    state_limit: int,
    transition_limit: int,
    concurrent_limit: int | None = None,
) -> AuthorityFold:
    """Fold every K-admitted control and probe every retained event."""

    controls = tuple(
        event
        for event in events
        if event.kind in EXPANSIONS | REDUCTIONS
    )
    forks = build_fork_slots(events, fork_relation)
    reachable, observations, terminal_sets, transitions, max_concurrent = _explore(
        controls,
        forks,
        lineage,
        frozenset({root_credential}),
        state_limit=state_limit,
        transition_limit=transition_limit,
        concurrent_limit=concurrent_limit,
    )
    may = {
        reference for reference, values in observations.items() if True in values
    }
    must = {
        reference
        for reference, values in observations.items()
        if values == frozenset({True})
    }
    accepted = {
        event.reference
        for event in controls
        if event.reference in must
    }
    may_only = may - must
    contested: dict[str, list[AuthorityEvent]] = {}
    for event in controls:
        if event.reference not in may_only or event.kind not in REDUCTIONS:
            continue
        if event.target_credential is None:
            raise AuthorityProjectionError("reduction has no target")
        if event.actor in lineage_descendants(lineage, {event.target_credential}):
            continue
        contested.setdefault(event.actor, []).append(event)
    for candidates in contested.values():
        selected_sequence = min(event.sequence for event in candidates)
        accepted.update(
            event.reference
            for event in candidates
            if event.sequence == selected_sequence
        )

    granted = {root_credential}
    revoked: set[str] = set()
    for event in controls:
        if event.reference not in accepted:
            continue
        if event.kind == "GRANT":
            granted.add(event.reference)
        elif event.kind in REDUCTIONS and event.target_credential is not None:
            revoked.add(event.target_credential)
    forked = frozenset(fork.credential for fork in forks)
    terminated = lineage_descendants(lineage, revoked | set(forked))
    terminal = frozenset(granted - set(terminated))
    possible = (
        frozenset().union(*terminal_sets) if terminal_sets else frozenset()
    )
    necessary = (
        frozenset.intersection(*terminal_sets) if terminal_sets else frozenset()
    )
    standing: dict[str, str] = {}
    for event in controls:
        if event.reference not in accepted or event.kind not in REDUCTIONS:
            continue
        issuer, grant_reference = lineage[event.actor]
        standing[event.reference] = (
            "GENESIS"
            if issuer is None
            else "ACCEPTED_GRANT"
            if grant_reference in accepted
            else "POSSIBLE_GRANT"
        )
    verdicts = {
        reference: (
            "MUST_AUTH"
            if reference in must
            else "MAY_AUTH"
            if reference in may
            else "NO_AUTH"
        )
        for reference in observations
    }

    # Ordinary/removal acting-prefix probes use the same reachable state set,
    # but the event itself never becomes an authority item.
    control_references = {event.reference for event in controls}
    prefix_query_counts = {state: 0 for state in reachable}
    for event in events:
        if event.reference in verdicts:
            continue
        required_before = set(event.ancestors) & control_references
        required_after = {
            control.reference
            for control in controls
            if event.reference in control.ancestors
        }
        for fork in forks:
            if set(fork.siblings) <= set(event.ancestors):
                required_before.add(fork.internal_id)
            if event.reference in fork.closure:
                required_after.add(fork.internal_id)
        values = []
        for state in reachable:
            if not required_before <= set(state.processed):
                continue
            if set(state.processed) & required_after:
                continue
            prefix_query_counts[state] += 1
            terminated_at_prefix = lineage_descendants(
                lineage, set(state.revoked) | set(state.forked)
            )
            values.append(
                event.actor in state.authority
                and event.actor not in terminated_at_prefix
            )
        if not values:
            raise AuthorityProjectionError("ordinary acting prefix is unreachable")
        verdicts[event.reference] = (
            "MUST_AUTH" if all(values) else "MAY_AUTH" if any(values) else "NO_AUTH"
        )

    return AuthorityFold(
        accepted_controls=frozenset(accepted),
        reduction_standing=dict(sorted(standing.items())),
        event_authority=dict(sorted(verdicts.items())),
        possible_terminal_authority=possible,
        necessary_terminal_authority=necessary,
        terminal_authority=terminal,
        revoked=frozenset(revoked),
        terminated=terminated,
        forked_credentials=forked,
        fork_slots=forks,
        reachable_state_count=len(reachable),
        transition_count=transitions,
        max_concurrent_controls=max_concurrent,
        ordinary_prefix_query_max=max(prefix_query_counts.values(), default=0),
        replayed_event_work=(
            len(events) + transitions + sum(prefix_query_counts.values())
        ),
    )
