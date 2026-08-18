"""Bounded, specification-derived causal model for Styx C0.2d.

This module is deliberately independent from every production and legacy Styx
implementation.  Synthetic byte strings stand in for future authenticated
event references; this module does not define their cryptographic derivation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping, Sequence


class ModelInputError(ValueError):
    """The closed synthetic input is malformed or exceeds its profile."""


class Status(str, Enum):
    ADMITTED = "admitted"
    FORK = "fork"
    GAP = "gap"
    DEFERRED = "deferred"
    STALE = "stale"
    INVALID = "invalid"


@dataclass(frozen=True, order=True)
class Context:
    application: str
    profile: str
    instance: str
    genesis_ref: bytes


@dataclass(frozen=True)
class CredentialAuthority:
    credential_id: bytes
    context: Context
    grant_ref: bytes
    revocation_refs: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class Event:
    reference: bytes
    context: Context
    credential_id: bytes
    sequence: int
    author_predecessor: bytes | None
    causal_parents: tuple[bytes, ...]
    kind: str = "action"

    @property
    def dependencies(self) -> tuple[bytes, ...]:
        if self.author_predecessor is None:
            return self.causal_parents
        return (self.author_predecessor, *self.causal_parents)


@dataclass(frozen=True)
class CheckpointEvidence:
    context: Context
    proven_refs: frozenset[bytes] = frozenset()
    stale_refs: frozenset[bytes] = frozenset()
    author_heads: tuple[tuple[bytes, int, bytes], ...] = ()

    def author_head(self, credential_id: bytes) -> tuple[int, bytes] | None:
        for candidate, sequence, reference in self.author_heads:
            if candidate == credential_id:
                return sequence, reference
        return None


@dataclass(frozen=True)
class Profile:
    max_events: int = 9
    max_credentials: int = 8
    max_parents: int = 4
    max_checkpoint_refs: int = 32
    max_reference_bytes: int = 8
    max_text_bytes: int = 64
    max_input_bytes: int = 4096
    max_sequence: int = 255
    max_delivery_traces: int = 720

    def validate(self) -> None:
        fields = (
            self.max_events,
            self.max_credentials,
            self.max_parents,
            self.max_checkpoint_refs,
            self.max_reference_bytes,
            self.max_text_bytes,
            self.max_input_bytes,
            self.max_sequence,
            self.max_delivery_traces,
        )
        if any(type(value) is not int or value < 1 for value in fields):
            raise ModelInputError("profile limits must be positive integers")


@dataclass(frozen=True)
class Decision:
    status: Status
    reasons: tuple[str, ...] = ()
    duplicate_observations: int = 0
    fork_peers: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class Handoff:
    reference: bytes
    classification: Status
    context: Context
    credential_id: bytes
    grant_ref: bytes
    sequence: int
    kind: str
    author_predecessor: bytes | None
    causal_parents: tuple[bytes, ...]
    prior_references: tuple[bytes, ...]
    causal_relations: tuple[tuple[bytes, str], ...]
    fork_peers: tuple[bytes, ...]
    revocation_relations: tuple[tuple[bytes, str], ...]


@dataclass(frozen=True)
class Evaluation:
    decisions: Mapping[bytes, Decision]
    duplicate_refs: tuple[bytes, ...]
    graph: Mapping[bytes, tuple[bytes, ...]]
    ready_sets: tuple[tuple[bytes, ...], ...]
    order: tuple[bytes, ...]
    handoffs: tuple[Handoff, ...]


def _hex(reference: bytes | None) -> str | None:
    return None if reference is None else reference.hex()


def _context_json(context: Context) -> dict[str, object]:
    return {
        "application": context.application,
        "profile": context.profile,
        "instance": context.instance,
        "genesis_ref": context.genesis_ref.hex(),
    }


def evaluation_json(evaluation: Evaluation) -> dict[str, object]:
    """Return a deterministic JSON-ready representation."""

    decisions = {}
    for reference in sorted(evaluation.decisions):
        decision = evaluation.decisions[reference]
        decisions[reference.hex()] = {
            "status": decision.status.value,
            "reasons": list(decision.reasons),
            "duplicate_observations": decision.duplicate_observations,
            "fork_peers": [item.hex() for item in decision.fork_peers],
        }
    handoffs = []
    for item in evaluation.handoffs:
        handoffs.append(
            {
                "reference": item.reference.hex(),
                "classification": item.classification.value,
                "context": _context_json(item.context),
                "credential_id": item.credential_id.hex(),
                "grant_ref": item.grant_ref.hex(),
                "sequence": item.sequence,
                "kind": item.kind,
                "author_predecessor": _hex(item.author_predecessor),
                "causal_parents": [parent.hex() for parent in item.causal_parents],
                "prior_references": [reference.hex() for reference in item.prior_references],
                "causal_relations": [
                    [other.hex(), relation] for other, relation in item.causal_relations
                ],
                "fork_peers": [peer.hex() for peer in item.fork_peers],
                "revocation_relations": [
                    [revocation.hex(), relation]
                    for revocation, relation in item.revocation_relations
                ],
            }
        )
    return {
        "decisions": decisions,
        "duplicate_refs": [item.hex() for item in evaluation.duplicate_refs],
        "graph": {
            reference.hex(): [parent.hex() for parent in evaluation.graph[reference]]
            for reference in sorted(evaluation.graph)
        },
        "ready_sets": [
            [reference.hex() for reference in ready] for ready in evaluation.ready_sets
        ],
        "order": [reference.hex() for reference in evaluation.order],
        "handoffs": handoffs,
    }


class CausalModel:
    """Evaluate one closed context under the C0.2c topology hypothesis."""

    def __init__(
        self,
        *,
        context: Context,
        authorities: Sequence[CredentialAuthority],
        checkpoint: CheckpointEvidence,
        profile: Profile,
    ) -> None:
        profile.validate()
        self.profile = profile
        self._validate_context(context, "model")
        if len(authorities) > profile.max_credentials:
            raise ModelInputError("credential authority bound exceeded")
        if checkpoint.context != context:
            raise ModelInputError("checkpoint context mismatch")
        self._validate_context(checkpoint.context, "checkpoint")
        if checkpoint.proven_refs & checkpoint.stale_refs:
            raise ModelInputError("checkpoint evidence overlaps proven and stale sets")
        checkpoint_ref_count = (
            len(checkpoint.proven_refs)
            + len(checkpoint.stale_refs)
            + len(checkpoint.author_heads)
            + sum(len(authority.revocation_refs) for authority in authorities)
        )
        if checkpoint_ref_count > profile.max_checkpoint_refs:
            raise ModelInputError("checkpoint reference bound exceeded")
        for reference in checkpoint.proven_refs | checkpoint.stale_refs:
            if not self._valid_ref(reference):
                raise ModelInputError("checkpoint reference bounds exceeded")

        authority_map: dict[bytes, CredentialAuthority] = {}
        for authority in authorities:
            if authority.context != context:
                raise ModelInputError("credential authority context mismatch")
            if not self._valid_ref(authority.credential_id):
                raise ModelInputError("credential identifier bounds exceeded")
            if not self._valid_ref(authority.grant_ref):
                raise ModelInputError("credential grant reference bounds exceeded")
            if any(not self._valid_ref(item) for item in authority.revocation_refs):
                raise ModelInputError("credential revocation reference bounds exceeded")
            if authority.credential_id in authority_map:
                raise ModelInputError("duplicate credential authority")
            authority_map[authority.credential_id] = authority
        if not authority_map:
            raise ModelInputError("at least one credential authority is required")

        head_credentials: set[bytes] = set()
        for credential_id, sequence, reference in checkpoint.author_heads:
            if credential_id in head_credentials:
                raise ModelInputError("duplicate checkpoint author head")
            head_credentials.add(credential_id)
            if credential_id not in authority_map:
                raise ModelInputError("checkpoint head has unknown credential")
            if type(sequence) is not int or not 0 <= sequence <= profile.max_sequence:
                raise ModelInputError("checkpoint head sequence bounds exceeded")
            if not self._valid_ref(reference):
                raise ModelInputError("checkpoint head reference bounds exceeded")
            if reference not in checkpoint.proven_refs:
                raise ModelInputError("checkpoint head is not proven")

        self.context = context
        self.authorities = authority_map
        self.checkpoint = checkpoint
        self._static_input_bytes = self._static_input_size(authorities, checkpoint)
        if self._static_input_bytes > profile.max_input_bytes:
            raise ModelInputError("static input byte bound exceeded")

    def evaluate(self, observations: Sequence[Event]) -> Evaluation:
        if len(observations) > self.profile.max_events:
            raise ModelInputError("event observation bound exceeded")
        if any(not isinstance(event, Event) for event in observations):
            raise ModelInputError("observations must contain Event records")
        for event in observations:
            if (
                not isinstance(event.reference, bytes)
                or not isinstance(event.credential_id, bytes)
                or not isinstance(event.causal_parents, tuple)
                or any(not isinstance(parent, bytes) for parent in event.causal_parents)
                or (
                    event.author_predecessor is not None
                    and not isinstance(event.author_predecessor, bytes)
                )
            ):
                raise ModelInputError("event record field types are invalid")
        input_bytes = self._static_input_bytes + sum(
            self._event_input_size(event) for event in observations
        )
        if input_bytes > self.profile.max_input_bytes:
            raise ModelInputError("total input byte bound exceeded")

        events: dict[bytes, Event] = {}
        collisions: set[bytes] = set()
        duplicate_counts: dict[bytes, int] = {}
        for event in observations:
            previous = events.get(event.reference)
            if previous is None:
                events[event.reference] = event
                duplicate_counts[event.reference] = 0
            elif previous == event:
                duplicate_counts[event.reference] += 1
            else:
                collisions.add(event.reference)

        structural: dict[bytes, list[str]] = {
            reference: self._structural_reasons(event)
            for reference, event in events.items()
        }
        for reference in collisions:
            structural[reference].append("REFERENCE_COLLISION")

        cycle_nodes = self._cycle_nodes(events, structural)
        for reference in cycle_nodes:
            structural[reference].append("CYCLE")

        memo: dict[bytes, Decision] = {}
        visiting: set[bytes] = set()

        def decide(reference: bytes) -> Decision:
            cached = memo.get(reference)
            if cached is not None:
                return cached
            if reference in visiting:
                decision = Decision(Status.INVALID, ("CYCLE",))
                memo[reference] = decision
                return decision
            event = events[reference]
            reasons = sorted(set(structural[reference]))
            if reasons:
                decision = Decision(
                    Status.INVALID,
                    tuple(reasons),
                    duplicate_counts[reference],
                )
                memo[reference] = decision
                return decision

            visiting.add(reference)
            dependency_states: list[Status] = []
            dependency_reasons: list[str] = []
            for dependency in event.dependencies:
                target = events.get(dependency)
                if target is not None:
                    if target.context != event.context:
                        dependency_states.append(Status.INVALID)
                        dependency_reasons.append("CROSS_CONTEXT_PARENT")
                        continue
                    target_decision = decide(dependency)
                    dependency_states.append(target_decision.status)
                    if target_decision.status in (Status.INVALID, Status.GAP):
                        dependency_reasons.append("INVALID_PARENT")
                    elif target_decision.status is Status.STALE:
                        dependency_reasons.append("STALE_PARENT")
                    elif target_decision.status is Status.DEFERRED:
                        dependency_reasons.append("DEFERRED_PARENT")
                elif dependency in self.checkpoint.proven_refs:
                    dependency_states.append(Status.ADMITTED)
                elif dependency in self.checkpoint.stale_refs:
                    dependency_states.append(Status.STALE)
                    dependency_reasons.append("STALE_PARENT")
                else:
                    dependency_states.append(Status.DEFERRED)
                    dependency_reasons.append("MISSING_PARENT")

            visiting.remove(reference)
            if Status.INVALID in dependency_states or Status.GAP in dependency_states:
                decision = Decision(
                    Status.INVALID,
                    tuple(sorted(set(dependency_reasons))),
                    duplicate_counts[reference],
                )
            elif Status.STALE in dependency_states:
                decision = Decision(
                    Status.STALE,
                    tuple(sorted(set(dependency_reasons))),
                    duplicate_counts[reference],
                )
            elif Status.DEFERRED in dependency_states:
                decision = Decision(
                    Status.DEFERRED,
                    tuple(sorted(set(dependency_reasons))),
                    duplicate_counts[reference],
                )
            else:
                chain_reason = self._author_chain_reason(event, events)
                if chain_reason is not None:
                    decision = Decision(
                        Status.GAP,
                        (chain_reason,),
                        duplicate_counts[reference],
                    )
                elif not self._has_authority_ancestry(event, events):
                    decision = Decision(
                        Status.INVALID,
                        ("GRANT_ANCESTRY_MISSING",),
                        duplicate_counts[reference],
                    )
                elif self._frontier_is_redundant(event, events):
                    decision = Decision(
                        Status.INVALID,
                        ("PARENT_FRONTIER_NOT_ANTICHAIN",),
                        duplicate_counts[reference],
                    )
                else:
                    decision = Decision(
                        Status.ADMITTED,
                        (),
                        duplicate_counts[reference],
                    )
            memo[reference] = decision
            return decision

        for reference in sorted(events):
            decide(reference)

        self._reject_post_revocation(events, memo)
        self._propagate_invalid_dependencies(events, memo)
        self._mark_forks(events, memo)

        graph = self._admitted_graph(events, memo)
        ready_sets, order = self._topological_order(graph)
        handoffs = tuple(
            self._handoff(
                events[reference],
                events,
                memo,
                graph,
                prior_references=order[:index],
            )
            for index, reference in enumerate(order)
        )
        return Evaluation(
            decisions=dict(sorted(memo.items())),
            duplicate_refs=tuple(
                sorted(reference for reference, count in duplicate_counts.items() if count)
            ),
            graph=graph,
            ready_sets=ready_sets,
            order=order,
            handoffs=handoffs,
        )

    def _valid_ref(self, reference: object) -> bool:
        return (
            isinstance(reference, bytes)
            and 0 < len(reference) <= self.profile.max_reference_bytes
        )

    def _text_size(self, value: object) -> int | None:
        if not isinstance(value, str):
            return None
        try:
            return len(value.encode("utf-8"))
        except UnicodeEncodeError:
            return None

    def _valid_text(self, value: object) -> bool:
        size = self._text_size(value)
        return size is not None and 0 < size <= self.profile.max_text_bytes

    def _validate_context(self, context: object, label: str) -> None:
        if not isinstance(context, Context):
            raise ModelInputError(f"{label} context must be a Context record")
        if not all(
            self._valid_text(value)
            for value in (context.application, context.profile, context.instance)
        ):
            raise ModelInputError(f"{label} context text bounds exceeded")
        if not self._valid_ref(context.genesis_ref):
            raise ModelInputError(f"{label} genesis reference bounds exceeded")

    def _context_input_size(self, context: Context) -> int:
        sizes = (
            self._text_size(context.application),
            self._text_size(context.profile),
            self._text_size(context.instance),
        )
        return sum(size or 0 for size in sizes) + (
            len(context.genesis_ref) if isinstance(context.genesis_ref, bytes) else 0
        )

    def _static_input_size(
        self,
        authorities: Sequence[CredentialAuthority],
        checkpoint: CheckpointEvidence,
    ) -> int:
        total = self._context_input_size(self.context)
        for authority in authorities:
            total += self._context_input_size(authority.context)
            total += len(authority.credential_id) + len(authority.grant_ref)
            total += sum(len(reference) for reference in authority.revocation_refs)
        total += self._context_input_size(checkpoint.context)
        total += sum(len(reference) for reference in checkpoint.proven_refs)
        total += sum(len(reference) for reference in checkpoint.stale_refs)
        for credential_id, _sequence, reference in checkpoint.author_heads:
            total += len(credential_id) + 8 + len(reference)
        return total

    def _event_input_size(self, event: Event) -> int:
        total = self._context_input_size(event.context) if isinstance(event.context, Context) else 0
        total += len(event.reference) if isinstance(event.reference, bytes) else 0
        total += len(event.credential_id) if isinstance(event.credential_id, bytes) else 0
        total += 8
        if isinstance(event.author_predecessor, bytes):
            total += len(event.author_predecessor)
        if isinstance(event.causal_parents, tuple):
            total += sum(len(parent) for parent in event.causal_parents if isinstance(parent, bytes))
        total += self._text_size(event.kind) or 0
        return total

    def _structural_reasons(self, event: Event) -> list[str]:
        reasons: list[str] = []
        if not self._valid_ref(event.reference):
            reasons.append("REFERENCE_BOUNDS")
        if not isinstance(event.context, Context) or not all(
            self._valid_text(value)
            for value in (
                getattr(event.context, "application", None),
                getattr(event.context, "profile", None),
                getattr(event.context, "instance", None),
            )
        ) or not self._valid_ref(getattr(event.context, "genesis_ref", None)):
            reasons.append("CONTEXT_FIELD_BOUNDS")
        if event.context != self.context:
            reasons.append("CONTEXT_MISMATCH")
        authority = self.authorities.get(event.credential_id)
        if authority is None or authority.context != event.context:
            reasons.append("UNAUTHORIZED_CREDENTIAL")
        if type(event.sequence) is not int or not 0 <= event.sequence <= self.profile.max_sequence:
            reasons.append("SEQUENCE_BOUNDS")
        if len(event.causal_parents) > self.profile.max_parents:
            reasons.append("PARENT_COUNT_BOUNDS")
        if event.causal_parents != tuple(sorted(set(event.causal_parents))):
            reasons.append("PARENTS_NOT_CANONICAL")
        if any(not self._valid_ref(parent) for parent in event.causal_parents):
            reasons.append("PARENT_REFERENCE_BOUNDS")
        if event.author_predecessor is not None and not self._valid_ref(event.author_predecessor):
            reasons.append("AUTHOR_PREDECESSOR_BOUNDS")
        if event.sequence == 0 and event.author_predecessor is not None:
            reasons.append("FIRST_EVENT_HAS_PREDECESSOR")
        if event.sequence > 0 and event.author_predecessor is None:
            reasons.append("LATER_EVENT_MISSING_PREDECESSOR")
        if event.reference == event.author_predecessor or event.reference in event.causal_parents:
            reasons.append("SELF_REFERENCE")
        if event.author_predecessor in event.causal_parents:
            reasons.append("AUTHOR_PREDECESSOR_DUPLICATED_AS_PARENT")
        if not self._valid_text(event.kind):
            reasons.append("KIND_INVALID")
        return reasons

    def _cycle_nodes(
        self,
        events: Mapping[bytes, Event],
        structural: Mapping[bytes, Sequence[str]],
    ) -> set[bytes]:
        state: dict[bytes, int] = {}
        stack: list[bytes] = []
        cycle_nodes: set[bytes] = set()

        def visit(reference: bytes) -> None:
            state[reference] = 1
            stack.append(reference)
            for dependency in events[reference].dependencies:
                if dependency not in events or structural[dependency]:
                    continue
                if state.get(dependency, 0) == 0:
                    visit(dependency)
                elif state.get(dependency) == 1:
                    start = stack.index(dependency)
                    cycle_nodes.update(stack[start:])
            stack.pop()
            state[reference] = 2

        for reference in sorted(events):
            if not structural[reference] and state.get(reference, 0) == 0:
                visit(reference)
        return cycle_nodes

    def _author_chain_reason(
        self, event: Event, events: Mapping[bytes, Event]
    ) -> str | None:
        if event.sequence == 0:
            return None
        assert event.author_predecessor is not None
        predecessor = events.get(event.author_predecessor)
        if predecessor is not None:
            if predecessor.credential_id != event.credential_id:
                return "AUTHOR_PREDECESSOR_CREDENTIAL_MISMATCH"
            if predecessor.sequence != event.sequence - 1:
                return "AUTHOR_SEQUENCE_GAP"
            return None
        head = self.checkpoint.author_head(event.credential_id)
        if event.author_predecessor in self.checkpoint.proven_refs:
            if head != (event.sequence - 1, event.author_predecessor):
                return "CHECKPOINT_AUTHOR_HEAD_MISMATCH"
            return None
        return None

    def _has_authority_ancestry(
        self, event: Event, events: Mapping[bytes, Event]
    ) -> bool:
        authority = self.authorities[event.credential_id]
        if event.sequence > 0 and event.author_predecessor is not None:
            head = self.checkpoint.author_head(event.credential_id)
            if head == (event.sequence - 1, event.author_predecessor):
                return event.author_predecessor in self.checkpoint.proven_refs
        return self._has_ancestor(
            event.reference,
            authority.grant_ref,
            events,
            set(),
        )

    def _has_ancestor(
        self,
        reference: bytes,
        ancestor: bytes,
        events: Mapping[bytes, Event],
        seen: set[bytes],
    ) -> bool:
        if reference == ancestor:
            return True
        if reference in seen:
            return False
        seen.add(reference)
        event = events.get(reference)
        if event is None:
            return reference == ancestor and reference in self.checkpoint.proven_refs
        for dependency in event.dependencies:
            if dependency == ancestor:
                return True
            if dependency in events and self._has_ancestor(dependency, ancestor, events, seen):
                return True
        return False

    def _frontier_is_redundant(
        self, event: Event, events: Mapping[bytes, Event]
    ) -> bool:
        parents = event.causal_parents
        for left in parents:
            for right in parents:
                if left == right:
                    continue
                if self._has_ancestor(right, left, events, set()):
                    return True
        return False

    @staticmethod
    def _eligible(decision: Decision) -> bool:
        return decision.status in (Status.ADMITTED, Status.FORK)

    def _reject_post_revocation(
        self, events: Mapping[bytes, Event], decisions: dict[bytes, Decision]
    ) -> None:
        for reference in sorted(events):
            if not self._eligible(decisions[reference]):
                continue
            event = events[reference]
            authority = self.authorities[event.credential_id]
            for revocation in authority.revocation_refs:
                if (
                    revocation in events or revocation in self.checkpoint.proven_refs
                ) and self._has_ancestor(reference, revocation, events, set()):
                    decisions[reference] = Decision(
                        Status.INVALID,
                        ("POST_REVOCATION",),
                        decisions[reference].duplicate_observations,
                    )
                    break

    def _propagate_invalid_dependencies(
        self, events: Mapping[bytes, Event], decisions: dict[bytes, Decision]
    ) -> None:
        changed = True
        while changed:
            changed = False
            for reference in sorted(events):
                if not self._eligible(decisions[reference]):
                    continue
                for dependency in events[reference].dependencies:
                    dependency_decision = decisions.get(dependency)
                    if dependency_decision is not None and not self._eligible(dependency_decision):
                        decisions[reference] = Decision(
                            Status.INVALID,
                            ("INVALID_PARENT",),
                            decisions[reference].duplicate_observations,
                        )
                        changed = True
                        break

    def _mark_forks(
        self, events: Mapping[bytes, Event], decisions: dict[bytes, Decision]
    ) -> None:
        families: list[dict[tuple[object, ...], list[bytes]]] = [{}, {}]
        for reference, event in events.items():
            if not self._eligible(decisions[reference]):
                continue
            families[0].setdefault((event.credential_id, event.sequence), []).append(reference)
            if event.author_predecessor is not None:
                families[1].setdefault(
                    (event.credential_id, event.author_predecessor), []
                ).append(reference)
        peers: dict[bytes, set[bytes]] = {}
        for family in families:
            for references in family.values():
                if len(references) < 2:
                    continue
                for reference in references:
                    peers.setdefault(reference, set()).update(
                        candidate for candidate in references if candidate != reference
                    )
        for reference, candidates in peers.items():
            previous = decisions[reference]
            decisions[reference] = Decision(
                Status.FORK,
                ("AUTHOR_EQUIVOCATION",),
                previous.duplicate_observations,
                tuple(sorted(candidates)),
            )

    def _admitted_graph(
        self, events: Mapping[bytes, Event], decisions: Mapping[bytes, Decision]
    ) -> dict[bytes, tuple[bytes, ...]]:
        admitted = {
            reference for reference, decision in decisions.items() if self._eligible(decision)
        }
        return {
            reference: tuple(
                sorted(dependency for dependency in events[reference].dependencies if dependency in admitted)
            )
            for reference in sorted(admitted)
        }

    @staticmethod
    def _topological_order(
        graph: Mapping[bytes, tuple[bytes, ...]]
    ) -> tuple[tuple[tuple[bytes, ...], ...], tuple[bytes, ...]]:
        remaining = set(graph)
        emitted: set[bytes] = set()
        ready_sets: list[tuple[bytes, ...]] = []
        order: list[bytes] = []
        while remaining:
            ready = tuple(
                sorted(
                    reference
                    for reference in remaining
                    if set(graph[reference]).issubset(emitted)
                )
            )
            if not ready:
                raise ModelInputError("admitted graph is cyclic")
            ready_sets.append(ready)
            selected = ready[0]
            remaining.remove(selected)
            emitted.add(selected)
            order.append(selected)
        return tuple(ready_sets), tuple(order)

    @staticmethod
    def _reachable(
        start: bytes, target: bytes, graph: Mapping[bytes, tuple[bytes, ...]]
    ) -> bool:
        pending = list(graph.get(start, ()))
        seen: set[bytes] = set()
        while pending:
            candidate = pending.pop()
            if candidate == target:
                return True
            if candidate in seen:
                continue
            seen.add(candidate)
            pending.extend(graph.get(candidate, ()))
        return False

    def _relation(
        self,
        left: bytes,
        right: bytes,
        graph: Mapping[bytes, tuple[bytes, ...]],
    ) -> str:
        if left == right:
            return "same"
        if self._reachable(right, left, graph):
            return "before"
        if self._reachable(left, right, graph):
            return "after"
        return "concurrent"

    def _handoff(
        self,
        event: Event,
        events: Mapping[bytes, Event],
        decisions: Mapping[bytes, Decision],
        graph: Mapping[bytes, tuple[bytes, ...]],
        *,
        prior_references: Sequence[bytes],
    ) -> Handoff:
        relations = tuple(
            (other, self._relation(event.reference, other, graph))
            for other in prior_references
        )
        authority = self.authorities[event.credential_id]
        visible = set(prior_references)
        visible_fork_peers = tuple(
            peer for peer in decisions[event.reference].fork_peers if peer in visible
        )
        revocations = tuple(
            (reference, self._relation(event.reference, reference, graph))
            for reference in sorted(authority.revocation_refs)
            if reference in visible
        )
        return Handoff(
            reference=event.reference,
            classification=Status.FORK if visible_fork_peers else Status.ADMITTED,
            context=event.context,
            credential_id=event.credential_id,
            grant_ref=authority.grant_ref,
            sequence=event.sequence,
            kind=event.kind,
            author_predecessor=event.author_predecessor,
            causal_parents=event.causal_parents,
            prior_references=tuple(prior_references),
            causal_relations=relations,
            fork_peers=visible_fork_peers,
            revocation_relations=revocations,
        )


def affected_replay_boundary(
    old_order: Sequence[bytes], new_order: Sequence[bytes]
) -> int:
    """Return the first changed position, or len(old_order) for an exact prefix."""

    for index, (old, new) in enumerate(zip(old_order, new_order)):
        if old != new:
            return index
    return min(len(old_order), len(new_order))


def incremental_handoffs(
    old: Evaluation, new: Evaluation
) -> tuple[int, tuple[Handoff, ...]]:
    """Replay only the affected suffix using the freshly validated new order."""

    boundary = affected_replay_boundary(old.order, new.order)
    fresh_by_reference = {handoff.reference: handoff for handoff in new.handoffs}
    prefix = old.handoffs[:boundary]
    suffix = tuple(fresh_by_reference[reference] for reference in new.order[boundary:])
    return boundary, prefix + suffix


def event_set_fingerprint(events: Iterable[Event]) -> tuple[tuple[object, ...], ...]:
    """Non-cryptographic deterministic identity used only in simulator traces."""

    return tuple(
        sorted(
            (
                event.reference.hex(),
                event.context.application,
                event.context.profile,
                event.context.instance,
                event.context.genesis_ref.hex(),
                event.credential_id.hex(),
                event.sequence,
                _hex(event.author_predecessor),
                tuple(parent.hex() for parent in event.causal_parents),
                event.kind,
            )
            for event in events
        )
    )


def event_trace_fingerprint(events: Iterable[Event]) -> tuple[tuple[object, ...], ...]:
    """Preserve delivery order in a deterministic simulator counterexample."""

    return tuple(
        (
            event.reference.hex(),
            event.context.application,
            event.context.profile,
            event.context.instance,
            event.context.genesis_ref.hex(),
            event.credential_id.hex(),
            event.sequence,
            _hex(event.author_predecessor),
            tuple(parent.hex() for parent in event.causal_parents),
            event.kind,
        )
        for event in events
    )
