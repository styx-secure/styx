"""Bounded executable semantics for the C0.2i pending-subtree construction.

This module is deliberately independent from the historical v1 simulator.  It
models symbolic authentication and commitments; it does not select wire bytes,
cryptographic primitives, production bounds, or stable outcome codes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from itertools import permutations
from typing import Iterable, Mapping, Sequence


MODEL_ID = "styx.pending-subtree-falsification/v2"
SCHEMA_ID = "styx.pending-subtree-report/v2"


class ModelInputError(ValueError):
    """A fail-closed rejection of input outside the bounded model envelope."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class ContentClass(str, Enum):
    NONE = "NONE"
    REQUIRED = "REQUIRED"
    DETACHABLE = "DETACHABLE"


class EventRole(str, Enum):
    ORDINARY = "ORDINARY"
    CONTROL = "CONTROL"


class EventKind(str, Enum):
    ACTION = "ACTION"
    GRANT = "GRANT"
    REVOKE = "REVOKE"
    ROTATE = "ROTATE"
    RECOVER = "RECOVER"
    POLICY = "POLICY"
    CLOSURE = "CLOSURE"
    REMOVE = "REMOVE"


class OpeningObservation(str, Enum):
    OPENING_MISSING = "OPENING_MISSING"
    LENGTH_MISMATCH = "LENGTH_MISMATCH"
    COMMITMENT_MISMATCH = "COMMITMENT_MISMATCH"
    VERIFIED = "VERIFIED"


class Availability(str, Enum):
    ABSENT = "ABSENT"
    PARTIAL = "PARTIAL"
    PRESENT = "PRESENT"


class BindingObservation(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_CHECKED = "NOT_CHECKED"
    VERIFIED = "VERIFIED"
    OPENING_MISSING = "OPENING_MISSING"
    LENGTH_MISMATCH = "LENGTH_MISMATCH"
    COMMITMENT_MISMATCH = "COMMITMENT_MISMATCH"


class AxisPresentation(str, Enum):
    NO_CONTENT = "NO_CONTENT"
    UNEXPECTED_CONTENT_REJECTED = "UNEXPECTED_CONTENT_REJECTED"
    PENDING_OPENING = "PENDING_OPENING"
    ACTIVE_VERIFIED = "ACTIVE_VERIFIED"
    ACTIVE_UNAVAILABLE = "ACTIVE_UNAVAILABLE"
    ACTIVE_UNVERIFIABLE = "ACTIVE_UNVERIFIABLE"
    ACTIVE_SUBSTITUTED_REJECTED = "ACTIVE_SUBSTITUTED_REJECTED"


class Outcome(str, Enum):
    APPLIED = "APPLIED"
    PENDING_OPENING = "PENDING_OPENING"
    PENDING_ANCESTOR = "PENDING_ANCESTOR"
    AUTHENTIC_BUT_UNAUTHORIZED = "AUTHENTIC_BUT_UNAUTHORIZED"
    POST_REVOCATION = "POST_REVOCATION"
    FORK_EVIDENCE = "FORK_EVIDENCE"
    FORK_QUARANTINED = "FORK_QUARANTINED"
    CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED = (
        "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED"
    )
    STRUCTURAL_REJECTION = "STRUCTURAL_REJECTION"
    INVALID = "INVALID"
    DEFERRED = "DEFERRED"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    REMOVAL_INAPPLICABLE = "REMOVAL_INAPPLICABLE"
    ALREADY_REMOVED = "ALREADY_REMOVED"


class PresentationState(str, Enum):
    ACTIVE = "ACTIVE"
    REMOVED_PRESENTED_VERIFIED = "REMOVED_PRESENTED_VERIFIED"
    REMOVED_PRESENTED_UNVERIFIABLE = "REMOVED_PRESENTED_UNVERIFIABLE"
    REMOVED_SUBSTITUTED_REJECTED = "REMOVED_SUBSTITUTED_REJECTED"


CONTROL_KINDS = frozenset(
    {
        EventKind.GRANT,
        EventKind.REVOKE,
        EventKind.ROTATE,
        EventKind.RECOVER,
        EventKind.POLICY,
        EventKind.CLOSURE,
        EventKind.REMOVE,
    }
)


def classify_payload_axis(
    content_class: ContentClass,
    availability: Availability,
    binding: BindingObservation,
) -> AxisPresentation:
    """Classify the closed C0.2f-05 local observation product.

    This is deliberately separate from the application fold: availability and
    presentation are replica-local observations, while only an unverified
    REQUIRED opening can halt application replay in C0.2i.
    """

    if not isinstance(content_class, ContentClass):
        raise ModelInputError("ILLEGAL_AXIS_COMBINATION", "content class is invalid")
    if not isinstance(availability, Availability) or not isinstance(
        binding, BindingObservation
    ):
        raise ModelInputError(
            "ILLEGAL_AXIS_COMBINATION", "payload observation axis type is invalid"
        )

    if content_class is ContentClass.NONE:
        if binding is not BindingObservation.NOT_APPLICABLE or availability not in (
            Availability.ABSENT,
            Availability.PRESENT,
        ):
            raise ModelInputError(
                "ILLEGAL_AXIS_COMBINATION",
                "NONE event has impossible payload observation",
            )
        return (
            AxisPresentation.NO_CONTENT
            if availability is Availability.ABSENT
            else AxisPresentation.UNEXPECTED_CONTENT_REJECTED
        )

    legal = {
        Availability.ABSENT: {BindingObservation.NOT_CHECKED},
        Availability.PARTIAL: {BindingObservation.NOT_CHECKED},
        Availability.PRESENT: {
            BindingObservation.NOT_CHECKED,
            BindingObservation.VERIFIED,
            BindingObservation.OPENING_MISSING,
            BindingObservation.LENGTH_MISMATCH,
            BindingObservation.COMMITMENT_MISMATCH,
        },
    }
    if binding not in legal[availability]:
        raise ModelInputError(
            "ILLEGAL_AXIS_COMBINATION",
            "content-bearing event has impossible payload observation",
        )
    if content_class is ContentClass.REQUIRED and binding is not BindingObservation.VERIFIED:
        return AxisPresentation.PENDING_OPENING
    if binding is BindingObservation.VERIFIED:
        return AxisPresentation.ACTIVE_VERIFIED
    if availability in (Availability.ABSENT, Availability.PARTIAL):
        return AxisPresentation.ACTIVE_UNAVAILABLE
    if binding in (
        BindingObservation.LENGTH_MISMATCH,
        BindingObservation.COMMITMENT_MISMATCH,
    ):
        return AxisPresentation.ACTIVE_SUBSTITUTED_REJECTED
    return AxisPresentation.ACTIVE_UNVERIFIABLE


@dataclass(frozen=True)
class Event:
    """One symbolic signed transcript.

    ``binding_ref`` is ``genesis:<credential_id>`` for the O-07 static
    abstraction, otherwise the reference of the causal-ancestor GRANT that
    binds the signing credential.  Signatures themselves are assumed; this
    field lets the model exercise grant ancestry without inventing a suite.
    """

    reference: str
    context_identifier: str
    credential_id: str
    sequence: int
    direct_predecessor: str | None = None
    parents: tuple[str, ...] = ()
    content_class: ContentClass = ContentClass.NONE
    event_role: EventRole = EventRole.ORDINARY
    kind: EventKind = EventKind.ACTION
    binding_ref: str = ""
    subject_credential: str | None = None
    target_reference: str | None = None
    target_commitment: str | None = None
    descriptor: str = ""
    commitment: str = ""

    def transcript_identity(self) -> tuple[object, ...]:
        return (
            self.reference,
            self.context_identifier,
            self.credential_id,
            self.sequence,
            self.direct_predecessor,
            self.parents,
            self.content_class.value,
            self.event_role.value,
            self.kind.value,
            self.binding_ref,
            self.subject_credential,
            self.target_reference,
            self.target_commitment,
            self.descriptor,
            self.commitment,
        )


@dataclass(frozen=True)
class Scenario:
    events: tuple[Event, ...]
    genesis_authority: tuple[str, ...]
    context_identifier: str = "ctx"
    opening_observations: Mapping[str, OpeningObservation] = field(
        default_factory=dict
    )
    checkpoint_evidence: tuple[str, ...] = ()
    replay_dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class GraphView:
    admitted: tuple[str, ...]
    deferred: tuple[str, ...]
    structurally_rejected: tuple[str, ...]
    invalid: tuple[str, ...]
    canonical_order: tuple[str, ...]
    forks: frozenset[str]
    duplicate_observations: int
    collisions: frozenset[str]
    ancestors: Mapping[str, frozenset[str]]

    def semantic_view(self) -> tuple[object, ...]:
        """Set-relative graph facts; delivery diagnostics are excluded."""

        return (
            self.admitted,
            self.deferred,
            self.structurally_rejected,
            self.invalid,
            self.canonical_order,
            self.forks,
            self.collisions,
            tuple(
                sorted(
                    (reference, tuple(sorted(ancestors)))
                    for reference, ancestors in self.ancestors.items()
                )
            ),
        )


@dataclass(frozen=True)
class WorkMetrics:
    pending_roots: int
    pending_descendants: int
    earliest_replay_boundary: int | None
    replayed_event_work: int


FoldSnapshot = tuple[
    Mapping[str, Outcome],
    tuple[str, ...],
    frozenset[str],
    frozenset[str],
]


@dataclass(frozen=True)
class Projection:
    graph: GraphView
    binding_observations: Mapping[str, OpeningObservation]
    pending_roots: frozenset[str]
    pending: frozenset[str]
    outcomes: Mapping[str, Outcome]
    applied_order: tuple[str, ...]
    authorized_credentials: frozenset[str]
    removed_targets: frozenset[str]
    stale_evidence: bool
    fork_quarantined: bool
    metrics: WorkMetrics
    replay_prefix_states: tuple[FoldSnapshot, ...] = field(
        repr=False,
        compare=False,
    )

    def semantic_view(self) -> tuple[object, ...]:
        """Fields whose equality is asserted by replay/convergence checks."""

        return (
            self.graph.semantic_view(),
            tuple(
                sorted(
                    (key, value.value)
                    for key, value in self.binding_observations.items()
                )
            ),
            self.pending_roots,
            self.pending,
            tuple(sorted((key, value.value) for key, value in self.outcomes.items())),
            self.applied_order,
            self.authorized_credentials,
            self.removed_targets,
            self.stale_evidence,
            self.fork_quarantined,
        )


MAX_EVENTS = 10
MAX_PARENTS = 4
MAX_GENESIS_AUTHORITIES = 4
MAX_TEXT_BYTES = 96
MAX_DELIVERY_PERMUTATIONS = 720
CURRENT_CTX_OCTETS = 44
CURRENT_GEOMETRY_OCTETS = 16
CURRENT_SYMBOLIC_MAX_CHUNK_SIZE = 256
CURRENT_SYMBOLIC_MAX_CHUNKS = 8


def _control_structure_invalid(event: Event) -> bool:
    missing_subject = event.kind in {
        EventKind.GRANT,
        EventKind.REVOKE,
        EventKind.ROTATE,
        EventKind.RECOVER,
    } and not event.subject_credential
    return missing_subject or (
        event.kind in CONTROL_KINDS
        and (
            event.event_role is not EventRole.CONTROL
            or event.content_class is not ContentClass.NONE
        )
    ) or (event.event_role is EventRole.CONTROL and event.kind not in CONTROL_KINDS)


def _bounded_text(value: str, field_name: str) -> None:
    if not value or len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ModelInputError("MODEL_BOUND_EXCEEDED", field_name)


def _bounded_optional_text(value: str | None, field_name: str) -> None:
    if value is not None and len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ModelInputError("MODEL_BOUND_EXCEEDED", field_name)


def _deduplicate(events: Sequence[Event]) -> tuple[dict[str, Event], int]:
    unique: dict[str, Event] = {}
    duplicates = 0
    for event in events:
        _bounded_text(event.reference, "event reference")
        _bounded_text(event.context_identifier, "event context identifier")
        _bounded_text(event.credential_id, "credential identifier")
        _bounded_text(event.binding_ref, "binding reference")
        _bounded_optional_text(event.direct_predecessor, "direct predecessor")
        for parent in event.parents:
            _bounded_text(parent, "parent reference")
        _bounded_optional_text(event.subject_credential, "subject credential")
        _bounded_optional_text(event.target_reference, "target reference")
        _bounded_optional_text(event.target_commitment, "target commitment")
        _bounded_optional_text(event.descriptor, "descriptor")
        _bounded_optional_text(event.commitment, "commitment")
        if event.sequence < 0 or event.sequence > 255:
            raise ModelInputError("MODEL_BOUND_EXCEEDED", "sequence")
        if len(event.parents) > MAX_PARENTS:
            raise ModelInputError("MODEL_BOUND_EXCEEDED", "parent count")
        previous = unique.get(event.reference)
        if previous is None:
            unique[event.reference] = event
        elif previous.transcript_identity() == event.transcript_identity():
            duplicates += 1
        else:
            raise ModelInputError(
                "REFERENCE_COLLISION_UNSUPPORTED",
                f"non-identical transcripts share {event.reference}",
            )
    return unique, duplicates


def _dependencies(event: Event) -> tuple[str, ...]:
    if event.direct_predecessor is None:
        return event.parents
    return (event.direct_predecessor,) + event.parents


def _ancestors_of(reference: str, events: Mapping[str, Event]) -> frozenset[str]:
    found: set[str] = set()
    stack = list(_dependencies(events[reference]))
    while stack:
        parent = stack.pop()
        if parent in found or parent not in events:
            continue
        found.add(parent)
        stack.extend(_dependencies(events[parent]))
    return frozenset(found)


def _binding_is_in_ancestry(
    event: Event,
    admitted: Mapping[str, Event],
    genesis: frozenset[str],
) -> bool:
    if event.credential_id in genesis:
        return event.binding_ref == f"genesis:{event.credential_id}"
    binding = admitted.get(event.binding_ref)
    return bool(
        binding
        and binding.kind is EventKind.GRANT
        and binding.subject_credential == event.credential_id
        and binding.reference in _ancestors_of(event.reference, admitted)
    )


def _canonical_topological_order(events: Mapping[str, Event]) -> tuple[str, ...]:
    indegree = {reference: 0 for reference in events}
    children = {reference: set() for reference in events}
    for event in events.values():
        for parent in _dependencies(event):
            if parent in events:
                indegree[event.reference] += 1
                children[parent].add(event.reference)
    ready = sorted(
        (events[reference] for reference, degree in indegree.items() if degree == 0),
        key=lambda event: event.reference,
    )
    ordered: list[str] = []
    while ready:
        current = ready.pop(0)
        ordered.append(current.reference)
        for child in sorted(children[current.reference]):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(events[child])
                ready.sort(key=lambda event: event.reference)
    if len(ordered) != len(events):
        raise ModelInputError("STRUCTURAL_REJECTION", "causal cycle")
    return tuple(ordered)


def derive_graph(scenario: Scenario) -> tuple[GraphView, Mapping[str, Event]]:
    """Derive K facts without consulting openings or AP authority."""

    if len(scenario.events) > MAX_EVENTS:
        raise ModelInputError("MODEL_BOUND_EXCEEDED", "event count")
    _bounded_text(scenario.context_identifier, "scenario context identifier")
    genesis = frozenset(scenario.genesis_authority)
    if not genesis or len(genesis) > MAX_GENESIS_AUTHORITIES:
        raise ModelInputError("MODEL_BOUND_EXCEEDED", "genesis authority")
    if len(genesis) != len(scenario.genesis_authority):
        raise ModelInputError(
            Outcome.CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED.value,
            "genesis identifier bound more than once",
        )
    for credential in genesis:
        _bounded_text(credential, "genesis credential identifier")
    if len(scenario.opening_observations) > MAX_EVENTS:
        raise ModelInputError("MODEL_BOUND_EXCEEDED", "opening observation count")
    for reference, observation in scenario.opening_observations.items():
        _bounded_text(reference, "opening event reference")
        if not isinstance(observation, OpeningObservation):
            raise ModelInputError(
                "ILLEGAL_AXIS_COMBINATION",
                "opening observation type is invalid",
            )
    if len(scenario.checkpoint_evidence) > MAX_EVENTS:
        raise ModelInputError("MODEL_BOUND_EXCEEDED", "checkpoint evidence count")
    for reference in scenario.checkpoint_evidence:
        _bounded_text(reference, "checkpoint evidence reference")
    if len(scenario.replay_dependencies) > MAX_EVENTS:
        raise ModelInputError("MODEL_BOUND_EXCEEDED", "replay dependency count")
    for reference in scenario.replay_dependencies:
        _bounded_text(reference, "replay dependency reference")
    unique, duplicates = _deduplicate(scenario.events)

    structurally_rejected: set[str] = set()
    for event in unique.values():
        if event.context_identifier != scenario.context_identifier:
            structurally_rejected.add(event.reference)
            continue
        if _control_structure_invalid(event):
            structurally_rejected.add(event.reference)
            continue
        if event.reference in event.parents:
            structurally_rejected.add(event.reference)
            continue
        if event.parents != tuple(sorted(set(event.parents))):
            structurally_rejected.add(event.reference)
            continue
        if event.direct_predecessor in event.parents:
            structurally_rejected.add(event.reference)
            continue
        if (event.sequence == 0) != (event.direct_predecessor is None):
            structurally_rejected.add(event.reference)

    admitted: dict[str, Event] = {}
    invalid: set[str] = set()
    deferred = set(unique) - structurally_rejected
    progress = True
    while progress:
        progress = False
        for reference in sorted(tuple(deferred)):
            event = unique[reference]
            dependencies = _dependencies(event)
            if any(parent in structurally_rejected or parent in invalid for parent in dependencies):
                invalid.add(reference)
                deferred.remove(reference)
                progress = True
                continue
            if any(parent not in admitted for parent in dependencies):
                continue
            if event.direct_predecessor is not None:
                predecessor = admitted[event.direct_predecessor]
                if (
                    predecessor.credential_id != event.credential_id
                    or predecessor.sequence + 1 != event.sequence
                ):
                    structurally_rejected.add(reference)
                    deferred.remove(reference)
                    progress = True
                    continue
            candidate = dict(admitted)
            candidate[reference] = event
            redundant = False
            for left in event.parents:
                for right in event.parents:
                    if left != right and left in _ancestors_of(right, candidate):
                        redundant = True
                        break
                if redundant:
                    break
            if event.direct_predecessor is not None and any(
                parent in _ancestors_of(event.direct_predecessor, candidate)
                for parent in event.parents
            ):
                redundant = True
            if redundant:
                structurally_rejected.add(reference)
                deferred.remove(reference)
                progress = True
                continue
            if not _binding_is_in_ancestry(event, candidate, genesis):
                invalid.add(reference)
                deferred.remove(reference)
                progress = True
                continue
            admitted[reference] = event
            deferred.remove(reference)
            progress = True

    def reaches(start: str, target: str, visiting: set[str]) -> bool:
        if start == target:
            return True
        if start in visiting or start not in unique:
            return False
        visiting.add(start)
        return any(reaches(dep, target, visiting) for dep in _dependencies(unique[start]))

    cyclic = {
        reference
        for reference in deferred
        if any(reaches(dep, reference, set()) for dep in _dependencies(unique[reference]))
    }
    structurally_rejected.update(cyclic)
    deferred.difference_update(cyclic)

    # A present but invalid/rejected dependency is terminal K-invalidity.  Only
    # genuinely absent transcript ancestry remains retriable DEFERRED state.
    progress = True
    while progress:
        progress = False
        for reference in sorted(tuple(deferred)):
            if any(
                parent in structurally_rejected or parent in invalid
                for parent in _dependencies(unique[reference])
            ):
                invalid.add(reference)
                deferred.remove(reference)
                progress = True

    # Parent completeness and symbolic signature ancestry are both K deferral.
    ancestors = {
        reference: _ancestors_of(reference, admitted) for reference in admitted
    }
    order = _canonical_topological_order(admitted)

    by_sequence: dict[tuple[str, int], list[str]] = {}
    for event in admitted.values():
        by_sequence.setdefault((event.credential_id, event.sequence), []).append(
            event.reference
        )
    forks = frozenset(
        reference
        for references in by_sequence.values()
        if len(references) > 1
        for reference in references
    )

    bindings: dict[str, set[str]] = {
        credential: {f"genesis:{credential}"} for credential in genesis
    }
    for event in admitted.values():
        if event.kind is EventKind.GRANT and event.subject_credential:
            bindings.setdefault(event.subject_credential, set()).add(event.reference)
    collisions = frozenset(
        credential for credential, references in bindings.items() if len(references) > 1
    )
    if collisions:
        raise ModelInputError(
            Outcome.CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED.value,
            ",".join(sorted(collisions)),
        )

    return (
        GraphView(
            admitted=tuple(sorted(admitted)),
            deferred=tuple(sorted(deferred)),
            structurally_rejected=tuple(sorted(structurally_rejected)),
            invalid=tuple(sorted(invalid)),
            canonical_order=order,
            forks=forks,
            duplicate_observations=duplicates,
            collisions=collisions,
            ancestors=ancestors,
        ),
        admitted,
    )


def _pending_sets(
    graph: GraphView,
    events: Mapping[str, Event],
    observations: Mapping[str, OpeningObservation],
) -> tuple[frozenset[str], frozenset[str]]:
    roots = frozenset(
        reference
        for reference in graph.admitted
        if events[reference].content_class is ContentClass.REQUIRED
        and not _control_structure_invalid(events[reference])
        and observations.get(reference, OpeningObservation.OPENING_MISSING)
        is not OpeningObservation.VERIFIED
    )
    pending = set(roots)
    changed = True
    while changed:
        changed = False
        for reference in graph.admitted:
            if reference not in pending and any(
                parent in pending for parent in _dependencies(events[reference])
            ):
                pending.add(reference)
                changed = True
    return roots, frozenset(pending)


def _fold_application(
    graph: GraphView,
    events: Mapping[str, Event],
    pending_roots: frozenset[str],
    pending: frozenset[str],
    genesis: Iterable[str],
    stale: bool,
) -> tuple[dict[str, Outcome], tuple[str, ...], frozenset[str], frozenset[str]]:
    outcomes: dict[str, Outcome] = {
        reference: Outcome.DEFERRED for reference in graph.deferred
    }
    outcomes.update(
        {
            reference: Outcome.STRUCTURAL_REJECTION
            for reference in graph.structurally_rejected
        }
    )
    outcomes.update({reference: Outcome.INVALID for reference in graph.invalid})
    if stale:
        outcomes.update(
            {reference: Outcome.STALE_EVIDENCE for reference in graph.admitted}
        )
        return outcomes, (), frozenset(), frozenset()

    if graph.forks:
        outcomes.update(
            {
                reference: (
                    Outcome.FORK_EVIDENCE
                    if reference in graph.forks
                    else Outcome.FORK_QUARANTINED
                )
                for reference in graph.admitted
            }
        )
        return outcomes, (), frozenset(), frozenset()

    authorized = set(genesis)
    revoked: dict[str, set[str]] = {}
    removed: set[str] = set()
    applied: list[str] = []

    for reference in graph.canonical_order:
        event = events[reference]
        if reference in pending_roots:
            outcomes[reference] = Outcome.PENDING_OPENING
            continue
        if reference in pending:
            outcomes[reference] = Outcome.PENDING_ANCESTOR
            continue
        if reference in graph.forks:
            outcomes[reference] = Outcome.FORK_EVIDENCE
            continue
        revocations = revoked.get(event.credential_id, set())
        if any(revocation in graph.ancestors[reference] for revocation in revocations):
            outcomes[reference] = Outcome.POST_REVOCATION
            continue

        actor_authorized = event.credential_id in authorized
        if not actor_authorized:
            outcomes[reference] = Outcome.AUTHENTIC_BUT_UNAUTHORIZED
            continue

        if event.kind is EventKind.GRANT:
            if not event.subject_credential:
                outcomes[reference] = Outcome.STRUCTURAL_REJECTION
                continue
            authorized.add(event.subject_credential)
        elif event.kind is EventKind.REVOKE:
            if not event.subject_credential:
                outcomes[reference] = Outcome.STRUCTURAL_REJECTION
                continue
            authorized.discard(event.subject_credential)
            revoked.setdefault(event.subject_credential, set()).add(reference)
        elif event.kind in (EventKind.ROTATE, EventKind.RECOVER):
            # C0.2i models these as authorized control evidence only.  It does
            # not let them resurrect a revoked identifier; C0.2j owns exact
            # credential succession and grant carriage.
            pass
        elif event.kind is EventKind.REMOVE:
            target = events.get(event.target_reference or "")
            if (
                target is None
                or target.content_class is not ContentClass.DETACHABLE
                or target.reference not in graph.ancestors[reference]
                or (event.target_commitment and event.target_commitment != target.commitment)
            ):
                outcomes[reference] = Outcome.REMOVAL_INAPPLICABLE
                continue
            if target.reference in removed:
                outcomes[reference] = Outcome.ALREADY_REMOVED
                continue
            removed.add(target.reference)

        outcomes[reference] = Outcome.APPLIED
        applied.append(reference)

    return outcomes, tuple(applied), frozenset(authorized), frozenset(removed)


def _fold_application_from_state(
    graph: GraphView,
    events: Mapping[str, Event],
    pending_roots: frozenset[str],
    pending: frozenset[str],
    start_index: int,
    prior_outcomes: Mapping[str, Outcome],
    prior_applied: Sequence[str],
    prior_authorized: Iterable[str],
    prior_removed: Iterable[str],
) -> tuple[dict[str, Outcome], tuple[str, ...], frozenset[str], frozenset[str]]:
    """Continue AP replay from an independently reconstructed prefix state."""

    if graph.forks:
        raise ModelInputError(
            "INCREMENTAL_INPUT_MISMATCH",
            "fork-quarantined projections have no reusable AP prefix",
        )

    outcomes = dict(prior_outcomes)
    applied = list(prior_applied)
    authorized = set(prior_authorized)
    removed = set(prior_removed)
    revoked: dict[str, set[str]] = {}
    for reference in prior_applied:
        event = events[reference]
        if event.kind is EventKind.REVOKE and event.subject_credential:
            revoked.setdefault(event.subject_credential, set()).add(reference)

    for reference in graph.canonical_order[start_index:]:
        event = events[reference]
        if reference in pending_roots:
            outcomes[reference] = Outcome.PENDING_OPENING
            continue
        if reference in pending:
            outcomes[reference] = Outcome.PENDING_ANCESTOR
            continue
        if reference in graph.forks:
            outcomes[reference] = Outcome.FORK_EVIDENCE
            continue
        if any(
            revocation in graph.ancestors[reference]
            for revocation in revoked.get(event.credential_id, set())
        ):
            outcomes[reference] = Outcome.POST_REVOCATION
            continue
        if event.credential_id not in authorized:
            outcomes[reference] = Outcome.AUTHENTIC_BUT_UNAUTHORIZED
            continue

        if event.kind is EventKind.GRANT:
            if not event.subject_credential:
                outcomes[reference] = Outcome.STRUCTURAL_REJECTION
                continue
            authorized.add(event.subject_credential)
        elif event.kind is EventKind.REVOKE:
            if not event.subject_credential:
                outcomes[reference] = Outcome.STRUCTURAL_REJECTION
                continue
            subject = event.subject_credential
            authorized.discard(subject)
            revoked.setdefault(subject, set()).add(reference)
        elif event.kind in (EventKind.ROTATE, EventKind.RECOVER):
            pass
        elif event.kind is EventKind.REMOVE:
            target = events.get(event.target_reference or "")
            if (
                target is None
                or target.content_class is not ContentClass.DETACHABLE
                or target.reference not in graph.ancestors[reference]
                or (
                    event.target_commitment
                    and event.target_commitment != target.commitment
                )
            ):
                outcomes[reference] = Outcome.REMOVAL_INAPPLICABLE
                continue
            if target.reference in removed:
                outcomes[reference] = Outcome.ALREADY_REMOVED
                continue
            removed.add(target.reference)

        outcomes[reference] = Outcome.APPLIED
        applied.append(reference)

    return outcomes, tuple(applied), frozenset(authorized), frozenset(removed)


def project(scenario: Scenario) -> Projection:
    graph, events = derive_graph(scenario)
    roots, pending = _pending_sets(graph, events, scenario.opening_observations)
    binding_observations = {
        reference: scenario.opening_observations.get(
            reference, OpeningObservation.OPENING_MISSING
        )
        for reference in graph.admitted
        if events[reference].content_class is ContentClass.REQUIRED
    }
    checkpoint_only = set(scenario.checkpoint_evidence) - set(graph.admitted)
    stale = bool(checkpoint_only & set(scenario.replay_dependencies))
    # Staleness has outcome precedence, but it must not hide the permanent
    # terminal quarantine fact from presentation or producer-eligibility
    # consumers.  A later recovery from symbolic staleness cannot un-fork the
    # transcript set.
    fork_quarantined = bool(graph.forks)
    replay_prefix_states: tuple[FoldSnapshot, ...]
    if stale or fork_quarantined:
        outcomes, applied, authorized, removed = _fold_application(
            graph,
            events,
            roots,
            pending,
            scenario.genesis_authority,
            stale,
        )
        replay_prefix_states = ()
    else:
        cached_prefixes: list[FoldSnapshot] = []
        for boundary in range(len(graph.canonical_order) + 1):
            prefix_graph = GraphView(
                admitted=graph.admitted,
                deferred=graph.deferred,
                structurally_rejected=graph.structurally_rejected,
                invalid=graph.invalid,
                canonical_order=graph.canonical_order[:boundary],
                forks=graph.forks,
                duplicate_observations=graph.duplicate_observations,
                collisions=graph.collisions,
                ancestors=graph.ancestors,
            )
            cached_prefixes.append(
                _fold_application(
                    prefix_graph,
                    events,
                    roots,
                    pending,
                    scenario.genesis_authority,
                    False,
                )
            )
        replay_prefix_states = tuple(cached_prefixes)
        outcomes, applied, authorized, removed = replay_prefix_states[-1]
    first = min(
        (graph.canonical_order.index(reference) for reference in pending),
        default=None,
    )
    return Projection(
        graph=graph,
        binding_observations=binding_observations,
        pending_roots=roots,
        pending=pending,
        outcomes=outcomes,
        applied_order=applied,
        authorized_credentials=authorized,
        removed_targets=removed,
        stale_evidence=stale,
        fork_quarantined=fork_quarantined,
        metrics=WorkMetrics(
            pending_roots=len(roots),
            pending_descendants=len(pending - roots),
            earliest_replay_boundary=(
                None if stale or fork_quarantined else first
            ),
            replayed_event_work=0,
        ),
        replay_prefix_states=replay_prefix_states,
    )


def incremental_replay(
    prior: Scenario,
    updated: Scenario,
) -> Projection:
    """Replay after monotone opening acquisition and expose bounded work.

    The transcript set must be identical.  This deliberately narrow interface
    exercises the C0.2i opening transition; late transcript admission remains a
    separate set-relative full replay input.
    """

    prior_unique, _ = _deduplicate(prior.events)
    updated_unique, _ = _deduplicate(updated.events)
    if {
        reference: event.transcript_identity()
        for reference, event in prior_unique.items()
    } != {
        reference: event.transcript_identity()
        for reference, event in updated_unique.items()
    }:
        raise ModelInputError("INCREMENTAL_INPUT_MISMATCH", "transcript set changed")
    if (
        prior.context_identifier != updated.context_identifier
        or frozenset(prior.genesis_authority) != frozenset(updated.genesis_authority)
        or frozenset(prior.checkpoint_evidence)
        != frozenset(updated.checkpoint_evidence)
        or frozenset(prior.replay_dependencies)
        != frozenset(updated.replay_dependencies)
    ):
        raise ModelInputError(
            "INCREMENTAL_INPUT_MISMATCH", "non-opening projection input changed"
        )
    before_verified = {
        reference
        for reference, observation in prior.opening_observations.items()
        if observation is OpeningObservation.VERIFIED
    }
    after_verified = {
        reference
        for reference, observation in updated.opening_observations.items()
        if observation is OpeningObservation.VERIFIED
    }
    if not before_verified <= after_verified:
        raise ModelInputError("NON_MONOTONE_OPENING_SET", "verified opening removed")

    graph, events = derive_graph(updated)
    prior_roots, prior_pending = _pending_sets(
        graph, events, prior.opening_observations
    )
    updated_roots, updated_pending = _pending_sets(
        graph, events, updated.opening_observations
    )
    affected = (prior_pending - updated_pending) | (
        prior_roots - updated_roots
    )
    earliest = min(
        (graph.canonical_order.index(reference) for reference in affected),
        default=None,
    )
    checkpoint_only = set(updated.checkpoint_evidence) - set(graph.admitted)
    stale = bool(checkpoint_only & set(updated.replay_dependencies))
    fork_quarantined = bool(graph.forks) and not stale

    # Consume the prefix state cached by the prior full projection, then execute
    # only the updated suffix.  The fresh oracle used by the scenario suite is
    # ``project(updated)`` and no semantic field below is copied from it.
    boundary = len(graph.canonical_order) if earliest is None else earliest
    if stale or fork_quarantined:
        outcomes, applied, authorized, removed = _fold_application(
            graph,
            events,
            updated_roots,
            updated_pending,
            updated.genesis_authority,
            stale,
        )
    else:
        prior_projection = project(prior)
        if not prior_projection.replay_prefix_states:
            raise ModelInputError(
                "INCREMENTAL_INPUT_MISMATCH",
                "prior projection has no reusable prefix state",
            )
        (
            prefix_outcomes,
            prefix_applied,
            prefix_authorized,
            prefix_removed,
        ) = prior_projection.replay_prefix_states[boundary]
        if boundary == len(graph.canonical_order):
            outcomes = prefix_outcomes
            applied = prefix_applied
            authorized = prefix_authorized
            removed = prefix_removed
        else:
            outcomes, applied, authorized, removed = _fold_application_from_state(
                graph,
                events,
                updated_roots,
                updated_pending,
                boundary,
                prefix_outcomes,
                prefix_applied,
                prefix_authorized,
                prefix_removed,
            )

    binding_observations = {
        reference: updated.opening_observations.get(
            reference, OpeningObservation.OPENING_MISSING
        )
        for reference in graph.admitted
        if events[reference].content_class is ContentClass.REQUIRED
    }
    if stale or fork_quarantined:
        earliest = None
    work = 0 if earliest is None else len(graph.canonical_order) - earliest
    return Projection(
        graph=graph,
        binding_observations=binding_observations,
        pending_roots=updated_roots,
        pending=updated_pending,
        outcomes=outcomes,
        applied_order=applied,
        authorized_credentials=authorized,
        removed_targets=removed,
        stale_evidence=stale,
        fork_quarantined=fork_quarantined,
        metrics=WorkMetrics(
            pending_roots=len(updated_roots),
            pending_descendants=len(updated_pending - updated_roots),
            earliest_replay_boundary=earliest,
            replayed_event_work=work,
        ),
        replay_prefix_states=(),
    )


def delivery_orders(events: Sequence[Event]) -> tuple[tuple[Event, ...], ...]:
    """Enumerate deterministic bounded delivery orders for hostile scenarios."""

    count = 1
    for value in range(2, len(events) + 1):
        count *= value
    if count > MAX_DELIVERY_PERMUTATIONS:
        raise ModelInputError("MODEL_BOUND_EXCEEDED", "delivery permutations")
    return tuple(permutations(events))


def frontier_is_producible(scenario: Scenario, frontier: Iterable[str]) -> bool:
    """Future O-11 custody precondition; not a transport implementation."""

    projection = project(scenario)
    frontier_set = frozenset(frontier)
    if not frontier_set or not frontier_set <= set(projection.graph.admitted):
        return False
    if projection.stale_evidence or projection.fork_quarantined:
        return False
    required_history: set[str] = set(frontier_set)
    for reference in frontier_set:
        required_history.update(projection.graph.ancestors[reference])
    return not bool(required_history & projection.pending)


def removed_presentation_state(
    *, removed: bool, observation: OpeningObservation
) -> PresentationState:
    """Keep post-removal presentation distinct from retention authority."""

    if not removed:
        return PresentationState.ACTIVE
    if observation is OpeningObservation.VERIFIED:
        return PresentationState.REMOVED_PRESENTED_VERIFIED
    if observation is OpeningObservation.OPENING_MISSING:
        return PresentationState.REMOVED_PRESENTED_UNVERIFIABLE
    return PresentationState.REMOVED_SUBSTITUTED_REJECTED


def current_profile_symbolic_commitment(
    *,
    context_token: str,
    content_type: str,
    exact_length: int,
    shape: str,
    content_symbol: str,
    opening_randomizer: str,
) -> tuple[object, ...]:
    """Mirror the fields of the frozen 44-octet CTX symbolically.

    Credential identity and author sequence are deliberately not parameters.
    Their absence makes the current copy non-protection executable evidence,
    not an accidental claim that C0.2i repaired it.
    """

    return (
        CURRENT_CTX_OCTETS,
        context_token,
        content_type,
        exact_length,
        shape,
        content_symbol,
        opening_randomizer,
    )


def current_symbolic_geometry_is_legal(
    exact_length: int,
    chunk_size: int,
    chunk_count: int,
    final_chunk_length: int,
) -> bool:
    """The frozen C0.2f symbolic envelope, not production O-08 bounds."""

    if not (
        1 <= chunk_size <= CURRENT_SYMBOLIC_MAX_CHUNK_SIZE
        and 2 <= chunk_count <= CURRENT_SYMBOLIC_MAX_CHUNKS
        and chunk_size < exact_length
        and 1 <= final_chunk_length <= chunk_size
    ):
        return False
    return (
        chunk_count == (exact_length + chunk_size - 1) // chunk_size
        and final_chunk_length == exact_length - chunk_size * (chunk_count - 1)
    )
