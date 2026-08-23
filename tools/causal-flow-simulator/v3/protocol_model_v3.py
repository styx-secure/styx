"""Independent bounded model for Styx C0.2j credential succession.

The model is intentionally symbolic.  It exercises K admission, grant-rooted
credential binding, provenance containment, scoped fork quarantine, and the
bounded Pass0/first-contested-slot authority fold.  It is not a wire implementation,
cryptographic proof, production limit, or stable error taxonomy.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from hashlib import sha256
from itertools import permutations
import json
from typing import Iterable, Mapping, Sequence


MODEL_ID = "styx.credential-succession-falsification/v3"
SCHEMA_ID = "styx.credential-succession-report/v3"
CONTEXT_ID = "63" * 32
GENESIS_DOMAIN = b"STYX\x00\x01\x00\x04" + b"\x00" * 8
EVENT_DOMAIN = b"STYX\x00\x01\x00\x03" + b"\x00" * 8

# Six control events and six independent fork slots require eighteen admitted
# events when each fork slot is witnessed by two ordinary siblings.  The bound
# is therefore joint rather than a set of individually unreachable maxima.
MAX_EVENTS = 18
MAX_CONTROL_EVENTS = 6
MAX_FORK_SLOTS = 6
MAX_PARENTS = 4
MAX_CREDENTIALS = 10
MAX_LINEAGE_DEPTH = 4
MAX_TOPOLOGICAL_ORDERS = 720
MAX_REACHABLE_AUTHORITY_STATES = 65_536
MAX_REACHABLE_AUTHORITY_TRANSITIONS = 524_288
MAX_KEY_OCTETS = 64
MAX_DELIVERY_PERMUTATION_WIDTH = 6
SUITES = frozenset({"0x0001"})


class ModelInputError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class Role(str, Enum):
    ORDINARY = "ORDINARY"
    RETENTION_CONTROL = "RETENTION_CONTROL"
    CREDENTIAL_CONTROL = "CREDENTIAL_CONTROL"


class Kind(str, Enum):
    ACTION = "ACTION"
    GRANT = "GRANT"
    REVOKE = "REVOKE"
    ROTATE = "ROTATE"
    RECOVER = "RECOVER"
    POLICY = "POLICY"
    CLOSURE = "CLOSURE"
    REMOVE = "REMOVE"


class ContentClass(str, Enum):
    NONE = "NONE"
    REQUIRED = "REQUIRED"
    DETACHABLE = "DETACHABLE"


class Outcome(str, Enum):
    APPLIED = "APPLIED"
    PENDING_OPENING = "PENDING_OPENING"
    PENDING_ANCESTOR = "PENDING_ANCESTOR"
    AUTHENTIC_BUT_UNAUTHORIZED = "AUTHENTIC_BUT_UNAUTHORIZED"
    POST_REVOCATION = "POST_REVOCATION"
    FORK_EVIDENCE = "FORK_EVIDENCE"
    LINEAGE_QUARANTINED = "LINEAGE_QUARANTINED"
    STRUCTURAL_REJECTION = "STRUCTURAL_REJECTION"
    UNRESOLVED_CREDENTIAL_BINDING = "UNRESOLVED_CREDENTIAL_BINDING"
    UNRESOLVABLE_CREDENTIAL = "UNRESOLVABLE_CREDENTIAL"
    CREDENTIAL_BINDING_MISMATCH = "CREDENTIAL_BINDING_MISMATCH"
    CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED = (
        "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED"
    )
    REMOVAL_INAPPLICABLE = "REMOVAL_INAPPLICABLE"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    AUTHORITY_PROJECTION_UNAVAILABLE = "AUTHORITY_PROJECTION_UNAVAILABLE"


class AuthorityUnavailableReason(str, Enum):
    STALE_EVIDENCE = "STALE_EVIDENCE"
    REACHABLE_STATE_LIMIT = "REACHABLE_STATE_LIMIT"
    REACHABLE_TRANSITION_LIMIT = "REACHABLE_TRANSITION_LIMIT"


class ReductionStanding(str, Enum):
    GENESIS = "GENESIS"
    ACCEPTED_GRANT = "ACCEPTED_GRANT"
    POSSIBLE_GRANT = "POSSIBLE_GRANT"


class AuthorityVerdict(str, Enum):
    MUST_AUTH = "MUST_AUTH"
    MAY_AUTH = "MAY_AUTH"
    NO_AUTH = "NO_AUTH"


CONTROL_KINDS = frozenset(
    {Kind.GRANT, Kind.REVOKE, Kind.ROTATE, Kind.RECOVER, Kind.POLICY, Kind.CLOSURE}
)
REDUCTION_KINDS = frozenset({Kind.REVOKE, Kind.ROTATE})
EXPANSION_SENSITIVE_KINDS = frozenset(
    {Kind.GRANT, Kind.RECOVER, Kind.POLICY, Kind.CLOSURE}
)


@dataclass(frozen=True)
class Binding:
    credential_id: str
    suite_id: str
    verification_key: str
    issuer_id: str | None
    grant_reference: str
    genesis: bool = False


@dataclass(frozen=True)
class Event:
    name: str
    reference: str
    context_id: str
    actor_id: str
    actor_suite: str
    actor_key: str
    sequence: int
    predecessor: str | None = None
    parents: tuple[str, ...] = ()
    role: Role = Role.ORDINARY
    kind: Kind = Kind.ACTION
    content_class: ContentClass = ContentClass.NONE
    opening_verified: bool = True
    grantee_suite: str | None = None
    grantee_key: str | None = None
    target_id: str | None = None
    target_reference: str | None = None
    declared_subject_id: str | None = None
    malformed_tail: bool = False
    ap_applicable: bool = True

    def semantic_tuple(self) -> tuple[object, ...]:
        return (
            self.name,
            self.context_id,
            self.actor_id,
            self.actor_suite,
            self.actor_key,
            self.sequence,
            self.predecessor,
            self.parents,
            self.role.value,
            self.kind.value,
            self.content_class.value,
            self.opening_verified,
            self.grantee_suite,
            self.grantee_key,
            self.target_id,
            self.target_reference,
            self.declared_subject_id,
            self.malformed_tail,
        )


@dataclass(frozen=True)
class Scenario:
    events: tuple[Event, ...]
    genesis_bindings: tuple[Binding, ...]
    context_id: str = CONTEXT_ID
    checkpoint_references: tuple[str, ...] = ()
    replay_dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class Mutation:
    identifier: str = "NONE"


@dataclass(frozen=True)
class ForkJoin:
    """One virtual authority item for a complete same-sequence fork slot."""

    reference: str
    credential_id: str
    sibling_references: tuple[str, ...]
    closure: frozenset[str]


@dataclass(frozen=True)
class AuthorityState:
    """Sufficient reachable-state key for the non-recursive authority fold.

    ``processed`` determines which causal frontier items are ready.  The other
    three components are exactly the data read by the next authority
    transition.  No accepted-set decision feeds back into this Pass-0 state.
    """

    processed: frozenset[str]
    authority: frozenset[str]
    revoked: frozenset[str]
    forked: frozenset[str]


@dataclass(frozen=True)
class AuthorityAnalysis:
    observations: Mapping[str, frozenset[bool]]
    terminal_authorities: frozenset[frozenset[str]]
    reachable_states: frozenset[AuthorityState]
    complete_paths: int
    transitions: int


@dataclass(frozen=True)
class Projection:
    admitted: tuple[str, ...]
    rejected: Mapping[str, Outcome]
    outcomes: Mapping[str, Outcome]
    bindings: Mapping[str, Binding]
    alias_groups: tuple[tuple[str, ...], ...]
    accepted_controls: frozenset[str]
    reduction_standing: Mapping[str, ReductionStanding]
    event_authority: Mapping[str, AuthorityVerdict]
    possible_terminal_authority: frozenset[str]
    necessary_terminal_authority: frozenset[str]
    terminal_authority: frozenset[str]
    revoked: frozenset[str]
    terminated: frozenset[str]
    forked_credentials: frozenset[str]
    fork_joins: tuple[str, ...]
    pending_roots: frozenset[str]
    pending: frozenset[str]
    stale_evidence: bool
    authority_available: bool
    authority_unavailable_reason: AuthorityUnavailableReason | None
    explored_orders: int
    reachable_authority_states: int
    authority_transitions: int
    replayed_event_work: int
    max_lineage_depth: int

    def semantic_view(self) -> tuple[object, ...]:
        return (
            self.admitted,
            tuple(sorted((key, value.value) for key, value in self.rejected.items())),
            tuple(sorted((key, value.value) for key, value in self.outcomes.items())),
            tuple(
                sorted(
                    (
                        key,
                        value.suite_id,
                        value.verification_key,
                        value.issuer_id,
                        value.grant_reference,
                    )
                    for key, value in self.bindings.items()
                )
            ),
            tuple(
                sorted(
                    (reference, verdict.value)
                    for reference, verdict in self.event_authority.items()
                )
            ),
            self.alias_groups,
            self.accepted_controls,
            tuple(
                sorted(
                    (reference, standing.value)
                    for reference, standing in self.reduction_standing.items()
                )
            ),
            self.possible_terminal_authority,
            self.necessary_terminal_authority,
            self.terminal_authority,
            self.revoked,
            self.terminated,
            self.forked_credentials,
            self.fork_joins,
            self.pending_roots,
            self.pending,
            self.stale_evidence,
            self.authority_available,
            (
                self.authority_unavailable_reason.value
                if self.authority_unavailable_reason is not None
                else None
            ),
        )


def _frame(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def derive_genesis_credential_id(
    context_id: str, suite_id: str, verification_key: str
) -> str:
    body = _frame(bytes.fromhex(context_id)) + _frame(suite_id.encode()) + _frame(
        bytes.fromhex(verification_key)
    )
    return sha256(GENESIS_DOMAIN + _frame(body)).hexdigest()


def event_preimage(event: Event, mutation: Mutation = Mutation()) -> bytes:
    fields: list[bytes] = [
        event.name.encode(),
        bytes.fromhex(event.context_id),
        event.actor_id.encode(),
        event.actor_suite.encode(),
        bytes.fromhex(event.actor_key),
        event.sequence.to_bytes(8, "big"),
        (event.predecessor or "").encode(),
        b"\x00".join(parent.encode() for parent in event.parents),
        event.role.value.encode(),
        event.kind.value.encode(),
        event.content_class.value.encode(),
        (event.grantee_suite or "").encode(),
        bytes.fromhex(event.grantee_key or ""),
        (event.target_id or "").encode(),
        (event.target_reference or "").encode(),
    ]
    if mutation.identifier == "M01_IDENTIFIER_OMITS_CONTEXT":
        fields[1] = b""
    if mutation.identifier == "M02_IDENTIFIER_OMITS_ALGORITHM":
        fields[3] = b""
        fields[11] = b""
    if mutation.identifier == "M03_IDENTIFIER_OMITS_ISSUER":
        fields[2] = b""
    return b"".join(_frame(value) for value in fields)


def derive_event_reference(event: Event, mutation: Mutation = Mutation()) -> str:
    preimage = event_preimage(event, mutation)
    return sha256(EVENT_DOMAIN + _frame(preimage)).hexdigest()


def credential_domains_are_separated(mutation: Mutation = Mutation()) -> bool:
    """Expose the domain-separation invariant to the hostile model suite."""

    if mutation.identifier == "M21_GENESIS_USES_EVENT_DOMAIN":
        return False
    return GENESIS_DOMAIN != EVENT_DOMAIN


def make_event(
    name: str,
    actor: Binding,
    *,
    context_id: str = CONTEXT_ID,
    sequence: int = 0,
    predecessor: str | None = None,
    parents: Iterable[str] = (),
    role: Role = Role.ORDINARY,
    kind: Kind = Kind.ACTION,
    content_class: ContentClass = ContentClass.NONE,
    opening_verified: bool = True,
    grantee_suite: str | None = None,
    grantee_key: str | None = None,
    target_id: str | None = None,
    target_reference: str | None = None,
    declared_subject_id: str | None = None,
    malformed_tail: bool = False,
    ap_applicable: bool = True,
    forced_reference: str | None = None,
    claimed_actor_suite: str | None = None,
    claimed_actor_key: str | None = None,
    mutation: Mutation = Mutation(),
) -> Event:
    candidate = Event(
        name=name,
        reference="",
        context_id=context_id,
        actor_id=actor.credential_id,
        actor_suite=claimed_actor_suite or actor.suite_id,
        actor_key=claimed_actor_key or actor.verification_key,
        sequence=sequence,
        predecessor=predecessor,
        parents=tuple(sorted(parents)),
        role=role,
        kind=kind,
        content_class=content_class,
        opening_verified=opening_verified,
        grantee_suite=grantee_suite,
        grantee_key=grantee_key,
        target_id=target_id,
        target_reference=target_reference,
        declared_subject_id=declared_subject_id,
        malformed_tail=malformed_tail,
        ap_applicable=ap_applicable,
    )
    return replace(
        candidate,
        reference=forced_reference or derive_event_reference(candidate, mutation),
    )


def grant_binding(event: Event) -> Binding:
    if event.kind is not Kind.GRANT:
        raise ModelInputError("NOT_A_GRANT", event.name)
    return Binding(
        credential_id=event.reference,
        suite_id=event.grantee_suite or "",
        verification_key=event.grantee_key or "",
        issuer_id=event.actor_id,
        grant_reference=event.reference,
    )


def _validate_envelope(scenario: Scenario) -> None:
    if len(scenario.events) > MAX_EVENTS:
        raise ModelInputError("MODEL_BOUND_EXCEEDED", "event count")
    if len(scenario.genesis_bindings) > MAX_CREDENTIALS:
        raise ModelInputError("MODEL_BOUND_EXCEEDED", "genesis credentials")
    for event in scenario.events:
        if len(event.parents) > MAX_PARENTS:
            raise ModelInputError("MODEL_BOUND_EXCEEDED", "parent count")
        if event.sequence < 0 or event.sequence >= 2**64:
            raise ModelInputError("MODEL_BOUND_EXCEEDED", "sequence")
        for key in (event.actor_key, event.grantee_key or ""):
            if len(bytes.fromhex(key)) > MAX_KEY_OCTETS:
                raise ModelInputError("MODEL_BOUND_EXCEEDED", "key length")


def _dependencies(event: Event) -> frozenset[str]:
    values = set(event.parents)
    if event.predecessor:
        values.add(event.predecessor)
    if event.kind in {Kind.ROTATE, Kind.RECOVER} and event.target_reference:
        values.add(event.target_reference)
    return frozenset(values)


def _causal_ancestors(events: Sequence[Event]) -> Mapping[str, frozenset[str]]:
    """Return transitive O-01 ancestry over parents and direct predecessors.

    Semantic references such as a ROTATE replacement are deliberately excluded:
    the transcript profile requires those references to occur in ``parents`` when
    they are causal. Missing references remain admission failures rather than
    invented graph vertices.
    """

    by_reference = {event.reference: event for event in events}
    ancestors: dict[str, set[str]] = {
        event.reference: {
            reference
            for reference in (*event.parents, event.predecessor)
            if reference is not None and reference in by_reference
        }
        for event in events
    }
    changed = True
    while changed:
        changed = False
        for reference, values in ancestors.items():
            expanded = set(values)
            for dependency in values:
                expanded.update(ancestors.get(dependency, ()))
            if reference in expanded:
                raise ModelInputError("CYCLIC_CAUSAL_EVIDENCE", reference)
            if expanded != values:
                ancestors[reference] = expanded
                changed = True
    return {reference: frozenset(values) for reference, values in ancestors.items()}


def _valid_author_chain(
    event: Event,
    raw_by_reference: Mapping[str, Event],
    ancestors: Mapping[str, frozenset[str]],
    genesis_ids: frozenset[str],
    mutation: Mutation,
) -> bool:
    """Enforce O-01 sequence continuity and causal binding availability."""

    if tuple(sorted(set(event.parents))) != event.parents:
        return False
    if event.reference in event.parents or event.predecessor in event.parents:
        return False
    for index, left in enumerate(event.parents):
        for right in event.parents[index + 1 :]:
            if left in ancestors.get(right, ()) or right in ancestors.get(left, ()):
                return False
    if event.predecessor is not None and any(
        parent in ancestors.get(event.predecessor, ()) for parent in event.parents
    ):
        return False
    if mutation.identifier != "M28_NO_AUTHOR_CONTINUITY":
        if event.sequence == 0 and event.predecessor is not None:
            return False
        if event.sequence > 0 and event.predecessor is None:
            return False
        if event.predecessor is not None:
            predecessor = raw_by_reference.get(event.predecessor)
            if (
                predecessor is None
                or predecessor.actor_id != event.actor_id
                or predecessor.sequence + 1 != event.sequence
            ):
                return False
    if event.actor_id not in genesis_ids:
        return event.actor_id in ancestors.get(event.reference, frozenset())
    return True


def _valid_control_tail(
    event: Event, admitted: Mapping[str, Event], mutation: Mutation
) -> bool:
    """Validate the closed CREDENTIAL_CONTROL tail before AP evaluation.

    `target_reference` names the fresh binding GRANT for ROTATE/RECOVER.  It is
    deliberately not a binding source: only that referenced GRANT can create
    the replacement credential record.
    """

    if event.kind is Kind.GRANT:
        return (
            event.declared_subject_id is None
            and (
                event.target_id is None
                or mutation.identifier == "M19_REGRANT_REVOKED_IDENTIFIER"
            )
            and event.target_reference is None
            and event.grantee_suite in SUITES
            and (
                bool(event.grantee_key)
                or mutation.identifier == "M18_AP_BYTES_AS_K_BINDING"
            )
        )
    if event.kind is Kind.REVOKE:
        return (
            event.target_id is not None
            and event.target_reference is None
            and event.grantee_suite is None
            and event.grantee_key is None
        )
    if event.kind in {Kind.ROTATE, Kind.RECOVER}:
        replacement = admitted.get(event.target_reference or "")
        return (
            event.target_id is not None
            and replacement is not None
            and replacement.kind is Kind.GRANT
            and replacement.role is Role.CREDENTIAL_CONTROL
            and (
                replacement.reference == event.predecessor
                or replacement.reference in event.parents
            )
            and event.grantee_suite is None
            and event.grantee_key is None
        )
    if event.kind in {Kind.POLICY, Kind.CLOSURE}:
        return (
            event.target_id is None
            and event.target_reference is None
            and event.grantee_suite is None
            and event.grantee_key is None
        )
    return False


def _fork_joins(
    admitted: Mapping[str, Event],
    ancestors: Mapping[str, frozenset[str]],
    mutation: Mutation,
) -> tuple[tuple[ForkJoin, ...], frozenset[str], frozenset[str]]:
    """Construct one bounded causal join for every same-sequence fork slot.

    The author-chain rules make the earliest divergence a same-predecessor pair;
    later same-sequence events can have different predecessors only below an
    already forked lineage.  One slot join therefore carries the complete sibling
    set without quadratic pairwise authority items.
    """

    slots: dict[tuple[str, int], list[str]] = {}
    for event in admitted.values():
        slot = (event.actor_id, event.sequence)
        slots.setdefault(slot, []).append(event.reference)

    joins: list[ForkJoin] = []
    forked: set[str] = set()
    fork_events: set[str] = set()
    for slot, references in sorted(slots.items(), key=lambda item: repr(item[0])):
        credential_id = str(slot[0])
        sequence = int(slot[1])
        ordered = sorted(set(references))
        if len(ordered) < 2:
            continue
        forked.add(credential_id)
        fork_events.update(ordered)
        closure: set[str] = set(ordered)
        for reference in ordered:
            closure.update(ancestors.get(reference, frozenset()))
        joins.append(
            ForkJoin(
                reference=(
                    f"fork:{credential_id}:{sequence}:{':'.join(ordered)}"
                ),
                credential_id=credential_id,
                sibling_references=tuple(ordered),
                closure=frozenset(closure),
            )
        )
    return (
        tuple(sorted(joins, key=lambda item: item.reference)),
        frozenset(forked),
        frozenset(fork_events),
    )


def _topological_orders(
    events: Sequence[Event],
    joins: Sequence[ForkJoin],
    ancestors: Mapping[str, frozenset[str]],
    mutation: Mutation,
) -> tuple[tuple[Event | ForkJoin, ...], ...]:
    items: tuple[Event | ForkJoin, ...] = tuple(events) + tuple(joins)
    if sum(event.role is Role.CREDENTIAL_CONTROL for event in events) > MAX_CONTROL_EVENTS:
        raise ModelInputError("AUTHORITY_BOUND_EXCEEDED", "control event count")
    if len(joins) > MAX_FORK_SLOTS:
        raise ModelInputError("AUTHORITY_BOUND_EXCEEDED", "fork slot count")
    predecessors = _authority_predecessors(events, joins, ancestors, mutation)

    by_reference: dict[str, Event | ForkJoin] = {
        item.reference: item for item in items
    }
    orders: list[tuple[Event | ForkJoin, ...]] = []

    def visit(prefix: tuple[Event | ForkJoin, ...], remaining: frozenset[str]) -> None:
        ready = sorted(
            reference
            for reference in remaining
            if predecessors[reference].isdisjoint(remaining)
        )
        if not ready:
            if not remaining:
                orders.append(prefix)
                if len(orders) > MAX_TOPOLOGICAL_ORDERS:
                    raise ModelInputError(
                        "AUTHORITY_BOUND_EXCEEDED", "order count"
                    )
            return
        for reference in ready:
            visit(prefix + (by_reference[reference],), remaining - {reference})

    visit((), frozenset(by_reference))
    if not orders:
        raise ModelInputError("CYCLIC_CONTROL_EVIDENCE", "no topological order")
    return tuple(orders)


def _authority_predecessors(
    events: Sequence[Event],
    joins: Sequence[ForkJoin],
    ancestors: Mapping[str, frozenset[str]],
    mutation: Mutation,
) -> Mapping[str, frozenset[str]]:
    """Build the common partial order used by both DP and test oracle."""

    controls_by_reference = {event.reference: event for event in events}
    predecessors: dict[str, set[str]] = {}
    for event in events:
        required = set(
            _dependencies(event)
            if mutation.identifier == "M26_DIRECT_DEPENDENCIES_ONLY"
            else ancestors.get(event.reference, frozenset())
        ) & set(controls_by_reference)
        for join in joins:
            if set(join.sibling_references) <= set(
                ancestors.get(event.reference, frozenset())
            ):
                required.add(join.reference)
            if (
                mutation.identifier == "M32_FORK_JOIN_BEFORE_SIBLINGS"
                and event.reference in set(join.sibling_references)
            ):
                required.add(join.reference)
        predecessors[event.reference] = required
    for join in joins:
        required = set(join.closure) & set(controls_by_reference)
        if mutation.identifier == "M32_FORK_JOIN_BEFORE_SIBLINGS":
            required -= set(join.sibling_references)
        for other in joins:
            if (
                other.reference != join.reference
                and set(other.sibling_references) <= join.closure
            ):
                required.add(other.reference)
        predecessors[join.reference] = required
    return {
        reference: frozenset(required)
        for reference, required in predecessors.items()
    }


def _single_topological_order(
    events: Sequence[Event],
    joins: Sequence[ForkJoin],
    ancestors: Mapping[str, frozenset[str]],
    mutation: Mutation,
) -> tuple[Event | ForkJoin, ...]:
    """Deterministic greedy linearization used only by the M08 mutant."""

    items: dict[str, Event | ForkJoin] = {
        item.reference: item for item in (*events, *joins)
    }
    predecessors = _authority_predecessors(events, joins, ancestors, mutation)
    processed: set[str] = set()
    order: list[Event | ForkJoin] = []
    while len(processed) < len(items):
        ready = sorted(
            reference
            for reference in items
            if reference not in processed
            and predecessors[reference] <= processed
        )
        if not ready:
            raise ModelInputError("CYCLIC_CONTROL_EVIDENCE", "no topological order")
        selected = ready[0]
        processed.add(selected)
        order.append(items[selected])
    return tuple(order)


def _lineage_descendants(
    bindings: Mapping[str, Binding], roots: Iterable[str]
) -> frozenset[str]:
    terminated = set(roots)
    changed = True
    while changed:
        changed = False
        for credential_id, binding in bindings.items():
            if binding.issuer_id in terminated and credential_id not in terminated:
                terminated.add(credential_id)
                changed = True
    return frozenset(terminated)


def _lineage_depth(bindings: Mapping[str, Binding], credential_id: str) -> int:
    seen: set[str] = set()
    cursor = credential_id
    depth = 0
    while cursor in bindings and bindings[cursor].issuer_id is not None:
        if cursor in seen:
            raise ModelInputError("LINEAGE_CYCLE", credential_id)
        seen.add(cursor)
        depth += 1
        if depth > MAX_LINEAGE_DEPTH:
            raise ModelInputError("LINEAGE_BOUND_EXCEEDED", credential_id)
        cursor = bindings[cursor].issuer_id or ""
    return depth


def _simulate_order(
    order: Sequence[Event | ForkJoin],
    genesis_authority: frozenset[str],
    bindings: Mapping[str, Binding],
    mutation: Mutation,
) -> tuple[Mapping[str, bool], frozenset[str]]:
    authority = set(genesis_authority)
    actor_authorized: dict[str, bool] = {}
    revoked: set[str] = set()
    forked: set[str] = set()
    globally_forked = {
        item.credential_id for item in order if isinstance(item, ForkJoin)
    }
    if mutation.identifier == "M27_GLOBAL_FORK_TERMINATION":
        forked.update(globally_forked)
    for item in order:
        if isinstance(item, ForkJoin):
            forked.add(item.credential_id)
            authority -= set(_lineage_descendants(bindings, {item.credential_id}))
            continue
        event = item
        terminated = _lineage_descendants(bindings, revoked | forked)
        actor_ok = event.actor_id in authority and event.actor_id not in terminated
        if mutation.identifier == "M24_REVOKED_REDUCTION_ACCEPTED" and event.kind in REDUCTION_KINDS:
            actor_ok = True
        actor_authorized[event.reference] = actor_ok
        if not actor_ok:
            continue
        if event.kind is Kind.GRANT:
            authority.add(event.reference)
        elif event.kind in REDUCTION_KINDS and event.target_id:
            revoked.add(event.target_id)
            authority -= set(_lineage_descendants(bindings, {event.target_id}))
    return actor_authorized, frozenset(authority)


def _advance_authority_state(
    state: AuthorityState,
    item: Event | ForkJoin,
    bindings: Mapping[str, Binding],
    mutation: Mutation,
) -> tuple[AuthorityState, bool | None]:
    """Apply one Pass-0 transition without consulting accepted controls."""

    authority = set(state.authority)
    revoked = set(state.revoked)
    forked = set(state.forked)
    if isinstance(item, ForkJoin):
        forked.add(item.credential_id)
        authority -= set(_lineage_descendants(bindings, {item.credential_id}))
        return (
            AuthorityState(
                processed=state.processed | {item.reference},
                authority=frozenset(authority),
                revoked=frozenset(revoked),
                forked=frozenset(forked),
            ),
            None,
        )

    terminated = _lineage_descendants(bindings, revoked | forked)
    actor_ok = item.actor_id in authority and item.actor_id not in terminated
    if (
        mutation.identifier == "M24_REVOKED_REDUCTION_ACCEPTED"
        and item.kind in REDUCTION_KINDS
    ):
        actor_ok = True
    if actor_ok:
        if item.kind is Kind.GRANT:
            authority.add(item.reference)
        elif item.kind in REDUCTION_KINDS and item.target_id:
            revoked.add(item.target_id)
            authority -= set(_lineage_descendants(bindings, {item.target_id}))
    if (
        mutation.identifier == "M47_STATE_KEY_OMITS_AUTHORITY"
        and isinstance(item, Event)
        and item.kind in REDUCTION_KINDS
    ):
        authority = set(state.authority)
    return (
        AuthorityState(
            processed=state.processed | {item.reference},
            authority=frozenset(authority),
            revoked=frozenset(revoked),
            forked=frozenset(forked),
        ),
        actor_ok,
    )


def _reachable_authority_states(
    events: Sequence[Event],
    joins: Sequence[ForkJoin],
    bindings: Mapping[str, Binding],
    genesis_authority: frozenset[str],
    ancestors: Mapping[str, frozenset[str]],
    mutation: Mutation,
    state_limit: int,
    transition_limit: int,
) -> AuthorityAnalysis:
    """Explore the finite authority machine while merging equivalent states.

    The factorial oracle enumerates histories.  This production model instead
    expands each sufficient state key once per frontier depth and carries path
    multiplicities only as diagnostics.  Observations are unioned across all
    incoming paths, so May0/Must0 remain exact.
    """

    if len(events) > MAX_CONTROL_EVENTS:
        raise ModelInputError("AUTHORITY_BOUND_EXCEEDED", "control event count")
    if len(joins) > MAX_FORK_SLOTS:
        raise ModelInputError("AUTHORITY_BOUND_EXCEEDED", "fork slot count")
    items: dict[str, Event | ForkJoin] = {
        item.reference: item for item in (*events, *joins)
    }
    predecessors = _authority_predecessors(events, joins, ancestors, mutation)
    initially_forked = (
        frozenset(join.credential_id for join in joins)
        if mutation.identifier == "M27_GLOBAL_FORK_TERMINATION"
        else frozenset()
    )
    initial = AuthorityState(
        processed=frozenset(),
        authority=genesis_authority,
        revoked=frozenset(),
        forked=initially_forked,
    )
    frontier: dict[AuthorityState, int] = {initial: 1}
    reachable: set[AuthorityState] = {initial}
    observations: dict[str, set[bool]] = {
        event.reference: set() for event in events
    }
    transitions = 0

    for _ in range(len(items)):
        next_frontier: dict[AuthorityState, int] = {}
        for state, path_count in frontier.items():
            ready = sorted(
                reference
                for reference in items
                if reference not in state.processed
                and predecessors[reference] <= state.processed
            )
            for reference in ready:
                transitions += 1
                if transitions > transition_limit:
                    raise ModelInputError(
                        "AUTHORITY_BOUND_EXCEEDED", "reachable transition count"
                    )
                successor, actor_ok = _advance_authority_state(
                    state, items[reference], bindings, mutation
                )
                if actor_ok is not None:
                    observations[reference].add(actor_ok)
                next_frontier[successor] = (
                    next_frontier.get(successor, 0) + path_count
                )
        if not next_frontier:
            raise ModelInputError("CYCLIC_CONTROL_EVIDENCE", "no reachable state")
        reachable.update(next_frontier)
        if len(reachable) > state_limit:
            raise ModelInputError(
                "AUTHORITY_BOUND_EXCEEDED", "reachable state count"
            )
        frontier = next_frontier

    if not all(len(state.processed) == len(items) for state in frontier):
        raise ModelInputError("CYCLIC_CONTROL_EVIDENCE", "incomplete authority fold")
    return AuthorityAnalysis(
        observations={
            reference: frozenset(values)
            for reference, values in observations.items()
        },
        terminal_authorities=frozenset(state.authority for state in frontier),
        reachable_states=frozenset(reachable),
        complete_paths=sum(frontier.values()),
        transitions=transitions,
    )


def _oracle_authority_analysis(
    events: Sequence[Event],
    joins: Sequence[ForkJoin],
    bindings: Mapping[str, Binding],
    genesis_authority: frozenset[str],
    ancestors: Mapping[str, frozenset[str]],
    mutation: Mutation,
) -> AuthorityAnalysis:
    """Factorial test oracle retained only for bounded DP equivalence tests."""

    orders = _topological_orders(events, joins, ancestors, mutation)
    observations: dict[str, set[bool]] = {
        event.reference: set() for event in events
    }
    terminals: set[frozenset[str]] = set()
    for order in orders:
        actors, terminal = _simulate_order(
            order, genesis_authority, bindings, mutation
        )
        terminals.add(terminal)
        for reference, authorized in actors.items():
            observations[reference].add(authorized)
    return AuthorityAnalysis(
        observations={
            reference: frozenset(values)
            for reference, values in observations.items()
        },
        terminal_authorities=frozenset(terminals),
        reachable_states=frozenset(),
        complete_paths=len(orders),
        transitions=0,
    )


def _authority_fold(
    controls: Sequence[Event],
    joins: Sequence[ForkJoin],
    bindings: Mapping[str, Binding],
    genesis_authority: frozenset[str],
    forked: frozenset[str],
    ancestors: Mapping[str, frozenset[str]],
    mutation: Mutation,
    engine: str,
    state_limit: int,
    transition_limit: int,
) -> tuple[
    frozenset[str],
    Mapping[str, ReductionStanding],
    Mapping[str, AuthorityVerdict],
    frozenset[str],
    frozenset[str],
    frozenset[str],
    frozenset[str],
    int,
    int,
    int,
]:
    evidence = tuple(
        event
        for event in controls
        if not (
            mutation.identifier == "M20_FILTER_EVIDENCE_BY_AP_STATE"
            and not event.ap_applicable
        )
    )
    if engine == "dp" and mutation.identifier != "M45_ORDER_COUNT_IS_GATE":
        analysis = _reachable_authority_states(
            evidence,
            joins,
            bindings,
            genesis_authority,
            ancestors,
            mutation,
            state_limit,
            transition_limit,
        )
    elif engine == "oracle" or mutation.identifier == "M45_ORDER_COUNT_IS_GATE":
        analysis = _oracle_authority_analysis(
            evidence, joins, bindings, genesis_authority, ancestors, mutation
        )
    else:
        raise ModelInputError("UNKNOWN_AUTHORITY_ENGINE", engine)
    observations = analysis.observations

    may_events = {
        reference for reference, values in observations.items() if True in values
    }
    must_events = {
        reference
        for reference, values in observations.items()
        if values == frozenset({True})
    }
    accepted: set[str] = set()
    for event in evidence:
        if mutation.identifier == "M04_POSSESSION_IMPLIES_AUTHORITY":
            accepted.add(event.reference)
        elif event.kind in REDUCTION_KINDS:
            required = (
                must_events
                if mutation.identifier == "M06_REDUCTION_REQUIRES_MUST"
                else may_events
            )
            if event.reference in required:
                accepted.add(event.reference)
        else:
            required = (
                may_events
                if mutation.identifier == "M05_EXPANSION_USES_MAY"
                else must_events
            )
            if event.reference in required:
                accepted.add(event.reference)

    # A May0-only reduction receives no general destructive privilege.  The
    # bounded v0 exception is one first eligible author-sequence slot per actor;
    # every eligible sibling in that selected slot applies as an unordered set.
    may_only = may_events - must_events
    contested_by_actor: dict[str, list[Event]] = {}
    for event in evidence:
        if event.reference not in may_only or event.kind not in REDUCTION_KINDS:
            continue
        if (
            event.target_id is None
            or event.actor_id
            in _lineage_descendants(bindings, {event.target_id})
        ) and mutation.identifier != "M42_SELF_LINEAGE_MAY_ACCEPTED":
            accepted.discard(event.reference)
            continue
        contested_by_actor.setdefault(event.actor_id, []).append(event)
    for actor_events in contested_by_actor.values():
        selected_sequence = min(event.sequence for event in actor_events)
        selected_reference = min(event.reference for event in actor_events)
        for event in actor_events:
            selected = (
                event.reference == selected_reference
                if mutation.identifier == "M40_GRINDABLE_CONTESTED_SELECTOR"
                else event.sequence == selected_sequence
            )
            if selected:
                if mutation.identifier != "M06_REDUCTION_REQUIRES_MUST":
                    accepted.add(event.reference)
            else:
                accepted.discard(event.reference)
    if mutation.identifier == "M34_UNBOUNDED_CONTESTED_REDUCTIONS":
        accepted.update(
            event.reference
            for event in evidence
            if event.reference in may_only and event.kind in REDUCTION_KINDS
        )
    if mutation.identifier == "M39_CROSS_LINEAGE_CANONICAL_WINNER":
        contested = sorted(
            event.reference
            for event in evidence
            if event.reference in may_only and event.kind in REDUCTION_KINDS
        )
        accepted -= set(contested[1:])
    if mutation.identifier == "M38_STANDING_FIXED_POINT_SEED":
        accepted -= may_only
    if mutation.identifier == "M41_TERMINATED_DESCENDANT_FRESH_STANDING":
        accepted.update(
            event.reference
            for event in evidence
            if event.kind in REDUCTION_KINDS
            and event.reference not in may_events
            and not bindings[event.actor_id].genesis
        )

    if mutation.identifier == "M07_IGNORE_MAY_REDUCTION":
        accepted = {
            reference
            for reference in accepted
            if (
                (event := next(item for item in evidence if item.reference == reference)).kind
                not in REDUCTION_KINDS
                or bindings[event.actor_id].genesis
                or bindings[event.actor_id].grant_reference in accepted
            )
        }

    if mutation.identifier == "M11_CANONICAL_MUTUAL_REVOCATION":
        reductions = sorted(
            event.reference for event in evidence if event.kind in REDUCTION_KINDS
        )
        accepted -= set(reductions[1:])

    if mutation.identifier == "M08_SINGLE_LINEARIZATION":
        single_observations = _simulate_order(
            _single_topological_order(evidence, joins, ancestors, mutation),
            genesis_authority,
            bindings,
            mutation,
        )[0]
        accepted = {
            event.reference for event in evidence
            if single_observations.get(event.reference, False)
        }

    granted = set(genesis_authority)
    revoked: set[str] = set()
    for event in evidence:
        if event.reference not in accepted:
            continue
        if event.kind is Kind.GRANT:
            granted.add(event.reference)
        elif event.kind in REDUCTION_KINDS and event.target_id:
            revoked.add(event.target_id)

    if mutation.identifier == "M37_REJECTED_REDUCTION_DEGRADES_PASS2":
        revoked.update(
            event.target_id
            for event in evidence
            if event.reference in may_only
            and event.reference not in accepted
            and event.kind in REDUCTION_KINDS
            and event.target_id is not None
        )

    if mutation.identifier == "M09_NON_TRANSITIVE_PROVENANCE":
        terminated = frozenset(revoked | set(forked))
    else:
        terminated = _lineage_descendants(bindings, revoked | set(forked))
    terminal = frozenset(granted - set(terminated))
    terminal_sets = analysis.terminal_authorities
    possible_terminal_authority = (
        frozenset().union(*terminal_sets) if terminal_sets else frozenset()
    )
    necessary_terminal_authority = (
        frozenset.intersection(*terminal_sets) if terminal_sets else frozenset()
    )
    reduction_standing: dict[str, ReductionStanding] = {}
    for event in evidence:
        if event.reference not in accepted or event.kind not in REDUCTION_KINDS:
            continue
        actor_binding = bindings[event.actor_id]
        if actor_binding.genesis:
            standing = ReductionStanding.GENESIS
        elif actor_binding.grant_reference in accepted:
            standing = ReductionStanding.ACCEPTED_GRANT
        else:
            standing = ReductionStanding.POSSIBLE_GRANT
        reduction_standing[event.reference] = standing
    event_authority = {
        reference: (
            AuthorityVerdict.MUST_AUTH
            if reference in must_events
            else AuthorityVerdict.MAY_AUTH
            if reference in may_events
            else AuthorityVerdict.NO_AUTH
        )
        for reference in observations
    }
    return (
        frozenset(accepted),
        dict(sorted(reduction_standing.items())),
        dict(sorted(event_authority.items())),
        possible_terminal_authority,
        necessary_terminal_authority,
        frozenset(revoked),
        terminal,
        analysis.complete_paths,
        len(analysis.reachable_states),
        analysis.transitions,
    )


def _probe_authority(
    event: Event,
    controls: Sequence[Event],
    joins: Sequence[ForkJoin],
    bindings: Mapping[str, Binding],
    genesis_authority: frozenset[str],
    ancestors: Mapping[str, frozenset[str]],
    mutation: Mutation,
    engine: str,
    state_limit: int,
    transition_limit: int,
) -> AuthorityVerdict:
    """Evaluate one non-control event at its own causal acting prefix."""

    if engine == "oracle" or mutation.identifier == "M44_ORDINARY_PROBE_IS_ITEM":
        evidence = tuple(controls) + (event,)
        orders = _topological_orders(evidence, joins, ancestors, mutation)
        observations: list[bool] = []
        for order in orders:
            actor_authorized, _ = _simulate_order(
                order, genesis_authority, bindings, mutation
            )
            observations.append(actor_authorized[event.reference])
    elif engine == "dp":
        analysis = _reachable_authority_states(
            controls,
            joins,
            bindings,
            genesis_authority,
            ancestors,
            mutation,
            state_limit,
            transition_limit,
        )
        control_references = {control.reference for control in controls}
        acting_ancestors = set(ancestors.get(event.reference, frozenset()))
        required_before = acting_ancestors & control_references
        required_after = {
            control.reference
            for control in controls
            if event.reference in ancestors.get(control.reference, frozenset())
        }
        for join in joins:
            if set(join.sibling_references) <= acting_ancestors:
                required_before.add(join.reference)
            if event.reference in join.closure:
                required_after.add(join.reference)
        observations = []
        for state in analysis.reachable_states:
            if not required_before <= state.processed:
                continue
            if state.processed & required_after:
                continue
            terminated = _lineage_descendants(
                bindings, state.revoked | state.forked
            )
            observations.append(
                event.actor_id in state.authority
                and event.actor_id not in terminated
            )
        if not observations:
            raise ModelInputError(
                "CYCLIC_CONTROL_EVIDENCE", "ordinary acting prefix unreachable"
            )
    else:
        raise ModelInputError("UNKNOWN_AUTHORITY_ENGINE", engine)
    if observations and all(observations):
        return AuthorityVerdict.MUST_AUTH
    if any(observations):
        return AuthorityVerdict.MAY_AUTH
    return AuthorityVerdict.NO_AUTH


def project(
    scenario: Scenario,
    mutation: Mutation = Mutation(),
    *,
    authority_engine: str = "dp",
    authority_state_limit: int = MAX_REACHABLE_AUTHORITY_STATES,
    authority_transition_limit: int = MAX_REACHABLE_AUTHORITY_TRANSITIONS,
) -> Projection:
    _validate_envelope(scenario)
    genesis = {binding.credential_id: binding for binding in scenario.genesis_bindings}
    if len(genesis) != len(scenario.genesis_bindings):
        raise ModelInputError("GENESIS_IDENTIFIER_COLLISION", "duplicate genesis id")
    for binding in genesis.values():
        if binding.suite_id not in SUITES:
            raise ModelInputError("UNKNOWN_SUITE", binding.suite_id)

    raw_by_reference: dict[str, Event] = {}
    duplicate_count = 0
    reference_collisions: set[str] = set()
    for event in scenario.events:
        previous = raw_by_reference.get(event.reference)
        if previous is None:
            raw_by_reference[event.reference] = event
        elif previous.semantic_tuple() == event.semantic_tuple():
            duplicate_count += 1
        else:
            reference_collisions.add(event.reference)
    if (
        reference_collisions
        and mutation.identifier != "M25_COLLISION_SELECTS_WINNER"
    ):
        raise ModelInputError(
            "REFERENCE_COLLISION_UNSUPPORTED", ",".join(sorted(reference_collisions))
        )

    events = tuple(raw_by_reference.values())
    ancestors = _causal_ancestors(events)
    rejected: dict[str, Outcome] = {}
    admitted: dict[str, Event] = {}
    bindings: dict[str, Binding] = dict(genesis)
    remaining = sorted(events, key=lambda item: item.reference)
    progress = True
    while progress and remaining:
        progress = False
        for event in tuple(remaining):
            dependencies = _dependencies(event)
            if not dependencies <= admitted.keys():
                continue
            remaining.remove(event)
            progress = True

            expected_reference = derive_event_reference(event, mutation)
            if event.reference != expected_reference:
                rejected[event.reference] = Outcome.STRUCTURAL_REJECTION
                continue
            if event.context_id != scenario.context_id:
                rejected[event.reference] = Outcome.STRUCTURAL_REJECTION
                continue
            if not _valid_author_chain(
                event, raw_by_reference, ancestors, frozenset(genesis), mutation
            ):
                rejected[event.reference] = Outcome.STRUCTURAL_REJECTION
                continue
            if event.reference in genesis:
                rejected[event.reference] = (
                    Outcome.CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED
                )
                continue
            if (
                event.role is Role.CREDENTIAL_CONTROL
                and event.content_class is not ContentClass.NONE
                and mutation.identifier != "M22_CONTROL_CONTENT_ACCEPTED"
            ):
                rejected[event.reference] = Outcome.STRUCTURAL_REJECTION
                continue
            if event.role is Role.CREDENTIAL_CONTROL and event.kind not in CONTROL_KINDS:
                rejected[event.reference] = Outcome.STRUCTURAL_REJECTION
                continue
            if event.kind in CONTROL_KINDS and event.role is not Role.CREDENTIAL_CONTROL:
                rejected[event.reference] = Outcome.STRUCTURAL_REJECTION
                continue
            if event.kind is Kind.REMOVE and event.role is not Role.RETENTION_CONTROL:
                rejected[event.reference] = Outcome.STRUCTURAL_REJECTION
                continue
            if event.malformed_tail and mutation.identifier != "M13_MALFORMED_TAIL_ACCEPTED":
                rejected[event.reference] = Outcome.STRUCTURAL_REJECTION
                continue
            if (
                event.role is Role.CREDENTIAL_CONTROL
                and not _valid_control_tail(event, admitted, mutation)
                and mutation.identifier
                != "M13_MALFORMED_TAIL_ACCEPTED"
            ):
                rejected[event.reference] = Outcome.STRUCTURAL_REJECTION
                continue

            actor_binding = bindings.get(event.actor_id)
            if actor_binding is None:
                if mutation.identifier == "M23_UNRESOLVED_DEFERRED":
                    continue
                rejected[event.reference] = Outcome.UNRESOLVED_CREDENTIAL_BINDING
                continue
            if (
                actor_binding.suite_id != event.actor_suite
                or actor_binding.verification_key != event.actor_key
            ):
                rejected[event.reference] = Outcome.CREDENTIAL_BINDING_MISMATCH
                continue

            if event.kind is Kind.GRANT:
                candidate = grant_binding(event)
                candidate_id = (
                    event.target_id
                    if mutation.identifier == "M19_REGRANT_REVOKED_IDENTIFIER"
                    and event.target_id
                    else event.reference
                )
                if mutation.identifier == "M18_AP_BYTES_AS_K_BINDING" and not event.grantee_key:
                    candidate = Binding(
                        credential_id=candidate_id,
                        suite_id=event.actor_suite,
                        verification_key=event.actor_key,
                        issuer_id=event.actor_id,
                        grant_reference=event.reference,
                    )
                else:
                    candidate = replace(candidate, credential_id=candidate_id)
                if candidate_id in bindings:
                    if mutation.identifier == "M19_REGRANT_REVOKED_IDENTIFIER":
                        bindings[candidate_id] = candidate
                        admitted[event.reference] = event
                        continue
                    rejected[event.reference] = (
                        Outcome.CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED
                    )
                    continue
                if mutation.identifier == "M12_NON_GRANT_CREATES_BINDING":
                    pass
                bindings[candidate_id] = candidate
            elif (
                mutation.identifier == "M12_NON_GRANT_CREATES_BINDING"
                and event.target_id
                and event.target_id not in bindings
            ):
                bindings[event.target_id] = Binding(
                    event.target_id,
                    event.actor_suite,
                    event.actor_key,
                    event.actor_id,
                    event.reference,
                )
            admitted[event.reference] = event

    for event in remaining:
        if mutation.identifier != "M23_UNRESOLVED_DEFERRED":
            rejected[event.reference] = Outcome.UNRESOLVED_CREDENTIAL_BINDING

    # R-1 is evaluated after binding discovery so a missing target can be
    # distinguished from a resolvable but non-causal target.  RECOVER has its
    # own transcript rule and is deliberately outside REDUCTION_KINDS.
    for reference, event in tuple(admitted.items()):
        target_causality_kind = (
            event.kind in REDUCTION_KINDS
            or (
                mutation.identifier == "M36_RECOVER_REQUIRES_RETIRED_ANCESTRY"
                and event.kind is Kind.RECOVER
            )
        )
        if target_causality_kind and event.target_id is not None:
            target_binding = bindings.get(event.target_id)
            if target_binding is None:
                del admitted[reference]
                rejected[reference] = Outcome.UNRESOLVABLE_CREDENTIAL
                continue
            if (
                not target_binding.genesis
                and target_binding.grant_reference
                not in ancestors.get(event.reference, frozenset())
                and mutation.identifier != "M35_NONCAUSAL_TARGET_ACCEPTED"
            ):
                del admitted[reference]
                rejected[reference] = Outcome.STRUCTURAL_REJECTION
                continue
        if (
            event.kind is Kind.ROTATE
            and event.target_id == event.actor_id
            and mutation.identifier != "M43_SELF_ROTATION_ACCEPTED"
        ):
            del admitted[reference]
            rejected[reference] = Outcome.STRUCTURAL_REJECTION

    for credential_id in tuple(bindings):
        _lineage_depth(bindings, credential_id)
    max_depth = max((_lineage_depth(bindings, item) for item in bindings), default=0)
    if len(bindings) > MAX_CREDENTIALS:
        raise ModelInputError("AUTHORITY_BOUND_EXCEEDED", "credential count")

    joins, forked_ids, fork_event_ids = _fork_joins(admitted, ancestors, mutation)
    forked = set(forked_ids)
    fork_events = set(fork_event_ids)

    controls = tuple(
        event
        for event in admitted.values()
        if event.role is Role.CREDENTIAL_CONTROL
    )
    genesis_authority = frozenset(genesis)
    authority_unavailable_reason: AuthorityUnavailableReason | None = None
    try:
        (
            accepted,
            reduction_standing,
            event_authority,
            may,
            must,
            revoked,
            terminal,
            explored,
            reachable_state_count,
            authority_transition_count,
        ) = _authority_fold(
            controls,
            joins,
            bindings,
            genesis_authority,
            frozenset(forked),
            ancestors,
            mutation,
            authority_engine,
            authority_state_limit,
            authority_transition_limit,
        )
    except ModelInputError as error:
        limit_reasons = {
            "reachable state count": AuthorityUnavailableReason.REACHABLE_STATE_LIMIT,
            "reachable transition count": (
                AuthorityUnavailableReason.REACHABLE_TRANSITION_LIMIT
            ),
        }
        if error.code != "AUTHORITY_BOUND_EXCEEDED" or error.detail not in limit_reasons:
            raise
        authority_unavailable_reason = limit_reasons[error.detail]
        if mutation.identifier == "M46_STATE_OVERFLOW_IS_EMPTY_AUTHORITY":
            authority_unavailable_reason = None
        accepted = frozenset()
        reduction_standing = {}
        event_authority = {}
        may = frozenset()
        must = frozenset()
        revoked = frozenset()
        terminal = frozenset()
        explored = 0
        reachable_state_count = 0
        authority_transition_count = 0
    terminated = (
        frozenset(set(revoked) | set(forked))
        if mutation.identifier == "M09_NON_TRANSITIVE_PROVENANCE"
        else _lineage_descendants(bindings, revoked | forked)
    )
    if mutation.identifier == "M10_RECOVERY_RESURRECTS_REVOKED":
        for event in controls:
            if event.kind is Kind.RECOVER and event.target_id:
                terminated = frozenset(set(terminated) - {event.target_id})
                terminal = frozenset(set(terminal) | {event.target_id})
    if mutation.identifier == "M14_FORK_EXPANDS_AUTHORITY" and forked:
        terminal = frozenset(set(terminal) | set(bindings))

    alias_map: dict[tuple[str, str], list[str]] = {}
    for credential_id, binding in bindings.items():
        alias_map.setdefault((binding.suite_id, binding.verification_key), []).append(
            credential_id
        )
    alias_groups = tuple(
        sorted(tuple(sorted(values)) for values in alias_map.values() if len(values) > 1)
    )
    if mutation.identifier == "M16_ALIAS_CHANGES_AUTHORITY" and alias_groups:
        terminal = frozenset(set(terminal) - set(alias_groups[0]))
    if mutation.identifier == "M17_TERMINAL_SET_TAMPER" and admitted:
        terminal = frozenset(set(terminal) | {scenario.events[0].actor_id})

    pending_roots = {
        event.reference
        for event in admitted.values()
        if event.content_class is ContentClass.REQUIRED and not event.opening_verified
    }
    pending = set(pending_roots)
    changed = True
    while changed:
        changed = False
        for event in admitted.values():
            if event.reference not in pending and _dependencies(event) & pending:
                pending.add(event.reference)
                changed = True

    checkpoint_only = set(scenario.checkpoint_references) - admitted.keys()
    stale = bool(checkpoint_only & set(scenario.replay_dependencies))
    if mutation.identifier == "M15_CHECKPOINT_SUBSTITUTES" and stale:
        stale = False

    if stale:
        authority_unavailable_reason = AuthorityUnavailableReason.STALE_EVIDENCE
    if stale or authority_unavailable_reason is not None:
        accepted = frozenset()
        reduction_standing = {}
        event_authority = {}
        may = frozenset()
        must = frozenset()
        revoked = frozenset()
        terminal = frozenset()
        terminated = frozenset()
    else:
        for reference, event in admitted.items():
            if event.role is not Role.CREDENTIAL_CONTROL:
                event_authority[reference] = _probe_authority(
                    event,
                    controls,
                    joins,
                    bindings,
                    genesis_authority,
                    ancestors,
                    mutation,
                    authority_engine,
                    authority_state_limit,
                    authority_transition_limit,
                )

    outcomes: dict[str, Outcome] = {}
    for reference, event in admitted.items():
        if authority_unavailable_reason in {
            AuthorityUnavailableReason.REACHABLE_STATE_LIMIT,
            AuthorityUnavailableReason.REACHABLE_TRANSITION_LIMIT,
        }:
            outcomes[reference] = Outcome.AUTHORITY_PROJECTION_UNAVAILABLE
        elif stale:
            outcomes[reference] = Outcome.STALE_EVIDENCE
        elif (
            mutation.identifier == "M48_OUTCOME_PRECEDENCE_DRIFT"
            and reference in pending_roots
        ):
            outcomes[reference] = Outcome.PENDING_OPENING
        elif reference in fork_events:
            outcomes[reference] = Outcome.FORK_EVIDENCE
        elif reference in pending_roots:
            outcomes[reference] = Outcome.PENDING_OPENING
        elif reference in pending:
            outcomes[reference] = Outcome.PENDING_ANCESTOR
        elif event.kind is Kind.REMOVE and event.target_reference in controls_by_ref(controls):
            outcomes[reference] = Outcome.REMOVAL_INAPPLICABLE
        elif event.role is Role.CREDENTIAL_CONTROL:
            outcomes[reference] = (
                Outcome.APPLIED
                if reference in accepted
                else Outcome.AUTHENTIC_BUT_UNAUTHORIZED
            )
        elif (
            mutation.identifier == "M33_TERMINAL_AUTHORITY_FOR_ORDINARY"
            and event.actor_id in terminated
        ):
            outcomes[reference] = Outcome.LINEAGE_QUARANTINED
        elif (
            mutation.identifier == "M33_TERMINAL_AUTHORITY_FOR_ORDINARY"
            and event.actor_id in terminal
        ):
            outcomes[reference] = Outcome.APPLIED
        elif event_authority[reference] is AuthorityVerdict.MUST_AUTH:
            outcomes[reference] = Outcome.APPLIED
        elif (
            event_authority[reference] is AuthorityVerdict.NO_AUTH
            and any(
                reduction.reference in ancestors.get(reference, frozenset())
                and reduction.target_id is not None
                and event.actor_id
                in _lineage_descendants(bindings, {reduction.target_id})
                for reduction in controls
                if reduction.reference in accepted
                and reduction.kind in REDUCTION_KINDS
            )
        ):
            outcomes[reference] = Outcome.POST_REVOCATION
        elif (
            event_authority[reference] is AuthorityVerdict.NO_AUTH
            and any(
                set(join.sibling_references)
                <= set(ancestors.get(reference, frozenset()))
                and event.actor_id
                in _lineage_descendants(bindings, {join.credential_id})
                for join in joins
            )
        ):
            outcomes[reference] = Outcome.LINEAGE_QUARANTINED
        else:
            outcomes[reference] = Outcome.AUTHENTIC_BUT_UNAUTHORIZED

    return Projection(
        admitted=tuple(sorted(admitted)),
        rejected=dict(sorted(rejected.items())),
        outcomes=dict(sorted(outcomes.items())),
        bindings=dict(sorted(bindings.items())),
        alias_groups=alias_groups,
        accepted_controls=accepted,
        reduction_standing=reduction_standing,
        event_authority=dict(sorted(event_authority.items())),
        possible_terminal_authority=may,
        necessary_terminal_authority=must,
        terminal_authority=terminal,
        revoked=revoked,
        terminated=terminated,
        forked_credentials=frozenset(forked),
        fork_joins=tuple(join.reference for join in joins),
        pending_roots=frozenset(pending_roots),
        pending=frozenset(pending),
        stale_evidence=stale,
        authority_available=authority_unavailable_reason is None,
        authority_unavailable_reason=authority_unavailable_reason,
        explored_orders=explored,
        reachable_authority_states=reachable_state_count,
        authority_transitions=authority_transition_count,
        replayed_event_work=len(admitted) + authority_transition_count,
        max_lineage_depth=max_depth,
    )


def controls_by_ref(events: Sequence[Event]) -> frozenset[str]:
    return frozenset(event.reference for event in events)


def delivery_views(
    scenario: Scenario, mutation: Mutation = Mutation()
) -> tuple[tuple[object, ...], ...]:
    if len(scenario.events) > MAX_DELIVERY_PERMUTATION_WIDTH:
        raise ModelInputError("DELIVERY_BOUND_EXCEEDED", "more than six events")
    views = []
    for order in permutations(scenario.events):
        reordered = replace(scenario, events=tuple(order))
        views.append(project(reordered, mutation).semantic_view())
    return tuple(views)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()
