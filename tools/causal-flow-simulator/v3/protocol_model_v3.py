"""Independent bounded model for Styx C0.2j credential succession.

The model is intentionally symbolic.  It exercises K admission, grant-rooted
credential binding, provenance containment, scoped fork quarantine, and the
two-sided MayAuth/MustAuth authority fold.  It is not a wire implementation,
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

MAX_EVENTS = 12
MAX_CONTROL_EVENTS = 6
MAX_PARENTS = 4
MAX_CREDENTIALS = 10
MAX_LINEAGE_DEPTH = 4
MAX_TOPOLOGICAL_ORDERS = 720
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
    UNRESOLVABLE_CREDENTIAL = "UNRESOLVABLE_CREDENTIAL"
    CREDENTIAL_BINDING_MISMATCH = "CREDENTIAL_BINDING_MISMATCH"
    CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED = (
        "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED"
    )
    REMOVAL_INAPPLICABLE = "REMOVAL_INAPPLICABLE"
    STALE_EVIDENCE = "STALE_EVIDENCE"


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
    """Virtual authority item positioned at the causal join of a fork pair."""

    reference: str
    credential_id: str
    left_reference: str
    right_reference: str
    closure: frozenset[str]


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
    may_authority: frozenset[str]
    must_authority: frozenset[str]
    terminal_authority: frozenset[str]
    revoked: frozenset[str]
    terminated: frozenset[str]
    forked_credentials: frozenset[str]
    fork_joins: tuple[str, ...]
    pending_roots: frozenset[str]
    pending: frozenset[str]
    stale_evidence: bool
    explored_orders: int
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
            self.may_authority,
            self.must_authority,
            self.terminal_authority,
            self.revoked,
            self.terminated,
            self.forked_credentials,
            self.fork_joins,
            self.pending_roots,
            self.pending,
            self.stale_evidence,
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


def _valid_control_tail(event: Event, admitted: Mapping[str, Event]) -> bool:
    """Validate the closed CREDENTIAL_CONTROL tail before AP evaluation.

    `target_reference` names the fresh binding GRANT for ROTATE/RECOVER.  It is
    deliberately not a binding source: only that referenced GRANT can create
    the replacement credential record.
    """

    if event.kind is Kind.GRANT:
        return (
            event.declared_subject_id is None
            and event.target_id is None
            and event.target_reference is None
            and event.grantee_suite in SUITES
            and bool(event.grantee_key)
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
    """Construct the minimal pairwise causal joins for every valid fork slot."""

    slots: dict[tuple[object, ...], list[str]] = {}
    for event in admitted.values():
        slot = (
            (event.actor_id, event.sequence, event.predecessor)
            if mutation.identifier == "M29_PREDECESSOR_SLOT_FORK_ONLY"
            else (event.actor_id, event.sequence)
        )
        slots.setdefault(slot, []).append(event.reference)

    candidates: list[ForkJoin] = []
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
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                closure = frozenset(
                    set(ancestors.get(left, frozenset()))
                    | set(ancestors.get(right, frozenset()))
                    | {left, right}
                )
                candidates.append(
                    ForkJoin(
                        reference=(
                            f"fork:{credential_id}:{sequence}:{left}:{right}"
                        ),
                        credential_id=credential_id,
                        left_reference=left,
                        right_reference=right,
                        closure=closure,
                    )
                )

    minimal: list[ForkJoin] = []
    for candidate in candidates:
        superseded = any(
            other.credential_id == candidate.credential_id
            and other.reference != candidate.reference
            and {other.left_reference, other.right_reference} <= candidate.closure
            for other in candidates
        )
        if not superseded:
            minimal.append(candidate)
    return tuple(sorted(minimal, key=lambda item: item.reference)), frozenset(forked), frozenset(fork_events)


def _topological_orders(
    events: Sequence[Event],
    joins: Sequence[ForkJoin],
    ancestors: Mapping[str, frozenset[str]],
    mutation: Mutation,
) -> tuple[tuple[Event | ForkJoin, ...], ...]:
    items: tuple[Event | ForkJoin, ...] = tuple(events) + tuple(joins)
    if len(items) > MAX_CONTROL_EVENTS:
        raise ModelInputError("AUTHORITY_BOUND_EXCEEDED", "control event count")
    controls_by_reference = {event.reference: event for event in events}
    joins_by_reference = {join.reference: join for join in joins}
    predecessors: dict[str, set[str]] = {}
    for event in events:
        required = set(
            _dependencies(event)
            if mutation.identifier == "M26_DIRECT_DEPENDENCIES_ONLY"
            else ancestors.get(event.reference, frozenset())
        ) & set(controls_by_reference)
        for join in joins:
            if {
                join.left_reference,
                join.right_reference,
            } <= set(ancestors.get(event.reference, frozenset())):
                required.add(join.reference)
            if (
                mutation.identifier == "M32_FORK_JOIN_BEFORE_SIBLINGS"
                and event.reference
                in {join.left_reference, join.right_reference}
            ):
                required.add(join.reference)
        predecessors[event.reference] = required
    for join in joins:
        required = set(join.closure) & set(controls_by_reference)
        if mutation.identifier == "M32_FORK_JOIN_BEFORE_SIBLINGS":
            required -= {join.left_reference, join.right_reference}
        for other in joins:
            if other.reference != join.reference and {
                other.left_reference,
                other.right_reference,
            } <= join.closure:
                required.add(other.reference)
        predecessors[join.reference] = required

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


def _authority_fold(
    controls: Sequence[Event],
    joins: Sequence[ForkJoin],
    bindings: Mapping[str, Binding],
    genesis_authority: frozenset[str],
    forked: frozenset[str],
    ancestors: Mapping[str, frozenset[str]],
    mutation: Mutation,
) -> tuple[
    frozenset[str],
    Mapping[str, ReductionStanding],
    Mapping[str, AuthorityVerdict],
    frozenset[str],
    frozenset[str],
    frozenset[str],
    frozenset[str],
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
    orders = _topological_orders(evidence, joins, ancestors, mutation)
    observations: dict[str, list[bool]] = {
        event.reference: [] for event in evidence
    }
    terminal_sets: list[frozenset[str]] = []
    for order in orders:
        actors, terminal = _simulate_order(
            order, genesis_authority, bindings, mutation
        )
        terminal_sets.append(terminal)
        for reference, authorized in actors.items():
            observations[reference].append(authorized)

    may_events = {
        reference for reference, values in observations.items() if any(values)
    }
    must_events = {
        reference for reference, values in observations.items() if values and all(values)
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
            orders[0], genesis_authority, bindings, mutation
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

    if mutation.identifier == "M09_NON_TRANSITIVE_PROVENANCE":
        terminated = frozenset(revoked | set(forked))
    else:
        terminated = _lineage_descendants(bindings, revoked | set(forked))
    terminal = frozenset(granted - set(terminated))
    may_authority = frozenset().union(*terminal_sets) if terminal_sets else frozenset()
    must_authority = (
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
        may_authority,
        must_authority,
        frozenset(revoked),
        terminal,
        len(orders),
    )


def _probe_authority(
    event: Event,
    controls: Sequence[Event],
    joins: Sequence[ForkJoin],
    bindings: Mapping[str, Binding],
    genesis_authority: frozenset[str],
    ancestors: Mapping[str, frozenset[str]],
    mutation: Mutation,
) -> AuthorityVerdict:
    """Evaluate one non-control event at its own causal acting prefix."""

    evidence = tuple(controls) + (event,)
    orders = _topological_orders(evidence, joins, ancestors, mutation)
    observations: list[bool] = []
    for order in orders:
        actor_authorized, _ = _simulate_order(
            order, genesis_authority, bindings, mutation
        )
        observations.append(actor_authorized[event.reference])
    if observations and all(observations):
        return AuthorityVerdict.MUST_AUTH
    if any(observations):
        return AuthorityVerdict.MAY_AUTH
    return AuthorityVerdict.NO_AUTH


def project(scenario: Scenario, mutation: Mutation = Mutation()) -> Projection:
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
                and not _valid_control_tail(event, admitted)
                and mutation.identifier
                not in {
                    "M13_MALFORMED_TAIL_ACCEPTED",
                    "M18_AP_BYTES_AS_K_BINDING",
                    "M19_REGRANT_REVOKED_IDENTIFIER",
                }
            ):
                rejected[event.reference] = Outcome.STRUCTURAL_REJECTION
                continue

            actor_binding = bindings.get(event.actor_id)
            if actor_binding is None:
                if mutation.identifier == "M23_UNRESOLVED_DEFERRED":
                    continue
                rejected[event.reference] = Outcome.UNRESOLVABLE_CREDENTIAL
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
            rejected[event.reference] = Outcome.UNRESOLVABLE_CREDENTIAL

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
    (
        accepted,
        reduction_standing,
        event_authority,
        may,
        must,
        revoked,
        terminal,
        explored,
    ) = _authority_fold(
        controls,
        joins,
        bindings,
        genesis_authority,
        frozenset(forked),
        ancestors,
        mutation,
    )
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
            )

    outcomes: dict[str, Outcome] = {}
    for reference, event in admitted.items():
        if stale:
            outcomes[reference] = Outcome.STALE_EVIDENCE
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
                {join.left_reference, join.right_reference}
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
        may_authority=may,
        must_authority=must,
        terminal_authority=terminal,
        revoked=revoked,
        terminated=terminated,
        forked_credentials=frozenset(forked),
        fork_joins=tuple(join.reference for join in joins),
        pending_roots=frozenset(pending_roots),
        pending=frozenset(pending),
        stale_evidence=stale,
        explored_orders=explored,
        replayed_event_work=len(admitted) * explored,
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
