"""Closed hostile suite for the C0.2i v2 falsification model."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from inspect import signature
from itertools import product
from typing import Callable

from kernel_model_v2 import (
    Availability,
    AxisPresentation,
    BindingObservation,
    ContentClass,
    Event,
    EventKind,
    EventRole,
    CURRENT_CTX_OCTETS,
    CURRENT_GEOMETRY_OCTETS,
    MAX_DELIVERY_PERMUTATIONS,
    MAX_EVENTS,
    MAX_GENESIS_AUTHORITIES,
    MAX_PARENTS,
    MAX_TEXT_BYTES,
    ModelInputError,
    OpeningObservation,
    Outcome,
    PresentationState,
    Scenario,
    delivery_orders,
    derive_graph,
    current_profile_symbolic_commitment,
    current_symbolic_geometry_is_legal,
    classify_payload_axis,
    frontier_is_producible,
    incremental_replay,
    project,
    removed_presentation_state,
)


C0_2F_OBLIGATIONS = frozenset(f"C0.2f-{number:02d}" for number in range(1, 17))

# The causal families are re-expressed independently rather than imported from
# the immutable v1 suite.  Their names keep the historical evidence traceable.
C0_2D_FAMILIES = frozenset(
    {
        "author-gap",
        "child-before-parent",
        "cross-context",
        "cycle-defense",
        "delivery-permutation",
        "duplicate-replay",
        "late-exact-prefix",
        "late-fork",
        "late-lower-reference",
        "malicious-omission-limit",
        "missing-parent",
        "mixed-causal-concurrent",
        "parent-canonicality",
        "replay-boundary",
        "resource-bound",
        "rollback-limit",
        "stale-parent",
        "incremental-full-equivalence",
        "exhaustive-incremental-replay",
        "checkpoint-proof",
        "revocation-race",
        "ownership-boundary",
    }
)

C0_2I_FAMILIES = frozenset(
    {
        "opening-event-interleavings",
        "selective-opening-convergence",
        "pending-descendant-closure",
        "opening-monotonicity",
        "pending-incremental-full-equivalence",
        "fork-required-partial-opening",
        "fork-quarantine",
        "fork-free-authority-laundering-nonclaim",
        "nested-required-root-replay",
        "overlapping-root-diamond",
        "binding-observation-distinction",
        "unauthorized-hole-independent-authority",
        "revocation-hole-interactions",
        "revoked-old-key",
        "late-authority-replay",
        "rotation-recovery-outside-hole",
        "credential-identifier-collision",
        "grant-behind-hole",
        "delayed-reveal",
        "relay-withholding",
        "late-low-reference-sibling",
        "transcript-deferred-distinction",
        "removal-behind-hole",
        "late-removal-authority-replay",
        "detachable-removal-in-pending-subtree",
        "required-removal-inapplicable",
        "checkpoint-pending-producer",
        "checkpoint-authority-staleness",
        "checkpoint-retained-live",
        "self-rotation-and-admin-recovery",
        "bounded-hole-flood",
        "sole-authority-self-lockout",
        "authentic-but-unauthorized",
        "content-bearing-control-rejected",
        "current-profile-copy-nonprotection",
        "geometry-frozen",
        "checkpoint-staleness-nonclaim",
        "fork-stale-precedence",
        "closure-outside-hole",
        "target-prefix-abandonment-rejected",
        "custody-frontier-obligation",
    }
)


class Suite:
    def __init__(self) -> None:
        self.results: list[dict[str, object]] = []
        self.family_counts: Counter[str] = Counter()
        self.obligation_counts: Counter[str] = Counter()
        self.explored_traces = 0
        self.max_pending_roots = 0
        self.max_pending_descendants = 0
        self.max_replayed_work = 0
        self.earliest_replay_boundary: int | None = None

    def evaluate(self, scenario: Scenario):
        projection = project(scenario)
        self.observe(projection)
        return projection

    def observe(self, projection) -> None:
        self.max_pending_roots = max(
            self.max_pending_roots, projection.metrics.pending_roots
        )
        self.max_pending_descendants = max(
            self.max_pending_descendants, projection.metrics.pending_descendants
        )
        self.max_replayed_work = max(
            self.max_replayed_work, projection.metrics.replayed_event_work
        )
        boundary = projection.metrics.earliest_replay_boundary
        if boundary is not None:
            self.earliest_replay_boundary = (
                boundary
                if self.earliest_replay_boundary is None
                else min(self.earliest_replay_boundary, boundary)
            )

    def check(
        self,
        identifier: str,
        condition: bool,
        *,
        family: str,
        detail: str,
        obligation: str | None = None,
        trace: tuple[str, ...] = (),
    ) -> None:
        self.family_counts[family] += 1
        if obligation:
            self.obligation_counts[obligation] += 1
        self.results.append(
            {
                "id": identifier,
                "family": family,
                "obligation": obligation,
                "passed": bool(condition),
                "detail": detail,
                "trace": list(trace),
            }
        )

    def expect_error(
        self,
        identifier: str,
        code: str,
        operation: Callable[[], object],
        *,
        family: str,
        detail: str,
        obligation: str | None = None,
    ) -> None:
        observed = None
        try:
            operation()
        except ModelInputError as error:
            observed = error.code
        self.check(
            identifier,
            observed == code,
            family=family,
            detail=f"{detail}; observed={observed!r}",
            obligation=obligation,
        )


def event(
    reference: str,
    sequence: int,
    *,
    credential: str = "admin",
    context: str = "ctx",
    predecessor: str | None = None,
    parents: tuple[str, ...] = (),
    content: ContentClass = ContentClass.NONE,
    kind: EventKind = EventKind.ACTION,
    role: EventRole | None = None,
    binding_ref: str | None = None,
    subject: str | None = None,
    target: str | None = None,
    commitment: str | None = None,
) -> Event:
    if role is None:
        role = EventRole.CONTROL if kind in {
            EventKind.GRANT,
            EventKind.REVOKE,
            EventKind.ROTATE,
            EventKind.RECOVER,
            EventKind.POLICY,
            EventKind.CLOSURE,
            EventKind.REMOVE,
        } else EventRole.ORDINARY
    return Event(
        reference=reference,
        context_identifier=context,
        credential_id=credential,
        sequence=sequence,
        direct_predecessor=predecessor,
        parents=parents,
        content_class=content,
        event_role=role,
        kind=kind,
        binding_ref=binding_ref or f"genesis:{credential}",
        subject_credential=subject,
        target_reference=target,
        target_commitment=commitment,
        descriptor=f"descriptor:{reference}",
        commitment=f"commitment:{reference}",
    )


def _scenario(
    events: tuple[Event, ...],
    openings: dict[str, OpeningObservation] | None = None,
    *,
    genesis: tuple[str, ...] = ("admin",),
    context: str = "ctx",
    checkpoint_only: tuple[str, ...] = (),
    checkpoint_evidence: tuple[str, ...] | None = None,
    replay_dependencies: tuple[str, ...] | None = None,
) -> Scenario:
    return Scenario(
        events=events,
        genesis_authority=genesis,
        context_identifier=context,
        opening_observations=openings or {},
        checkpoint_evidence=(
            checkpoint_only if checkpoint_evidence is None else checkpoint_evidence
        ),
        replay_dependencies=(
            checkpoint_only
            if replay_dependencies is None
            else replay_dependencies
        ),
    )


def _delivery_convergence(
    suite: Suite,
    scenario: Scenario,
) -> tuple[object, bool, int, tuple[str, ...]]:
    """Evaluate every permitted delivery order against one set-relative oracle."""

    expected = suite.evaluate(scenario)
    orders = delivery_orders(scenario.events)
    first_failure: tuple[str, ...] = ()
    converged = True
    for order in orders:
        actual = suite.evaluate(replace(scenario, events=order))
        if actual.semantic_view() != expected.semantic_view():
            converged = False
            if not first_failure:
                first_failure = tuple(item.reference for item in order)
    suite.explored_traces += len(orders)
    return expected, converged, len(orders), first_failure


def _exercise_causal_core(suite: Suite) -> None:
    root = event("a", 0)
    child = event("c", 1, predecessor="a")
    side = event("b", 0, credential="peer")
    base = _scenario((root, child, side), genesis=("admin", "peer"))
    expected = suite.evaluate(base)
    suite.observe(expected)
    orders = delivery_orders(base.events)
    suite.explored_traces += len(orders)
    for index, order in enumerate(orders):
        actual = suite.evaluate(replace(base, events=order))
        suite.check(
            f"c02d-delivery-{index}",
            actual.semantic_view() == expected.semantic_view(),
            family="delivery-permutation",
            detail="delivery order does not change set-relative graph or projection",
            trace=tuple(item.reference for item in order),
        )

    duplicate = suite.evaluate(replace(base, events=(root, root, child, side)))
    suite.check(
        "c02d-duplicate",
        duplicate.graph.duplicate_observations == 1
        and duplicate.graph.canonical_order == expected.graph.canonical_order,
        family="duplicate-replay",
        detail="byte-identical observations collapse to one graph node",
    )
    suite.expect_error(
        "c02d-reference-collision",
        "REFERENCE_COLLISION_UNSUPPORTED",
        lambda: suite.evaluate(
            _scenario((root, replace(root, descriptor="different-descriptor")))
        ),
        family="duplicate-replay",
        detail="one reference cannot identify two non-identical transcripts",
    )
    missing = suite.evaluate(_scenario((event("orphan", 1, predecessor="absent"),)))
    suite.check(
        "c02d-missing-parent",
        missing.graph.deferred == ("orphan",)
        and missing.outcomes["orphan"] is Outcome.DEFERRED,
        family="missing-parent",
        detail="transcript-missing K deferral is explicit",
    )

    gap = suite.evaluate(_scenario((event("gap-root", 0), event(
        "gap", 2, predecessor="gap-root"
    ))))
    suite.check(
        "c02d-author-gap",
        gap.outcomes["gap"] is Outcome.STRUCTURAL_REJECTION,
        family="author-gap",
        detail="a direct predecessor must have the same credential and sequence n-1",
    )

    reversed_delivery = suite.evaluate(replace(base, events=(child, side, root)))
    suite.check(
        "c02d-child-before-parent",
        reversed_delivery.semantic_view() == expected.semantic_view(),
        family="child-before-parent",
        detail="delivery before a direct predecessor cannot change the set-relative result",
    )

    foreign = suite.evaluate(_scenario((event("foreign", 0, context="other"),)))
    suite.check(
        "c02d-cross-context",
        foreign.outcomes["foreign"] is Outcome.STRUCTURAL_REJECTION
        and "foreign" not in foreign.graph.admitted,
        family="cross-context",
        detail="an event from another authenticated context is not admitted",
    )

    cycle_a = event("cycle-a", 0, credential="admin", parents=("cycle-b",))
    cycle_b = event("cycle-b", 0, credential="peer", parents=("cycle-a",))
    cycle = suite.evaluate(_scenario((cycle_a, cycle_b), genesis=("admin", "peer")))
    suite.check(
        "c02d-cycle-defense",
        set(cycle.graph.structurally_rejected) == {"cycle-a", "cycle-b"}
        and not cycle.graph.admitted,
        family="cycle-defense",
        detail="a closed dependency cycle is rejected rather than ordered",
    )

    prefix = suite.evaluate(_scenario((root,)))
    extended = suite.evaluate(base)
    suite.check(
        "c02d-late-exact-prefix",
        prefix.applied_order == ("a",)
        and extended.applied_order.index("a") < extended.applied_order.index("c"),
        family="late-exact-prefix",
        detail="late set growth preserves causal order while permitting full replay",
    )

    fork_left = event("fork-left", 0)
    fork_right = event("fork-right", 0)
    late_fork = suite.evaluate(_scenario((fork_left, fork_right)))
    suite.check(
        "c02d-late-fork",
        late_fork.graph.forks == {"fork-left", "fork-right"}
        and all(
            late_fork.outcomes[item] is Outcome.FORK_EVIDENCE
            for item in late_fork.graph.forks
        )
        and late_fork.fork_quarantined
        and not late_fork.applied_order
        and not late_fork.authorized_credentials,
        family="late-fork",
        detail="same-author same-sequence siblings remain graph-visible while AP is quarantined",
    )

    high = event("z-high", 0)
    low = event("a-low", 0, credential="peer")
    high_only = suite.evaluate(_scenario((high,)))
    with_low = suite.evaluate(_scenario((high, low), genesis=("admin", "peer")))
    suite.check(
        "c02d-late-lower-reference",
        high_only.applied_order == ("z-high",)
        and with_low.applied_order == ("a-low", "z-high"),
        family="late-lower-reference",
        detail="a late lower reference causes deterministic set-relative reorder",
    )

    observed = event("observed", 0, credential="peer")
    claimed_child = event("claimed-child", 0, parents=("observed",))
    omitted = replace(claimed_child, reference="omitted", parents=())
    omission = suite.evaluate(
        _scenario((observed, claimed_child, omitted), genesis=("admin", "peer"))
    )
    suite.check(
        "c02d-malicious-omission-limit",
        "observed" in omission.graph.ancestors["claimed-child"]
        and "observed" not in omission.graph.ancestors["omitted"],
        family="malicious-omission-limit",
        detail="K authenticates claimed ancestry but cannot infer an omitted observation",
    )

    suite.check(
        "c02d-mixed-causal-concurrent",
        expected.graph.ancestors["c"] == {"a"}
        and "b" not in expected.graph.ancestors["c"]
        and expected.graph.canonical_order.index("a") < expected.graph.canonical_order.index("c"),
        family="mixed-causal-concurrent",
        detail="causal edges precede the reference tiebreak used only among ready events",
    )

    duplicate_parents = suite.evaluate(
        _scenario((event("p", 0, credential="peer"), event(
            "bad-parents", 0, parents=("p", "p")
        )), genesis=("admin", "peer"))
    )
    suite.check(
        "c02d-parent-canonicality",
        duplicate_parents.outcomes["bad-parents"] is Outcome.STRUCTURAL_REJECTION,
        family="parent-canonicality",
        detail="duplicate or non-canonical causal parents are rejected",
    )

    suite.check(
        "c02d-replay-boundary",
        with_low.applied_order != high_only.applied_order
        and with_low.graph.canonical_order == ("a-low", "z-high"),
        family="replay-boundary",
        detail="late admission is handled by deterministic full replay, not append-only finality",
    )

    suite.expect_error(
        "c02d-resource-bound",
        "MODEL_BOUND_EXCEEDED",
        lambda: suite.evaluate(_scenario(tuple(event(f"bound-{i}", 0) for i in range(MAX_EVENTS + 1)))),
        family="resource-bound",
        detail="event-set inflation fails before graph exploration",
        obligation="C0.2f-16",
    )

    rolled_back = suite.evaluate(_scenario((root,)))
    suite.check(
        "c02d-rollback-limit",
        rolled_back.applied_order == ("a",)
        and rolled_back.semantic_view() != expected.semantic_view(),
        family="rollback-limit",
        detail="a coherent older transcript set can remain locally valid; no rollback detection is inferred",
    )

    stale_root = event("stale-root", 0)
    stale_child = event("stale-child", 1, predecessor="stale-root")
    stale = event(
        "stale-frontier",
        0,
        credential="peer",
        parents=("stale-child", "stale-root"),
    )
    stale_result = suite.evaluate(
        _scenario((stale_root, stale_child, stale), genesis=("admin", "peer"))
    )
    suite.check(
        "c02d-stale-parent",
        stale_result.outcomes["stale-frontier"] is Outcome.STRUCTURAL_REJECTION,
        family="stale-parent",
        detail="a frontier containing an ancestor of another frontier member is rejected",
    )

    # The direct predecessor is a separate author-chain edge.  A causal parent
    # may descend from it; only a parent already covered by the predecessor is
    # redundant.  This is the asymmetric O-01 maximal-frontier rule.
    admin_zero = event("frontier-a0", 0)
    peer_zero = event(
        "frontier-p0", 0, credential="peer", parents=("frontier-a0",)
    )
    valid_frontier = event(
        "frontier-a1",
        1,
        predecessor="frontier-a0",
        parents=("frontier-p0",),
    )
    valid_frontier_result = suite.evaluate(
        _scenario(
            (admin_zero, peer_zero, valid_frontier),
            genesis=("admin", "peer"),
        )
    )
    suite.check(
        "c02d-maximal-frontier-asymmetry",
        valid_frontier_result.outcomes["frontier-a1"] is Outcome.APPLIED,
        family="stale-parent",
        detail="a parent descending from the direct predecessor is not redundant",
    )

    checkpoint_required = suite.evaluate(
        _scenario(
            (event("checkpoint-required", 0),),
            checkpoint_evidence=("authority-proof", "unrelated-proof"),
            replay_dependencies=("authority-proof",),
        )
    )
    checkpoint_irrelevant = suite.evaluate(
        _scenario(
            (event("checkpoint-irrelevant", 0),),
            checkpoint_evidence=("unrelated-proof",),
            replay_dependencies=("authority-proof",),
        )
    )
    suite.check(
        "c02d-checkpoint-proof",
        checkpoint_required.outcomes["checkpoint-required"]
        is Outcome.STALE_EVIDENCE
        and checkpoint_irrelevant.outcomes["checkpoint-irrelevant"]
        is Outcome.APPLIED,
        family="checkpoint-proof",
        detail="only checkpoint evidence intersecting authenticated replay dependencies makes the projection stale",
    )

    graph_field_names = set(type(expected.graph).__dataclass_fields__)
    suite.check(
        "c02d-ownership-boundary",
        {"outcomes", "applied_order", "authorized_credentials", "removed_targets"}.isdisjoint(
            graph_field_names
        ),
        family="ownership-boundary",
        detail="K graph output contains no AP authorization, retention or finality verdict",
    )


def _exercise_pending_fold(suite: Suite) -> None:
    none_projection = suite.evaluate(_scenario((event("class-none", 0),)))
    required_projection = suite.evaluate(
        _scenario((event("class-required", 0, content=ContentClass.REQUIRED),))
    )
    detachable_projection = suite.evaluate(
        _scenario((event("class-detachable", 0, content=ContentClass.DETACHABLE),))
    )
    suite.check(
        "content-class-separation",
        none_projection.outcomes["class-none"] is Outcome.APPLIED
        and required_projection.outcomes["class-required"]
        is Outcome.PENDING_OPENING
        and detachable_projection.outcomes["class-detachable"] is Outcome.APPLIED,
        family="binding-observation-distinction",
        detail="NONE, REQUIRED-without-opening and DETACHABLE have distinct replay effects",
        obligation="C0.2f-01",
    )

    hole = event("hole", 0, content=ContentClass.REQUIRED)
    child = event("child", 1, predecessor="hole")
    independent = event("independent", 0, credential="peer")
    closed = _scenario((hole, child, independent), genesis=("admin", "peer"))
    pending = suite.evaluate(closed)
    suite.observe(pending)
    suite.check(
        "pending-closure",
        pending.pending_roots == {"hole"}
        and pending.pending == {"hole", "child"}
        and pending.outcomes["hole"] is Outcome.PENDING_OPENING
        and pending.outcomes["child"] is Outcome.PENDING_ANCESTOR,
        family="pending-descendant-closure",
        detail="root and causal descendant are pending with distinct outcomes",
        obligation="C0.2f-04",
    )
    suite.check(
        "independent-continuation",
        pending.applied_order == ("independent",),
        family="pending-descendant-closure",
        detail="independent work after a hole remains applicable",
        obligation="C0.2f-04",
    )

    opened = replace(
        closed, opening_observations={"hole": OpeningObservation.VERIFIED}
    )
    resumed = incremental_replay(closed, opened)
    fresh = suite.evaluate(opened)
    suite.observe(resumed)
    suite.check(
        "incremental-full",
        resumed.semantic_view() == fresh.semantic_view()
        and resumed.metrics.earliest_replay_boundary == 0,
        family="pending-incremental-full-equivalence",
        detail="monotone opening acquisition resumes from the earliest affected position",
        obligation="C0.2f-03",
    )
    suite.check(
        "c02d-incremental-full-equivalence",
        resumed.semantic_view() == fresh.semantic_view(),
        family="incremental-full-equivalence",
        detail="the incremental suffix machine equals an independent fresh projection",
    )
    suite.check(
        "opening-monotone",
        resumed.pending < pending.pending,
        family="opening-monotonicity",
        detail="adding a verified opening never adds pending events",
        obligation="C0.2f-03",
    )
    suite.expect_error(
        "opening-unverify-rejected",
        "NON_MONOTONE_OPENING_SET",
        lambda: incremental_replay(opened, closed),
        family="opening-monotonicity",
        detail="a verified value cannot be un-verified",
    )
    mismatch = replace(
        closed,
        opening_observations={"hole": OpeningObservation.COMMITMENT_MISMATCH},
    )
    repaired = incremental_replay(mismatch, opened)
    suite.check(
        "mismatch-then-correct",
        repaired.semantic_view() == fresh.semantic_view()
        and repaired.binding_observations["hole"] is OpeningObservation.VERIFIED,
        family="binding-observation-distinction",
        detail="a substituted opening remains typed until a later correct opening enables replay",
        obligation="C0.2f-05",
    )

    before_event = suite.evaluate(
        _scenario(
            (independent,),
            {"hole": OpeningObservation.VERIFIED},
            genesis=("peer",),
        )
    )
    suite.check(
        "opening-alone",
        before_event.graph.admitted == ("independent",)
        and before_event.applied_order == ("independent",),
        family="opening-event-interleavings",
        detail="an opening without its event has no graph or AP effect",
    )
    opened_deliveries = (
        replace(opened, events=(independent, child, hole)),
        replace(opened, events=(hole, independent, child)),
    )
    suite.explored_traces += len(opened_deliveries)
    for index, delivered in enumerate(opened_deliveries):
        suite.check(
            f"opening-event-final-{index}",
            suite.evaluate(delivered).semantic_view() == fresh.semantic_view(),
            family="opening-event-interleavings",
            detail="equal final transcript/opening sets converge when the opening is observed before or after its event",
            trace=tuple(item.reference for item in delivered.events),
        )

    for observation in (
        OpeningObservation.OPENING_MISSING,
        OpeningObservation.LENGTH_MISMATCH,
        OpeningObservation.COMMITMENT_MISMATCH,
    ):
        result = suite.evaluate(_scenario((hole,), {"hole": observation}))
        suite.check(
            f"binding-{observation.value.lower()}",
            result.outcomes["hole"] is Outcome.PENDING_OPENING
            and result.binding_observations["hole"] is observation,
            family="binding-observation-distinction",
            detail=f"{observation.value} remains a distinct observation",
            obligation="C0.2f-05",
        )

    all_observation_states = {
        suite.evaluate(_scenario((hole,), {"hole": observation}))
        .binding_observations["hole"]
        for observation in OpeningObservation
    }
    suite.check(
        "binding-axis-closed",
        all_observation_states == set(OpeningObservation),
        family="binding-observation-distinction",
        detail="the bounded opening-observation axis is typed, exhaustive and closed",
        obligation="C0.2f-05",
    )

    content_bearing_legal = {
        (Availability.ABSENT, BindingObservation.NOT_CHECKED),
        (Availability.PARTIAL, BindingObservation.NOT_CHECKED),
        (Availability.PRESENT, BindingObservation.NOT_CHECKED),
        (Availability.PRESENT, BindingObservation.VERIFIED),
        (Availability.PRESENT, BindingObservation.OPENING_MISSING),
        (Availability.PRESENT, BindingObservation.LENGTH_MISMATCH),
        (Availability.PRESENT, BindingObservation.COMMITMENT_MISMATCH),
    }
    none_legal = {
        (Availability.ABSENT, BindingObservation.NOT_APPLICABLE),
        (Availability.PRESENT, BindingObservation.NOT_APPLICABLE),
    }
    typed_axis_ok = True
    typed_axis_cases = 0
    for content_class, availability, binding in product(
        ContentClass, Availability, BindingObservation
    ):
        legal = none_legal if content_class is ContentClass.NONE else content_bearing_legal
        expected_acceptance = (availability, binding) in legal
        try:
            presentation = classify_payload_axis(
                content_class,
                availability,
                binding,
            )
            accepted = True
        except ModelInputError as error:
            presentation = None
            accepted = False
            typed_axis_ok = typed_axis_ok and error.code == "ILLEGAL_AXIS_COMBINATION"

        typed_axis_ok = typed_axis_ok and accepted == expected_acceptance
        if accepted:
            if content_class is ContentClass.NONE:
                expected_presentation = (
                    AxisPresentation.NO_CONTENT
                    if availability is Availability.ABSENT
                    else AxisPresentation.UNEXPECTED_CONTENT_REJECTED
                )
            elif (
                content_class is ContentClass.REQUIRED
                and binding is not BindingObservation.VERIFIED
            ):
                expected_presentation = AxisPresentation.PENDING_OPENING
            elif binding is BindingObservation.VERIFIED:
                expected_presentation = AxisPresentation.ACTIVE_VERIFIED
            elif availability in (Availability.ABSENT, Availability.PARTIAL):
                expected_presentation = AxisPresentation.ACTIVE_UNAVAILABLE
            elif binding in (
                BindingObservation.LENGTH_MISMATCH,
                BindingObservation.COMMITMENT_MISMATCH,
            ):
                expected_presentation = AxisPresentation.ACTIVE_SUBSTITUTED_REJECTED
            else:
                expected_presentation = AxisPresentation.ACTIVE_UNVERIFIABLE
            typed_axis_ok = typed_axis_ok and presentation is expected_presentation
        typed_axis_cases += 1
    suite.explored_traces += typed_axis_cases
    suite.check(
        "typed-axis-closure-v2",
        typed_axis_ok and typed_axis_cases == 54,
        family="binding-observation-distinction",
        detail=f"all {typed_axis_cases} content-class/availability/binding combinations are accepted and classified or rejected explicitly",
        obligation="C0.2f-05",
    )

    # Exhaust every prior/updated verified-opening pair and every delivery order
    # for a bounded two-root diamond.  The incremental implementation is not the
    # fresh oracle and accepts transcript sets rather than tuple order.
    replay_left = event("replay-left", 0, content=ContentClass.REQUIRED)
    replay_right = event(
        "replay-right", 0, credential="peer", content=ContentClass.REQUIRED
    )
    replay_child = event(
        "replay-child",
        1,
        predecessor="replay-left",
        parents=("replay-right",),
        content=ContentClass.REQUIRED,
    )
    replay_events = (replay_left, replay_right, replay_child)
    replay_refs = ("replay-left", "replay-right")
    exhaustive_ok = True
    exhaustive_cases = 0
    replay_orders = delivery_orders(replay_events)
    for prior_mask in range(4):
        for updated_mask in range(4):
            if prior_mask & ~updated_mask:
                continue
            prior_openings = {
                reference: OpeningObservation.VERIFIED
                for index, reference in enumerate(replay_refs)
                if prior_mask & (1 << index)
            }
            updated_openings = {
                reference: OpeningObservation.VERIFIED
                for index, reference in enumerate(replay_refs)
                if updated_mask & (1 << index)
            }
            for prior_order in replay_orders:
                for updated_order in replay_orders:
                    prior_scenario = _scenario(
                        prior_order,
                        prior_openings,
                        genesis=("admin", "peer"),
                    )
                    updated_scenario = _scenario(
                        updated_order,
                        updated_openings,
                        genesis=("admin", "peer"),
                    )
                    incremental = incremental_replay(
                        prior_scenario, updated_scenario
                    )
                    oracle = suite.evaluate(updated_scenario)
                    exhaustive_ok = exhaustive_ok and (
                        incremental.semantic_view() == oracle.semantic_view()
                    )
                    suite.observe(incremental)
                    exhaustive_cases += 1
    suite.explored_traces += exhaustive_cases
    suite.check(
        "c02d-exhaustive-incremental-replay",
        exhaustive_ok and exhaustive_cases == 324,
        family="exhaustive-incremental-replay",
        detail=f"all {exhaustive_cases} bounded opening/delivery combinations equal fresh replay",
        obligation="C0.2f-03",
    )

    selective_a = suite.evaluate(closed)
    selective_b = suite.evaluate(opened)
    converged_a = suite.evaluate(opened)
    suite.check(
        "selective-convergence",
        selective_a.semantic_view() != selective_b.semantic_view()
        and converged_a.semantic_view() == selective_b.semantic_view(),
        family="selective-opening-convergence",
        detail="replicas may diverge on availability and converge on equal sets",
        obligation="C0.2f-13",
    )

    left = event("left", 0, content=ContentClass.REQUIRED)
    right = event("right", 0, credential="peer", content=ContentClass.REQUIRED)
    diamond = event("diamond", 1, predecessor="left", parents=("right",))
    one_open = suite.evaluate(
        _scenario(
            (left, right, diamond),
            {"left": OpeningObservation.VERIFIED},
            genesis=("admin", "peer"),
        )
    )
    suite.check(
        "overlapping-roots",
        one_open.pending_roots == {"right"} and one_open.pending == {"right", "diamond"},
        family="overlapping-root-diamond",
        detail="a descendant releases only after every pending causal root opens",
        obligation="C0.2f-11",
    )

    fork_a = event("fork-a", 0, content=ContentClass.REQUIRED)
    fork_b = event("fork-b", 0, content=ContentClass.REQUIRED)
    forked = suite.evaluate(
        _scenario(
            (fork_a, fork_b),
            {"fork-a": OpeningObservation.VERIFIED},
        )
    )
    suite.check(
        "fork-hole",
        forked.graph.forks == {"fork-a", "fork-b"}
        and forked.pending_roots == {"fork-b"},
        family="fork-required-partial-opening",
        detail="fork evidence is graph-visible while each REQUIRED opening is independent",
        obligation="C0.2f-11",
    )
    fork_child = event("fork-child", 1, predecessor="fork-a")
    fork_descendant = suite.evaluate(
        _scenario(
            (fork_a, fork_b, fork_child),
            {"fork-b": OpeningObservation.VERIFIED},
        )
    )
    suite.check(
        "fork-hole-descendant",
        fork_descendant.outcomes["fork-a"] is Outcome.FORK_EVIDENCE
        and fork_descendant.outcomes["fork-b"] is Outcome.FORK_EVIDENCE
        and fork_descendant.outcomes["fork-child"] is Outcome.FORK_QUARANTINED
        and fork_descendant.pending_roots == {"fork-a"}
        and fork_descendant.pending == {"fork-a", "fork-child"}
        and fork_descendant.fork_quarantined
        and not fork_descendant.applied_order,
        family="fork-required-partial-opening",
        detail="pending membership remains observable while every AP outcome is fork-quarantined",
        obligation="C0.2f-11",
    )

    delayed = incremental_replay(closed, opened)
    suite.observe(delayed)
    suite.check(
        "delayed-reveal",
        delayed.semantic_view() == fresh.semantic_view()
        and delayed.metrics.replayed_event_work == 3,
        family="delayed-reveal",
        detail="a delayed verified opening triggers measured deterministic suffix replay",
    )
    withheld_replica = suite.evaluate(closed)
    supplied_replica = suite.evaluate(opened)
    suite.check(
        "relay-withholding",
        withheld_replica.pending == {"hole", "child"}
        and supplied_replica.pending == set()
        and withheld_replica.outcomes["independent"] is Outcome.APPLIED
        and supplied_replica.outcomes["independent"] is Outcome.APPLIED,
        family="relay-withholding",
        detail="selective opening withholding diverges only the affected subtree and not independent work",
    )

    late_low = event("a-late-low", 0, credential="recovery")
    with_late_low = suite.evaluate(
        replace(
            closed,
            events=closed.events + (late_low,),
            genesis_authority=("admin", "peer", "recovery"),
        )
    )
    suite.check(
        "late-low-reference-sibling",
        with_late_low.pending == pending.pending
        and with_late_low.outcomes["a-late-low"] is Outcome.APPLIED,
        family="late-low-reference-sibling",
        detail="late lower-reference concurrency changes schedule but not the pending causal closure",
    )


def _exercise_authority_and_control(suite: Suite) -> None:
    grant = event("grant-bob", 0, kind=EventKind.GRANT, subject="bob")
    bob_action = event(
        "bob-action",
        0,
        credential="bob",
        parents=("grant-bob",),
        binding_ref="grant-bob",
    )
    authorized = suite.evaluate(_scenario((grant, bob_action)))
    suite.check(
        "bound-and-authorized",
        authorized.outcomes["grant-bob"] is Outcome.APPLIED
        and authorized.outcomes["bob-action"] is Outcome.APPLIED,
        family="authentic-but-unauthorized",
        detail="a K binding and AP grant produce an authorized action",
        obligation="C0.2f-07",
    )

    revoke = event(
        "revoke-bob", 1, predecessor="grant-bob", kind=EventKind.REVOKE, subject="bob"
    )
    old_key = replace(
        bob_action,
        reference="old-key-action",
        sequence=1,
        direct_predecessor="bob-action",
        parents=("revoke-bob",),
    )
    revoked = suite.evaluate(_scenario((grant, bob_action, revoke, old_key)))
    suite.check(
        "post-revocation",
        revoked.outcomes["old-key-action"] is Outcome.POST_REVOCATION,
        family="revoked-old-key",
        detail="causal-past authorized revocation is an AP outcome, not K rejection",
    )

    first_revoke = event(
        "revocation-race-first",
        1,
        predecessor="grant-bob",
        kind=EventKind.REVOKE,
        subject="bob",
    )
    second_revoke = event(
        "a-revocation-race-second",
        2,
        predecessor="revocation-race-first",
        kind=EventKind.REVOKE,
        subject="bob",
    )
    after_first = event(
        "z-revocation-race-action",
        0,
        credential="bob",
        parents=("revocation-race-first",),
        binding_ref="grant-bob",
    )
    multiple_revocations = suite.evaluate(
        _scenario((grant, first_revoke, second_revoke, after_first))
    )
    concurrent_early_revoke = event(
        "a-concurrent-revoke",
        1,
        predecessor="grant-bob",
        kind=EventKind.REVOKE,
        subject="bob",
    )
    concurrent_late_action = event(
        "z-concurrent-action",
        0,
        credential="bob",
        parents=("grant-bob",),
        binding_ref="grant-bob",
    )
    concurrent_early = suite.evaluate(
        _scenario((grant, concurrent_early_revoke, concurrent_late_action))
    )
    concurrent_late_revoke = replace(
        concurrent_early_revoke, reference="z-concurrent-revoke"
    )
    concurrent_early_action = replace(
        concurrent_late_action, reference="a-concurrent-action"
    )
    concurrent_late = suite.evaluate(
        _scenario((grant, concurrent_late_revoke, concurrent_early_action))
    )
    suite.check(
        "c02d-revocation-race",
        multiple_revocations.outcomes["z-revocation-race-action"]
        is Outcome.POST_REVOCATION
        and concurrent_early.outcomes["z-concurrent-action"]
        is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
        and concurrent_late.outcomes["a-concurrent-action"] is Outcome.APPLIED,
        family="revocation-race",
        detail="all causal revocations are retained while concurrent revocation is deterministically AP-adjudicated in either reference order",
    )

    # A K-valid grant issued after its signer was revoked still binds its subject
    # historically, but neither the grant nor the grantee receives AP authority.
    admin_revoke = event(
        "recovery-revokes-admin",
        0,
        credential="recovery",
        kind=EventKind.REVOKE,
        subject="admin",
    )
    bad_grant = event(
        "bad-grant",
        0,
        parents=("recovery-revokes-admin",),
        kind=EventKind.GRANT,
        subject="eve",
    )
    unauthorized_revoke = event(
        "unauthorized-revoke",
        0,
        credential="eve",
        parents=("bad-grant",),
        binding_ref="bad-grant",
        kind=EventKind.REVOKE,
        subject="recovery",
    )
    unauthorized = suite.evaluate(
        _scenario(
            (admin_revoke, bad_grant, unauthorized_revoke),
            genesis=("admin", "recovery"),
        )
    )
    suite.check(
        "unauthorized-revocation",
        unauthorized.outcomes["bad-grant"] is Outcome.POST_REVOCATION
        and unauthorized.outcomes["unauthorized-revoke"]
        is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
        and "unauthorized-revoke" in unauthorized.graph.admitted,
        family="authentic-but-unauthorized",
        detail="binding survives while unauthorized revocation has no AP effect",
        obligation="C0.2f-07",
    )

    eve_hole = event(
        "eve-hole",
        0,
        credential="eve",
        parents=("bad-grant",),
        binding_ref="bad-grant",
        content=ContentClass.REQUIRED,
    )
    independent_policy = event(
        "independent-policy",
        1,
        credential="recovery",
        predecessor="recovery-revokes-admin",
        kind=EventKind.POLICY,
    )
    unauthorized_hole = suite.evaluate(
        _scenario(
            (admin_revoke, bad_grant, eve_hole, independent_policy),
            genesis=("admin", "recovery"),
        )
    )
    suite.check(
        "unauthorized-hole-independent-authority",
        unauthorized_hole.outcomes["eve-hole"] is Outcome.PENDING_OPENING
        and unauthorized_hole.outcomes["independent-policy"] is Outcome.APPLIED
        and unauthorized_hole.pending == {"eve-hole"},
        family="unauthorized-hole-independent-authority",
        detail="an authentic but unauthorized REQUIRED hole cannot freeze independent authority",
        obligation="C0.2f-04",
    )

    hole = event("authority-hole", 0, content=ContentClass.REQUIRED)
    recovery = event(
        "admin-recovery",
        0,
        credential="recovery",
        kind=EventKind.RECOVER,
        subject="bob",
    )
    blocked_rotation = event(
        "blocked-rotation",
        1,
        predecessor="authority-hole",
        kind=EventKind.ROTATE,
        subject="admin",
    )
    authority_projection = suite.evaluate(
        _scenario((hole, recovery, blocked_rotation), genesis=("admin", "recovery"))
    )
    suite.check(
        "independent-recovery",
        authority_projection.outcomes["admin-recovery"] is Outcome.APPLIED
        and authority_projection.outcomes["blocked-rotation"] is Outcome.PENDING_ANCESTOR,
        family="self-rotation-and-admin-recovery",
        detail="a control descendant waits while independent recovery applies",
    )
    suite.check(
        "rotation-recovery-outside-hole",
        authority_projection.pending == {"authority-hole", "blocked-rotation"}
        and authority_projection.outcomes["admin-recovery"] is Outcome.APPLIED,
        family="rotation-recovery-outside-hole",
        detail="independent recovery applies while self-rotation stays in the pending subtree",
    )
    independent_revoke = event(
        "independent-revoke",
        0,
        credential="recovery",
        kind=EventKind.REVOKE,
        subject="admin",
    )
    blocked_revoke = event(
        "blocked-revoke",
        1,
        predecessor="authority-hole",
        kind=EventKind.REVOKE,
        subject="recovery",
    )
    revocation_holes = suite.evaluate(
        _scenario(
            (hole, independent_revoke, blocked_revoke),
            genesis=("admin", "recovery"),
        )
    )
    suite.check(
        "revocation-hole-interactions",
        revocation_holes.outcomes["independent-revoke"] is Outcome.APPLIED
        and revocation_holes.outcomes["blocked-revoke"] is Outcome.PENDING_ANCESTOR,
        family="revocation-hole-interactions",
        detail="a concurrent revocation applies while a revocation descending from the hole stays pending",
    )
    suite.check(
        "late-authority-replay",
        authorized.outcomes["bob-action"] is Outcome.APPLIED
        and revoked.outcomes["bob-action"] is Outcome.APPLIED
        and revoked.outcomes["old-key-action"] is Outcome.POST_REVOCATION
        and "old-key-action" in revoked.graph.admitted,
        family="late-authority-replay",
        detail="late transcript admission extends K evidence and replays AP authority without K-removing old-key descendants",
    )

    bad_control = event(
        "bad-control",
        0,
        kind=EventKind.POLICY,
        content=ContentClass.REQUIRED,
    )
    structural = suite.evaluate(_scenario((bad_control,)))
    suite.check(
        "control-none-only",
        structural.outcomes["bad-control"] is Outcome.STRUCTURAL_REJECTION,
        family="content-bearing-control-rejected",
        detail="control content is rejected before commitment or AP evaluation",
    )
    false_control = event(
        "false-control",
        0,
        role=EventRole.CONTROL,
        kind=EventKind.ACTION,
        content=ContentClass.REQUIRED,
    )
    false_control_projection = suite.evaluate(_scenario((false_control,)))
    suite.check(
        "control-role-rejects-ordinary-kind",
        false_control_projection.outcomes["false-control"]
        is Outcome.STRUCTURAL_REJECTION
        and "false-control" not in false_control_projection.pending,
        family="content-bearing-control-rejected",
        detail="CONTROL role on an ordinary kind is rejected before it can become a pending root",
    )

    pending_grant = event(
        "pending-grant",
        1,
        predecessor="authority-hole",
        kind=EventKind.GRANT,
        subject="eve",
    )
    eve = event(
        "eve-action",
        0,
        credential="eve",
        parents=("pending-grant",),
        binding_ref="pending-grant",
    )
    pending_chain = suite.evaluate(_scenario((hole, pending_grant, eve)))
    suite.check(
        "grant-chain-pending",
        {"pending-grant", "eve-action"} <= pending_chain.graph.ancestors.keys()
        and pending_chain.pending == {"authority-hole", "pending-grant", "eve-action"},
        family="grant-behind-hole",
        detail="the grantee chain is K-valid but causally pending",
    )

    admitted_non_ancestor_grant = event(
        "a-non-ancestor-grant",
        0,
        kind=EventKind.GRANT,
        subject="eve",
    )
    missing_binding = event(
        "z-missing-binding",
        0,
        credential="eve",
        binding_ref="a-non-ancestor-grant",
    )
    invalid_binding = suite.evaluate(
        _scenario((admitted_non_ancestor_grant, missing_binding))
    )
    suite.check(
        "structural-grant-ancestry-invalid",
        invalid_binding.outcomes["z-missing-binding"] is Outcome.INVALID
        and "a-non-ancestor-grant" in invalid_binding.graph.admitted
        and "z-missing-binding" not in invalid_binding.graph.deferred
        and "z-missing-binding" not in invalid_binding.applied_order,
        family="authentic-but-unauthorized",
        detail="an already admitted binding outside causal ancestry is terminal INVALID, not retriable transcript deferral",
        obligation="C0.2f-07",
    )

    sole_hole = event("sole-hole", 0, content=ContentClass.REQUIRED)
    sole_control = event(
        "sole-control",
        1,
        predecessor="sole-hole",
        kind=EventKind.POLICY,
    )
    sole_projection = suite.evaluate(_scenario((sole_hole, sole_control)))
    suite.check(
        "sole-authority-self-lockout-exact",
        sole_projection.pending == {"sole-hole", "sole-control"}
        and not sole_projection.applied_order,
        family="sole-authority-self-lockout",
        detail="with one genesis authority and no alternate branch, its own unopened REQUIRED prefix holds its control descendant pending",
    )

    unauthorized_target = event(
        "unauthorized-target",
        0,
        credential="peer",
        content=ContentClass.DETACHABLE,
    )
    unauthorized_remove = event(
        "unauthorized-remove",
        0,
        credential="eve",
        parents=("bad-grant", "unauthorized-target"),
        binding_ref="bad-grant",
        kind=EventKind.REMOVE,
        target="unauthorized-target",
        commitment="commitment:unauthorized-target",
    )
    unauthorized_removal = suite.evaluate(
        _scenario(
            (admin_revoke, bad_grant, unauthorized_target, unauthorized_remove),
            genesis=("admin", "recovery", "peer"),
        )
    )
    suite.check(
        "direct-unauthorized-remove",
        unauthorized_removal.outcomes["unauthorized-remove"]
        is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
        and not unauthorized_removal.removed_targets,
        family="authentic-but-unauthorized",
        detail="an authenticated but unauthorized REMOVE has no retention effect",
        obligation="C0.2f-07",
    )


def _exercise_security_remediation(suite: Suite) -> None:
    """Exercise the review counterexamples and the bounded interim containment."""

    revoked_admin = event(
        "a-revoke-admin",
        0,
        credential="recovery",
        kind=EventKind.REVOKE,
        subject="admin",
    )
    revoked_fork_left = event("b-revoked-fork-left", 0)
    revoked_fork_right = event("c-revoked-fork-right", 0)
    revoked_fork_scenario = _scenario(
        (revoked_admin, revoked_fork_left, revoked_fork_right),
        genesis=("admin", "recovery"),
    )
    revoked_fork, converged, count, trace = _delivery_convergence(
        suite, revoked_fork_scenario
    )
    suite.check(
        "revoked-key-fork-quarantines",
        converged
        and count == 6
        and revoked_fork.fork_quarantined
        and revoked_fork.graph.forks
        == {"b-revoked-fork-left", "c-revoked-fork-right"}
        and not revoked_fork.applied_order
        and not revoked_fork.authorized_credentials
        and not revoked_fork.removed_targets
        and not frontier_is_producible(
            revoked_fork_scenario, ("a-revoke-admin",)
        ),
        family="fork-quarantine",
        detail="a holder of revoked key material can inject fork evidence but can only quarantine the v0 AP context",
        trace=trace,
    )

    honest_succession = event(
        "g-succ",
        0,
        kind=EventKind.GRANT,
        subject="succ",
    )
    honest_self_revoke = event(
        "self-revoke",
        1,
        predecessor="g-succ",
        kind=EventKind.REVOKE,
        subject="admin",
    )
    attacker_zero = event("zz-a0", 0)
    attacker_one = event("zz-a1", 1, predecessor="zz-a0")
    attacker_grant = event(
        "zz-a2",
        2,
        predecessor="zz-a1",
        kind=EventKind.GRANT,
        subject="evil",
    )
    attacker_action = event(
        "zz-evil0",
        0,
        credential="evil",
        parents=("zz-a2",),
        binding_ref="zz-a2",
    )
    takeover_scenario = _scenario(
        (
            honest_succession,
            honest_self_revoke,
            attacker_zero,
            attacker_one,
            attacker_grant,
            attacker_action,
        )
    )
    takeover, converged, count, trace = _delivery_convergence(
        suite, takeover_scenario
    )
    suite.check(
        "retired-genesis-takeover-contained",
        converged
        and count == MAX_DELIVERY_PERMUTATIONS
        and takeover.fork_quarantined
        and takeover.graph.forks
        == {"g-succ", "self-revoke", "zz-a0", "zz-a1"}
        and takeover.outcomes["zz-a2"] is Outcome.FORK_QUARANTINED
        and takeover.outcomes["zz-evil0"] is Outcome.FORK_QUARANTINED
        and not takeover.applied_order
        and not takeover.authorized_credentials,
        family="fork-quarantine",
        detail="forking a succession and self-revocation cannot resurrect the retired authority or mint an attacker successor",
        trace=trace,
    )

    member_grant = event(
        "grant-member",
        0,
        kind=EventKind.GRANT,
        subject="member",
    )
    member_left = event(
        "member-left",
        0,
        credential="member",
        parents=("grant-member",),
        binding_ref="grant-member",
    )
    member_right = replace(member_left, reference="member-right")
    member_control = event(
        "member-control",
        1,
        credential="member",
        predecessor="member-left",
        binding_ref="grant-member",
        kind=EventKind.POLICY,
    )
    independent_policy = event(
        "recovery-policy",
        0,
        credential="recovery",
        kind=EventKind.POLICY,
    )
    ordinary_fork_scenario = _scenario(
        (
            member_grant,
            member_left,
            member_right,
            member_control,
            independent_policy,
        ),
        genesis=("admin", "recovery"),
    )
    ordinary_fork, converged, count, trace = _delivery_convergence(
        suite, ordinary_fork_scenario
    )
    suite.check(
        "ordinary-fork-quarantines-independent-control",
        converged
        and count == 120
        and ordinary_fork.fork_quarantined
        and ordinary_fork.outcomes["member-left"] is Outcome.FORK_EVIDENCE
        and ordinary_fork.outcomes["member-right"] is Outcome.FORK_EVIDENCE
        and ordinary_fork.outcomes["member-control"]
        is Outcome.FORK_QUARANTINED
        and ordinary_fork.outcomes["recovery-policy"]
        is Outcome.FORK_QUARANTINED
        and not ordinary_fork.authorized_credentials,
        family="fork-quarantine",
        detail="even a lowest-privilege ordinary fork terminally quarantines independent control work in the interim profile",
        trace=trace,
    )

    admin_left = event("admin-left", 0)
    admin_right = event("admin-right", 0)
    peer_left = event("peer-left", 0, credential="peer")
    peer_right = event("peer-right", 0, credential="peer")
    double_fork_scenario = _scenario(
        (admin_left, admin_right, peer_left, peer_right),
        genesis=("admin", "peer"),
    )
    double_fork, converged, count, trace = _delivery_convergence(
        suite, double_fork_scenario
    )
    suite.check(
        "two-equivocators-one-quarantine",
        converged
        and count == 24
        and double_fork.fork_quarantined
        and double_fork.graph.forks
        == {"admin-left", "admin-right", "peer-left", "peer-right"}
        and not double_fork.applied_order,
        family="fork-quarantine",
        detail="multiple equivocators still produce one order-independent whole-context quarantine",
        trace=trace,
    )

    pending_left = event(
        "pending-left", 0, content=ContentClass.REQUIRED
    )
    pending_right = event(
        "pending-right", 0, content=ContentClass.REQUIRED
    )
    pending_child = event(
        "pending-child", 1, predecessor="pending-left"
    )
    pending_fork_prior = _scenario(
        (pending_left, pending_right, pending_child),
        {"pending-right": OpeningObservation.VERIFIED},
    )
    pending_fork_updated = replace(
        pending_fork_prior,
        opening_observations={
            "pending-left": OpeningObservation.VERIFIED,
            "pending-right": OpeningObservation.VERIFIED,
        },
    )
    pending_before = suite.evaluate(pending_fork_prior)
    pending_after = incremental_replay(
        pending_fork_prior, pending_fork_updated
    )
    pending_fresh = suite.evaluate(pending_fork_updated)
    suite.check(
        "fork-pending-late-reveal",
        pending_before.fork_quarantined
        and pending_before.pending_roots == {"pending-left"}
        and pending_before.pending == {"pending-left", "pending-child"}
        and pending_after.semantic_view() == pending_fresh.semantic_view()
        and pending_after.fork_quarantined
        and not pending_after.pending
        and pending_after.metrics.earliest_replay_boundary is None
        and pending_after.metrics.replayed_event_work == 0,
        family="fork-quarantine",
        detail="opening acquisition changes observable pending sets but never replays or lifts a fixed-transcript fork quarantine",
        obligation="C0.2f-11",
    )

    grant_first = event(
        "a-evil-grant",
        0,
        kind=EventKind.GRANT,
        subject="evil",
    )
    revoke_last = event(
        "z-admin-revoke",
        0,
        credential="recovery",
        kind=EventKind.REVOKE,
        subject="admin",
    )
    evil_first_action = event(
        "b-evil-action",
        0,
        credential="evil",
        parents=("a-evil-grant",),
        binding_ref="a-evil-grant",
    )
    grant_first_scenario = _scenario(
        (grant_first, revoke_last, evil_first_action),
        genesis=("admin", "recovery"),
    )
    grant_first_projection, grant_first_converged, grant_first_count, first_trace = (
        _delivery_convergence(suite, grant_first_scenario)
    )

    revoke_first = replace(revoke_last, reference="a-admin-revoke")
    grant_last = replace(grant_first, reference="z-evil-grant")
    evil_last_action = replace(
        evil_first_action,
        reference="zz-evil-action",
        parents=("z-evil-grant",),
        binding_ref="z-evil-grant",
    )
    revoke_first_scenario = _scenario(
        (revoke_first, grant_last, evil_last_action),
        genesis=("admin", "recovery"),
    )
    revoke_first_projection, revoke_first_converged, revoke_first_count, second_trace = (
        _delivery_convergence(suite, revoke_first_scenario)
    )
    suite.check(
        "concurrent-grant-revoke-both-reference-orders",
        grant_first_converged
        and revoke_first_converged
        and grant_first_count == 6
        and revoke_first_count == 6
        and not grant_first_projection.graph.forks
        and not revoke_first_projection.graph.forks
        and grant_first_projection.outcomes["a-evil-grant"] is Outcome.APPLIED
        and grant_first_projection.outcomes["b-evil-action"] is Outcome.APPLIED
        and grant_first_projection.authorized_credentials == {"evil", "recovery"}
        and revoke_first_projection.outcomes["z-evil-grant"]
        is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
        and revoke_first_projection.outcomes["zz-evil-action"]
        is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
        and revoke_first_projection.authorized_credentials == {"recovery"},
        family="fork-free-authority-laundering-nonclaim",
        detail="v0 intentionally preserves the executable counterexample: a concurrent grant can survive revocation in one grindable reference order; C0.2j is mandatory",
        trace=first_trace or second_trace,
    )

    outer = event("nested-outer", 0, content=ContentClass.REQUIRED)
    inner = event(
        "nested-inner",
        1,
        predecessor="nested-outer",
        content=ContentClass.REQUIRED,
    )
    nested_prior = _scenario((outer, inner))
    nested_updated = replace(
        nested_prior,
        opening_observations={"nested-inner": OpeningObservation.VERIFIED},
    )
    nested_prior_projection = suite.evaluate(nested_prior)
    nested_updated_projection = incremental_replay(nested_prior, nested_updated)
    nested_oracle = suite.evaluate(nested_updated)
    suite.check(
        "nested-root-outcome-replay",
        nested_prior_projection.pending == nested_oracle.pending
        and nested_prior_projection.pending_roots
        != nested_oracle.pending_roots
        and nested_updated_projection.semantic_view()
        == nested_oracle.semantic_view()
        and nested_updated_projection.outcomes["nested-inner"]
        is Outcome.PENDING_ANCESTOR
        and nested_updated_projection.metrics.earliest_replay_boundary == 1,
        family="nested-required-root-replay",
        detail="a root-only change invalidates the reusable suffix even when pending membership is unchanged",
        obligation="C0.2f-03",
    )

    cross_outer = event(
        "cross-outer", 0, content=ContentClass.REQUIRED
    )
    cross_inner = event(
        "cross-inner",
        0,
        credential="peer",
        parents=("cross-outer",),
        content=ContentClass.REQUIRED,
    )
    cross_prior = _scenario(
        (cross_outer, cross_inner), genesis=("admin", "peer")
    )
    cross_updated = replace(
        cross_prior,
        opening_observations={"cross-inner": OpeningObservation.VERIFIED},
    )
    cross_incremental = incremental_replay(cross_prior, cross_updated)
    cross_oracle = suite.evaluate(cross_updated)
    suite.check(
        "cross-credential-nested-root-replay",
        cross_incremental.semantic_view() == cross_oracle.semantic_view()
        and cross_incremental.outcomes["cross-inner"]
        is Outcome.PENDING_ANCESTOR,
        family="nested-required-root-replay",
        detail="root-delta replay is independent of the credentials that authored the nested REQUIRED events",
        obligation="C0.2f-03",
    )

    prefix_grant = event(
        "a-prefix-grant", 0, kind=EventKind.GRANT, subject="bob"
    )
    prefix_revoke = event(
        "b-prefix-revoke",
        1,
        predecessor="a-prefix-grant",
        kind=EventKind.REVOKE,
        subject="bob",
    )
    prefix_hole = event(
        "c-prefix-hole",
        0,
        credential="peer",
        content=ContentClass.REQUIRED,
    )
    prefix_bob = event(
        "d-prefix-bob",
        0,
        credential="bob",
        parents=("a-prefix-grant", "c-prefix-hole"),
        binding_ref="a-prefix-grant",
    )
    prefix_prior = _scenario(
        (prefix_grant, prefix_revoke, prefix_hole, prefix_bob),
        genesis=("admin", "peer"),
    )
    prefix_updated = replace(
        prefix_prior,
        opening_observations={"c-prefix-hole": OpeningObservation.VERIFIED},
    )
    prefix_incremental = incremental_replay(prefix_prior, prefix_updated)
    prefix_oracle = suite.evaluate(prefix_updated)
    suite.check(
        "prefix-revocation-reconstructed",
        prefix_incremental.semantic_view() == prefix_oracle.semantic_view()
        and prefix_incremental.outcomes["d-prefix-bob"]
        is Outcome.AUTHENTIC_BUT_UNAUTHORIZED,
        family="nested-required-root-replay",
        detail="incremental suffix replay reconstructs revocation state from the reused prefix",
        obligation="C0.2f-10",
    )

    prefix_target = event(
        "a-prefix-target",
        0,
        credential="peer",
        content=ContentClass.DETACHABLE,
    )
    prefix_remove = event(
        "b-prefix-remove",
        0,
        parents=("a-prefix-target",),
        kind=EventKind.REMOVE,
        target="a-prefix-target",
        commitment="commitment:a-prefix-target",
    )
    removal_hole = event(
        "c-removal-hole",
        0,
        credential="recovery",
        content=ContentClass.REQUIRED,
    )
    repeat_remove = event(
        "d-prefix-repeat-remove",
        1,
        predecessor="b-prefix-remove",
        parents=("c-removal-hole",),
        kind=EventKind.REMOVE,
        target="a-prefix-target",
        commitment="commitment:a-prefix-target",
    )
    removal_prior = _scenario(
        (prefix_target, prefix_remove, removal_hole, repeat_remove),
        genesis=("admin", "peer", "recovery"),
    )
    removal_updated = replace(
        removal_prior,
        opening_observations={"c-removal-hole": OpeningObservation.VERIFIED},
    )
    removal_incremental = incremental_replay(removal_prior, removal_updated)
    removal_oracle = suite.evaluate(removal_updated)
    suite.check(
        "prefix-removal-reconstructed",
        removal_incremental.semantic_view() == removal_oracle.semantic_view()
        and removal_incremental.outcomes["d-prefix-repeat-remove"]
        is Outcome.ALREADY_REMOVED,
        family="nested-required-root-replay",
        detail="incremental suffix replay reconstructs removal state from the reused prefix",
        obligation="C0.2f-06",
    )


def _exercise_collisions(suite: Suite) -> None:
    first = event("grant-1", 0, kind=EventKind.GRANT, subject="bob")
    second = event(
        "grant-2", 0, credential="peer", kind=EventKind.GRANT, subject="bob"
    )
    revoke_peer = event(
        "revoke-peer", 0, kind=EventKind.REVOKE, subject="peer"
    )
    revoked_peer_grant = event(
        "revoked-peer-grant",
        0,
        credential="peer",
        parents=("revoke-peer",),
        kind=EventKind.GRANT,
        subject="bob",
    )
    variants = {
        "before-sequence-zero": (second, first),
        "with-attacker-descendant": (
            first,
            second,
            event(
                "bob-0",
                0,
                credential="bob",
                parents=("grant-1",),
                binding_ref="grant-1",
            ),
        ),
        "after-existing-chain": (
            first,
            event(
                "bob-existing",
                0,
                credential="bob",
                parents=("grant-1",),
                binding_ref="grant-1",
            ),
            second,
        ),
        "genesis-identifier": (
            event("grant-admin", 0, kind=EventKind.GRANT, subject="admin"),
        ),
        "revoked-credential": (first, revoke_peer, revoked_peer_grant),
    }
    for name, events in variants.items():
        suite.expect_error(
            f"collision-{name}",
            Outcome.CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED.value,
            lambda events=events: suite.evaluate(
                _scenario(events, genesis=("admin", "peer"))
            ),
            family="credential-identifier-collision",
            detail="whole-set collision rejection is order-independent and makes no continuation claim",
        )
        reverse = tuple(reversed(events))
        suite.expect_error(
            f"collision-{name}-reverse",
            Outcome.CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED.value,
            lambda reverse=reverse: suite.evaluate(
                _scenario(reverse, genesis=("admin", "peer"))
            ),
            family="credential-identifier-collision",
            detail="arrival order cannot select a preferred binding",
        )

    suite.expect_error(
        "collision-duplicate-genesis-authority",
        Outcome.CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED.value,
        lambda: suite.evaluate(
            _scenario((), genesis=("admin", "admin"))
        ),
        family="credential-identifier-collision",
        detail="the O-07 genesis abstraction cannot bind one identifier twice",
    )


def _exercise_retention_checkpoint_and_bounds(suite: Suite) -> None:
    detachable = event("detachable", 0, content=ContentClass.DETACHABLE)
    remove = event(
        "remove", 1, predecessor="detachable", kind=EventKind.REMOVE,
        target="detachable", commitment="commitment:detachable"
    )
    removed = suite.evaluate(_scenario((detachable, remove)))
    suite.check(
        "detachable-removal",
        removed.removed_targets == {"detachable"},
        family="detachable-removal-in-pending-subtree",
        detail="authorized DETACHABLE removal is replay-derived",
        obligation="C0.2f-06",
    )
    presentation_states = {
        removed_presentation_state(removed=True, observation=observation)
        for observation in (
            OpeningObservation.VERIFIED,
            OpeningObservation.OPENING_MISSING,
            OpeningObservation.LENGTH_MISMATCH,
            OpeningObservation.COMMITMENT_MISMATCH,
        )
    }
    suite.check(
        "post-removal-presentation",
        presentation_states
        == {
            PresentationState.REMOVED_PRESENTED_VERIFIED,
            PresentationState.REMOVED_PRESENTED_UNVERIFIABLE,
            PresentationState.REMOVED_SUBSTITUTED_REJECTED,
        }
        and removed.removed_targets == {"detachable"},
        family="detachable-removal-in-pending-subtree",
        detail="post-removal verified, unverifiable and substituted presentations remain distinct without changing retention",
        obligation="C0.2f-08",
    )

    subtree_hole = event(
        "subtree-hole", 0, credential="peer", content=ContentClass.REQUIRED
    )
    subtree_target = replace(
        detachable,
        reference="subtree-target",
        sequence=1,
        direct_predecessor="detachable",
        parents=("subtree-hole",),
        descriptor="descriptor:subtree-target",
        commitment="commitment:subtree-target",
    )
    subtree_remove = replace(
        remove,
        reference="subtree-remove",
        sequence=2,
        direct_predecessor="subtree-target",
        target_reference="subtree-target",
        target_commitment="commitment:subtree-target",
    )
    subtree_scenario = _scenario(
        (detachable, subtree_hole, subtree_target, subtree_remove),
        genesis=("admin", "peer"),
    )
    subtree_pending = suite.evaluate(subtree_scenario)
    subtree_opened = suite.evaluate(
        replace(
            subtree_scenario,
            opening_observations={"subtree-hole": OpeningObservation.VERIFIED},
        )
    )
    suite.check(
        "detachable-removal-in-pending-subtree",
        subtree_pending.pending
        == {"subtree-hole", "subtree-target", "subtree-remove"}
        and not subtree_pending.removed_targets
        and subtree_opened.removed_targets == {"subtree-target"},
        family="detachable-removal-in-pending-subtree",
        detail="a DETACHABLE removal inside a pending subtree applies only after every causal root opens",
        obligation="C0.2f-06",
    )

    # The initial fold authorizes Bob's removal.  A late-admitted revocation is
    # concurrent with that removal but sorts before it under this symbolic AP
    # profile, so replay withdraws authority and restores retention.
    grant_bob = event("grant-bob-late", 0, kind=EventKind.GRANT, subject="bob")
    late_target = event(
        "late-target", 0, credential="peer", content=ContentClass.DETACHABLE
    )
    bob_remove = event(
        "z-bob-remove",
        0,
        credential="bob",
        parents=("grant-bob-late", "late-target"),
        binding_ref="grant-bob-late",
        kind=EventKind.REMOVE,
        target="late-target",
        commitment="commitment:late-target",
    )
    before_late = suite.evaluate(
        _scenario((late_target, grant_bob, bob_remove), genesis=("admin", "peer"))
    )
    late_revoke = event(
        "a-late-revoke",
        1,
        predecessor="grant-bob-late",
        kind=EventKind.REVOKE,
        subject="bob",
    )
    after_late = suite.evaluate(
        _scenario(
            (late_target, grant_bob, bob_remove, late_revoke),
            genesis=("admin", "peer"),
        )
    )
    suite.check(
        "late-removal-reverses",
        before_late.removed_targets == {"late-target"}
        and not after_late.removed_targets
        and after_late.outcomes["z-bob-remove"]
        is Outcome.AUTHENTIC_BUT_UNAUTHORIZED,
        family="late-removal-authority-replay",
        detail="late concurrent revocation reversibly changes AP authority under full replay",
        obligation="C0.2f-10",
    )

    required = event("required", 0, content=ContentClass.REQUIRED)
    remove_required = event(
        "remove-required", 1, predecessor="required", kind=EventKind.REMOVE,
        target="required", commitment="commitment:required"
    )
    attempted = suite.evaluate(
        _scenario(
            (required, remove_required),
            {"required": OpeningObservation.VERIFIED},
        )
    )
    suite.check(
        "required-removal",
        attempted.outcomes["remove-required"] is Outcome.REMOVAL_INAPPLICABLE,
        family="required-removal-inapplicable",
        detail="REQUIRED retention is active and removal is inapplicable",
        obligation="C0.2f-06",
    )

    none_target = event("none-target", 0)
    remove_none = event(
        "remove-none",
        1,
        predecessor="none-target",
        kind=EventKind.REMOVE,
        target="none-target",
        commitment="commitment:none-target",
    )
    none_removal = suite.evaluate(_scenario((none_target, remove_none)))

    late_detachable = event(
        "late-detachable", 0, credential="peer", content=ContentClass.DETACHABLE
    )
    late_directive = event(
        "late-directive",
        0,
        kind=EventKind.REMOVE,
        target="late-detachable",
        commitment="commitment:late-detachable",
    )
    late_removal = suite.evaluate(
        _scenario((late_directive, late_detachable), genesis=("admin", "peer"))
    )

    repeat_remove = event(
        "repeat-remove",
        2,
        predecessor="remove",
        kind=EventKind.REMOVE,
        target="detachable",
        commitment="commitment:detachable",
    )
    repeated_removal = suite.evaluate(
        _scenario((detachable, remove, repeat_remove))
    )
    suite.check(
        "removal-target-cases",
        none_removal.outcomes["remove-none"] is Outcome.REMOVAL_INAPPLICABLE
        and late_removal.outcomes["late-directive"]
        is Outcome.REMOVAL_INAPPLICABLE
        and repeated_removal.outcomes["repeat-remove"]
        is Outcome.ALREADY_REMOVED,
        family="required-removal-inapplicable",
        detail="NONE, non-ancestral late and already-removed targets are deterministically distinguished",
        obligation="C0.2f-14",
    )

    required_peer = replace(required, credential_id="peer", binding_ref="genesis:peer")
    behind = replace(
        remove,
        reference="remove-behind",
        direct_predecessor="detachable",
        parents=("required",),
    )
    behind_result = suite.evaluate(
        _scenario((required_peer, detachable, behind), genesis=("admin", "peer"))
    )
    suite.check(
        "removal-behind-hole",
        behind_result.outcomes["remove-behind"] is Outcome.PENDING_ANCESTOR,
        family="removal-behind-hole",
        detail="control in a pending subtree cannot bypass its root",
        obligation="C0.2f-14",
    )

    closure_hole = event(
        "closure-hole",
        0,
        content=ContentClass.REQUIRED,
    )
    independent_closure = event(
        "independent-closure",
        0,
        credential="recovery",
        kind=EventKind.CLOSURE,
    )
    closure_projection = suite.evaluate(
        _scenario(
            (closure_hole, independent_closure),
            genesis=("admin", "recovery"),
        )
    )
    suite.check(
        "independent-closure-outside-pending-subtree",
        closure_projection.outcomes["closure-hole"] is Outcome.PENDING_OPENING
        and closure_projection.outcomes["independent-closure"] is Outcome.APPLIED
        and closure_projection.applied_order == ("independent-closure",),
        family="closure-outside-hole",
        detail="an independent symbolic CLOSURE applies outside a pending REQUIRED subtree",
        obligation="C0.2f-04",
    )

    stale = suite.evaluate(_scenario((detachable,), checkpoint_only=("revocation-x",)))
    suite.check(
        "checkpoint-whole-stale",
        stale.outcomes["detachable"] is Outcome.STALE_EVIDENCE
        and stale.stale_evidence
        and not stale.applied_order
        and not stale.authorized_credentials
        and not stale.removed_targets,
        family="checkpoint-authority-staleness",
        detail="checkpoint-only authority evidence makes the whole projection stale",
        obligation="C0.2f-12",
    )
    unrelated_checkpoint = suite.evaluate(
        _scenario(
            (event("unrelated-checkpoint", 0),),
            checkpoint_evidence=("unrelated",),
            replay_dependencies=("required-authority",),
        )
    )
    suite.check(
        "checkpoint-staleness-nonclaim",
        stale.outcomes["detachable"] is Outcome.STALE_EVIDENCE
        and unrelated_checkpoint.outcomes["unrelated-checkpoint"]
        is Outcome.APPLIED,
        family="checkpoint-staleness-nonclaim",
        detail="checkpoint evidence never substitutes for a matching replay dependency and unrelated evidence does not stale the projection",
    )
    stale_fork_scenario = _scenario(
        (
            event("stale-fork-left", 0),
            event("stale-fork-right", 0),
            event("stale-fork-independent", 0, credential="recovery"),
        ),
        genesis=("admin", "recovery"),
        checkpoint_only=("withheld-authority-transcript",),
    )
    stale_fork = suite.evaluate(stale_fork_scenario)
    suite.check(
        "stale-outcome-precedes-but-does-not-hide-terminal-fork",
        stale_fork.stale_evidence
        and stale_fork.fork_quarantined
        and all(
            outcome is Outcome.STALE_EVIDENCE
            for reference, outcome in stale_fork.outcomes.items()
            if reference in stale_fork.graph.admitted
        )
        and not stale_fork.applied_order
        and not stale_fork.authorized_credentials
        and not stale_fork.removed_targets
        and not frontier_is_producible(
            stale_fork_scenario, ("stale-fork-independent",)
        ),
        family="fork-stale-precedence",
        detail="STALE_EVIDENCE owns AP outcomes while the permanent fork quarantine remains visible and producer-ineligible",
        obligation="C0.2f-12",
    )
    checkpoint_hole = _scenario(
        (event("checkpoint-hole", 0, content=ContentClass.REQUIRED),),
        checkpoint_only=("checkpoint-hole",),
    )
    retained_checkpoint = suite.evaluate(checkpoint_hole)
    suite.check(
        "checkpoint-pending-producer",
        retained_checkpoint.outcomes["checkpoint-hole"]
        is Outcome.PENDING_OPENING
        and not retained_checkpoint.stale_evidence
        and not frontier_is_producible(checkpoint_hole, ("checkpoint-hole",)),
        family="checkpoint-pending-producer",
        detail="retained checkpoint evidence is not checkpoint-only and cannot make a pending frontier producer eligible",
        obligation="C0.2f-02",
    )
    suite.check(
        "checkpoint-retained-live",
        retained_checkpoint.outcomes["checkpoint-hole"]
        is Outcome.PENDING_OPENING
        and not retained_checkpoint.stale_evidence,
        family="checkpoint-retained-live",
        detail="an admitted live transcript is not stale merely because checkpoint evidence also names it",
        obligation="C0.2f-12",
    )

    flood = tuple(
        event(
            f"hole-{index}",
            index,
            predecessor=None if index == 0 else f"hole-{index - 1}",
            content=ContentClass.REQUIRED,
        )
        for index in range(MAX_EVENTS)
    )
    flooded = suite.evaluate(_scenario(flood))
    suite.observe(flooded)
    counts = Counter(event.credential_id for event in flood if event.reference in flooded.pending_roots)
    suite.check(
        "bounded-hole-count",
        flooded.metrics.pending_roots == MAX_EVENTS and counts == {"admin": MAX_EVENTS},
        family="bounded-hole-flood",
        detail="a non-forking author chain can contain the bounded maximum of independently missing REQUIRED openings",
        obligation="C0.2f-16",
    )
    suite.expect_error(
        "event-bound",
        "MODEL_BOUND_EXCEEDED",
        lambda: suite.evaluate(_scenario(flood + (event("overflow", MAX_EVENTS),))),
        family="resource-bound",
        detail="event inflation rejects before exploration",
        obligation="C0.2f-16",
    )

    suite.check(
        "custody-frontier",
        not frontier_is_producible(_scenario(flood), ("hole-9",))
        and frontier_is_producible(
            _scenario(
                flood,
                {
                    item.reference: OpeningObservation.VERIFIED
                    for item in flood
                },
            ),
            ("hole-9",),
        ),
        family="custody-frontier-obligation",
        detail="an honest frontier cannot reference locally pending REQUIRED ancestry",
        obligation="C0.2f-09",
    )
    fresh_missing = suite.evaluate(_scenario(flood))
    fresh_complete = suite.evaluate(
        _scenario(
            flood,
            {
                item.reference: OpeningObservation.VERIFIED
                for item in flood
            },
        )
    )
    suite.check(
        "fresh-replica-required-openings",
        not fresh_missing.applied_order
        and fresh_complete.applied_order
        == tuple(item.reference for item in flood),
        family="custody-frontier-obligation",
        detail="fresh replay applies the in-horizon chain only when every REQUIRED opening is locally verified",
        obligation="C0.2f-09",
    )

    suite.check(
        "target-prefix-abandonment-rejected",
        behind_result.outcomes["remove-behind"] is Outcome.PENDING_ANCESTOR
        and attempted.outcomes["remove-required"] is Outcome.REMOVAL_INAPPLICABLE,
        family="target-prefix-abandonment-rejected",
        detail="neither target-prefix abandonment nor a pending control bypass exists",
    )
    missing_transcript = suite.evaluate(
        _scenario((event("missing-transcript", 1, predecessor="absent"),))
    )
    suite.check(
        "transcript-deferred-distinction",
        missing_transcript.outcomes["missing-transcript"] is Outcome.DEFERRED
        and behind_result.outcomes["required"] is Outcome.PENDING_OPENING,
        family="transcript-deferred-distinction",
        detail="missing K transcript ancestry is DEFERRED and distinct from an opening-missing pending root",
    )

    profile_parameters = tuple(
        signature(current_profile_symbolic_commitment).parameters
    )
    expected_profile_parameters = (
        "context_token",
        "content_type",
        "exact_length",
        "shape",
        "content_symbol",
        "opening_randomizer",
    )
    left_application_identity = ("credential-a", 0)
    right_application_identity = ("credential-b", 7)
    shared_profile_inputs = {
        "context_token": "ctx",
        "content_type": "type",
        "exact_length": 4,
        "shape": "single",
        "content_symbol": "data",
        "opening_randomizer": "randomizer",
    }
    copied_a = current_profile_symbolic_commitment(**shared_profile_inputs)
    copied_b = current_profile_symbolic_commitment(**shared_profile_inputs)
    suite.check(
        "copy-nonprotection",
        left_application_identity != right_application_identity
        and profile_parameters == expected_profile_parameters
        and not {
            "credential_id",
            "credential_reference",
            "author_sequence",
        }
        & set(profile_parameters)
        and copied_a == copied_b
        and copied_a[0] == CURRENT_CTX_OCTETS,
        family="current-profile-copy-nonprotection",
        detail="distinct credential/sequence identities are absent from the current 44-octet CTX inputs, so descriptor copy remains accepted",
        obligation="C0.2f-15",
    )
    suite.check(
        "geometry-unchanged",
        CURRENT_CTX_OCTETS == 44
        and CURRENT_GEOMETRY_OCTETS == 16
        and current_symbolic_geometry_is_legal(513, 256, 3, 1)
        and not current_symbolic_geometry_is_legal(512, 256, 1, 256),
        family="geometry-frozen",
        detail="symbolic v2 does not amend O-06b-2 CTX or geometry",
        obligation="C0.2f-15",
    )


def _close_obligation_registry(suite: Suite) -> None:
    observed_families = set(suite.family_counts)
    expected_families = C0_2D_FAMILIES | C0_2I_FAMILIES | {"obligation-registry-v2"}
    suite.check(
        "closed-family-registry",
        expected_families <= observed_families | {"obligation-registry-v2"},
        family="obligation-registry-v2",
        detail=(
            f"missing={sorted(expected_families - observed_families)!r}; "
            f"empty={sorted(key for key in expected_families if not suite.family_counts[key])!r}"
        ),
    )
    suite.check(
        "closed-obligation-registry",
        set(suite.obligation_counts) == C0_2F_OBLIGATIONS
        and all(suite.obligation_counts.values()),
        family="obligation-registry-v2",
        detail=f"observed={sorted(suite.obligation_counts)!r}",
    )


def run_required_suite() -> Suite:
    suite = Suite()
    _exercise_causal_core(suite)
    _exercise_pending_fold(suite)
    _exercise_authority_and_control(suite)
    _exercise_security_remediation(suite)
    _exercise_collisions(suite)
    _exercise_retention_checkpoint_and_bounds(suite)
    _close_obligation_registry(suite)
    return suite


BOUNDS = {
    "events": MAX_EVENTS,
    "parents_per_event": MAX_PARENTS,
    "genesis_authorities": MAX_GENESIS_AUTHORITIES,
    "utf8_bytes_per_symbol": MAX_TEXT_BYTES,
    "delivery_permutations": MAX_DELIVERY_PERMUTATIONS,
}
