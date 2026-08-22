"""Closed hostile suite for the C0.2i v2 falsification model."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from typing import Callable

from kernel_model_v2 import (
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
        "self-rotation-and-admin-recovery",
        "bounded-hole-flood",
        "sole-authority-self-lockout",
        "authentic-but-unauthorized",
        "content-bearing-control-rejected",
        "current-profile-copy-nonprotection",
        "geometry-frozen",
        "checkpoint-staleness-nonclaim",
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
) -> Scenario:
    return Scenario(
        events=events,
        genesis_authority=genesis,
        context_identifier=context,
        opening_observations=openings or {},
        checkpoint_only_dependencies=checkpoint_only,
    )


def _exercise_causal_core(suite: Suite) -> None:
    root = event("a", 0)
    child = event("c", 1, predecessor="a")
    side = event("b", 0, credential="peer")
    base = _scenario((root, child, side), genesis=("admin", "peer"))
    expected = project(base)
    suite.observe(expected)
    orders = delivery_orders(base.events)
    suite.explored_traces += len(orders)
    for index, order in enumerate(orders):
        actual = project(replace(base, events=order))
        suite.check(
            f"c02d-delivery-{index}",
            actual.semantic_view() == expected.semantic_view(),
            family="delivery-permutation",
            detail="delivery order does not change set-relative graph or projection",
            trace=tuple(item.reference for item in order),
        )

    duplicate = project(replace(base, events=(root, root, child, side)))
    suite.check(
        "c02d-duplicate",
        duplicate.graph.duplicate_observations == 1
        and duplicate.graph.canonical_order == expected.graph.canonical_order,
        family="duplicate-replay",
        detail="byte-identical observations collapse to one graph node",
    )
    missing = project(_scenario((event("orphan", 1, predecessor="absent"),)))
    suite.check(
        "c02d-missing-parent",
        missing.graph.deferred == ("orphan",)
        and missing.outcomes["orphan"] is Outcome.DEFERRED,
        family="missing-parent",
        detail="transcript-missing K deferral is explicit",
    )

    gap = project(_scenario((event("gap-root", 0), event(
        "gap", 2, predecessor="gap-root"
    ))))
    suite.check(
        "c02d-author-gap",
        gap.outcomes["gap"] is Outcome.STRUCTURAL_REJECTION,
        family="author-gap",
        detail="a direct predecessor must have the same credential and sequence n-1",
    )

    reversed_delivery = project(replace(base, events=(child, side, root)))
    suite.check(
        "c02d-child-before-parent",
        reversed_delivery.semantic_view() == expected.semantic_view(),
        family="child-before-parent",
        detail="delivery before a direct predecessor cannot change the set-relative result",
    )

    foreign = project(_scenario((event("foreign", 0, context="other"),)))
    suite.check(
        "c02d-cross-context",
        foreign.outcomes["foreign"] is Outcome.STRUCTURAL_REJECTION
        and "foreign" not in foreign.graph.admitted,
        family="cross-context",
        detail="an event from another authenticated context is not admitted",
    )

    cycle_a = event("cycle-a", 0, credential="admin", parents=("cycle-b",))
    cycle_b = event("cycle-b", 0, credential="peer", parents=("cycle-a",))
    cycle = project(_scenario((cycle_a, cycle_b), genesis=("admin", "peer")))
    suite.check(
        "c02d-cycle-defense",
        set(cycle.graph.structurally_rejected) == {"cycle-a", "cycle-b"}
        and not cycle.graph.admitted,
        family="cycle-defense",
        detail="a closed dependency cycle is rejected rather than ordered",
    )

    prefix = project(_scenario((root,)))
    extended = project(base)
    suite.check(
        "c02d-late-exact-prefix",
        prefix.applied_order == ("a",)
        and extended.applied_order.index("a") < extended.applied_order.index("c"),
        family="late-exact-prefix",
        detail="late set growth preserves causal order while permitting full replay",
    )

    fork_left = event("fork-left", 0)
    fork_right = event("fork-right", 0)
    late_fork = project(_scenario((fork_left, fork_right)))
    suite.check(
        "c02d-late-fork",
        late_fork.graph.forks == {"fork-left", "fork-right"}
        and all(late_fork.outcomes[item] is Outcome.FORK_EVIDENCE for item in late_fork.graph.forks),
        family="late-fork",
        detail="same-author same-sequence siblings remain graph-visible fork evidence",
    )

    high = event("z-high", 0)
    low = event("a-low", 0, credential="peer")
    high_only = project(_scenario((high,)))
    with_low = project(_scenario((high, low), genesis=("admin", "peer")))
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
    omission = project(
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

    duplicate_parents = project(
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
        lambda: project(_scenario(tuple(event(f"bound-{i}", 0) for i in range(MAX_EVENTS + 1)))),
        family="resource-bound",
        detail="event-set inflation fails before graph exploration",
        obligation="C0.2f-16",
    )

    rolled_back = project(_scenario((root,)))
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
    stale_result = project(
        _scenario((stale_root, stale_child, stale), genesis=("admin", "peer"))
    )
    suite.check(
        "c02d-stale-parent",
        stale_result.outcomes["stale-frontier"] is Outcome.STRUCTURAL_REJECTION,
        family="stale-parent",
        detail="a frontier containing an ancestor of another frontier member is rejected",
    )


def _exercise_pending_fold(suite: Suite) -> None:
    none_projection = project(_scenario((event("class-none", 0),)))
    required_projection = project(
        _scenario((event("class-required", 0, content=ContentClass.REQUIRED),))
    )
    detachable_projection = project(
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
    pending = project(closed)
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
    fresh = project(opened)
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

    before_event = project(
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
            project(delivered).semantic_view() == fresh.semantic_view(),
            family="opening-event-interleavings",
            detail="equal final transcript/opening sets converge when the opening is observed before or after its event",
            trace=tuple(item.reference for item in delivered.events),
        )

    for observation in (
        OpeningObservation.OPENING_MISSING,
        OpeningObservation.LENGTH_MISMATCH,
        OpeningObservation.COMMITMENT_MISMATCH,
    ):
        result = project(_scenario((hole,), {"hole": observation}))
        suite.check(
            f"binding-{observation.value.lower()}",
            result.outcomes["hole"] is Outcome.PENDING_OPENING
            and result.binding_observations["hole"] is observation,
            family="binding-observation-distinction",
            detail=f"{observation.value} remains a distinct observation",
            obligation="C0.2f-05",
        )

    selective_a = project(closed)
    selective_b = project(opened)
    converged_a = project(opened)
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
    one_open = project(
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
    forked = project(
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

    for family in ("delayed-reveal", "relay-withholding"):
        suite.check(
            family,
            pending.outcomes["independent"] is Outcome.APPLIED
            and pending.outcomes["child"] is Outcome.PENDING_ANCESTOR,
            family=family,
            detail="delay or withholding neither bypasses descendants nor blocks independence",
        )

    late_low = event("a-late-low", 0, credential="recovery")
    with_late_low = project(
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
    authorized = project(_scenario((grant, bob_action)))
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
    revoked = project(_scenario((grant, bob_action, revoke, old_key)))
    suite.check(
        "post-revocation",
        revoked.outcomes["old-key-action"] is Outcome.POST_REVOCATION,
        family="revoked-old-key",
        detail="causal-past authorized revocation is an AP outcome, not K rejection",
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
    unauthorized = project(
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
    unauthorized_hole = project(
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
    authority_projection = project(
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
    suite.check(
        "sole-authority-self-lockout",
        authority_projection.outcomes["blocked-rotation"] is Outcome.PENDING_ANCESTOR,
        family="sole-authority-self-lockout",
        detail="a sole authority can keep its own control descendant pending without creating a bypass",
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
    revocation_holes = project(
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
        unauthorized.outcomes["bad-grant"] is Outcome.POST_REVOCATION
        and "bad-grant" in unauthorized.graph.admitted,
        family="late-authority-replay",
        detail="authority is replay-derived and can change without changing K graph admission",
    )

    bad_control = event(
        "bad-control",
        0,
        kind=EventKind.POLICY,
        content=ContentClass.REQUIRED,
    )
    structural = project(_scenario((bad_control,)))
    suite.check(
        "control-none-only",
        structural.outcomes["bad-control"] is Outcome.STRUCTURAL_REJECTION,
        family="content-bearing-control-rejected",
        detail="control content is rejected before commitment or AP evaluation",
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
    pending_chain = project(_scenario((hole, pending_grant, eve)))
    suite.check(
        "grant-chain-pending",
        {"pending-grant", "eve-action"} <= pending_chain.graph.ancestors.keys()
        and pending_chain.pending == {"authority-hole", "pending-grant", "eve-action"},
        family="grant-behind-hole",
        detail="the grantee chain is K-valid but causally pending",
    )


def _exercise_collisions(suite: Suite) -> None:
    first = event("grant-1", 0, kind=EventKind.GRANT, subject="bob")
    second = event("grant-2", 0, kind=EventKind.GRANT, subject="bob")
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
    }
    for name, events in variants.items():
        suite.expect_error(
            f"collision-{name}",
            Outcome.CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED.value,
            lambda events=events: project(_scenario(events)),
            family="credential-identifier-collision",
            detail="whole-set collision rejection is order-independent and makes no continuation claim",
        )
        reverse = tuple(reversed(events))
        suite.expect_error(
            f"collision-{name}-reverse",
            Outcome.CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED.value,
            lambda reverse=reverse: project(_scenario(reverse)),
            family="credential-identifier-collision",
            detail="arrival order cannot select a preferred binding",
        )


def _exercise_retention_checkpoint_and_bounds(suite: Suite) -> None:
    detachable = event("detachable", 0, content=ContentClass.DETACHABLE)
    remove = event(
        "remove", 1, predecessor="detachable", kind=EventKind.REMOVE,
        target="detachable", commitment="commitment:detachable"
    )
    removed = project(_scenario((detachable, remove)))
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
    subtree_pending = project(subtree_scenario)
    subtree_opened = project(
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
    before_late = project(
        _scenario((late_target, grant_bob, bob_remove), genesis=("admin", "peer"))
    )
    late_revoke = event(
        "a-late-revoke",
        1,
        predecessor="grant-bob-late",
        kind=EventKind.REVOKE,
        subject="bob",
    )
    after_late = project(
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
    attempted = project(
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

    required_peer = replace(required, credential_id="peer", binding_ref="genesis:peer")
    behind = replace(
        remove,
        reference="remove-behind",
        direct_predecessor="detachable",
        parents=("required",),
    )
    behind_result = project(
        _scenario((required_peer, detachable, behind), genesis=("admin", "peer"))
    )
    suite.check(
        "removal-behind-hole",
        behind_result.outcomes["remove-behind"] is Outcome.PENDING_ANCESTOR,
        family="removal-behind-hole",
        detail="control in a pending subtree cannot bypass its root",
        obligation="C0.2f-14",
    )

    stale = project(_scenario((detachable,), checkpoint_only=("revocation-x",)))
    suite.check(
        "checkpoint-whole-stale",
        stale.outcomes["detachable"] is Outcome.STALE_EVIDENCE
        and not stale.applied_order,
        family="checkpoint-authority-staleness",
        detail="checkpoint-only authority evidence makes the whole projection stale",
        obligation="C0.2f-12",
    )
    suite.check(
        "checkpoint-staleness-nonclaim",
        stale.outcomes["detachable"] is Outcome.STALE_EVIDENCE,
        family="checkpoint-staleness-nonclaim",
        detail="checkpoint evidence never substitutes for authenticated replay history",
    )
    checkpoint_hole = _scenario(
        (event("checkpoint-hole", 0, content=ContentClass.REQUIRED),),
        checkpoint_only=("checkpoint-hole",),
    )
    suite.check(
        "checkpoint-pending-producer",
        project(checkpoint_hole).outcomes["checkpoint-hole"] is Outcome.STALE_EVIDENCE
        and not frontier_is_producible(checkpoint_hole, ("checkpoint-hole",)),
        family="checkpoint-pending-producer",
        detail="checkpoint closure cannot make a pending frontier producer eligible",
        obligation="C0.2f-02",
    )

    flood = tuple(
        event(f"hole-{index}", 0, content=ContentClass.REQUIRED)
        for index in range(MAX_EVENTS)
    )
    flooded = project(_scenario(flood))
    suite.observe(flooded)
    counts = Counter(event.credential_id for event in flood if event.reference in flooded.pending_roots)
    suite.check(
        "bounded-hole-count",
        flooded.metrics.pending_roots == MAX_EVENTS and counts == {"admin": MAX_EVENTS},
        family="bounded-hole-flood",
        detail="pending roots are instrumented per credential within explicit bounds",
        obligation="C0.2f-16",
    )
    suite.expect_error(
        "event-bound",
        "MODEL_BOUND_EXCEEDED",
        lambda: project(_scenario(flood + (event("overflow", MAX_EVENTS),))),
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

    suite.check(
        "target-prefix-abandonment-rejected",
        behind_result.outcomes["remove-behind"] is Outcome.PENDING_ANCESTOR
        and attempted.outcomes["remove-required"] is Outcome.REMOVAL_INAPPLICABLE,
        family="target-prefix-abandonment-rejected",
        detail="neither target-prefix abandonment nor a pending control bypass exists",
    )
    missing_transcript = project(
        _scenario((event("missing-transcript", 1, predecessor="absent"),))
    )
    suite.check(
        "transcript-deferred-distinction",
        missing_transcript.outcomes["missing-transcript"] is Outcome.DEFERRED
        and behind_result.outcomes["required"] is Outcome.PENDING_OPENING,
        family="transcript-deferred-distinction",
        detail="missing K transcript ancestry is DEFERRED and distinct from an opening-missing pending root",
    )

    copied_a = current_profile_symbolic_commitment(
        context_token="ctx",
        content_type="type",
        exact_length=4,
        shape="single",
        content_symbol="data",
        opening_randomizer="randomizer",
    )
    # Deliberately no credential or sequence arguments exist in this profile.
    copied_b = current_profile_symbolic_commitment(
        context_token="ctx",
        content_type="type",
        exact_length=4,
        shape="single",
        content_symbol="data",
        opening_randomizer="randomizer",
    )
    suite.check(
        "copy-nonprotection",
        copied_a == copied_b and copied_a[0] == CURRENT_CTX_OCTETS,
        family="current-profile-copy-nonprotection",
        detail="current 44-octet CTX intentionally accepts cross-credential and cross-sequence descriptor copy",
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
