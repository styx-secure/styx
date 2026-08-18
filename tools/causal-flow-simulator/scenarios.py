"""Required bounded adversarial scenarios for the C0.2d falsification gate."""

from __future__ import annotations

from dataclasses import replace
from itertools import permutations
from typing import Callable, Sequence

from model import (
    CausalModel,
    CheckpointEvidence,
    Context,
    CredentialAuthority,
    Evaluation,
    Event,
    ModelInputError,
    Profile,
    Status,
    affected_replay_boundary,
    evaluation_json,
    event_trace_fingerprint,
    incremental_handoffs,
)


MODEL_VERSION = "styx.causal-flow-simulator/v0"


CTX = Context("example.app", "bounded-v0", "case-1", b"g")
OTHER_CTX = Context("example.app", "bounded-v0", "case-2", b"h")
GRANT_A = b"ga"
GRANT_B = b"gb"
GRANT_C = b"gc"
GRANT_D = b"gd"


def authorities(*, revocations: tuple[bytes, ...] = ()) -> tuple[CredentialAuthority, ...]:
    return (
        CredentialAuthority(b"a", CTX, GRANT_A, revocations),
        CredentialAuthority(b"b", CTX, GRANT_B),
        CredentialAuthority(b"c", CTX, GRANT_C),
        CredentialAuthority(b"d", CTX, GRANT_D),
    )


def checkpoint(
    *,
    proven: frozenset[bytes] | None = None,
    stale: frozenset[bytes] = frozenset(),
    heads: tuple[tuple[bytes, int, bytes], ...] = (),
) -> CheckpointEvidence:
    return CheckpointEvidence(
        CTX,
        frozenset((GRANT_A, GRANT_B, GRANT_C, GRANT_D)) if proven is None else proven,
        stale,
        heads,
    )


def model(
    *,
    profile: Profile | None = None,
    evidence: CheckpointEvidence | None = None,
    revocations: tuple[bytes, ...] = (),
) -> CausalModel:
    return CausalModel(
        context=CTX,
        authorities=authorities(revocations=revocations),
        checkpoint=checkpoint() if evidence is None else evidence,
        profile=Profile() if profile is None else profile,
    )


def first(
    reference: bytes,
    credential: bytes,
    grant: bytes,
    *,
    parents: tuple[bytes, ...] = (),
    context: Context = CTX,
    kind: str = "action",
) -> Event:
    return Event(reference, context, credential, 0, None, tuple(sorted((grant, *parents))), kind)


def next_event(
    reference: bytes,
    credential: bytes,
    sequence: int,
    predecessor: bytes,
    *,
    parents: tuple[bytes, ...] = (),
    context: Context = CTX,
    kind: str = "action",
) -> Event:
    return Event(reference, context, credential, sequence, predecessor, tuple(sorted(parents)), kind)


class Suite:
    def __init__(self) -> None:
        self.invariants: list[dict[str, object]] = []
        self.scenario_counts: dict[str, int] = {}
        self.explored_delivery_traces = 0
        self.counterexamples: list[dict[str, object]] = []
        self.samples: dict[str, object] = {}

    def explored(self) -> None:
        self.explored_delivery_traces += 1
        if self.explored_delivery_traces > Profile().max_delivery_traces:
            raise ModelInputError("delivery exploration budget exceeded")

    def count(self, family: str, amount: int = 1) -> None:
        self.scenario_counts[family] = self.scenario_counts.get(family, 0) + amount

    def check(
        self,
        name: str,
        condition: bool,
        *,
        family: str,
        trace: Sequence[Event] = (),
        detail: str = "",
    ) -> None:
        self.count(family)
        self.invariants.append({"name": name, "passed": bool(condition)})
        if condition:
            return
        self.counterexamples.append(
            {
                "invariant": name,
                "detail": detail,
                "smallest_observed_trace": event_trace_fingerprint(trace),
            }
        )

    def check_raises(
        self,
        name: str,
        operation: Callable[[], object],
        *,
        family: str,
    ) -> None:
        try:
            operation()
        except ModelInputError:
            self.check(name, True, family=family)
        else:
            self.check(name, False, family=family, detail="operation did not fail closed")

    def report(self) -> dict[str, object]:
        return {
            "schema": "styx.causal-flow-falsification-report/v0",
            "model_version": MODEL_VERSION,
            "bounded_search_envelope": {
                "max_events_per_evaluation": Profile().max_events,
                "max_credentials": Profile().max_credentials,
                "max_parents_per_event": Profile().max_parents,
                "max_checkpoint_references": Profile().max_checkpoint_refs,
                "max_reference_bytes": Profile().max_reference_bytes,
                "max_text_field_utf8_bytes": Profile().max_text_bytes,
                "max_total_input_bytes": Profile().max_input_bytes,
                "max_sequence": Profile().max_sequence,
                "max_delivery_traces": Profile().max_delivery_traces,
            },
            "scenario_counts": dict(sorted(self.scenario_counts.items())),
            "explored_delivery_traces": self.explored_delivery_traces,
            "invariants": self.invariants,
            "samples": dict(sorted(self.samples.items())),
            "counterexamples": self.counterexamples,
            "verdict": "FAIL" if self.counterexamples else "NO_COUNTEREXAMPLE_WITHIN_BOUNDS",
            "non_claims": [
                "bounded exploration is not a formal proof",
                "synthetic references do not define transcript or cryptographic bytes",
                "the model does not establish global rollback detection",
                "the result is not a production-readiness or security verdict",
            ],
        }


def _full_signature(result: Evaluation) -> tuple[object, ...]:
    return (
        tuple((reference, result.graph[reference]) for reference in sorted(result.graph)),
        tuple(
            (
                reference,
                decision.status,
                decision.reasons,
                decision.fork_peers,
            )
            for reference, decision in sorted(result.decisions.items())
        ),
        result.order,
        tuple(result.handoffs),
    )


def run_required_suite() -> dict[str, object]:
    suite = Suite()
    evaluator = model()

    # Three authors with mixed causality/concurrency.  C depends on A while B is
    # concurrent; byte-order must choose A, then B, then C.
    a0 = first(b"\x10", b"a", GRANT_A)
    b0 = first(b"\x20", b"b", GRANT_B)
    c0 = first(b"\x30", b"c", GRANT_C, parents=(a0.reference,))
    mixed = (a0, b0, c0)
    baseline = evaluator.evaluate(mixed)
    suite.samples["mixed_causal_graph"] = evaluation_json(baseline)
    suite.check(
        "mixed causal/concurrent order",
        baseline.order == (a0.reference, b0.reference, c0.reference),
        family="mixed-causal-concurrent",
        trace=mixed,
    )
    suite.check(
        "ready sets expose concurrent choices",
        baseline.ready_sets[:2] == ((a0.reference, b0.reference), (b0.reference, c0.reference)),
        family="mixed-causal-concurrent",
        trace=mixed,
    )

    signatures = set()
    for delivery in permutations(mixed):
        suite.explored()
        signatures.add(repr(_full_signature(evaluator.evaluate(delivery))))
    suite.check(
        "same set converges across all delivery permutations",
        len(signatures) == 1,
        family="delivery-permutation",
        trace=mixed,
    )

    # A lower-reference late concurrent insertion changes only the suffix.
    high = first(b"\x40", b"c", GRANT_C, parents=(a0.reference,))
    low_late = first(b"\x18", b"b", GRANT_B)
    old = evaluator.evaluate((a0, high))
    expanded = evaluator.evaluate((a0, high, low_late))
    boundary, incremental = incremental_handoffs(old, expanded)
    suite.samples["late_lower_reference"] = {
        "old_order": [reference.hex() for reference in old.order],
        "expanded_order": [reference.hex() for reference in expanded.order],
        "affected_replay_boundary": boundary,
    }
    suite.check(
        "late lower reference finds first affected suffix",
        boundary == 1 and expanded.order == (a0.reference, low_late.reference, high.reference),
        family="late-lower-reference",
        trace=(a0, high, low_late),
    )
    suite.check(
        "late lower reference incremental replay equals full replay",
        incremental == expanded.handoffs,
        family="incremental-full-equivalence",
        trace=(a0, high, low_late),
    )

    # An event ordered after the old order preserves an exact prefix.
    exact_prefix_late = first(b"\x50", b"d", GRANT_D)
    prefix_old = evaluator.evaluate((a0, b0))
    prefix_new = evaluator.evaluate((a0, b0, exact_prefix_late))
    prefix_boundary, prefix_incremental = incremental_handoffs(prefix_old, prefix_new)
    suite.check(
        "late exact-prefix insertion returns old length",
        prefix_boundary == len(prefix_old.order),
        family="late-exact-prefix",
        trace=(a0, b0, exact_prefix_late),
    )
    suite.check(
        "late exact-prefix incremental replay equals full replay",
        prefix_incremental == prefix_new.handoffs,
        family="incremental-full-equivalence",
        trace=(a0, b0, exact_prefix_late),
    )

    # Exhaustively compare incremental and full replay for every prefix of each
    # delivery of the bounded mixed set.
    for delivery in permutations(mixed):
        prior = evaluator.evaluate(())
        for end in range(1, len(delivery) + 1):
            current = evaluator.evaluate(delivery[:end])
            _, projected = incremental_handoffs(prior, current)
            suite.explored()
            suite.check(
                "bounded incremental prefix equals fresh full replay",
                projected == current.handoffs,
                family="exhaustive-incremental-replay",
                trace=delivery[:end],
            )
            prior = current

    # Child-before-parent is deferred and produces no handoff until evidence is
    # present.  The final same set converges regardless of arrival.
    a1 = next_event(b"\x11", b"a", 1, a0.reference)
    child_only = evaluator.evaluate((a1,))
    child_resolved = evaluator.evaluate((a1, a0))
    suite.check(
        "child before parent is deferred without AP handoff",
        child_only.decisions[a1.reference].status is Status.DEFERRED
        and not child_only.handoffs,
        family="child-before-parent",
        trace=(a1,),
    )
    suite.check(
        "child becomes admitted when parent arrives",
        child_resolved.order == (a0.reference, a1.reference),
        family="child-before-parent",
        trace=(a1, a0),
    )

    duplicate = evaluator.evaluate((a0, a0))
    suite.check(
        "duplicate observation remains one graph node",
        duplicate.duplicate_refs == (a0.reference,)
        and duplicate.decisions[a0.reference].duplicate_observations == 1
        and duplicate.order == (a0.reference,),
        family="duplicate-replay",
        trace=(a0, a0),
    )

    fork_left = next_event(b"\x12", b"a", 1, a0.reference)
    fork_right = next_event(b"\x13", b"a", 1, a0.reference)
    forked = evaluator.evaluate((a0, fork_right, fork_left))
    suite.samples["late_fork"] = evaluation_json(forked)
    suite.check(
        "late same-sequence and same-predecessor fork remains visible",
        forked.decisions[fork_left.reference].status is Status.FORK
        and forked.decisions[fork_right.reference].status is Status.FORK
        and forked.decisions[fork_left.reference].fork_peers == (fork_right.reference,),
        family="late-fork",
        trace=(a0, fork_right, fork_left),
    )
    fork_old = evaluator.evaluate((a0, fork_left))
    fork_expanded = evaluator.evaluate((a0, fork_left, fork_right))
    fork_boundary, fork_incremental = incremental_handoffs(fork_old, fork_expanded)
    suite.check(
        "late higher fork is disclosed at its replay point without rewriting prefix",
        fork_boundary == len(fork_old.order)
        and fork_incremental == fork_expanded.handoffs
        and fork_expanded.handoffs[-1].fork_peers == (fork_left.reference,),
        family="late-fork",
        trace=(a0, fork_left, fork_right),
    )
    higher_first = evaluator.evaluate((a0, fork_right))
    lower_expanded = evaluator.evaluate((a0, fork_right, fork_left))
    lower_boundary, lower_incremental = incremental_handoffs(higher_first, lower_expanded)
    suite.check(
        "late lower fork replays from changed order and exposes sibling",
        lower_boundary == 1
        and lower_incremental == lower_expanded.handoffs
        and lower_expanded.handoffs[-1].fork_peers == (fork_left.reference,),
        family="late-fork",
        trace=(a0, fork_right, fork_left),
    )

    gap = next_event(b"\x14", b"a", 2, a0.reference)
    gap_result = evaluator.evaluate((a0, gap))
    suite.check(
        "author sequence gap is distinct",
        gap_result.decisions[gap.reference].status is Status.GAP,
        family="author-gap",
        trace=(a0, gap),
    )

    missing = replace(a1, reference=b"\x15", author_predecessor=b"missing")
    missing_result = evaluator.evaluate((missing,))
    suite.check(
        "recoverably missing evidence is deferred",
        missing_result.decisions[missing.reference].status is Status.DEFERRED
        and not missing_result.handoffs,
        family="missing-parent",
        trace=(missing,),
    )

    stale_evidence = checkpoint(stale=frozenset((b"old",)))
    stale_event = next_event(b"\x16", b"a", 1, b"old")
    stale_result = model(evidence=stale_evidence).evaluate((stale_event,))
    suite.check(
        "pruned parent without proof is stale",
        stale_result.decisions[stale_event.reference].status is Status.STALE
        and not stale_result.handoffs,
        family="stale-parent",
        trace=(stale_event,),
    )

    proven_evidence = checkpoint(
        proven=frozenset((GRANT_A, GRANT_B, GRANT_C, GRANT_D, b"old")),
        heads=((b"a", 0, b"old"),),
    )
    proven_event = next_event(b"\x17", b"a", 1, b"old")
    proven_result = model(evidence=proven_evidence).evaluate((proven_event,))
    suite.check(
        "authenticated checkpoint author head permits bounded continuation",
        proven_result.decisions[proven_event.reference].status is Status.ADMITTED,
        family="checkpoint-proof",
        trace=(proven_event,),
    )
    suite.samples["checkpoint_states"] = {
        "proven_refs": [reference.hex() for reference in sorted(proven_evidence.proven_refs)],
        "stale_refs": [reference.hex() for reference in sorted(stale_evidence.stale_refs)],
        "proven_event_status": proven_result.decisions[proven_event.reference].status.value,
        "stale_event_status": stale_result.decisions[stale_event.reference].status.value,
        "unknown_event_status": missing_result.decisions[missing.reference].status.value,
    }

    wrong_context_parent = first(b"\x60", b"b", GRANT_B, context=OTHER_CTX)
    cross = first(b"\x61", b"a", GRANT_A, parents=(wrong_context_parent.reference,))
    cross_result = evaluator.evaluate((wrong_context_parent, cross))
    suite.check(
        "cross-context parent is invalid",
        cross_result.decisions[cross.reference].status is Status.INVALID
        and not cross_result.handoffs,
        family="cross-context",
        trace=(wrong_context_parent, cross),
    )

    duplicate_parent = replace(a0, reference=b"\x62", causal_parents=(GRANT_A, GRANT_A))
    duplicate_parent_result = evaluator.evaluate((duplicate_parent,))
    suite.check(
        "duplicate parent list is noncanonical",
        duplicate_parent_result.decisions[duplicate_parent.reference].status is Status.INVALID,
        family="parent-canonicality",
        trace=(duplicate_parent,),
    )

    redundant = first(
        b"\x63",
        b"c",
        GRANT_C,
        parents=(a0.reference, a1.reference),
    )
    redundant_result = evaluator.evaluate((a0, a1, redundant))
    suite.check(
        "ancestor-redundant frontier is rejected",
        redundant_result.decisions[redundant.reference].status is Status.INVALID,
        family="parent-canonicality",
        trace=(a0, a1, redundant),
    )

    too_many = first(
        b"\x64",
        b"a",
        GRANT_A,
        parents=(b"1", b"2", b"3", b"4"),
    )
    bounded_model = model(profile=Profile(max_parents=3))
    fanout = bounded_model.evaluate((too_many,))
    suite.check(
        "parent fan-out fails closed at profile bound",
        fanout.decisions[too_many.reference].status is Status.INVALID,
        family="resource-bound",
        trace=(too_many,),
    )
    suite.check_raises(
        "observation count over budget fails closed",
        lambda: model(profile=Profile(max_events=1)).evaluate((a0, b0)),
        family="resource-bound",
    )
    suite.check_raises(
        "credential count over budget fails closed",
        lambda: model(profile=Profile(max_credentials=3)),
        family="resource-bound",
    )
    suite.check_raises(
        "checkpoint evidence over budget fails closed",
        lambda: model(profile=Profile(max_checkpoint_refs=3)),
        family="resource-bound",
    )
    small_context = Context("a", "p", "i", b"g")
    small_authority = CredentialAuthority(b"a", small_context, b"q")
    small_checkpoint = CheckpointEvidence(small_context, frozenset((b"q",)))

    def exceed_input_bytes() -> object:
        small_model = CausalModel(
            context=small_context,
            authorities=(small_authority,),
            checkpoint=small_checkpoint,
            profile=Profile(max_input_bytes=35),
        )
        return small_model.evaluate(
            (Event(b"e", small_context, b"a", 0, None, (b"q",)),)
        )

    suite.check_raises(
        "aggregate input bytes over budget fail closed",
        exceed_input_bytes,
        family="resource-bound",
    )
    oversized_kind = replace(a0, reference=b"\x65", kind="x" * 65)
    oversized_kind_result = evaluator.evaluate((oversized_kind,))
    suite.check(
        "UTF-8 text field over budget is invalid",
        oversized_kind_result.decisions[oversized_kind.reference].status is Status.INVALID
        and "KIND_INVALID" in oversized_kind_result.decisions[oversized_kind.reference].reasons,
        family="resource-bound",
        trace=(oversized_kind,),
    )

    cycle_a = next_event(b"\x70", b"a", 1, b"\x71")
    cycle_b = next_event(b"\x71", b"a", 0, b"\x70")
    # Structural first-event rules independently invalidate cycle_b; a separate
    # cross-author causal cycle exercises the defensive graph check directly.
    cycle_x = first(b"\x72", b"a", GRANT_A, parents=(b"\x73",))
    cycle_y = first(b"\x73", b"b", GRANT_B, parents=(b"\x72",))
    cycle_result = evaluator.evaluate((cycle_x, cycle_y))
    suite.check(
        "synthetic reference cycle is rejected defensively",
        cycle_result.decisions[cycle_x.reference].status is Status.INVALID
        and cycle_result.decisions[cycle_y.reference].status is Status.INVALID,
        family="cycle-defense",
        trace=(cycle_x, cycle_y),
    )
    del cycle_a, cycle_b

    # Revocation concurrent with an old-key action is a fact for AP; an action
    # descending from the revocation is rejected by K.
    revoke = first(b"\x80", b"d", GRANT_D, kind="revoke-a")
    old_key_concurrent = first(b"\x81", b"a", GRANT_A)
    revocation_model = model(revocations=(revoke.reference,))
    concurrent_result = revocation_model.evaluate((revoke, old_key_concurrent))
    concurrent_handoff = next(
        handoff for handoff in concurrent_result.handoffs if handoff.reference == old_key_concurrent.reference
    )
    suite.check(
        "revocation race is classified without AP verdict",
        concurrent_handoff.revocation_relations == ((revoke.reference, "concurrent"),),
        family="revocation-race",
        trace=(revoke, old_key_concurrent),
    )
    late_revoke = replace(revoke, reference=b"\x90")
    late_revocation_model = model(revocations=(late_revoke.reference,))
    action_before_revoke = late_revocation_model.evaluate((old_key_concurrent,))
    action_plus_revoke = late_revocation_model.evaluate((old_key_concurrent, late_revoke))
    revocation_boundary, revocation_incremental = incremental_handoffs(
        action_before_revoke, action_plus_revoke
    )
    suite.check(
        "late higher revocation is delivered as a new AP fact without rewriting prefix",
        revocation_boundary == len(action_before_revoke.order)
        and revocation_incremental == action_plus_revoke.handoffs
        and action_plus_revoke.handoffs[-1].kind == "revoke-a"
        and action_plus_revoke.handoffs[-1].causal_relations
        == ((old_key_concurrent.reference, "concurrent"),),
        family="revocation-race",
        trace=(old_key_concurrent, late_revoke),
    )
    post_revoke = first(b"\x82", b"a", GRANT_A, parents=(revoke.reference,))
    post_result = revocation_model.evaluate((revoke, post_revoke))
    suite.check(
        "post-revocation action is rejected",
        post_result.decisions[post_revoke.reference].status is Status.INVALID,
        family="revocation-race",
        trace=(revoke, post_revoke),
    )

    # AP ownership: serialized handoff contains facts and no business verdict,
    # delivery/finality flag, or irreversible-effect authorization.
    serialized = evaluation_json(baseline)
    forbidden = {"accept", "reject", "authorized", "delivered", "final", "effect"}
    handoff_keys = set().union(*(item.keys() for item in serialized["handoffs"]))
    suite.check(
        "AP handoff remains fact-only",
        forbidden.isdisjoint(handoff_keys),
        family="ownership-boundary",
        trace=mixed,
    )

    # A local checkpoint can distinguish retained proof from known-pruned and
    # unknown references, but cannot prove absence of a hidden remote branch.
    suite.check(
        "checkpoint states remain explicit without global rollback claim",
        proven_result.decisions[proven_event.reference].status is Status.ADMITTED
        and stale_result.decisions[stale_event.reference].status is Status.STALE
        and missing_result.decisions[missing.reference].status is Status.DEFERRED,
        family="rollback-limit",
        trace=(proven_event, stale_event, missing),
    )

    omitted_a = first(b"\xa0", b"a", GRANT_A)
    omitted_b = first(b"\xa1", b"b", GRANT_B)
    omission_result = evaluator.evaluate((omitted_a, omitted_b))
    omission_relation = next(
        relation
        for reference, relation in omission_result.handoffs[-1].causal_relations
        if reference == omitted_a.reference
    )
    suite.check(
        "an omitted observation cannot manufacture a causal edge",
        omission_relation == "concurrent",
        family="malicious-omission-limit",
        trace=(omitted_a, omitted_b),
    )

    suite.check(
        "affected boundary function is set-relative and prefix-aware",
        affected_replay_boundary((b"a", b"c"), (b"a", b"b", b"c")) == 1
        and affected_replay_boundary((b"a", b"b"), (b"a", b"b", b"c")) == 2,
        family="replay-boundary",
    )
    return suite.report()
