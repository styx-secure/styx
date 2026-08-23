"""Closed C0.2j hostile-witness suite for the independent v3 model."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Mapping

from protocol_model_v3 import (
    AuthorityVerdict,
    Binding,
    ContentClass,
    CONTEXT_ID,
    Event,
    Kind,
    MAX_CONTROL_EVENTS,
    MAX_CREDENTIALS,
    MAX_DELIVERY_PERMUTATION_WIDTH,
    MAX_EVENTS,
    MAX_FORK_SLOTS,
    MAX_KEY_OCTETS,
    MAX_LINEAGE_DEPTH,
    MAX_PARENTS,
    MAX_TOPOLOGICAL_ORDERS,
    ModelInputError,
    Mutation,
    Outcome,
    Projection,
    REDUCTION_KINDS,
    ReductionStanding,
    Role,
    Scenario,
    credential_domains_are_separated,
    derive_event_reference,
    derive_genesis_credential_id,
    delivery_views,
    grant_binding,
    make_event as _make_event,
    project,
)


_BUILD_MUTATION = Mutation()


def make_event(*args: object, **kwargs: object) -> Event:
    """Construct fixtures under the mutation being exercised."""

    return _make_event(*args, **kwargs, mutation=_BUILD_MUTATION)


BOUNDS = {
    "events": MAX_EVENTS,
    "control_events": MAX_CONTROL_EVENTS,
    "fork_slots": MAX_FORK_SLOTS,
    "parents_per_event": MAX_PARENTS,
    "lineage_depth": MAX_LINEAGE_DEPTH,
    "topological_orders": MAX_TOPOLOGICAL_ORDERS,
    "delivery_permutation_width": MAX_DELIVERY_PERMUTATION_WIDTH,
    "credentials": MAX_CREDENTIALS,
    "verification_key_octets": MAX_KEY_OCTETS,
    "author_sequence_exclusive_upper_bound": 2**64,
}

REQUIRED_MUTANTS = frozenset(
    {
        "M01_IDENTIFIER_OMITS_CONTEXT",
        "M02_IDENTIFIER_OMITS_ALGORITHM",
        "M03_IDENTIFIER_OMITS_ISSUER",
        "M04_POSSESSION_IMPLIES_AUTHORITY",
        "M05_EXPANSION_USES_MAY",
        "M06_REDUCTION_REQUIRES_MUST",
        "M07_IGNORE_MAY_REDUCTION",
        "M08_SINGLE_LINEARIZATION",
        "M09_NON_TRANSITIVE_PROVENANCE",
        "M10_RECOVERY_RESURRECTS_REVOKED",
        "M11_CANONICAL_MUTUAL_REVOCATION",
        "M12_NON_GRANT_CREATES_BINDING",
        "M13_MALFORMED_TAIL_ACCEPTED",
        "M14_FORK_EXPANDS_AUTHORITY",
        "M15_CHECKPOINT_SUBSTITUTES",
        "M16_ALIAS_CHANGES_AUTHORITY",
        "M17_TERMINAL_SET_TAMPER",
        "M18_AP_BYTES_AS_K_BINDING",
        "M19_REGRANT_REVOKED_IDENTIFIER",
        "M20_FILTER_EVIDENCE_BY_AP_STATE",
        "M21_GENESIS_USES_EVENT_DOMAIN",
        "M22_CONTROL_CONTENT_ACCEPTED",
        "M23_UNRESOLVED_DEFERRED",
        "M24_REVOKED_REDUCTION_ACCEPTED",
        "M25_COLLISION_SELECTS_WINNER",
        "M26_DIRECT_DEPENDENCIES_ONLY",
        "M27_GLOBAL_FORK_TERMINATION",
        "M28_NO_AUTHOR_CONTINUITY",
        "M32_FORK_JOIN_BEFORE_SIBLINGS",
        "M33_TERMINAL_AUTHORITY_FOR_ORDINARY",
    }
)

REQUIRED_WITNESSES = frozenset(
    {
        "identifier-binding-and-cross-context",
        "duplicate-grant-and-deliberate-collision",
        "genesis-domain-separation",
        "grant-revoke-grinding-and-delivery",
        "successor-reduction-standing",
        "ordinary-event-prefix-authority",
        "transitive-control-causality",
        "author-chain-and-frontier-canonicality",
        "may-only-reduction",
        "multi-hop-provenance-containment",
        "independent-authority-continuation",
        "mutual-concurrent-revocation",
        "single-compromised-authority-takeover",
        "regrant-and-recovery-non-resurrection",
        "alias-evidence-survival",
        "rotation-recovery-and-old-key-continuation",
        "fork-scope-and-privilege-neutrality",
        "fork-after-reduction-non-resurrection",
        "fork-twin-non-resurrection",
        "fork-acknowledgment-boundary",
        "forked-descendant-containment",
        "pending-required-with-authority",
        "checkpoint-stale-no-substitution",
        "removal-control-inapplicable",
        "transport-and-case-ephemeral-neutrality",
        "full-replay-delivery-convergence",
        "bounded-hostile-flood",
        "unresolvable-dangling-and-forward",
        "non-grant-binding-spoof",
        "control-tail-and-content-structure",
    }
)


@dataclass(frozen=True)
class Check:
    identifier: str
    family: str
    passed: bool
    assertion: str
    detail: str
    kills: tuple[str, ...] = ()

    def record(self) -> dict[str, object]:
        return {
            "id": self.identifier,
            "family": self.family,
            "passed": self.passed,
            "assertion": self.assertion,
            "detail": self.detail,
            "kills": list(self.kills),
        }


@dataclass
class Suite:
    checks: list[Check]
    projections: list[Projection]

    @property
    def witnesses(self) -> frozenset[str]:
        return frozenset(check.family for check in self.checks)


def genesis(label: str, octet: str) -> Binding:
    key = octet * 32
    credential_id = derive_genesis_credential_id(CONTEXT_ID, "0x0001", key)
    return Binding(
        credential_id=credential_id,
        suite_id="0x0001",
        verification_key=key,
        issuer_id=None,
        grant_reference=f"genesis:{label}",
        genesis=True,
    )


def control(
    name: str,
    actor: Binding,
    kind: Kind,
    *,
    sequence: int = 0,
    predecessor: str | None = None,
    parents: tuple[str, ...] = (),
    grantee_key: str | None = None,
    target_id: str | None = None,
    target_reference: str | None = None,
    content_class: ContentClass = ContentClass.NONE,
    malformed_tail: bool = False,
    ap_applicable: bool = True,
) -> Event:
    return make_event(
        name,
        actor,
        sequence=sequence,
        predecessor=predecessor,
        parents=parents,
        role=Role.CREDENTIAL_CONTROL,
        kind=kind,
        content_class=content_class,
        grantee_suite="0x0001" if kind is Kind.GRANT else None,
        grantee_key=grantee_key,
        target_id=target_id,
        target_reference=target_reference,
        malformed_tail=malformed_tail,
        ap_applicable=ap_applicable,
    )


def grind_grant(
    actor: Binding, revoke_reference: str, *, sorts_before: bool
) -> Event:
    """Find bounded deterministic GRANT evidence on one requested order side."""

    for nonce in range(4096):
        candidate = control(
            f"ground-grant-{int(sorts_before)}-{nonce}",
            actor,
            Kind.GRANT,
            grantee_key="ed" * 32,
        )
        if (candidate.reference < revoke_reference) is sorts_before:
            return candidate
    raise AssertionError("bounded reference grinding did not find requested side")


def check(
    identifier: str,
    family: str,
    passed: bool,
    assertion: str,
    detail: str,
    *kills: str,
) -> Check:
    return Check(identifier, family, bool(passed), assertion, detail, tuple(kills))


def _project(
    suite: Suite, scenario: Scenario, mutation: Mutation
) -> Projection:
    value = project(scenario, mutation)
    suite.projections.append(value)
    return value


def _expect_error(
    scenario: Scenario, mutation: Mutation, code: str
) -> bool:
    try:
        project(scenario, mutation)
    except ModelInputError as error:
        return error.code == code
    return False


def _identifier_checks(suite: Suite, mutation: Mutation) -> None:
    a = genesis("a", "11")
    g = control("grant-b", a, Kind.GRANT, grantee_key="22" * 32)
    b = grant_binding(g)
    use = make_event("b-use", b, parents=(g.reference,))
    p = _project(suite, Scenario((g, use), (a,)), mutation)
    context_variant = replace(g, reference="", context_id="64" * 32)
    algorithm_variant = replace(g, reference="", grantee_suite="0xffff")
    alternate_issuer = replace(a, credential_id="alternate-issuer")
    issuer_variant = make_event(
        "grant-b",
        alternate_issuer,
        role=Role.CREDENTIAL_CONTROL,
        kind=Kind.GRANT,
        content_class=ContentClass.NONE,
        grantee_suite="0x0001",
        grantee_key="22" * 32,
    )
    identifier_fields_bound = (
        g.reference != derive_event_reference(context_variant, mutation)
        and g.reference != derive_event_reference(algorithm_variant, mutation)
        and g.reference != issuer_variant.reference
    )
    suite.checks.append(
        check(
            "W-ID-01",
            "identifier-binding-and-cross-context",
            p.outcomes.get(g.reference) is Outcome.APPLIED
            and p.outcomes.get(use.reference) is Outcome.APPLIED
            and b.credential_id == g.reference
            and b.issuer_id == a.credential_id
            and identifier_fields_bound,
            "grant-rooted identifier is the causal GRANT reference and binds issuer/suite/key",
            "No declared subject or ambient AP/transport field contributes to the identifier.",
            "M01_IDENTIFIER_OMITS_CONTEXT",
            "M02_IDENTIFIER_OMITS_ALGORITHM",
            "M03_IDENTIFIER_OMITS_ISSUER",
        )
    )

    copied = make_event(
        "cross-context-copy", b, context_id="64" * 32, parents=(g.reference,)
    )
    mismatch = make_event(
        "key-mismatch",
        b,
        parents=(g.reference,),
        claimed_actor_key="33" * 32,
    )
    algorithm = make_event(
        "algorithm-mismatch",
        b,
        parents=(g.reference,),
        claimed_actor_suite="0xffff",
    )
    q = _project(suite, Scenario((g, copied, mismatch, algorithm), (a,)), mutation)
    suite.checks.append(
        check(
            "W-ID-02",
            "identifier-binding-and-cross-context",
            all(
                q.rejected.get(event.reference)
                in {Outcome.STRUCTURAL_REJECTION, Outcome.CREDENTIAL_BINDING_MISMATCH}
                for event in (copied, mismatch, algorithm)
            ),
            "cross-context, key and algorithm mutation fail closed",
            "No attacker-selected field can rebind an admitted credential.",
        )
    )

    declared = make_event(
        "declared-subject",
        a,
        role=Role.CREDENTIAL_CONTROL,
        kind=Kind.GRANT,
        grantee_suite="0x0001",
        grantee_key="44" * 32,
        declared_subject_id="attacker-selected",
    )
    r = _project(suite, Scenario((declared,), (a,)), mutation)
    suite.checks.append(
        check(
            "W-ID-03",
            "duplicate-grant-and-deliberate-collision",
            r.rejected.get(declared.reference) is Outcome.STRUCTURAL_REJECTION,
            "a binding GRANT carries no declared subject identifier",
            "The reference cannot circularly authenticate itself.",
        )
    )

    duplicate = Scenario((g, g), (a,))
    d = _project(suite, duplicate, mutation)
    suite.checks.append(
        check(
            "W-ID-04",
            "duplicate-grant-and-deliberate-collision",
            len(d.bindings) == 2 and g.reference in d.bindings,
            "byte-identical duplicate GRANT is idempotent evidence",
            "A distinct transcript under the same reference is rejected before projection.",
        )
    )

    collision = make_event(
        "distinct-collision",
        a,
        role=Role.CREDENTIAL_CONTROL,
        kind=Kind.GRANT,
        grantee_suite="0x0001",
        grantee_key="23" * 32,
        forced_reference=g.reference,
    )
    rejected_collision_orders = 0
    for delivery in ((g, collision), (collision, g)):
        try:
            project(Scenario(delivery, (a,)), mutation)
        except ModelInputError as error:
            if error.code == "REFERENCE_COLLISION_UNSUPPORTED":
                rejected_collision_orders += 1
    suite.checks.append(
        check(
            "W-ID-09",
            "duplicate-grant-and-deliberate-collision",
            rejected_collision_orders == 2,
            "distinct transcripts sharing one reference fail closed before projection",
            "No delivery order selects a collision winner.",
            "M25_COLLISION_SELECTS_WINNER",
        )
    )

    spoof = make_event(
        "spoof-binding",
        a,
        kind=Kind.ACTION,
        target_id=g.reference,
    )
    s = _project(suite, Scenario((spoof,), (a,)), mutation)
    suite.checks.append(
        check(
            "W-ID-05",
            "non-grant-binding-spoof",
            g.reference not in s.bindings,
            "a non-GRANT cannot create a credential binding",
            "Claimed identifiers are lookup inputs only.",
            "M12_NON_GRANT_CREATES_BINDING",
        )
    )

    bad_grant = control("ap-derived-grant", a, Kind.GRANT, grantee_key=None)
    bad = _project(suite, Scenario((bad_grant,), (a,)), mutation)
    suite.checks.append(
        check(
            "W-ID-06",
            "non-grant-binding-spoof",
            bad.rejected.get(bad_grant.reference) is Outcome.STRUCTURAL_REJECTION
            and bad_grant.reference not in bad.bindings,
            "K never derives credential bytes from an AP transition block",
            "Missing exact GRANT-tail evidence is structural rejection.",
            "M18_AP_BYTES_AS_K_BINDING",
        )
    )

    rejected_grant = control(
        "rejected-grant",
        a,
        Kind.GRANT,
        grantee_key="66" * 32,
        malformed_tail=True,
    )
    dangling_binding = grant_binding(rejected_grant)
    dangling = make_event(
        "dangling",
        dangling_binding,
        parents=(rejected_grant.reference,),
    )
    future_grant = control("future-grant", a, Kind.GRANT, grantee_key="55" * 32)
    future_binding = grant_binding(future_grant)
    forward = make_event("forward-use", future_binding)
    u = _project(
        suite,
        Scenario((dangling, forward, future_grant, rejected_grant), (a,)),
        mutation,
    )
    suite.checks.append(
        check(
            "W-ID-07",
            "unresolvable-dangling-and-forward",
            u.rejected.get(dangling.reference) is Outcome.UNRESOLVABLE_CREDENTIAL
            and u.rejected.get(forward.reference) is Outcome.STRUCTURAL_REJECTION,
            "dangling and forward credential references reject rather than defer",
            "Dangling bindings are unresolvable; non-causal future bindings are structurally invalid.",
            "M23_UNRESOLVED_DEFERRED",
        )
    )

    suite.checks.append(
        check(
            "W-ID-08",
            "genesis-domain-separation",
            derive_genesis_credential_id(CONTEXT_ID, "0x0001", "11" * 32)
            != derive_event_reference(g, mutation)
            and credential_domains_are_separated(mutation),
            "genesis credential and grant-event references use disjoint domains",
            "K rejects equality with a genesis identifier.",
            "M21_GENESIS_USES_EVENT_DOMAIN",
        )
    )


def _topology_checks(suite: Suite, mutation: Mutation) -> None:
    a = genesis("topology-a", "91")
    y = genesis("topology-y", "92")
    z = genesis("topology-z", "93")

    revoke_y = control(
        "topology-a-revokes-y", a, Kind.REVOKE, target_id=y.credential_id
    )
    ordinary = make_event(
        "topology-y-hop", y, parents=(revoke_y.reference,)
    )
    revoke_z = control(
        "topology-y-revokes-z",
        y,
        Kind.REVOKE,
        sequence=1,
        predecessor=ordinary.reference,
        target_id=z.credential_id,
    )
    transitive = _project(
        suite,
        Scenario((revoke_z, ordinary, revoke_y), (a, y, z)),
        mutation,
    )
    suite.checks.append(
        check(
            "W-TOPO-01",
            "transitive-control-causality",
            revoke_z.reference not in transitive.accepted_controls
            and z.credential_id in transitive.terminal_authority,
            "authority ordering projects the full K causal ancestry through ordinary events",
            "A direct-control-only projection would admit a reduction by an already revoked actor.",
            "M26_DIRECT_DEPENDENCIES_ONLY",
        )
    )

    y_root = make_event("topology-y-root", y)
    a_root = make_event("topology-a-root", a)
    gap = control(
        "topology-gap",
        y,
        Kind.REVOKE,
        sequence=2,
        predecessor=y_root.reference,
        target_id=z.credential_id,
    )
    cross_author = control(
        "topology-cross-author",
        y,
        Kind.REVOKE,
        sequence=1,
        predecessor=a_root.reference,
        target_id=z.credential_id,
    )
    zero_with_predecessor = control(
        "topology-zero-with-predecessor",
        y,
        Kind.REVOKE,
        predecessor=y_root.reference,
        target_id=z.credential_id,
    )
    predecessor_in_parents = control(
        "topology-predecessor-in-parents",
        y,
        Kind.REVOKE,
        sequence=1,
        predecessor=y_root.reference,
        parents=(y_root.reference,),
        target_id=z.credential_id,
    )
    y_after_a = make_event(
        "topology-y-after-a",
        y,
        sequence=1,
        predecessor=y_root.reference,
        parents=(a_root.reference,),
    )
    redundant_parents = make_event(
        "topology-redundant-parents",
        a,
        sequence=1,
        predecessor=a_root.reference,
        parents=(y_root.reference, y_after_a.reference),
    )
    ancestor_of_predecessor = make_event(
        "topology-ancestor-of-predecessor",
        y,
        sequence=2,
        predecessor=y_after_a.reference,
        parents=(a_root.reference,),
    )
    malformed = _project(
        suite,
        Scenario(
            (
                y_root,
                a_root,
                y_after_a,
                gap,
                cross_author,
                zero_with_predecessor,
                predecessor_in_parents,
                redundant_parents,
                ancestor_of_predecessor,
            ),
            (a, y, z),
        ),
        mutation,
    )
    invalid = (
        gap,
        cross_author,
        zero_with_predecessor,
        predecessor_in_parents,
        redundant_parents,
        ancestor_of_predecessor,
    )
    suite.checks.append(
        check(
            "W-FORK-06",
            "author-chain-and-frontier-canonicality",
            all(
                malformed.rejected.get(event.reference)
                is Outcome.STRUCTURAL_REJECTION
                for event in invalid
            ),
            "invalid author continuity and non-canonical causal frontiers reject before fork or authority evaluation",
            "Gaps, cross-author predecessors, predecessor duplication and redundant ancestors are not fork evidence.",
            "M28_NO_AUTHOR_CONTINUITY",
        )
    )


def _authority_checks(suite: Suite, mutation: Mutation) -> None:
    a = genesis("a", "11")
    c = genesis("c", "33")
    grant = control("a-grants-evil", a, Kind.GRANT, grantee_key="ee" * 32)
    evil = grant_binding(grant)
    revoke_a = control("c-revokes-a", c, Kind.REVOKE, target_id=a.credential_id)
    evil_action = make_event("evil-action", evil, parents=(grant.reference,))
    scenario = Scenario((grant, revoke_a, evil_action), (a, c))
    p = _project(suite, scenario, mutation)
    converged = len(set(delivery_views(scenario, mutation))) == 1
    suite.checks.append(
        check(
            "W-AUTH-01",
            "grant-revoke-grinding-and-delivery",
            grant.reference not in p.accepted_controls
            and evil.credential_id not in p.terminal_authority
            and p.outcomes.get(evil_action.reference)
            is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
            and p.event_authority.get(evil_action.reference)
            is AuthorityVerdict.MAY_AUTH
            and p.terminal_authority <= p.necessary_terminal_authority
            and p.necessary_terminal_authority <= p.possible_terminal_authority
            and converged,
            "authority expansion requires MustAuth across every admissible order",
            "Reference grinding and delivery order cannot preserve the laundered successor.",
            "M04_POSSESSION_IMPLIES_AUTHORITY",
            "M05_EXPANSION_USES_MAY",
            "M17_TERMINAL_SET_TAMPER",
        )
    )

    ground_results: list[bool] = []
    ground_details: list[str] = []
    for sorts_before in (True, False):
        ground = grind_grant(a, revoke_a.reference, sorts_before=sorts_before)
        ground_subject = grant_binding(ground)
        early = _project(
            suite,
            Scenario((ground, revoke_a), (a, c)),
            mutation,
        )
        case_ok = (
            (ground.reference < revoke_a.reference) is sorts_before
            and ground.reference not in early.accepted_controls
            and ground_subject.credential_id not in early.terminal_authority
        )
        ground_results.append(case_ok)
        ground_details.append(
            f"grant_{'before' if sorts_before else 'after'}_revoke={case_ok}"
        )
    suite.checks.append(
        check(
            "W-AUTH-08",
            "grant-revoke-grinding-and-delivery",
            all(ground_results),
            "attacker-selected GRANT references on both order sides cannot bypass MustAuth",
            ", ".join(ground_details),
        )
    )

    d = genesis("d", "44")
    contested_grant = control(
        "a-grants-contested-successor",
        a,
        Kind.GRANT,
        grantee_key="ee" * 32,
    )
    contested_successor = grant_binding(contested_grant)
    c_revokes_a_for_successor = control(
        "c-revokes-a-for-successor",
        c,
        Kind.REVOKE,
        target_id=a.credential_id,
    )
    successor_reduces_d = control(
        "contested-successor-revokes-d",
        contested_successor,
        Kind.REVOKE,
        parents=(contested_grant.reference,),
        target_id=d.credential_id,
    )
    successor_case = _project(
        suite,
        Scenario(
            (
                contested_grant,
                c_revokes_a_for_successor,
                successor_reduces_d,
            ),
            (a, c, d),
        ),
        mutation,
    )

    b_for_resurrection = genesis("b-for-resurrection", "55")
    resurrection_grant = control(
        "a-grants-resurrection-successor",
        a,
        Kind.GRANT,
        grantee_key="ef" * 32,
    )
    resurrection_successor = grant_binding(resurrection_grant)
    successor_reduces_b = control(
        "successor-revokes-b",
        resurrection_successor,
        Kind.REVOKE,
        parents=(resurrection_grant.reference,),
        target_id=b_for_resurrection.credential_id,
    )
    b_reduces_a = control(
        "b-revokes-a-concurrently",
        b_for_resurrection,
        Kind.REVOKE,
        target_id=a.credential_id,
    )
    resurrection_case = _project(
        suite,
        Scenario(
            (resurrection_grant, successor_reduces_b, b_reduces_a),
            (a, b_for_resurrection),
        ),
        mutation,
    )
    suite.checks.append(
        check(
            "W-AUTH-09",
            "successor-reduction-standing",
            contested_grant.reference not in successor_case.accepted_controls
            and successor_reduces_d.reference in successor_case.accepted_controls
            and successor_case.reduction_standing.get(successor_reduces_d.reference)
            is ReductionStanding.POSSIBLE_GRANT
            and not resurrection_case.terminal_authority,
            "prefix-possible reduction standing is explicit and cannot be conditioned on final grant acceptance",
            "Filtering reductions by accepted grants would resurrect a revoked peer as sole authority.",
            "M07_IGNORE_MAY_REDUCTION",
        )
    )

    a_revokes_c = control("a-revokes-c", a, Kind.REVOKE, target_id=c.credential_id)
    c_revokes_a = control("c-revokes-a-2", c, Kind.REVOKE, target_id=a.credential_id)
    mutual = _project(
        suite, Scenario((a_revokes_c, c_revokes_a), (a, c)), mutation
    )
    suite.checks.append(
        check(
            "W-AUTH-02",
            "mutual-concurrent-revocation",
            not mutual.terminal_authority
            and {a_revokes_c.reference, c_revokes_a.reference}
            <= mutual.accepted_controls,
            "authority reductions use MayAuth and mutual revocation is non-resurrecting",
            "No canonical ordering chooses a winner.",
            "M06_REDUCTION_REQUIRES_MUST",
            "M08_SINGLE_LINEARIZATION",
            "M11_CANONICAL_MUTUAL_REVOCATION",
        )
    )

    b = genesis("b", "22")
    c_revokes_a3 = control("c-revokes-a-3", c, Kind.REVOKE, target_id=a.credential_id)
    a_revokes_b = control("a-revokes-b", a, Kind.REVOKE, target_id=b.credential_id)
    possible = _project(
        suite, Scenario((c_revokes_a3, a_revokes_b), (a, b, c)), mutation
    )
    suite.checks.append(
        check(
            "W-AUTH-03",
            "may-only-reduction",
            b.credential_id not in possible.terminal_authority,
            "a reduction by a MayAuth-only actor remains effective",
            "Requiring MustAuth for reductions would resurrect authority.",
            "M06_REDUCTION_REQUIRES_MUST",
        )
    )

    g_b = control("a-grants-b", a, Kind.GRANT, grantee_key="24" * 32)
    b_child = grant_binding(g_b)
    g_c = control(
        "b-grants-c",
        b_child,
        Kind.GRANT,
        parents=(g_b.reference,),
        grantee_key="25" * 32,
    )
    c_child = grant_binding(g_c)
    revoke_root = control(
        "c-revokes-root", c, Kind.REVOKE, target_id=a.credential_id
    )
    child_action = make_event(
        "c-child-action", c_child, parents=(g_c.reference,)
    )
    chain = _project(
        suite,
        Scenario((g_b, g_c, revoke_root, child_action), (a, c)),
        mutation,
    )
    suite.checks.append(
        check(
            "W-AUTH-04",
            "multi-hop-provenance-containment",
            {a.credential_id, b_child.credential_id, c_child.credential_id}
            <= chain.terminated
            and child_action.reference in chain.admitted
            and chain.outcomes.get(child_action.reference)
            is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
            and chain.event_authority.get(child_action.reference)
            is AuthorityVerdict.MAY_AUTH,
            "revocation terminates every bounded descendant while retaining K evidence",
            "Late evidence cannot revive a tainted lineage.",
            "M09_NON_TRANSITIVE_PROVENANCE",
        )
    )

    before = make_event("a-before-revocation", a)
    revoke_after = control(
        "c-revokes-a-after-action",
        c,
        Kind.REVOKE,
        parents=(before.reference,),
        target_id=a.credential_id,
    )
    after = make_event(
        "a-after-revocation",
        a,
        sequence=1,
        predecessor=before.reference,
        parents=(revoke_after.reference,),
    )
    prefix = _project(
        suite,
        Scenario((after, revoke_after, before), (a, c)),
        mutation,
    )
    suite.checks.append(
        check(
            "W-AUTH-12",
            "ordinary-event-prefix-authority",
            prefix.event_authority.get(before.reference)
            is AuthorityVerdict.MUST_AUTH
            and prefix.outcomes.get(before.reference) is Outcome.APPLIED
            and prefix.event_authority.get(after.reference)
            is AuthorityVerdict.NO_AUTH
            and prefix.outcomes.get(after.reference) is Outcome.POST_REVOCATION
            and a.credential_id in prefix.terminated,
            "ordinary events use authority at their causal acting prefix",
            "A later revocation cannot rewrite prior history, while a causal successor fails closed.",
            "M33_TERMINAL_AUTHORITY_FOR_ORDINARY",
        )
    )

    fresh_after_containment = control(
        "untainted-regrant-after-containment",
        c,
        Kind.GRANT,
        sequence=1,
        predecessor=revoke_root.reference,
        grantee_key="26" * 32,
    )
    fresh_binding = grant_binding(fresh_after_containment)
    fresh_action = make_event(
        "untainted-regrant-action",
        fresh_binding,
        parents=(fresh_after_containment.reference,),
    )
    repaired = _project(
        suite,
        Scenario(
            (g_b, g_c, revoke_root, fresh_after_containment, fresh_action),
            (a, c),
        ),
        mutation,
    )
    suite.checks.append(
        check(
            "W-AUTH-07",
            "multi-hop-provenance-containment",
            {a.credential_id, b_child.credential_id, c_child.credential_id}
            <= repaired.terminated
            and fresh_binding.credential_id in repaired.terminal_authority
            and repaired.outcomes.get(fresh_action.reference) is Outcome.APPLIED,
            "an independent authority can issue a fresh untainted grant after containment",
            "Continuity requires new provenance; no terminated identifier is reused.",
        )
    )

    x = genesis("x", "66")
    y = genesis("y", "77")
    x_revoke_y = control("x-revokes-y", x, Kind.REVOKE, target_id=y.credential_id)
    x_revoke_c = control(
        "x-revokes-c",
        x,
        Kind.REVOKE,
        sequence=1,
        predecessor=x_revoke_y.reference,
        target_id=c.credential_id,
    )
    takeover = _project(
        suite, Scenario((x_revoke_y, x_revoke_c), (x, y, c)), mutation
    )
    suite.checks.append(
        check(
            "W-AUTH-05",
            "single-compromised-authority-takeover",
            takeover.terminal_authority == {x.credential_id},
            "one uncontested valid authority can remove all peers and remain sole producer",
            "This measured availability/safety limit is disclosed, not repaired by quorum or timeout.",
        )
    )

    revoked_reduction = control(
        "revoked-a-reduces-c",
        a,
        Kind.REVOKE,
        parents=(revoke_a.reference,),
        target_id=c.credential_id,
    )
    rr = _project(
        suite, Scenario((revoke_a, revoked_reduction), (a, c)), mutation
    )
    suite.checks.append(
        check(
            "W-AUTH-06",
            "may-only-reduction",
            revoked_reduction.reference not in rr.accepted_controls
            and c.credential_id in rr.terminal_authority,
            "an actor revoked in every acting-prefix interpretation cannot reduce authority",
            "MayAuth does not mean possession after terminal revocation.",
            "M24_REVOKED_REDUCTION_ACCEPTED",
        )
    )


def _succession_alias_fork_checks(suite: Suite, mutation: Mutation) -> None:
    a = genesis("a", "11")
    b = genesis("b", "22")
    c = genesis("c", "33")
    grant_old = control("grant-old", a, Kind.GRANT, grantee_key="44" * 32)
    old = grant_binding(grant_old)
    revoke_old = control(
        "revoke-old", b, Kind.REVOKE, target_id=old.credential_id
    )
    regrant_old = control(
        "regrant-old-id",
        c,
        Kind.GRANT,
        grantee_key="44" * 32,
        target_id=old.credential_id,
    )
    recover_old = control(
        "recover-old-id",
        b,
        Kind.RECOVER,
        sequence=1,
        predecessor=revoke_old.reference,
        target_id=old.credential_id,
    )
    p = _project(
        suite,
        Scenario((grant_old, revoke_old, regrant_old, recover_old), (a, b, c)),
        mutation,
    )
    suite.checks.append(
        check(
            "W-SUCC-01",
            "regrant-and-recovery-non-resurrection",
            p.rejected.get(regrant_old.reference) is Outcome.STRUCTURAL_REJECTION
            and p.rejected.get(recover_old.reference) is Outcome.STRUCTURAL_REJECTION
            and p.bindings[old.credential_id].issuer_id == a.credential_id
            and old.credential_id in p.terminated
            and old.credential_id not in p.terminal_authority,
            "revoked identifiers are never re-granted or recovered",
            "Legitimate recovery requires a fresh GRANT reference and lineage.",
            "M19_REGRANT_REVOKED_IDENTIFIER",
        )
    )

    alias_one = control("alias-one", a, Kind.GRANT, grantee_key="aa" * 32)
    alias_two = control(
        "alias-two",
        a,
        Kind.GRANT,
        sequence=1,
        predecessor=alias_one.reference,
        grantee_key="aa" * 32,
    )
    alias_one_binding = grant_binding(alias_one)
    alias_two_binding = grant_binding(alias_two)
    alias_one_action = make_event(
        "alias-one-action", alias_one_binding, parents=(alias_one.reference,)
    )
    alias_two_action = make_event(
        "alias-two-action", alias_two_binding, parents=(alias_two.reference,)
    )
    alias_equivocation = _project(
        suite,
        Scenario(
            (alias_one, alias_two, alias_one_action, alias_two_action),
            (a, b),
        ),
        mutation,
    )
    revoke_alias_one = control(
        "revoke-alias-one",
        b,
        Kind.REVOKE,
        target_id=alias_one_binding.credential_id,
    )
    aliases = _project(
        suite, Scenario((alias_one, alias_two, revoke_alias_one), (a, b)), mutation
    )
    suite.checks.append(
        check(
            "W-SUCC-02",
            "alias-evidence-survival",
            len(aliases.alias_groups) == 1
            and alias_one.reference not in aliases.terminal_authority
            and alias_two.reference in aliases.terminal_authority
            and {
                alias_one_action.reference,
                alias_two_action.reference,
            } <= {
                reference
                for reference, outcome in alias_equivocation.outcomes.items()
                if outcome is Outcome.APPLIED
            }
            and not {
                alias_one_binding.credential_id,
                alias_two_binding.credential_id,
            } & alias_equivocation.forked_credentials,
            "byte-identical keys form visible alias evidence without coupled revocation",
            "One issuer can mint same-key aliases that survive independently and equivocate without credential-scoped fork evidence.",
            "M16_ALIAS_CHANGES_AUTHORITY",
        )
    )

    fresh = control("fresh-rotation-grant", b, Kind.GRANT, grantee_key="55" * 32)
    rotate = control(
        "retire-old-on-rotation",
        b,
        Kind.ROTATE,
        sequence=1,
        predecessor=fresh.reference,
        target_id=a.credential_id,
        target_reference=fresh.reference,
    )
    rotated = grant_binding(fresh)
    old_action = make_event(
        "old-key-continuation", a, parents=(rotate.reference,)
    )
    new_action = make_event(
        "new-key-action", rotated, parents=(rotate.reference,)
    )
    rotation = _project(
        suite, Scenario((fresh, rotate, old_action, new_action), (a, b)), mutation
    )
    suite.checks.append(
        check(
            "W-SUCC-03",
            "rotation-recovery-and-old-key-continuation",
            rotation.outcomes.get(old_action.reference)
            in {Outcome.POST_REVOCATION, Outcome.LINEAGE_QUARANTINED}
            and rotation.outcomes.get(new_action.reference) is Outcome.APPLIED,
            "rotation is fresh grant plus authorized retirement; old-key continuation is inert",
            "ROTATE/RECOVER do not create bindings by themselves.",
        )
    )

    recovery_grant = control(
        "independent-recovery-grant",
        c,
        Kind.GRANT,
        grantee_key="56" * 32,
    )
    recovered = grant_binding(recovery_grant)
    recovery = control(
        "independent-recovery",
        c,
        Kind.RECOVER,
        sequence=1,
        predecessor=recovery_grant.reference,
        parents=(revoke_old.reference,),
        target_id=old.credential_id,
        target_reference=recovery_grant.reference,
    )
    recovered_action = make_event(
        "recovered-action",
        recovered,
        parents=(recovery.reference,),
    )
    recovery_projection = _project(
        suite,
        Scenario(
            (grant_old, revoke_old, recovery_grant, recovery, recovered_action),
            (a, b, c),
        ),
        mutation,
    )
    suite.checks.append(
        check(
            "W-SUCC-04",
            "regrant-and-recovery-non-resurrection",
            recovery_grant.reference in recovery_projection.accepted_controls
            and recovery.reference in recovery_projection.accepted_controls
            and old.credential_id in recovery_projection.terminated
            and recovered.credential_id in recovery_projection.terminal_authority
            and recovery_projection.outcomes.get(recovered_action.reference)
            is Outcome.APPLIED,
            "recovery uses an independently authorized fresh GRANT and never rebinds the old identifier",
            "Recovery continuity is explicit evidence, not resurrection.",
            "M10_RECOVERY_RESURRECTS_REVOKED",
        )
    )

    concurrent_revoke = control(
        "concurrent-rotation-revoke",
        c,
        Kind.REVOKE,
        target_id=a.credential_id,
    )
    rotation_race = _project(
        suite,
        Scenario((fresh, rotate, concurrent_revoke), (a, b, c)),
        mutation,
    )
    suite.checks.append(
        check(
            "W-SUCC-05",
            "rotation-recovery-and-old-key-continuation",
            a.credential_id in rotation_race.terminated
            and rotated.credential_id in rotation_race.terminal_authority
            and {rotate.reference, concurrent_revoke.reference}
            <= rotation_race.accepted_controls,
            "concurrent ROTATE and REVOKE cannot resurrect the retiring credential",
            "The fresh GRANT remains independently evaluated under MustAuth.",
        )
    )

    left = make_event("a-fork-left", a, sequence=0)
    right = make_event("a-fork-right", a, sequence=0)
    independent_grant = control("b-grants-independent", b, Kind.GRANT, grantee_key="99" * 32)
    independent = grant_binding(independent_grant)
    independent_action = make_event(
        "independent-action", independent, parents=(independent_grant.reference,)
    )
    fork = _project(
        suite,
        Scenario((left, right, independent_grant, independent_action), (a, b)),
        mutation,
    )
    suite.checks.append(
        check(
            "W-FORK-01",
            "independent-authority-continuation",
            a.credential_id in fork.forked_credentials
            and a.credential_id not in fork.terminal_authority
            and independent.credential_id in fork.terminal_authority
            and fork.outcomes.get(independent_action.reference) is Outcome.APPLIED,
            "fork quarantine is credential-lineage scoped and cannot expand authority",
            "Independent definitely authorized progress survives.",
            "M14_FORK_EXPANDS_AUTHORITY",
        )
    )
    suite.checks.append(
        check(
            "W-FORK-02",
            "fork-scope-and-privilege-neutrality",
            left.reference in fork.admitted
            and right.reference in fork.admitted
            and fork.outcomes.get(left.reference) is Outcome.FORK_EVIDENCE
            and fork.outcomes.get(right.reference) is Outcome.FORK_EVIDENCE,
            "ordinary, privileged, genesis and revoked credentials use one fork rule",
            "A fork remains K evidence; role labels do not alter its scope.",
        )
    )

    fork_matrix_ok = True
    fork_matrix_details: list[str] = []
    for kind in (Kind.GRANT, Kind.REVOKE, Kind.ROTATE, Kind.RECOVER):
        for placement in ("before", "after"):
            replacement = control(
                f"{kind.value.lower()}-{placement}-replacement",
                b,
                Kind.GRANT,
                grantee_key=("a1" if kind is Kind.ROTATE else "a2") * 32,
            )
            extra_events: tuple[Event, ...] = ()
            target_reference: str | None = None
            parents: tuple[str, ...] = ()
            if kind in {Kind.ROTATE, Kind.RECOVER}:
                extra_events = (replacement,)
                target_reference = replacement.reference
                parents = (replacement.reference,)

            if placement == "before":
                fork_left = make_event(f"{kind.value.lower()}-fork-left", a)
                fork_right = make_event(f"{kind.value.lower()}-fork-right", a)
                candidate = control(
                    f"{kind.value.lower()}-after-fork",
                    a,
                    kind,
                    sequence=1,
                    predecessor=fork_left.reference,
                    parents=parents,
                    grantee_key="b1" * 32 if kind is Kind.GRANT else None,
                    target_id=b.credential_id if kind is not Kind.GRANT else None,
                    target_reference=target_reference,
                )
                events = extra_events + (fork_left, fork_right, candidate)
            else:
                candidate = control(
                    f"{kind.value.lower()}-at-fork",
                    a,
                    kind,
                    parents=parents,
                    grantee_key="b2" * 32 if kind is Kind.GRANT else None,
                    target_id=b.credential_id if kind is not Kind.GRANT else None,
                    target_reference=target_reference,
                )
                fork_peer = make_event(f"{kind.value.lower()}-fork-peer", a)
                events = extra_events + (candidate, fork_peer)

            matrix_projection = _project(
                suite, Scenario(events, (a, b)), mutation
            )
            expected_accepted = (
                kind in REDUCTION_KINDS if placement == "before" else True
            )
            case_ok = (
                a.credential_id in matrix_projection.forked_credentials
                and (
                    (candidate.reference in matrix_projection.accepted_controls)
                    is expected_accepted
                )
                and a.credential_id not in matrix_projection.terminal_authority
            )
            fork_matrix_ok = fork_matrix_ok and case_ok
            fork_matrix_details.append(f"{kind.value}:{placement}={case_ok}")

    suite.checks.append(
        check(
            "W-FORK-03",
            "fork-scope-and-privilege-neutrality",
            fork_matrix_ok,
            "fork joins preserve causally prior controls, admit only possible branch-local reductions, and block branch-local expansions",
            ", ".join(fork_matrix_details),
        )
    )

    revoke_before_fork = control(
        "a-revokes-b-before-fork",
        a,
        Kind.REVOKE,
        target_id=b.credential_id,
    )
    fork_after_left = make_event(
        "a-forks-after-revoke-left",
        a,
        sequence=1,
        predecessor=revoke_before_fork.reference,
    )
    fork_after_right = make_event(
        "a-forks-after-revoke-right",
        a,
        sequence=1,
        predecessor=revoke_before_fork.reference,
    )
    non_resurrection = _project(
        suite,
        Scenario(
            (revoke_before_fork, fork_after_left, fork_after_right),
            (a, b),
        ),
        mutation,
    )
    suite.checks.append(
        check(
            "W-FORK-04",
            "fork-after-reduction-non-resurrection",
            revoke_before_fork.reference in non_resurrection.accepted_controls
            and b.credential_id not in non_resurrection.terminal_authority
            and a.credential_id not in non_resurrection.terminal_authority,
            "a later fork cannot retroactively void an accepted causal-prefix reduction",
            "Positional fork joins terminate the forker without resurrecting its prior targets.",
            "M27_GLOBAL_FORK_TERMINATION",
        )
    )

    twin_revoke = control(
        "a-revokes-b-as-fork-sibling",
        a,
        Kind.REVOKE,
        target_id=b.credential_id,
    )
    ordinary_twin = make_event("a-ordinary-fork-sibling", a)
    twin_projection = _project(
        suite,
        Scenario((ordinary_twin, twin_revoke), (a, b)),
        mutation,
    )
    suite.checks.append(
        check(
            "W-FORK-07",
            "fork-twin-non-resurrection",
            twin_revoke.reference in twin_projection.accepted_controls
            and b.credential_id not in twin_projection.terminal_authority
            and a.credential_id not in twin_projection.terminal_authority
            and {
                twin_revoke.reference,
                ordinary_twin.reference,
            }
            <= {
                reference
                for reference, outcome in twin_projection.outcomes.items()
                if outcome is Outcome.FORK_EVIDENCE
            },
            "a valid reduction sibling is evaluated before the fork join",
            "The virtual join cannot move ahead of its own evidence and resurrect the reduction target.",
            "M32_FORK_JOIN_BEFORE_SIBLINGS",
        )
    )

    boundary_left = make_event("fork-boundary-left", a)
    boundary_right = make_event("fork-boundary-right", a)
    branch_reduction = control(
        "branch-local-reduction",
        a,
        Kind.REVOKE,
        sequence=1,
        predecessor=boundary_left.reference,
        target_id=c.credential_id,
    )
    branch_reduction_projection = _project(
        suite,
        Scenario(
            (boundary_left, boundary_right, branch_reduction),
            (a, b, c),
        ),
        mutation,
    )
    acknowledging_reduction = control(
        "fork-acknowledging-reduction",
        a,
        Kind.REVOKE,
        sequence=1,
        predecessor=boundary_left.reference,
        parents=(boundary_right.reference,),
        target_id=c.credential_id,
    )
    acknowledging_projection = _project(
        suite,
        Scenario(
            (boundary_left, boundary_right, acknowledging_reduction),
            (a, b, c),
        ),
        mutation,
    )
    branch_grant = control(
        "branch-local-expansion",
        a,
        Kind.GRANT,
        sequence=1,
        predecessor=boundary_left.reference,
        grantee_key="b3" * 32,
    )
    branch_grant_projection = _project(
        suite,
        Scenario((boundary_left, boundary_right, branch_grant), (a, b)),
        mutation,
    )
    suite.checks.append(
        check(
            "W-FORK-08",
            "fork-acknowledgment-boundary",
            branch_reduction.reference
            in branch_reduction_projection.accepted_controls
            and c.credential_id
            not in branch_reduction_projection.terminal_authority
            and acknowledging_reduction.reference
            not in acknowledging_projection.accepted_controls
            and c.credential_id in acknowledging_projection.terminal_authority
            and branch_grant.reference
            not in branch_grant_projection.accepted_controls,
            "fork effects begin at the causal join rather than at global discovery time",
            "A branch-local possible reduction remains effective, while an acknowledging reduction and every branch-local expansion fail closed.",
        )
    )

    parent_grant = control(
        "fork-parent-grants-successor",
        a,
        Kind.GRANT,
        grantee_key="b4" * 32,
    )
    successor = grant_binding(parent_grant)
    parent_left = make_event(
        "fork-parent-left",
        a,
        sequence=1,
        predecessor=parent_grant.reference,
    )
    parent_right = make_event(
        "fork-parent-right",
        a,
        sequence=1,
        predecessor=parent_grant.reference,
    )
    successor_reduction = control(
        "forked-successor-reduces-c",
        successor,
        Kind.REVOKE,
        parents=(parent_grant.reference,),
        target_id=c.credential_id,
    )
    successor_expansion = control(
        "forked-successor-expands",
        successor,
        Kind.GRANT,
        sequence=1,
        predecessor=successor_reduction.reference,
        grantee_key="b5" * 32,
    )
    descendant_projection = _project(
        suite,
        Scenario(
            (
                parent_grant,
                parent_left,
                parent_right,
                successor_reduction,
                successor_expansion,
            ),
            (a, b, c),
        ),
        mutation,
    )
    suite.checks.append(
        check(
            "W-FORK-09",
            "forked-descendant-containment",
            successor_reduction.reference
            in descendant_projection.accepted_controls
            and successor_expansion.reference
            not in descendant_projection.accepted_controls
            and c.credential_id not in descendant_projection.terminal_authority
            and successor.credential_id not in descendant_projection.terminal_authority,
            "a fork terminates its grant descendants without resurrecting their causal-prefix reductions",
            "A descendant keeps only possible destructive standing; it cannot expand authority.",
        )
    )


def _pending_checkpoint_removal_checks(suite: Suite, mutation: Mutation) -> None:
    a = genesis("a", "11")
    b = genesis("b", "22")
    pending = make_event(
        "required-pending",
        a,
        content_class=ContentClass.REQUIRED,
        opening_verified=False,
    )
    revoke = control(
        "b-revokes-a-behind-pending",
        b,
        Kind.REVOKE,
        parents=(pending.reference,),
        target_id=a.credential_id,
        ap_applicable=False,
    )
    child = make_event(
        "pending-child", a, sequence=1, predecessor=pending.reference, parents=(revoke.reference,)
    )
    p = _project(suite, Scenario((pending, revoke, child), (a, b)), mutation)
    suite.checks.append(
        check(
            "W-PENDING-01",
            "pending-required-with-authority",
            pending.reference in p.pending_roots
            and {revoke.reference, child.reference} <= p.pending
            and a.credential_id not in p.terminal_authority,
            "K authority evidence is retained even when AP is pending or inapplicable",
            "No opening, removal or AP outcome filters the set-relative authority set.",
            "M20_FILTER_EVIDENCE_BY_AP_STATE",
        )
    )

    stale_scenario = Scenario(
        (pending,),
        (a,),
        checkpoint_references=("missing-history",),
        replay_dependencies=("missing-history",),
    )
    stale = _project(suite, stale_scenario, mutation)
    suite.checks.append(
        check(
            "W-CP-01",
            "checkpoint-stale-no-substitution",
            stale.stale_evidence
            and not stale.authority_available
            and not stale.accepted_controls
            and not stale.event_authority
            and not stale.possible_terminal_authority
            and not stale.necessary_terminal_authority
            and not stale.terminal_authority
            and all(value is Outcome.STALE_EVIDENCE for value in stale.outcomes.values()),
            "checkpoint-only evidence is stale and never substitutes for retained history",
            "No freshness, finality or rollback claim follows.",
            "M15_CHECKPOINT_SUBSTITUTES",
        )
    )

    grant = control("grant-target", a, Kind.GRANT, grantee_key="88" * 32)
    removal = make_event(
        "remove-control",
        b,
        role=Role.RETENTION_CONTROL,
        kind=Kind.REMOVE,
        target_reference=grant.reference,
    )
    removed = _project(suite, Scenario((grant, removal), (a, b)), mutation)
    suite.checks.append(
        check(
            "W-REMOVE-01",
            "removal-control-inapplicable",
            removed.outcomes.get(removal.reference) is Outcome.REMOVAL_INAPPLICABLE
            and grant.reference in removed.bindings,
            "logical removal cannot target CREDENTIAL_CONTROL evidence",
            "Binding, provenance and authority remain unchanged.",
        )
    )

    malformed = control(
        "malformed-control", a, Kind.GRANT, grantee_key="77" * 32, malformed_tail=True
    )
    content_control = control(
        "content-control",
        a,
        Kind.GRANT,
        grantee_key="76" * 32,
        content_class=ContentClass.REQUIRED,
    )
    structure = _project(
        suite, Scenario((malformed, content_control), (a,)), mutation
    )
    suite.checks.append(
        check(
            "W-STRUCT-01",
            "control-tail-and-content-structure",
            structure.rejected.get(malformed.reference) is Outcome.STRUCTURAL_REJECTION
            and structure.rejected.get(content_control.reference)
            is Outcome.STRUCTURAL_REJECTION,
            "malformed tails and content-bearing credential controls reject before AP",
            "The O-06b-1 role/class boundary is fail closed.",
            "M13_MALFORMED_TAIL_ACCEPTED",
            "M22_CONTROL_CONTENT_ACCEPTED",
        )
    )


def _convergence_bounds_checks(suite: Suite, mutation: Mutation) -> None:
    a = genesis("case-ephemeral-a", "a1")
    b = genesis("organization-role-b", "b2")
    event_a = make_event("transport-neutral-a", a)
    event_b = make_event("transport-neutral-b", b)
    scenario = Scenario((event_a, event_b), (a, b))
    views = delivery_views(scenario, mutation)
    suite.checks.append(
        check(
            "W-CONV-01",
            "full-replay-delivery-convergence",
            len(views) == 2 and len(set(views)) == 1,
            "fresh full replay converges for every bounded delivery permutation",
            "V3 selects full replay only; no prefix-cache handoff is claimed.",
        )
    )
    projection = _project(suite, scenario, mutation)
    suite.checks.append(
        check(
            "W-NEUTRAL-01",
            "transport-and-case-ephemeral-neutrality",
            projection.terminal_authority == {a.credential_id, b.credential_id}
            and not hasattr(event_a, "nostr_key")
            and not hasattr(event_a, "mls_leaf")
            and not hasattr(event_a, "transport_sender"),
            "case-ephemeral credentials are first-class and transport/session facts are absent",
            "No account, MLS, Nostr, storage, operator or UI identity is application authority.",
        )
    )

    excessive = tuple(make_event(f"flood-{index}", a, sequence=index) for index in range(MAX_EVENTS + 1))
    suite.checks.append(
        check(
            "W-BOUND-01",
            "bounded-hostile-flood",
            _expect_error(Scenario(excessive, (a,)), mutation, "MODEL_BOUND_EXCEEDED"),
            "event, parent, order and lineage envelopes fail closed before expansion",
            f"Common candidate envelope: {BOUNDS}",
        )
    )

    excessive_parents = make_event(
        "excessive-parent-frontier",
        a,
        parents=tuple(f"missing-parent-{index}" for index in range(MAX_PARENTS + 1)),
    )
    oversized_key = make_event(
        "oversized-verification-key",
        a,
        claimed_actor_key="ab" * (MAX_KEY_OCTETS + 1),
    )
    overflow_sequence = make_event(
        "overflow-author-sequence",
        a,
        sequence=2**64,
        forced_reference="overflow-author-sequence",
    )
    suite.checks.append(
        check(
            "W-BOUND-02",
            "bounded-hostile-flood",
            _expect_error(
                Scenario((excessive_parents,), (a,)),
                mutation,
                "MODEL_BOUND_EXCEEDED",
            )
            and _expect_error(
                Scenario((oversized_key,), (a,)),
                mutation,
                "MODEL_BOUND_EXCEEDED",
            )
            and _expect_error(
                Scenario((overflow_sequence,), (a,)),
                mutation,
                "MODEL_BOUND_EXCEEDED",
            ),
            "parent, verification-key and author-sequence scalar bounds fail closed",
            "Each scalar limit is exercised independently before graph or authority processing.",
        )
    )

    lineage_events: list[Event] = []
    lineage_actor = a
    for index in range(MAX_LINEAGE_DEPTH + 1):
        grant = control(
            f"lineage-depth-{index}",
            lineage_actor,
            Kind.GRANT,
            parents=(lineage_events[-1].reference,) if lineage_events else (),
            grantee_key=f"{0xc0 + index:02x}" * 32,
        )
        lineage_events.append(grant)
        lineage_actor = grant_binding(grant)
    too_many_genesis = tuple(
        genesis(f"credential-bound-{index}", f"{0xd0 + index:02x}")
        for index in range(MAX_CREDENTIALS + 1)
    )
    suite.checks.append(
        check(
            "W-BOUND-03",
            "bounded-hostile-flood",
            _expect_error(
                Scenario(tuple(lineage_events), (a,)),
                mutation,
                "LINEAGE_BOUND_EXCEEDED",
            )
            and _expect_error(
                Scenario((), too_many_genesis),
                mutation,
                "MODEL_BOUND_EXCEEDED",
            ),
            "credential cardinality and provenance depth are independently bounded",
            "A deep grant chain or oversized initial authority set cannot reach a positive authority result.",
        )
    )

    control_actors = tuple(
        genesis(f"order-actor-{index}", f"{0xe0 + index:02x}")
        for index in range(MAX_CONTROL_EVENTS)
    )
    independent_controls = tuple(
        control(
            f"independent-control-{index}",
            actor,
            Kind.REVOKE,
            target_id=actor.credential_id,
        )
        for index, actor in enumerate(control_actors)
    )
    exact_order_projection = _project(
        suite,
        Scenario(independent_controls, control_actors),
        mutation,
    )
    excessive_controls = independent_controls + (
        control(
            "excessive-control",
            control_actors[0],
            Kind.REVOKE,
            target_id=control_actors[0].credential_id,
        ),
    )
    suite.checks.append(
        check(
            "W-BOUND-04",
            "bounded-hostile-flood",
            exact_order_projection.explored_orders == MAX_TOPOLOGICAL_ORDERS
            and _expect_error(
                Scenario(excessive_controls, control_actors),
                mutation,
                "AUTHORITY_BOUND_EXCEEDED",
            ),
            "the exact linear-extension ceiling is reachable and one additional control fails closed",
            "Backtracking enumeration counts real orders rather than allocating all permutations first.",
        )
    )

    join_siblings = tuple(
        make_event(f"join-flood-{index}", a)
        for index in range(5)
    )
    join_projection = _project(
        suite,
        Scenario(join_siblings, (a,)),
        mutation,
    )
    suite.checks.append(
        check(
            "W-BOUND-05",
            "bounded-hostile-flood",
            join_projection.forked_credentials == {a.credential_id}
            and len(join_projection.fork_joins) == 1
            and a.credential_id not in join_projection.terminal_authority,
            "one bounded virtual join represents a complete same-sequence fork slot",
            "A k-way equivocation terminates only its lineage without quadratic joins or whole-context failure.",
        )
    )

    delivery_flood = Scenario(
        tuple(make_event(f"delivery-flood-{index}", a) for index in range(7)),
        (a,),
    )
    try:
        delivery_views(delivery_flood, mutation)
    except ModelInputError as error:
        delivery_bound_ok = error.code == "DELIVERY_BOUND_EXCEEDED"
    else:
        delivery_bound_ok = False
    suite.checks.append(
        check(
            "W-BOUND-06",
            "bounded-hostile-flood",
            delivery_bound_ok,
            "delivery-permutation exploration has an explicit independent width bound",
            "The reporting harness cannot silently attempt factorial work beyond its declared envelope.",
        )
    )


def run_required_suite(mutation: Mutation = Mutation()) -> Suite:
    global _BUILD_MUTATION
    previous = _BUILD_MUTATION
    _BUILD_MUTATION = mutation
    try:
        suite = Suite(checks=[], projections=[])
        _identifier_checks(suite, mutation)
        _topology_checks(suite, mutation)
        _authority_checks(suite, mutation)
        _succession_alias_fork_checks(suite, mutation)
        _pending_checkpoint_removal_checks(suite, mutation)
        _convergence_bounds_checks(suite, mutation)
        return suite
    finally:
        _BUILD_MUTATION = previous


def declared_mutation_coverage() -> Mapping[str, tuple[str, ...]]:
    suite = run_required_suite()
    coverage: dict[str, list[str]] = {item: [] for item in REQUIRED_MUTANTS}
    for item in suite.checks:
        for mutant in item.kills:
            coverage[mutant].append(item.identifier)
    return {key: tuple(sorted(values)) for key, values in sorted(coverage.items())}


def mutation_coverage() -> Mapping[str, tuple[str, ...]]:
    """Return only witness→mutant edges observed to fail under that mutant."""

    declared = declared_mutation_coverage()
    observed: dict[str, tuple[str, ...]] = {}
    for mutant, detectors in declared.items():
        results = {
            item.identifier: item.passed
            for item in run_required_suite(Mutation(mutant)).checks
        }
        observed[mutant] = tuple(
            detector for detector in detectors if not results.get(detector, True)
        )
    return observed
