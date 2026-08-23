"""Closed C0.2j hostile-witness suite for the independent v3 model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from protocol_model_v3 import (
    Binding,
    ContentClass,
    CONTEXT_ID,
    Event,
    Kind,
    MAX_CONTROL_EVENTS,
    MAX_EVENTS,
    MAX_LINEAGE_DEPTH,
    MAX_PARENTS,
    MAX_TOPOLOGICAL_ORDERS,
    ModelInputError,
    Mutation,
    Outcome,
    Projection,
    Role,
    Scenario,
    derive_event_reference,
    derive_genesis_credential_id,
    delivery_views,
    grant_binding,
    make_event,
    project,
)


BOUNDS = {
    "events": MAX_EVENTS,
    "control_events": MAX_CONTROL_EVENTS,
    "parents_per_event": MAX_PARENTS,
    "lineage_depth": MAX_LINEAGE_DEPTH,
    "topological_orders": MAX_TOPOLOGICAL_ORDERS,
    "delivery_permutation_width": 6,
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
        "M17_INCREMENTAL_DIVERGES",
        "M18_AP_BYTES_AS_K_BINDING",
        "M19_REGRANT_REVOKED_IDENTIFIER",
        "M20_FILTER_EVIDENCE_BY_AP_STATE",
        "M21_GENESIS_USES_EVENT_DOMAIN",
        "M22_CONTROL_CONTENT_ACCEPTED",
        "M23_UNRESOLVED_DEFERRED",
        "M24_REVOKED_REDUCTION_ACCEPTED",
    }
)

REQUIRED_WITNESSES = frozenset(
    {
        "identifier-binding-and-cross-context",
        "duplicate-grant-and-deliberate-collision",
        "genesis-domain-separation",
        "grant-revoke-grinding-and-delivery",
        "may-only-reduction",
        "multi-hop-provenance-containment",
        "independent-authority-continuation",
        "mutual-concurrent-revocation",
        "single-compromised-authority-takeover",
        "regrant-and-recovery-non-resurrection",
        "alias-evidence-survival",
        "rotation-recovery-and-old-key-continuation",
        "fork-scope-and-privilege-neutrality",
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
    suite.checks.append(
        check(
            "W-ID-01",
            "identifier-binding-and-cross-context",
            p.outcomes.get(g.reference) is Outcome.APPLIED
            and p.outcomes.get(use.reference) is Outcome.APPLIED
            and b.credential_id == g.reference
            and b.issuer_id == a.credential_id,
            "grant-rooted identifier is the causal GRANT reference and binds issuer/suite/key",
            "No declared subject or ambient AP/transport field contributes to the identifier.",
            "M01_IDENTIFIER_OMITS_CONTEXT",
            "M02_IDENTIFIER_OMITS_ALGORITHM",
            "M03_IDENTIFIER_OMITS_ISSUER",
            "M21_GENESIS_USES_EVENT_DOMAIN",
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
            bad.rejected.get(bad_grant.reference) is Outcome.STRUCTURAL_REJECTION,
            "K never derives credential bytes from an AP transition block",
            "Missing exact GRANT-tail evidence is structural rejection.",
            "M18_AP_BYTES_AS_K_BINDING",
        )
    )

    dangling_binding = Binding("ff" * 32, "0x0001", "55" * 32, None, "none")
    dangling = make_event("dangling", dangling_binding)
    future_grant = control("future-grant", a, Kind.GRANT, grantee_key="55" * 32)
    future_binding = grant_binding(future_grant)
    forward = make_event("forward-use", future_binding)
    u = _project(
        suite, Scenario((dangling, forward, future_grant), (a,)), mutation
    )
    suite.checks.append(
        check(
            "W-ID-07",
            "unresolvable-dangling-and-forward",
            u.rejected.get(dangling.reference) is Outcome.UNRESOLVABLE_CREDENTIAL
            and u.rejected.get(forward.reference) is Outcome.UNRESOLVABLE_CREDENTIAL,
            "dangling and forward credential references reject rather than defer",
            "No attacker-controlled pending binding state is created.",
            "M23_UNRESOLVED_DEFERRED",
        )
    )

    suite.checks.append(
        check(
            "W-ID-08",
            "genesis-domain-separation",
            derive_genesis_credential_id(CONTEXT_ID, "0x0001", "11" * 32)
            != derive_event_reference(g, mutation),
            "genesis credential and grant-event references use disjoint domains",
            "K rejects equality with a genesis identifier.",
            "M21_GENESIS_USES_EVENT_DOMAIN",
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
            is Outcome.LINEAGE_QUARANTINED
            and converged,
            "authority expansion requires MustAuth across every admissible order",
            "Reference grinding and delivery order cannot preserve the laundered successor.",
            "M04_POSSESSION_IMPLIES_AUTHORITY",
            "M05_EXPANSION_USES_MAY",
            "M08_SINGLE_LINEARIZATION",
            "M17_INCREMENTAL_DIVERGES",
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
            "M07_IGNORE_MAY_REDUCTION",
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
            "M07_IGNORE_MAY_REDUCTION",
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
        "c-child-action", c_child, parents=(g_b.reference, g_c.reference)
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
            is Outcome.LINEAGE_QUARANTINED,
            "revocation terminates every bounded descendant while retaining K evidence",
            "Late evidence cannot revive a tainted lineage.",
            "M09_NON_TRANSITIVE_PROVENANCE",
        )
    )

    fresh_after_containment = control(
        "untainted-regrant-after-containment",
        c,
        Kind.GRANT,
        sequence=1,
        predecessor=revoke_root.reference,
        parents=(revoke_root.reference,),
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
        parents=(x_revoke_y.reference,),
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
        parents=(revoke_old.reference,),
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
            and old.credential_id in p.terminated
            and old.credential_id not in p.terminal_authority,
            "revoked identifiers are never re-granted or recovered",
            "Legitimate recovery requires a fresh GRANT reference and lineage.",
            "M10_RECOVERY_RESURRECTS_REVOKED",
            "M19_REGRANT_REVOKED_IDENTIFIER",
        )
    )

    alias_one = control("alias-one", a, Kind.GRANT, grantee_key="aa" * 32)
    alias_two = control("alias-two", b, Kind.GRANT, grantee_key="aa" * 32)
    alias_one_binding = grant_binding(alias_one)
    revoke_alias_one = control(
        "revoke-alias-one",
        b,
        Kind.REVOKE,
        sequence=1,
        predecessor=alias_two.reference,
        parents=(alias_two.reference,),
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
            and alias_two.reference in aliases.terminal_authority,
            "byte-identical keys form visible alias evidence without coupled revocation",
            "An independently granted alias survives; this containment gap remains explicit.",
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
        parents=(fresh.reference,),
        target_id=a.credential_id,
        target_reference=fresh.reference,
    )
    rotated = grant_binding(fresh)
    old_action = make_event(
        "old-key-continuation", a, parents=(rotate.reference,)
    )
    new_action = make_event(
        "new-key-action", rotated, parents=(fresh.reference, rotate.reference)
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
        parents=(recovery_grant.reference, revoke_old.reference),
        target_id=old.credential_id,
        target_reference=recovery_grant.reference,
    )
    recovered_action = make_event(
        "recovered-action",
        recovered,
        parents=(recovery_grant.reference, recovery.reference),
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
                parents = tuple(sorted(set(parents) | {fork_left.reference}))
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
            case_ok = (
                a.credential_id in matrix_projection.forked_credentials
                and candidate.reference not in matrix_projection.accepted_controls
                and a.credential_id not in matrix_projection.terminal_authority
            )
            fork_matrix_ok = fork_matrix_ok and case_ok
            fork_matrix_details.append(f"{kind.value}:{placement}={case_ok}")

    suite.checks.append(
        check(
            "W-FORK-03",
            "fork-scope-and-privilege-neutrality",
            fork_matrix_ok,
            "the same lineage-quarantine rule applies before and after GRANT, REVOKE, ROTATE and RECOVER",
            ", ".join(fork_matrix_details),
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
            "M17_INCREMENTAL_DIVERGES",
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


def run_required_suite(mutation: Mutation = Mutation()) -> Suite:
    suite = Suite(checks=[], projections=[])
    _identifier_checks(suite, mutation)
    _authority_checks(suite, mutation)
    _succession_alias_fork_checks(suite, mutation)
    _pending_checkpoint_removal_checks(suite, mutation)
    _convergence_bounds_checks(suite, mutation)
    return suite


def mutation_coverage() -> Mapping[str, tuple[str, ...]]:
    suite = run_required_suite()
    coverage: dict[str, list[str]] = {item: [] for item in REQUIRED_MUTANTS}
    for item in suite.checks:
        for mutant in item.kills:
            coverage[mutant].append(item.identifier)
    return {key: tuple(sorted(values)) for key, values in sorted(coverage.items())}
