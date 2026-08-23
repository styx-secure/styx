"""RED witnesses for the amended C0.2j remediation contract.

These tests deliberately describe the required post-remediation behavior.  The
suite combines RED regressions with positive controls that prevent a candidate
repair from weakening an already-satisfied safety property.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


V3_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V3_ROOT))

from protocol_model_v3 import (  # noqa: E402
    AuthorityVerdict,
    AuthorityUnavailableReason,
    Kind,
    Outcome,
    Scenario,
    grant_binding,
    make_event,
    project,
)
from scenarios_v3 import control, genesis  # noqa: E402


class C02jRemediationRedTests(unittest.TestCase):
    def test_dp_state_overflow_is_typed_whole_projection_unavailable(self) -> None:
        authority = genesis("authority", "11")
        target = genesis("target", "22")
        revoke = control(
            "revoke", authority, Kind.REVOKE, target_id=target.credential_id
        )

        value = project(
            Scenario((revoke,), (authority, target)),
            authority_state_limit=1,
        )

        self.assertFalse(value.authority_available)
        self.assertIs(
            value.authority_unavailable_reason,
            AuthorityUnavailableReason.REACHABLE_STATE_LIMIT,
        )
        self.assertIs(
            value.outcomes[revoke.reference],
            Outcome.AUTHORITY_PROJECTION_UNAVAILABLE,
        )
        self.assertFalse(value.accepted_controls)
        self.assertFalse(value.terminal_authority)
        self.assertIsNone(value.operational_terminal_authority)

    def test_dp_transition_overflow_is_typed_whole_projection_unavailable(self) -> None:
        authority = genesis("authority", "11")
        grant = control("grant", authority, Kind.GRANT, grantee_key="22" * 32)

        value = project(
            Scenario((grant,), (authority,)),
            authority_transition_limit=0,
        )

        self.assertFalse(value.authority_available)
        self.assertIs(
            value.authority_unavailable_reason,
            AuthorityUnavailableReason.REACHABLE_TRANSITION_LIMIT,
        )
        self.assertIs(
            value.outcomes[grant.reference],
            Outcome.AUTHORITY_PROJECTION_UNAVAILABLE,
        )
        self.assertIsNone(value.operational_terminal_authority)

    def test_dp_matches_factorial_oracle_within_oracle_envelope(self) -> None:
        actor = genesis("actor", "11")
        revoker = genesis("revoker", "22")
        target = genesis("target", "33")
        revoke_actor = control(
            "revoke-actor", revoker, Kind.REVOKE, target_id=actor.credential_id
        )
        actor_reduces_target = control(
            "actor-reduces-target",
            actor,
            Kind.REVOKE,
            target_id=target.credential_id,
        )
        probe = make_event("target-probe", target)
        scenario = Scenario(
            (revoke_actor, actor_reduces_target, probe),
            (actor, revoker, target),
        )

        dp = project(scenario, authority_engine="dp")
        oracle = project(scenario, authority_engine="oracle")

        self.assertEqual(dp.semantic_view(), oracle.semantic_view())

    def test_five_sibling_contested_slot_is_executable_without_factorial_cap(
        self,
    ) -> None:
        actor = genesis("actor", "11")
        revoker = genesis("revoker", "22")
        targets = tuple(
            genesis(f"target-{index}", f"{0x30 + index:02x}")
            for index in range(5)
        )
        revoke_actor = control(
            "revoke-actor", revoker, Kind.REVOKE, target_id=actor.credential_id
        )
        siblings = tuple(
            control(
                f"actor-reduces-{index}",
                actor,
                Kind.REVOKE,
                target_id=target.credential_id,
            )
            for index, target in enumerate(targets)
        )

        value = project(
            Scenario((revoke_actor, *siblings), (actor, revoker, *targets))
        )

        self.assertEqual(
            {event.reference for event in siblings} & value.accepted_controls,
            {event.reference for event in siblings},
        )
        self.assertTrue(
            all(
                value.event_authority[event.reference]
                is AuthorityVerdict.MAY_AUTH
                for event in siblings
            )
        )
        self.assertTrue(
            all(
                target.credential_id not in value.terminal_authority
                for target in targets
            )
        )
        self.assertGreater(value.explored_orders, 720)

    def test_self_lineage_must_reduction_cannot_launder_successor(self) -> None:
        root = genesis("root", "11")
        grant = control("root-grants-child", root, Kind.GRANT, grantee_key="22" * 32)
        child = grant_binding(grant)
        child_reduces_root = control(
            "child-reduces-root",
            child,
            Kind.REVOKE,
            parents=(grant.reference,),
            target_id=root.credential_id,
        )

        value = project(Scenario((grant, child_reduces_root), (root,)))

        self.assertIs(
            value.event_authority[child_reduces_root.reference],
            AuthorityVerdict.MUST_AUTH,
        )
        self.assertIn(child_reduces_root.reference, value.accepted_controls)
        self.assertNotIn(root.credential_id, value.terminal_authority)
        self.assertNotIn(child.credential_id, value.terminal_authority)

    def test_bounded_standing_does_not_operationalize_rejected_target_successor(
        self,
    ) -> None:
        actor = genesis("actor", "11")
        revoker = genesis("revoker", "22")
        first_target = genesis("first-target", "33")
        second_target = genesis("second-target", "44")

        revoke_actor = control(
            "revoke-actor", revoker, Kind.REVOKE, target_id=actor.credential_id
        )
        first_reduction = control(
            "actor-reduces-first",
            actor,
            Kind.REVOKE,
            target_id=first_target.credential_id,
        )
        second_reduction = control(
            "actor-reduces-second",
            actor,
            Kind.REVOKE,
            sequence=1,
            predecessor=first_reduction.reference,
            target_id=second_target.credential_id,
        )
        first_successor_grant = control(
            "first-target-grants-successor",
            first_target,
            Kind.GRANT,
            grantee_key="55" * 32,
        )
        second_successor_grant = control(
            "second-target-grants-successor",
            second_target,
            Kind.GRANT,
            grantee_key="66" * 32,
        )
        first_successor = grant_binding(first_successor_grant)
        second_successor = grant_binding(second_successor_grant)

        value = project(
            Scenario(
                (
                    revoke_actor,
                    first_reduction,
                    second_reduction,
                    first_successor_grant,
                    second_successor_grant,
                ),
                (actor, revoker, first_target, second_target),
            )
        )

        self.assertNotIn(first_successor.credential_id, value.terminal_authority)
        self.assertNotIn(second_successor.credential_id, value.terminal_authority)

    def test_revoked_actor_has_at_most_one_contested_reduction(self) -> None:
        actor = genesis("actor", "11")
        revoker = genesis("revoker", "22")
        first_target = genesis("first-target", "33")
        second_target = genesis("second-target", "44")

        revoke_actor = control(
            "revoke-actor", revoker, Kind.REVOKE, target_id=actor.credential_id
        )
        first = control(
            "actor-reduces-first",
            actor,
            Kind.REVOKE,
            target_id=first_target.credential_id,
        )
        second = control(
            "actor-reduces-second",
            actor,
            Kind.REVOKE,
            sequence=1,
            predecessor=first.reference,
            target_id=second_target.credential_id,
        )

        value = project(
            Scenario(
                (revoke_actor, first, second),
                (actor, revoker, first_target, second_target),
            )
        )
        accepted = {first.reference, second.reference} & value.accepted_controls

        self.assertEqual(len(accepted), 1)
        self.assertEqual(
            sum(
                credential.credential_id in value.terminal_authority
                for credential in (first_target, second_target)
            ),
            1,
        )

    def test_noncausal_reduction_cannot_veto_fresh_independent_grant(self) -> None:
        actor = genesis("actor", "11")
        honest = genesis("honest", "22")
        revoke_actor = control(
            "honest-revokes-actor",
            honest,
            Kind.REVOKE,
            target_id=actor.credential_id,
        )
        fresh_grant = control(
            "honest-grants-fresh",
            honest,
            Kind.GRANT,
            sequence=1,
            predecessor=revoke_actor.reference,
            grantee_key="33" * 32,
        )
        fresh = grant_binding(fresh_grant)
        noncausal_reduction = control(
            "actor-reduces-unseen-fresh-grant",
            actor,
            Kind.REVOKE,
            target_id=fresh.credential_id,
        )

        value = project(
            Scenario((revoke_actor, fresh_grant, noncausal_reduction), (actor, honest))
        )

        self.assertIs(
            value.rejected.get(noncausal_reduction.reference),
            Outcome.STRUCTURAL_REJECTION,
        )
        self.assertIn(fresh.credential_id, value.terminal_authority)

    def test_independent_recovery_does_not_require_retired_grant_ancestry(self) -> None:
        issuer = genesis("issuer", "11")
        revoker = genesis("revoker", "22")
        recovery_authority = genesis("recovery-authority", "33")
        old_grant = control(
            "old-grant", issuer, Kind.GRANT, grantee_key="44" * 32
        )
        old = grant_binding(old_grant)
        revoke_old = control(
            "revoke-old",
            revoker,
            Kind.REVOKE,
            parents=(old_grant.reference,),
            target_id=old.credential_id,
        )
        recovery_grant = control(
            "recovery-grant",
            recovery_authority,
            Kind.GRANT,
            grantee_key="55" * 32,
        )
        recovered = grant_binding(recovery_grant)
        recovery = control(
            "recover-old",
            recovery_authority,
            Kind.RECOVER,
            sequence=1,
            predecessor=recovery_grant.reference,
            parents=(revoke_old.reference,),
            target_id=old.credential_id,
            target_reference=recovery_grant.reference,
        )

        value = project(
            Scenario(
                (old_grant, revoke_old, recovery_grant, recovery),
                (issuer, revoker, recovery_authority),
            )
        )

        self.assertIn(recovery.reference, value.accepted_controls)
        self.assertIn(recovered.credential_id, value.terminal_authority)
        self.assertNotIn(old.credential_id, value.terminal_authority)

    def test_post_admission_rejection_propagates_to_dependants(self) -> None:
        issuer = genesis("issuer", "11")
        attacker = genesis("attacker", "22")
        observer = genesis("observer", "33")
        fresh_grant = control(
            "fresh-grant", issuer, Kind.GRANT, grantee_key="44" * 32
        )
        fresh = grant_binding(fresh_grant)
        noncausal_reduction = control(
            "noncausal-reduction",
            attacker,
            Kind.REVOKE,
            target_id=fresh.credential_id,
        )
        dependant = make_event(
            "dependant-on-rejected-reduction",
            observer,
            parents=(noncausal_reduction.reference,),
        )

        value = project(
            Scenario(
                (fresh_grant, noncausal_reduction, dependant),
                (issuer, attacker, observer),
            )
        )

        self.assertIs(
            value.rejected.get(noncausal_reduction.reference),
            Outcome.STRUCTURAL_REJECTION,
        )
        self.assertIs(
            value.rejected.get(dependant.reference), Outcome.STRUCTURAL_REJECTION
        )
        self.assertNotIn(dependant.reference, value.admitted)

    def test_accepted_terminal_accounting_is_not_operational_authority(self) -> None:
        actor = genesis("accounting-actor", "11")
        revoker = genesis("accounting-revoker", "22")
        child_grant = control(
            "accounting-child-grant", actor, Kind.GRANT, grantee_key="33" * 32
        )
        child = grant_binding(child_grant)
        contest = control(
            "accounting-contest",
            revoker,
            Kind.REVOKE,
            parents=(child_grant.reference,),
            target_id=child.credential_id,
        )
        rejected_self_reduction = control(
            "accounting-self-reduction",
            child,
            Kind.REVOKE,
            parents=(child_grant.reference,),
            target_id=actor.credential_id,
        )
        probe = make_event(
            "accounting-probe",
            actor,
            sequence=1,
            predecessor=child_grant.reference,
            parents=(contest.reference, rejected_self_reduction.reference),
        )

        value = project(
            Scenario(
                (child_grant, contest, rejected_self_reduction, probe),
                (actor, revoker),
            )
        )

        self.assertIn(actor.credential_id, value.accepted_terminal_authority)
        self.assertNotIn(actor.credential_id, value.operational_terminal_authority)
        self.assertIs(value.event_authority[probe.reference], AuthorityVerdict.MAY_AUTH)
        self.assertIs(value.outcomes[probe.reference], Outcome.AUTHENTIC_BUT_UNAUTHORIZED)

    def test_ordinary_probe_does_not_consume_control_budget(self) -> None:
        authority = genesis("authority", "11")
        controls = tuple(
            control(
                f"grant-{index}",
                authority,
                Kind.GRANT,
                grantee_key=f"{index + 32:02x}" * 32,
            )
            for index in range(6)
        )
        probe = make_event("ordinary-probe", authority)

        value = project(Scenario((*controls, probe), (authority,)))

        self.assertTrue(value.authority_available)

    def test_self_rotation_is_rejected_without_destroying_replacement(self) -> None:
        authority = genesis("authority", "11")
        replacement_grant = control(
            "self-replacement-grant",
            authority,
            Kind.GRANT,
            grantee_key="22" * 32,
        )
        replacement = grant_binding(replacement_grant)
        rotation = control(
            "self-rotation",
            authority,
            Kind.ROTATE,
            sequence=1,
            predecessor=replacement_grant.reference,
            target_id=authority.credential_id,
            target_reference=replacement_grant.reference,
        )

        value = project(Scenario((replacement_grant, rotation), (authority,)))

        self.assertIs(
            value.rejected.get(rotation.reference),
            Outcome.STRUCTURAL_REJECTION,
        )
        self.assertIn(replacement.credential_id, value.terminal_authority)


if __name__ == "__main__":
    unittest.main()
