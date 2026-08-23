"""RED witnesses for the amended C0.2j remediation contract.

These tests deliberately describe the required post-remediation behavior.  They
must fail against candidate ff470f8 before the authority fold is changed.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


V3_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V3_ROOT))

from protocol_model_v3 import Kind, Outcome, Scenario, grant_binding, make_event, project  # noqa: E402
from scenarios_v3 import control, genesis  # noqa: E402


class C02jRemediationRedTests(unittest.TestCase):
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
            "revoke-old", revoker, Kind.REVOKE, target_id=old.credential_id
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
