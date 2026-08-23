from __future__ import annotations

from dataclasses import replace
from itertools import permutations
from pathlib import Path
import sys
import unittest


V3_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V3_ROOT))

from protocol_model_v3 import (  # noqa: E402
    ContentClass,
    Kind,
    ModelInputError,
    Outcome,
    Role,
    Scenario,
    delivery_views,
    grant_binding,
    make_event,
    project,
)
from scenarios_v3 import genesis, control  # noqa: E402


class CredentialBindingTests(unittest.TestCase):
    def test_grant_reference_is_credential_identifier(self) -> None:
        issuer = genesis("issuer", "11")
        grant = control("grant", issuer, Kind.GRANT, grantee_key="22" * 32)
        binding = grant_binding(grant)
        self.assertEqual(binding.credential_id, grant.reference)
        self.assertEqual(binding.issuer_id, issuer.credential_id)

    def test_non_grant_does_not_create_binding(self) -> None:
        issuer = genesis("issuer", "11")
        event = make_event("ordinary", issuer, target_id="aa" * 32)
        value = project(Scenario((event,), (issuer,)))
        self.assertNotIn("aa" * 32, value.bindings)

    def test_control_requires_none_content(self) -> None:
        issuer = genesis("issuer", "11")
        event = control(
            "bad", issuer, Kind.GRANT, grantee_key="22" * 32,
            content_class=ContentClass.REQUIRED,
        )
        value = project(Scenario((event,), (issuer,)))
        self.assertIs(value.rejected[event.reference], Outcome.STRUCTURAL_REJECTION)

    def test_noncausal_successor_use_rejects_for_every_delivery_order(self) -> None:
        issuer = genesis("issuer", "11")
        grant = control("grant", issuer, Kind.GRANT, grantee_key="22" * 32)
        use = make_event("noncausal-use", grant_binding(grant))
        for delivery in permutations((grant, use)):
            with self.subTest(delivery=tuple(event.reference for event in delivery)):
                value = project(Scenario(delivery, (issuer,)))
                self.assertIs(
                    value.rejected[use.reference],
                    Outcome.STRUCTURAL_REJECTION,
                )


class AuthorityTests(unittest.TestCase):
    def test_mutual_revocation_has_no_winner(self) -> None:
        a = genesis("a", "11")
        b = genesis("b", "22")
        ar = control("a-r-b", a, Kind.REVOKE, target_id=b.credential_id)
        br = control("b-r-a", b, Kind.REVOKE, target_id=a.credential_id)
        value = project(Scenario((ar, br), (a, b)))
        self.assertFalse(value.terminal_authority)

    def test_independent_authority_survives_fork(self) -> None:
        a = genesis("a", "11")
        b = genesis("b", "22")
        left = make_event("left", a)
        right = make_event("right", a)
        grant = control("b-grants", b, Kind.GRANT, grantee_key="33" * 32)
        value = project(Scenario((left, right, grant), (a, b)))
        self.assertNotIn(a.credential_id, value.terminal_authority)
        self.assertIn(grant.reference, value.terminal_authority)

    def test_delivery_order_is_semantically_irrelevant(self) -> None:
        a = genesis("a", "11")
        b = genesis("b", "22")
        ar = control("a-r-b", a, Kind.REVOKE, target_id=b.credential_id)
        br = control("b-r-a", b, Kind.REVOKE, target_id=a.credential_id)
        views = delivery_views(Scenario((ar, br), (a, b)))
        self.assertEqual(len(views), 2)
        self.assertEqual(len(set(views)), 1)

    def test_required_pending_does_not_filter_k_control(self) -> None:
        a = genesis("a", "11")
        b = genesis("b", "22")
        pending = make_event(
            "pending", a, content_class=ContentClass.REQUIRED,
            opening_verified=False,
        )
        revoke = control(
            "revoke", b, Kind.REVOKE, parents=(pending.reference,),
            target_id=a.credential_id, ap_applicable=False,
        )
        value = project(Scenario((pending, revoke), (a, b)))
        self.assertIn(revoke.reference, value.pending)
        self.assertNotIn(a.credential_id, value.terminal_authority)

    def test_noncontrol_causal_hop_orders_authority_controls(self) -> None:
        a = genesis("a", "11")
        y = genesis("y", "22")
        z = genesis("z", "33")
        revoke_y = control("a-revokes-y", a, Kind.REVOKE, target_id=y.credential_id)
        ordinary = make_event("y-ordinary", y, parents=(revoke_y.reference,))
        revoke_z = control(
            "y-revokes-z",
            y,
            Kind.REVOKE,
            sequence=1,
            predecessor=ordinary.reference,
            target_id=z.credential_id,
        )
        value = project(Scenario((revoke_y, ordinary, revoke_z), (a, y, z)))
        self.assertNotIn(revoke_z.reference, value.accepted_controls)
        self.assertIn(z.credential_id, value.terminal_authority)

    def test_stale_history_exposes_no_authority_result(self) -> None:
        a = genesis("a", "11")
        event = make_event("stale", a)
        value = project(
            Scenario(
                (event,),
                (a,),
                checkpoint_references=("missing-history",),
                replay_dependencies=("missing-history",),
            )
        )
        self.assertTrue(value.stale_evidence)
        self.assertFalse(value.authority_available)
        self.assertFalse(value.terminal_authority)
        self.assertFalse(value.accepted_controls)

    def test_same_key_aliases_do_not_share_a_fork_namespace(self) -> None:
        issuer = genesis("issuer", "11")
        first = control("first-alias", issuer, Kind.GRANT, grantee_key="22" * 32)
        second = control(
            "second-alias",
            issuer,
            Kind.GRANT,
            sequence=1,
            predecessor=first.reference,
            grantee_key="22" * 32,
        )
        first_binding = grant_binding(first)
        second_binding = grant_binding(second)
        first_action = make_event(
            "first-action", first_binding, parents=(first.reference,)
        )
        second_action = make_event(
            "second-action", second_binding, parents=(second.reference,)
        )
        value = project(
            Scenario((first, second, first_action, second_action), (issuer,))
        )
        self.assertEqual(len(value.alias_groups), 1)
        self.assertNotIn(first_binding.credential_id, value.forked_credentials)
        self.assertNotIn(second_binding.credential_id, value.forked_credentials)

    def test_many_siblings_use_one_bounded_fork_join(self) -> None:
        a = genesis("a", "11")
        siblings = tuple(make_event(f"sibling-{index}", a) for index in range(5))
        value = project(Scenario(siblings, (a,)))
        self.assertEqual(value.forked_credentials, {a.credential_id})
        self.assertEqual(len(value.fork_joins), 1)
        self.assertNotIn(a.credential_id, value.terminal_authority)

    def test_author_sequence_requires_exact_same_author_predecessor(self) -> None:
        a = genesis("a", "11")
        y = genesis("y", "22")
        z = genesis("z", "33")
        y_root = make_event("y-root", y)
        a_root = make_event("a-root", a)
        gap = control(
            "gap",
            y,
            Kind.REVOKE,
            sequence=2,
            predecessor=y_root.reference,
            target_id=z.credential_id,
        )
        cross_author = control(
            "cross-author",
            y,
            Kind.REVOKE,
            sequence=1,
            predecessor=a_root.reference,
            target_id=z.credential_id,
        )
        zero_with_predecessor = control(
            "zero-with-predecessor",
            y,
            Kind.REVOKE,
            predecessor=y_root.reference,
            target_id=z.credential_id,
        )
        value = project(
            Scenario(
                (y_root, a_root, gap, cross_author, zero_with_predecessor),
                (a, y, z),
            )
        )
        for event in (gap, cross_author, zero_with_predecessor):
            with self.subTest(event=event.reference):
                self.assertIs(
                    value.rejected[event.reference],
                    Outcome.STRUCTURAL_REJECTION,
                )


class BoundsTests(unittest.TestCase):
    def test_control_flood_fails_closed(self) -> None:
        a = genesis("a", "11")
        events = tuple(
            control(f"g-{index}", a, Kind.GRANT, grantee_key=f"{index + 32:02x}" * 32)
            for index in range(7)
        )
        with self.assertRaisesRegex(ModelInputError, "AUTHORITY_BOUND_EXCEEDED"):
            project(Scenario(events, (a,)))


if __name__ == "__main__":
    unittest.main()
