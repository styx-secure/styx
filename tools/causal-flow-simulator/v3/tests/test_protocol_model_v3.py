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
