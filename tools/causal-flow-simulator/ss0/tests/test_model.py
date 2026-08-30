from __future__ import annotations

import sys
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))

from model import PROFILE, evaluate  # noqa: E402


class ModelTests(unittest.TestCase):
    def test_retention_boundaries_are_independent(self) -> None:
        for distance, expected in ((0, "ACCEPTED_EVIDENCE"), (1, "ACCEPTED_EVIDENCE"), (5, "ACCEPTED_EVIDENCE"), (6, "EPOCH_OUT_OF_RANGE")):
            observed = evaluate(
                {
                    "operation": "retention",
                    "profile": PROFILE,
                    "current_epoch": "10",
                    "message_epoch": str(10 - distance),
                }
            )
            self.assertEqual(expected, observed["disposition"])

    def test_session_success_never_grants_application_authority(self) -> None:
        observed = evaluate(
            {
                "operation": "receive",
                "profile": PROFILE,
                "member_count": 2,
                "authenticated": True,
                "opaque_application_bytes": True,
            }
        )
        self.assertEqual("AP_AUTHORITY_REQUIRED", observed["disposition"])
        self.assertTrue(observed["emitted_plaintext"])
        self.assertFalse(observed["applied"])

    def test_profile_member_order_is_semantic_but_object_order_is_not(self) -> None:
        reordered = {key: PROFILE[key] for key in reversed(PROFILE)}
        self.assertEqual(
            "ACCEPTED_EVIDENCE",
            evaluate({"operation": "profile", "profile": reordered})["disposition"],
        )
        reordered["members"] = list(reversed(reordered["members"]))
        self.assertEqual(
            "DRIFT_INVALIDATED",
            evaluate({"operation": "profile", "profile": reordered})["disposition"],
        )

    def test_unknown_candidate_fields_fail_closed(self) -> None:
        observed = evaluate(
            {"operation": "profile", "profile": PROFILE, "scenario_variant": "inert"}
        )
        self.assertEqual("INVALID_SESSION_INPUT", observed["disposition"])

    def test_epoch_input_is_canonical_complete_u64(self) -> None:
        accepted = ("0", "1", str(2**53 - 1), str(2**53), str(2**64 - 1))
        for value in accepted:
            with self.subTest(value=value):
                observed = evaluate(
                    {
                        "operation": "retention",
                        "profile": PROFILE,
                        "current_epoch": value,
                        "message_epoch": value,
                    }
                )
                self.assertEqual("ACCEPTED_EVIDENCE", observed["disposition"])
        for value in (0, "00", "+1", "-1", "1e3", " 1", str(2**64), "9" * 21):
            with self.subTest(value=value):
                observed = evaluate(
                    {
                        "operation": "retention",
                        "profile": PROFILE,
                        "current_epoch": value,
                        "message_epoch": "0",
                    }
                )
                self.assertEqual("EPOCH_OUT_OF_RANGE", observed["disposition"])

    def test_only_committed_staged_mutation_applies(self) -> None:
        common = {"operation": "mutation", "profile": PROFILE, "authoritative": True, "staged": True}
        self.assertTrue(evaluate({**common, "rs_result": "COMMITTED"})["applied"])
        self.assertFalse(evaluate({**common, "rs_result": "NOT_COMMITTED"})["applied"])
        self.assertFalse(evaluate({**common, "rs_result": "INDETERMINATE"})["applied"])

    def test_replay_is_idempotent(self) -> None:
        observed = evaluate(
            {
                "operation": "replay",
                "profile": PROFILE,
                "message_identity": "message-a",
                "already_emitted": True,
            }
        )
        self.assertEqual("DUPLICATE_SUPPRESSED", observed["disposition"])
        self.assertFalse(observed["emitted_plaintext"])


if __name__ == "__main__":
    unittest.main()
