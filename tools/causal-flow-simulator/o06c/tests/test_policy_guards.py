from __future__ import annotations

from pathlib import Path
import sys
import unittest


O06C_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(O06C_ROOT))

from policy_guards import (  # noqa: E402
    RemovalTarget,
    detects_collapsed_removal_identity,
    project_removal_directive,
)


class RemovalProjectionTests(unittest.TestCase):
    def test_vacuous_target_classes_have_exact_typed_statuses(self) -> None:
        none_reference = bytes.fromhex("01" * 32)
        required_reference = bytes.fromhex("02" * 32)
        unretained_reference = bytes.fromhex("03" * 32)
        commitment = bytes.fromhex("22" * 32)
        ambient = (
            RemovalTarget(
                none_reference,
                "NONE",
                ("NONE", 0),
                None,
                True,
                True,
                "BOUND",
                "VISIBLE",
            ),
            RemovalTarget(
                required_reference,
                "REQUIRED",
                ("REQUIRED", 3, 1, 0, commitment),
                commitment,
                True,
                True,
                "BOUND",
                "VISIBLE",
            ),
            RemovalTarget(
                unretained_reference,
                "DETACHABLE",
                ("DETACHABLE", 3, 1, 0, commitment),
                commitment,
                False,
                False,
                "BOUND",
                "WITHHELD",
            ),
        )
        cases = (
            (
                none_reference,
                ("REMOVAL_INAPPLICABLE", "VALIDATED", "RETAINED", "VISIBLE"),
            ),
            (
                required_reference,
                ("REMOVAL_INAPPLICABLE", "VALIDATED", "RETAINED", "VISIBLE"),
            ),
            (
                bytes.fromhex("04" * 32),
                ("REMOVAL_INAPPLICABLE", "ABSENT", "NOT_RETAINED", "ABSENT"),
            ),
            (
                unretained_reference,
                ("REMOVAL_DEFERRED", "VALIDATED", "NOT_RETAINED", "WITHHELD"),
            ),
        )

        for reference, expected_status in cases:
            with self.subTest(reference=reference.hex()):
                projection = project_removal_directive(
                    ambient,
                    target_reference=reference,
                    target_commitment=bytes.fromhex("23" * 32),
                )
                self.assertEqual(projection.removal_effect, "NONE")
                self.assertEqual(
                    (
                        projection.classification,
                        projection.target_validity,
                        projection.target_retention,
                        projection.target_presentation,
                    ),
                    expected_status,
                )

    def test_retained_detachable_target_is_logically_removed(self) -> None:
        reference = bytes.fromhex("11" * 32)
        commitment = bytes.fromhex("22" * 32)
        target = RemovalTarget(
            reference,
            "DETACHABLE",
            ("DETACHABLE", 3, 1, 0, commitment),
            commitment,
            True,
            True,
            "BOUND",
            "VISIBLE",
        )

        projection = project_removal_directive(
            (target,),
            target_reference=reference,
            target_commitment=commitment,
        )

        self.assertEqual(projection.classification, "REMOVAL_APPLIED")
        self.assertEqual(projection.removal_effect, "LOGICAL_DETACH")
        self.assertEqual(projection.target_presentation, "REMOVED")
        self.assertEqual(projection.ambient_projection[0][6], "REMOVED")

    def test_retained_projection_has_a_vacuous_negative_control(self) -> None:
        reference = bytes.fromhex("11" * 32)
        commitment = bytes.fromhex("22" * 32)
        target = RemovalTarget(
            reference,
            "DETACHABLE",
            ("DETACHABLE", 3, 1, 0, commitment),
            commitment,
            True,
            True,
            "BOUND",
            "VISIBLE",
        )

        applied = project_removal_directive(
            (target,),
            target_reference=reference,
            target_commitment=commitment,
        )
        mismatched = project_removal_directive(
            (target,),
            target_reference=reference,
            target_commitment=bytes.fromhex("23" * 32),
        )

        self.assertNotEqual(applied, mismatched)
        self.assertEqual(mismatched.classification, "REMOVAL_INAPPLICABLE")
        self.assertEqual(mismatched.removal_effect, "NONE")
        self.assertEqual(mismatched.target_presentation, "VISIBLE")

    def test_collapsed_identity_detector_checks_both_polarities(self) -> None:
        first_reference = bytes.fromhex("31" * 32)
        second_reference = bytes.fromhex("32" * 32)
        first_key = ("credential", 4, bytes.fromhex("41" * 32))
        same_key = ("credential", 4, bytes.fromhex("41" * 32))
        different_key = ("credential", 4, bytes.fromhex("42" * 32))

        self.assertTrue(
            detects_collapsed_removal_identity(
                first_reference,
                second_reference,
                first_key,
                same_key,
            )
        )
        self.assertFalse(
            detects_collapsed_removal_identity(
                first_reference,
                first_reference,
                first_key,
                same_key,
            )
        )
        self.assertFalse(
            detects_collapsed_removal_identity(
                first_reference,
                second_reference,
                first_key,
                different_key,
            )
        )


if __name__ == "__main__":
    unittest.main()
