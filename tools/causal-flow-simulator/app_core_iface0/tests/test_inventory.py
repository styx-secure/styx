from __future__ import annotations

import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inventory import (
    InventoryError,
    SEMANTIC_COUNT,
    STRUCTURAL_COUNT,
    TOTAL_COUNT,
    _semantic_axis_members,
    derive_semantic_execution_relation,
    expand_semantic_instances,
    expand_structural_instances,
    _load_json,
)
from validate_inventory import (  # noqa: E402
    PhaseAValidationError,
    _validate_positive_coverage_union,
)


class InventoryTests(unittest.TestCase):
    @staticmethod
    def _synthetic_seed_registry() -> dict[str, object]:
        reachability = _load_json(
            ROOT / "contract/APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"
        )
        pointers = sorted(
            row["objectSchemaPointer"] for row in reachability["objectCoverage"]
        )
        return {
            "rows": [
                {
                    "objectSchemaPointer": pointer,
                    "carrierDirection": (
                        "REQUEST" if index % 2 == 0 else "RESPONSE"
                    ),
                }
                for index, pointer in enumerate(pointers)
            ]
        }

    def test_semantic_execution_relation_closes_all_5149_instances(self) -> None:
        seeds = self._synthetic_seed_registry()
        rows = derive_semantic_execution_relation(ROOT / "contract", seeds)
        self.assertEqual(len(rows), SEMANTIC_COUNT)
        self.assertEqual(len({row["instanceId"] for row in rows}), SEMANTIC_COUNT)
        self.assertEqual(
            Counter(row["executionPhase"] for row in rows),
            Counter(
                {
                    "BLIND_INPUT_EXECUTION": 910,
                    "POST_OUTPUT_MUTATION": 4212,
                    "VALIDATOR_SELF_TEST": 27,
                }
            ),
        )
        acv048 = [row for row in rows if row["semanticRuleId"] == "ACV-048"]
        self.assertEqual(len(acv048), 702)
        self.assertEqual(
            Counter(row["executionPhase"] for row in acv048),
            Counter(
                {
                    "BLIND_INPUT_EXECUTION": 351,
                    "POST_OUTPUT_MUTATION": 351,
                }
            ),
        )

    def test_semantic_execution_relation_rejects_seed_partition_drift(self) -> None:
        for mutation, message in (
            (lambda rows: rows.pop(), "requires 78 seed rows"),
            (
                lambda rows: rows[1].__setitem__(
                    "objectSchemaPointer", rows[0]["objectSchemaPointer"]
                ),
                "seed partition drift",
            ),
            (
                lambda rows: rows[0].__setitem__("carrierDirection", "UNKNOWN"),
                "seed partition drift",
            ),
        ):
            seeds = self._synthetic_seed_registry()
            mutation(seeds["rows"])
            with self.assertRaisesRegex(InventoryError, message):
                derive_semantic_execution_relation(ROOT / "contract", seeds)

    def test_positive_coverage_union_rejects_exact_object_or_arm_omission(self) -> None:
        reachability = _load_json(
            ROOT / "contract/APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"
        )
        objects = sorted(
            row["objectSchemaPointer"] for row in reachability["objectCoverage"]
        )
        arms = sorted(
            (row["oneOfPointer"], row["armIndex"])
            for row in reachability["oneOfArmCoverage"]
        )
        _validate_positive_coverage_union(objects, arms, reachability)
        with self.assertRaisesRegex(
            PhaseAValidationError, "POSITIVE_COVERAGE_UNION_DRIFT"
        ):
            _validate_positive_coverage_union(objects[1:], arms, reachability)
        with self.assertRaisesRegex(
            PhaseAValidationError, "POSITIVE_COVERAGE_UNION_DRIFT"
        ):
            _validate_positive_coverage_union(objects, arms[1:], reachability)

    def test_structural_relation_is_exact_and_unique(self) -> None:
        rows = expand_structural_instances(ROOT / "contract")
        self.assertEqual(len(rows), STRUCTURAL_COUNT)
        self.assertEqual(len({row.instance_id for row in rows}), STRUCTURAL_COUNT)
        self.assertEqual(rows[0].instance_id, "STR-REQUIRED-PROPERTY-OMISSION--0001")

    def test_semantic_relation_is_exact_and_unique(self) -> None:
        rows = expand_semantic_instances(ROOT / "contract")
        self.assertEqual(len(rows), SEMANTIC_COUNT)
        self.assertEqual(len({row.instance_id for row in rows}), SEMANTIC_COUNT)
        self.assertEqual(len(rows) + STRUCTURAL_COUNT, TOTAL_COUNT)

    def test_per_target_drift_has_only_the_ratified_acv020_derivation(self) -> None:
        with self.assertRaisesRegex(InventoryError, "PER_TARGET relation drift"):
            _semantic_axis_members(
                {"id": "ACV-999", "mode": "PER_TARGET", "expectedCount": 2},
                {"targets": ["one"], "customKeywordCoverage": {}},
                ROOT / "contract",
            )


if __name__ == "__main__":
    unittest.main()
