from __future__ import annotations

import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inventory import (
    ACV049_LITERAL_FAMILIES,
    ACV049_RELATION_COUNT,
    ACV049_RELATION_COUNTS,
    ACV049_REQUEST_CASE_IDS,
    InventoryError,
    SEMANTIC_COUNT,
    STRUCTURAL_COUNT,
    TOTAL_COUNT,
    _semantic_axis_members,
    derive_acv049_path_partition,
    derive_acv049_relation_members,
    derive_acv049_old_to_new_reconciliation,
    derive_semantic_execution_relation,
    digest_lines,
    expand_semantic_instances,
    expand_acv049_replacement_instances,
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

    def test_semantic_execution_relation_requires_exact_acv049_materialization(self) -> None:
        seeds = self._synthetic_seed_registry()
        with self.assertRaisesRegex(
            InventoryError, "ACV-049 materialized phase partition drift"
        ):
            derive_semantic_execution_relation(ROOT / "contract", seeds)

    def test_semantic_execution_relation_rejects_seed_partition_drift(self) -> None:
        for mutation, message in (
            (lambda rows: rows.pop(), "requires 87 seed rows"),
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

    def test_acv049_path_partition_is_exact_and_schema_derived(self) -> None:
        partition = derive_acv049_path_partition(ROOT / "contract")
        self.assertEqual(
            {name: len(rows) for name, rows in partition.items()},
            {
                "literal": 401,
                "logical": 406,
                "mutable": 300,
                "non_string": 5,
                "singleton": 101,
            },
        )
        self.assertEqual(
            {name: digest_lines(rows) for name, rows in partition.items()},
            {
                "literal": "253048d2193a1d37cd51d9505409b7b1ad943333ad0993cb22c09cc9e6986419",
                "logical": "cdd2f3f325800fffd08b23c08ab51d3b3ba6a3eb949af10ad488d72a854e5fe4",
                "mutable": "beee0c5b76943e52a0e55d7420f952b759e0732be06e4071c34d5d370d4a0c21",
                "non_string": "ff6a882b2805320261707316f8a3c354806b27fc042c5f64d6dafedb47e2d509",
                "singleton": "50c380ce5b29a7158774fd11daf93675428cc6c56c3b7832a23aa050063856fe",
            },
        )
        self.assertEqual(
            set(partition["mutable"]) | set(partition["singleton"]),
            set(partition["literal"]),
        )
        self.assertFalse(set(partition["mutable"]) & set(partition["singleton"]))

    def test_acv049_five_relation_replacement_is_exact(self) -> None:
        relations = derive_acv049_relation_members(ROOT / "contract")
        self.assertEqual(
            {name: len(rows) for name, rows in relations.items()},
            ACV049_RELATION_COUNTS,
        )
        self.assertEqual(sum(map(len, relations.values())), ACV049_RELATION_COUNT)
        self.assertEqual(relations["ACV-049-E"], list(ACV049_REQUEST_CASE_IDS))
        self.assertEqual(
            digest_lines(relations["ACV-049-E"]),
            "8233dd1a8172383e4679780474910b468139baeb4df028ecadc18f1fa83ecb8f",
        )
        instances = expand_acv049_replacement_instances(ROOT / "contract")
        self.assertEqual(len(instances), 884)
        self.assertEqual(len({row.instance_id for row in instances}), 884)
        self.assertEqual(
            Counter(row.family_id for row in instances),
            Counter(ACV049_RELATION_COUNTS),
        )

    def test_acv049_historical_ids_are_reconciled_without_silent_loss(self) -> None:
        rows = derive_acv049_old_to_new_reconciliation(ROOT / "contract")
        self.assertEqual(len(rows), 4060)
        self.assertEqual(len({row["historicalInstanceId"] for row in rows}), 4060)
        replacement_counts = Counter(row["replacementInstanceId"] for row in rows)
        self.assertEqual(len(replacement_counts), 406)
        self.assertEqual(set(replacement_counts.values()), {10})
        self.assertEqual(
            Counter(row["historicalLiteralFamily"] for row in rows),
            Counter({family: 406 for family in ACV049_LITERAL_FAMILIES}),
        )

    def test_acv049_relation_modes_bind_exact_derived_members(self) -> None:
        relations = derive_acv049_relation_members(ROOT / "contract")
        modes = {
            "ACV-049-L": "PER_RESPONSE_STRING_PATH_WITH_FAMILY_VECTOR",
            "ACV-049-P": "PER_MUTABLE_RESPONSE_STRING_PATH",
            "ACV-049-S": "PER_SINGLETON_RESPONSE_STRING_PATH",
            "ACV-049-N": "PER_NON_STRING_HISTORICAL_RESPONSE_PATH",
            "ACV-049-E": "PER_RATIFIED_REQUEST_CARRIER",
        }
        semantic = {"customKeywordCoverage": {}}
        for relation_id, mode in modes.items():
            with self.subTest(relation_id=relation_id):
                axis = {
                    "id": relation_id,
                    "semanticRuleId": "ACV-049",
                    "mode": mode,
                    "expectedCount": len(relations[relation_id]),
                    "memberSetSha256": digest_lines(relations[relation_id]),
                }
                if relation_id == "ACV-049-L":
                    axis["literalFamilyVector"] = list(ACV049_LITERAL_FAMILIES)
                self.assertEqual(
                    _semantic_axis_members(axis, semantic, ROOT / "contract"),
                    relations[relation_id],
                )
                axis["memberSetSha256"] = "0" * 64
                with self.assertRaisesRegex(InventoryError, "axis digest drift"):
                    _semantic_axis_members(axis, semantic, ROOT / "contract")

    def test_per_target_drift_has_only_the_ratified_acv020_derivation(self) -> None:
        with self.assertRaisesRegex(InventoryError, "PER_TARGET relation drift"):
            _semantic_axis_members(
                {"id": "ACV-999", "mode": "PER_TARGET", "expectedCount": 2},
                {"targets": ["one"], "customKeywordCoverage": {}},
                ROOT / "contract",
            )


if __name__ == "__main__":
    unittest.main()
