from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generate_structural_witnesses import (
    ISOLATION_RELATION_FILENAME,
    WitnessGenerationError,
    load_structural_isolation_relation,
)
from inventory import expand_structural_instances


class StructuralIsolationRelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = ROOT / "contract"
        cls.instance_ids = {
            row.instance_id for row in expand_structural_instances(cls.contract)
        }
        cls.relation = json.loads(
            (cls.contract / ISOLATION_RELATION_FILENAME).read_text(encoding="utf-8")
        )

    def test_exact_v24_relation_passes(self) -> None:
        relation = load_structural_isolation_relation(
            self.contract, self.instance_ids
        )
        self.assertEqual(len(relation["carrierReselections"]), 29)
        self.assertEqual(len(relation["boundedRecipeRows"]), 20)
        self.assertEqual(
            sum(len(row["instanceIds"]) for row in relation["coConstrainedClasses"]),
            82,
        )

    def _assert_mutation_fails(self, mutation) -> None:
        value = copy.deepcopy(self.relation)
        mutation(value)
        with tempfile.TemporaryDirectory() as raw:
            contract = Path(raw)
            (contract / ISOLATION_RELATION_FILENAME).write_text(
                json.dumps(value), encoding="utf-8"
            )
            with self.assertRaises(WitnessGenerationError):
                load_structural_isolation_relation(contract, self.instance_ids)

    def test_authority_count_partition_and_recipe_drift_fail_closed(self) -> None:
        mutations = (
            lambda value: value["authority"].update(providerCommentId="0"),
            lambda value: value["classificationCounts"].update(
                TARGET_ONLY_COUNTERFACTUAL=1470
            ),
            lambda value: value["carrierReselections"].pop(),
            lambda value: value["completeSchemaLiveInstanceIds"].append(
                value["boundedRecipeRows"][0]["instanceId"]
            ),
            lambda value: value["boundedRecipeRows"][0].update(
                recipeId="UNLISTED_RECIPE"
            ),
            lambda value: value["coConstrainedClasses"][0]["instanceIds"].append(
                value["coConstrainedClasses"][1]["instanceIds"][0]
            ),
            lambda value: value["antiDowngrade"].update(
                reducedCarrierAcceptedNestedInputArmIndex=2
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self._assert_mutation_fails(mutation)


if __name__ == "__main__":
    unittest.main()
