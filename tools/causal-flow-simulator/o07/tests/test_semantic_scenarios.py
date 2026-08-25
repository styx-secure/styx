from __future__ import annotations

from pathlib import Path
import sys
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from inventory import validate_inventory  # noqa: E402
from test_helpers.scenario_engine import evaluate_semantic_scenario  # noqa: E402


class SemanticScenarioTest(unittest.TestCase):
    def test_every_semantic_atom_executes_without_skip_or_alias(self) -> None:
        inventory = validate_inventory()
        outputs = []
        for entry in inventory.semantic_entries:
            result = evaluate_semantic_scenario(entry["atom_instance_id"])
            self.assertEqual(
                result["disposition"],
                entry["expected_disposition"],
                entry["atom_instance_id"],
            )
            self.assertTrue(result["observation"], entry["atom_instance_id"])
            outputs.append(
                (
                    entry["atom_instance_id"],
                    entry["scenario_instance_id"],
                    entry["assertion_id"],
                    entry["observation_id"],
                )
            )
        self.assertEqual(len(outputs), 229)
        self.assertEqual(len(outputs), len(set(outputs)))


if __name__ == "__main__":
    unittest.main()
