from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
import sys

if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from inventory import (  # noqa: E402
    EVIDENCE_INVENTORY_PATH,
    InventoryError,
    REQUIRED_RELATION_PATH,
    validate_inventory,
)


class InventoryTest(unittest.TestCase):
    def test_exact_literal_relation_is_complete(self) -> None:
        inventory = validate_inventory()
        self.assertEqual(len(inventory.entries), 287)
        self.assertEqual(len(inventory.semantic_entries), 229)
        self.assertEqual(len(inventory.gate_entries), 58)

    def test_scenario_alias_is_rejected(self) -> None:
        payload = json.loads(EVIDENCE_INVENTORY_PATH.read_text(encoding="utf-8"))
        payload["entries"][1]["scenario_instance_id"] = payload["entries"][0][
            "scenario_instance_id"
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(InventoryError, "relation is not exact"):
                validate_inventory(inventory_path=path, enforce_pins=False)

    def test_mutation_alias_is_rejected(self) -> None:
        payload = json.loads(EVIDENCE_INVENTORY_PATH.read_text(encoding="utf-8"))
        payload["entries"][1]["mutation_relation"] = payload["entries"][0][
            "mutation_relation"
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(InventoryError, "duplicate semantic mutation"):
                validate_inventory(inventory_path=path, enforce_pins=False)

    def test_requirement_drift_is_rejected(self) -> None:
        payload = json.loads(EVIDENCE_INVENTORY_PATH.read_text(encoding="utf-8"))
        payload["entries"][0]["requirement"] = "weakened"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(InventoryError, "requirement drift"):
                validate_inventory(inventory_path=path, enforce_pins=False)


if __name__ == "__main__":
    unittest.main()
