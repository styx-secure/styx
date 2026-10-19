from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[2]
sys.path.insert(0, str(PACKAGE))

from inventory import (  # noqa: E402
    load_unique,
    validate_anchor,
    validate_inventory,
    validate_public_reader_inputs,
)


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = load_unique(PACKAGE / "source-inventory.json")

    def test_closed_inventory_and_anchor_pass(self) -> None:
        validated = validate_inventory(self.inventory)
        self.assertEqual(60, len(validated["atoms"]))
        self.assertEqual(56, len(validated["witnesses"]))
        self.assertEqual(104, len(validated["relations"]))
        validate_anchor(ROOT, load_unique(PACKAGE / "phase-b-anchor.json"))
        self.assertEqual(5, validate_public_reader_inputs(ROOT))

    def test_missing_atom_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.inventory)
        mutated["atoms"].pop()
        with self.assertRaises(ValueError):
            validate_inventory(mutated)

    def test_anchor_registry_qualification_fails_closed(self) -> None:
        anchor = load_unique(PACKAGE / "phase-b-anchor.json")
        anchor["profile"]["ciphersuite_registry"] = "STYX_SIGNATURE"
        with self.assertRaisesRegex(ValueError, "profile mismatch"):
            validate_anchor(ROOT, anchor)

    def test_oracle_in_adapter_input_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.inventory)
        mutated["witnesses"][0]["input"]["expected"] = "PASS"
        with self.assertRaises(ValueError):
            validate_inventory(mutated)

    def test_reused_executable_witness_input_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.inventory)
        mutated["witnesses"][1]["input"] = copy.deepcopy(
            mutated["witnesses"][0]["input"]
        )
        with self.assertRaisesRegex(ValueError, "duplicate executable witness"):
            validate_inventory(mutated)

    def test_inert_scenario_variant_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.inventory)
        mutated["witnesses"][0]["input"]["scenario_variant"] = "fake-uniqueness"
        with self.assertRaisesRegex(ValueError, "field set|discriminator"):
            validate_inventory(mutated)

    def test_shared_witness_is_one_explicit_relation(self) -> None:
        validated = validate_inventory(self.inventory)
        witness_id = "W-OB-SS01-H-UNAUTHENTICATED-OB"
        relations = [
            row for row in validated["relations"] if row["witness"] == witness_id
        ]
        self.assertEqual(2, len(relations))
        self.assertEqual(
            {"ATOM-OB-SS01-HOSTILE_BOUNDARY", "ATOM-SSD-02-HOSTILE_BOUNDARY"},
            {row["atom"] for row in relations},
        )

    def test_every_closed_disposition_has_an_executable_witness(self) -> None:
        mutated = copy.deepcopy(self.inventory)
        witness = next(
            row
            for row in mutated["witnesses"]
            if row["id"] == "W-MUTATION-NOT-COMMITTED"
        )
        witness["expected"]["disposition"] = "INVALID_SESSION_INPUT"
        with self.assertRaisesRegex(ValueError, "disposition witness coverage"):
            validate_inventory(mutated)

    def test_public_derivation_drift_fails_closed(self) -> None:
        path = PACKAGE / "public-candidate-projections.json"
        original = path.read_text(encoding="utf-8")
        mutated = original.replace(
            "LOWER_UNSIGNED_LEXICOGRAPHIC_ACCOUNT_AFTER_FIXED_INPUT_CHECKS",
            "APPLICATION_WITNESS_SELECTOR",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "tools/causal-flow-simulator/ss0"
            target.mkdir(parents=True)
            for name in (
                "oracle-reader-task.json",
                "phase-b-anchor.json",
                "public-candidate-projections.json",
            ):
                (target / name).write_bytes((PACKAGE / name).read_bytes())
            (target / path.name).write_text(mutated, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "derivation mismatch"):
                validate_public_reader_inputs(root)


if __name__ == "__main__":
    unittest.main()
