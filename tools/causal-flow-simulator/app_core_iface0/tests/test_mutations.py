from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema.validators import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generate_structural_witnesses import (  # noqa: E402
    _PARENT_RESOLVED_ARRAY_INSERTION_FAMILIES,
    _resolve_data_pointer,
    derive_phase_b_registries,
    derive_seed_registry,
    derive_structural_isolation_preflight,
    derive_structural_plan,
    derive_structural_target_preflight,
    main as structural_main,
    validate_structural_witness_identifiers,
    WitnessGenerationError,
)
from generate_seed_registry import generate_phase_a  # noqa: E402
from run_mutations import build_report as build_phase_a_mutation_report  # noqa: E402


class StructuralPlanTests(unittest.TestCase):
    def test_contract_derives_exact_closed_structural_plan(self) -> None:
        report = derive_structural_plan(ROOT / "contract")
        self.assertEqual(report["instance_count"], 1450)
        rows = report["rows"]
        self.assertEqual(len(rows), 1450)
        self.assertEqual(len({row["instanceId"] for row in rows}), 1450)
        self.assertEqual(len({row["assertionId"] for row in rows}), 1450)
        self.assertEqual(len({row["mutationId"] for row in rows}), 1450)
        self.assertEqual(len({row["detectorId"] for row in rows}), 1450)
        self.assertEqual(
            rows[0]["instanceId"], "STR-REQUIRED-PROPERTY-OMISSION--0001"
        )
        self.assertEqual(
            rows[-1]["instanceId"], "STR-MAX-PROPERTIES-OVERFLOW--0001"
        )
        self.assertEqual(
            {row["isolationMode"] for row in rows},
            {
                "TARGET_ONLY_COUNTERFACTUAL",
                "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST",
            },
        )

        schema = json.loads(
            (ROOT / "contract/APP-CORE-IFACE-0-STRUCTURAL-WITNESS-SCHEMA-CANDIDATE.json").read_text(
                encoding="utf-8"
            )
        )
        validators = {
            field: Draft202012Validator(
                {"$schema": schema["$schema"], **schema["$defs"][definition]}
            )
            for field, definition in {
                "assertionId": "AssertionId",
                "mutationId": "MutationId",
                "detectorId": "DetectorId",
            }.items()
        }
        for row in rows:
            for field, validator in validators.items():
                self.assertTrue(validator.is_valid(row[field]), (field, row[field]))

        first = rows[0]
        invalid = {
            "wrong namespace": ("assertionId", first["assertionId"].replace("AST-", "DET-", 1)),
            "missing double hyphen": ("assertionId", first["assertionId"].replace("--", "-", 1)),
            "extra hyphen": ("mutationId", first["mutationId"].replace("--", "---", 1)),
        }
        for name, (field, value) in invalid.items():
            with self.subTest(name=name):
                self.assertFalse(validators[field].is_valid(value))

    def test_full_synthesis_cannot_run_without_provider_bound_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "witnesses.json"
            result = structural_main(
                ["--contract", str(ROOT / "contract"), "--output", str(output)]
            )
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())


class PhaseAMutationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.evidence = Path(cls._temporary.name) / "evidence"
        generate_phase_a(ROOT.parents[2], ROOT / "contract", cls.evidence)
        cls.phase_b_seeds, cls.phase_b_registry = derive_phase_b_registries(
            ROOT.parents[2], ROOT / "contract", cls.evidence
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def test_every_phase_a_package_mutant_is_killed(self) -> None:
        report = build_phase_a_mutation_report(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(
            report,
            {
                "family_counts": {
                    "authority-header": 2,
                    "carrier-identity": 1,
                    "coverage-binding": 1,
                    "direction-binding": 1,
                    "inventory-closure": 2,
                    "oracle-binding": 2,
                    "package-closure": 3,
                    "toolchain-identity": 1,
                },
                "killed_count": 13,
                "schema": "styx.app-core-iface0.phase-a-mutation-report.v1",
                "survivor_count": 0,
                "verdict": "PASS",
            },
        )

    def test_phase_b_seed_registry_selects_all_78_objects_deterministically(self) -> None:
        registry, cases = derive_seed_registry(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(registry["rowCount"], 78)
        self.assertEqual(len(registry["rows"]), 78)
        self.assertEqual(len(cases), 80)
        self.assertEqual(
            len({row["objectSchemaId"] for row in registry["rows"]}), 78
        )
        self.assertEqual(
            len({row["objectSchemaPointer"] for row in registry["rows"]}), 78
        )
        self.assertEqual(
            registry["rows"][0]["objectSchemaId"], "OBJ-0001"
        )
        self.assertEqual(
            registry["rows"][-1]["objectSchemaId"], "OBJ-0078"
        )
        repeated, _cases = derive_seed_registry(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(registry, repeated)

    def test_stored_witness_ids_are_recomputed_before_consumption(self) -> None:
        registry = self.phase_b_registry
        validate_structural_witness_identifiers(registry)
        mutations = {
            "wrong namespace": ("assertionId", "DET-REQUIRED-PROPERTY-OMISSION--0001"),
            "wrong suffix": ("mutationId", "MUT-WRONG-SUFFIX--0001"),
            "wrong index": ("detectorId", "DET-REQUIRED-PROPERTY-OMISSION--0002"),
            "missing double hyphen": ("assertionId", "AST-REQUIRED-PROPERTY-OMISSION-0001"),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(registry)
                candidate["rows"][0][field] = value
                with self.assertRaisesRegex(WitnessGenerationError, field):
                    validate_structural_witness_identifiers(candidate)

    def test_every_witness_target_has_a_real_carrier_parent(self) -> None:
        inventory = json.loads(
            (self.evidence / "positive-carrier-inventory.json").read_text(
                encoding="utf-8"
            )
        )
        carrier_files = {
            row["caseId"]: row["carrierFile"] for row in inventory["cases"]
        }
        inserted_arrays = {
            "STR-REF-TARGET-CONSTRAINT--0001",
            "STR-REF-TARGET-CONSTRAINT--0015",
            "STR-REF-TARGET-CONSTRAINT--0063",
            "STR-REF-TARGET-CONSTRAINT--0068",
            "STR-REF-TARGET-CONSTRAINT--0071",
            "STR-REF-TARGET-CONSTRAINT--0073",
            "STR-REF-TARGET-CONSTRAINT--0074",
            "STR-REF-TARGET-CONSTRAINT--0078",
            "STR-REF-TARGET-CONSTRAINT--0079",
            "STR-REF-TARGET-CONSTRAINT--0080",
            "STR-REF-TARGET-CONSTRAINT--0093",
            "STR-REF-TARGET-CONSTRAINT--0113",
            "STR-REF-TARGET-CONSTRAINT--0114",
            "STR-REF-TARGET-CONSTRAINT--0198",
            "STR-REF-TARGET-CONSTRAINT--0210",
            "STR-MIN-ITEMS-UNDERFLOW--0001",
            "STR-ALL-OF-BRANCH-CONSTRAINT--0001",
            "STR-ALL-OF-BRANCH-CONSTRAINT--0002",
            "STR-ALL-OF-BRANCH-CONSTRAINT--0004",
            "STR-ALL-OF-BRANCH-CONSTRAINT--0005",
            "STR-ALL-OF-BRANCH-CONSTRAINT--0006",
            "STR-ALL-OF-BRANCH-CONSTRAINT--0007",
        }
        observed_array_insertions: set[str] = set()
        for row in self.phase_b_registry["rows"]:
            carrier = json.loads(
                (self.evidence / carrier_files[row["carrierCaseId"]]).read_text(
                    encoding="utf-8"
                )
            )
            target = row["targetJsonPointer"]
            try:
                _resolve_data_pointer(carrier, target)
                continue
            except (KeyError, IndexError, TypeError, ValueError):
                pass
            parent_pointer, token = target.rsplit("/", 1)
            parent = _resolve_data_pointer(carrier, parent_pointer)
            if isinstance(parent, dict):
                self.assertNotIn(token, parent, row["instanceId"])
            else:
                self.assertIsInstance(parent, list, row["instanceId"])
                self.assertTrue(token.isdecimal(), row["instanceId"])
                self.assertEqual(int(token), len(parent), row["instanceId"])
                self.assertIn(
                    row["structuralRuleId"],
                    _PARENT_RESOLVED_ARRAY_INSERTION_FAMILIES,
                )
                observed_array_insertions.add(row["instanceId"])
        self.assertEqual(observed_array_insertions, inserted_arrays)

    def test_structural_target_preflight_covers_every_instance(self) -> None:
        report = derive_structural_target_preflight(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["instance_count"], 1450)
        self.assertEqual(report["unresolved_instance_ids"], [])
        self.assertEqual(
            report["resolution_counts"],
            {
                "PARENT_RESOLVED_MEMBER_ABSENT": 24,
                "RESOLVED": 1426,
                "UNRESOLVED_TARGET": 0,
            },
        )

    def test_carrier_search_isolation_preflight_is_complete_and_fail_closed(self) -> None:
        report = derive_structural_isolation_preflight(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(report["verdict"], "AMEND_REQUIRED")
        self.assertEqual(report["instance_count"], 1450)
        self.assertEqual(
            report["classification_counts"],
            {
                "EQUIVALENT_MUTANT": 72,
                "PALETTE_EXHAUSTED": 8,
                "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST": 1,
                "SATISFIABLE": 1369,
            },
        )
        self.assertEqual(
            report["selected_classification_counts"],
            {
                "EQUIVALENT_MUTANT": 70,
                "PALETTE_EXHAUSTED": 38,
                "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST": 1,
                "SATISFIABLE": 1341,
            },
        )
        self.assertEqual(len(report["non_satisfiable_rows"]), 80)
        self.assertEqual(
            {row["instance_id"] for row in report["non_satisfiable_rows"]},
            {
                "STR-ALL-OF-BRANCH-CONSTRAINT--0005",
                "STR-ALL-OF-BRANCH-CONSTRAINT--0006",
                "STR-ALL-OF-BRANCH-CONSTRAINT--0007",
                "STR-ALL-OF-BRANCH-CONSTRAINT--0015",
                "STR-ALL-OF-BRANCH-CONSTRAINT--0017",
                "STR-ALL-OF-BRANCH-CONSTRAINT--0019",
                "STR-CONST-SUBSTITUTION--0002",
                "STR-CONST-SUBSTITUTION--0003",
                "STR-CONST-SUBSTITUTION--0004",
                "STR-CONST-SUBSTITUTION--0015",
                "STR-ITEM-CONSTRAINT-VIOLATION--0001",
                "STR-ITEM-CONSTRAINT-VIOLATION--0004",
                "STR-MAX-ITEMS-OVERFLOW--0001",
                "STR-MAX-LENGTH-OVERFLOW--0001",
                "STR-MAX-LENGTH-OVERFLOW--0002",
                "STR-MAX-LENGTH-OVERFLOW--0003",
                "STR-MIN-ITEMS-UNDERFLOW--0001",
                "STR-MIN-LENGTH-UNDERFLOW--0001",
                "STR-NOT-SUBSCHEMA-MATCH--0001",
                "STR-NULL-SUBSTITUTION--0004",
                "STR-NULL-SUBSTITUTION--0009",
                "STR-NULL-SUBSTITUTION--0017",
                "STR-ONE-OF-NO-ARM--0001",
                "STR-ONE-OF-NO-ARM--0010",
                "STR-ONE-OF-NO-ARM--0011",
                "STR-ONE-OF-NO-ARM--0013",
                "STR-ONE-OF-NO-ARM--0016",
                "STR-ONE-OF-POSITIVE-ARM--0025",
                "STR-ONE-OF-POSITIVE-ARM--0026",
                "STR-ONE-OF-POSITIVE-ARM--0027",
                "STR-ONE-OF-POSITIVE-ARM--0028",
                "STR-ONE-OF-POSITIVE-ARM--0029",
                "STR-ONE-OF-POSITIVE-ARM--0030",
                "STR-ONE-OF-POSITIVE-ARM--0031",
                "STR-ONE-OF-POSITIVE-ARM--0032",
                "STR-ONE-OF-POSITIVE-ARM--0033",
                "STR-ONE-OF-POSITIVE-ARM--0034",
                "STR-ONE-OF-POSITIVE-ARM--0035",
                "STR-ONE-OF-POSITIVE-ARM--0036",
                "STR-ONE-OF-POSITIVE-ARM--0053",
                "STR-ONE-OF-POSITIVE-ARM--0054",
                "STR-REF-TARGET-CONSTRAINT--0003",
                "STR-REF-TARGET-CONSTRAINT--0004",
                "STR-REF-TARGET-CONSTRAINT--0005",
                "STR-REF-TARGET-CONSTRAINT--0006",
                "STR-REF-TARGET-CONSTRAINT--0007",
                "STR-REF-TARGET-CONSTRAINT--0008",
                "STR-REF-TARGET-CONSTRAINT--0009",
                "STR-REF-TARGET-CONSTRAINT--0010",
                "STR-REF-TARGET-CONSTRAINT--0014",
                "STR-REF-TARGET-CONSTRAINT--0019",
                "STR-REF-TARGET-CONSTRAINT--0023",
                "STR-REF-TARGET-CONSTRAINT--0137",
                "STR-REF-TARGET-CONSTRAINT--0138",
                "STR-REF-TARGET-CONSTRAINT--0139",
                "STR-REF-TARGET-CONSTRAINT--0140",
                "STR-REF-TARGET-CONSTRAINT--0141",
                "STR-REF-TARGET-CONSTRAINT--0142",
                "STR-REF-TARGET-CONSTRAINT--0143",
                "STR-REF-TARGET-CONSTRAINT--0144",
                "STR-REF-TARGET-CONSTRAINT--0145",
                "STR-REF-TARGET-CONSTRAINT--0146",
                "STR-REF-TARGET-CONSTRAINT--0147",
                "STR-REF-TARGET-CONSTRAINT--0148",
                "STR-REF-TARGET-CONSTRAINT--0223",
                "STR-REF-TARGET-CONSTRAINT--0224",
                "STR-REF-TARGET-CONSTRAINT--0225",
                "STR-REF-TARGET-CONSTRAINT--0226",
                "STR-REF-TARGET-CONSTRAINT--0227",
                "STR-REF-TARGET-CONSTRAINT--0228",
                "STR-REF-TARGET-CONSTRAINT--0229",
                "STR-REF-TARGET-CONSTRAINT--0230",
                "STR-REF-TARGET-CONSTRAINT--0262",
                "STR-REF-TARGET-CONSTRAINT--0263",
                "STR-REQUIRED-PROPERTY-OMISSION--0004",
                "STR-REQUIRED-PROPERTY-OMISSION--0315",
                "STR-TYPE-MISMATCH--0002",
                "STR-UNIQUE-ITEMS-DUPLICATE--0001",
                "STR-UNIQUE-ITEMS-DUPLICATE--0004",
                "STR-UNKNOWN-OBJECT-PROPERTY--0019",
            },
        )
        self.assertEqual(report["reselected_count"], 28)
        self.assertEqual(len(report["reselected_rows"]), 28)
        self.assertEqual(
            {row["instance_id"] for row in report["reselected_rows"]},
            {
                "STR-ALL-OF-BRANCH-CONSTRAINT--0004",
                "STR-ANY-OF-ALL-ARMS--0001",
                "STR-ANY-OF-POSITIVE-ARM--0002",
                "STR-ITEM-CONSTRAINT-VIOLATION--0002",
                "STR-ITEM-CONSTRAINT-VIOLATION--0003",
                "STR-ITEM-CONSTRAINT-VIOLATION--0005",
                "STR-ITEM-CONSTRAINT-VIOLATION--0007",
                "STR-ITEM-CONSTRAINT-VIOLATION--0008",
                "STR-ITEM-CONSTRAINT-VIOLATION--0009",
                "STR-ITEM-CONSTRAINT-VIOLATION--0010",
                "STR-ITEM-CONSTRAINT-VIOLATION--0011",
                "STR-ITEM-CONSTRAINT-VIOLATION--0012",
                "STR-ITEM-CONSTRAINT-VIOLATION--0013",
                "STR-ITEM-CONSTRAINT-VIOLATION--0014",
                "STR-ITEM-CONSTRAINT-VIOLATION--0015",
                "STR-MIN-ITEMS-UNDERFLOW--0003",
                "STR-UNIQUE-ITEMS-DUPLICATE--0002",
                "STR-UNIQUE-ITEMS-DUPLICATE--0003",
                "STR-UNIQUE-ITEMS-DUPLICATE--0005",
                "STR-UNIQUE-ITEMS-DUPLICATE--0007",
                "STR-UNIQUE-ITEMS-DUPLICATE--0008",
                "STR-UNIQUE-ITEMS-DUPLICATE--0009",
                "STR-UNIQUE-ITEMS-DUPLICATE--0010",
                "STR-UNIQUE-ITEMS-DUPLICATE--0011",
                "STR-UNIQUE-ITEMS-DUPLICATE--0012",
                "STR-UNIQUE-ITEMS-DUPLICATE--0013",
                "STR-UNIQUE-ITEMS-DUPLICATE--0014",
                "STR-UNIQUE-ITEMS-DUPLICATE--0015",
            },
        )
        self.assertTrue(
            all(row["candidate_ordinal"] >= 2 for row in report["reselected_rows"])
        )
        self.assertNotIn(
            "RECIPE_NOT_IMPLEMENTED", report["classification_counts"]
        )


if __name__ == "__main__":
    unittest.main()
