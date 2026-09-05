from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
from run_semantic_preflight import (  # noqa: E402
    SemanticPreflightError,
    build_report_from_seed_registry as build_semantic_preflight,
)
from run_semantic_acv048 import derive_python_report as derive_acv048_report  # noqa: E402
from run_semantic_acv049 import build_report as build_acv049_preflight  # noqa: E402


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

    def test_real_seed_partition_closes_all_semantic_execution_rows(self) -> None:
        report = build_semantic_preflight(self.phase_b_seeds, ROOT / "contract")
        self.assertEqual(report["semantic_instance_count"], 5149)
        self.assertEqual(
            report["seed_direction_counts"], {"REQUEST": 48, "RESPONSE": 30}
        )
        self.assertEqual(
            report["acv048_phase_counts"],
            {
                "BLIND_INPUT_EXECUTION": 432,
                "POST_OUTPUT_MUTATION": 270,
                "VALIDATOR_SELF_TEST": 0,
            },
        )
        self.assertEqual(
            report["execution_phase_counts"],
            {
                "BLIND_INPUT_EXECUTION": 991,
                "POST_OUTPUT_MUTATION": 4131,
                "VALIDATOR_SELF_TEST": 27,
            },
        )
        self.assertEqual(report["status"], "PRESELECTION_EVIDENCE")

    def test_semantic_preflight_rejects_incomplete_seed_relation(self) -> None:
        mutant = copy.deepcopy(self.phase_b_seeds)
        mutant["rows"].pop()
        with self.assertRaisesRegex(
            SemanticPreflightError, "requires 78 seed rows"
        ):
            build_semantic_preflight(mutant, ROOT / "contract")

    def test_acv048_executes_all_cross_plane_field_smuggling_instances(self) -> None:
        report = derive_acv048_report(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(report["instance_count"], 702)
        self.assertEqual(report["exact_rejected_count"], 702)
        self.assertEqual(report["mutant_admitted_count"], 702)
        self.assertEqual(
            report["phase_counts"],
            {"BLIND_INPUT_EXECUTION": 432, "POST_OUTPUT_MUTATION": 270},
        )
        self.assertEqual(len({row["instanceId"] for row in report["rows"]}), 702)
        self.assertTrue(all(not row["exactAccepted"] for row in report["rows"]))
        self.assertTrue(all(row["mutantAccepted"] for row in report["rows"]))

    def test_acv049_preflight_is_branch_faithful_and_non_authoritative(self) -> None:
        with patch("run_semantic_acv049._javascript_rejects", return_value=True):
            report = build_acv049_preflight(
                ROOT.parents[2], ROOT / "contract", self.evidence, node="node"
            )
        self.assertEqual(report["instance_count"], 3770)
        self.assertEqual(report["path_count"], 377)
        self.assertEqual(report["string_path_count"], 372)
        self.assertEqual(report["non_string_path_count"], 5)
        self.assertEqual(report["materialized_path_count"], 296)
        self.assertEqual(report["unmaterialized_path_count"], 81)
        self.assertEqual(report["live_rejection_count"], 1676)
        self.assertEqual(report["claimed_mutant_kills"], 0)
        self.assertEqual(report["status"], "PRESELECTION_EVIDENCE")
        self.assertEqual(report["verdict"], "AMEND_REQUIRED")
        self.assertEqual(
            report["class_counts"],
            {
                "NON_STRING_CONST": 50,
                "SCHEMA_ADMISSIBLE_ENCODED": 1921,
                "SCHEMA_CLOSED": 1799,
            },
        )
        self.assertEqual(
            report["class_materialization_counts"],
            {
                "NON_STRING_CONST:UNMATERIALIZED": 50,
                "SCHEMA_ADMISSIBLE_ENCODED:MATERIALIZED": 1284,
                "SCHEMA_ADMISSIBLE_ENCODED:UNMATERIALIZED": 637,
                "SCHEMA_CLOSED:MATERIALIZED": 1676,
                "SCHEMA_CLOSED:UNMATERIALIZED": 123,
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
                "PARENT_RESOLVED_MEMBER_ABSENT": 20,
                "RESOLVED": 1430,
                "UNRESOLVED_TARGET": 0,
            },
        )

    def test_carrier_search_isolation_preflight_is_complete_and_fail_closed(self) -> None:
        report = derive_structural_isolation_preflight(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["instance_count"], 1450)
        self.assertEqual(
            report["classification_counts"],
            {
                "ANTI_DOWNGRADE_OVERLAP_SELF_TEST": 1,
                "CO_CONSTRAINED_OCCURRENCE_SELF_TEST": 81,
                "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST": 1,
                "TARGET_ONLY_COUNTERFACTUAL": 1367,
            },
        )
        self.assertEqual(
            report["selected_classification_counts"],
            {
                "ANTI_DOWNGRADE_OVERLAP_SELF_TEST": 1,
                "EQUIVALENT_MUTANT": 27,
                "PALETTE_EXHAUSTED": 1,
                "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST": 1,
                "SATISFIABLE": 1420,
            },
        )
        self.assertEqual(report["non_satisfiable_rows"], [])
        relation = json.loads(
            (
                ROOT
                / "contract/APP-CORE-IFACE-0-STRUCTURAL-ISOLATION-RELATION-CANDIDATE.json"
            ).read_text(encoding="utf-8")
        )
        expected_reselections = [
            {
                "candidate_ordinal": row["candidateOrdinal"],
                "carrier_case_id": row["carrierCaseId"],
                "instance_id": row["instanceId"],
            }
            for row in relation["carrierReselections"]
        ]
        self.assertEqual(report["reselected_count"], 31)
        self.assertEqual(report["reselected_rows"], expected_reselections)
        self.assertTrue(
            all(row["candidate_ordinal"] >= 2 for row in report["reselected_rows"])
        )
        self.assertNotIn(
            "RECIPE_NOT_IMPLEMENTED", report["classification_counts"]
        )


if __name__ == "__main__":
    unittest.main()
