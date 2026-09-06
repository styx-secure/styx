from __future__ import annotations

import ast
import copy
import json
import subprocess
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
from canonical_json import dumps as canonical_dumps  # noqa: E402
from canonical_report import canonical_bytes  # noqa: E402
from run_mutations import build_report as build_phase_a_mutation_report  # noqa: E402
from run_semantic_preflight import (  # noqa: E402
    SemanticPreflightError,
    build_report_from_seed_registry as build_semantic_preflight,
)
from run_semantic_acv048 import derive_python_report as derive_acv048_report  # noqa: E402
from run_semantic_acv049 import (  # noqa: E402
    REPORT_FIELDS as ACV049_REPORT_FIELDS,
    SemanticACV049Error,
    _SourceSiteInstrumenter,
    _SourceTaggedString,
    _pattern_values,
    _tag_source_value,
    build_report as build_acv049_preflight,
    build_terminal_jobs as build_acv049_terminal_jobs,
    derive_phase_a_materialized_paths,
    derive_phase_a_source_site_map,
)


class StructuralPlanTests(unittest.TestCase):
    def test_acv049_source_tagging_is_value_preserving_and_nearest_site_wins(
        self,
    ) -> None:
        tagged = _tag_source_value(
            "PURITY-SITE-FIRST",
            {"outer": ["alpha", {"inner": "bravo"}], "number": 7},
        )
        self.assertEqual(
            tagged,
            {"outer": ["alpha", {"inner": "bravo"}], "number": 7},
        )
        self.assertIsInstance(tagged["outer"][0], _SourceTaggedString)
        self.assertEqual(tagged["outer"][0].site_id, "PURITY-SITE-FIRST")
        retagged = _tag_source_value("PURITY-SITE-SECOND", tagged)
        self.assertEqual(retagged["outer"][0].site_id, "PURITY-SITE-FIRST")
        self.assertIs(copy.deepcopy(retagged["outer"][0]), retagged["outer"][0])

    def test_acv049_pattern_expansion_retains_every_concrete_pointer(self) -> None:
        value = {"items": [{"state": "one"}, {"state": "two"}]}
        self.assertEqual(
            _pattern_values(value, ("items", None, "state")),
            [
                (("items", 0, "state"), "one"),
                (("items", 1, "state"), "two"),
            ],
        )
        self.assertEqual(_pattern_values(value, ("missing",)), [])

    def test_acv049_duplicate_explicit_removal_site_fails_closed(self) -> None:
        tree = ast.parse(
            "def _assemble_context_projection():\n"
            "    result = {}\n"
            "    result['retentionState'] = 'FIRST'\n"
            "    result['retentionState'] = 'SECOND'\n"
            "    return result\n"
        )
        with self.assertRaisesRegex(
            SemanticACV049Error, "duplicate ACV-049 construction site"
        ):
            _SourceSiteInstrumenter().visit(tree)

    def test_contract_derives_exact_closed_structural_plan(self) -> None:
        report = derive_structural_plan(ROOT / "contract")
        self.assertEqual(report["instance_count"], 1553)
        rows = report["rows"]
        self.assertEqual(len(rows), 1553)
        self.assertEqual(len({row["instanceId"] for row in rows}), 1553)
        self.assertEqual(len({row["assertionId"] for row in rows}), 1553)
        self.assertEqual(len({row["mutationId"] for row in rows}), 1553)
        self.assertEqual(len({row["detectorId"] for row in rows}), 1553)
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
        materialized = derive_phase_a_materialized_paths(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        report = build_semantic_preflight(
            self.phase_b_seeds,
            ROOT / "contract",
            acv049_materialized_paths=materialized,
        )
        self.assertEqual(report["semantic_instance_count"], 2359)
        self.assertEqual(
            report["seed_direction_counts"], {"REQUEST": 56, "RESPONSE": 31}
        )
        self.assertEqual(
            report["acv048_phase_counts"],
            {
                "BLIND_INPUT_EXECUTION": 504,
                "POST_OUTPUT_MUTATION": 279,
                "VALIDATOR_SELF_TEST": 0,
                "TWO_ENVIRONMENT_SOURCE_MUTATION": 0,
            },
        )
        self.assertEqual(
            report["execution_phase_counts"],
            {
                "BLIND_INPUT_EXECUTION": 1156,
                "POST_OUTPUT_MUTATION": 691,
                "VALIDATOR_SELF_TEST": 212,
                "TWO_ENVIRONMENT_SOURCE_MUTATION": 300,
            },
        )
        self.assertEqual(report["status"], "PRESELECTION_EVIDENCE")

    def test_semantic_preflight_rejects_incomplete_seed_relation(self) -> None:
        mutant = copy.deepcopy(self.phase_b_seeds)
        mutant["rows"].pop()
        with self.assertRaisesRegex(
            SemanticPreflightError, "requires 87 seed rows"
        ):
            build_semantic_preflight(
                mutant,
                ROOT / "contract",
                acv049_materialized_paths=set(),
            )

    def test_acv048_executes_all_cross_plane_field_smuggling_instances(self) -> None:
        report = derive_acv048_report(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(report["instance_count"], 783)
        self.assertEqual(report["exact_rejected_count"], 783)
        self.assertEqual(report["mutant_admitted_count"], 783)
        self.assertEqual(
            report["phase_counts"],
            {"BLIND_INPUT_EXECUTION": 504, "POST_OUTPUT_MUTATION": 279},
        )
        self.assertEqual(len({row["instanceId"] for row in report["rows"]}), 783)
        self.assertTrue(all(not row["exactAccepted"] for row in report["rows"]))
        self.assertTrue(all(row["mutantAccepted"] for row in report["rows"]))

    def test_acv049_replacement_registry_is_branch_faithful_and_non_authoritative(self) -> None:
        jobs = build_acv049_terminal_jobs(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )["jobs"]
        javascript_rows: list[object] = []
        for offset in range(0, len(jobs), 64):
            batch = jobs[offset:offset + 64]
            with tempfile.TemporaryFile() as input_file:
                input_file.write(canonical_dumps({"jobs": batch}))
                input_file.seek(0)
                completed = subprocess.run(
                    [
                        "node",
                        str(ROOT / "node_adapter.mjs"),
                        "--self-test-terminal-schema",
                        "--contract",
                        str(ROOT / "contract"),
                    ],
                    stdin=input_file,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            result = json.loads(completed.stdout)
            self.assertEqual(set(result), {"results"})
            javascript_rows.extend(result["results"])
        report = build_acv049_preflight(
            ROOT.parents[2], ROOT / "contract", self.evidence,
            javascript_result={"results": javascript_rows},
        )
        self.assertEqual(report["instance_count"], 884)
        self.assertEqual(report["path_count"], 406)
        self.assertEqual(report["materialized_path_count"], 321)
        self.assertEqual(report["materialized_mutable_path_count"], 228)
        self.assertEqual(report["materialized_singleton_path_count"], 93)
        self.assertEqual(report["unmaterialized_path_count"], 80)
        self.assertEqual(report["claimed_mutant_kills"], 0)
        self.assertEqual(report["historical_reconciliation_count"], 4060)
        self.assertEqual(report["status"], "REMEDIATION_PARTIAL_EXECUTION")
        self.assertEqual(report["verdict"], "PARTIAL_EXECUTION_PASS")
        self.assertTrue(canonical_bytes(report, allowed_fields=ACV049_REPORT_FIELDS))
        self.assertEqual(
            report["executed_relation_counts"],
            {"ACV-049-L": 401, "ACV-049-N": 5, "ACV-049-S": 101},
        )
        self.assertEqual(
            report["pending_relation_counts"],
            {"ACV-049-E": 77, "ACV-049-P": 300},
        )
        self.assertEqual(
            report["relation_counts"],
            {
                "ACV-049-L": 401,
                "ACV-049-P": 300,
                "ACV-049-S": 101,
                "ACV-049-N": 5,
                "ACV-049-E": 77,
            },
        )
        self.assertEqual(len({row["instanceId"] for row in report["rows"]}), 884)
        self.assertTrue(
            all(
                row.get("evidenceDisposition")
                in {
                    "DOMAIN_CLOSURE_PASS",
                    "LITERAL_PROVENANCE_CLOSURE_PASS",
                    "LOCAL_BLIND_EXECUTION_PASS_TWO_ENVIRONMENT_PENDING",
                    "NON_STRING_RECONCILIATION_PASS",
                    "SOURCE_SITE_EVIDENCE_PENDING",
                }
                for row in report["rows"]
            )
        )
        literal_rows = [
            row for row in report["rows"] if row["relationId"] == "ACV-049-L"
        ]
        self.assertTrue(
            all(
                [member["familyId"] for member in row["literalFamilyVector"]]
                == [f"LITERAL-FAMILY-{index:02d}" for index in range(10)]
                and all(
                    len(member["encodedRepresentatives"]) == 3
                    for member in row["literalFamilyVector"]
                )
                for row in literal_rows
            )
        )
        self.assertTrue(
            all(
                row["dataPointer"].startswith("JSON_POINTER:")
                and all(
                    occurrence.startswith("JSON_POINTER:")
                    for occurrence in row["terminalSchemaOccurrences"]
                )
                for row in literal_rows
            )
        )
        singleton_rows = [
            row for row in report["rows"] if row["relationId"] == "ACV-049-S"
        ]
        non_string_rows = [
            row for row in report["rows"] if row["relationId"] == "ACV-049-N"
        ]
        self.assertTrue(
            all(
                row["pythonSchemaAccepted"]
                == row["javascriptSchemaAccepted"]
                == [True, False]
                for row in singleton_rows
            )
        )
        self.assertTrue(
            all(
                row["pythonSchemaAccepted"]
                == row["javascriptSchemaAccepted"]
                == [True, False, False]
                and len(row["historicalStringProvenanceIdsRetired"]) == 10
                for row in non_string_rows
            )
        )
        evaluator_rows = [
            row for row in report["rows"] if row["relationId"] == "ACV-049-E"
        ]
        self.assertEqual(len(evaluator_rows), 77)
        self.assertTrue(
            all(
                len(row["requestSha256"]) == 64
                and len(row["responseSha256"]) == 64
                and row["responseCarrierCaseIds"]
                and row["evidenceDisposition"]
                == "LOCAL_BLIND_EXECUTION_PASS_TWO_ENVIRONMENT_PENDING"
                for row in evaluator_rows
            )
        )

    def test_acv049_phase_a_source_sites_are_ast_derived_and_closed(self) -> None:
        report = derive_phase_a_source_site_map(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(report["schema"], "styx.app-core-iface0.acv049-source-site-map.v1")
        self.assertEqual(report["verdict"], "PHASE_A_SOURCE_SITE_MAP_PASS")
        self.assertEqual(report["instrumentationPointCount"], 507)
        self.assertEqual(report["materializedMutablePathCount"], 228)
        self.assertEqual(report["pendingSupplementaryMutablePathCount"], 72)
        self.assertEqual(
            len(set(report["pendingSupplementaryLogicalPaths"])), 72
        )
        self.assertEqual(report["routeCount"], 596)
        self.assertEqual(
            report["routeClassCounts"],
            {"FAULT_INJECTED_ROUTE": 15, "ORDINARY_ROUTE": 581},
        )
        self.assertEqual(report["usedSiteCount"], 76)
        self.assertEqual(len(report["routeSetSha256"]), 64)
        self.assertEqual(len(report["usedSiteSetSha256"]), 64)
        self.assertEqual(
            len({row["siteId"] for row in report["usedSites"]}),
            report["usedSiteCount"],
        )
        self.assertTrue(
            {
                "PURITY-SITE-CANDIDATE-TERMINAL",
                "PURITY-SITE-CONTENT-STATE-AXIS",
                "PURITY-SITE-GENESIS-TERMINAL",
                "PURITY-SITE-TRANSCRIPT-REJECTED",
                "PURITY-SITE-TRANSCRIPT-VALIDATED",
            }
            <= {row["siteId"] for row in report["usedSites"]}
        )
        self.assertTrue(all(row["astMembers"] for row in report["usedSites"]))
        self.assertTrue(
            all(
                row["logicalPath"].startswith("LOGICAL_PATH:")
                and row["concretePointers"]
                and all(
                    pointer.startswith("JSON_POINTER:")
                    for pointer in row["concretePointers"]
                )
                and row["astSiteIds"]
                and row["siteId"].startswith("PURITY-SITE-")
                and row["routeClass"]
                in {"ORDINARY_ROUTE", "FAULT_INJECTED_ROUTE"}
                for row in report["routes"]
            )
        )

    def test_phase_b_seed_registry_selects_all_87_objects_deterministically(self) -> None:
        registry, cases = derive_seed_registry(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(registry["rowCount"], 87)
        self.assertEqual(len(registry["rows"]), 87)
        self.assertEqual(len(cases), 96)
        self.assertEqual(
            len({row["objectSchemaId"] for row in registry["rows"]}), 87
        )
        self.assertEqual(
            len({row["objectSchemaPointer"] for row in registry["rows"]}), 87
        )
        self.assertEqual(
            registry["rows"][0]["objectSchemaId"], "OBJ-0001"
        )
        self.assertEqual(
            registry["rows"][-1]["objectSchemaId"], "OBJ-0087"
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
            "STR-REF-TARGET-CONSTRAINT--0031",
            "STR-REF-TARGET-CONSTRAINT--0044",
            "STR-REF-TARGET-CONSTRAINT--0072",
            "STR-REF-TARGET-CONSTRAINT--0075",
            "STR-REF-TARGET-CONSTRAINT--0076",
            "STR-REF-TARGET-CONSTRAINT--0077",
            "STR-REF-TARGET-CONSTRAINT--0078",
            "STR-REF-TARGET-CONSTRAINT--0082",
            "STR-REF-TARGET-CONSTRAINT--0083",
            "STR-REF-TARGET-CONSTRAINT--0084",
            "STR-REF-TARGET-CONSTRAINT--0096",
            "STR-REF-TARGET-CONSTRAINT--0097",
            "STR-REF-TARGET-CONSTRAINT--0115",
            "STR-REF-TARGET-CONSTRAINT--0116",
            "STR-REF-TARGET-CONSTRAINT--0161",
            "STR-REF-TARGET-CONSTRAINT--0215",
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
        self.assertEqual(report["instance_count"], 1553)
        self.assertEqual(report["unresolved_instance_ids"], [])
        self.assertEqual(
            report["resolution_counts"],
            {
                "PARENT_RESOLVED_MEMBER_ABSENT": 25,
                "RESOLVED": 1528,
                "UNRESOLVED_TARGET": 0,
            },
        )

    def test_carrier_search_isolation_preflight_is_complete_and_fail_closed(self) -> None:
        report = derive_structural_isolation_preflight(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["instance_count"], 1553)
        self.assertEqual(
            report["classification_counts"],
            {
                "ANTI_DOWNGRADE_OVERLAP_SELF_TEST": 1,
                "CO_CONSTRAINED_OCCURRENCE_SELF_TEST": 82,
                "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST": 1,
                "TARGET_ONLY_COUNTERFACTUAL": 1469,
            },
        )
        self.assertEqual(
            report["selected_classification_counts"],
            {
                "ANTI_DOWNGRADE_OVERLAP_SELF_TEST": 1,
                "EQUIVALENT_MUTANT": 28,
                "PALETTE_EXHAUSTED": 1,
                "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST": 1,
                "SATISFIABLE": 1522,
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
        self.assertEqual(report["reselected_count"], 29)
        self.assertEqual(report["reselected_rows"], expected_reselections)
        self.assertTrue(
            all(row["candidate_ordinal"] >= 2 for row in report["reselected_rows"])
        )
        self.assertNotIn(
            "RECIPE_NOT_IMPLEMENTED", report["classification_counts"]
        )


if __name__ == "__main__":
    unittest.main()
