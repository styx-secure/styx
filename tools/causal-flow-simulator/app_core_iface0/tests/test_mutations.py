from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generate_structural_witnesses import (  # noqa: E402
    derive_structural_plan,
    main as structural_main,
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


if __name__ == "__main__":
    unittest.main()
