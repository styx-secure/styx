from __future__ import annotations

import json
from pathlib import Path
import tempfile
import sys
import unittest


C02K_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(C02K_ROOT))

from commitment_context_probe import (  # noqa: E402
    build_report,
    canonical_bytes,
    main as probe_main,
)
from mutation_harness_c02k import (  # noqa: E402
    build_report as build_mutation_report,
    canonical_bytes as mutation_bytes,
    main as mutation_main,
)
from scenarios_c02k import (  # noqa: E402
    REQUIRED_MUTANTS,
    REQUIRED_WITNESSES,
    declared_mutation_coverage,
    run_required_suite,
)


class ClosedSuiteTests(unittest.TestCase):
    def test_required_suite_is_complete_unique_and_green(self) -> None:
        suite = run_required_suite()
        self.assertEqual(suite.witnesses, REQUIRED_WITNESSES)
        self.assertEqual(len(suite.checks), 43)
        self.assertEqual(len({item.identifier for item in suite.checks}), len(suite.checks))
        self.assertTrue(all(item.passed for item in suite.checks))

    def test_every_mutant_has_declared_detectors_and_is_killed(self) -> None:
        declared = declared_mutation_coverage()
        self.assertEqual(set(declared), set(REQUIRED_MUTANTS))
        self.assertTrue(all(declared[identifier] for identifier in REQUIRED_MUTANTS))
        report, passed = build_mutation_report()
        self.assertTrue(passed)
        self.assertEqual(report["verdict"], "ALL_REQUIRED_MUTANTS_KILLED")
        self.assertEqual(report["killed"], len(REQUIRED_MUTANTS))
        self.assertEqual(report["survived"], [])

    def test_reports_are_canonical_and_deterministic(self) -> None:
        first, first_passed = build_report()
        second, second_passed = build_report()
        self.assertTrue(first_passed and second_passed)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(json.loads(canonical_bytes(first)), first)
        self.assertEqual(
            set(first["work_counter_units"]),
            {
                "serialization_invocations",
                "parse_invocations",
                "inverse_invocations",
                "digest_invocations",
                "bytes_hashed",
                "leaf_visits",
                "node_visits",
            },
        )
        self.assertEqual(
            first["sample_work"],
            {
                "serialization_invocations": 12,
                "parse_invocations": 12,
                "inverse_invocations": 12,
                "digest_invocations": 12,
                "bytes_hashed": 1618,
                "leaf_visits": 6,
                "node_visits": 5,
            },
        )

        first_mutants, first_mutants_passed = build_mutation_report()
        second_mutants, second_mutants_passed = build_mutation_report()
        self.assertTrue(first_mutants_passed and second_mutants_passed)
        self.assertEqual(mutation_bytes(first_mutants), mutation_bytes(second_mutants))

    def test_cli_outputs_repeat_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe_a = root / "probe-a.json"
            probe_b = root / "probe-b.json"
            mutant_a = root / "mutant-a.json"
            mutant_b = root / "mutant-b.json"
            self.assertEqual(probe_main(["--suite", "required", "--output", str(probe_a)]), 0)
            self.assertEqual(probe_main(["--suite", "required", "--output", str(probe_b)]), 0)
            self.assertEqual(mutation_main(["--suite", "required", "--output", str(mutant_a)]), 0)
            self.assertEqual(mutation_main(["--suite", "required", "--output", str(mutant_b)]), 0)
            self.assertEqual(probe_a.read_bytes(), probe_b.read_bytes())
            self.assertEqual(mutant_a.read_bytes(), mutant_b.read_bytes())


if __name__ == "__main__":
    unittest.main()
