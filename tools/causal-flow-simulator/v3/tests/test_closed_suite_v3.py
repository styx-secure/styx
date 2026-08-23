from __future__ import annotations

from pathlib import Path
import sys
import unittest


V3_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V3_ROOT))

from causal_flow_simulator_v3 import build_report, canonical_bytes  # noqa: E402
from mutation_harness_v3 import build_report as build_mutation_report  # noqa: E402
from scenarios_v3 import (  # noqa: E402
    REQUIRED_MUTANTS,
    REQUIRED_WITNESSES,
    declared_mutation_coverage,
    mutation_coverage,
    run_required_suite,
)


class ClosedSuiteTests(unittest.TestCase):
    def test_required_suite_is_complete_and_green(self) -> None:
        suite = run_required_suite()
        self.assertEqual(suite.witnesses, REQUIRED_WITNESSES)
        self.assertTrue(all(item.passed for item in suite.checks))
        self.assertEqual(len({item.identifier for item in suite.checks}), len(suite.checks))

    def test_report_is_deterministic(self) -> None:
        first, first_pass = build_report()
        second, second_pass = build_report()
        self.assertTrue(first_pass and second_pass)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))

    def test_every_required_mutant_is_killed(self) -> None:
        report, passed = build_mutation_report()
        self.assertTrue(passed)
        self.assertEqual(report["killed"], len(REQUIRED_MUTANTS))
        self.assertEqual(report["survived"], [])

    def test_every_declared_witness_mutant_edge_is_observed(self) -> None:
        self.assertEqual(mutation_coverage(), declared_mutation_coverage())


if __name__ == "__main__":
    unittest.main()
