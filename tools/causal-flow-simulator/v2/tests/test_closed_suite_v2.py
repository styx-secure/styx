from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

V2_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V2_ROOT))

from causal_flow_simulator_v2 import build_report, canonical_bytes, main  # noqa: E402
from scenarios_v2 import (  # noqa: E402
    C0_2D_FAMILIES,
    C0_2F_OBLIGATIONS,
    C0_2I_FAMILIES,
)


class ClosedSuiteTests(unittest.TestCase):
    def test_registry_is_exact_non_empty_and_green(self) -> None:
        report, passed = build_report()
        self.assertTrue(passed)
        registry = report["closed_registry"]
        self.assertEqual(set(registry["c0_2d_families"]), C0_2D_FAMILIES)
        self.assertEqual(set(registry["c0_2f_obligations"]), C0_2F_OBLIGATIONS)
        self.assertEqual(set(registry["c0_2i_families"]), C0_2I_FAMILIES)
        self.assertTrue(registry["complete_and_non_empty"])
        self.assertEqual(report["verdict"], "NO_COUNTEREXAMPLE_WITHIN_BOUNDS")
        self.assertEqual(report["instrumentation"]["earliest_replay_boundary"], 0)

    def test_every_family_and_obligation_has_a_directed_check(self) -> None:
        report, _ = build_report()
        counts = report["exploration"]["scenario_counts"]
        obligations = report["exploration"]["obligation_check_counts"]
        self.assertTrue((C0_2D_FAMILIES | C0_2I_FAMILIES) <= set(counts))
        self.assertTrue(all(counts[name] > 0 for name in C0_2D_FAMILIES | C0_2I_FAMILIES))
        self.assertEqual(set(obligations), C0_2F_OBLIGATIONS)
        self.assertTrue(all(obligations[name] > 0 for name in C0_2F_OBLIGATIONS))

    def test_collision_inputs_are_excluded_from_positive_claim(self) -> None:
        report, _ = build_report()
        self.assertEqual(
            report["excluded_inputs"][0]["code"],
            "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED",
        )
        collision_checks = [
            item
            for item in report["invariants"]
            if item["family"] == "credential-identifier-collision"
        ]
        self.assertGreaterEqual(len(collision_checks), 8)
        self.assertTrue(all(item["passed"] for item in collision_checks))

    def test_canonical_output_is_stable_with_one_terminal_newline(self) -> None:
        report_a, _ = build_report()
        report_b, _ = build_report()
        output_a = canonical_bytes(report_a)
        output_b = canonical_bytes(report_b)
        self.assertEqual(output_a, output_b)
        self.assertTrue(output_a.endswith(b"\n"))
        self.assertFalse(output_a.endswith(b"\n\n"))
        self.assertEqual(json.loads(output_a), report_a)

    def test_cli_writes_the_same_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            self.assertEqual(main(["--suite", "required", "--output", str(first)]), 0)
            self.assertEqual(main(["--suite", "required", "--output", str(second)]), 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == "__main__":
    unittest.main()
