from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import support

from scenarios import run_required_suite


class RequiredSuiteTest(unittest.TestCase):
    def test_required_suite_finds_no_counterexample(self):
        report = run_required_suite()
        self.assertEqual(report["verdict"], "NO_COUNTEREXAMPLE_WITHIN_BOUNDS")
        self.assertEqual(report["counterexamples"], [])
        self.assertGreaterEqual(report["explored_delivery_traces"], 24)
        required_families = {
            "author-gap",
            "checkpoint-proof",
            "child-before-parent",
            "cross-context",
            "cycle-defense",
            "delivery-permutation",
            "duplicate-replay",
            "exhaustive-incremental-replay",
            "incremental-full-equivalence",
            "late-exact-prefix",
            "late-fork",
            "late-lower-reference",
            "malicious-omission-limit",
            "missing-parent",
            "mixed-causal-concurrent",
            "ownership-boundary",
            "parent-canonicality",
            "replay-boundary",
            "resource-bound",
            "revocation-race",
            "rollback-limit",
            "stale-parent",
        }
        self.assertEqual(set(report["scenario_counts"]), required_families)
        self.assertTrue(all(item["passed"] for item in report["invariants"]))

    def test_cli_output_is_byte_deterministic(self):
        cli = support.load_cli()
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            self.assertEqual(cli.main(["--suite", "required", "--output", str(first)]), 0)
            self.assertEqual(cli.main(["--suite", "required", "--output", str(second)]), 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            decoded = json.loads(first.read_text(encoding="ascii"))
            self.assertEqual(decoded["schema"], "styx.causal-flow-falsification-report/v0")

    def test_cli_rejects_relative_output(self):
        cli = support.load_cli()
        self.assertEqual(cli.main(["--suite", "required", "--output", "relative.json"]), 2)


if __name__ == "__main__":
    unittest.main()
