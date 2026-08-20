from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import support

from model import ModelInputError
from payload_model import PayloadProfile
from scenarios import EXPECTED_C0_2F_OBLIGATIONS, Suite, first, run_required_suite


class RequiredSuiteTest(unittest.TestCase):
    def test_required_suite_finds_no_counterexample(self):
        report = run_required_suite()
        self.assertEqual(report["verdict"], "NO_COUNTEREXAMPLE_WITHIN_BOUNDS")
        self.assertEqual(report["counterexamples"], [])
        self.assertGreaterEqual(report["explored_delivery_traces"], 42)
        self.assertGreaterEqual(report["payload_exploration_cases"], 18)
        obligations = report["c0_2f_obligations"]
        self.assertEqual(
            {item["id"] for item in obligations},
            {f"C0.2f-{number:02d}" for number in range(1, 17)},
        )
        self.assertTrue(all(item["passed"] and item["checks"] >= 1 for item in obligations))
        required_families = {
            "availability-not-fork",
            "author-gap",
            "checkpoint-availability",
            "checkpoint-non-substitution",
            "checkpoint-proof",
            "child-before-parent",
            "chunk-privacy",
            "compacted-reference-collision",
            "cross-context",
            "cycle-defense",
            "delivery-permutation",
            "duplicate-replay",
            "exhaustive-incremental-replay",
            "incremental-full-equivalence",
            "late-exact-prefix",
            "late-fork",
            "late-lower-reference",
            "late-removal-invalidation",
            "malicious-omission-limit",
            "missing-parent",
            "mixed-causal-concurrent",
            "obligation-registry",
            "ownership-boundary",
            "parent-canonicality",
            "payload-availability-invariance",
            "payload-replay-equivalence",
            "payload-resource-bound",
            "post-removal-presentation",
            "fresh-reconstruction",
            "replay-boundary",
            "removal-policy",
            "removal-target-cases",
            "required-bypass",
            "required-deferral",
            "resource-bound",
            "revocation-race",
            "rollback-limit",
            "stale-parent",
            "typed-axis-closure",
        }
        self.assertEqual(set(report["scenario_counts"]), required_families)
        self.assertTrue(all(item["passed"] for item in report["invariants"]))

    def test_incomplete_obligation_registry_fails_closed(self):
        suite = Suite()
        suite.check(
            "one obligation is present",
            True,
            family="test",
            obligation="C0.2f-01",
        )
        suite.check_c0_2f_obligation_registry()
        report = suite.report()
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(
            report["counterexamples"][0]["invariant"],
            "the exact C0.2f obligation registry is complete",
        )
        self.assertEqual(
            EXPECTED_C0_2F_OBLIGATIONS,
            {f"C0.2f-{number:02d}" for number in range(1, 17)},
        )

    def test_payload_exploration_budget_fails_closed(self):
        suite = Suite()
        suite.payload_exploration_cases = PayloadProfile().max_exploration_cases
        with self.assertRaises(ModelInputError):
            suite.payload_explored()

    def test_cli_output_is_byte_deterministic(self):
        cli = support.load_cli()
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            self.assertEqual(cli.main(["--suite", "required", "--output", str(first)]), 0)
            self.assertEqual(cli.main(["--suite", "required", "--output", str(second)]), 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            decoded = json.loads(first.read_text(encoding="ascii"))
            self.assertEqual(decoded["schema"], "styx.causal-flow-falsification-report/v1")
            self.assertEqual(
                decoded["exact_base_sha"],
                "e232c2c1c4687fa09ca12594c90e0aafc67b4ebb",
            )

    def test_cli_rejects_relative_output(self):
        cli = support.load_cli()
        self.assertEqual(cli.main(["--suite", "required", "--output", "relative.json"]), 2)

    def test_suite_retains_only_global_smallest_counterexample(self):
        suite = Suite()
        long_trace = (
            first(b"c0", b"a", b"grant-a"),
            first(b"c1", b"a", b"grant-a"),
        )
        short_trace = (long_trace[0],)
        suite.check("long invariant", False, family="test", trace=long_trace)
        suite.check("short invariant", False, family="test", trace=short_trace)
        report = suite.report()
        self.assertEqual(len(report["counterexamples"]), 1)
        self.assertEqual(
            len(report["counterexamples"][0]["smallest_observed_trace"]), 1
        )
        self.assertEqual(
            report["counterexamples"][0]["invariant"], "short invariant"
        )

    def test_real_trace_outranks_an_empty_diagnostic_counterexample(self):
        suite = Suite()
        trace = (first(b"c0", b"a", b"grant-a"),)
        suite.check(
            "real trace invariant",
            False,
            family="test",
            trace=trace,
        )
        suite.check(
            "trace-free bounds diagnostic",
            False,
            family="test",
        )
        report = suite.report()
        self.assertEqual(
            report["counterexamples"][0]["invariant"], "real trace invariant"
        )
        self.assertEqual(
            len(report["counterexamples"][0]["smallest_observed_trace"]), 1
        )


if __name__ == "__main__":
    unittest.main()
