from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))

from canonical_json import load  # noqa: E402
from replay_corpus import replay  # noqa: E402


class ReplayTests(unittest.TestCase):
    def test_all_vectors_and_scenarios_replay(self) -> None:
        report = replay(REPO, CORPUS)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual((report["validVectors"], report["invalidVectors"], report["scenarios"]), (11, 16, 46))
        self.assertRegex(report["corpusDigest"], r"^[0-9a-f]{64}$")
        self.assertRegex(report["traceDigest"], r"^[0-9a-f]{64}$")

    def test_expected_traces_are_closed_and_effect_free(self) -> None:
        traces = load(CORPUS / "expected-traces.json")["records"]
        scenarios = load(CORPUS / "state-machine-scenarios.json")["records"]
        self.assertEqual(
            {trace["scenarioId"] for trace in traces},
            {scenario["id"] for scenario in scenarios},
        )
        step_count = 0
        for trace in traces:
            self.assertEqual(trace["id"], f"trace-{trace['scenarioId']}")
            self.assertTrue(trace["steps"])
            for position, step in enumerate(trace["steps"]):
                self.assertEqual(step["step"], position)
                self.assertEqual(step["externalEffects"], [])
                self.assertRegex(step["preStateDigest"], r"^[0-9a-f]{64}$")
                self.assertRegex(step["postStateDigest"], r"^[0-9a-f]{64}$")
                step_count += 1
        self.assertEqual(step_count, 46)


if __name__ == "__main__":
    unittest.main()
