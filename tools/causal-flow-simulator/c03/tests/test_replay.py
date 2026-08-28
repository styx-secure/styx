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
        self.assertEqual(report["validVectors"], len(load(CORPUS / "valid-transcript-vectors.json")["records"]))
        self.assertEqual(report["invalidVectors"], len(load(CORPUS / "invalid-transcript-vectors.json")["records"]))
        self.assertEqual(report["scenarios"], len(load(CORPUS / "state-machine-scenarios.json")["records"]))
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
        self.assertEqual(step_count, sum(len(scenario["steps"]) for scenario in scenarios))
        self.assertGreater(step_count, len(scenarios))

    def test_vectors_cover_identity_parent_and_selected_resource_boundaries(self) -> None:
        valid = load(CORPUS / "valid-transcript-vectors.json")["records"]
        invalid = load(CORPUS / "invalid-transcript-vectors.json")["records"]
        events = [record for record in valid if record["kind"] == "APPLICATION_EVENT"]
        self.assertGreaterEqual(len({record["fields"]["contextIdentifierHex"] for record in events}), 2)
        self.assertGreaterEqual(len({record["fields"]["credentialIdentifierHex"] for record in events}), 2)
        self.assertGreaterEqual(len({record["binding"]["verificationKeyHex"] for record in events}), 2)
        self.assertTrue({0, 1, 2} <= {len(record["fields"]["causalParents"]) for record in events})

        selected = next(record for record in valid if record["id"] == "vec-selected-resource-boundaries")
        self.assertEqual(selected["fields"]["authorSequence"], 4095)
        self.assertEqual(len(selected["fields"]["causalParents"]), 8)
        self.assertEqual(len(bytes.fromhex(selected["fields"]["transitionBlockHex"])), 4096)
        self.assertEqual(selected["fields"]["content"]["exactLength"], 262144)
        self.assertEqual(selected["fields"]["content"]["geometry"]["chunkCount"], 64)
        self.assertEqual(
            next(record for record in valid if record["id"] == "vec-selected-chunk-octets")["fields"]["content"]["geometry"]["chunkSize"],
            16384,
        )
        self.assertEqual(
            len(bytes.fromhex(next(record for record in valid if record["id"] == "vec-selected-genesis-policy")["fields"]["initialAuthorityPolicyHex"])),
            4096,
        )
        self.assertTrue(
            {
                "inv-parent-order",
                "inv-profile-substitution",
                "inv-noncanonical-integer",
                "inv-resource-parent-count",
                "inv-resource-sequence",
                "inv-resource-transition-block",
                "inv-resource-framing-object",
                "inv-resource-chunk-size",
                "inv-resource-chunk-count",
                "inv-resource-content-length",
                "inv-resource-genesis-policy",
            }
            <= {record["id"] for record in invalid}
        )


if __name__ == "__main__":
    unittest.main()
