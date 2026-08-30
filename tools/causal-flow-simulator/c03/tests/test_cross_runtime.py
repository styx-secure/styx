from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))

from canonical_json import dumps, load, store  # noqa: E402
from corpus_model import load_local_json  # noqa: E402
from replay_corpus import _transition_index, compute_trace  # noqa: E402
from run_cross_runtime import run  # noqa: E402


class CrossRuntimeTests(unittest.TestCase):
    def test_javascript_intrinsic_geometry_ceiling_is_exact_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "geometry-boundaries.json"
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--mode",
                    "geometry-boundaries",
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                load(output),
                {
                    "intrinsicExactLengthCeiling": "4294967163",
                    "rows": [
                        {"exactLength": "4294967162", "geometryPredicate2": "PASS"},
                        {"exactLength": "4294967163", "geometryPredicate2": "PASS"},
                        {"exactLength": "4294967164", "geometryPredicate2": "FAIL"},
                    ],
                    "schema": "styx-c03-geometry-boundaries/v1",
                },
            )

    def test_javascript_executes_all_grant_key_boundaries(self) -> None:
        valid = load(CORPUS / "valid-transcript-vectors.json")["records"]
        invalid = load(CORPUS / "invalid-transcript-vectors.json")["records"]
        by_id = {row["id"]: row for row in valid + invalid}
        self.assertEqual(
            [
                len(bytes.fromhex(by_id[identifier]["fields"]["tail"]["granteeVerificationKeyHex"]))
                for identifier in (
                    "inv-grantee-key-empty",
                    "inv-grantee-key-short",
                    "vec-control-grant",
                    "inv-resource-grantee-key",
                )
            ],
            [0, 31, 32, 33],
        )
        # The independent adapter validates every vector against its exact
        # transcript/reference/signature/stage oracle before writing this report.
        self.assertEqual(run(REPO, CORPUS)["result"], "PASS")

    def test_python_and_javascript_reports_are_identical(self) -> None:
        report = run(REPO, CORPUS)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["runtimes"], ["javascript", "python"])
        self.assertEqual(report["scenarios"], len(load(CORPUS / "state-machine-scenarios.json")["records"]))
        self.assertEqual(report["kAdmissionRecords"], 18)
        self.assertEqual(report["kAdmissionScenarios"], 3)
        self.assertEqual(report["kAdmissionHostileScenarios"], 17)
        self.assertEqual(
            report["vectors"],
            len(load(CORPUS / "valid-transcript-vectors.json")["records"])
            + len(load(CORPUS / "invalid-transcript-vectors.json")["records"]),
        )
        self.assertRegex(report["reportDigest"], r"^[0-9a-f]{64}$")

    def test_cross_report_has_closed_canonical_shape(self) -> None:
        report = run(REPO, CORPUS)
        self.assertEqual(
            set(report),
            {
                "kAdmissionHostileScenarios",
                "kAdmissionRecords",
                "kAdmissionScenarios",
                "reportDigest",
                "result",
                "runtimes",
                "scenarios",
                "vectors",
            },
        )
        encoded = dumps(report)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertNotIn(str(REPO).encode(), encoded)
        self.assertNotIn(b"elapsed", encoded)

    def test_javascript_rejects_rotated_invariant_relations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "corpus"
            shutil.copytree(CORPUS, target)
            manifest = load(target / "manifest.json")
            rows = [row for row in manifest["coverage"]["invariants"] if row["branch"] == "EXECUTABLE_WITNESS"]
            witnesses = [row["witnessScenarioIds"][0] for row in rows]
            mutations = [row["hostileMutationIds"][0] for row in rows]
            for index, row in enumerate(rows):
                row["witnessScenarioIds"] = [witnesses[(index + 7) % len(rows)]]
                row["hostileMutationIds"] = [mutations[(index + 7) % len(rows)]]
            store(target / "manifest.json", manifest)
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--repo-root",
                    str(REPO),
                    "--corpus",
                    str(target),
                    "--output",
                    str(Path(directory) / "node.json"),
                    "--mode",
                    "replay",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("invariant witness semantic mismatch", completed.stderr)

    def test_javascript_rejects_rotated_invariant_vectors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "corpus"
            shutil.copytree(CORPUS, target)
            scenarios = load(target / "state-machine-scenarios.json")
            rows = [row for row in scenarios["records"] if row.get("modelId") == "invariant"]
            vector_ids = [row["steps"][0]["inputVectorId"] for row in rows]
            for index, row in enumerate(rows):
                row["steps"][0]["inputVectorId"] = vector_ids[(index + 1) % len(rows)]
            store(target / "state-machine-scenarios.json", scenarios)
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--repo-root",
                    str(REPO),
                    "--corpus",
                    str(target),
                    "--output",
                    str(Path(directory) / "node.json"),
                    "--mode",
                    "replay",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("invariant witness-vector mismatch", completed.stderr)

    def test_javascript_rejects_collapsed_counterexample_observations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "corpus"
            shutil.copytree(CORPUS, target)
            scenarios_doc = load(target / "state-machine-scenarios.json")
            expected_doc = load(target / "expected-traces.json")
            counterexamples = [row for row in scenarios_doc["records"] if "counterexampleId" in row]
            common_vectors = [step["inputVectorId"] for step in counterexamples[0]["steps"]]
            valid = load(target / "valid-transcript-vectors.json")["records"]
            invalid_document = load(target / "invalid-transcript-vectors.json")
            invalid = invalid_document["records"]
            vectors = {
                row["id"]: row
                for row in valid + invalid + invalid_document["apExpectationOnlyRecords"]
            }
            model = load_local_json(REPO / "docs/protocol/review/styx-app-kernel-v0-review-model.json")
            transitions = _transition_index(model)
            expected_by_scenario = {row["scenarioId"]: row for row in expected_doc["records"]}
            for scenario in counterexamples:
                for step, vector_id in zip(scenario["steps"], common_vectors, strict=True):
                    step["inputVectorId"] = vector_id
                expected_by_scenario[scenario["id"]] = compute_trace(scenario, vectors, transitions)
            expected_doc["records"] = sorted(expected_by_scenario.values(), key=lambda row: row["id"])
            store(target / "state-machine-scenarios.json", scenarios_doc)
            store(target / "expected-traces.json", expected_doc)
            completed = subprocess.run(
                ["node", str(ROOT / "node_adapter.mjs"), "--repo-root", str(REPO),
                 "--corpus", str(target), "--output", str(Path(directory) / "node.json"), "--mode", "replay"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("counterexample observation collision", completed.stderr)

    def test_javascript_rejects_incompatible_transition_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "corpus"
            shutil.copytree(CORPUS, target)
            scenarios = load(target / "state-machine-scenarios.json")
            transition = next(
                row
                for row in scenarios["records"]
                if row["modelId"] == "k_admission"
                and row["steps"][0].get("expectedResultLayer") == "K_ADMISSION_ONLY"
            )
            transition["steps"][0]["evidenceLayer"] = "LOCAL_NEGATIVE"
            transition["steps"][0]["inputVectorId"] = "inv-signature"
            transition["steps"][0].pop("inputKAdmissionScenarioId")
            transition["steps"][0].pop("inputKAdmissionRecordId")
            store(target / "state-machine-scenarios.json", scenarios)
            completed = subprocess.run(
                ["node", str(ROOT / "node_adapter.mjs"), "--repo-root", str(REPO),
                 "--corpus", str(target), "--output", str(Path(directory) / "node.json"), "--mode", "replay"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("scenario evidence-layer cardinality mismatch", completed.stderr)


if __name__ == "__main__":
    unittest.main()
