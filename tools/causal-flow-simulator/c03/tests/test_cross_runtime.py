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
from run_cross_runtime import run  # noqa: E402


class CrossRuntimeTests(unittest.TestCase):
    def test_python_and_javascript_reports_are_identical(self) -> None:
        report = run(REPO, CORPUS)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["runtimes"], ["javascript", "python"])
        self.assertEqual(report["scenarios"], len(load(CORPUS / "state-machine-scenarios.json")["records"]))
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
            {"reportDigest", "result", "runtimes", "scenarios", "vectors"},
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


if __name__ == "__main__":
    unittest.main()
