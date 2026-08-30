from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))

from build_blind_projection import (  # noqa: E402
    BlindProjectionError,
    build_integration,
    build_kit,
    freeze_reader,
)
from canonical_json import load, store  # noqa: E402
from compare_clean_room import (  # noqa: E402
    CleanRoomComparisonError,
    THIRD_REPORT_SCHEMA,
    compare,
)
from replay_corpus import replay  # noqa: E402


class CleanRoomComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="styx-c03-compare-test-")
        cls.root = Path(cls.temporary.name)
        cls.kit = cls.root / "kit"
        build_kit(REPO, CORPUS, cls.kit)
        cls.reader = cls.root / "reader-root"
        cls.reader.mkdir()
        (cls.reader / "reader").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        os.chmod(cls.reader / "reader", 0o755)
        (cls.reader / "TOOLCHAIN.md").write_text("isolated test reader\n", encoding="utf-8")
        cls.freeze = cls.root / "freeze.json"
        freeze_reader(cls.reader, cls.freeze)
        cls.integration = cls.root / "integration"
        build_integration(REPO, CORPUS, cls.kit, cls.freeze, cls.integration)
        cls.python = cls.root / "python.json"
        store(cls.python, replay(REPO, CORPUS))
        cls.node = cls.root / "node.json"
        completed = subprocess.run(
            [
                "node", str(ROOT / "node_adapter.mjs"), "--repo-root", str(REPO),
                "--corpus", str(CORPUS), "--output", str(cls.node),
            ],
            cwd=REPO,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr)
        integration = load(cls.integration / "integration-map.json")
        cls.third = cls.root / "third.json"
        store(
            cls.third,
            {
                "admissionGraphs": [
                    {
                        "observations": row["expectedObservations"],
                        "opaqueGraphId": row["opaqueGraphId"],
                    }
                    for row in integration["admissionGraphs"]
                ],
                "observations": [
                    {"opaqueId": row["opaqueId"], **row["expectedPublicObservation"]}
                    for row in integration["records"]
                ],
                "schema": THIRD_REPORT_SCHEMA,
            },
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_exact_three_runtime_agreement(self) -> None:
        report = compare(
            self.kit, self.integration, self.python, self.node,
            self.third, self.freeze, self.reader,
        )
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["records"], 53)
        self.assertEqual(report["admissionGraphs"], 20)
        self.assertGreater(report["connectedAdmissions"], 0)
        self.assertGreater(report["connectedRejections"], 0)
        self.assertEqual(report["transcriptConformanceChecks"], 68)
        self.assertEqual(report["invalidClassifications"], 36)
        self.assertEqual(report["runtimes"], ["javascript", "python", "third-clean-room"])

    def test_missing_or_extra_reader_output_fails_closed(self) -> None:
        document = load(self.third)
        document["observations"].pop()
        path = self.root / "third-missing.json"
        store(path, document)
        with self.assertRaises(CleanRoomComparisonError):
            compare(self.kit, self.integration, self.python, self.node, path, self.freeze, self.reader)

    def test_record_mismatch_does_not_hide_graph_mismatch(self) -> None:
        document = load(self.third)
        document["observations"][0]["signatureVerification"] = "REJECTED"
        document["admissionGraphs"][0]["observations"][0]["stage"] = "EVENT_LOCAL"
        path = self.root / "third-two-mismatches.json"
        store(path, document)
        report = compare(
            self.kit, self.integration, self.python, self.node,
            path, self.freeze, self.reader,
        )
        self.assertEqual(report["result"], "FAIL")
        kinds = {row["kind"] for row in report["mismatches"]}
        self.assertIn("THIRD_RECORD", kinds)
        self.assertIn("THIRD_GRAPH", kinds)

    def test_reader_byte_drift_fails_closed(self) -> None:
        original = (self.reader / "TOOLCHAIN.md").read_bytes()
        try:
            (self.reader / "TOOLCHAIN.md").write_bytes(original + b"drift\n")
            with self.assertRaises(BlindProjectionError):
                compare(self.kit, self.integration, self.python, self.node, self.third, self.freeze, self.reader)
        finally:
            (self.reader / "TOOLCHAIN.md").write_bytes(original)


if __name__ == "__main__":
    unittest.main()
