from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
CORPUS_TOOL = ROOT / "tools/causal-flow-simulator/ss0/corpus"
sys.path.insert(0, str(CORPUS_TOOL))

from replay_corpus import build_child_inputs, replay  # noqa: E402
from validate_corpus import CorpusValidationError  # noqa: E402


class ReplayTests(unittest.TestCase):
    def test_provenance_bearing_input_is_rejected_by_the_real_detector(self) -> None:
        for key in (
            "sourceWitness",
            "source_file",
            "partition",
            "caseId",
        ):
            with self.subTest(key=key):
                records = [{"input": {"operation": "profile", key: "hostile"}}]
                with self.assertRaises(CorpusValidationError) as raised:
                    build_child_inputs(records)
                self.assertEqual(raised.exception.code, "CDM-028")

        nested = [{"input": {"operation": "profile", "nested": {"id": "x"}}}]
        with self.assertRaises(CorpusValidationError) as raised:
            build_child_inputs(nested)
        self.assertEqual(raised.exception.code, "CDM-028")

    def test_blind_replay_matches_frozen_traces(self) -> None:
        node = shutil.which("node")
        self.assertIsNotNone(node)
        with tempfile.TemporaryDirectory() as name:
            report = replay(
                ROOT,
                Path(node),
                ROOT / "conformance/secure-session/ss0",
                Path(name) / "replay.json",
            )
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["caseCount"], 56)


if __name__ == "__main__":
    unittest.main()
