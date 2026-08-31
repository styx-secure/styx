from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
CORPUS_TOOL = ROOT / "tools/causal-flow-simulator/ss0/corpus"
sys.path.insert(0, str(CORPUS_TOOL))

from replay_corpus import replay  # noqa: E402


class ReplayTests(unittest.TestCase):
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
