from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
CORPUS_TOOL = ROOT / "tools/causal-flow-simulator/ss0/corpus"
sys.path.insert(0, str(CORPUS_TOOL))

from validate_corpus import validate_corpus  # noqa: E402


class ValidationTests(unittest.TestCase):
    def test_repository_corpus_is_valid(self) -> None:
        report = validate_corpus(ROOT, ROOT / "conformance/secure-session/ss0")
        self.assertEqual(report, {"cases": 56, "mutations": 44, "result": "PASS"})


if __name__ == "__main__":
    unittest.main()
