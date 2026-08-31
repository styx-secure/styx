from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
CORPUS_TOOL = ROOT / "tools/causal-flow-simulator/ss0/corpus"
sys.path.insert(0, str(CORPUS_TOOL))

from canonical_json import canonical_bytes  # noqa: E402
from generate_corpus import CORPUS_PATHS, EXPECTED_COUNTS, build_files  # noqa: E402


class GenerationTests(unittest.TestCase):
    def test_generated_bytes_match_checkout(self) -> None:
        expected = build_files(ROOT)
        self.assertEqual(list(expected), list(CORPUS_PATHS))
        for name, data in expected.items():
            self.assertEqual((ROOT / name).read_bytes(), data, name)

    def test_counts_are_frozen(self) -> None:
        self.assertEqual(EXPECTED_COUNTS["sourceWitnesses"], 56)
        self.assertEqual(EXPECTED_COUNTS["corpusDataMutations"], 28)
        self.assertEqual(EXPECTED_COUNTS["frozenSupplementalMutations"], 3)

    def test_non_ascii_fixture_digest_is_literal_utf8(self) -> None:
        encoded = canonical_bytes({"١": "٢"})
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            "07ae35fe9aa6f0a77170e1ada00a1488f5d1682bb8882fb2e7cd06beb51d737c",
        )
        self.assertIn("١".encode(), encoded)


if __name__ == "__main__":
    unittest.main()
