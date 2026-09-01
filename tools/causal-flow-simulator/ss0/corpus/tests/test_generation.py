from __future__ import annotations

import copy
import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
CORPUS_TOOL = ROOT / "tools/causal-flow-simulator/ss0/corpus"
sys.path.insert(0, str(CORPUS_TOOL))

from canonical_json import canonical_bytes, loads_unique  # noqa: E402
from generate_corpus import (  # noqa: E402
    CORPUS_PATHS,
    EXPECTED_COUNTS,
    SUPPLEMENTAL_MUTANTS,
    _build_mutation_rows,
    build_files,
)


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

    def test_mutation_coverage_classes_are_structural(self) -> None:
        inventory = loads_unique(
            (ROOT / "tools/causal-flow-simulator/ss0/source-inventory.json").read_bytes()
        )
        mutants = loads_unique(
            (ROOT / "tools/causal-flow-simulator/ss0/source-mutants.json").read_bytes()
        )
        rows = _build_mutation_rows(inventory, mutants)
        witness_ids = {row["id"] for row in inventory["witnesses"]}
        for row in rows:
            if row["id"] in SUPPLEMENTAL_MUTANTS:
                self.assertEqual(row["coverageClass"], "FROZEN_SUPPLEMENTAL")
                self.assertNotIn(row["detector"], witness_ids)
            else:
                self.assertEqual(row["coverageClass"], "CORPUS_WITNESS")
                self.assertIn(row["detector"], witness_ids)

        broken = copy.deepcopy(mutants)
        corpus_mutant = next(
            row for row in broken["mutants"] if row["id"] not in SUPPLEMENTAL_MUTANTS
        )
        corpus_mutant["detector"] = SUPPLEMENTAL_MUTANTS[
            "M-X-TOP-LEVEL-UNKNOWN-FIELD"
        ]
        with self.assertRaisesRegex(ValueError, "corpus witness detector unavailable"):
            _build_mutation_rows(inventory, broken)


if __name__ == "__main__":
    unittest.main()
