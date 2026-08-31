from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
CORPUS_TOOL = ROOT / "tools/causal-flow-simulator/ss0/corpus"
sys.path.insert(0, str(CORPUS_TOOL))

from run_mutations import DATA_MUTATION_IDS, run, run_data_mutations  # noqa: E402


class MutationTests(unittest.TestCase):
    def test_closed_data_mutation_registry_is_killed(self) -> None:
        rows = run_data_mutations(ROOT)
        self.assertEqual([row["id"] for row in rows], list(DATA_MUTATION_IDS))
        self.assertTrue(all(row["killed"] is True for row in rows))

    def test_source_and_data_mutation_families_pass(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            report = run(ROOT, Path(name) / "mutations.json")
        self.assertEqual(report["sourceMutationsKilled"], 44)
        self.assertEqual(report["dataMutationsKilled"], 28)
        self.assertEqual(report["coverage"], {"corpusWitness": 41, "frozenSupplemental": 3})


if __name__ == "__main__":
    unittest.main()
