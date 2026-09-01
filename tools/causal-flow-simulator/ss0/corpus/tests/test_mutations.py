from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
CORPUS_TOOL = ROOT / "tools/causal-flow-simulator/ss0/corpus"
sys.path.insert(0, str(CORPUS_TOOL))

from run_mutations import (  # noqa: E402
    DATA_MUTATION_IDS,
    DATA_MUTATIONS,
    DETECTOR_OWNER,
    run,
    run_data_mutations,
)


EXPECTED_DATA_MUTATIONS = (
    ("CDM-001", "missing manifest"),
    ("CDM-002", "missing non-manifest corpus file"),
    ("CDM-003", "unlisted seventh regular file"),
    ("CDM-004", "symlink replacing a corpus file"),
    ("CDM-005", "reordered generatedFiles relation"),
    ("CDM-006", "wrong generated-file digest"),
    ("CDM-007", "wrong manifestPayloadSha256"),
    ("CDM-008", "duplicate JSON object key"),
    ("CDM-009", "unknown top-level field"),
    ("CDM-010", "missing required top-level field"),
    ("CDM-011", "unknown schema identifier"),
    ("CDM-012", "non-canonical object-key order"),
    ("CDM-013", "absent final LF"),
    ("CDM-014", "UTF-8 BOM or invalid UTF-8"),
    ("CDM-015", "floating-point value outside frozen supplemental evidence"),
    ("CDM-016", "duplicate case identifier"),
    ("CDM-017", "missing source witness"),
    ("CDM-018", "extra source witness"),
    ("CDM-019", "witness moved to the wrong partition"),
    ("CDM-020", "trace/input identifier mismatch"),
    ("CDM-021", "expected result or disposition injected into reader input"),
    ("CDM-022", "assertion, detector or source-mutant data injected into reader input"),
    ("CDM-023", "synthetic false or upstreamBytes other than none"),
    ("CDM-024", "missing or extra mutation record"),
    ("CDM-025", "wrong mutation coverageClass or detector relation"),
    ("CDM-026", "changed owner/atom/relation/disposition count"),
    ("CDM-027", "runtime or repository provenance injected into a canonical report"),
    ("CDM-028", "input stream exposes source filename or partition membership"),
)


class MutationTests(unittest.TestCase):
    def test_data_mutation_registry_is_literal_and_exact(self) -> None:
        self.assertEqual(DATA_MUTATIONS, EXPECTED_DATA_MUTATIONS)
        self.assertEqual(len({identity for identity, _ in DATA_MUTATIONS}), 28)
        self.assertEqual(len({target for _, target in DATA_MUTATIONS}), 28)
        self.assertEqual(
            DETECTOR_OWNER,
            {
                **{
                    identity: "validate_corpus.py"
                    for identity in DATA_MUTATION_IDS[:26]
                },
                "CDM-027": "run_mutations.py",
                "CDM-028": "replay_corpus.py",
            },
        )

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
