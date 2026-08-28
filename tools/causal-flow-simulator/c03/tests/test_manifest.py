from __future__ import annotations

from pathlib import Path
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))

from canonical_json import load, store  # noqa: E402
from validate_corpus import ValidationError, _walk_hygiene, validate  # noqa: E402


class ManifestTests(unittest.TestCase):
    def test_tracked_manifest_and_corpus_validate(self) -> None:
        report = validate(REPO, CORPUS)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["mutations"], 476)

    def test_hygiene_rejects_embedded_absolute_paths_but_not_reuse_label(self) -> None:
        for value in ("path=/", "provenance=/tmp/styx", "path=C:\\review", r"path=\\host\share"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                _walk_hygiene(value)
        _walk_hygiene("6.2.0 / REUSE-3.3")

    def _mutated_corpus(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        target = Path(temporary.name) / "corpus"
        shutil.copytree(CORPUS, target)
        return temporary, target

    def test_nested_seventh_file_fails_closed(self) -> None:
        temporary, target = self._mutated_corpus()
        self.addCleanup(temporary.cleanup)
        nested = target / "nested"
        nested.mkdir()
        (nested / "seventh.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "regular top-level files"):
            validate(REPO, target)

    def test_unknown_o08_dimension_fails_closed(self) -> None:
        temporary, target = self._mutated_corpus()
        self.addCleanup(temporary.cleanup)
        manifest = load(target / "manifest.json")
        manifest["coverage"]["o08"]["participatingDimensions"][0] = "UNKNOWN_DIMENSION"
        store(target / "manifest.json", manifest)
        with self.assertRaisesRegex(ValidationError, "O-08 coverage mismatch"):
            validate(REPO, target)

    def test_empty_invariant_witness_fails_closed(self) -> None:
        temporary, target = self._mutated_corpus()
        self.addCleanup(temporary.cleanup)
        manifest = load(target / "manifest.json")
        row = next(item for item in manifest["coverage"]["invariants"] if item["branch"] == "EXECUTABLE_WITNESS")
        row["witnessScenarioIds"] = []
        store(target / "manifest.json", manifest)
        with self.assertRaisesRegex(ValidationError, "empty invariant witness"):
            validate(REPO, target)

    def test_uncited_non_claim_fails_closed(self) -> None:
        temporary, target = self._mutated_corpus()
        self.addCleanup(temporary.cleanup)
        manifest = load(target / "manifest.json")
        row = next(item for item in manifest["coverage"]["invariants"] if item["branch"] == "NON_EXECUTABLE_NON_CLAIM")
        row["citations"] = []
        store(target / "manifest.json", manifest)
        with self.assertRaisesRegex(ValidationError, "non-claim citation"):
            validate(REPO, target)

    def test_executable_invariant_cannot_be_reclassified_as_non_claim(self) -> None:
        temporary, target = self._mutated_corpus()
        self.addCleanup(temporary.cleanup)
        manifest = load(target / "manifest.json")
        cited = next(item for item in manifest["coverage"]["invariants"] if item["branch"] == "NON_EXECUTABLE_NON_CLAIM")
        row = next(item for item in manifest["coverage"]["invariants"] if item["branch"] == "EXECUTABLE_WITNESS")
        identifier = row["id"]
        row.clear()
        row.update(
            {
                "branch": "NON_EXECUTABLE_NON_CLAIM",
                "citations": cited["citations"],
                "id": identifier,
                "reason": "GOVERNANCE_OR_AUTHORIZATION_STATEMENT",
            }
        )
        store(target / "manifest.json", manifest)
        with self.assertRaisesRegex(ValidationError, "branch assignment mismatch"):
            validate(REPO, target)


if __name__ == "__main__":
    unittest.main()
