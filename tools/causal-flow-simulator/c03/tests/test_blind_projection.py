from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import os
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))

from build_blind_projection import (  # noqa: E402
    BlindProjectionError,
    KIT_PATHS,
    _project_record,
    _public_observation,
    build_integration,
    build_kit,
    freeze_reader,
    materialize_blind_evaluator_input,
    validate_kit,
    validate_reader_freeze,
)
from canonical_json import load, store  # noqa: E402


class BlindProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="styx-c03-blind-test-")
        self.root = Path(self.temporary.name)
        self.kit = self.root / "kit"
        self.report = build_kit(REPO, CORPUS, self.kit)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_public_kit_is_exact_and_self_verifying(self) -> None:
        self.assertEqual(self.report["records"], 43)
        self.assertEqual(self.report["sources"], 8)
        self.assertEqual(validate_kit(self.kit), self.report)
        actual = {
            path.relative_to(self.kit).as_posix()
            for path in self.kit.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual, KIT_PATHS)

    def test_projection_contains_no_oracle_and_is_complete(self) -> None:
        blind = load(self.kit / "blind-input.json")
        rendered = (self.kit / "blind-input.json").read_text("utf-8")
        for forbidden in ("expected", "localOutcome", "firstFailingStage", "scenario-", "trace-", "vec-", "inv-"):
            self.assertNotIn(forbidden, rendered)
        valid = load(CORPUS / "valid-transcript-vectors.json")["records"]
        invalid_document = load(CORPUS / "invalid-transcript-vectors.json")
        invalid = invalid_document["records"]
        self.assertEqual(len(invalid_document["apExpectationOnlyRecords"]), 3)
        projected = {record["opaqueId"]: record for record in blind["records"]}
        self.assertEqual(len(projected), 43)
        for official in valid + invalid:
            opaque, public = _project_record(official)
            self.assertEqual(projected[opaque], public)
            rebuilt = materialize_blind_evaluator_input(public)
            self.assertEqual(_public_observation(rebuilt), _public_observation(official), official["id"])

    def test_reader_output_contract_is_public_but_contains_no_oracle(self) -> None:
        readme = (self.kit / "README.md").read_text("utf-8")
        normalized_readme = " ".join(readme.split())
        self.assertIn("styx-c03-clean-room-report/v1", readme)
        self.assertIn("localOutcomePresent", readme)
        self.assertIn("geometryPredicate7", readme)
        self.assertIn("supplies field names and shape only", normalized_readme)
        self.assertNotIn("case-", readme)

    def test_validator_fails_closed_on_hidden_or_extra_input(self) -> None:
        bad = self.root / "bad"
        shutil.copytree(self.kit, bad)
        document = load(bad / "blind-input.json")
        document["records"][0]["expectedOutcome"] = "APPLIED"
        store(bad / "blind-input.json", document)
        with self.assertRaises(BlindProjectionError):
            validate_kit(bad)

    def test_reader_freeze_is_exact_and_precedes_integration(self) -> None:
        reader = self.root / "reader-root"
        reader.mkdir()
        (reader / "reader").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        os.chmod(reader / "reader", 0o755)
        (reader / "TOOLCHAIN.md").write_text("test reader\n", encoding="utf-8")
        freeze = self.root / "freeze.json"
        result = freeze_reader(reader, freeze)
        self.assertEqual(result["files"], 2)
        validate_reader_freeze(reader, freeze)
        integration = self.root / "integration"
        report = build_integration(REPO, CORPUS, self.kit, freeze, integration)
        self.assertEqual(report["records"], 43)
        mapping = load(integration / "integration-map.json")
        self.assertEqual(len(mapping["records"]), 43)
        (reader / "reader").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        with self.assertRaises(BlindProjectionError):
            validate_reader_freeze(reader, freeze)


if __name__ == "__main__":
    unittest.main()
