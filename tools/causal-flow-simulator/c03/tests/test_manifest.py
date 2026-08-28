from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))

from canonical_json import dumps, load, store  # noqa: E402
import generate_corpus  # noqa: E402
from corpus_model import semantic_observation_digest  # noqa: E402
from validate_corpus import SCHEMAS, ValidationError, _walk_hygiene, validate  # noqa: E402


class ManifestTests(unittest.TestCase):
    def test_tracked_manifest_and_corpus_validate(self) -> None:
        report = validate(REPO, CORPUS)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["mutations"], 513)

    def test_every_v1_corpus_schema_identifier_fails_closed(self) -> None:
        for name in sorted(SCHEMAS):
            with self.subTest(name=name):
                temporary, target = self._mutated_corpus()
                self.addCleanup(temporary.cleanup)
                document = load(target / name)
                document["schema"] = document["schema"].replace("/v2", "/v1")
                store(target / name, document)
                with self.assertRaisesRegex(ValidationError, "schema mismatch"):
                    validate(REPO, target)

    def test_v1_manifest_format_version_fails_closed(self) -> None:
        temporary, target = self._mutated_corpus()
        self.addCleanup(temporary.cleanup)
        manifest = load(target / "manifest.json")
        manifest["corpusFormatVersion"] = 1
        store(target / "manifest.json", manifest)
        with self.assertRaisesRegex(ValidationError, "corpus format version mismatch"):
            validate(REPO, target)

    def test_o10_source_rows_have_exact_explicit_witnesses(self) -> None:
        rows = load(CORPUS / "manifest.json")["coverage"]["o10"]["sourceRows"]
        self.assertEqual(len(rows), 102)
        produced = [row for row in rows if row["disposition"] == "PRODUCED"]
        self.assertEqual(len(produced), 25)
        self.assertTrue(all(row["witnesses"] for row in produced))
        self.assertTrue(
            all(not row["witnesses"] for row in rows if row["disposition"] != "PRODUCED")
        )
        chunk_count = next(
            row for row in produced
            if row["rowId"] == "O08:CHUNKS_PER_CONTENT:S3_KERNEL_STRUCTURAL"
        )
        self.assertEqual(
            chunk_count["witnesses"],
            [{
                "inputId": "inv-resource-chunk-count",
                "jointSourceRowIds": [
                    "O08:CHUNKS_PER_CONTENT:S3_KERNEL_STRUCTURAL",
                    "O08:CONTENT_EXACT_OCTETS:S3_KERNEL_STRUCTURAL",
                ],
                "scenarioId": "scenario-vector-inv-resource-chunk-count",
            }],
        )
        unresolved = [
            row
            for row in produced
            if row["primary"] == "UNRESOLVABLE_CREDENTIAL"
        ]
        self.assertEqual(len(unresolved), 2)
        self.assertTrue(
            all(
                row["witnesses"][0]["scenarioId"]
                == "k-hostile-revoke-unknown-target"
                and row["witnesses"][0]["inputKAdmissionRecordId"]
                == "k-hostile-revoke-unknown-target"
                for row in unresolved
            )
        )

    def test_generic_same_outcome_cannot_replace_o10_row_witness(self) -> None:
        temporary, target = self._mutated_corpus()
        self.addCleanup(temporary.cleanup)
        manifest = load(target / "manifest.json")
        row = next(
            item for item in manifest["coverage"]["o10"]["sourceRows"]
            if item["rowId"] == "O08:CHUNK_OCTETS:S3_KERNEL_STRUCTURAL"
        )
        row["witnesses"][0]["inputId"] = "inv-resource-sequence"
        row["witnesses"][0]["scenarioId"] = "scenario-vector-inv-resource-sequence"
        store(target / "manifest.json", manifest)
        with self.assertRaisesRegex(ValidationError, "O-10 source-row partition mismatch"):
            validate(REPO, target)

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

    def test_rotated_invariant_witness_map_fails_semantically(self) -> None:
        witness_ids = list(generate_corpus.INVARIANT_WITNESS_VECTORS.values())
        rotated = {
            identifier: witness_ids[(index + 1) % len(witness_ids)]
            for index, identifier in enumerate(generate_corpus.INVARIANT_WITNESS_VECTORS)
        }
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            generate_corpus.INVARIANT_WITNESS_VECTORS, rotated, clear=True
        ):
            with self.assertRaisesRegex(ValueError, "curated invariant witness-vector relation drifted"):
                generate_corpus.generate(REPO, Path(directory) / "generated")

    def test_collapsed_counterexample_programs_fail_before_generation(self) -> None:
        collapsed = {
            identifier: ["vec-ordinary-none", "inv-fork", "vec-secondary-context-author"]
            for identifier in generate_corpus.COUNTEREXAMPLE_VECTOR_PROGRAMS
        }
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            generate_corpus.COUNTEREXAMPLE_VECTOR_PROGRAMS, collapsed, clear=True
        ):
            with self.assertRaisesRegex(ValueError, "counterexample executable program collision"):
                generate_corpus.generate(REPO, Path(directory) / "generated")

    def test_semantic_observation_excludes_scenario_identity(self) -> None:
        traces = load(CORPUS / "expected-traces.json")["records"]
        steps = traces[0]["steps"]
        first = {"scenarioId": "scenario-a", "steps": steps}
        second = {"scenarioId": "scenario-b", "steps": steps}
        self.assertNotEqual(sha256(dumps(first)).hexdigest(), sha256(dumps(second)).hexdigest())
        self.assertEqual(
            semantic_observation_digest(first["steps"]),
            semantic_observation_digest(second["steps"]),
        )

    def test_every_vector_is_executed_and_counterexamples_are_distinct(self) -> None:
        valid = load(CORPUS / "valid-transcript-vectors.json")["records"]
        invalid_document = load(CORPUS / "invalid-transcript-vectors.json")
        invalid = invalid_document["records"]
        ap_expectations = invalid_document["apExpectationOnlyRecords"]
        scenarios = load(CORPUS / "state-machine-scenarios.json")["records"]
        traces = load(CORPUS / "expected-traces.json")["records"]
        used = {
            step["inputVectorId"]
            for scenario in scenarios
            for step in scenario["steps"]
            if "inputVectorId" in step
        }
        self.assertEqual(used, {row["id"] for row in valid + invalid + ap_expectations})
        counterexamples = [row for row in scenarios if "counterexampleId" in row]
        self.assertEqual({len(row["steps"]) for row in counterexamples}, {3})
        observations = {
            row["semanticObservationDigest"]
            for row in traces
            if row["scenarioId"].startswith("scenario-counterexample-")
        }
        self.assertEqual(len(observations), len(counterexamples))
        self.assertFalse(any("conditions" in row for row in invalid))


if __name__ == "__main__":
    unittest.main()
