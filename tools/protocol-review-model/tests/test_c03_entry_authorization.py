"""Fail-closed tests for the exact C0.3 corpus-entry authorization."""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import MODEL_PATH, REPO_ROOT, SCHEMA_PATH, load_validator


validator = load_validator()


class C03EntryAuthorizationTests(unittest.TestCase):
    EXPECTED_C03_BLOCKS = [
        "demo",
        "implementation_alignment",
        "product",
        "sensitive_use",
    ]

    @classmethod
    def setUpClass(cls) -> None:
        cls.model = validator.load_json_unique(MODEL_PATH)
        cls.schema = validator.load_json_unique(SCHEMA_PATH)

    @staticmethod
    def _c03(model: dict) -> dict:
        return next(item for item in model["blockers"] if item["id"] == "C0.3")

    def _codes(self, model: dict) -> set[str]:
        return {
            finding.code
            for finding in validator.validate(model, self.schema, REPO_ROOT)
        }

    def test_exact_entry_state_authorizes_only_corpus_construction(self) -> None:
        self.assertEqual([], validator.validate(self.model, self.schema, REPO_ROOT))
        self.assertEqual(self.EXPECTED_C03_BLOCKS, self._c03(self.model)["blocks"])
        self.assertNotIn("corpus", self._c03(self.model)["blocks"])
        self.assertEqual(
            {"corpus"}, validator.AUTHORIZED_UNBLOCKED_CAPABILITIES
        )
        invariant = next(
            item
            for item in self.model["invariants"]
            if item["id"] == "INV_C0_3_NO_GO"
        )
        self.assertEqual(
            "The separately contracted transcript-only C0.3 corpus is constructed "
            "and validated; implementation alignment, demo, product "
            "implementation and sensitive use remain unauthorized while their "
            "declared blockers remain open.",
            invariant["statement"],
        )

    def test_corpus_completion_gate_executes_both_runtimes_and_mutations(self) -> None:
        self.assertEqual([], validator._validate_c03_corpus_gate(REPO_ROOT))

    def test_corpus_completion_gate_rejects_missing_evidence_classes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "repo"
            subprocess.run(
                ["git", "clone", "--quiet", "--shared", str(REPO_ROOT), str(clone)],
                check=True,
            )
            corpus = clone / "conformance/application-protocol/c03"
            tools = clone / "tools/causal-flow-simulator/c03"
            cases = (
                ("generated-file", corpus / "expected-traces.json", None),
                (
                    "generated-digest",
                    corpus / "valid-transcript-vectors.json",
                    lambda payload: payload + b" ",
                ),
                (
                    "coverage-row",
                    corpus / "manifest.json",
                    self._remove_first_invariant,
                ),
                (
                    "manifest-record-count",
                    corpus / "manifest.json",
                    self._increment_first_record_count,
                ),
                ("cross-runtime-result", tools / "node_adapter.mjs", None),
                ("mutation-gate", tools / "run_mutations.py", None),
            )
            for label, path, transform in cases:
                with self.subTest(label=label):
                    original = path.read_bytes()
                    try:
                        if transform is None:
                            path.unlink()
                        else:
                            path.write_bytes(transform(original))
                        findings = validator._validate_c03_corpus_gate(clone)
                        self.assertEqual(
                            {"C03_CORPUS_GATE_MISSING"},
                            {finding.code for finding in findings},
                        )
                    finally:
                        path.write_bytes(original)

    @staticmethod
    def _remove_first_invariant(payload: bytes) -> bytes:
        document = json.loads(payload)
        del document["coverage"]["invariants"][0]
        return (
            json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")

    @staticmethod
    def _increment_first_record_count(payload: bytes) -> bytes:
        document = json.loads(payload)
        document["files"][0]["recordCount"] += 1
        return (
            json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")

    def test_restoring_stale_corpus_gate_fails_closed(self) -> None:
        model = copy.deepcopy(self.model)
        self._c03(model)["blocks"].insert(0, "corpus")
        self.assertIn("BLOCKER_EDGE_MISMATCH", self._codes(model))

    def test_removing_any_retained_gate_fails_closed(self) -> None:
        for retained in self.EXPECTED_C03_BLOCKS:
            with self.subTest(retained=retained):
                model = copy.deepcopy(self.model)
                self._c03(model)["blocks"].remove(retained)
                self.assertIn("BLOCKER_EDGE_MISMATCH", self._codes(model))

    def test_adding_an_unratified_capability_gate_fails_closed(self) -> None:
        model = copy.deepcopy(self.model)
        self._c03(model)["blocks"].append("time_bearing_profile")
        self.assertIn("BLOCKER_EDGE_MISMATCH", self._codes(model))

    def test_other_blocker_edge_drift_remains_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        o07 = next(item for item in model["blockers"] if item["id"] == "O-07")
        o07["blocks"].append("product")
        self.assertIn("BLOCKER_EDGE_MISMATCH", self._codes(model))


if __name__ == "__main__":
    unittest.main()
