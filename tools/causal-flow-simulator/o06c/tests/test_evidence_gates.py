from __future__ import annotations

import json
from pathlib import Path
import tempfile
import sys
import unittest


O06C_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = O06C_ROOT.parents[2]
sys.path.insert(0, str(O06C_ROOT))

from common import canonical_bytes  # noqa: E402
from historical_evidence_gate import (  # noqa: E402
    HISTORICAL_REGISTRY,
    HistoricalGateError,
    build_report as build_historical,
    validate_registry,
)
from verify_frozen_sections import (  # noqa: E402
    BASE_SHA,
    FrozenSectionError,
    build_report as build_frozen,
    digest_status,
    extract_raw_section,
)


class FrozenSectionTests(unittest.TestCase):
    def test_exact_baseline_passes_and_is_canonical(self) -> None:
        first, first_passed = build_frozen(REPO_ROOT, "HEAD", BASE_SHA)
        second, second_passed = build_frozen(REPO_ROOT, "HEAD", BASE_SHA)
        self.assertTrue(first_passed and second_passed)
        self.assertEqual(first, second)
        self.assertEqual(first["verdict"], "PASS")
        self.assertEqual(len(first["sections"]), 6)
        self.assertEqual(first["candidate_identity_location"], "immutable_pr_evidence")
        self.assertNotIn("candidate_commit", first)
        self.assertNotIn("candidate_tree", first)
        self.assertEqual(json.loads(canonical_bytes(first)), first)

    def test_extractor_rejects_missing_successor_heading(self) -> None:
        with self.assertRaisesRegex(FrozenSectionError, "no following"):
            extract_raw_section(b"## 4. Frozen\nbody\n", b"## 4.")

    def test_extractor_rejects_heading_inside_fence(self) -> None:
        document = b"## 4. Frozen\n```text\n## forged\n```\n## 5. Next\n"
        with self.assertRaisesRegex(FrozenSectionError, "inside fence"):
            extract_raw_section(document, b"## 4.")

    def test_digest_mismatch_never_passes(self) -> None:
        self.assertEqual(digest_status("00" * 32, "00" * 32), "PASS")
        self.assertEqual(digest_status("00" * 32, "01" * 32), "DIGEST_MISMATCH")


class HistoricalEvidenceTests(unittest.TestCase):
    def test_registry_rejects_an_eighth_entry(self) -> None:
        with self.assertRaisesRegex(HistoricalGateError, "exactly seven"):
            validate_registry(HISTORICAL_REGISTRY + (HISTORICAL_REGISTRY[0],))

    def test_closed_registry_reproduces_from_two_distinct_roots(self) -> None:
        frozen, passed = build_frozen(REPO_ROOT, "HEAD", BASE_SHA)
        self.assertTrue(passed)
        with tempfile.TemporaryDirectory() as first_parent, tempfile.TemporaryDirectory() as second_parent:
            first, first_passed = build_historical(
                REPO_ROOT, Path(first_parent) / "stage"
            )
            second, second_passed = build_historical(
                REPO_ROOT, Path(second_parent) / "different-stage"
            )
        self.assertTrue(first_passed and second_passed)
        self.assertEqual(first, second)
        self.assertEqual(first["registry_size"], 7)
        self.assertEqual(first["verdict"], "PASS")
        self.assertEqual(json.loads(canonical_bytes(first)), first)
        self.assertEqual(frozen["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
