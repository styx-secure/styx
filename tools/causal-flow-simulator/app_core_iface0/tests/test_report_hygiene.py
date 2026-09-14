from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from canonical_report import ReportError, canonical_bytes


class ReportHygieneTests(unittest.TestCase):
    def test_closed_report_passes(self) -> None:
        self.assertEqual(
            canonical_bytes(
                {"schema": "styx.test.v1", "verdict": "PASS"},
                allowed_fields=frozenset({"schema", "verdict"}),
            ),
            b'{"schema":"styx.test.v1","verdict":"PASS"}\n',
        )

    def test_paths_runtime_values_and_unknown_fields_fail(self) -> None:
        samples = (
            {"schema": "path=/tmp/private", "verdict": "PASS"},
            {"schema": "elapsed=1.2s", "verdict": "PASS"},
            {"schema": "2026-09-01T12:00", "verdict": "PASS"},
            {"schema": "traceback follows", "verdict": "PASS"},
            {"schema": "styx.test.v1", "verdict": "PASS", "pid": 1},
        )
        for sample in samples:
            with self.subTest(sample=sample), self.assertRaises(ReportError):
                canonical_bytes(
                    sample, allowed_fields=frozenset({"schema", "verdict"})
                )

    def test_forbidden_exact_identity_and_prefix_fail(self) -> None:
        identity = "abcdef0123456789"
        for value in (identity, f"value={identity}", "abcdef0"):
            with self.subTest(value=value), self.assertRaises(ReportError):
                canonical_bytes(
                    {"schema": value, "verdict": "PASS"},
                    allowed_fields=frozenset({"schema", "verdict"}),
                    forbidden_values=frozenset({identity, "abcdef0"}),
                )


if __name__ == "__main__":
    unittest.main()

