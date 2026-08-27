from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools/causal-flow-simulator/o10"))

from canonical_report import ReportError, canonical_bytes  # noqa: E402


class CanonicalReportTests(unittest.TestCase):
    def test_provenance_and_unknown_fields_fail_closed(self) -> None:
        with self.assertRaises(ReportError):
            canonical_bytes({"value": "provenance=/tmp/private"}, allowed_fields=frozenset({"value"}))
        with self.assertRaises(ReportError):
            canonical_bytes({"value": "ok", "extra": 1}, allowed_fields=frozenset({"value"}))

    def test_repository_relative_protocol_path_is_allowed(self) -> None:
        self.assertTrue(
            canonical_bytes(
                {"value": "docs/protocol/root-authority.md"},
                allowed_fields=frozenset({"value"}),
            )
        )


if __name__ == "__main__":
    unittest.main()
