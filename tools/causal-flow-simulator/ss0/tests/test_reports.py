from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[2]
sys.path.insert(0, str(PACKAGE))

from canonical_report import canonical_bytes, store  # noqa: E402
from run_probe import build_report  # noqa: E402


class ReportTests(unittest.TestCase):
    def test_probe_is_byte_deterministic(self) -> None:
        first = canonical_bytes(build_report(ROOT))
        second = canonical_bytes(build_report(ROOT))
        self.assertEqual(first, second)

    def test_runtime_provenance_and_secret_are_rejected(self) -> None:
        for value in ("path=/tmp/ss0", r"path=C:\\ss0", "elapsed=1.2s", "secret=bytes"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_bytes({"schema": "styx.ss0.test.v1", "value": value})

    def test_atomic_store_leaves_no_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            store({"result": "PASS", "schema": "styx.ss0.test.v1"}, output)
            self.assertTrue(output.is_file())
            self.assertEqual([], list(Path(directory).glob(".*.tmp")))


if __name__ == "__main__":
    unittest.main()
