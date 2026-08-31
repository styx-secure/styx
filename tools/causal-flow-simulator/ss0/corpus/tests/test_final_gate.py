from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
CORPUS_TOOL = ROOT / "tools/causal-flow-simulator/ss0/corpus"
sys.path.insert(0, str(CORPUS_TOOL))

from final_gate import (  # noqa: E402
    CANONICAL_REPORTS,
    FinalGateError,
    _compare_reports,
    _require_external_root,
    _resolve_plain_directory,
)


class FinalGateTests(unittest.TestCase):
    def test_entrypoint_accepts_the_contract_cli(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(CORPUS_TOOL / "final_gate.py"), "--help"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(0, completed.returncode, completed.stderr.decode())
        for option in (
            "--checkout-a", "--checkout-b", "--evidence-a", "--evidence-b"
        ):
            self.assertIn(option, completed.stdout.decode())

    def test_four_report_sources_must_be_distinct_and_identical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            roots = [Path(directory) / f"root-{index}" for index in range(4)]
            for root in roots:
                root.mkdir()
                for name in CANONICAL_REPORTS:
                    (root / name).write_bytes((name + "\n").encode("ascii"))
            rows = _compare_reports(*roots)
            self.assertEqual(len(CANONICAL_REPORTS), len(rows))
            self.assertEqual(
                hashlib.sha256(b"replay.json\n").hexdigest(),
                next(row["sha256"] for row in rows if row["name"] == "replay.json"),
            )
            (roots[3] / "replay.json").write_bytes(b"different\n")
            with self.assertRaises(FinalGateError):
                _compare_reports(*roots)
            with self.assertRaises(FinalGateError):
                _compare_reports(roots[0], roots[0], roots[1], roots[2])

    def test_external_roots_cannot_overlap_or_use_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            external = root / "external"
            external.mkdir()
            _require_external_root(external, (checkout,))
            with self.assertRaises(FinalGateError):
                _require_external_root(checkout / "evidence", (checkout,))
            link = root / "linked"
            link.symlink_to(external, target_is_directory=True)
            with self.assertRaises(FinalGateError):
                _resolve_plain_directory(link, "linked evidence")


if __name__ == "__main__":
    unittest.main()
