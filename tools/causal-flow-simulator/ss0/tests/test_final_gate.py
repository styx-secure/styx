from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))

from final_gate import (  # noqa: E402
    FinalGateError,
    REPORT_NAMES,
    _compare_reports,
    _gate_a_command,
    _require_external_root,
)


class FinalGateTests(unittest.TestCase):
    def test_final_gate_starts_under_the_required_isolated_interpreter(self) -> None:
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                str(PACKAGE / "final_gate.py"),
                "--help",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(0, completed.returncode, completed.stderr.decode("utf-8"))

    def test_inner_gate_a_command_is_explicitly_isolated(self) -> None:
        command = _gate_a_command(
            Path("/checkout"),
            base="b" * 40,
            head="h" * 40,
            phase_a="a" * 40,
            comment_id="123",
            output=Path("/evidence/gate.json"),
        )
        self.assertEqual(["/usr/bin/python3", "-I", "-S", "-B"], command[:4])
        self.assertIn("model-binding", command)

    def test_four_report_sources_must_be_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            roots = [Path(directory) / f"root-{index}" for index in range(4)]
            for root in roots:
                root.mkdir()
                for name in REPORT_NAMES:
                    (root / name).write_bytes((name + "\n").encode("ascii"))
            rows = _compare_reports(*roots)
            self.assertEqual(len(REPORT_NAMES), len(rows))
            self.assertEqual(
                hashlib.sha256(b"inventory.json\n").hexdigest(),
                next(row["sha256"] for row in rows if row["id"] == "inventory"),
            )
            (roots[3] / "probe.json").write_bytes(b"different\n")
            with self.assertRaises(FinalGateError):
                _compare_reports(*roots)

    def test_evidence_root_cannot_overlap_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            external = root / "external"
            external.mkdir()
            _require_external_root(external, (checkout,))
            with self.assertRaises(FinalGateError):
                _require_external_root(checkout / "evidence", (checkout,))


if __name__ == "__main__":
    unittest.main()
