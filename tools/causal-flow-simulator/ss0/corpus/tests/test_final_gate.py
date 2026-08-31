from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[5]
CORPUS_TOOL = ROOT / "tools/causal-flow-simulator/ss0/corpus"
sys.path.insert(0, str(CORPUS_TOOL))

from final_gate import (  # noqa: E402
    CANONICAL_REPORTS,
    FinalGateError,
    _checkout_identity,
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

    def test_clean_dirty_ancestor_and_alternate_checkout_fixtures(self) -> None:
        node_name = shutil.which("node")
        self.assertIsNotNone(node_name)
        node = Path(node_name).resolve(strict=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            temporary = root / "temporary"
            checkout.mkdir()
            temporary.mkdir()
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            subprocess.run(
                ["git", "-C", str(checkout), "config", "user.name", "SS0 test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(checkout), "config", "user.email", "ss0@example.invalid"],
                check=True,
            )
            (checkout / "tracked.txt").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(checkout), "add", "tracked.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(checkout), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            head = subprocess.check_output(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
            ).strip()
            with mock.patch("final_gate.REQUIRED_HISTORY", ()):
                git_dir = _checkout_identity(
                    checkout,
                    base=head,
                    head=head,
                    temporary_root=temporary,
                    node=node,
                )
                self.assertEqual(checkout / ".git", git_dir)
                (checkout / "dirty.txt").write_text("dirty\n", encoding="utf-8")
                with self.assertRaises(FinalGateError):
                    _checkout_identity(
                        checkout,
                        base=head,
                        head=head,
                        temporary_root=temporary,
                        node=node,
                    )
                (checkout / "dirty.txt").unlink()
                with self.assertRaises(FinalGateError):
                    _checkout_identity(
                        checkout,
                        base="0" * 40,
                        head=head,
                        temporary_root=temporary,
                        node=node,
                    )
                alternates = checkout / ".git/objects/info/alternates"
                alternates.parent.mkdir(parents=True, exist_ok=True)
                foreign_objects = root / "foreign-objects"
                foreign_objects.mkdir()
                alternates.write_text(f"{foreign_objects}\n", encoding="utf-8")
                with self.assertRaises(FinalGateError):
                    _checkout_identity(
                        checkout,
                        base=head,
                        head=head,
                        temporary_root=temporary,
                        node=node,
                    )


if __name__ == "__main__":
    unittest.main()
