from __future__ import annotations

from contextlib import redirect_stderr
import io
from pathlib import Path
import sys
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from run_cross_runtime import main as runtime_main  # noqa: E402
from run_genesis_checkpoint_probe import main as probe_main  # noqa: E402
from run_mutations import main as mutations_main  # noqa: E402
from scope_guard_o07 import main as scope_main  # noqa: E402


class ProducerCliTests(unittest.TestCase):
    def test_every_producer_requires_bundle_and_locked_digest(self) -> None:
        commands = (
            (
                probe_main,
                ["--repo-root", ".", "--suite", "required", "--output", "out.json"],
            ),
            (
                runtime_main,
                [
                    "--repo-root",
                    ".",
                    "--suite",
                    "required",
                    "--javascript",
                    "node",
                    "--workspace",
                    "workspace",
                    "--output",
                    "out.json",
                ],
            ),
            (
                mutations_main,
                ["--repo-root", ".", "--suite", "required", "--output", "out.json"],
            ),
            (
                scope_main,
                [
                    "--repo-root",
                    ".",
                    "--base",
                    "base",
                    "--candidate",
                    "candidate",
                    "--output",
                    "out.json",
                ],
            ),
        )
        for producer, arguments in commands:
            with self.subTest(producer=producer.__module__, missing="bundle"):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    producer([*arguments, "--bundle-sha256", "0" * 64])
            with self.subTest(producer=producer.__module__, missing="bundle-sha256"):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    producer([*arguments, "--bundle", "candidate.bundle"])


if __name__ == "__main__":
    unittest.main()
