from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from review_sandbox import (
    DEFAULT_TIMEOUT_SECONDS,
    ReviewSandboxError,
    classify_finding,
    parse_probe_output,
    required_validation_commands,
    run_read_only,
    run_review,
)

IN_REVIEW_SANDBOX = os.environ.get("STYX_REVIEW_SANDBOX") == "1"


class ReviewSandboxTests(unittest.TestCase):
    @unittest.skipIf(IN_REVIEW_SANDBOX, "outer sandbox already enforces isolation")
    def test_failed_probe_is_invalid_instead_of_downgraded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            (repo / "tracked").write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked"], cwd=repo, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Review Sandbox Test",
                    "-c",
                    "user.email=review-sandbox@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "baseline",
                ],
                cwd=repo,
                check=True,
            )
            output = root / "report.json"
            with patch(
                "review_sandbox.required_validation_commands",
                return_value=[[sys.executable, "-c", "pass"]],
            ):
                report = run_review(
                    repo_root=repo,
                    revision="HEAD",
                    finding_id="TEST-FAILED-PROBE",
                    severity="HIGH",
                    probe_argv=[sys.executable, "-c", "raise SystemExit(3)"],
                    output=output,
                    timeout_seconds=30,
                )
            self.assertEqual(report["disposition"], "INVALID_PROBE")
            self.assertNotIn("effectiveSeverity", report)

    @unittest.skipIf(IN_REVIEW_SANDBOX, "outer sandbox already enforces isolation")
    def test_review_validation_sees_self_contained_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            (repo / "tracked").write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked"], cwd=repo, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Review Sandbox Test",
                    "-c",
                    "user.email=review-sandbox@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "baseline",
                ],
                cwd=repo,
                check=True,
            )
            output = root / "report.json"
            with patch(
                "review_sandbox.required_validation_commands",
                return_value=[["git", "rev-parse", "HEAD"]],
            ):
                report = run_review(
                    repo_root=repo,
                    revision="HEAD",
                    finding_id="TEST-GIT-METADATA",
                    severity="HIGH",
                    probe_argv=[
                        sys.executable,
                        "-c",
                        'print(\'{"reproduced":false,"summary":"no finding"}\')',
                    ],
                    output=output,
                    timeout_seconds=30,
                )
            self.assertEqual(report["disposition"], "DOWNGRADED_NOT_REPRODUCED")

    def test_default_timeout_covers_the_measured_full_suite(self) -> None:
        self.assertGreaterEqual(DEFAULT_TIMEOUT_SECONDS, 3600)

    def test_reproduced_counterexample_keeps_reported_severity(self) -> None:
        self.assertEqual(
            classify_finding("HIGH", reproduced=True),
            {"disposition": "CONFIRMED", "effectiveSeverity": "HIGH"},
        )

    def test_non_reproduced_counterexample_is_downgraded(self) -> None:
        self.assertEqual(
            classify_finding("HIGH", reproduced=False),
            {
                "disposition": "DOWNGRADED_NOT_REPRODUCED",
                "effectiveSeverity": "NOTE",
            },
        )

    def test_probe_output_is_strict_typed_canonical_json(self) -> None:
        parsed = parse_probe_output(
            b'{"reproduced":true,"summary":"minimal counterexample reaches the claimed branch"}\n'
        )
        self.assertTrue(parsed.reproduced)
        self.assertEqual(
            parsed.summary, "minimal counterexample reaches the claimed branch"
        )
        with self.assertRaisesRegex(ReviewSandboxError, "canonical JSON"):
            parse_probe_output(b'{"reproduced": true, "summary": "x"}')
        with self.assertRaisesRegex(ReviewSandboxError, "exactly reproduced and summary"):
            parse_probe_output(b'{"extra":1,"reproduced":true,"summary":"x"}\n')

    @unittest.skipIf(IN_REVIEW_SANDBOX, "outer sandbox already enforces isolation")
    def test_read_only_runner_can_read_checkout_and_write_scratch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            scratch = root / "scratch"
            checkout.mkdir()
            scratch.mkdir()
            (checkout / "marker").write_text("visible", encoding="utf-8")
            completed = run_read_only(
                checkout,
                scratch,
                [
                    sys.executable,
                    "-c",
                    (
                        "import os; from pathlib import Path; "
                        "assert os.environ['STYX_REVIEW_SANDBOX'] == '1'; "
                        "assert Path('marker').read_text() == 'visible'; "
                        "(Path(os.environ['TMPDIR']) / 'made').write_text('ok')"
                    ),
                ],
                timeout_seconds=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual((scratch / "made").read_text(), "ok")

    @unittest.skipIf(IN_REVIEW_SANDBOX, "outer sandbox already enforces isolation")
    def test_read_only_runner_does_not_pass_host_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            scratch = root / "scratch"
            checkout.mkdir()
            scratch.mkdir()
            variable = "STYX_REVIEW_HOST_SECRET_TEST"
            previous = os.environ.get(variable)
            os.environ[variable] = "must-not-cross-boundary"
            self.addCleanup(
                lambda: (
                    os.environ.pop(variable, None)
                    if previous is None
                    else os.environ.__setitem__(variable, previous)
                )
            )
            completed = run_read_only(
                checkout,
                scratch,
                [
                    sys.executable,
                    "-c",
                    (
                        "import os; "
                        "raise SystemExit(1 if 'STYX_REVIEW_HOST_SECRET_TEST' in os.environ else 0)"
                    ),
                ],
                timeout_seconds=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    @unittest.skipIf(IN_REVIEW_SANDBOX, "outer sandbox already enforces isolation")
    def test_read_only_runner_mounts_explicit_external_probe_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            scratch = root / "scratch"
            probe_dir = root / "external"
            checkout.mkdir()
            scratch.mkdir()
            probe_dir.mkdir()
            probe = probe_dir / "probe.py"
            probe.write_text(
                "import os\nfrom pathlib import Path\n"
                "Path(os.environ['TMPDIR'], 'probe-ran').write_text('ok')\n",
                encoding="utf-8",
            )
            completed = run_read_only(
                checkout,
                scratch,
                [sys.executable, str(probe)],
                timeout_seconds=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual((scratch / "probe-ran").read_text(), "ok")

    @unittest.skipIf(IN_REVIEW_SANDBOX, "outer sandbox already enforces isolation")
    def test_read_only_runner_exposes_required_node_runtime(self) -> None:
        node = shutil.which("node")
        if node is None:
            candidates = sorted(
                (Path.home() / ".nvm" / "versions" / "node").glob("*/bin/node")
            )
            if not candidates:
                self.skipTest("host has no Node runtime")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            scratch = root / "scratch"
            checkout.mkdir()
            scratch.mkdir()
            completed = run_read_only(
                checkout,
                scratch,
                ["node", "--version"],
                timeout_seconds=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    @unittest.skipIf(IN_REVIEW_SANDBOX, "outer sandbox already enforces isolation")
    def test_read_only_runner_cannot_read_unbound_host_home_file(self) -> None:
        marker = Path.home() / f".styx-review-secret-test-{os.getpid()}"
        marker.write_text("secret", encoding="utf-8")
        self.addCleanup(marker.unlink, missing_ok=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            scratch = root / "scratch"
            checkout.mkdir()
            scratch.mkdir()
            completed = run_read_only(
                checkout,
                scratch,
                [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; "
                        f"raise SystemExit(1 if Path({str(marker)!r}).exists() else 0)"
                    ),
                ],
                timeout_seconds=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    @unittest.skipIf(IN_REVIEW_SANDBOX, "outer sandbox already enforces isolation")
    def test_read_only_runner_does_not_share_host_dev_shm(self) -> None:
        marker = Path("/dev/shm") / f"styx-review-test-{os.getpid()}"
        marker.unlink(missing_ok=True)
        self.addCleanup(marker.unlink, missing_ok=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            scratch = root / "scratch"
            checkout.mkdir()
            scratch.mkdir()
            completed = run_read_only(
                checkout,
                scratch,
                [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; "
                        f"path=Path({str(marker)!r}); "
                        "path.parent.mkdir(parents=True, exist_ok=True); "
                        "path.write_text('sandbox')"
                    ),
                ],
                timeout_seconds=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertFalse(marker.exists())

    @unittest.skipIf(IN_REVIEW_SANDBOX, "outer sandbox already enforces isolation")
    def test_read_only_runner_preserves_standalone_checkout_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            scratch = root / "scratch"
            checkout.mkdir()
            scratch.mkdir()
            subprocess.run(["git", "init", "--quiet"], cwd=checkout, check=True)
            (checkout / "tracked").write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked"], cwd=checkout, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Review Sandbox Test",
                    "-c",
                    "user.email=review-sandbox@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "baseline",
                ],
                cwd=checkout,
                check=True,
            )
            completed = run_read_only(
                checkout,
                scratch,
                ["git", "rev-parse", "HEAD"],
                timeout_seconds=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertRegex(completed.stdout.decode().strip(), r"^[0-9a-f]{40}$")

    @unittest.skipIf(IN_REVIEW_SANDBOX, "outer sandbox already enforces isolation")
    def test_read_only_runner_blocks_checkout_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            scratch = root / "scratch"
            checkout.mkdir()
            scratch.mkdir()
            completed = run_read_only(
                checkout,
                scratch,
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; Path('forbidden').write_text('x')",
                ],
                timeout_seconds=30,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((checkout / "forbidden").exists())

    @unittest.skipIf(IN_REVIEW_SANDBOX, "outer sandbox already enforces isolation")
    def test_read_only_runner_cannot_see_host_processes(self) -> None:
        sleeper = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"]
        )

        def stop_sleeper() -> None:
            if sleeper.poll() is None:
                sleeper.kill()
            sleeper.wait()

        self.addCleanup(stop_sleeper)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            scratch = root / "scratch"
            checkout.mkdir()
            scratch.mkdir()
            completed = run_read_only(
                checkout,
                scratch,
                [
                    sys.executable,
                    "-c",
                    f"import os; os.kill({sleeper.pid}, 0)",
                ],
                timeout_seconds=30,
            )
            self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(sleeper.poll())

    def test_validation_runs_suite_and_both_existing_generators(self) -> None:
        commands = required_validation_commands(Path("/checkout"))
        rendered = [" ".join(command) for command in commands]
        self.assertEqual(len(rendered), 3)
        self.assertIn("unittest discover", rendered[0])
        self.assertIn("--prove-reference-round-trip", rendered[1])
        self.assertIn("--prove-positive-carrier-closure", rendered[2])


if __name__ == "__main__":
    unittest.main()
