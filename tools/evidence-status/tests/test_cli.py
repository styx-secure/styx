from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import support
import evidence_status
from model import EXIT_DIAGNOSTIC, EXIT_INPUT, EXIT_INTERNAL, MAX_INPUT_BYTES, canonical_json_bytes


class CliHarness:
    def prepare(self, tmp: Path) -> tuple[list[str], Path, Path]:
        repo = tmp / "repo"
        repo.mkdir()
        inputs = tmp / "inputs"
        candidate_path = support.write_json(inputs / "candidate.json", support.candidate())
        scope_raw, test_raw, review_raw = support.evidence_bytes()
        scope_path = support.write_bytes(inputs / "scope.json", scope_raw)
        test_path = support.write_bytes(inputs / "test.json", test_raw)
        review_path = support.write_bytes(inputs / "review.json", review_raw)
        output = tmp / "diagnostics" / "status.json"
        argv = [
            "--candidate", str(candidate_path),
            "--scope-report", str(scope_path),
            "--test-report", str(test_path),
            "--review-report", str(review_path),
            "--repo-root", str(repo),
            "--output", str(output),
        ]
        return argv, output, repo

    def invoke(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = evidence_status.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()


class DiagnosticCliTest(unittest.TestCase, CliHarness):
    def test_exact_current_emits_report_and_diagnostic_summary(self):
        with tempfile.TemporaryDirectory() as raw:
            argv, output, _ = self.prepare(Path(raw))
            code, stdout, stderr = self.invoke(argv)
            self.assertEqual(code, EXIT_DIAGNOSTIC)
            self.assertEqual(stderr, "")
            self.assertTrue(output.is_file())
            report = support.read_json(output)
            self.assertEqual(report["schema"], "styx.evidence-status/v1")
            self.assertEqual([item["state"] for item in report["items"]], ["CURRENT"] * 3)
            self.assertIn("diagnostic only", stdout)
            self.assertIn("not an authorization verdict", stdout)

    def test_repeated_run_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as raw:
            argv, output, _ = self.prepare(Path(raw))
            first_code, first_stdout, _ = self.invoke(argv)
            first_bytes = output.read_bytes()
            second_code, second_stdout, _ = self.invoke(argv)
            self.assertEqual((first_code, first_stdout), (second_code, second_stdout))
            self.assertEqual(first_bytes, output.read_bytes())

    def test_missing_evidence_is_a_diagnostic_not_process_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            argv, output, _ = self.prepare(Path(raw))
            scope_index = argv.index("--scope-report") + 1
            Path(argv[scope_index]).unlink()
            code, stdout, _ = self.invoke(argv)
            self.assertEqual(code, EXIT_DIAGNOSTIC)
            report = support.read_json(output)
            self.assertEqual(report["items"][0]["state"], "MISSING")
            self.assertEqual(report["items"][1]["state"], "UNPROVABLE")
            self.assertEqual(report["items"][2]["state"], "UNPROVABLE")
            self.assertIn("scope: MISSING [FILE_MISSING]", stdout)

    def test_oversized_evidence_is_invalid_but_reported(self):
        with tempfile.TemporaryDirectory() as raw:
            argv, output, _ = self.prepare(Path(raw))
            scope_path = Path(argv[argv.index("--scope-report") + 1])
            scope_path.write_bytes(b"x" * (MAX_INPUT_BYTES + 1))
            code, _, _ = self.invoke(argv)
            self.assertEqual(code, EXIT_DIAGNOSTIC)
            item = support.read_json(output)["items"][0]
            self.assertEqual(item["state"], "INVALID")
            self.assertEqual(item["reasons"], ["INPUT_TOO_LARGE"])

    def test_no_authorization_verdict_is_emitted(self):
        with tempfile.TemporaryDirectory() as raw:
            argv, output, _ = self.prepare(Path(raw))
            code, stdout, _ = self.invoke(argv)
            self.assertEqual(code, EXIT_DIAGNOSTIC)
            combined = output.read_text(encoding="utf-8") + stdout
            for forbidden in ('"PASS"', '"GO"', "APPROVED", "MERGEABLE"):
                self.assertNotIn(forbidden, combined)


class InvalidInvocationTest(unittest.TestCase, CliHarness):
    def test_help_and_usage_codes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                evidence_status.parse_args(["--help"])
        self.assertEqual(caught.exception.code, 0)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                evidence_status.parse_args([])
        self.assertEqual(caught.exception.code, EXIT_INPUT)

    def test_bad_candidate_returns_input_error_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as raw:
            argv, output, _ = self.prepare(Path(raw))
            candidate_path = Path(argv[argv.index("--candidate") + 1])
            candidate_path.write_bytes(b'{"repository":"a","repository":"b"}\n')
            code, _, stderr = self.invoke(argv)
            self.assertEqual(code, EXIT_INPUT)
            self.assertIn("E_INPUT", stderr)
            self.assertFalse(output.exists())

    def test_relative_input_path_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            argv, output, _ = self.prepare(Path(raw))
            argv[argv.index("--candidate") + 1] = "candidate.json"
            code, _, _ = self.invoke(argv)
            self.assertEqual(code, EXIT_INPUT)
            self.assertFalse(output.exists())

    def test_output_inside_declared_repository_is_refused_without_creation(self):
        with tempfile.TemporaryDirectory() as raw:
            argv, _, repo = self.prepare(Path(raw))
            output = repo / "deep" / "status.json"
            argv[argv.index("--output") + 1] = str(output)
            code, _, stderr = self.invoke(argv)
            self.assertEqual(code, EXIT_INPUT)
            self.assertIn("E_OUTPUT", stderr)
            self.assertFalse((repo / "deep").exists())

    def test_output_inside_any_other_worktree_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            argv, _, _ = self.prepare(tmp)
            other = tmp / "other-checkout"
            (other / ".git").mkdir(parents=True)
            output = other / "status.json"
            argv[argv.index("--output") + 1] = str(output)
            code, _, _ = self.invoke(argv)
            self.assertEqual(code, EXIT_INPUT)
            self.assertFalse(output.exists())

    def test_symlinked_input_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            argv, output, _ = self.prepare(tmp)
            original = Path(argv[argv.index("--candidate") + 1])
            link = tmp / "candidate-link.json"
            link.symlink_to(original)
            argv[argv.index("--candidate") + 1] = str(link)
            code, _, _ = self.invoke(argv)
            self.assertEqual(code, EXIT_INPUT)
            self.assertFalse(output.exists())

    def test_unexpected_exception_uses_internal_code_without_details(self):
        with tempfile.TemporaryDirectory() as raw:
            argv, output, _ = self.prepare(Path(raw))
            original = evidence_status.build_report
            try:
                evidence_status.build_report = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RuntimeError("secret-detail")
                )
                code, _, stderr = self.invoke(argv)
            finally:
                evidence_status.build_report = original
            self.assertEqual(code, EXIT_INTERNAL)
            self.assertNotIn("secret-detail", stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
