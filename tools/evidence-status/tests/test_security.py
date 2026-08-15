from __future__ import annotations

import ast
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

import support
import evidence_status
from model import EXIT_DIAGNOSTIC, canonical_json_bytes


class HostileEvidenceTest(unittest.TestCase):
    def test_untrusted_payload_cannot_select_path_or_leak_into_output(self):
        secret = "STYX-OBSERVER-SECRET-MUST-NOT-LEAK"
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            repo = tmp / "repo"
            repo.mkdir()
            scope_raw, test_raw, _ = support.evidence_bytes()
            hostile_finding = {
                "finding_id": "9" * 64,
                "severity": "INFO",
                "component_path": f"../../{secret}",
                "problem": secret,
                "required_behavior": secret,
                "required_test": secret,
                "acceptance_criterion": secret,
                "lifecycle": "RESOLVED",
                "required_fix": False,
            }
            review_raw = canonical_json_bytes(support.review_report(scope_raw, test_raw, findings=[hostile_finding]))
            inputs = tmp / "inputs"
            candidate_path = support.write_json(inputs / "candidate.json", support.candidate())
            scope_path = support.write_bytes(inputs / "scope.json", scope_raw)
            test_path = support.write_bytes(inputs / "test.json", test_raw)
            review_path = support.write_bytes(inputs / "review.json", review_raw)
            output = tmp / "outside" / "status.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = evidence_status.main([
                    "--candidate", str(candidate_path),
                    "--scope-report", str(scope_path),
                    "--test-report", str(test_path),
                    "--review-report", str(review_path),
                    "--repo-root", str(repo),
                    "--output", str(output),
                ])
            self.assertEqual(code, EXIT_DIAGNOSTIC)
            self.assertNotIn(secret, output.read_text(encoding="utf-8"))
            self.assertNotIn(secret, stdout.getvalue())
            self.assertFalse((tmp / secret).exists())

    def test_environment_values_are_not_emitted(self):
        marker = "STYX_ENVIRONMENT_MARKER_182"
        previous = os.environ.get("STYX_OBSERVER_TEST_SECRET")
        os.environ["STYX_OBSERVER_TEST_SECRET"] = marker
        try:
            with tempfile.TemporaryDirectory() as raw:
                tmp = Path(raw)
                harness = _Harness(tmp)
                code, stdout = harness.run()
                self.assertEqual(code, EXIT_DIAGNOSTIC)
                self.assertNotIn(marker, harness.output.read_text(encoding="utf-8"))
                self.assertNotIn(marker, stdout)
        finally:
            if previous is None:
                del os.environ["STYX_OBSERVER_TEST_SECRET"]
            else:
                os.environ["STYX_OBSERVER_TEST_SECRET"] = previous


class StaticBoundaryTest(unittest.TestCase):
    def test_runtime_modules_import_no_network_or_command_execution_library(self):
        forbidden = {"socket", "subprocess", "urllib", "http", "requests", "shlex"}
        for name in ("model.py", "evidence_status.py"):
            source = (support.TOOL_ROOT / name).read_text(encoding="utf-8")
            tree = ast.parse(source)
            imports: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".")[0])
            self.assertTrue(forbidden.isdisjoint(imports), f"{name} imports {forbidden & imports}")

    def test_runtime_has_no_dynamic_execution_calls(self):
        forbidden_calls = {"eval", "exec", "compile", "__import__", "system", "popen"}
        for name in ("model.py", "evidence_status.py"):
            tree = ast.parse((support.TOOL_ROOT / name).read_text(encoding="utf-8"))
            calls = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            self.assertTrue(forbidden_calls.isdisjoint(calls), f"{name} calls {forbidden_calls & calls}")


class _Harness:
    def __init__(self, tmp: Path):
        self.repo = tmp / "repo"
        self.repo.mkdir()
        inputs = tmp / "inputs"
        self.candidate = support.write_json(inputs / "candidate.json", support.candidate())
        scope_raw, test_raw, review_raw = support.evidence_bytes()
        self.scope = support.write_bytes(inputs / "scope.json", scope_raw)
        self.test = support.write_bytes(inputs / "test.json", test_raw)
        self.review = support.write_bytes(inputs / "review.json", review_raw)
        self.output = tmp / "out" / "status.json"

    def run(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = evidence_status.main([
                "--candidate", str(self.candidate),
                "--scope-report", str(self.scope),
                "--test-report", str(self.test),
                "--review-report", str(self.review),
                "--repo-root", str(self.repo),
                "--output", str(self.output),
            ])
        return code, stdout.getvalue()


if __name__ == "__main__":
    unittest.main()
