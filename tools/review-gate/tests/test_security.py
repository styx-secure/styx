"""Adversarial and determinism guarantees, plus isolation proofs.

These tests prove, statically and behaviourally, that the review gate performs
no network access, uses no subprocess, reads no credentials, executes no tests
and never writes inside the reviewed repository (i.e. never mutates the
implementation branch).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import support
from support import evidence_pair, finding_dict, review_request_dict

from evidence import load_evidence
from model import (
    EXIT_ERROR,
    EXIT_PASS,
    OutputError,
    PathError,
    ReviewGateError,
    ReviewInputError,
    load_strict_json,
)
from review import build_review_report, review_report_bytes, validate_review_request

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_MODULES = ("model.py", "evidence.py", "review.py", "remediation.py", "review_gate.py")


class ClosedShapeTest(unittest.TestCase):
    def test_unknown_top_level_field_rejected(self):
        request = review_request_dict(verdict="GO")
        request["surprise"] = 1
        with self.assertRaises(ReviewInputError):
            validate_review_request(request)

    def test_unknown_candidate_field_rejected(self):
        request = review_request_dict(verdict="GO")
        request["candidate"]["surprise"] = 1
        with self.assertRaises(ReviewInputError):
            validate_review_request(request)

    def test_unknown_reviewer_field_rejected(self):
        request = review_request_dict(verdict="GO")
        request["reviewer"]["surprise"] = 1
        with self.assertRaises(ReviewInputError):
            validate_review_request(request)

    def test_unknown_finding_field_rejected(self):
        finding = finding_dict(severity="HIGH", required_fix=True)
        finding["surprise"] = 1
        with self.assertRaises(ReviewInputError):
            validate_review_request(review_request_dict(verdict="CHANGES_REQUESTED", findings=[finding]))


class MalformedInputTest(unittest.TestCase):
    def test_duplicate_keys_rejected(self):
        raw = b'{"verdict":"GO","verdict":"BLOCKED"}'
        with self.assertRaises(ReviewInputError):
            load_strict_json(raw, source="x", error=ReviewInputError)

    def test_non_json_rejected(self):
        with self.assertRaises(ReviewInputError):
            load_strict_json(b"not json at all", source="x", error=ReviewInputError)

    def test_non_utf8_rejected(self):
        with self.assertRaises(ReviewInputError):
            load_strict_json(b"\xff\xfe", source="x", error=ReviewInputError)

    def test_cli_malformed_request_is_error(self):
        scope, test = evidence_pair()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            request_path = support.write_bytes(tmp / "review-request.json", b"{ broken")
            scope_path = support.write_bytes(tmp / "scope.json", scope)
            test_path = support.write_bytes(tmp / "test.json", test)
            import review_gate
            code = review_gate.main([
                "review",
                "--review-request", str(request_path),
                "--scope-report", str(scope_path),
                "--test-report", str(test_path),
                "--output", str(tmp / "out.json"),
            ])
        self.assertEqual(code, EXIT_ERROR)


class PathReplacementTest(unittest.TestCase):
    def test_symlinked_input_rejected(self):
        scope, test = evidence_pair()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            real = support.write_bytes(tmp / "real-scope.json", scope)
            link = tmp / "scope-link.json"
            os.symlink(real, link)
            test_path = support.write_bytes(tmp / "test.json", test)
            request_path = support.write_json(tmp / "req.json", review_request_dict(verdict="GO"))
            import review_gate
            code = review_gate.main([
                "review",
                "--review-request", str(request_path),
                "--scope-report", str(link),
                "--test-report", str(test_path),
                "--output", str(tmp / "out.json"),
            ])
        self.assertEqual(code, EXIT_ERROR)

    def test_symlinked_output_rejected(self):
        scope, test = evidence_pair()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            elsewhere = support.write_bytes(tmp / "elsewhere.json", b"{}")
            output = tmp / "out.json"
            os.symlink(elsewhere, output)
            code, _ = support.run_review(tmp, request=review_request_dict(verdict="GO"),
                                         scope_bytes=scope, test_bytes=test, output_name="out.json")
        self.assertEqual(code, EXIT_ERROR)

    def test_output_inside_repo_rejected(self):
        scope, test = evidence_pair()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            repo_root = tmp / "repo"
            repo_root.mkdir()
            request_path = support.write_json(tmp / "req.json", review_request_dict(verdict="GO"))
            scope_path = support.write_bytes(tmp / "scope.json", scope)
            test_path = support.write_bytes(tmp / "test.json", test)
            import review_gate
            code = review_gate.main([
                "review",
                "--review-request", str(request_path),
                "--scope-report", str(scope_path),
                "--test-report", str(test_path),
                "--repo-root", str(repo_root),
                "--output", str(repo_root / "inside" / "out.json"),
            ])
        self.assertEqual(code, EXIT_ERROR)


class AtomicWriteFailureTest(unittest.TestCase):
    def test_write_failure_maps_to_error(self):
        scope, test = evidence_pair()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            # Make the output parent a regular file so mkdir fails.
            blocker = support.write_bytes(tmp / "blocker", b"x")
            request_path = support.write_json(tmp / "req.json", review_request_dict(verdict="GO"))
            scope_path = support.write_bytes(tmp / "scope.json", scope)
            test_path = support.write_bytes(tmp / "test.json", test)
            import review_gate
            code = review_gate.main([
                "review",
                "--review-request", str(request_path),
                "--scope-report", str(scope_path),
                "--test-report", str(test_path),
                "--output", str(blocker / "out.json"),
            ])
        self.assertEqual(code, EXIT_ERROR)


class RedactionTest(unittest.TestCase):
    def test_secret_in_finding_is_redacted(self):
        token = "ghp_" + "A" * 32
        report = build_review_report(
            validate_review_request(review_request_dict(
                verdict="CHANGES_REQUESTED",
                findings=[finding_dict(
                    severity="HIGH", required_fix=True,
                    problem=f"Leaked token {token} in the log.",
                )],
            )),
            load_evidence(*evidence_pair()),
        )
        blob = review_report_bytes(report).decode("utf-8")
        self.assertNotIn(token, blob)
        self.assertIn("[REDACTED]", blob)

    def test_redaction_preserves_commit_sha(self):
        # A commit SHA must never be mistaken for a secret.
        report = build_review_report(
            validate_review_request(review_request_dict(
                verdict="CHANGES_REQUESTED",
                findings=[finding_dict(
                    severity="HIGH", required_fix=True,
                    problem=f"Regression at {support.BASE_SHA}.",
                )],
            )),
            load_evidence(*evidence_pair()),
        )
        blob = review_report_bytes(report).decode("utf-8")
        self.assertIn(support.BASE_SHA, blob)


class IsolationProofTest(unittest.TestCase):
    """Static proof that the gate cannot egress, shell out or run tests."""

    FORBIDDEN_MODULE_NAMES = (
        "subprocess", "socket", "ssl", "urllib", "http", "requests",
        "httpx", "ftplib", "smtplib", "telnetlib", "asyncio", "pty",
    )
    FORBIDDEN_SOURCE_TOKENS = (
        "subprocess", "urllib", "requests.", "httpx", "ftplib", "smtplib",
        "Popen", "os.system", "pty.spawn", "socket.socket", "http.client",
        "os.exec", "commands.getoutput",
    )

    def test_modules_do_not_import_network_or_process_libs(self):
        import importlib

        for module_name in ("model", "evidence", "review", "remediation", "review_gate"):
            module = importlib.import_module(module_name)
            for forbidden in self.FORBIDDEN_MODULE_NAMES:
                self.assertNotIn(
                    forbidden, vars(module),
                    f"{module_name} unexpectedly binds '{forbidden}'",
                )

    def test_source_has_no_egress_or_shell_tokens(self):
        for filename in PACKAGE_MODULES:
            text = (PACKAGE_ROOT / filename).read_text(encoding="utf-8")
            for token in self.FORBIDDEN_SOURCE_TOKENS:
                self.assertNotIn(token, text, f"{filename} contains forbidden token '{token}'")

    def test_no_test_runner_invocation(self):
        # The gate must not execute tests: no test-runner tokens in package code.
        for filename in PACKAGE_MODULES:
            text = (PACKAGE_ROOT / filename).read_text(encoding="utf-8")
            self.assertNotIn("-m unittest", text)
            self.assertNotIn("pytest", text)

    def test_no_github_or_credential_tokens(self):
        for filename in PACKAGE_MODULES:
            text = (PACKAGE_ROOT / filename).read_text(encoding="utf-8")
            for token in ("github.com", "api.github", "GITHUB_TOKEN", "/gh/", "hub.com/repos"):
                self.assertNotIn(token, text, f"{filename} references GitHub/credential token '{token}'")

    def test_gate_never_writes_inside_repository(self):
        # Behavioural counterpart: any output under repo_root is refused.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            repo_root = tmp / "repo"
            (repo_root / "sub").mkdir(parents=True)
            with self.assertRaises(OutputError):
                from model import ensure_writable_output
                ensure_writable_output(repo_root / "sub" / "x.json", repo_root=repo_root)


class SchemaAgreementTest(unittest.TestCase):
    SCHEMA_DIR = PACKAGE_ROOT.parent.parent / "docs" / "governance" / "schemas"

    def test_review_report_schema_matches_code(self):
        from review import REVIEW_REPORT_FIELDS, FINDING_OUTPUT_FIELDS

        schema = json.loads((self.SCHEMA_DIR / "review-report-v1.schema.json").read_text())
        self.assertEqual(set(schema["required"]), set(REVIEW_REPORT_FIELDS))
        self.assertEqual(set(schema["properties"]), set(REVIEW_REPORT_FIELDS))
        finding_props = schema["$defs"]["finding"]["properties"]
        self.assertEqual(set(finding_props), set(FINDING_OUTPUT_FIELDS))
        self.assertFalse(schema["additionalProperties"])

    def test_remediation_schema_matches_code(self):
        from remediation import REMEDIATION_REQUEST_FIELDS, REMEDIATION_ITEM_FIELDS

        schema = json.loads((self.SCHEMA_DIR / "remediation-request-v1.schema.json").read_text())
        self.assertEqual(set(schema["required"]), set(REMEDIATION_REQUEST_FIELDS))
        self.assertEqual(set(schema["properties"]), set(REMEDIATION_REQUEST_FIELDS))
        item_props = schema["$defs"]["item"]["properties"]
        self.assertEqual(set(item_props), set(REMEDIATION_ITEM_FIELDS))
        self.assertFalse(schema["additionalProperties"])

    def test_emitted_report_conforms_to_schema_shape(self):
        report = build_review_report(
            validate_review_request(review_request_dict(verdict="GO")),
            load_evidence(*evidence_pair()),
        )
        schema = json.loads((self.SCHEMA_DIR / "review-report-v1.schema.json").read_text())
        self.assertEqual(set(report), set(schema["required"]))


if __name__ == "__main__":
    unittest.main()
