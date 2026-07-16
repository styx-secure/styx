"""Shared fixtures for the review-gate test suite.

Fixtures are conformant to the authoritative ``styx.task-scope-report/v1`` and
``styx.test-report/v1`` schemas present on ``main``; only the frozen minimum
test-report interface is relied upon.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
from typing import Any

# Make the review-gate package importable when unittest discovers this
# directory as the start dir.
_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)

from model import canonical_json_bytes, generation_stanza, sha256_hex  # noqa: E402

BASE_SHA = "9ada666d438a667bcc934784101bc99b3d98d50b"
HEAD_SHA = "1111111111111111111111111111111111111111"
OTHER_HEAD_SHA = "2222222222222222222222222222222222222222"
ISSUE_NUMBER = 55

ISSUE_BODY = b"<!-- styx-task-contract:v1 -->\nreview gate body\n"
ISSUE_BODY_SHA256 = sha256_hex(ISSUE_BODY)
DIFF_SHA256 = sha256_hex(b"unified diff of the candidate")
OTHER_DIFF_SHA256 = sha256_hex(b"a different diff")
PLAN_SHA256 = sha256_hex(b"test plan")

IMPLEMENTER_EXECUTION_ID = "issue-55-implementer-01"
IMPLEMENTER_CONTEXT_ID = "impl-context-abc"
REVIEWER_EXECUTION_ID = "issue-55-reviewer-09"
REVIEWER_CONTEXT_ID = "review-context-xyz"


def scope_report_dict(*, verdict: str = "PASS", head_sha: str = HEAD_SHA, base_sha: str = BASE_SHA,
                      issue_number: int = ISSUE_NUMBER, issue_body_sha256: str = ISSUE_BODY_SHA256,
                      execution_id: str = IMPLEMENTER_EXECUTION_ID) -> dict[str, Any]:
    return {
        "schema": "styx.task-scope-report/v1",
        "tool_version": "0.1.0",
        "issue_number": issue_number,
        "execution_id": execution_id,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "issue_body_sha256": issue_body_sha256,
        "contract_version": "v1",
        "allowed_patterns": ["tools/review-gate/**"],
        "forbidden_patterns": ["tools/test-orchestrator/**"],
        "changed_entries": [],
        "diagnostics": [],
        "generation": generation_stanza(),
        "verdict": verdict,
    }


def scope_report_bytes(**kwargs: Any) -> bytes:
    return canonical_json_bytes(scope_report_dict(**kwargs))


def test_report_dict(*, verdict: str = "PASS", head_sha: str = HEAD_SHA, base_sha: str = BASE_SHA,
                     issue_number: int = ISSUE_NUMBER, issue_body_sha256: str = ISSUE_BODY_SHA256,
                     scope_report_sha256: str | None = None,
                     mandatory_verdict: str = "PASS",
                     execution_id: str = IMPLEMENTER_EXECUTION_ID) -> dict[str, Any]:
    if scope_report_sha256 is None:
        scope_report_sha256 = sha256_hex(scope_report_bytes(
            verdict="PASS", head_sha=head_sha, base_sha=base_sha,
            issue_number=issue_number, issue_body_sha256=issue_body_sha256,
            execution_id=execution_id,
        ))
    return {
        "schema": "styx.test-report/v1",
        "issue_number": issue_number,
        "execution_id": execution_id,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "issue_body_sha256": issue_body_sha256,
        "plan_sha256": PLAN_SHA256,
        "scope_report_sha256": scope_report_sha256,
        "command_policy_sha256": sha256_hex(b"command policy"),
        "mandatory_verdict": mandatory_verdict,
        "regression_verdict": "PASS",
        "generated_verdict": "NOT_RUN",
        "adversarial_verdict": "PASS",
        "static_verdict": "PASS",
        "rollback_verdict": "PASS",
        "failures": [],
        "generation": generation_stanza(),
        "verdict": verdict,
    }


def evidence_pair(*, scope_verdict: str = "PASS", test_verdict: str = "PASS",
                  head_sha: str = HEAD_SHA, base_sha: str = BASE_SHA,
                  issue_number: int = ISSUE_NUMBER,
                  issue_body_sha256: str = ISSUE_BODY_SHA256,
                  execution_id: str = IMPLEMENTER_EXECUTION_ID,
                  test_execution_id: str | None = None) -> tuple[bytes, bytes]:
    """Return a cross-bound (scope_bytes, test_bytes) pair.

    ``execution_id`` sets the authoritative implementer identity carried by both
    halves. ``test_execution_id`` overrides it in the test report only, to build
    an evidence pair that disagrees about who produced the candidate.
    """

    scope = scope_report_bytes(verdict=scope_verdict, head_sha=head_sha, base_sha=base_sha,
                               issue_number=issue_number, issue_body_sha256=issue_body_sha256,
                               execution_id=execution_id)
    test = canonical_json_bytes(test_report_dict(
        verdict=test_verdict, head_sha=head_sha, base_sha=base_sha,
        issue_number=issue_number, issue_body_sha256=issue_body_sha256,
        scope_report_sha256=sha256_hex(scope),
        execution_id=execution_id if test_execution_id is None else test_execution_id,
    ))
    return scope, test


def candidate_dict(**overrides: Any) -> dict[str, Any]:
    candidate = {
        "repository": "styx-secure/styx",
        "issue_number": ISSUE_NUMBER,
        "issue_body_sha256": ISSUE_BODY_SHA256,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "diff_sha256": DIFF_SHA256,
        "implementer_execution_id": IMPLEMENTER_EXECUTION_ID,
        "implementer_context_id": IMPLEMENTER_CONTEXT_ID,
    }
    candidate.update(overrides)
    return candidate


def reviewer_dict(**overrides: Any) -> dict[str, Any]:
    reviewer = {
        "reviewer_class": "HUMAN",
        "execution_id": REVIEWER_EXECUTION_ID,
        "context_id": REVIEWER_CONTEXT_ID,
        "identity_ref": "human:security-reviewer",
    }
    reviewer.update(overrides)
    return reviewer


def finding_dict(**overrides: Any) -> dict[str, Any]:
    finding = {
        "severity": "MEDIUM",
        "component_path": "tools/review-gate/review.py",
        "problem": "The precondition does not reject stale evidence.",
        "required_behavior": "Reject any evidence whose HEAD differs from the candidate.",
        "required_test": "Add a stale-evidence rejection test.",
        "acceptance_criterion": "Stale evidence yields a fail-closed error.",
        "lifecycle": "OPEN",
        "required_fix": False,
    }
    finding.update(overrides)
    return finding


def review_request_dict(*, verdict: str = "GO", findings: list[dict[str, Any]] | None = None,
                        candidate: dict[str, Any] | None = None,
                        reviewer: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "candidate": copy.deepcopy(candidate) if candidate is not None else candidate_dict(),
        "reviewer": copy.deepcopy(reviewer) if reviewer is not None else reviewer_dict(),
        "verdict": verdict,
        "findings": copy.deepcopy(findings) if findings is not None else [],
    }


def write_bytes(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def write_json(path: Path, value: Any) -> Path:
    path.write_bytes(canonical_json_bytes(value))
    return path


#: Sentinel meaning "create and pass a default --repo-root". Distinct from
#: ``None``, which means "omit the flag entirely" so a test can exercise the
#: fail-closed parse.
DEFAULT_REPO_ROOT = object()


def default_repo_root(tmp: Path) -> Path:
    """An existing repository root outside which the output may be written."""

    root = tmp / "repo-root"
    root.mkdir(exist_ok=True)
    return root


def _repo_root_args(tmp: Path, repo_root: Any) -> list[str]:
    if repo_root is None:
        return []
    resolved = default_repo_root(tmp) if repo_root is DEFAULT_REPO_ROOT else repo_root
    return ["--repo-root", str(resolved)]


def run_review(tmp: Path, *, request: dict[str, Any], scope_bytes: bytes, test_bytes: bytes,
               output_name: str = "review-report.json", extra_args: list[str] | None = None,
               repo_root: Any = DEFAULT_REPO_ROOT) -> tuple[int, Path]:
    import review_gate

    request_path = write_json(tmp / "review-request.json", request)
    scope_path = write_bytes(tmp / "scope-report.json", scope_bytes)
    test_path = write_bytes(tmp / "test-report.json", test_bytes)
    output_path = tmp / output_name
    argv = [
        "review",
        "--review-request", str(request_path),
        "--scope-report", str(scope_path),
        "--test-report", str(test_path),
        "--output", str(output_path),
        *_repo_root_args(tmp, repo_root),
    ]
    if extra_args:
        argv.extend(extra_args)
    with contextlib.redirect_stdout(io.StringIO()):
        code = review_gate.main(argv)
    return code, output_path


def run_remediate(tmp: Path, *, review_report_bytes: bytes, round_id: int,
                  output_name: str = "remediation.json",
                  repo_root: Any = DEFAULT_REPO_ROOT) -> tuple[int, Path]:
    import review_gate

    report_path = write_bytes(tmp / "review-report-in.json", review_report_bytes)
    output_path = tmp / output_name
    argv = [
        "remediate",
        "--review-report", str(report_path),
        "--round", str(round_id),
        "--output", str(output_path),
        *_repo_root_args(tmp, repo_root),
    ]
    with contextlib.redirect_stdout(io.StringIO()):
        code = review_gate.main(argv)
    return code, output_path


def read_json(path: Path) -> Any:
    return json.loads(path.read_bytes().decode("utf-8"))
