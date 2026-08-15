"""Deterministic fixtures for the evidence-status observer tests."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

TOOL_ROOT = Path(__file__).resolve().parents[1]
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

from model import canonical_json_bytes

BASE = "1" * 40
HEAD = "2" * 40
OTHER = "3" * 40
BODY = "4" * 64
DIFF = "5" * 64
ZERO = "0" * 64


def candidate() -> dict[str, Any]:
    return {
        "repository": "styx-secure/styx",
        "issue_number": 182,
        "base_sha": BASE,
        "head_sha": HEAD,
        "issue_body_sha256": BODY,
        "diff_sha256": DIFF,
        "tool_versions": {"scope": "0.4.0", "review": "0.1.0"},
    }


def scope_report(**changes: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "styx.task-scope-report/v1",
        "tool_version": "0.4.0",
        "issue_number": 182,
        "execution_id": "issue-182-implementer-01",
        "base_sha": BASE,
        "head_sha": HEAD,
        "issue_body_sha256": BODY,
        "contract_version": "v1",
        "allowed_patterns": ["tools/evidence-status/**"],
        "forbidden_patterns": [".github/**"],
        "changed_entries": [],
        "diagnostics": [],
        "generation": {"canonical_json": "RFC8259-sort-keys-utf8-lf", "timestamp_omitted": True},
        "verdict": "PASS",
    }
    report.update(changes)
    return report


def test_report(scope_raw: bytes, **changes: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "styx.test-report/v1",
        "issue_number": 182,
        "execution_id": "issue-182-implementer-01",
        "base_sha": BASE,
        "head_sha": HEAD,
        "issue_body_sha256": BODY,
        "plan_sha256": "6" * 64,
        "scope_report_sha256": hashlib.sha256(scope_raw).hexdigest(),
        "command_policy_sha256": "7" * 64,
        "mandatory_verdict": "PASS",
        "regression_verdict": "PASS",
        "generated_verdict": "PASS",
        "adversarial_verdict": "PASS",
        "static_verdict": "PASS",
        "rollback_verdict": "PASS",
        "failures": [],
        "generation": {"canonical_json": "RFC8259-sort-keys-utf8-lf", "timestamp_omitted": True},
        "verdict": "PASS",
    }
    report.update(changes)
    return report


def review_report(scope_raw: bytes, test_raw: bytes, **changes: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "styx.review-report/v1",
        "tool_version": "0.1.0",
        "repository": "styx-secure/styx",
        "issue_number": 182,
        "base_sha": BASE,
        "head_sha": HEAD,
        "issue_body_sha256": BODY,
        "diff_sha256": DIFF,
        "scope_report_sha256": hashlib.sha256(scope_raw).hexdigest(),
        "test_report_sha256": hashlib.sha256(test_raw).hexdigest(),
        "scope_verdict": "PASS",
        "test_verdict": "PASS",
        "reviewer_class": "DELEGATED_AGENT",
        "reviewer_execution_id": "issue-182-reviewer-01",
        "reviewer_context_id": "issue-182-review-context-01",
        "reviewer_identity_ref": "independent-agent",
        "implementer_execution_id": "issue-182-implementer-01",
        "implementer_context_id": "issue-182-implementer-context-01",
        "independent": True,
        "verdict": "GO",
        "remediation_required": False,
        "findings": [],
        "generation": {"canonical_json": "RFC8259-sort-keys-utf8-lf", "timestamp_omitted": True},
    }
    report.update(changes)
    return report


def evidence_bytes() -> tuple[bytes, bytes, bytes]:
    scope_raw = canonical_json_bytes(scope_report())
    test_raw = canonical_json_bytes(test_report(scope_raw))
    review_raw = canonical_json_bytes(review_report(scope_raw, test_raw))
    return scope_raw, test_raw, review_raw


def cloned(value: dict[str, Any], **changes: Any) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result.update(changes)
    return result


def write_bytes(path: Path, raw: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


def write_json(path: Path, value: dict[str, Any]) -> Path:
    return write_bytes(path, canonical_json_bytes(value))


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value
