"""Structured remediation derived from a review report.

When a review requests changes, the gate turns the review report's open
findings into a canonical ``styx.remediation-request/v1`` document. Each item
is actionable for the implementer and is bound, exactly, to the review report
hash and the remediation round, so remediation verified against an old commit
can never be reused after a new candidate HEAD.
"""

from __future__ import annotations

from typing import Any, Mapping

from model import (
    ACCEPTANCE_VERDICTS,
    OPEN_LIFECYCLE_STATES,
    REMEDIATION_REQUEST_SCHEMA_ID,
    ReviewInputError,
    TOOL_VERSION,
    canonical_json_bytes,
    generation_stanza,
    require,
    sha256_hex,
)
from review import validate_review_report_document

REMEDIATION_REQUEST_FIELDS = (
    "schema",
    "tool_version",
    "review_report_sha256",
    "repository",
    "issue_number",
    "base_sha",
    "head_sha",
    "issue_body_sha256",
    "diff_sha256",
    "remediation_round_id",
    "reviewer_class",
    "reviewer_execution_id",
    "items",
    "generation",
)
REMEDIATION_ITEM_FIELDS = (
    "finding_id",
    "severity",
    "component_path",
    "problem",
    "required_behavior",
    "required_test",
    "acceptance_criterion",
    "lifecycle",
    "review_report_sha256",
    "remediation_round_id",
)


def _validate_round_id(value: object) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool) and value >= 1,
        "remediation_round_id must be a positive integer",
        error=ReviewInputError,
    )
    return value  # type: ignore[return-value]


def build_remediation_request(review_report_bytes: bytes, remediation_round_id: object) -> dict[str, Any]:
    """Emit a canonical remediation request, or fail closed.

    Fails closed unless the review report is valid, requests changes (never an
    accepting verdict) and carries at least one open finding to act on.
    """

    round_id = _validate_round_id(remediation_round_id)
    report = validate_review_report_document(review_report_bytes)
    review_report_sha256 = sha256_hex(review_report_bytes)

    require(
        report["verdict"] not in ACCEPTANCE_VERDICTS,
        "remediation cannot be derived from an accepting review verdict",
        error=ReviewInputError,
    )

    open_findings = [f for f in report["findings"] if f["lifecycle"] in OPEN_LIFECYCLE_STATES]
    require(open_findings, "review report has no open finding to remediate", error=ReviewInputError)

    items = sorted(
        (
            {
                "finding_id": finding["finding_id"],
                "severity": finding["severity"],
                "component_path": finding["component_path"],
                "problem": finding["problem"],
                "required_behavior": finding["required_behavior"],
                "required_test": finding["required_test"],
                "acceptance_criterion": finding["acceptance_criterion"],
                "lifecycle": finding["lifecycle"],
                "review_report_sha256": review_report_sha256,
                "remediation_round_id": round_id,
            }
            for finding in open_findings
        ),
        key=lambda item: item["finding_id"],
    )

    request = {
        "schema": REMEDIATION_REQUEST_SCHEMA_ID,
        "tool_version": TOOL_VERSION,
        "review_report_sha256": review_report_sha256,
        "repository": report["repository"],
        "issue_number": report["issue_number"],
        "base_sha": report["base_sha"],
        "head_sha": report["head_sha"],
        "issue_body_sha256": report["issue_body_sha256"],
        "diff_sha256": report["diff_sha256"],
        "remediation_round_id": round_id,
        "reviewer_class": report["reviewer_class"],
        "reviewer_execution_id": report["reviewer_execution_id"],
        "items": items,
        "generation": generation_stanza(),
    }
    return request


def remediation_request_bytes(request: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(request)
