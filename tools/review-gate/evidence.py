"""Consumption and cross-binding of the technical evidence pair.

The review gate consumes two read-only documents produced upstream:

- ``styx.task-scope-report/v1`` (owned by the scope guard), and
- ``styx.test-report/v1`` (owned exclusively by task #54).

Neither schema is redefined, duplicated or mutated here. Only the frozen
minimum interface declared by the task contract is validated, plus the exact
cross-binding required before a review may start. Any missing, ambiguous,
duplicated, malformed, stale or cross-linked field fails closed.
"""

from __future__ import annotations

from typing import Any, Mapping

from model import (
    CLASS_VERDICTS,
    EVIDENCE_VERDICTS,
    EvidenceError,
    IdentityError,
    PreconditionError,
    SCOPE_REPORT_SCHEMA_ID,
    SHA256_RE,
    SHA_RE,
    TEST_REPORT_SCHEMA_ID,
    load_strict_json,
    require,
    sha256_hex,
    validate_canonical_id,
)

# Frozen minimum test-report interface consumed by #55 (per the contract:
# Issue, execution, base, HEAD, Issue-body hash, plan hash, scope-report hash,
# per-class verdicts, failures, generation and overall verdict). Additional
# fields owned by #54 (e.g. command_policy_sha256) are tolerated but never
# required, so this consumer does not couple to the full #54 shape.
TEST_REPORT_CLASS_FIELDS = (
    "mandatory_verdict",
    "regression_verdict",
    "generated_verdict",
    "adversarial_verdict",
    "static_verdict",
    "rollback_verdict",
)
TEST_REPORT_REQUIRED_FIELDS = (
    "schema",
    "issue_number",
    "execution_id",
    "base_sha",
    "head_sha",
    "issue_body_sha256",
    "plan_sha256",
    "scope_report_sha256",
    *TEST_REPORT_CLASS_FIELDS,
    "failures",
    "generation",
    "verdict",
)

# ``execution_id`` is part of the authoritative styx.task-scope-report/v1 shape
# declared on the base; it is consumed here (never redefined) because it is the
# only evidence-anchored statement of who produced the candidate, and the
# reviewer independence decision is derived from it.
SCOPE_REPORT_REQUIRED_FIELDS = (
    "schema",
    "issue_number",
    "execution_id",
    "base_sha",
    "head_sha",
    "issue_body_sha256",
    "changed_entries",
    "verdict",
)


class Evidence:
    """A validated, cross-bound scope + test evidence pair."""

    def __init__(
        self,
        *,
        scope_report: Mapping[str, Any],
        scope_report_bytes: bytes,
        test_report: Mapping[str, Any],
        test_report_bytes: bytes,
    ):
        self.scope_report = scope_report
        self.scope_report_bytes = scope_report_bytes
        self.scope_report_sha256 = sha256_hex(scope_report_bytes)
        self.test_report = test_report
        self.test_report_bytes = test_report_bytes
        self.test_report_sha256 = sha256_hex(test_report_bytes)

    @property
    def execution_id(self) -> str:
        """The authoritative implementer execution id.

        Taken from the scope report and guaranteed by ``load_evidence`` to be
        identical in the test report. This is the only implementer identity the
        gate trusts: a value declared by the reviewer in the review request is
        accepted solely as an exact restatement of it.
        """

        return self.scope_report["execution_id"]

    @property
    def issue_number(self) -> int:
        return self.test_report["issue_number"]

    @property
    def base_sha(self) -> str:
        return self.test_report["base_sha"]

    @property
    def head_sha(self) -> str:
        return self.test_report["head_sha"]

    @property
    def issue_body_sha256(self) -> str:
        return self.test_report["issue_body_sha256"]

    @property
    def scope_verdict(self) -> str:
        return self.scope_report["verdict"]

    @property
    def test_verdict(self) -> str:
        return self.test_report["verdict"]


def _is_sha(value: object) -> bool:
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def validate_scope_report(raw_bytes: bytes) -> dict[str, Any]:
    document = load_strict_json(raw_bytes, source="scope report", error=EvidenceError)
    require(isinstance(document, dict), "scope report must be a JSON object", error=EvidenceError)
    for field in SCOPE_REPORT_REQUIRED_FIELDS:
        require(field in document, f"scope report is missing field: {field}", error=EvidenceError)
    require(
        document["schema"] == SCOPE_REPORT_SCHEMA_ID,
        "scope report has an unexpected schema identifier",
        error=EvidenceError,
    )
    require(
        isinstance(document["issue_number"], int) and not isinstance(document["issue_number"], bool) and document["issue_number"] >= 1,
        "scope report issue_number must be a positive integer",
        error=EvidenceError,
    )
    validate_canonical_id(document["execution_id"], "scope report execution_id", error=EvidenceError)
    for field in ("base_sha", "head_sha"):
        require(_is_sha(document[field]), f"scope report {field} must be a full lowercase commit SHA", error=EvidenceError)
    require(_is_sha256(document["issue_body_sha256"]), "scope report issue_body_sha256 is malformed", error=EvidenceError)
    require(isinstance(document["changed_entries"], list), "scope report changed_entries must be an array", error=EvidenceError)
    require(document["verdict"] in EVIDENCE_VERDICTS, "scope report verdict is not recognised", error=EvidenceError)
    return document


def validate_test_report(raw_bytes: bytes) -> dict[str, Any]:
    document = load_strict_json(raw_bytes, source="test report", error=EvidenceError)
    require(isinstance(document, dict), "test report must be a JSON object", error=EvidenceError)
    for field in TEST_REPORT_REQUIRED_FIELDS:
        require(field in document, f"test report is missing field: {field}", error=EvidenceError)
    require(
        document["schema"] == TEST_REPORT_SCHEMA_ID,
        "test report has an unexpected schema identifier",
        error=EvidenceError,
    )
    require(
        isinstance(document["issue_number"], int) and not isinstance(document["issue_number"], bool) and document["issue_number"] >= 1,
        "test report issue_number must be a positive integer",
        error=EvidenceError,
    )
    validate_canonical_id(document["execution_id"], "test report execution_id", error=EvidenceError)
    for field in ("base_sha", "head_sha"):
        require(_is_sha(document[field]), f"test report {field} must be a full lowercase commit SHA", error=EvidenceError)
    for field in ("issue_body_sha256", "plan_sha256", "scope_report_sha256"):
        require(_is_sha256(document[field]), f"test report {field} must be a sha256 digest", error=EvidenceError)
    for field in TEST_REPORT_CLASS_FIELDS:
        require(document[field] in CLASS_VERDICTS, f"test report {field} is not a class verdict", error=EvidenceError)
    require(isinstance(document["failures"], list), "test report failures must be an array", error=EvidenceError)
    require(document["verdict"] in EVIDENCE_VERDICTS, "test report verdict is not recognised", error=EvidenceError)
    return document


def load_evidence(scope_report_bytes: bytes, test_report_bytes: bytes) -> Evidence:
    """Validate both documents and cross-bind them.

    Cross-binding rejects a test report paired with a foreign scope report
    (cross-linked evidence), and any Issue / base / HEAD / body-hash divergence
    between the two documents.
    """

    scope = validate_scope_report(scope_report_bytes)
    test = validate_test_report(test_report_bytes)
    evidence = Evidence(
        scope_report=scope,
        scope_report_bytes=scope_report_bytes,
        test_report=test,
        test_report_bytes=test_report_bytes,
    )

    require(
        test["scope_report_sha256"] == evidence.scope_report_sha256,
        "test report is bound to a different scope report (cross-linked evidence)",
        error=PreconditionError,
    )
    # The authoritative implementer identity must be stated identically by both
    # halves of the evidence pair; a divergence means the pair does not describe
    # one execution and no implementer identity can be derived from it.
    require(
        scope["execution_id"] == test["execution_id"],
        "scope and test reports bind different implementer executions",
        error=IdentityError,
    )
    require(scope["issue_number"] == test["issue_number"], "scope and test reports bind different issues", error=PreconditionError)
    require(scope["base_sha"] == test["base_sha"], "scope and test reports bind different base commits", error=PreconditionError)
    require(scope["head_sha"] == test["head_sha"], "scope and test reports bind different candidate HEADs", error=PreconditionError)
    require(
        scope["issue_body_sha256"] == test["issue_body_sha256"],
        "scope and test reports bind different Issue bodies",
        error=PreconditionError,
    )
    return evidence
