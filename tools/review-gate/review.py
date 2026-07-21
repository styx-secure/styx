"""Review request validation, verdict rules and canonical review report.

A review may only start when the technical evidence pair is green and every
identity, binding and independence constraint holds. The reviewer authors a
closed-shape review request; this module validates it against the evidence,
applies the frozen verdict and finding rules, and emits a canonical
``styx.review-report/v1`` document. It never runs tests, never touches git and
never publishes anything.

Trust boundary of the declared candidate
----------------------------------------

The review request is reviewer-authored input and is trusted only where it is
checked against evidence:

- ``base_sha`` + ``head_sha`` are the **authoritative binding of the code
  state**. Both are stated independently by the scope and test reports and must
  match the candidate exactly, so the reviewed tree is pinned to one commit.
- ``implementer_execution_id`` is **not** an identity claim the gate believes:
  the authoritative implementer identity is derived from the evidence
  (``Evidence.execution_id``) and the candidate's value is accepted only as an
  exact restatement of it. Independence is decided against the evidence-derived
  identity, never against the declared one.
- ``diff_sha256`` is **advisory metadata only**. The consumed frozen evidence
  interface carries no diff digest, so this value is unauthenticated reviewer
  input and cannot be verified against a bound source. No security decision may
  rest on it: it is recorded for correlation, and it participates in
  invalidation only in the one-way direction where a *changed* digest can
  additionally invalidate a prior acceptance. It can never make invalid
  evidence valid, never substitute for the base/HEAD binding, and never rescue
  an acceptance whose HEAD has moved. Deriving a trustworthy digest would
  require a diff hash inside the evidence, which #55 does not own.
- ``implementer_context_id`` likewise has no anchor in the frozen evidence
  interface. It is retained as defence in depth (a reviewer reusing the
  implementer's context id is rejected) but, unlike the execution id, it is not
  evidence-bound and no acceptance rests on it alone.
"""

from __future__ import annotations

from typing import Any, Mapping

from evidence import Evidence
from model import (
    ACCEPTANCE_VERDICTS,
    IdentityError,
    OPEN_LIFECYCLE_STATES,
    LIFECYCLE_STATES,
    PreconditionError,
    REVIEW_REPORT_SCHEMA_ID,
    REVIEWER_CLASSES,
    ReviewInputError,
    SEVERE_SEVERITIES,
    SEVERITIES,
    SHA256_RE,
    SHA_RE,
    TOOL_VERSION,
    VERDICTS,
    canonical_json_bytes,
    generation_stanza,
    ids_conflict,
    normalize_component_path,
    redact_text,
    require,
    sha256_hex,
    validate_canonical_id,
)

CANDIDATE_FIELDS = (
    "repository",
    "issue_number",
    "issue_body_sha256",
    "base_sha",
    "head_sha",
    "diff_sha256",
    "implementer_execution_id",
    "implementer_context_id",
)
REVIEWER_FIELDS = ("reviewer_class", "execution_id", "context_id", "identity_ref")
REVIEW_REQUEST_FIELDS = ("candidate", "reviewer", "verdict", "findings")
FINDING_INPUT_FIELDS = (
    "severity",
    "component_path",
    "problem",
    "required_behavior",
    "required_test",
    "acceptance_criterion",
    "lifecycle",
    "required_fix",
)
FINDING_OUTPUT_FIELDS = ("finding_id", *FINDING_INPUT_FIELDS)
# Fields that carry free reviewer prose and must be redacted before output.
FINDING_TEXT_FIELDS = ("problem", "required_behavior", "required_test", "acceptance_criterion")

REVIEW_REPORT_FIELDS = (
    "schema",
    "tool_version",
    "repository",
    "issue_number",
    "base_sha",
    "head_sha",
    "issue_body_sha256",
    "diff_sha256",
    "scope_report_sha256",
    "test_report_sha256",
    "scope_verdict",
    "test_verdict",
    "reviewer_class",
    "reviewer_execution_id",
    "reviewer_context_id",
    "reviewer_identity_ref",
    "implementer_execution_id",
    "implementer_context_id",
    "independent",
    "verdict",
    "remediation_required",
    "findings",
    "generation",
)

# Binding fields whose change invalidates a prior acceptance.
#
# base_sha and head_sha are the authoritative code-state binding: they are
# stated by the evidence and checked against the candidate. diff_sha256 is
# advisory (see the module docstring) and appears here only so that a *changed*
# digest can additionally invalidate; it can never validate anything, because a
# matching digest is never sufficient for any field of this tuple to match.
ACCEPTANCE_BINDING_FIELDS = (
    "repository",
    "issue_number",
    "base_sha",
    "head_sha",
    "issue_body_sha256",
    "diff_sha256",
)


def _require_nonempty_str(value: object, field: str) -> None:
    require(isinstance(value, str) and value != "", f"{field} must be a non-empty string", error=ReviewInputError)


def _require_sha(value: object, field: str) -> None:
    require(isinstance(value, str) and SHA_RE.fullmatch(value) is not None, f"{field} must be a full lowercase commit SHA", error=ReviewInputError)


def _require_sha256(value: object, field: str) -> None:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{field} must be a sha256 digest", error=ReviewInputError)


def _validate_candidate(candidate: object) -> dict[str, Any]:
    require(isinstance(candidate, dict), "review request candidate must be a JSON object", error=ReviewInputError)
    require(set(candidate) == set(CANDIDATE_FIELDS), f"candidate has missing or unknown fields; expected {sorted(CANDIDATE_FIELDS)}", error=ReviewInputError)
    _require_nonempty_str(candidate["repository"], "candidate.repository")
    require(
        isinstance(candidate["issue_number"], int) and not isinstance(candidate["issue_number"], bool) and candidate["issue_number"] >= 1,
        "candidate.issue_number must be a positive integer",
        error=ReviewInputError,
    )
    _require_sha256(candidate["issue_body_sha256"], "candidate.issue_body_sha256")
    _require_sha(candidate["base_sha"], "candidate.base_sha")
    _require_sha(candidate["head_sha"], "candidate.head_sha")
    # Advisory only: well-formedness is checked, authenticity cannot be.
    _require_sha256(candidate["diff_sha256"], "candidate.diff_sha256")
    validate_canonical_id(candidate["implementer_execution_id"], "candidate.implementer_execution_id")
    validate_canonical_id(candidate["implementer_context_id"], "candidate.implementer_context_id")
    return candidate


def _validate_reviewer(reviewer: object) -> dict[str, Any]:
    require(isinstance(reviewer, dict), "review request reviewer must be a JSON object", error=ReviewInputError)
    require(set(reviewer) == set(REVIEWER_FIELDS), f"reviewer has missing or unknown fields; expected {sorted(REVIEWER_FIELDS)}", error=ReviewInputError)
    require(reviewer["reviewer_class"] in REVIEWER_CLASSES, "reviewer_class must be HUMAN or DELEGATED_AGENT", error=ReviewInputError)
    validate_canonical_id(reviewer["execution_id"], "reviewer.execution_id")
    validate_canonical_id(reviewer["context_id"], "reviewer.context_id")
    # identity_ref is a free-form human/agent reference (e.g. "agent:reviewer"),
    # not an identifier the gate compares; it is not held to the canonical form.
    _require_nonempty_str(reviewer["identity_ref"], "reviewer.identity_ref")
    return reviewer


def _validate_finding(entry: object, position: int) -> dict[str, Any]:
    where = f"finding {position}"
    require(isinstance(entry, dict), f"{where} must be a JSON object", error=ReviewInputError)
    require(set(entry) == set(FINDING_INPUT_FIELDS), f"{where} has missing or unknown fields; expected {sorted(FINDING_INPUT_FIELDS)}", error=ReviewInputError)
    require(entry["severity"] in SEVERITIES, f"{where} severity is not recognised", error=ReviewInputError)
    require(entry["lifecycle"] in LIFECYCLE_STATES, f"{where} lifecycle is not recognised", error=ReviewInputError)
    require(isinstance(entry["required_fix"], bool), f"{where} required_fix must be a boolean", error=ReviewInputError)
    component_path = normalize_component_path(entry["component_path"])
    for field in FINDING_TEXT_FIELDS:
        _require_nonempty_str(entry[field], f"{where}.{field}")

    normalized = {
        "severity": entry["severity"],
        "component_path": component_path,
        "problem": redact_text(entry["problem"]),
        "required_behavior": redact_text(entry["required_behavior"]),
        "required_test": redact_text(entry["required_test"]),
        "acceptance_criterion": redact_text(entry["acceptance_criterion"]),
        "lifecycle": entry["lifecycle"],
        "required_fix": entry["required_fix"],
    }
    normalized["finding_id"] = _finding_id(normalized)
    return normalized


def _finding_id(finding: Mapping[str, Any]) -> str:
    """Stable, canonical identifier: identical semantics hash identically
    across remediation rounds, independent of lifecycle or criterion edits."""

    material = canonical_json_bytes(
        {
            "component_path": finding["component_path"],
            "problem": finding["problem"],
            "required_behavior": finding["required_behavior"],
            "severity": finding["severity"],
        }
    )
    return sha256_hex(material)


def _apply_precondition(candidate: Mapping[str, Any], evidence: Evidence) -> None:
    """Bind the declared candidate to the evidence and require green PASS.

    Rejects base, HEAD and Issue-body drift, and refuses to start a review
    over non-PASS technical evidence.
    """

    require(evidence.scope_verdict == "PASS", "scope report verdict is not PASS", error=PreconditionError)
    require(evidence.test_verdict == "PASS", "test report verdict is not PASS", error=PreconditionError)
    require(candidate["issue_number"] == evidence.issue_number, "candidate binds a different Issue than the evidence", error=PreconditionError)
    require(candidate["base_sha"] == evidence.base_sha, "candidate binds a different base than the evidence", error=PreconditionError)
    require(candidate["head_sha"] == evidence.head_sha, "candidate HEAD differs from the evidence HEAD (stale or drifted)", error=PreconditionError)
    require(candidate["issue_body_sha256"] == evidence.issue_body_sha256, "candidate Issue body hash differs from the evidence", error=PreconditionError)


def _bind_implementer_identity(candidate: Mapping[str, Any], evidence: Evidence) -> str:
    """Return the evidence-derived implementer identity, or fail closed.

    Runs before any independence check. The authoritative implementer execution
    id is the one carried by the evidence pair (``load_evidence`` has already
    proven the scope and test reports agree on it); the candidate's declaration
    is accepted only as an exact restatement.

    Without this binding a self-reviewing implementer could declare a decoy
    ``implementer_execution_id``, differ from it trivially, and obtain GO on
    their own work: the independence check would compare the reviewer against a
    value the reviewer itself chose.
    """

    authoritative = validate_canonical_id(evidence.execution_id, "evidence execution_id")
    require(
        candidate["implementer_execution_id"] == authoritative,
        "candidate implementer_execution_id is not the execution id bound by the evidence",
        error=IdentityError,
    )
    return authoritative


def _apply_independence(reviewer: Mapping[str, Any], *, implementer_execution_id: str, implementer_context_id: str) -> None:
    """Self-review and reused-implementer-context rejection (fail closed).

    ``implementer_execution_id`` must be the evidence-derived identity returned
    by ``_bind_implementer_identity``, never the candidate's declared value.
    """

    require(
        not ids_conflict(reviewer["execution_id"], implementer_execution_id),
        "self-review is not permitted: reviewer reuses the implementer execution id",
        error=IdentityError,
    )
    require(
        not ids_conflict(reviewer["context_id"], implementer_context_id),
        "reviewer reuses the implementer context id",
        error=IdentityError,
    )


def _apply_verdict_rules(verdict: str, reviewer: Mapping[str, Any], findings: list[Mapping[str, Any]]) -> None:
    open_findings = [f for f in findings if f["lifecycle"] in OPEN_LIFECYCLE_STATES]
    severe_open = [f for f in open_findings if f["severity"] in SEVERE_SEVERITIES or f["required_fix"]]

    waived = [f for f in findings if f["lifecycle"] == "WAIVED_BY_HUMAN"]
    if reviewer["reviewer_class"] == "DELEGATED_AGENT":
        require(
            not waived,
            "a delegated agent cannot waive findings; WAIVED_BY_HUMAN requires a human reviewer",
            error=IdentityError,
        )
        # A bare RESOLVED assertion is not evidence of a fix. Marking a finding
        # RESOLVED excludes it from the open/severe evaluation below, so without
        # this rule a delegated agent could clear its own BLOCKER and reach GO
        # with no new HEAD, no fix evidence and no re-verification -- the waiver
        # denial above in all but name.
        #
        # The frozen v1 shapes carry no way to *prove* a cross-round
        # re-verification (no prior review-report hash, no prior HEAD), and a
        # weak substitute would be worse than none. So this version fails closed
        # on the strict rule: final resolution of a severe or required-fix
        # finding is reserved to a human reviewer. A delegated agent may still
        # record such a finding as RESOLVED under a non-accepting verdict.
        if verdict in ACCEPTANCE_VERDICTS:
            self_cleared = [
                f
                for f in findings
                if f["lifecycle"] == "RESOLVED" and (f["severity"] in SEVERE_SEVERITIES or f["required_fix"])
            ]
            require(
                not self_cleared,
                f"{verdict} is invalid: a delegated agent cannot clear a BLOCKER, HIGH or required-fix "
                "finding by asserting RESOLVED without verifiable evidence of a new remediation; "
                "final resolution of a severe finding requires a human reviewer",
                error=IdentityError,
            )

    if verdict in ACCEPTANCE_VERDICTS:
        require(
            not severe_open,
            f"{verdict} is invalid while unresolved BLOCKER, HIGH or required-fix findings exist",
            error=PreconditionError,
        )
    if verdict in ("CHANGES_REQUESTED", "BLOCKED"):
        require(
            open_findings,
            f"{verdict} requires at least one OPEN or ADDRESSED_PENDING_REVERIFY finding",
            error=ReviewInputError,
        )


def validate_review_request(raw_request: Mapping[str, Any]) -> dict[str, Any]:
    require(isinstance(raw_request, dict), "review request must be a JSON object", error=ReviewInputError)
    require(set(raw_request) == set(REVIEW_REQUEST_FIELDS), f"review request has missing or unknown fields; expected {sorted(REVIEW_REQUEST_FIELDS)}", error=ReviewInputError)
    candidate = _validate_candidate(raw_request["candidate"])
    reviewer = _validate_reviewer(raw_request["reviewer"])
    require(raw_request["verdict"] in VERDICTS, "review verdict is not recognised", error=ReviewInputError)
    require(isinstance(raw_request["findings"], list), "review findings must be an array", error=ReviewInputError)
    findings = [_validate_finding(entry, position) for position, entry in enumerate(raw_request["findings"])]
    return {"candidate": candidate, "reviewer": reviewer, "verdict": raw_request["verdict"], "findings": findings}


def build_review_report(request: Mapping[str, Any], evidence: Evidence) -> dict[str, Any]:
    """Produce the canonical review report, or fail closed."""

    candidate = request["candidate"]
    reviewer = request["reviewer"]
    verdict = request["verdict"]
    findings = request["findings"]

    _apply_precondition(candidate, evidence)
    implementer_execution_id = _bind_implementer_identity(candidate, evidence)
    _apply_independence(
        reviewer,
        implementer_execution_id=implementer_execution_id,
        implementer_context_id=candidate["implementer_context_id"],
    )
    _apply_verdict_rules(verdict, reviewer, findings)

    output_findings = sorted(
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
                "required_fix": finding["required_fix"],
            }
            for finding in findings
        ),
        key=lambda f: f["finding_id"],
    )
    # Reject two findings that collapse to the same canonical identity.
    ids = [f["finding_id"] for f in output_findings]
    require(len(ids) == len(set(ids)), "findings collapse to a duplicate canonical identifier", error=ReviewInputError)

    report = {
        "schema": REVIEW_REPORT_SCHEMA_ID,
        "tool_version": TOOL_VERSION,
        "repository": redact_text(candidate["repository"]),
        "issue_number": candidate["issue_number"],
        "base_sha": candidate["base_sha"],
        "head_sha": candidate["head_sha"],
        "issue_body_sha256": candidate["issue_body_sha256"],
        # Advisory, unauthenticated; recorded for correlation only.
        "diff_sha256": candidate["diff_sha256"],
        "scope_report_sha256": evidence.scope_report_sha256,
        "test_report_sha256": evidence.test_report_sha256,
        "scope_verdict": evidence.scope_verdict,
        "test_verdict": evidence.test_verdict,
        "reviewer_class": reviewer["reviewer_class"],
        "reviewer_execution_id": reviewer["execution_id"],
        "reviewer_context_id": reviewer["context_id"],
        "reviewer_identity_ref": redact_text(reviewer["identity_ref"]),
        # Evidence-derived, not the declared value (they are equal by the
        # binding above, but the report records the authoritative source).
        "implementer_execution_id": implementer_execution_id,
        # Not evidence-anchored; see the module docstring.
        "implementer_context_id": candidate["implementer_context_id"],
        "independent": True,
        "verdict": verdict,
        "remediation_required": verdict == "CHANGES_REQUESTED",
        "findings": output_findings,
        "generation": generation_stanza(),
    }
    return report


def review_report_bytes(report: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(report)


def validate_review_report_document(raw_bytes: bytes) -> dict[str, Any]:
    """Strictly re-validate a produced review report before it is reconsumed.

    Enforces canonical bytes, closed shape, schema identifier, enums, binding
    digests and per-finding closed shape, so remediation can never be derived
    from a malformed or tampered review report.
    """

    from model import load_strict_json  # local import: keep module import graph flat

    report = load_strict_json(raw_bytes, source="review report", error=ReviewInputError)
    require(isinstance(report, dict), "review report must be a JSON object", error=ReviewInputError)
    require(canonical_json_bytes(report) == raw_bytes, "review report is not in canonical JSON form", error=ReviewInputError)
    require(set(report) == set(REVIEW_REPORT_FIELDS), "review report has missing or unknown fields", error=ReviewInputError)
    require(report["schema"] == REVIEW_REPORT_SCHEMA_ID, "review report has an unexpected schema identifier", error=ReviewInputError)
    _require_nonempty_str(report["tool_version"], "review report tool_version")
    _require_nonempty_str(report["repository"], "review report repository")
    require(
        isinstance(report["issue_number"], int) and not isinstance(report["issue_number"], bool) and report["issue_number"] >= 1,
        "review report issue_number must be a positive integer",
        error=ReviewInputError,
    )
    _require_sha(report["base_sha"], "review report base_sha")
    _require_sha(report["head_sha"], "review report head_sha")
    for field in ("issue_body_sha256", "diff_sha256", "scope_report_sha256", "test_report_sha256"):
        _require_sha256(report[field], f"review report {field}")
    require(report["scope_verdict"] == "PASS", "review report scope_verdict must be PASS", error=ReviewInputError)
    require(report["test_verdict"] == "PASS", "review report test_verdict must be PASS", error=ReviewInputError)
    require(report["reviewer_class"] in REVIEWER_CLASSES, "review report reviewer_class is not recognised", error=ReviewInputError)
    # Identifiers must still be canonical when a report is re-consumed, so a
    # tampered report cannot carry a non-canonical identity into remediation.
    for field in ("reviewer_execution_id", "reviewer_context_id", "implementer_execution_id", "implementer_context_id"):
        validate_canonical_id(report[field], f"review report {field}")
    _require_nonempty_str(report["reviewer_identity_ref"], "review report reviewer_identity_ref")
    require(report["independent"] is True, "review report independent flag must be true", error=ReviewInputError)
    require(report["verdict"] in VERDICTS, "review report verdict is not recognised", error=ReviewInputError)
    require(isinstance(report["remediation_required"], bool), "review report remediation_required must be a boolean", error=ReviewInputError)
    require(report["generation"] == generation_stanza(), "review report generation stanza is unexpected", error=ReviewInputError)
    require(isinstance(report["findings"], list), "review report findings must be an array", error=ReviewInputError)
    for position, finding in enumerate(report["findings"]):
        _validate_output_finding(finding, position)
    return report


def _validate_output_finding(finding: object, position: int) -> None:
    where = f"review report finding {position}"
    require(isinstance(finding, dict), f"{where} must be a JSON object", error=ReviewInputError)
    require(set(finding) == set(FINDING_OUTPUT_FIELDS), f"{where} has missing or unknown fields", error=ReviewInputError)
    _require_sha256(finding["finding_id"], f"{where} finding_id")
    require(finding["severity"] in SEVERITIES, f"{where} severity is not recognised", error=ReviewInputError)
    normalize_component_path(finding["component_path"])
    require(finding["lifecycle"] in LIFECYCLE_STATES, f"{where} lifecycle is not recognised", error=ReviewInputError)
    require(isinstance(finding["required_fix"], bool), f"{where} required_fix must be a boolean", error=ReviewInputError)
    for field in FINDING_TEXT_FIELDS:
        _require_nonempty_str(finding[field], f"{where}.{field}")


def acceptance_still_valid(prior_report: Mapping[str, Any], candidate: Mapping[str, Any]) -> bool:
    """True only if a prior acceptance still binds the current candidate.

    Any change to repository, Issue, base, HEAD, Issue-body hash or diff hash
    invalidates the prior acceptance: a new candidate requires a fresh
    scope -> test -> review cycle.
    """

    if prior_report.get("verdict") not in ACCEPTANCE_VERDICTS:
        return False
    for field in ACCEPTANCE_BINDING_FIELDS:
        if prior_report.get(field) != candidate.get(field):
            return False
    return True
