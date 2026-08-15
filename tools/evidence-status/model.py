"""Deterministic model for the non-authoritative Styx evidence observer.

This module deliberately does not import any evidence producer.  It observes
their frozen v1 documents without becoming a gate or an alternate validator.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Callable, Mapping

SCHEMA_ID = "styx.evidence-status/v1"
TOOL_VERSION = "0.1.0"

SCOPE_SCHEMA = "styx.task-scope-report/v1"
TEST_SCHEMA = "styx.test-report/v1"
REVIEW_SCHEMA = "styx.review-report/v1"

EXIT_DIAGNOSTIC = 0
EXIT_INPUT = 2
EXIT_INTERNAL = 3

MAX_INPUT_BYTES = 1_048_576
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
REPOSITORY_RE = re.compile(r"^(?!\.{1,2}/)[A-Za-z0-9_.-]+/(?!\.{1,2}$)[A-Za-z0-9_.-]+$")

STATES = ("CURRENT", "STALE", "MISSING", "CONTRADICTORY", "UNPROVABLE", "INVALID")
REASONS = (
    "IDENTITY_MATCH",
    "REPOSITORY_MISMATCH",
    "ISSUE_MISMATCH",
    "ISSUE_BODY_MISMATCH",
    "BASE_MISMATCH",
    "HEAD_MISMATCH",
    "DIFF_MISMATCH",
    "TOOL_MISMATCH",
    "SCHEMA_MISMATCH",
    "CONCLUSION_NOT_GREEN",
    "FIELD_NOT_AVAILABLE",
    "FILE_MISSING",
    "MALFORMED_JSON",
    "NON_CANONICAL_JSON",
    "DUPLICATE_KEY",
    "INPUT_TOO_LARGE",
    "CONTRADICTORY_ARTIFACTS",
)

CANDIDATE_FIELDS = {
    "repository",
    "issue_number",
    "base_sha",
    "head_sha",
    "issue_body_sha256",
    "diff_sha256",
    "tool_versions",
}
TOOL_VERSION_FIELDS = {"scope", "review"}

SCOPE_FIELDS = {
    "schema",
    "tool_version",
    "issue_number",
    "execution_id",
    "base_sha",
    "head_sha",
    "issue_body_sha256",
    "contract_version",
    "allowed_patterns",
    "forbidden_patterns",
    "changed_entries",
    "diagnostics",
    "generation",
    "verdict",
}
TEST_FIELDS = {
    "schema",
    "issue_number",
    "execution_id",
    "base_sha",
    "head_sha",
    "issue_body_sha256",
    "plan_sha256",
    "scope_report_sha256",
    "command_policy_sha256",
    "mandatory_verdict",
    "regression_verdict",
    "generated_verdict",
    "adversarial_verdict",
    "static_verdict",
    "rollback_verdict",
    "failures",
    "generation",
    "verdict",
}
REVIEW_FIELDS = {
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
}

GENERATION = {"canonical_json": "RFC8259-sort-keys-utf8-lf", "timestamp_omitted": True}
OBSERVED_FIELDS = (
    "schema",
    "repository",
    "issue_number",
    "base_sha",
    "head_sha",
    "issue_body_sha256",
    "diff_sha256",
    "tool_version",
    "conclusion_green",
)


class ObserverError(Exception):
    """Base class for deterministic observer failures."""

    code = "E_INTERNAL"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class InputError(ObserverError):
    code = "E_INPUT"


class OutputError(ObserverError):
    code = "E_OUTPUT"


class DuplicateKeyError(ValueError):
    """Raised when strict JSON encounters a duplicate object key."""


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(key)
        value[key] = item
    return value


def parse_json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicate_keys)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _is_semver(value: Any) -> bool:
    return isinstance(value, str) and SEMVER_RE.fullmatch(value) is not None


def _valid_generation(value: Any) -> bool:
    return value == GENERATION


def _nullable(value: Any, validator: Callable[[Any], bool]) -> bool:
    return value is None or validator(value)


def load_candidate(raw: bytes) -> dict[str, Any]:
    try:
        candidate = parse_json(raw)
    except DuplicateKeyError as exc:
        raise InputError("candidate contains a duplicate JSON key") from exc
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError(f"candidate is not strict JSON: {exc}") from exc
    if not isinstance(candidate, dict) or set(candidate) != CANDIDATE_FIELDS:
        raise InputError("candidate must be a closed object with the documented fields")
    if (
        not isinstance(candidate["repository"], str)
        or REPOSITORY_RE.fullmatch(candidate["repository"]) is None
    ):
        raise InputError("candidate repository must be a canonical owner/name identifier")
    if not _is_int(candidate["issue_number"]) or candidate["issue_number"] < 1:
        raise InputError("candidate issue_number must be a positive integer")
    for field in ("base_sha", "head_sha"):
        if not _is_sha(candidate[field]):
            raise InputError(f"candidate {field} must be a full lowercase commit SHA")
    for field in ("issue_body_sha256", "diff_sha256"):
        if not _is_sha256(candidate[field]):
            raise InputError(f"candidate {field} must be a sha256 digest")
    versions = candidate["tool_versions"]
    if not isinstance(versions, dict) or set(versions) != TOOL_VERSION_FIELDS:
        raise InputError("candidate tool_versions must contain exactly scope and review")
    for kind, version in versions.items():
        if not _is_semver(version):
            raise InputError(f"candidate tool_versions.{kind} must be semantic version text")
    return candidate


def _literal_path(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise InputError(f"{label} path must be absolute and contain no parent segments")
    walk = path
    while True:
        if walk.is_symlink():
            raise InputError(f"{label} path must not traverse a symlink")
        if walk.parent == walk:
            break
        walk = walk.parent
    return path


def read_required(path: Path, *, label: str) -> bytes:
    path = _literal_path(path, label=label)
    try:
        info = path.stat()
    except OSError as exc:
        raise InputError(f"{label} cannot be read: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise InputError(f"{label} must be a regular file")
    if info.st_size > MAX_INPUT_BYTES:
        raise InputError(f"{label} exceeds {MAX_INPUT_BYTES} bytes")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise InputError(f"{label} cannot be read: {exc}") from exc


def read_evidence(path: Path, *, label: str) -> tuple[bytes | None, str | None]:
    path = _literal_path(path, label=label)
    try:
        info = path.stat()
    except FileNotFoundError:
        return None, "FILE_MISSING"
    except OSError as exc:
        raise InputError(f"{label} cannot be inspected: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise InputError(f"{label} must be a regular file")
    if info.st_size > MAX_INPUT_BYTES:
        return None, "INPUT_TOO_LARGE"
    try:
        return path.read_bytes(), None
    except OSError as exc:
        raise InputError(f"{label} cannot be read: {exc}") from exc


def _empty_observed() -> dict[str, Any]:
    return {field: None for field in OBSERVED_FIELDS}


def _invalid_item(kind: str, reason: str, raw: bytes | None = None) -> dict[str, Any]:
    return {
        "kind": kind,
        "state": "MISSING" if reason == "FILE_MISSING" else "INVALID",
        "reasons": [reason],
        "artifact_sha256": sha256_hex(raw) if raw is not None else None,
        "observed": _empty_observed(),
    }


def _basic_shape(kind: str, document: dict[str, Any]) -> bool:
    expected_fields = {"scope": SCOPE_FIELDS, "test": TEST_FIELDS, "review": REVIEW_FIELDS}[kind]
    expected_schema = {"scope": SCOPE_SCHEMA, "test": TEST_SCHEMA, "review": REVIEW_SCHEMA}[kind]
    if set(document) != expected_fields or document.get("schema") != expected_schema:
        return False
    if not _valid_generation(document.get("generation")):
        return False
    if kind in {"scope", "review"} and not _is_semver(document.get("tool_version")):
        return False
    if kind == "scope":
        return (
            _nullable(document.get("issue_number"), lambda value: _is_int(value) and value >= 1)
            and _nullable(document.get("base_sha"), _is_sha)
            and _nullable(document.get("head_sha"), _is_sha)
            and _nullable(document.get("issue_body_sha256"), _is_sha256)
            and isinstance(document.get("execution_id"), str)
            and document.get("contract_version") in {"v1", None}
            and document.get("verdict") in {"PASS", "FAIL", "ERROR"}
            and isinstance(document.get("changed_entries"), list)
            and isinstance(document.get("diagnostics"), list)
            and isinstance(document.get("allowed_patterns"), list)
            and isinstance(document.get("forbidden_patterns"), list)
            and all(isinstance(value, str) and bool(value) for value in document["allowed_patterns"])
            and all(isinstance(value, str) and bool(value) for value in document["forbidden_patterns"])
        )
    if kind == "test":
        digests = ("plan_sha256", "scope_report_sha256", "command_policy_sha256")
        classes = (
            "mandatory_verdict",
            "regression_verdict",
            "generated_verdict",
            "adversarial_verdict",
            "static_verdict",
            "rollback_verdict",
        )
        return (
            _is_int(document.get("issue_number"))
            and document["issue_number"] >= 1
            and _is_sha(document.get("base_sha"))
            and _is_sha(document.get("head_sha"))
            and _is_sha256(document.get("issue_body_sha256"))
            and isinstance(document.get("execution_id"), str)
            and bool(document["execution_id"])
            and all(_is_sha256(document.get(field)) for field in digests)
            and all(document.get(field) in {"PASS", "FAIL", "ERROR", "NOT_RUN"} for field in classes)
            and isinstance(document.get("failures"), list)
            and document.get("verdict") in {"PASS", "FAIL", "ERROR"}
        )
    return (
        isinstance(document.get("repository"), str)
        and REPOSITORY_RE.fullmatch(document["repository"]) is not None
        and _is_int(document.get("issue_number"))
        and document["issue_number"] >= 1
        and _is_sha(document.get("base_sha"))
        and _is_sha(document.get("head_sha"))
        and _is_sha256(document.get("issue_body_sha256"))
        and all(
            _is_sha256(document.get(field))
            for field in ("diff_sha256", "scope_report_sha256", "test_report_sha256")
        )
        and document.get("scope_verdict") == "PASS"
        and document.get("test_verdict") == "PASS"
        and document.get("reviewer_class") in {"HUMAN", "DELEGATED_AGENT"}
        and all(
            isinstance(document.get(field), str) and bool(document[field])
            for field in (
                "reviewer_execution_id",
                "reviewer_context_id",
                "reviewer_identity_ref",
                "implementer_execution_id",
                "implementer_context_id",
            )
        )
        and document.get("independent") is True
        and document.get("verdict") in {"GO", "GO_WITH_CONDITIONS", "CHANGES_REQUESTED", "BLOCKED"}
        and isinstance(document.get("remediation_required"), bool)
        and document["remediation_required"] == (document["verdict"] == "CHANGES_REQUESTED")
        and isinstance(document.get("findings"), list)
    )


def _observed(kind: str, document: Mapping[str, Any], *, conclusion_green: bool) -> dict[str, Any]:
    observed = _empty_observed()
    observed.update(
        {
            "schema": document.get("schema"),
            "issue_number": document.get("issue_number"),
            "base_sha": document.get("base_sha"),
            "head_sha": document.get("head_sha"),
            "issue_body_sha256": document.get("issue_body_sha256"),
            "conclusion_green": conclusion_green,
        }
    )
    if kind == "review":
        observed["repository"] = document.get("repository")
        observed["diff_sha256"] = document.get("diff_sha256")
    if kind in {"scope", "review"}:
        observed["tool_version"] = document.get("tool_version")
    return observed


def _ordered_reasons(reasons: set[str]) -> list[str]:
    return [reason for reason in REASONS if reason in reasons]


def classify_document(
    kind: str,
    raw: bytes | None,
    read_reason: str | None,
    candidate: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if read_reason is not None:
        return _invalid_item(kind, read_reason), None
    assert raw is not None
    try:
        document = parse_json(raw)
    except DuplicateKeyError:
        return _invalid_item(kind, "DUPLICATE_KEY", raw), None
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        return _invalid_item(kind, "MALFORMED_JSON", raw), None
    if not isinstance(document, dict):
        return _invalid_item(kind, "SCHEMA_MISMATCH", raw), None
    if canonical_json_bytes(document) != raw:
        return _invalid_item(kind, "NON_CANONICAL_JSON", raw), None
    if not _basic_shape(kind, document):
        return _invalid_item(kind, "SCHEMA_MISMATCH", raw), None

    reasons: set[str] = set()
    comparisons = (
        ("issue_number", "ISSUE_MISMATCH"),
        ("issue_body_sha256", "ISSUE_BODY_MISMATCH"),
        ("base_sha", "BASE_MISMATCH"),
        ("head_sha", "HEAD_MISMATCH"),
    )
    unavailable = False
    for field, mismatch_reason in comparisons:
        if document[field] is None:
            unavailable = True
            reasons.add("FIELD_NOT_AVAILABLE")
        elif document[field] != candidate[field]:
            reasons.add(mismatch_reason)
    if kind == "review":
        if document["repository"] != candidate["repository"]:
            reasons.add("REPOSITORY_MISMATCH")
        if document["diff_sha256"] != candidate["diff_sha256"]:
            reasons.add("DIFF_MISMATCH")
    if kind in {"scope", "review"} and document["tool_version"] != candidate["tool_versions"][kind]:
        reasons.add("TOOL_MISMATCH")

    green = (
        document["verdict"] == "PASS"
        if kind in {"scope", "test"}
        else document["verdict"] in {"GO", "GO_WITH_CONDITIONS"}
    )
    if not green:
        reasons.add("CONCLUSION_NOT_GREEN")

    if not reasons:
        state = "CURRENT"
        reasons.add("IDENTITY_MATCH")
    elif unavailable:
        state = "UNPROVABLE"
    elif reasons == {"HEAD_MISMATCH"}:
        # v1 scope/test reports carry no authenticated diff identity and the
        # review diff is explicitly advisory.  The observer can prove the
        # exact-HEAD binding moved, but cannot prove content equivalence or
        # staleness beyond that fact.
        state = "UNPROVABLE"
        reasons.add("FIELD_NOT_AVAILABLE")
    else:
        state = "STALE"

    return (
        {
            "kind": kind,
            "state": state,
            "reasons": _ordered_reasons(reasons),
            "artifact_sha256": sha256_hex(raw),
            "observed": _observed(kind, document, conclusion_green=green),
        },
        document,
    )


def _mark_contradictory(item: dict[str, Any]) -> None:
    if item["state"] in {"INVALID", "MISSING"}:
        return
    item["state"] = "CONTRADICTORY"
    item["reasons"] = _ordered_reasons(set(item["reasons"]) | {"CONTRADICTORY_ARTIFACTS"})


def _mark_unprovable(item: dict[str, Any]) -> None:
    if item["state"] in {"INVALID", "MISSING", "CONTRADICTORY"}:
        return
    if item["state"] == "CURRENT":
        item["state"] = "UNPROVABLE"
    item["reasons"] = _ordered_reasons((set(item["reasons"]) - {"IDENTITY_MATCH"}) | {"FIELD_NOT_AVAILABLE"})


def apply_cross_checks(
    items: list[dict[str, Any]],
    documents: Mapping[str, dict[str, Any] | None],
    raw_by_kind: Mapping[str, bytes | None],
) -> None:
    by_kind = {item["kind"]: item for item in items}
    valid = {kind: doc for kind, doc in documents.items() if doc is not None}
    for field in ("issue_number", "base_sha", "head_sha", "issue_body_sha256"):
        values: dict[Any, list[str]] = {}
        for kind, document in valid.items():
            if document[field] is not None:
                values.setdefault(document[field], []).append(kind)
        if len(values) > 1:
            for kinds in values.values():
                for kind in kinds:
                    _mark_contradictory(by_kind[kind])

    scope_raw = raw_by_kind.get("scope")
    test_raw = raw_by_kind.get("test")
    test_doc = valid.get("test")
    review_doc = valid.get("review")
    scope_doc = valid.get("scope")
    if test_doc is not None:
        if scope_doc is None:
            _mark_unprovable(by_kind["test"])
        elif scope_raw is not None and test_doc["scope_report_sha256"] != sha256_hex(scope_raw):
            _mark_contradictory(by_kind["test"])
            _mark_contradictory(by_kind["scope"])
        elif scope_doc["verdict"] != "PASS":
            _mark_contradictory(by_kind["test"])
            _mark_contradictory(by_kind["scope"])
    if review_doc is not None:
        if scope_doc is None:
            _mark_unprovable(by_kind["review"])
        elif scope_raw is not None and review_doc["scope_report_sha256"] != sha256_hex(scope_raw):
            _mark_contradictory(by_kind["review"])
            _mark_contradictory(by_kind["scope"])
        elif scope_doc["verdict"] != review_doc["scope_verdict"]:
            _mark_contradictory(by_kind["review"])
            _mark_contradictory(by_kind["scope"])
        if test_doc is None:
            _mark_unprovable(by_kind["review"])
        elif test_raw is not None and review_doc["test_report_sha256"] != sha256_hex(test_raw):
            _mark_contradictory(by_kind["review"])
            _mark_contradictory(by_kind["test"])
        elif test_doc["verdict"] != review_doc["test_verdict"]:
            _mark_contradictory(by_kind["review"])
            _mark_contradictory(by_kind["test"])
        if (
            by_kind["scope"]["state"] == "CONTRADICTORY"
            or by_kind["test"]["state"] == "CONTRADICTORY"
        ):
            _mark_contradictory(by_kind["review"])


def build_report(
    candidate: Mapping[str, Any],
    inputs: Mapping[str, tuple[bytes | None, str | None]],
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    documents: dict[str, dict[str, Any] | None] = {}
    raw_by_kind: dict[str, bytes | None] = {}
    for kind in ("scope", "test", "review"):
        raw, reason = inputs[kind]
        item, document = classify_document(kind, raw, reason, candidate)
        items.append(item)
        documents[kind] = document
        raw_by_kind[kind] = raw
    apply_cross_checks(items, documents, raw_by_kind)
    return {
        "schema": SCHEMA_ID,
        "tool_version": TOOL_VERSION,
        "candidate": dict(candidate),
        "items": items,
        "generation": dict(GENERATION),
    }


def ensure_output_path(output: Path, *, repo_root: Path) -> None:
    output = _literal_path(output, label="output")
    repo_root = _literal_path(repo_root, label="repository root")
    try:
        root = repo_root.resolve(strict=True)
    except OSError as exc:
        raise OutputError(f"repository root cannot be resolved: {exc}") from exc
    if not root.is_dir():
        raise OutputError("repository root must be a directory")
    resolved = output.resolve(strict=False)
    if resolved == root or resolved.is_relative_to(root):
        raise OutputError("output must be outside the repository")
    if enclosing_git_worktree(resolved.parent) is not None:
        raise OutputError("output must not be written inside a git working tree")


def enclosing_git_worktree(start: Path) -> Path | None:
    """Find a normal or linked Git worktree without running Git."""

    walk = start
    while True:
        try:
            if (walk / ".git").exists():
                return walk
        except OSError:
            return None
        if walk.parent == walk:
            return None
        walk = walk.parent


def atomic_write(path: Path, raw: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temp = Path(temp_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
        except BaseException:
            temp.unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise OutputError(f"could not write output: {exc}") from exc
