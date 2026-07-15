"""Exceptions, constants, and the closed-shape request model.

Untrusted JSON is parsed explicitly here: exact key sets, explicit types, and no
generic deserialization or reflection. ``operation`` is kept as a raw string;
only ``broker.py`` decides which operations are permitted (unknown -> policy
denial), so the frozen result mapping is preserved.
"""
from __future__ import annotations

import dataclasses

import canonical


class BrokerError(Exception):
    code = "INTERNAL_ERROR"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class PolicyError(BrokerError):
    code = "DENIED_POLICY"


class EvidenceError(BrokerError):
    code = "DENIED_EVIDENCE"


class ConflictError(BrokerError):
    code = "CONFLICT_IDEMPOTENT"


class AuthUnavailable(BrokerError):
    code = "AUTH_UNAVAILABLE"


class RemoteFailure(BrokerError):
    code = "REMOTE_FAILURE"


REQUEST_SCHEMA = "styx.restricted-broker-request/v1"
PUSH = "push_task_branch"
OPEN_PR = "open_draft_pr"

_REQUEST_KEYS = {"schema", "operation", "issue_number", "execution_id", "idempotency_key", "evidence"}
_EVIDENCE_KEYS = {"scope_report", "runner_status", "hook_attestation"}


@dataclasses.dataclass(frozen=True)
class EvidenceBundle:
    """Canonical bytes of the three evidence documents. Storing bytes (not dicts)
    lets the broker re-parse and revalidate from an immutable representation
    immediately before the side effect."""

    scope_report: bytes
    runner_status: bytes
    hook_attestation: bytes


@dataclasses.dataclass(frozen=True)
class BrokerRequest:
    operation: str
    issue_number: int
    execution_id: str
    idempotency_key: str
    evidence: EvidenceBundle


def _require_exact_keys(obj: dict, expected: set, where: str) -> None:
    keys = set(obj)
    if keys != expected:
        raise EvidenceError(f"{where}: keys must be exactly {sorted(expected)}, got {sorted(keys)}")


def _require_str(obj: dict, key: str) -> str:
    value = obj[key]
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"field {key!r} must be a non-empty string")
    return value


def build_request(obj: dict) -> BrokerRequest:
    if not isinstance(obj, dict):
        raise EvidenceError("request must be an object")
    _require_exact_keys(obj, _REQUEST_KEYS, "request")
    if obj["schema"] != REQUEST_SCHEMA:
        raise EvidenceError("request schema mismatch")
    operation = _require_str(obj, "operation")  # raw string; dispatch decides (correction B)
    issue_number = obj["issue_number"]
    if not isinstance(issue_number, int) or isinstance(issue_number, bool) or issue_number < 1:
        raise EvidenceError("issue_number must be an integer >= 1")
    execution_id = _require_str(obj, "execution_id")
    idempotency_key = _require_str(obj, "idempotency_key")
    evidence = obj["evidence"]
    if not isinstance(evidence, dict):
        raise EvidenceError("evidence must be an object")
    _require_exact_keys(evidence, _EVIDENCE_KEYS, "evidence")
    for name in _EVIDENCE_KEYS:
        if not isinstance(evidence[name], dict):
            raise EvidenceError(f"evidence.{name} must be an object")
    bundle = EvidenceBundle(
        scope_report=canonical.canonical_bytes(evidence["scope_report"]),
        runner_status=canonical.canonical_bytes(evidence["runner_status"]),
        hook_attestation=canonical.canonical_bytes(evidence["hook_attestation"]),
    )
    return BrokerRequest(operation, issue_number, execution_id, idempotency_key, bundle)
