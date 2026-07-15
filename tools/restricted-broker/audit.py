"""Canonical, append-only audit records. Deterministic (no time, no random).

The sink assigns ``sequence``, finalizes the record, computes ``audit_id`` and
returns the immutable record used by the broker for the response. Identifiers
that are only known after validation are ``null`` in early-denial records;
``request_sha256`` is always present. No raw secrets or unsanitized payloads.
"""
from __future__ import annotations

import dataclasses
import re

import canonical

_TOKEN_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)authorization:\s*\S+"),
    re.compile(r"(?i)bearer\s+\S+"),
    re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@\S+"),  # userinfo URL
]


def sanitize(text):
    if not isinstance(text, str):
        return text
    out = text
    for pattern in _TOKEN_PATTERNS:
        out = pattern.sub("[redacted]", out)
    return out


def _sanitize_json(value):
    if isinstance(value, str):
        return sanitize(value)
    if isinstance(value, dict):
        return {k: _sanitize_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_json(v) for v in value]
    return value


@dataclasses.dataclass(frozen=True)
class AuditEvent:
    request_sha256: str
    execution_id: object
    issue_number: object
    operation: object
    idempotency_key: object
    evidence_hashes: object
    decision: str
    derived: object
    outcome: dict


@dataclasses.dataclass(frozen=True)
class AuditRecord:
    sequence: int
    audit_id: str
    request_sha256: str
    execution_id: object
    issue_number: object
    operation: object
    idempotency_key: object
    evidence_hashes: object
    decision: str
    derived: object
    outcome: dict

    def to_json(self) -> dict:
        return {
            "schema": "styx.restricted-broker-audit/v1",
            "sequence": self.sequence,
            "audit_id": self.audit_id,
            "request_sha256": self.request_sha256,
            "execution_id": self.execution_id,
            "issue_number": self.issue_number,
            "operation": self.operation,
            "idempotency_key": self.idempotency_key,
            "evidence_hashes": self.evidence_hashes,
            "decision": self.decision,
            "derived": self.derived,
            "outcome": self.outcome,
        }


class AuditSink:
    def append(self, event: AuditEvent) -> AuditRecord:
        raise NotImplementedError


class InMemoryAuditSink(AuditSink):
    def __init__(self):
        self._records = []

    @property
    def records(self):
        return list(self._records)  # snapshot; external mutation is inert

    def append(self, event: AuditEvent) -> AuditRecord:
        sequence = len(self._records)
        outcome = _sanitize_json(event.outcome)
        binding = [
            sequence,
            event.request_sha256,
            event.execution_id,
            event.operation,
            event.idempotency_key,
            event.evidence_hashes,
            event.decision,
        ]
        audit_id = canonical.canonical_sha256(binding)
        record = AuditRecord(
            sequence=sequence,
            audit_id=audit_id,
            request_sha256=event.request_sha256,
            execution_id=event.execution_id,
            issue_number=event.issue_number,
            operation=event.operation,
            idempotency_key=event.idempotency_key,
            evidence_hashes=event.evidence_hashes,
            decision=event.decision,
            derived=event.derived,
            outcome=outcome,
        )
        self._records.append(record)
        return record
