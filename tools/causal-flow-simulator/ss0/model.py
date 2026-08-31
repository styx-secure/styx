#!/usr/bin/env python3
"""Bounded, evidence-only SS-0 symbolic model.

This module is deliberately not an adapter.  It models only the decisions
selected by ``styx-secure-session-v0-decisions.md`` and never handles MLS
secrets, ciphertexts, persisted state, or product data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


PROFILE = {
    "ciphersuite_registry": "IANA_MLS",
    "openmls": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
    "marmot": "4ad4ae21479c3f3fa9950c6fc4556a76941a62e1",
    "mdk": "9396adb6aa6b95b521a7979facd5ea7040c07288",
    "ciphersuite": "0x0001",
    "members": ["MDK_PIN_9396ADB", "STYX_B32A"],
    "retained_past_epochs": 5,
}

U64_MAX = 2**64 - 1
OPERATION_FIELDS = {
    "convergence": frozenset({"candidates", "operation", "profile"}),
    "diagnostic_secret": frozenset({"operation", "profile"}),
    "mutation": frozenset(
        {"authoritative", "operation", "profile", "rs_result", "staged"}
    ),
    "physical_erasure": frozenset({"operation", "profile"}),
    "profile": frozenset({"operation", "profile"}),
    "receive": frozenset(
        {
            "authenticated",
            "member_count",
            "opaque_application_bytes",
            "operation",
            "profile",
        }
    ),
    "recovery": frozenset({"operation", "profile"}),
    "replay": frozenset(
        {"already_emitted", "message_identity", "operation", "profile"}
    ),
    "restored_state": frozenset({"operation", "profile"}),
    "retention": frozenset(
        {"current_epoch", "message_epoch", "operation", "profile"}
    ),
    "transport": frozenset({"operation", "profile"}),
    "welcome": frozenset(
        {
            "asserted_rollback",
            "consumed",
            "embedded_tree",
            "framed",
            "last_resort",
            "member_bound",
            "operation",
            "profile",
            "profile_bound",
        }
    ),
    "wire_format": frozenset({"operation", "profile"}),
}

DISPOSITIONS = frozenset(
    {
        "ACCEPTED_EVIDENCE",
        "AP_AUTHORITY_REQUIRED",
        "COMMITTED_MUTATION",
        "DEFERRED_CANDIDATE",
        "DRIFT_INVALIDATED",
        "DUPLICATE_SUPPRESSED",
        "EPOCH_OUT_OF_RANGE",
        "INVALID_SESSION_INPUT",
        "NOT_CLAIMED_IN_PROFILE",
        "NOT_COMMITTED",
        "REPLAY_REJECTED",
        "RS_RESULT_REQUIRED",
        "UNSUPPORTED_PROFILE_INPUT",
        "UNVALIDATED_RESTORED_STATE",
        "WELCOME_ACCEPTED",
    }
)


@dataclass(frozen=True)
class Observation:
    disposition: str
    applied: bool = False
    emitted_plaintext: bool = False
    selected: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "applied": self.applied,
            "disposition": self.disposition,
            "emitted_plaintext": self.emitted_plaintext,
        }
        if self.selected is not None:
            result["selected"] = self.selected
        return result


def _exact_profile(value: Any) -> bool:
    return isinstance(value, dict) and value == PROFILE


def _parse_u64(value: Any) -> int | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 20
        or (value != "0" and value.startswith("0"))
        or not value.isascii()
        or not value.isdecimal()
    ):
        return None
    parsed = int(value)
    return parsed if parsed <= U64_MAX else None


def _candidate(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "account",
        "app_witness_score",
        "authenticated",
        "depth",
        "parent",
        "proposal_free",
        "tip_priority",
    }:
        return False
    account = value["account"]
    return (
        isinstance(account, str)
        and len(account) == 64
        and all(character in "0123456789abcdef" for character in account)
        and value["authenticated"] is True
        and value["proposal_free"] is True
        and value["depth"] == "1"
        and value["app_witness_score"] == "0"
        and value["tip_priority"] == "ordinary"
        and isinstance(value["parent"], str)
        and bool(value["parent"])
    )


def evaluate(candidate: Any) -> dict[str, Any]:
    """Evaluate one ordinary bounded candidate and return a closed observation."""

    if not isinstance(candidate, dict) or not isinstance(candidate.get("operation"), str):
        return Observation("INVALID_SESSION_INPUT").as_dict()
    operation = candidate["operation"]
    expected_fields = OPERATION_FIELDS.get(
        operation, frozenset({"operation", "profile"})
    )
    if set(candidate) != expected_fields:
        return Observation("INVALID_SESSION_INPUT").as_dict()

    if operation == "profile":
        return Observation(
            "ACCEPTED_EVIDENCE" if _exact_profile(candidate.get("profile")) else "DRIFT_INVALIDATED"
        ).as_dict()

    if not _exact_profile(candidate.get("profile")):
        return Observation("DRIFT_INVALIDATED").as_dict()

    if operation == "receive":
        if candidate.get("member_count") != 2 or candidate.get("authenticated") is not True:
            return Observation("INVALID_SESSION_INPUT").as_dict()
        if candidate.get("opaque_application_bytes") is not True:
            return Observation("UNSUPPORTED_PROFILE_INPUT").as_dict()
        return Observation("AP_AUTHORITY_REQUIRED", emitted_plaintext=True).as_dict()

    if operation == "mutation":
        if candidate.get("authoritative") is not True or candidate.get("staged") is not True:
            return Observation("INVALID_SESSION_INPUT").as_dict()
        result = candidate.get("rs_result")
        if result == "COMMITTED":
            return Observation("COMMITTED_MUTATION", applied=True).as_dict()
        if result == "NOT_COMMITTED":
            return Observation("NOT_COMMITTED").as_dict()
        if result is None or result == "INDETERMINATE":
            return Observation("RS_RESULT_REQUIRED").as_dict()
        return Observation("INVALID_SESSION_INPUT").as_dict()

    if operation == "retention":
        current = _parse_u64(candidate.get("current_epoch"))
        message = _parse_u64(candidate.get("message_epoch"))
        if current is None or message is None or message > current:
            return Observation("EPOCH_OUT_OF_RANGE").as_dict()
        distance = current - message
        return Observation(
            "ACCEPTED_EVIDENCE" if distance <= PROFILE["retained_past_epochs"] else "EPOCH_OUT_OF_RANGE",
            emitted_plaintext=distance <= PROFILE["retained_past_epochs"],
        ).as_dict()

    if operation == "replay":
        if not isinstance(candidate.get("message_identity"), str) or not candidate["message_identity"]:
            return Observation("INVALID_SESSION_INPUT").as_dict()
        if candidate.get("already_emitted") is True:
            return Observation("DUPLICATE_SUPPRESSED").as_dict()
        return Observation("ACCEPTED_EVIDENCE", emitted_plaintext=True).as_dict()

    if operation == "convergence":
        candidates = candidate.get("candidates")
        if (
            not isinstance(candidates, list)
            or len(candidates) != 2
            or not all(_candidate(item) for item in candidates)
            or candidates[0]["parent"] != candidates[1]["parent"]
            or candidates[0]["account"] == candidates[1]["account"]
        ):
            return Observation("UNSUPPORTED_PROFILE_INPUT").as_dict()
        winner = min(item["account"] for item in candidates)
        return Observation("DEFERRED_CANDIDATE", applied=True, selected=winner).as_dict()

    if operation == "welcome":
        required_true = ("framed", "embedded_tree", "profile_bound", "member_bound")
        if any(candidate.get(name) is not True for name in required_true):
            return Observation("INVALID_SESSION_INPUT").as_dict()
        if candidate.get("last_resort") is not False:
            return Observation("UNSUPPORTED_PROFILE_INPUT").as_dict()
        if candidate.get("consumed") is True or candidate.get("asserted_rollback") is True:
            return Observation("REPLAY_REJECTED").as_dict()
        return Observation("WELCOME_ACCEPTED", applied=True).as_dict()

    if operation == "restored_state":
        return Observation("UNVALIDATED_RESTORED_STATE").as_dict()

    if operation in {
        "diagnostic_secret",
        "physical_erasure",
        "recovery",
        "transport",
        "wire_format",
    }:
        return Observation("NOT_CLAIMED_IN_PROFILE").as_dict()

    return Observation("UNSUPPORTED_PROFILE_INPUT").as_dict()
