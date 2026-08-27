"""Independent Python reference for the closed O-10 local taxonomy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


class TaxonomyError(ValueError):
    """An input is outside the closed O-10 scenario grammar."""


class TrustedBoundaryFailure(RuntimeError):
    """The local boundary cannot prove a safe mutation disposition."""


REMOTE_COLLAPSE = "OPAQUE_REMOTE_FAILURE"
ALIAS = "FORK_QUARANTINED"
POST_C03_MARKERS = frozenset({"SESSION_PROFILE_REQUIRED", "TRANSPORT_PROFILE_REQUIRED"})

PRIMARY_ROWS: dict[str, tuple[str, str, str, str | None, str, str]] = {
    "APPLIED": ("AP", "FINAL_AFTER_S6", "APPLIED", None, "NONE", "TRUSTED_LOCAL_ONLY"),
    "AUTHENTIC_BUT_UNAUTHORIZED": ("AP", "EVENT_LOCAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
    "AUTHORITY_PROJECTION_UNAVAILABLE": ("AP", "S5_AUTHORITY_PROJECTION", "NOT_APPLIED", "PRESERVE_CONTEXT_AND_RESTORE_AUTHORITY_CAPABILITY", "AUTHORITY_CAPABILITY_RESTORED", "TRUSTED_LOCAL_ONLY"),
    "COMMITMENT_MISMATCH": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
    "CONTEXT_CAPACITY_EXHAUSTED": ("K", "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT", "NOT_APPLIED", "NEW_CONTEXT_OR_RATIFIED_PROFILE_REQUIRED", "NEW_CONTEXT_OR_RATIFIED_PROFILE", "TRUSTED_LOCAL_ONLY"),
    "CREDENTIAL_BINDING_MISMATCH": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
    "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
    "CURRENT_OBJECT_OUT_OF_PROFILE": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "NEW_CONTEXT_OR_RATIFIED_PROFILE_REQUIRED", "NEW_CONTEXT_OR_RATIFIED_PROFILE", "TRUSTED_LOCAL_ONLY"),
    "DEPENDENCY_DEFERRED": ("K", "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT", "NOT_APPLIED", "RETRY_AFTER_DEPENDENCY_CHANGE", "AUTHENTICATED_DEPENDENCY_STATE_CHANGED", "TRUSTED_LOCAL_ONLY"),
    "DUPLICATE": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "NO_ACTION_IDEMPOTENT", "NONE", "TRUSTED_LOCAL_ONLY"),
    "FORK_EVIDENCE": ("K", "EVENT_LOCAL", "NOT_APPLIED", "QUARANTINE_LINEAGE_AND_REPLAY", "RATIFIED_LINEAGE_STATE_CHANGED", "TRUSTED_LOCAL_ONLY"),
    "INVALID": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
    "LENGTH_MISMATCH": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
    "LINEAGE_QUARANTINED": ("AP", "EVENT_LOCAL", "NOT_APPLIED", "QUARANTINE_LINEAGE_AND_REPLAY", "RATIFIED_LINEAGE_STATE_CHANGED", "TRUSTED_LOCAL_ONLY"),
    "OPENING_MISSING": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "SUPPLY_VERIFIED_OPENING_AND_REPLAY", "VERIFIED_OPENING_PRESENT", "TRUSTED_LOCAL_ONLY"),
    "PENDING_ANCESTOR": ("K", "EVENT_LOCAL", "NOT_APPLIED", "RETRY_AFTER_DEPENDENCY_CHANGE", "AUTHENTICATED_DEPENDENCY_STATE_CHANGED", "TRUSTED_LOCAL_ONLY"),
    "PENDING_OPENING": ("K", "EVENT_LOCAL", "NOT_APPLIED", "SUPPLY_VERIFIED_OPENING_AND_REPLAY", "VERIFIED_OPENING_PRESENT", "TRUSTED_LOCAL_ONLY"),
    "POST_REVOCATION": ("AP", "EVENT_LOCAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
    "PROFILE_ACTIVATION_UNSUPPORTED": ("K", "S0_PROFILE_ACTIVATION", "NOT_APPLIED", "NEW_CONTEXT_OR_RATIFIED_PROFILE_REQUIRED", "NEW_CONTEXT_OR_RATIFIED_PROFILE", "TRUSTED_LOCAL_ONLY"),
    "REFERENCE_COLLISION_UNSUPPORTED": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
    "REMOVAL_INAPPLICABLE": ("K", "EVENT_LOCAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
    "STALE_EVIDENCE": ("K", "POST_S3_REPLAY_EVIDENCE", "NOT_APPLIED", "REFRESH_LIVE_EVIDENCE_AND_REPLAY", "FRESH_LIVE_EVIDENCE_PRESENT", "TRUSTED_LOCAL_ONLY"),
    "STRUCTURAL_REJECTION": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
    "UNRESOLVABLE_CREDENTIAL": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
    "UNRESOLVED_CREDENTIAL_BINDING": ("K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"),
}

K_PRECEDENCE = (
    "STRUCTURAL_REJECTION",
    "LENGTH_MISMATCH",
    "CURRENT_OBJECT_OUT_OF_PROFILE",
    "COMMITMENT_MISMATCH",
    "OPENING_MISSING",
    "UNRESOLVABLE_CREDENTIAL",
    "UNRESOLVED_CREDENTIAL_BINDING",
    "CREDENTIAL_BINDING_MISMATCH",
    "REFERENCE_COLLISION_UNSUPPORTED",
    "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED",
    "INVALID",
)
EVENT_PRECEDENCE = (
    "FORK_EVIDENCE",
    "PENDING_OPENING",
    "PENDING_ANCESTOR",
    "REMOVAL_INAPPLICABLE",
    "POST_REVOCATION",
    "LINEAGE_QUARANTINED",
    "AUTHENTIC_BUT_UNAUTHORIZED",
)
SCENARIO_FIELDS = frozenset(
    {
        "id",
        "profile_activation_unsupported",
        "k_failures",
        "duplicate",
        "delivery_order",
        "stale_evidence",
        "s4_failures",
        "authority_projection_unavailable",
        "event_failures",
        "authorized",
        "s6_failures",
        "mutation_provable",
    }
)


@dataclass(frozen=True)
class Outcome:
    primary: str
    owner: str
    stage: str
    mutation: str
    recovery: str | None
    retry_precondition: str
    observability: str
    auxiliary: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "auxiliary": list(self.auxiliary),
            "mutation": self.mutation,
            "observability": self.observability,
            "owner": self.owner,
            "primary": self.primary,
            "recovery": self.recovery,
            "remote": project_remote(self),
            "retry_precondition": self.retry_precondition,
            "stage": self.stage,
        }


def _closed_strings(value: Any, *, field: str, allowed: frozenset[str]) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise TaxonomyError(f"{field} must be a string array")
    if len(value) != len(set(value)):
        raise TaxonomyError(f"{field} contains duplicates")
    unknown = set(value) - set(allowed)
    if unknown:
        raise TaxonomyError(f"{field} contains unknown identifiers")
    return tuple(value)


def _choose(order: Iterable[str], present: set[str]) -> str | None:
    return next((item for item in order if item in present), None)


def _outcome(primary: str, auxiliary: Iterable[str]) -> Outcome:
    owner, stage, mutation, recovery, retry, observability = PRIMARY_ROWS[primary]
    return Outcome(
        primary,
        owner,
        stage,
        mutation,
        recovery,
        retry,
        observability,
        tuple(sorted(set(auxiliary))),
    )


def evaluate(scenario: dict[str, Any]) -> Outcome:
    """Evaluate one ordinary, oracle-free local scenario."""

    if not isinstance(scenario, dict) or set(scenario) != set(SCENARIO_FIELDS):
        raise TaxonomyError("scenario fields do not match the closed grammar")
    if not isinstance(scenario["id"], str) or not scenario["id"]:
        raise TaxonomyError("scenario id must be non-empty")
    boolean_fields = SCENARIO_FIELDS - {
        "id",
        "k_failures",
        "delivery_order",
        "s4_failures",
        "event_failures",
        "s6_failures",
    }
    if any(type(scenario[field]) is not bool for field in boolean_fields):
        raise TaxonomyError("scenario flags must be booleans")
    delivery_order = scenario["delivery_order"]
    if (
        not isinstance(delivery_order, list)
        or any(not isinstance(item, str) or not item for item in delivery_order)
        or len(delivery_order) != len(set(delivery_order))
    ):
        raise TaxonomyError("delivery_order must contain unique non-empty strings")
    if not scenario["mutation_provable"]:
        raise TrustedBoundaryFailure("mutation disposition is not provable")

    k_failures = _closed_strings(
        scenario["k_failures"], field="k_failures", allowed=frozenset(K_PRECEDENCE)
    )
    event_failures = _closed_strings(
        scenario["event_failures"],
        field="event_failures",
        allowed=frozenset(EVENT_PRECEDENCE),
    )
    s4 = _closed_strings(
        scenario["s4_failures"],
        field="s4_failures",
        allowed=frozenset({"CONTEXT_CAPACITY_EXHAUSTED", "DEPENDENCY_DEFERRED"}),
    )
    s6 = _closed_strings(
        scenario["s6_failures"],
        field="s6_failures",
        allowed=frozenset({"CONTEXT_CAPACITY_EXHAUSTED", "DEPENDENCY_DEFERRED"}),
    )
    auxiliary = tuple(sorted(set(k_failures + event_failures + s4 + s6)))

    if scenario["profile_activation_unsupported"]:
        return _outcome("PROFILE_ACTIVATION_UNSUPPORTED", auxiliary)
    primary = _choose(K_PRECEDENCE, set(k_failures))
    if primary is not None:
        return _outcome(primary, auxiliary)
    if scenario["duplicate"]:
        return _outcome("DUPLICATE", auxiliary)
    if scenario["stale_evidence"]:
        return _outcome("STALE_EVIDENCE", auxiliary)
    if s4:
        primary = (
            "CONTEXT_CAPACITY_EXHAUSTED"
            if "CONTEXT_CAPACITY_EXHAUSTED" in s4
            else "DEPENDENCY_DEFERRED"
        )
        return _outcome(primary, auxiliary)
    if scenario["authority_projection_unavailable"]:
        return _outcome("AUTHORITY_PROJECTION_UNAVAILABLE", auxiliary)
    primary = _choose(EVENT_PRECEDENCE, set(event_failures))
    if primary is not None:
        return _outcome(primary, auxiliary)
    if not scenario["authorized"]:
        return _outcome("AUTHENTIC_BUT_UNAUTHORIZED", auxiliary)
    if s6:
        primary = (
            "CONTEXT_CAPACITY_EXHAUSTED"
            if "CONTEXT_CAPACITY_EXHAUSTED" in s6
            else "DEPENDENCY_DEFERRED"
        )
        return _outcome(primary, auxiliary)
    return _outcome("APPLIED", auxiliary)


def resolve_recovery(identifier: str) -> str | None:
    if identifier == ALIAS:
        identifier = "LINEAGE_QUARANTINED"
    if identifier not in PRIMARY_ROWS:
        raise TaxonomyError("UNKNOWN_PRIMARY")
    return PRIMARY_ROWS[identifier][3]


def project_remote(outcome: Outcome) -> dict[str, str]:
    if outcome.primary == "APPLIED":
        return {"result": "APPLIED"}
    return {"result": REMOTE_COLLAPSE}
