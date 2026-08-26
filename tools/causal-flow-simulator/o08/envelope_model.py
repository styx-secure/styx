"""Reference model for candidate and selected O-08 resource envelopes."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any

from semantic_registry import (
    BASE_SHA,
    CANDIDATE_SET_SCHEMA,
    ENVELOPE_SCHEMA,
    ENVELOPE_VERSION,
    FIXED_SEMANTIC_VALUES,
    ROLE_CAPABILITY,
    ROLE_EVIDENCE,
    ROLE_POST,
    ROLE_ZERO,
    SELECTED_PATH,
    SourceRegistry,
    canonical_bytes,
    load_json,
    load_source_registry,
    recovery_for,
    scope_for,
    unit_for,
)


PROFILE = "STYX_APP_KERNEL_V0_TRANSCRIPT_ONLY"
CANDIDATE_IDS = ("conservative", "balanced", "expansive")
CAPABILITY_PROFILE_IDS = ("conservative", "balanced")


class EnvelopeError(ValueError):
    """A candidate or selected envelope is not exact and closed."""


def load_selected_envelope(path=SELECTED_PATH) -> dict[str, Any]:
    raw = path.read_bytes()
    value = load_json(path)
    if raw != canonical_bytes(value):
        raise EnvelopeError("selected envelope is not canonical JSON with trailing LF")
    return value


@dataclass(frozen=True)
class Evaluation:
    dimension: str
    stage: str | None
    observed: int
    selected: int | None
    disposition: str
    authoritative_state_mutated: bool


def candidate_identity(candidate: dict[str, Any]) -> str:
    payload = {
        "candidate_id": candidate["id"],
        "envelope_version": ENVELOPE_VERSION,
        "profile": PROFILE,
        "values": candidate["values"],
    }
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def validate_candidate_set(
    payload: dict[str, Any], registry: SourceRegistry | None = None
) -> tuple[dict[str, Any], ...]:
    registry = registry or load_source_registry()
    if set(payload) != {
        "schema", "base_sha", "envelope_version", "profile",
        "capability_profiles", "candidates",
    }:
        raise EnvelopeError("candidate-set schema mismatch")
    if payload["schema"] != CANDIDATE_SET_SCHEMA:
        raise EnvelopeError("candidate-set identity mismatch")
    if payload["base_sha"] != BASE_SHA:
        raise EnvelopeError("candidate-set Base mismatch")
    if payload["envelope_version"] != ENVELOPE_VERSION or payload["profile"] != PROFILE:
        raise EnvelopeError("candidate profile mismatch")

    profiles = payload["capability_profiles"]
    if not isinstance(profiles, dict) or set(profiles) != set(CAPABILITY_PROFILE_IDS):
        raise EnvelopeError("capability-profile set mismatch")
    required_profile_fields = {
        "transient_memory_octets", "durable_required_octets",
        "durable_records", "custody_redundancy", "activation_capability_set",
    }
    for profile in profiles.values():
        if not isinstance(profile, dict) or set(profile) != required_profile_fields:
            raise EnvelopeError("capability-profile schema mismatch")
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in profile.values()):
            raise EnvelopeError("capability-profile values must be non-negative integers")

    candidates = payload["candidates"]
    if not isinstance(candidates, list) or tuple(item.get("id") for item in candidates) != CANDIDATE_IDS:
        raise EnvelopeError("candidate IDs/order mismatch")
    expected = set(registry.entry_dimensions)
    previous: dict[str, int] | None = None
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != {"id", "values"}:
            raise EnvelopeError("candidate schema mismatch")
        values = candidate["values"]
        if not isinstance(values, dict) or set(values) != expected:
            raise EnvelopeError(f"candidate dimension set mismatch: {candidate['id']}")
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values.values()):
            raise EnvelopeError("candidate values must be non-negative integers")
        for dimension, fixed in FIXED_SEMANTIC_VALUES.items():
            if values[dimension] != fixed:
                raise EnvelopeError(f"frozen semantic value changed: {dimension}")
        for dimension in ("CHECKPOINT_REFERENCES", "PHYSICAL_TIME_SKEW"):
            if values[dimension] != 0:
                raise EnvelopeError(f"v0 unsupported value must be zero: {dimension}")
        if previous is not None:
            for dimension in expected - set(FIXED_SEMANTIC_VALUES) - {
                "CHECKPOINT_REFERENCES", "PHYSICAL_TIME_SKEW",
            }:
                if values[dimension] < previous[dimension]:
                    raise EnvelopeError(f"candidate order is not monotone: {dimension}")
        previous = values
    return tuple(candidates)


def materialize_candidate(
    candidate: dict[str, Any], registry: SourceRegistry | None = None
) -> dict[str, Any]:
    registry = registry or load_source_registry()
    values = candidate["values"]
    entries: dict[str, dict[str, Any]] = {}
    for dimension in registry.dimensions:
        role = registry.roles[dimension]
        selected = values.get(dimension) if role not in {ROLE_POST, ROLE_EVIDENCE} else None
        if role == ROLE_CAPABILITY:
            comparison = "MINIMUM_CAPABILITY"
            value_range: list[int | None] | None = [selected, None]
        elif role == ROLE_ZERO:
            comparison = "EXACT_ZERO"
            value_range = [0, 0]
        elif role in {ROLE_POST, ROLE_EVIDENCE}:
            comparison = "NON_ENTRY"
            value_range = None
        else:
            comparison = "MAXIMUM"
            value_range = [0, selected]
        entries[dimension] = {
            "role": role,
            "unit": unit_for(dimension),
            "scope": scope_for(dimension),
            "stages": list(registry.stages[dimension]),
            "selected_value": selected,
            "comparison": comparison,
            "integer_range": value_range,
            "enforcement_points": [
                f"BEFORE_{stage}_PROTECTED_WORK" for stage in registry.stages[dimension]
            ],
            "closed_values": [selected] if dimension in FIXED_SEMANTIC_VALUES else None,
            "reopen_predicate": f"REOPEN_IF_{dimension}_SEMANTICS_OR_BOUND_CHANGES",
        }
    return {
        "schema": ENVELOPE_SCHEMA,
        "envelope_version": ENVELOPE_VERSION,
        "profile": PROFILE,
        "candidate_id": candidate["id"],
        "candidate_digest": candidate_identity(candidate),
        "entries": entries,
    }


def validate_selected(
    envelope: dict[str, Any], candidate_set: dict[str, Any], registry: SourceRegistry | None = None
) -> dict[str, Any]:
    registry = registry or load_source_registry()
    candidates = validate_candidate_set(candidate_set, registry)
    if not isinstance(envelope, dict) or set(envelope) != {
        "schema", "envelope_version", "profile", "candidate_id",
        "candidate_digest", "entries",
    }:
        raise EnvelopeError("selected envelope schema mismatch")
    candidate = next((item for item in candidates if item["id"] == envelope["candidate_id"]), None)
    if candidate is None:
        raise EnvelopeError("selected candidate is unknown")
    expected = materialize_candidate(candidate, registry)
    if envelope != expected:
        raise EnvelopeError("selected envelope does not exactly match candidate set")
    return envelope


def evaluate_observation(
    envelope: dict[str, Any], dimension: str, observed: int, *, stage: str | None = None
) -> Evaluation:
    if not isinstance(observed, int) or isinstance(observed, bool):
        raise EnvelopeError("observation must be an integer")
    entries = envelope["entries"]
    if dimension not in entries:
        raise EnvelopeError("unknown dimension")
    entry = entries[dimension]
    role = entry["role"]
    stages = entry["stages"]
    if stage is not None and stage not in stages:
        raise EnvelopeError("stage does not own dimension")
    selected = entry["selected_value"]
    if role in {ROLE_POST, ROLE_EVIDENCE}:
        return Evaluation(dimension, stage, observed, None, "POST_C03_NOT_EXECUTED", False)
    if selected is None:
        raise EnvelopeError("entry dimension has no selected value")
    if observed < 0:
        passed = False
    elif role == ROLE_CAPABILITY:
        passed = observed >= selected
    else:
        passed = observed <= selected
    effective_stage = stage or (stages[0] if stages else None)
    disposition = "ACCEPT" if passed else recovery_for(dimension, effective_stage or "", role)
    return Evaluation(dimension, effective_stage, observed, selected, disposition, False)


def boundary_observations(selected: int) -> tuple[int, ...]:
    return (selected - 1, selected, selected + 1)
