"""Closed witness and mutant registries for the integrated O-14/O-06c model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from integrated_model import (
    EXPECTED_ENVELOPE_ENTRY_COUNT,
    EXPECTED_HANDOFF_COUNT,
    envelope_boundary_cases,
    envelope_dispositions,
    envelope_handoffs,
    evaluate_envelope_handoff,
)


REGISTRY_VERSION = "styx-o14-o06c-integrated-registry/v1"
PROBE_SCHEMA = "styx-o14-o06c-integrated-probe/v1"
RUNTIME_SCHEMA = "styx-o14-o06c-integrated-cross-runtime/v1"
MUTATION_SCHEMA = "styx-o14-o06c-integrated-mutations/v1"
SCOPE_SCHEMA = "styx-o14-o06c-integrated-scope/v1"


class RegistryError(ValueError):
    """The executable inventory differs from the closed registry."""


@dataclass(frozen=True)
class WitnessSpec:
    identifier: str
    assertion: str
    expected_local_primary: str
    expected_remote_result: str
    expected_ap_exposure: bool
    expected_verifier_invocations: int
    detectors: tuple[str, ...]
    source_family: str

    def record(self) -> dict[str, object]:
        return {
            "assertion": self.assertion,
            "detectors": list(self.detectors),
            "expected_ap_exposure": self.expected_ap_exposure,
            "expected_local_primary": self.expected_local_primary,
            "expected_remote_result": self.expected_remote_result,
            "expected_verifier_invocations": self.expected_verifier_invocations,
            "id": self.identifier,
            "source_family": self.source_family,
        }


@dataclass(frozen=True)
class MutantSpec:
    identifier: str
    assertion: str
    detectors: tuple[str, ...]
    source_family: str

    def record(self) -> dict[str, object]:
        return {
            "assertion": self.assertion,
            "detectors": list(self.detectors),
            "id": self.identifier,
            "source_family": self.source_family,
        }


def _witness(
    identifier: str,
    assertion: str,
    primary: str,
    *,
    verifier: int,
    ap: bool,
    detectors: tuple[str, ...],
    family: str,
) -> WitnessSpec:
    remote = "APPLIED" if primary == "APPLIED" else "OPAQUE_REMOTE_FAILURE"
    return WitnessSpec(
        identifier,
        assertion,
        primary,
        remote,
        ap,
        verifier,
        detectors,
        family,
    )


_FIXED_WITNESSES = (
    _witness("I-POS-ORDINARY", "ordinary event reaches AP only after K", "APPLIED", verifier=1, ap=True, detectors=("ORDER", "TRANSCRIPT", "VERIFIER"), family="positive"),
    _witness("I-POS-REMOVAL", "removal transcript preserves its complete tail", "APPLIED", verifier=1, ap=True, detectors=("REMOVAL_TAIL", "TRANSCRIPT"), family="positive"),
    _witness("I-POS-GRANT", "GRANT event uses the issuer binding, not grantee fields", "APPLIED", verifier=1, ap=True, detectors=("GRANT_SELECTOR_ISOLATION", "VERIFIER"), family="positive"),
    _witness("I-POS-REVOKE", "REVOKE transcript is signed as a complete control arm", "APPLIED", verifier=1, ap=True, detectors=("CONTROL_ARM", "TRANSCRIPT"), family="positive"),
    _witness("I-POS-ROTATE", "ROTATE transcript is signed as a complete control arm", "APPLIED", verifier=1, ap=True, detectors=("CONTROL_ARM", "TRANSCRIPT"), family="positive"),
    _witness("I-POS-RECOVER", "RECOVER transcript is signed as a complete control arm", "APPLIED", verifier=1, ap=True, detectors=("CONTROL_ARM", "TRANSCRIPT"), family="positive"),
    _witness("I-POS-POLICY", "POLICY transcript is signed as a complete empty arm", "APPLIED", verifier=1, ap=True, detectors=("CONTROL_ARM", "TRANSCRIPT"), family="positive"),
    _witness("I-POS-CLOSURE", "CLOSURE transcript is signed as a complete empty arm", "APPLIED", verifier=1, ap=True, detectors=("CONTROL_ARM", "TRANSCRIPT"), family="positive"),
    _witness("I-POS-CONTENT-NONE", "CONTENT_NONE remains distinct", "APPLIED", verifier=1, ap=True, detectors=("CONTENT_CLASS",), family="content"),
    _witness("I-POS-CONTENT-REQUIRED-SINGLE", "REQUIRED SINGLE is covered by the transcript", "APPLIED", verifier=1, ap=True, detectors=("CONTENT_CLASS", "COMMITMENT_SHAPE"), family="content"),
    _witness("I-POS-CONTENT-DETACHABLE-TREE", "DETACHABLE TREE is covered by the transcript", "APPLIED", verifier=1, ap=True, detectors=("CONTENT_CLASS", "COMMITMENT_SHAPE"), family="content"),
    _witness("I-STATE-DUPLICATE", "exact K-valid duplicate is idempotent", "DUPLICATE", verifier=1, ap=True, detectors=("O10_DUPLICATE",), family="replay"),
    _witness("I-STATE-PENDING-OPENING", "pending opening retains the frozen event outcome", "PENDING_OPENING", verifier=1, ap=True, detectors=("O10_EVENT_PRECEDENCE",), family="replay"),
    _witness("I-STATE-PENDING-ANCESTOR", "pending ancestor retains the frozen event outcome", "PENDING_ANCESTOR", verifier=1, ap=True, detectors=("O10_EVENT_PRECEDENCE",), family="replay"),
    _witness("I-STATE-REMOVAL-INAPPLICABLE", "logical removal preserves applicability checks", "REMOVAL_INAPPLICABLE", verifier=1, ap=True, detectors=("O10_EVENT_PRECEDENCE",), family="removal"),
    _witness("I-STATE-FORK", "fork evidence outranks later event-local conditions", "FORK_EVIDENCE", verifier=1, ap=True, detectors=("O10_EVENT_PRECEDENCE", "FORK_SCOPE"), family="fork"),
    _witness("I-STATE-REVOKED", "inactive revoked binding completes K before authority denial", "POST_REVOCATION", verifier=1, ap=True, detectors=("K_FIRST_INACTIVE",), family="authority"),
    _witness("I-STATE-ROTATED", "retired rotation predecessor completes K before authority denial", "POST_REVOCATION", verifier=1, ap=True, detectors=("K_FIRST_INACTIVE",), family="authority"),
    _witness("I-STATE-RECOVERY-PREDECESSOR", "retired recovery predecessor completes K before authority denial", "POST_REVOCATION", verifier=1, ap=True, detectors=("K_FIRST_INACTIVE",), family="authority"),
    _witness("I-STATE-QUARANTINED", "quarantined binding selects lineage quarantine only after K", "LINEAGE_QUARANTINED", verifier=1, ap=True, detectors=("K_FIRST_INACTIVE", "O10_EVENT_PRECEDENCE"), family="authority"),
    _witness("I-STATE-AP-DENIED", "signature validity never substitutes for AP authority", "AUTHENTIC_BUT_UNAUTHORIZED", verifier=1, ap=True, detectors=("NO_AUTHORITY_SUBSTITUTION",), family="authority"),
    _witness("I-K-MISSING", "unresolvable credential is typed before verifier", "UNRESOLVABLE_CREDENTIAL", verifier=0, ap=False, detectors=("UNIQUE_BINDING",), family="binding"),
    _witness("I-K-INCOMPLETE", "unauthenticated resolution is not a binding", "UNRESOLVED_CREDENTIAL_BINDING", verifier=0, ap=False, detectors=("UNIQUE_BINDING",), family="binding"),
    _witness("I-K-AMBIGUOUS", "ambiguous resolution is rejected", "UNRESOLVED_CREDENTIAL_BINDING", verifier=0, ap=False, detectors=("UNIQUE_BINDING",), family="binding"),
    _witness("I-K-BINDING-MISMATCH", "binding tuple mismatch precedes verifier", "CREDENTIAL_BINDING_MISMATCH", verifier=0, ap=False, detectors=("BINDING_FIELDS",), family="binding"),
    _witness("I-K-UNKNOWN-SUITE", "binding-selected unknown suite is out of profile", "CURRENT_OBJECT_OUT_OF_PROFILE", verifier=0, ap=False, detectors=("CLOSED_SUITE",), family="signature"),
    _witness("I-K-KEY-31", "31-octet key is a length mismatch", "LENGTH_MISMATCH", verifier=0, ap=False, detectors=("KEY_LENGTH",), family="signature"),
    _witness("I-K-KEY-33", "33-octet key is a length mismatch", "LENGTH_MISMATCH", verifier=0, ap=False, detectors=("KEY_LENGTH",), family="signature"),
    _witness("I-K-SIG-63", "63-octet signature is a length mismatch", "LENGTH_MISMATCH", verifier=0, ap=False, detectors=("SIGNATURE_LENGTH",), family="signature"),
    _witness("I-K-SIG-65", "65-octet signature is a length mismatch", "LENGTH_MISMATCH", verifier=0, ap=False, detectors=("SIGNATURE_LENGTH",), family="signature"),
    _witness("I-K-SCALAR-L", "S equal to L is invalid before verifier", "INVALID", verifier=0, ap=False, detectors=("SCALAR_CANONICALITY",), family="signature"),
    _witness("I-K-BITFLIP", "bit-flipped signature cannot reach AP", "INVALID", verifier=1, ap=False, detectors=("COMPLETE_TRANSCRIPT_SIGNATURE",), family="signature"),
    _witness("I-K-CANDIDATE-HISTORICAL", "candidate bytes cannot select trusted historical mode", "STRUCTURAL_REJECTION", verifier=0, ap=False, detectors=("TRUSTED_LOCAL_HISTORICAL",), family="substitution"),
    _witness("I-SUB-EVENT-SUITE", "event-carried suite does not select verification", "APPLIED", verifier=1, ap=True, detectors=("BOUND_SELECTOR",), family="substitution"),
    _witness("I-SUB-EVENT-KEY", "event-carried key does not select verification", "APPLIED", verifier=1, ap=True, detectors=("BOUND_SELECTOR",), family="substitution"),
    _witness("I-SUB-GRANT-KEY", "GRANT grantee key does not verify the carrying event", "APPLIED", verifier=1, ap=True, detectors=("BOUND_SELECTOR",), family="substitution"),
    _witness("I-SUB-TRANSPORT", "transport validity cannot substitute for K", "INVALID", verifier=1, ap=False, detectors=("NO_TRANSPORT_SUBSTITUTION",), family="substitution"),
    _witness("I-SUB-SESSION", "session validity cannot substitute for K", "INVALID", verifier=1, ap=False, detectors=("NO_SESSION_SUBSTITUTION",), family="substitution"),
    _witness("I-PRECEDENCE-STRUCTURAL-LENGTH", "structural rejection outranks length mismatch", "STRUCTURAL_REJECTION", verifier=0, ap=False, detectors=("O10_K_PRECEDENCE",), family="precedence"),
    _witness("I-PRECEDENCE-INACTIVE-INVALID", "invalid K outranks inactive authority", "INVALID", verifier=0, ap=False, detectors=("O10_K_PRECEDENCE", "K_FIRST_INACTIVE"), family="precedence"),
)


_TRANSCRIPT_FIELDS = (
    "profile-id",
    "profile-version",
    "context",
    "genesis-reference",
    "credential-identifier",
    "author-sequence",
    "predecessor",
    "causal-parents",
    "event-role",
    "event-type",
    "schema-id",
    "schema-version",
    "transition-block",
    "content-descriptor",
    "commitment",
    "removal-target-reference",
    "removal-target-commitment",
    "control-kind",
    "grantee-suite",
    "grantee-key",
    "target-credential",
    "retiring-credential",
    "replacement-grant",
    "retired-credential",
    "recovery-grant",
)


def required_witnesses() -> tuple[WitnessSpec, ...]:
    rows = list(_FIXED_WITNESSES)
    for field_name in _TRANSCRIPT_FIELDS:
        rows.append(
            _witness(
                f"I-TRANSCRIPT-{field_name.upper()}",
                f"mutation of {field_name} changes the regenerated complete transcript",
                "INVALID",
                verifier=1,
                ap=False,
                detectors=("TRANSCRIPT_REGENERATION", "COMPLETE_TRANSCRIPT_SIGNATURE"),
                family="transcript-substitution",
            )
        )
    for disposition in envelope_dispositions():
        dimension = disposition["dimension"]
        rows.append(
            _witness(
                f"I-O08-DISPOSITION-{dimension}",
                f"{dimension} has its exact frozen C0.3 disposition",
                "APPLIED",
                verifier=1,
                ap=True,
                detectors=("O08_DISPOSITION",),
                family="o08-disposition",
            )
        )
    for handoff in envelope_handoffs():
        dimension = handoff["dimension"]
        stage = handoff["stage"]
        primary = evaluate_envelope_handoff(dimension, stage)
        rows.append(
            _witness(
                f"I-O08-HANDOFF-{dimension}-{stage}",
                f"{dimension} is enforced at {stage} with its frozen handoff",
                primary,
                verifier=0 if stage in {"S0_PROFILE_ACTIVATION", "S3_KERNEL_STRUCTURAL"} else 1,
                ap=stage in {"S5_AUTHORITY_PROJECTION", "S6_DURABLE_COMMIT"},
                detectors=("O08_BOUND", "O08_O10_HANDOFF"),
                family="o08-handoff",
            )
        )
    for boundary in envelope_boundary_cases():
        stage = boundary["stage"]
        accepted = boundary["accepted"]
        rows.append(
            _witness(
                boundary["id"],
                f"{boundary['dimension']} bounded observation {boundary['observed']} has its exact disposition",
                boundary["primary"],
                verifier=1 if accepted or stage not in {"S0_PROFILE_ACTIVATION", "S3_KERNEL_STRUCTURAL"} else 0,
                ap=True if accepted else stage in {"S5_AUTHORITY_PROJECTION", "S6_DURABLE_COMMIT"},
                detectors=("O08_BOUNDARY", "O08_O10_HANDOFF"),
                family="o08-boundary",
            )
        )
    _validate_witnesses(rows)
    return tuple(rows)


_AP_BEFORE_K_DETECTORS = tuple(
    item.identifier for item in _FIXED_WITNESSES if not item.expected_ap_exposure
) + tuple(f"I-TRANSCRIPT-{field.upper()}" for field in _TRANSCRIPT_FIELDS)


_MUTANTS = (
    MutantSpec("I-M-SKIP-ENVELOPE", "skipping a selected O-08 gate is detected", ("I-O08-HANDOFF-FRAMING_OBJECT_OCTETS-S3_KERNEL_STRUCTURAL",), "work-order"),
    MutantSpec("I-M-AP-BEFORE-K", "AP exposure before K is detected", _AP_BEFORE_K_DETECTORS, "work-order"),
    MutantSpec("I-M-HASH-BEFORE-BINDING", "hashing before unique binding is detected", ("I-K-MISSING", "I-K-INCOMPLETE", "I-K-AMBIGUOUS"), "work-order"),
    MutantSpec("I-M-TRUST-CANDIDATE-HISTORICAL", "candidate-selected historical mode is detected", ("I-K-CANDIDATE-HISTORICAL",), "substitution"),
    MutantSpec("I-M-FIRST-FAILURE-PRIMARY", "evaluation order cannot replace O-10 precedence", ("I-STATE-REVOKED", "I-STATE-ROTATED", "I-STATE-RECOVERY-PREDECESSOR", "I-STATE-QUARANTINED", "I-PRECEDENCE-STRUCTURAL-LENGTH", "I-PRECEDENCE-INACTIVE-INVALID"), "precedence"),
    MutantSpec("I-M-TRUST-EVENT-KEY", "event key cannot replace the resolved key", ("I-SUB-EVENT-KEY",), "substitution"),
    MutantSpec("I-M-RETRY-VERIFIER", "fallback or retry violates the one-verifier rule", ("I-K-UNKNOWN-SUITE",), "signature"),
)


def required_mutants() -> tuple[MutantSpec, ...]:
    rows = tuple(_MUTANTS)
    identifiers = [item.identifier for item in rows]
    if len(identifiers) != len(set(identifiers)):
        raise RegistryError("duplicate mutant identifier")
    witness_ids = {item.identifier for item in required_witnesses()}
    for item in rows:
        if not item.detectors or not set(item.detectors) <= witness_ids:
            raise RegistryError(f"invalid detector set: {item.identifier}")
    return rows


def _validate_witnesses(rows: Iterable[WitnessSpec]) -> None:
    rows = tuple(rows)
    identifiers = [item.identifier for item in rows]
    if len(identifiers) != len(set(identifiers)):
        raise RegistryError("duplicate witness identifier")
    for item in rows:
        if not item.identifier or not item.assertion or not item.detectors:
            raise RegistryError("incomplete witness entry")
        if item.expected_local_primary == "APPLIED":
            if item.expected_remote_result != "APPLIED":
                raise RegistryError("applied witness has wrong remote result")
        elif item.expected_remote_result != "OPAQUE_REMOTE_FAILURE":
            raise RegistryError("failure witness does not collapse remotely")
        if item.expected_verifier_invocations not in {0, 1}:
            raise RegistryError("invalid verifier invocation count")


def registry_record() -> dict[str, object]:
    witnesses = required_witnesses()
    mutants = required_mutants()
    return {
        "mutant_count": len(mutants),
        "mutants": [item.record() for item in mutants],
        "schema": REGISTRY_VERSION,
        "witness_count": len(witnesses),
        "witnesses": [item.record() for item in witnesses],
    }
