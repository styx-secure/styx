"""Bounded O-14 to O-06c integration evidence model.

The module composes the frozen O-06c transcript encoder, O-08 envelope,
O-10 taxonomy, and O-14 verification boundary.  It is evidence code only: it
defines neither product wire bytes nor a production credential resolver.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Mapping


SIMULATOR_ROOT = Path(__file__).resolve().parent.parent
REPOSITORY_ROOT = SIMULATOR_ROOT.parents[1]
if str(SIMULATOR_ROOT) not in sys.path:
    sys.path.insert(0, str(SIMULATOR_ROOT))

# semantic_registry.py uses the historical direct-module import when executed
# by its own scripts.  Install the exact frozen module under that spelling
# before importing the namespaced module; no implementation is copied here.
from o14 import ed25519_reference as _o14_reference

sys.modules.setdefault("ed25519_reference", _o14_reference)

from protocol_model import (  # noqa: E402
    CONTENT_NONE,
    EventAssignment,
    ModelError,
    WorkCounter as TranscriptWorkCounter,
    encode_event_transcript,
    event_reference,
    parse_event_transcript,
)
from o08.semantic_registry import (  # noqa: E402
    ENTRY_ROLES,
    ROLE_CAPABILITY,
    ROLE_EVIDENCE,
    ROLE_POST,
    recovery_for,
)
from o10.taxonomy import (  # noqa: E402
    EVENT_PRECEDENCE,
    K_PRECEDENCE,
    PRIMARY_ROWS,
    REMOTE_COLLAPSE,
    Outcome,
    evaluate as evaluate_taxonomy,
)
from o14.semantic_registry import (  # noqa: E402
    CredentialBinding as O14CredentialBinding,
    EventInput as O14EventInput,
    Mutation as O14Mutation,
    SUITE_ID,
    verify_event,
)


SELECTED_ENVELOPE_PATH = SIMULATOR_ROOT / "o08" / "resource-envelope.candidate.json"
EXPECTED_ENVELOPE_ENTRY_COUNT = 69
EXPECTED_ENTRY_DIMENSION_COUNT = 53
EXPECTED_HANDOFF_COUNT = 66
TEST_INTERCHANGE = "TEST_ONLY_NOT_O11"


class IntegratedError(ValueError):
    """The input is outside the closed integrated evidence grammar."""


@dataclass(frozen=True)
class IntegratedMutation:
    """One closed test-only mutation of the integrated work order."""

    identifier: str | None = None

    def enabled(self, identifier: str) -> bool:
        return self.identifier == identifier


@dataclass(frozen=True)
class CredentialBinding:
    """Authenticated O-07/C0.2j binding selected by the local resolver."""

    context: bytes
    credential_identifier: bytes
    author_sequence: int
    suite_id: int
    verification_key: bytes
    authority_state: str = "ACTIVE"
    provenance: str = "O07_GENESIS"


@dataclass(frozen=True)
class BindingResolution:
    """Trusted-local resolver result, never decoded from candidate bytes."""

    bindings: tuple[CredentialBinding, ...]
    authenticated: bool = True


@dataclass(frozen=True)
class BindingStore:
    """Closed in-memory resolver used by the bounded model."""

    records: Mapping[tuple[bytes, bytes, int], BindingResolution]

    @classmethod
    def from_bindings(cls, *bindings: CredentialBinding) -> "BindingStore":
        records: dict[tuple[bytes, bytes, int], BindingResolution] = {}
        for binding in bindings:
            key = (
                binding.context,
                binding.credential_identifier,
                binding.author_sequence,
            )
            if key in records:
                raise IntegratedError("duplicate resolver key")
            records[key] = BindingResolution((binding,))
        return cls(records)

    def resolve(self, event: EventAssignment) -> BindingResolution | None:
        return self.records.get(
            (
                event.context_identifier,
                event.credential_identifier,
                event.author_sequence,
            )
        )


@dataclass(frozen=True)
class SignedEventCandidate:
    """Test-only signature carriage outside the frozen O-06b-1 transcript."""

    event: EventAssignment
    signature: bytes
    declared_transcript_octets: int
    declared_key_octets: int | None = None
    declared_signature_octets: int | None = None
    event_suite_override: int | None = None
    event_key_override: bytes | None = None
    grant_suite_id: int | None = None
    grant_verification_key: bytes | None = None
    transport_valid: bool = False
    session_valid: bool = False
    supplied_transcript: bytes | None = None
    candidate_historical_evidence: bool | None = None


@dataclass(frozen=True)
class ProjectionState:
    """Trusted-local O-06c/AP state consulted only after K verification."""

    historical_evidence: bool = False
    duplicate: bool = False
    stale_evidence: bool = False
    s4_failures: tuple[str, ...] = ()
    authority_projection_unavailable: bool = False
    event_failures: tuple[str, ...] = ()
    authorized: bool = True
    s6_failures: tuple[str, ...] = ()


@dataclass
class IntegratedWorkCounter:
    """Observable evidence that bounds precede proportional work and AP."""

    envelope_checks: int = 0
    structural_checks: int = 0
    transcript_regenerations: int = 0
    transcript_parses: int = 0
    transcript_hashes: int = 0
    binding_resolutions: int = 0
    point_guards: int = 0
    verifier_invocations: int = 0
    ap_exposures: int = 0
    o06c: TranscriptWorkCounter = field(default_factory=TranscriptWorkCounter)

    def record(self) -> dict[str, object]:
        return {
            "ap_exposures": self.ap_exposures,
            "binding_resolutions": self.binding_resolutions,
            "envelope_checks": self.envelope_checks,
            "o06c": self.o06c.record(),
            "point_guards": self.point_guards,
            "structural_checks": self.structural_checks,
            "transcript_hashes": self.transcript_hashes,
            "transcript_parses": self.transcript_parses,
            "transcript_regenerations": self.transcript_regenerations,
            "verifier_invocations": self.verifier_invocations,
        }


@dataclass(frozen=True)
class IntegratedResult:
    primary: str
    remote: str
    owner: str
    stage: str
    recovery: str | None
    auxiliary: tuple[str, ...]
    ap_exposed: bool
    verifier_invocations: int
    transcript: bytes | None
    event_reference: bytes | None
    work: Mapping[str, object]

    @property
    def applied(self) -> bool:
        return self.primary == "APPLIED"

    def record(self) -> dict[str, object]:
        return {
            "ap_exposed": self.ap_exposed,
            "applied": self.applied,
            "auxiliary": list(self.auxiliary),
            "event_reference": (
                self.event_reference.hex() if self.event_reference is not None else None
            ),
            "interchange": TEST_INTERCHANGE,
            "owner": self.owner,
            "primary": self.primary,
            "recovery": self.recovery,
            "remote": self.remote,
            "stage": self.stage,
            "transcript": self.transcript.hex() if self.transcript is not None else None,
            "verifier_invocations": self.verifier_invocations,
            "work": dict(self.work),
        }


def load_selected_envelope(path: Path = SELECTED_ENVELOPE_PATH) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != {
        "candidate_digest",
        "candidate_id",
        "entries",
        "envelope_version",
        "profile",
        "schema",
    }:
        raise IntegratedError("selected envelope schema mismatch")
    entries = payload["entries"]
    if not isinstance(entries, dict) or len(entries) != EXPECTED_ENVELOPE_ENTRY_COUNT:
        raise IntegratedError("selected envelope entry count mismatch")
    entry_count = sum(
        entry.get("role") in ENTRY_ROLES
        for entry in entries.values()
        if isinstance(entry, dict)
    )
    if entry_count != EXPECTED_ENTRY_DIMENSION_COUNT:
        raise IntegratedError("selected envelope entry partition mismatch")
    handoff_count = sum(
        len(entry.get("stages", ()))
        for entry in entries.values()
        if isinstance(entry, dict) and entry.get("role") in ENTRY_ROLES
    )
    if handoff_count != EXPECTED_HANDOFF_COUNT:
        raise IntegratedError("selected envelope handoff count mismatch")
    return payload


def envelope_dispositions(
    envelope: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], ...]:
    """Return the exhaustive, closed disposition of all 69 O-08 entries."""

    envelope = envelope or load_selected_envelope()
    entries = envelope["entries"]
    rows = []
    for dimension in sorted(entries):
        entry = entries[dimension]
        role = entry["role"]
        rows.append(
            {
                "dimension": dimension,
                "disposition": "CONSUMED" if role in ENTRY_ROLES else "NOT_CONSUMED",
                "role": role,
                "stages": list(entry["stages"]),
            }
        )
    if len(rows) != EXPECTED_ENVELOPE_ENTRY_COUNT:
        raise IntegratedError("envelope disposition is not exhaustive")
    return tuple(rows)


def envelope_handoffs(
    envelope: Mapping[str, object] | None = None,
) -> tuple[dict[str, str], ...]:
    """Return all 66 selected dimension/stage handoff rows."""

    envelope = envelope or load_selected_envelope()
    rows = []
    for dimension in sorted(envelope["entries"]):
        entry = envelope["entries"][dimension]
        if entry["role"] not in ENTRY_ROLES:
            continue
        for stage in entry["stages"]:
            rows.append(
                {
                    "dimension": dimension,
                    "primary": recovery_for(dimension, stage, entry["role"]),
                    "stage": stage,
                }
            )
    if len(rows) != EXPECTED_HANDOFF_COUNT:
        raise IntegratedError("envelope handoff relation mismatch")
    if len({(row["dimension"], row["stage"]) for row in rows}) != len(rows):
        raise IntegratedError("duplicate envelope handoff row")
    return tuple(rows)


def envelope_boundary_cases(
    envelope: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], ...]:
    """Derive every required O-08 boundary observation without large inputs."""

    envelope = envelope or load_selected_envelope()
    rows: list[dict[str, object]] = []
    for dimension in sorted(envelope["entries"]):
        entry = envelope["entries"][dimension]
        if entry["role"] not in ENTRY_ROLES:
            continue
        selected = entry["selected_value"]
        comparison = entry["comparison"]
        if comparison == "EXACT_CLOSED_SET":
            admitted = tuple(entry["closed_values"])
            observations = admitted + (max(admitted) + 1,)
        elif comparison == "EXACT_CLOSED_KEY_SET":
            observations = (selected, max(0, selected - 1))
        elif entry["role"] == ROLE_CAPABILITY:
            observations = tuple(dict.fromkeys((max(0, selected - 1), selected, selected + 1)))
        elif comparison == "EXACT_ZERO" or selected == 0:
            observations = (0, 1)
        elif comparison == "MAXIMUM":
            observations = (selected - 1, selected, selected + 1)
        else:
            raise IntegratedError("unknown boundary comparison")
        for ordinal, observed in enumerate(observations):
            accepted = _envelope_accepts(entry, observed)
            stage = entry["stages"][0]
            primary = "APPLIED"
            if not accepted:
                primary = recovery_for(dimension, stage, entry["role"])
                if dimension in {"SIGNATURE_OCTETS", "VERIFICATION_KEY_OCTETS"}:
                    primary = "LENGTH_MISMATCH"
            rows.append(
                {
                    "accepted": accepted,
                    "dimension": dimension,
                    "id": f"I-O08-BOUNDARY-{dimension}-{ordinal:02d}",
                    "observed": observed,
                    "primary": primary,
                    "stage": stage,
                }
            )
    if len({row["id"] for row in rows}) != len(rows):
        raise IntegratedError("duplicate envelope boundary case")
    return tuple(rows)


def evaluate_envelope_handoff(
    dimension: str,
    stage: str,
    *,
    envelope: Mapping[str, object] | None = None,
    integrated_mutation: IntegratedMutation = IntegratedMutation(),
) -> str:
    """Exercise one frozen dimension/stage violation and return its primary."""

    envelope = envelope or load_selected_envelope()
    try:
        entry = envelope["entries"][dimension]
    except KeyError as error:
        raise IntegratedError("unknown handoff dimension") from error
    if entry["role"] not in ENTRY_ROLES or stage not in entry["stages"]:
        raise IntegratedError("unknown handoff relation")
    if (
        integrated_mutation.enabled("I-M-SKIP-ENVELOPE")
        and dimension == "FRAMING_OBJECT_OCTETS"
        and stage == "S3_KERNEL_STRUCTURAL"
    ):
        return "APPLIED"
    primary = recovery_for(dimension, stage, entry["role"])
    if dimension in {"SIGNATURE_OCTETS", "VERIFICATION_KEY_OCTETS"}:
        primary = "LENGTH_MISMATCH"
    if primary not in PRIMARY_ROWS:
        raise IntegratedError("handoff selected unknown O-10 primary")
    return primary


def _envelope_accepts(entry: Mapping[str, object], observed: int) -> bool:
    if not isinstance(observed, int) or isinstance(observed, bool) or observed < 0:
        return False
    role = entry["role"]
    selected = entry["selected_value"]
    if role in {ROLE_POST, ROLE_EVIDENCE}:
        raise IntegratedError("non-entry dimension cannot influence C0.3")
    if not isinstance(selected, int) or isinstance(selected, bool):
        raise IntegratedError("entry dimension has no integer selected value")
    comparison = entry["comparison"]
    if comparison == "EXACT_CLOSED_KEY_SET":
        return observed == selected
    if comparison == "EXACT_CLOSED_SET":
        closed = entry["closed_values"]
        return observed in closed
    if role == ROLE_CAPABILITY:
        return observed >= selected
    if comparison in {"MAXIMUM", "EXACT_ZERO"}:
        return observed <= selected
    raise IntegratedError("unknown envelope comparison")


def _taxonomy_scenario(
    *,
    profile_activation_unsupported: bool = False,
    k_failures: tuple[str, ...] = (),
    duplicate: bool = False,
    stale_evidence: bool = False,
    s4_failures: tuple[str, ...] = (),
    authority_projection_unavailable: bool = False,
    event_failures: tuple[str, ...] = (),
    authorized: bool = True,
    s6_failures: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "id": "integrated-candidate",
        "profile_activation_unsupported": profile_activation_unsupported,
        "k_failures": list(dict.fromkeys(k_failures)),
        "duplicate": duplicate,
        "delivery_order": [],
        "stale_evidence": stale_evidence,
        "s4_failures": list(dict.fromkeys(s4_failures)),
        "authority_projection_unavailable": authority_projection_unavailable,
        "event_failures": list(dict.fromkeys(event_failures)),
        "authorized": authorized,
        "s6_failures": list(dict.fromkeys(s6_failures)),
        "mutation_provable": True,
    }


def _result(
    outcome: Outcome,
    work: IntegratedWorkCounter,
    *,
    transcript: bytes | None = None,
    reference: bytes | None = None,
) -> IntegratedResult:
    if outcome.primary not in PRIMARY_ROWS:
        raise IntegratedError("unknown O-10 primary")
    remote = "APPLIED" if outcome.primary == "APPLIED" else REMOTE_COLLAPSE
    return IntegratedResult(
        outcome.primary,
        remote,
        outcome.owner,
        outcome.stage,
        outcome.recovery,
        outcome.auxiliary,
        work.ap_exposures == 1,
        work.verifier_invocations,
        transcript,
        reference,
        work.record(),
    )


def _preflight_observations(candidate: SignedEventCandidate) -> dict[str, int]:
    event = candidate.event
    return {
        "AP_TRANSITION_BLOCK_OCTETS": len(event.transition_block),
        "CHECKPOINT_REFERENCES": 0,
        "FRAMING_OBJECT_OCTETS": candidate.declared_transcript_octets,
        "PARENTS_PER_EVENT": len(event.causal_parents),
        "PHYSICAL_TIME_SKEW": 0,
        "PROFILE_VERSION_SKEW": 0,
        "SEQUENCE_VALUE": event.author_sequence,
        "SIGNATURE_ATTEMPTS": 1,
        "SIGNATURE_OCTETS": (
            len(candidate.signature)
            if candidate.declared_signature_octets is None
            else candidate.declared_signature_octets
        ),
    }


def _classify_envelope_failures(
    envelope: Mapping[str, object],
    observations: Mapping[str, int],
    work: IntegratedWorkCounter,
) -> tuple[bool, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    profile_unsupported = False
    k: list[str] = []
    s4: list[str] = []
    s6: list[str] = []
    entries = envelope["entries"]
    for dimension, observed in sorted(observations.items()):
        if dimension not in entries:
            raise IntegratedError(f"unknown envelope observation: {dimension}")
        entry = entries[dimension]
        if entry["role"] not in ENTRY_ROLES:
            raise IntegratedError("post-C0.3 observation supplied to integrated model")
        work.envelope_checks += 1
        if _envelope_accepts(entry, observed):
            continue
        for stage in entry["stages"]:
            primary = recovery_for(dimension, stage, entry["role"])
            if stage == "S0_PROFILE_ACTIVATION":
                profile_unsupported = True
            elif dimension in {"SIGNATURE_OCTETS", "VERIFICATION_KEY_OCTETS"}:
                k.append("LENGTH_MISMATCH")
            elif stage == "S3_KERNEL_STRUCTURAL":
                k.append(primary)
            elif stage == "S4_GRAPH_ADMISSION":
                s4.append(primary)
            elif stage == "S6_DURABLE_COMMIT":
                s6.append(primary)
            elif stage == "S5_AUTHORITY_PROJECTION":
                # O-10 models this as a dedicated gate rather than an array.
                if primary != "AUTHORITY_PROJECTION_UNAVAILABLE":
                    raise IntegratedError("unexpected S5 handoff primary")
            else:
                raise IntegratedError("entry dimension uses a non-C0.3 stage")
    return profile_unsupported, tuple(k), tuple(s4), tuple(s6)


_O14_LENGTH_CODES = frozenset({"PUBLIC_KEY_LENGTH", "SIGNATURE_LENGTH"})
_O14_INVALID_CODES = frozenset(
    {
        "NON_CANONICAL_SCALAR",
        "PUBLIC_KEY_NOT_PRIME_ORDER",
        "R_NOT_PRIME_ORDER",
        "NON_CANONICAL_POINT",
        "OFF_CURVE_POINT",
        "INVALID_POINT_ENCODING",
        "SIGNATURE_INVALID",
    }
)


def evaluate_candidate(
    candidate: SignedEventCandidate,
    store: BindingStore,
    projection: ProjectionState = ProjectionState(),
    *,
    profile_active: bool = True,
    observations: Mapping[str, int] | None = None,
    mutation: O14Mutation = O14Mutation(),
    integrated_mutation: IntegratedMutation = IntegratedMutation(),
    envelope: Mapping[str, object] | None = None,
) -> IntegratedResult:
    """Evaluate one candidate through the frozen integrated gate order."""

    work = IntegratedWorkCounter()
    if integrated_mutation.identifier not in {
        None,
        "I-M-SKIP-ENVELOPE",
        "I-M-AP-BEFORE-K",
        "I-M-HASH-BEFORE-BINDING",
        "I-M-TRUST-CANDIDATE-HISTORICAL",
        "I-M-FIRST-FAILURE-PRIMARY",
        "I-M-TRUST-EVENT-KEY",
        "I-M-RETRY-VERIFIER",
    }:
        raise IntegratedError("unknown integrated mutation")
    envelope = envelope or load_selected_envelope()
    merged_observations = _preflight_observations(candidate)
    for dimension, observed in (observations or {}).items():
        if dimension in merged_observations and merged_observations[dimension] != observed:
            raise IntegratedError("caller cannot override derived envelope observation")
        merged_observations[dimension] = observed

    if integrated_mutation.enabled("I-M-SKIP-ENVELOPE"):
        profile_failure, k_failures, s4, s6 = False, (), (), ()
    else:
        profile_failure, k_failures, s4, s6 = _classify_envelope_failures(
            envelope, merged_observations, work
        )
    if not profile_active:
        profile_failure = True
    # Activation is the only outcome that is selected before candidate work.
    if profile_failure:
        return _result(
            evaluate_taxonomy(
                _taxonomy_scenario(profile_activation_unsupported=True)
            ),
            work,
        )

    if integrated_mutation.enabled("I-M-AP-BEFORE-K"):
        work.ap_exposures += 1

    k = list(k_failures)
    work.structural_checks += 1
    if (
        candidate.candidate_historical_evidence is not None
        and not integrated_mutation.enabled("I-M-TRUST-CANDIDATE-HISTORICAL")
    ):
        # Trusted historical status cannot be selected by event/envelope bytes.
        k.append("STRUCTURAL_REJECTION")

    # A declared bound is inspected before encoding or parsing the candidate.
    framing_limit = envelope["entries"]["FRAMING_OBJECT_OCTETS"]["selected_value"]
    if (
        not isinstance(candidate.declared_transcript_octets, int)
        or isinstance(candidate.declared_transcript_octets, bool)
        or candidate.declared_transcript_octets < 0
    ):
        k.append("STRUCTURAL_REJECTION")
    elif candidate.declared_transcript_octets > framing_limit:
        k.append("CURRENT_OBJECT_OUT_OF_PROFILE")

    transcript: bytes | None = None
    reference: bytes | None = None
    if not any(item in {"STRUCTURAL_REJECTION", "CURRENT_OBJECT_OUT_OF_PROFILE"} for item in k):
        try:
            regenerated = encode_event_transcript(candidate.event, work.o06c)
            work.transcript_regenerations += 1
            if len(regenerated) != candidate.declared_transcript_octets:
                k.append("LENGTH_MISMATCH")
            supplied = candidate.supplied_transcript
            if supplied is not None and supplied != regenerated:
                k.append("STRUCTURAL_REJECTION")
            parsed = parse_event_transcript(regenerated, work.o06c)
            work.transcript_parses += 1
            if parsed != candidate.event or encode_event_transcript(parsed) != regenerated:
                k.append("STRUCTURAL_REJECTION")
            transcript = regenerated
        except ModelError:
            k.append("STRUCTURAL_REJECTION")

    resolution = store.resolve(candidate.event)
    if (
        integrated_mutation.enabled("I-M-HASH-BEFORE-BINDING")
        and transcript is not None
        and (
            resolution is None
            or not resolution.authenticated
            or len(resolution.bindings) != 1
        )
    ):
        event_reference(candidate.event, work.o06c)
        work.transcript_hashes += 1
    work.binding_resolutions += 1
    binding: CredentialBinding | None = None
    if resolution is None:
        k.append("UNRESOLVABLE_CREDENTIAL")
    elif not resolution.authenticated:
        k.append("UNRESOLVED_CREDENTIAL_BINDING")
    elif len(resolution.bindings) != 1:
        k.append("UNRESOLVED_CREDENTIAL_BINDING")
    else:
        binding = resolution.bindings[0]
        if binding.provenance not in {"O07_GENESIS", "C02J_GRANT"}:
            k.append("UNRESOLVED_CREDENTIAL_BINDING")
        if (
            binding.context != candidate.event.context_identifier
            or binding.credential_identifier != candidate.event.credential_identifier
            or binding.author_sequence != candidate.event.author_sequence
        ):
            k.append("CREDENTIAL_BINDING_MISMATCH")
        key_length = (
            len(binding.verification_key)
            if candidate.declared_key_octets is None
            else candidate.declared_key_octets
        )
        if not _envelope_accepts(
            envelope["entries"]["VERIFICATION_KEY_OCTETS"], key_length
        ) or key_length != len(binding.verification_key):
            k.append("LENGTH_MISMATCH")
        retry_unknown_suite = integrated_mutation.enabled(
            "I-M-RETRY-VERIFIER"
        ) and binding.suite_id != SUITE_ID
        if binding.suite_id != SUITE_ID and not retry_unknown_suite:
            k.append("CURRENT_OBJECT_OUT_OF_PROFILE")

    # Frozen O-10 precedence selects among every accumulated K failure.
    if (
        integrated_mutation.enabled("I-M-FIRST-FAILURE-PRIMARY")
        and binding is not None
        and binding.authority_state != "ACTIVE"
    ):
        inactive = {
            "REVOKED": "POST_REVOCATION",
            "ROTATED": "POST_REVOCATION",
            "RECOVERY_RETIRED": "POST_REVOCATION",
            "QUARANTINED": "LINEAGE_QUARANTINED",
        }.get(binding.authority_state, "AUTHENTIC_BUT_UNAUTHORIZED")
        return _result(
            evaluate_taxonomy(_taxonomy_scenario(event_failures=(inactive,))),
            work,
            transcript=transcript,
        )
    if k:
        selected_k = tuple(k)
        if integrated_mutation.enabled("I-M-FIRST-FAILURE-PRIMARY"):
            selected_k = (selected_k[0],)
        return _result(
            evaluate_taxonomy(_taxonomy_scenario(k_failures=selected_k)),
            work,
            transcript=transcript,
        )
    if transcript is None or binding is None:
        raise IntegratedError("K path reached verifier without transcript or binding")

    # The frozen O-14 implementation's inactive shortcut is deliberately not
    # used here: integrated precedence completes K first, then selects event
    # authority from the trusted projection and retained binding state.
    o14_binding = O14CredentialBinding(
        binding.context,
        binding.credential_identifier,
        SUITE_ID if retry_unknown_suite else binding.suite_id,
        (
            candidate.event_key_override
            if integrated_mutation.enabled("I-M-TRUST-EVENT-KEY")
            and candidate.event_key_override is not None
            else binding.verification_key
        ),
        authority_state="ACTIVE",
        expected_author_sequence=binding.author_sequence,
    )
    o14_event = O14EventInput(
        candidate.event.context_identifier,
        candidate.event.credential_identifier,
        candidate.event.author_sequence,
        transcript,
        candidate.signature,
        o14_binding,
        event_suite_override=candidate.event_suite_override,
        event_key_override=candidate.event_key_override,
        transport_valid=candidate.transport_valid,
        session_valid=candidate.session_valid,
        grant_suite_id=candidate.grant_suite_id,
        grant_verification_key=candidate.grant_verification_key,
        ap_authorized=True,
        declared_key_length=(
            len(binding.verification_key)
            if candidate.declared_key_octets is None
            else candidate.declared_key_octets
        ),
        declared_signature_length=(
            len(candidate.signature)
            if candidate.declared_signature_octets is None
            else candidate.declared_signature_octets
        ),
        historical_evidence=False,
    )
    verification = verify_event(o14_event, mutation)
    work.verifier_invocations = verification.verifier_invocations
    if retry_unknown_suite:
        work.verifier_invocations += 1
    work.point_guards = int(any(branch.startswith("guard:") for branch in verification.executed_branches))
    if verification.code in _O14_LENGTH_CODES:
        k.append("LENGTH_MISMATCH")
    elif verification.code == "UNKNOWN_SIGNATURE_SUITE":
        k.append("CURRENT_OBJECT_OUT_OF_PROFILE")
    elif verification.code in _O14_INVALID_CODES:
        k.append("INVALID")
    elif not verification.accepted or verification.code != "ACCEPTED":
        raise IntegratedError(f"unknown O-14 diagnostic: {verification.code}")
    if verification.verifier_invocations not in {0, 1}:
        k.append("INVALID")
    if k:
        return _result(
            evaluate_taxonomy(_taxonomy_scenario(k_failures=tuple(k))),
            work,
            transcript=transcript,
        )

    if verification.verifier_invocations != 1:
        raise IntegratedError("accepted K path did not invoke exactly one verifier")
    work.transcript_hashes += 1
    reference = event_reference(candidate.event, work.o06c)
    if work.ap_exposures == 0:
        work.ap_exposures += 1

    event_failures = list(projection.event_failures)
    if binding.authority_state != "ACTIVE":
        inactive = {
            "REVOKED": "POST_REVOCATION",
            "ROTATED": "POST_REVOCATION",
            "RECOVERY_RETIRED": "POST_REVOCATION",
            "QUARANTINED": "LINEAGE_QUARANTINED",
        }.get(binding.authority_state, "AUTHENTIC_BUT_UNAUTHORIZED")
        event_failures.append(inactive)
    outcome = evaluate_taxonomy(
        _taxonomy_scenario(
            duplicate=projection.duplicate,
            stale_evidence=projection.stale_evidence,
            s4_failures=tuple(dict.fromkeys(s4 + projection.s4_failures)),
            authority_projection_unavailable=projection.authority_projection_unavailable,
            event_failures=tuple(event_failures),
            authorized=projection.authorized,
            s6_failures=tuple(dict.fromkeys(s6 + projection.s6_failures)),
        )
    )
    return _result(outcome, work, transcript=transcript, reference=reference)


def canonical_result_bytes(result: IntegratedResult) -> bytes:
    return (
        json.dumps(result.record(), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def frozen_projection_identity() -> str:
    """Digest the imported O-10 rows/order used by the integration."""

    payload = {
        "event_precedence": list(EVENT_PRECEDENCE),
        "k_precedence": list(K_PRECEDENCE),
        "primaries": {key: list(value) for key, value in sorted(PRIMARY_ROWS.items())},
        "remote": REMOTE_COLLAPSE,
    }
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
