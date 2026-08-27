#!/usr/bin/env python3
"""Execute the closed integrated O-14/O-06c witness inventory."""

from __future__ import annotations

import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import stat
import subprocess
import sys

sys.dont_write_bytecode = True

from integrated_model import (
    BindingResolution,
    BindingStore,
    CredentialBinding,
    IntegratedResult,
    ProjectionState,
    SignedEventCandidate,
    canonical_result_bytes,
    envelope_boundary_cases,
    envelope_dispositions,
    envelope_handoffs,
    evaluate_candidate,
    evaluate_envelope_handoff,
    frozen_projection_identity,
)
from integrated_registry import PROBE_SCHEMA, registry_record, required_witnesses
from protocol_model import (
    CONTENT_DETACHABLE,
    CONTENT_NONE,
    CONTENT_REQUIRED,
    CONTROL_CLOSURE,
    CONTROL_GRANT,
    CONTROL_POLICY,
    CONTROL_RECOVER,
    CONTROL_REVOKE,
    CONTROL_ROTATE,
    ROLE_CREDENTIAL,
    ROLE_ORDINARY,
    ROLE_REMOVAL,
    CommitmentContext,
    ContentDescriptor,
    CredentialTail,
    EventAssignment,
    RemovalTail,
    build_commitment,
    descriptor_from_commitment,
    encode_event_transcript,
)
from o10.canonical_report import store_report
from o14.ed25519_reference import L, sign_from_seed


REPORT_FIELDS = frozenset(
    {
        "boundary_count",
        "boundary_results",
        "disposition_count",
        "dispositions",
        "handoff_count",
        "handoff_results",
        "interchange",
        "projection_digest",
        "registry_digest",
        "schema",
        "verdict",
        "witness_count",
        "witness_results",
    }
)

PINNED_INPUTS = {
    "tools/causal-flow-simulator/o07/genesis_model.py": "43a59519ab9a140bb3169026d670d7ae6e636002c8f62b988c2958da602b6d66",
    "tools/causal-flow-simulator/o08/resource-envelope.candidate.json": "3f66c0620699b260d11ba014a7355ec5234db1aad12a3e4d9ce797e5b98c5b3e",
    "tools/causal-flow-simulator/o08/resource-envelope.sources.json": "b32c852437805b1c9524fecdfb6e86e940693614fac59a70e2ba4ba4600e5f45",
    "tools/causal-flow-simulator/o10/outcome-taxonomy.json": "9565280a5e9a8c8035188cb1c652e2bed3c9496ad05ad0883b0acc07befb7e24",
    "tools/causal-flow-simulator/o10/source-inventory.json": "f2209badb8e142fb08e1402345d496c5d799360c0835394828a2d3c4557e737a",
    "tools/causal-flow-simulator/o14/semantic_registry.py": "0c18394d713367efb9d95aa325b050be0fbc06031528d8fabe7006427bf3ff88",
    "tools/causal-flow-simulator/o14/ed25519_reference.py": "e2ed8c97da836d39fece580f2cd81c155059e92fb65a3a5bc2357e05a59fb598",
    "tools/causal-flow-simulator/o06c/protocol_model.py": "f0cf5f98fbdd0e9edd498402f869aba75813c2fcde1f4b7b58355337ea304489",
    "tools/causal-flow-simulator/o06c/combined_falsification_probe.py": "2439048732ecd8a60bfc78d38d7f64a141adacaea9ee332acaf4bdce470c6afe",
    "docs/protocol/styx-app-kernel-v0-signature-suite-analysis.md": "4f24a696cf7e5333b5195e17cf1af72b44661f71590bd3f44f0d5c279e098fc8",
    "docs/protocol/styx-app-kernel-v0-identifier-commitment-falsification-report.md": "930447760fd68152519a2859d2c94fde8c896223450e8e1bf1db460e3e52c376",
}


class ProbeError(ValueError):
    """The closed probe could not produce complete evidence."""


def _bytes(label: str) -> bytes:
    return sha256(f"STYX-INTEGRATED|{label}".encode("utf-8")).digest()


def _base_event(
    *,
    role: int = ROLE_ORDINARY,
    content: ContentDescriptor | None = None,
    tail: CredentialTail | RemovalTail | None = None,
    sequence: int = 0,
) -> EventAssignment:
    return EventAssignment(
        application_profile_id=1,
        application_profile_version=1,
        context_identifier=_bytes("context"),
        event_role=role,
        event_type_id=7,
        schema_id=11,
        schema_version=1,
        transition_block=b"ap-transition",
        credential_identifier=_bytes("credential"),
        author_sequence=sequence,
        direct_predecessor=None if sequence == 0 else _bytes(f"predecessor-{sequence}"),
        causal_parents=() if sequence == 0 else (_bytes("causal-parent"),),
        genesis_reference=_bytes("genesis"),
        content=content or ContentDescriptor(CONTENT_NONE, 0),
        tail=tail,
    )


def _sign(
    event: EventAssignment,
    *,
    authority_state: str = "ACTIVE",
    signature_event: EventAssignment | None = None,
    seed: bytes = bytes(range(32)),
) -> tuple[SignedEventCandidate, CredentialBinding]:
    transcript = encode_event_transcript(event)
    signed_transcript = encode_event_transcript(signature_event or event)
    key, signature = sign_from_seed(seed, signed_transcript)
    binding = CredentialBinding(
        event.context_identifier,
        event.credential_identifier,
        event.author_sequence,
        1,
        key,
        authority_state,
    )
    return SignedEventCandidate(event, signature, len(transcript)), binding


def _content_event(content_class: int, *, tree: bool) -> EventAssignment:
    base = _base_event()
    context = CommitmentContext(
        base.application_profile_id,
        base.application_profile_version,
        base.context_identifier,
        base.credential_identifier,
        base.author_sequence,
    )
    content = b"integrated-content-tree" if tree else b"integrated-content"
    commitment = build_commitment(
        context,
        19,
        content,
        _bytes("randomizer"),
        chunk_size=4 if tree else None,
    )
    return replace(
        base,
        content=descriptor_from_commitment(content_class, commitment),
    )


def _control_event(kind: int) -> EventAssignment:
    values = {
        CONTROL_GRANT: CredentialTail(
            kind,
            grantee_suite_id=1,
            grantee_verification_key=_bytes("grantee-key"),
        ),
        CONTROL_REVOKE: CredentialTail(kind, target_credential_id=_bytes("target")),
        CONTROL_ROTATE: CredentialTail(
            kind,
            retiring_credential_id=_bytes("retiring"),
            replacement_grant_reference=_bytes("replacement"),
        ),
        CONTROL_RECOVER: CredentialTail(
            kind,
            retired_credential_id=_bytes("retired"),
            recovery_grant_reference=_bytes("recovery"),
        ),
        CONTROL_POLICY: CredentialTail(kind),
        CONTROL_CLOSURE: CredentialTail(kind),
    }
    return _base_event(role=ROLE_CREDENTIAL, tail=values[kind])


def _removal_event() -> EventAssignment:
    return _base_event(
        role=ROLE_REMOVAL,
        tail=RemovalTail(_bytes("removed-event"), _bytes("removed-commitment")),
    )


def _evaluate(
    candidate: SignedEventCandidate,
    binding: CredentialBinding,
    projection: ProjectionState = ProjectionState(),
    *,
    store: BindingStore | None = None,
) -> IntegratedResult:
    return evaluate_candidate(
        candidate,
        store or BindingStore.from_bindings(binding),
        projection,
    )


def _fixed_result(identifier: str) -> IntegratedResult:
    candidate, binding = _sign(_base_event())
    projection = ProjectionState()
    store: BindingStore | None = None

    positive_events = {
        "I-POS-ORDINARY": _base_event(),
        "I-POS-REMOVAL": _removal_event(),
        "I-POS-GRANT": _control_event(CONTROL_GRANT),
        "I-POS-REVOKE": _control_event(CONTROL_REVOKE),
        "I-POS-ROTATE": _control_event(CONTROL_ROTATE),
        "I-POS-RECOVER": _control_event(CONTROL_RECOVER),
        "I-POS-POLICY": _control_event(CONTROL_POLICY),
        "I-POS-CLOSURE": _control_event(CONTROL_CLOSURE),
        "I-POS-CONTENT-NONE": _base_event(),
        "I-POS-CONTENT-REQUIRED-SINGLE": _content_event(CONTENT_REQUIRED, tree=False),
        "I-POS-CONTENT-DETACHABLE-TREE": _content_event(CONTENT_DETACHABLE, tree=True),
    }
    if identifier in positive_events:
        candidate, binding = _sign(positive_events[identifier])
    elif identifier == "I-STATE-DUPLICATE":
        projection = ProjectionState(duplicate=True)
    elif identifier == "I-STATE-PENDING-OPENING":
        projection = ProjectionState(event_failures=("PENDING_OPENING",))
    elif identifier == "I-STATE-PENDING-ANCESTOR":
        projection = ProjectionState(event_failures=("PENDING_ANCESTOR",))
    elif identifier == "I-STATE-REMOVAL-INAPPLICABLE":
        projection = ProjectionState(event_failures=("REMOVAL_INAPPLICABLE",))
    elif identifier == "I-STATE-FORK":
        projection = ProjectionState(
            event_failures=("AUTHENTIC_BUT_UNAUTHORIZED", "FORK_EVIDENCE")
        )
    elif identifier in {
        "I-STATE-REVOKED",
        "I-STATE-ROTATED",
        "I-STATE-RECOVERY-PREDECESSOR",
    }:
        state = {
            "I-STATE-REVOKED": "REVOKED",
            "I-STATE-ROTATED": "ROTATED",
            "I-STATE-RECOVERY-PREDECESSOR": "RECOVERY_RETIRED",
        }[identifier]
        candidate, binding = _sign(_base_event(), authority_state=state)
        projection = ProjectionState(historical_evidence=True)
    elif identifier == "I-STATE-QUARANTINED":
        candidate, binding = _sign(_base_event(), authority_state="QUARANTINED")
        projection = ProjectionState(historical_evidence=True)
    elif identifier == "I-STATE-AP-DENIED":
        projection = ProjectionState(authorized=False)
    elif identifier == "I-K-MISSING":
        store = BindingStore({})
    elif identifier in {"I-K-INCOMPLETE", "I-K-AMBIGUOUS"}:
        key = (
            candidate.event.context_identifier,
            candidate.event.credential_identifier,
            candidate.event.author_sequence,
        )
        resolution = (
            BindingResolution((), authenticated=False)
            if identifier == "I-K-INCOMPLETE"
            else BindingResolution((binding, binding))
        )
        store = BindingStore({key: resolution})
    elif identifier == "I-K-BINDING-MISMATCH":
        mismatched = replace(binding, context=_bytes("other-context"))
        key = (
            candidate.event.context_identifier,
            candidate.event.credential_identifier,
            candidate.event.author_sequence,
        )
        store = BindingStore({key: BindingResolution((mismatched,))})
    elif identifier == "I-K-UNKNOWN-SUITE":
        binding = replace(binding, suite_id=2)
    elif identifier in {"I-K-KEY-31", "I-K-KEY-33"}:
        size = 31 if identifier.endswith("31") else 33
        binding = replace(binding, verification_key=binding.verification_key[:size].ljust(size, b"x"))
    elif identifier in {"I-K-SIG-63", "I-K-SIG-65"}:
        size = 63 if identifier.endswith("63") else 65
        candidate = replace(candidate, signature=candidate.signature[:size].ljust(size, b"x"))
    elif identifier == "I-K-SCALAR-L":
        candidate = replace(
            candidate,
            signature=candidate.signature[:32] + L.to_bytes(32, "little"),
        )
    elif identifier in {"I-K-BITFLIP", "I-SUB-TRANSPORT", "I-SUB-SESSION"}:
        changed = candidate.signature[:40] + bytes([candidate.signature[40] ^ 1]) + candidate.signature[41:]
        candidate = replace(
            candidate,
            signature=changed,
            transport_valid=identifier == "I-SUB-TRANSPORT",
            session_valid=identifier == "I-SUB-SESSION",
        )
    elif identifier == "I-K-CANDIDATE-HISTORICAL":
        candidate = replace(candidate, candidate_historical_evidence=True)
    elif identifier == "I-SUB-EVENT-SUITE":
        candidate = replace(candidate, event_suite_override=2)
    elif identifier == "I-SUB-EVENT-KEY":
        candidate = replace(candidate, event_key_override=_bytes("event-key"))
    elif identifier == "I-SUB-GRANT-KEY":
        candidate = replace(
            candidate,
            grant_suite_id=2,
            grant_verification_key=_bytes("untrusted-grantee-key"),
        )
    elif identifier == "I-PRECEDENCE-STRUCTURAL-LENGTH":
        candidate = replace(
            candidate,
            supplied_transcript=b"not-the-regenerated-transcript",
            signature=candidate.signature[:-1],
        )
    elif identifier == "I-PRECEDENCE-INACTIVE-INVALID":
        candidate, binding = _sign(_base_event(), authority_state="REVOKED")
        candidate = replace(candidate, signature=bytes(64))
        projection = ProjectionState(historical_evidence=True)
    else:
        raise ProbeError(f"unknown fixed witness: {identifier}")
    return _evaluate(candidate, binding, projection, store=store)


def _transcript_mutation(field_name: str) -> tuple[EventAssignment, EventAssignment]:
    original = _base_event(sequence=1)
    simple = {
        "profile-id": replace(original, application_profile_id=2),
        "profile-version": replace(original, application_profile_version=2),
        "context": replace(original, context_identifier=_bytes("context-other")),
        "genesis-reference": replace(original, genesis_reference=_bytes("genesis-other")),
        "credential-identifier": replace(original, credential_identifier=_bytes("credential-other")),
        "author-sequence": replace(original, author_sequence=2),
        "predecessor": replace(original, direct_predecessor=_bytes("predecessor-other")),
        "causal-parents": replace(original, causal_parents=(_bytes("causal-other"),)),
        "event-type": replace(original, event_type_id=8),
        "schema-id": replace(original, schema_id=12),
        "schema-version": replace(original, schema_version=2),
        "transition-block": replace(original, transition_block=b"ap-transition-mutated"),
    }
    if field_name in simple:
        return original, simple[field_name]
    if field_name == "event-role":
        return original, replace(
            _removal_event(),
            author_sequence=1,
            direct_predecessor=original.direct_predecessor,
            causal_parents=original.causal_parents,
        )
    if field_name == "content-descriptor":
        return original, replace(
            _content_event(CONTENT_REQUIRED, tree=False),
            author_sequence=1,
            direct_predecessor=original.direct_predecessor,
            causal_parents=original.causal_parents,
        )
    if field_name == "commitment":
        committed = replace(
            _content_event(CONTENT_REQUIRED, tree=False),
            author_sequence=1,
            direct_predecessor=original.direct_predecessor,
            causal_parents=original.causal_parents,
        )
        changed = replace(
            committed,
            content=replace(committed.content, commitment_value=_bytes("other-commitment")),
        )
        return committed, changed
    if field_name in {"removal-target-reference", "removal-target-commitment"}:
        removal = replace(
            _removal_event(),
            author_sequence=1,
            direct_predecessor=original.direct_predecessor,
            causal_parents=original.causal_parents,
        )
        tail = removal.tail
        changed_tail = (
            replace(tail, target_event_reference=_bytes("other-removed-event"))
            if field_name.endswith("reference")
            else replace(tail, target_commitment=_bytes("other-removed-commitment"))
        )
        return removal, replace(removal, tail=changed_tail)
    control_by_field = {
        "control-kind": CONTROL_GRANT,
        "grantee-suite": CONTROL_GRANT,
        "grantee-key": CONTROL_GRANT,
        "target-credential": CONTROL_REVOKE,
        "retiring-credential": CONTROL_ROTATE,
        "replacement-grant": CONTROL_ROTATE,
        "retired-credential": CONTROL_RECOVER,
        "recovery-grant": CONTROL_RECOVER,
    }
    if field_name not in control_by_field:
        raise ProbeError(f"unknown transcript field: {field_name}")
    control = replace(
        _control_event(control_by_field[field_name]),
        author_sequence=1,
        direct_predecessor=original.direct_predecessor,
        causal_parents=original.causal_parents,
    )
    tail = control.tail
    replacements = {
        "grantee-suite": {"grantee_suite_id": 2},
        "grantee-key": {"grantee_verification_key": _bytes("other-grantee")},
        "target-credential": {"target_credential_id": _bytes("other-target")},
        "retiring-credential": {"retiring_credential_id": _bytes("other-retiring")},
        "replacement-grant": {"replacement_grant_reference": _bytes("other-replacement")},
        "retired-credential": {"retired_credential_id": _bytes("other-retired")},
        "recovery-grant": {"recovery_grant_reference": _bytes("other-recovery")},
    }
    if field_name == "control-kind":
        changed = replace(
            _control_event(CONTROL_POLICY),
            author_sequence=1,
            direct_predecessor=original.direct_predecessor,
            causal_parents=original.causal_parents,
        )
    else:
        changed = replace(control, tail=replace(tail, **replacements[field_name]))
    return control, changed


def _transcript_result(identifier: str) -> IntegratedResult:
    field_name = identifier.removeprefix("I-TRANSCRIPT-").lower()
    original, mutated = _transcript_mutation(field_name)
    candidate, binding = _sign(mutated, signature_event=original)
    return _evaluate(candidate, binding)


def _result_matches(spec, result: IntegratedResult) -> bool:
    return (
        result.primary == spec.expected_local_primary
        and result.remote == spec.expected_remote_result
        and result.ap_exposed == spec.expected_ap_exposure
        and result.verifier_invocations == spec.expected_verifier_invocations
    )


def _verify_pins(repo_root: Path) -> None:
    for relative, expected in PINNED_INPUTS.items():
        path = repo_root / relative
        if path.is_symlink() or not path.is_file():
            raise ProbeError("pinned input is missing or not a regular file")
        if sha256(path.read_bytes()).hexdigest() != expected:
            raise ProbeError("pinned input digest mismatch")


def _verify_execution_identity(
    repo_root: Path,
    base: str,
    candidate: str,
    bundle: Path,
    bundle_sha256: str,
) -> None:
    _verify_pins(repo_root)
    if len(bundle_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in bundle_sha256):
        raise ProbeError("bundle digest is not canonical")
    if bundle.is_symlink() or not bundle.is_file() or not stat.S_ISREG(bundle.stat().st_mode):
        raise ProbeError("bundle is not a regular file")
    if sha256(bundle.read_bytes()).hexdigest() != bundle_sha256:
        raise ProbeError("bundle digest mismatch")
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(repo_root), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    if git("rev-parse", "HEAD") != candidate:
        raise ProbeError("candidate checkout mismatch")
    subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", base, candidate],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        ["git", "-C", str(repo_root), "bundle", "verify", str(bundle.resolve())],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def build_report() -> dict[str, object]:
    specs = required_witnesses()
    fixed = [item for item in specs if item.source_family not in {
        "transcript-substitution", "o08-disposition", "o08-handoff", "o08-boundary"
    }]
    transcript = [item for item in specs if item.source_family == "transcript-substitution"]
    witness_results = []
    for spec in fixed:
        actual = _fixed_result(spec.identifier)
        witness_results.append(
            {
                "actual_ap_exposure": actual.ap_exposed,
                "actual_local_primary": actual.primary,
                "actual_remote_result": actual.remote,
                "actual_verifier_invocations": actual.verifier_invocations,
                "detectors": list(spec.detectors),
                "id": spec.identifier,
                "passed": _result_matches(spec, actual),
            }
        )
    for spec in transcript:
        actual = _transcript_result(spec.identifier)
        witness_results.append(
            {
                "actual_ap_exposure": actual.ap_exposed,
                "actual_local_primary": actual.primary,
                "actual_remote_result": actual.remote,
                "actual_verifier_invocations": actual.verifier_invocations,
                "detectors": list(spec.detectors),
                "id": spec.identifier,
                "passed": _result_matches(spec, actual),
            }
        )

    dispositions = list(envelope_dispositions())
    disposition_specs = {
        item.identifier: item for item in specs if item.source_family == "o08-disposition"
    }
    disposition_results = []
    for row in dispositions:
        identifier = f"I-O08-DISPOSITION-{row['dimension']}"
        spec = disposition_specs[identifier]
        disposition_results.append(
            {
                "detectors": list(spec.detectors),
                "dimension": row["dimension"],
                "disposition": row["disposition"],
                "id": identifier,
                "passed": (
                    row["disposition"]
                    == ("CONSUMED" if row["role"].startswith("C03_") else "NOT_CONSUMED")
                ),
                "role": row["role"],
                "stages": row["stages"],
            }
        )

    handoff_specs = {
        item.identifier: item for item in specs if item.source_family == "o08-handoff"
    }
    handoff_results = []
    for row in envelope_handoffs():
        identifier = f"I-O08-HANDOFF-{row['dimension']}-{row['stage']}"
        spec = handoff_specs[identifier]
        actual = evaluate_envelope_handoff(row["dimension"], row["stage"])
        handoff_results.append(
            {
                "actual_local_primary": actual,
                "detectors": list(spec.detectors),
                "dimension": row["dimension"],
                "id": identifier,
                "passed": actual == spec.expected_local_primary,
                "stage": row["stage"],
            }
        )

    boundary_specs = {
        item.identifier: item for item in specs if item.source_family == "o08-boundary"
    }
    boundary_results = []
    for row in envelope_boundary_cases():
        spec = boundary_specs[row["id"]]
        boundary_results.append(
            {
                "accepted": row["accepted"],
                "actual_local_primary": row["primary"],
                "detectors": list(spec.detectors),
                "dimension": row["dimension"],
                "id": row["id"],
                "observed": row["observed"],
                "passed": row["primary"] == spec.expected_local_primary,
                "stage": row["stage"],
            }
        )

    executed = {
        item["id"]
        for family in (witness_results, disposition_results, handoff_results, boundary_results)
        for item in family
    }
    required = {item.identifier for item in specs}
    passed = (
        executed == required
        and all(
            item["passed"]
            for family in (witness_results, disposition_results, handoff_results, boundary_results)
            for item in family
        )
    )
    registry_bytes = json.dumps(
        registry_record(), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "boundary_count": len(boundary_results),
        "boundary_results": boundary_results,
        "disposition_count": len(disposition_results),
        "dispositions": disposition_results,
        "handoff_count": len(handoff_results),
        "handoff_results": handoff_results,
        "interchange": "TEST_ONLY_NOT_O11",
        "projection_digest": frozen_projection_identity(),
        "registry_digest": sha256(registry_bytes).hexdigest(),
        "schema": PROBE_SCHEMA,
        "verdict": "PASS" if passed else "FAIL",
        "witness_count": len(witness_results),
        "witness_results": witness_results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        _verify_execution_identity(
            args.repo_root.resolve(),
            args.base,
            args.candidate,
            args.bundle.resolve(),
            args.bundle_sha256,
        )
        report = build_report()
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (OSError, ProbeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"integrated probe failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(
        f"INTEGRATED PROBE verdict={report['verdict']} "
        f"witnesses={report['witness_count']} dispositions={report['disposition_count']} "
        f"handoffs={report['handoff_count']} boundaries={report['boundary_count']}"
    )
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
