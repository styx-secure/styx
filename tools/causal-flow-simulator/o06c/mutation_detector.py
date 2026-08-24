#!/usr/bin/env python3
"""End-to-end detector process executed against one staged source mutant."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys

from common import canonical_bytes
import historical_evidence_gate as history
import policy_guards as policy
import protocol_model as model
import verify_frozen_sections as frozen


def base_context() -> model.CommitmentContext:
    return model.CommitmentContext(1, 1, bytes.fromhex("11" * 32), bytes.fromhex("22" * 32), 0)


def none_event(**changes) -> model.EventAssignment:
    value = model.EventAssignment(
        application_profile_id=1,
        application_profile_version=1,
        context_identifier=bytes.fromhex("11" * 32),
        event_role=model.ROLE_ORDINARY,
        event_type_id=1,
        schema_id=1,
        schema_version=1,
        transition_block=b"ap",
        credential_identifier=bytes.fromhex("22" * 32),
        author_sequence=0,
        direct_predecessor=None,
        causal_parents=(),
        genesis_reference=bytes.fromhex("33" * 32),
        content=model.ContentDescriptor(model.CONTENT_NONE, 0),
    )
    return replace(value, **changes)


def detects(mutant: str) -> tuple[object, str, bool]:
    randomizer = bytes.fromhex("44" * 32)
    context = base_context()
    module: object = model
    detected = False
    detector = ""
    if mutant == "M01_TRANSCRIPT_DOMAIN_ROLE":
        detector = "CROSS_LANGUAGE_TRANSCRIPT_MISMATCH"
        detected = model.encode_event_transcript(none_event())[:16] != model.DOMAINS["application"]
    elif mutant == "M02_TRANSCRIPT_LENGTH":
        detector = "TRANSCRIPT_LENGTH_REJECT"
        try:
            model.parse_event_transcript(model.encode_event_transcript(none_event()))
        except model.ModelError:
            detected = True
    elif mutant == "M03_CREDENTIAL_TAIL":
        detector = "CREDENTIAL_TAIL_REJECT"
        grant = model.make_grant(
            issuer_credential=bytes.fromhex("22" * 32),
            context_identifier=bytes.fromhex("11" * 32),
            genesis_reference=bytes.fromhex("33" * 32),
            transition_block=b"grant",
            verification_key=b"key",
        )
        try:
            parsed = model.parse_event_transcript(model.encode_event_transcript(grant))
            detected = parsed.tail.grantee_suite_id != 1
        except model.ModelError:
            detected = True
    elif mutant == "M04_CONTEXT_84":
        detector = "CTX84_SUITE_DRIFT"
        commitment = model.build_commitment(context, 1, b"abc", randomizer)
        try:
            parsed = model.parse_commitment_preimage(commitment.commitment_preimage)
            detected = parsed["context"].commitment_suite_id != 1
        except model.ModelError:
            detected = True
    elif mutant == "M05_CREDENTIAL_BINDING":
        detector = "CREDENTIAL_BINDING_ALIAS"
        first = model.build_commitment(context, 1, b"abc", randomizer)
        second = model.build_commitment(
            replace(context, credential_identifier=bytes.fromhex("23" * 32)),
            1,
            b"abc",
            randomizer,
        )
        detected = first.commitment_value == second.commitment_value
    elif mutant == "M06_AUTHOR_SEQUENCE_BINDING":
        detector = "SEQUENCE_BINDING_ALIAS"
        first = model.build_commitment(context, 1, b"abc", randomizer)
        second = model.build_commitment(replace(context, author_sequence=1), 1, b"abc", randomizer)
        detected = first.commitment_value == second.commitment_value
    elif mutant == "M07_LEAF_PREIMAGE":
        detector = "LEAF_ORDINAL_ALIAS"
        value = model.build_commitment(context, 1, b"aaaa", randomizer, chunk_size=2)
        detected = value.leaf_digests[0] == value.leaf_digests[1]
    elif mutant == "M08_NODE_PREIMAGE":
        detector = "NODE_COUNT_DRIFT"
        value = model.build_commitment(context, 1, b"abcdef", randomizer, chunk_size=2)
        detected = model.parse_node_preimage(value.node_preimages[-1])["subtree_leaf_count"] != 3
    elif mutant == "M09_COMMITMENT_OBJECT":
        detector = "COMMITMENT_ROOT_DRIFT"
        value = model.build_commitment(context, 1, b"abc", randomizer)
        detected = model.parse_commitment_preimage(value.commitment_preimage)["root"] != value.root
    elif mutant == "M10_PARSER_GEOMETRY":
        detector = "INVALID_GEOMETRY_ACCEPTED"
        value = model.build_commitment(context, 1, b"abcdef", randomizer, chunk_size=2)
        malformed = bytearray(value.commitment_preimage)
        malformed[121:129] = (99).to_bytes(8, "big")
        try:
            model.parse_commitment_preimage(bytes(malformed))
            detected = True
        except model.ModelError:
            pass
    elif mutant == "M11_AUTHORITY_MUST0":
        module = policy
        detector = "MUST0_EXPANSION"
        detected = policy.reject_any_must0_bypass((False, True))
    elif mutant == "M12_PENDING_RETENTION":
        module = policy
        detector = "K_EVIDENCE_FILTERED"
        detected = policy.retain_k_evidence(("grant", "revoke"), ap_pending=True) != ("grant", "revoke")
    elif mutant == "M13_LINEAGE_FORK":
        module = policy
        detector = "UNRELATED_AUTHORITY_LOST"
        detected = policy.lineage_scoped_quarantine(
            frozenset({"forked", "independent"}), frozenset({"forked"})
        ) != frozenset({"independent"})
    elif mutant == "M14_FROZEN_DIGEST":
        module = frozen
        detector = "FROZEN_DIGEST_BYPASS"
        detected = frozen.digest_status("00" * 32, "01" * 32) == "PASS"
    elif mutant == "M15_HISTORICAL_REGISTRY":
        module = history
        detector = "EIGHTH_HISTORY_ACCEPTED"
        eighth = history.HistoricalEntry(
            "EIGHTH",
            "tools/causal-flow-simulator/nonexistent.py",
            "FAIL",
            "00" * 32,
        )
        try:
            history.validate_registry(history.HISTORICAL_REGISTRY + (eighth,))
            detected = True
        except history.HistoricalGateError:
            pass
    elif mutant == "M16_C03_CAPABILITY":
        module = policy
        detector = "C03_CAPABILITY_OPENED"
        detected = policy.c03_blocked_capabilities(
            "NO_GO",
            policy.C03_DEPENDENCIES,
            policy.C03_BLOCKED_CAPABILITIES,
        ) != policy.C03_BLOCKED_CAPABILITIES
    elif mutant == "M17_REMOVAL_PROJECTION":
        module = policy
        detector = "RETAINED_REMOVAL_NOT_APPLIED"
        reference = bytes.fromhex("55" * 32)
        commitment = bytes.fromhex("66" * 32)
        target = policy.RemovalTarget(
            reference,
            "DETACHABLE",
            ("DETACHABLE", 3, 1, 0, commitment),
            commitment,
            True,
            True,
            "BOUND",
            "VISIBLE",
        )
        projection = policy.project_removal_directive(
            (target,),
            target_reference=reference,
            target_commitment=commitment,
        )
        detected = (
            projection.classification != "REMOVAL_APPLIED"
            or projection.removal_effect != "LOGICAL_DETACH"
            or projection.target_presentation != "REMOVED"
            or projection.ambient_projection[0][6] != "REMOVED"
        )
    else:
        raise SystemExit(f"unknown mutant: {mutant}")
    executed = mutant in getattr(module, "_MUTATION_PATHS", set())
    return module, detector, detected and executed


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: mutation_detector.py MUTANT")
    mutant = sys.argv[1]
    module, detector, killed = detects(mutant)
    report = {
        "mutant": mutant,
        "path_executed": mutant in getattr(module, "_MUTATION_PATHS", set()),
        "detectors": [detector] if killed else [],
    }
    sys.stdout.buffer.write(canonical_bytes(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
