#!/usr/bin/env python3
"""Generate the exact synthetic transcript-only C0.3 conformance corpus."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from canonical_json import dumps, store  # noqa: E402
from corpus_model import (  # noqa: E402
    BASE_SHA,
    AP_OWNED_EXCLUSIONS,
    AP_EXPECTATION_ONLY_STEP_LOCATORS,
    BaseReader,
    DOMAINS,
    NONEXECUTABLE_INVARIANTS,
    PRODUCED_K_PRIMARIES,
    TRANSCRIPT_PROFILE_UNREACHABLE,
    ed25519_sign,
    encode_commitment,
    encode_event,
    encode_genesis,
    evaluate_k_admission_graph,
    evaluate_k_admission_scenario,
    evaluate_transcript_conformance,
    evaluate_vector,
    framed_hash,
    load_local_json,
    semantic_input_digest,
    semantic_k_graph_input_digest,
    semantic_observation_digest,
    sha256_hex,
    synthetic_octets,
    transition_input_is_compatible,
    validate_base_inputs,
)


CONNECTED_K_TRANSITION_WITNESSES = {
    ("k_admission", "k_admit_binding_grant"): (
        "k-admission-grant-rooted-join",
        "k-join-grant-a",
    ),
    ("k_admission", "k_admit_candidate"): (
        "k-admission-grant-rooted-join",
        "k-join-actor-a",
    ),
    ("pending_replay", "replay_apply_candidate"): (
        "k-admission-grant-rooted-join",
        "k-join-root-event",
    ),
    ("pending_replay", "replay_verified_opening"): (
        "k-admission-linear-controls",
        "k-linear-ordinary",
    ),
}


CORPUS_FILES = (
    "adversarial-mutations.json",
    "expected-traces.json",
    "invalid-transcript-vectors.json",
    "state-machine-scenarios.json",
    "valid-transcript-vectors.json",
)
COMMON_CITATIONS = [
    {
        "anchor": "## 5. Application-event signature transcript",
        "path": "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
    },
    {
        "anchor": "## 2. Domains and authenticated commitment context",
        "path": "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
    },
]

# Closed source-anchored mutations required by Issue #266 R3.  Each entry names
# the exact Base authority that the detector protects; validators reject stale
# anchors or source-row identifiers before either runtime may claim a kill.
SOURCE_SECURITY_MUTATIONS = (
    {
        "detector": "SOURCE_O10_CLASS_MEMBERSHIP",
        "generatedTargetId": "APPLIED",
        "id": "mutation-source-o10-class-membership",
        "sourceAnchor": '"id":"APPLIED"',
        "sourcePath": "tools/causal-flow-simulator/o10/outcome-taxonomy.json",
        "sourceRowIds": ["BASE:APPLIED:00"],
        "transformation": "ALLOW_AP_OWNED_PRIMARY_IN_K_SELECTOR",
        "violatedInvariant": "INV_OUTCOME_PRECEDENCE",
    },
    {
        "detector": "SOURCE_O10_APPLICABILITY",
        "generatedTargetId": "LENGTH_MISMATCH:EVENT_LOCAL",
        "id": "mutation-source-o10-applicability",
        "sourceAnchor": '"id":"LENGTH_MISMATCH"',
        "sourcePath": "tools/causal-flow-simulator/o10/outcome-taxonomy.json",
        "sourceRowIds": ["BASE:LENGTH_MISMATCH:00"],
        "transformation": "ALLOW_PRIMARY_AT_UNREGISTERED_STAGE",
        "violatedInvariant": "INV_OUTCOME_PRECEDENCE",
    },
    {
        "detector": "SOURCE_O10_PRECEDENCE",
        "generatedTargetId": "inv-commitment",
        "id": "mutation-source-o10-precedence",
        "sourceAnchor": '"k_precedence"',
        "sourcePath": "tools/causal-flow-simulator/o10/outcome-taxonomy.json",
        "sourceRowIds": ["BASE:LENGTH_MISMATCH:00", "BASE:COMMITMENT_MISMATCH:00"],
        "transformation": "SELECT_COMMITMENT_BEFORE_LENGTH",
        "violatedInvariant": "INV_OUTCOME_PRECEDENCE",
    },
    {
        "detector": "SOURCE_CHECKPOINT_BEFORE_PROTECTED_WORK",
        "generatedTargetId": "inv-signature",
        "id": "mutation-source-checkpoint-after-protected-work",
        "sourceAnchor": "Any attempt to populate checkpoint evidence is rejected before",
        "sourcePath": "docs/protocol/styx-app-kernel-v0-decisions.md",
        "sourceRowIds": ["O08:CHECKPOINT_REFERENCES:S3_KERNEL_STRUCTURAL"],
        "transformation": "MOVE_CHECKPOINT_REJECTION_AFTER_SIGNATURE_OR_COMMITMENT",
        "violatedInvariant": "INV_NO_CHECKPOINT_SUBSTITUTION",
    },
    *(
        {
            "detector": "SOURCE_GEOMETRY_PREDICATE",
            "generatedTargetId": f"geometry-predicate-{number}",
            "id": f"mutation-source-geometry-predicate-{number}",
            "predicateNumber": number,
            "sourceAnchor": "### 4.1 Geometry container",
            "sourcePath": "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
            "sourceRowIds": ["BASE:STRUCTURAL_REJECTION:00"],
            "transformation": (
                "MAKE_FINAL_CHUNK_UPPER_BOUND_EXCLUSIVE"
                if number == 7
                else f"REMOVE_OR_INVERT_GEOMETRY_PREDICATE_{number}"
            ),
            "violatedInvariant": "INV_COMMITMENT_CONTEXT_BINDING",
        }
        for number in range(1, 8)
    ),
    {
        "detector": "SOURCE_R6_CLASSIFICATION",
        "generatedTargetId": "inv-resource-chunk-size",
        "id": "mutation-source-r6-classification",
        "sourceAnchor": "O08:CHUNK_OCTETS:S3_KERNEL_STRUCTURAL",
        "sourcePath": "tools/causal-flow-simulator/o10/source-inventory.json",
        "sourceRowIds": ["O08:CHUNK_OCTETS:S3_KERNEL_STRUCTURAL"],
        "transformation": "CLASSIFY_WELL_FORMED_UNSUPPORTED_CHUNK_AS_STRUCTURAL",
        "violatedInvariant": "INV_AUTHORITY_PROJECTION_LIMITS",
    },
    {
        "detector": "SOURCE_R5_LAYERING",
        "generatedTargetId": "vec-required-single",
        "id": "mutation-source-r5-flatten-k-admission",
        "sourceAnchor": "## 6. Gate for C0.3 and exact next sequence",
        "sourcePath": "docs/protocol/styx-app-kernel-v0-decisions.md",
        "sourceRowIds": ["BASE:APPLIED:00"],
        "transformation": "FLATTEN_ADMITTED_AP_FOLD_NOT_EXECUTED_TO_SUCCESS",
        "violatedInvariant": "INV_AUTH_NOT_KEY",
    },
    {
        "detector": "SOURCE_FORK_DESCENDANT_GRAPH_RETENTION",
        "generatedTargetId": "k-hostile-connected-same-author-fork",
        "id": "mutation-source-fork-descendant-dependency-rejection",
        "sourceAnchor": "The graph, ancestry, order and pending sets remain visible",
        "sourcePath": "docs/protocol/styx-app-kernel-v0-decisions.md",
        "sourceRowIds": [
            "BASE:FORK_EVIDENCE:00",
            "BASE:LINEAGE_QUARANTINED:00",
        ],
        "transformation": "DROP_FORK_SIBLINGS_FROM_K_ADMITTED_DEPENDENCY_GRAPH",
        "violatedInvariant": "INV_FORK_QUARANTINE",
    },
)

# These relations are deliberately semantic and reviewable.  They replace the
# former positional/modulo joins, which could associate any invariant with any
# scenario without changing a gate result.  Every executable invariant owns a
# distinct witness and a distinct hostile mutation.
INVARIANT_WITNESS_VECTORS = {
    "INV_AUTHORITY_PROJECTION_LIMITS": "inv-resource-sequence",
    "INV_AUTH_NOT_KEY": "inv-unauthorized",
    "INV_BOUNDED_CONTESTED_STANDING": "inv-contested-standing",
    "INV_CAUSALITY_TRANSCRIPT_ONLY": "inv-parent-order",
    "INV_CAUSAL_TARGET_AVAILABILITY": "inv-missing-dependency",
    "INV_COMMITMENT_CONTEXT_BINDING": "inv-commitment",
    "INV_CONTROL_NONE_CLASS": "vec-control-grant",
    "INV_CROSS_CONTEXT_REJECTION": "inv-binding-context",
    "INV_FORK_QUARANTINE": "inv-fork",
    "INV_GRANT_ROOTED_BINDING": "inv-binding-credential",
    "INV_LINEAGE_CONTAINMENT": "inv-post-revocation",
    "INV_NO_CHECKPOINT_SUBSTITUTION": "inv-checkpoint-substitution",
    "INV_NO_OPENING_SUBSTITUTION": "inv-opening-missing",
    "INV_O06C_BOUNDED_EVIDENCE": "inv-body-length",
    "INV_OUTCOME_PRECEDENCE": "inv-signature",
    "INV_PENDING_SELECTIVE_PROGRESS": "vec-required-single",
    "INV_PROTECTION_SEPARATION": "inv-profile-substitution",
    "INV_REPLAY_NO_AUTHORITY": "inv-duplicate",
    "INV_SELF_LINEAGE_REDUCTION": "inv-self-lineage",
    "INV_SET_RELATIVE_REPLAY": "vec-secondary-context-author",
    "INV_TWO_SIDED_AUTHORITY": "vec-control-revoke",
}

COUNTEREXAMPLE_VECTOR_PROGRAMS = {
    "CE_ALIAS_SURVIVAL": ["vec-control-grant", "vec-control-revoke", "vec-secondary-context-author"],
    "CE_AUTHORITY_PROJECTION_EXHAUSTION": ["vec-selected-resource-boundaries", "inv-resource-sequence", "vec-ordinary-none"],
    "CE_BOUNDED_CONTESTED_STANDING": ["vec-control-revoke", "inv-contested-standing", "inv-unauthorized"],
    "CE_CHECKPOINT_STALE": ["vec-parent-single", "inv-checkpoint-substitution", "vec-ordinary-none"],
    "CE_CREDENTIAL_COLLISION": ["vec-control-grant", "inv-reference", "vec-ordinary-none"],
    "CE_FORK_CONTEXT_QUARANTINE": ["vec-ordinary-none", "inv-fork", "vec-secondary-context-author"],
    "CE_GRANT_REVOKE_LAUNDERING_ORDER_A": ["vec-control-grant", "vec-control-revoke", "inv-unauthorized"],
    "CE_GRANT_REVOKE_LAUNDERING_ORDER_B": ["vec-control-revoke", "vec-control-grant", "inv-unauthorized"],
    "CE_GRANT_ROOTED_BINDING": ["vec-control-grant", "inv-binding-credential", "vec-ordinary-none"],
    "CE_MISSING_REQUIRED_OPENING": ["vec-required-single", "inv-opening-missing", "vec-secondary-context-author"],
    "CE_MUTUAL_REDUCTION_NO_AUTHORITY": ["vec-control-revoke", "inv-unauthorized", "inv-post-revocation"],
    "CE_NONCAUSAL_REDUCTION_TARGET": ["vec-parent-multiple", "inv-missing-dependency", "vec-control-revoke"],
    "CE_SELECTIVE_REVEAL": ["vec-required-single", "inv-opening-missing", "vec-required-single"],
    "CE_SELF_LINEAGE_REDUCTION": ["vec-control-revoke", "inv-self-lineage", "vec-secondary-context-author"],
    "CE_SINGLE_AUTHORITY_TAKEOVER": ["vec-control-revoke", "inv-post-revocation", "vec-control-closure"],
    "CE_SUBTREE_AMPLIFICATION": ["vec-control-grant", "vec-control-revoke", "inv-post-revocation"],
}

AP_EXPECTATION_ONLY_VECTOR_IDS = frozenset(
    {"inv-post-revocation", "inv-self-lineage", "inv-unauthorized"}
)
K_ADMISSION_ONLY_TRANSITIONS = frozenset(
    {
        ("k_admission", "k_admit_binding_grant"),
        ("k_admission", "k_admit_candidate"),
        ("pending_replay", "replay_apply_candidate"),
        ("pending_replay", "replay_verified_opening"),
    }
)
NEGATIVE_K_TRANSITION_VECTORS = {
    ("k_admission", "k_reject_invalid"): "inv-signature",
    ("k_admission", "k_reject_unresolved_binding"): "inv-unresolved-credential-binding",
    ("k_admission", "k_to_collision"): "inv-credential-identifier-collision",
    ("k_admission", "k_to_fork"): "inv-fork",
    ("pending_replay", "replay_to_pending_descendant"): "inv-pending-ancestor",
    ("pending_replay", "replay_to_pending_root"): "inv-opening-missing",
}

INVALID_VECTOR_INVARIANTS = {
    "inv-binding-context": "INV_CROSS_CONTEXT_REJECTION",
    "inv-binding-credential": "INV_GRANT_ROOTED_BINDING",
    "inv-body-length": "INV_O06C_BOUNDED_EVIDENCE",
    "inv-checkpoint-substitution": "INV_NO_CHECKPOINT_SUBSTITUTION",
    "inv-commitment": "INV_COMMITMENT_CONTEXT_BINDING",
    "inv-commitment-equal-length": "INV_COMMITMENT_CONTEXT_BINDING",
    "inv-contested-standing": "INV_BOUNDED_CONTESTED_STANDING",
    "inv-duplicate": "INV_REPLAY_NO_AUTHORITY",
    "inv-fork": "INV_FORK_QUARANTINE",
    "inv-missing-dependency": "INV_CAUSAL_TARGET_AVAILABILITY",
    "inv-pending-ancestor": "INV_CAUSAL_TARGET_AVAILABILITY",
    "inv-opening-missing": "INV_NO_OPENING_SUBSTITUTION",
    "inv-opening-missing-detachable": "INV_NO_OPENING_SUBSTITUTION",
    "inv-parent-order": "INV_CAUSALITY_TRANSCRIPT_ONLY",
    "inv-profile-substitution": "INV_PROTECTION_SEPARATION",
    "inv-reference": "INV_GRANT_ROOTED_BINDING",
    "inv-rejected-signature-representation": "INV_REPLAY_NO_AUTHORITY",
    "inv-resource-chunk-count": "INV_AUTHORITY_PROJECTION_LIMITS",
    "inv-resource-chunk-size": "INV_AUTHORITY_PROJECTION_LIMITS",
    "inv-resource-content-length": "INV_AUTHORITY_PROJECTION_LIMITS",
    "inv-resource-parent-count": "INV_AUTHORITY_PROJECTION_LIMITS",
    "inv-resource-sequence": "INV_AUTHORITY_PROJECTION_LIMITS",
    "inv-resource-transition-block": "INV_AUTHORITY_PROJECTION_LIMITS",
    "inv-signature": "INV_OUTCOME_PRECEDENCE",
    "inv-credential-identifier-collision": "INV_GRANT_ROOTED_BINDING",
    "inv-unresolved-credential-binding": "INV_GRANT_ROOTED_BINDING",
    "inv-wrong-domain": "INV_O06C_BOUNDED_EVIDENCE",
}


def _digest(value: Any) -> str:
    return sha256(dumps(value)).hexdigest()


def _event_fields(
    identifier: str,
    *,
    role: str = "ORDINARY",
    sequence: int = 0,
    predecessor: str | None = None,
    parents: list[str] | None = None,
    content: dict[str, Any] | None = None,
    tail: dict[str, Any] | None = None,
    credential: bytes | None = None,
    context: bytes | None = None,
    genesis_reference: bytes | None = None,
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "applicationProfileId": 1,
        "applicationProfileVersion": 1,
        "authorSequence": sequence,
        "causalParents": sorted(parents or []),
        "content": content or {"class": "NONE", "exactLength": 0},
        "contextIdentifierHex": (context or synthetic_octets("context-primary", 32)).hex(),
        "credentialIdentifierHex": (credential or synthetic_octets("credential-root", 32)).hex(),
        "directPredecessorHex": predecessor,
        "eventRole": role,
        "eventTypeId": {"ORDINARY": 1, "REMOVAL": 2, "CREDENTIAL": 3}[role],
        "genesisReferenceHex": (
            genesis_reference or synthetic_octets("genesis-reference", 32)
        ).hex(),
        "schemaId": 1,
        "schemaVersion": 1,
        "transitionBlockHex": synthetic_octets(f"transition/{identifier}", 8).hex(),
    }
    if tail is not None:
        fields["tail"] = tail
    return fields


def _application_vector(identifier: str, fields: dict[str, Any], seed_label: str) -> dict[str, Any]:
    transcript = encode_event(fields)
    public, signature = ed25519_sign(synthetic_octets(seed_label, 32), transcript)
    return {
        "binding": {
            "contextIdentifierHex": fields["contextIdentifierHex"],
            "credentialIdentifierHex": fields["credentialIdentifierHex"],
            "verificationKeyHex": public.hex(),
        },
        "citations": COMMON_CITATIONS,
        "eventReferenceHex": framed_hash(DOMAINS["event_reference"], transcript).hex(),
        "fields": fields,
        "id": identifier,
        "kind": "APPLICATION_EVENT",
        "profile": "STYX_APP_KERNEL_V0_TRANSCRIPT_ONLY",
        "signatureHex": signature.hex(),
        "signatureSuiteId": 1,
        "synthetic": True,
        "testOnly": True,
        "transcriptHex": transcript.hex(),
    }


def _genesis_vector(
    identifier: str,
    *,
    context_label: str,
    policy_label: str,
    seed_label: str,
) -> dict[str, Any]:
    seed = synthetic_octets(seed_label, 32)
    public_key, _ = ed25519_sign(seed, b"")
    fields = {
        "applicationProfileId": 1,
        "applicationProfileVersion": 1,
        "contextIdentifierHex": synthetic_octets(context_label, 32).hex(),
        "initialAuthorityPolicyHex": synthetic_octets(policy_label, 12).hex(),
        "rootVerificationKeyHex": public_key.hex(),
    }
    transcript = encode_genesis(fields)
    _, signature = ed25519_sign(seed, transcript)
    return {
        "binding": {"verificationKeyHex": public_key.hex()},
        "citations": [
            {
                "anchor": "O-07 fixes `T_genesis` as exactly:",
                "path": "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
            }
        ],
        "fields": fields,
        "genesisReferenceHex": framed_hash(
            DOMAINS["genesis_reference"], transcript
        ).hex(),
        "id": identifier,
        "kind": "GENESIS",
        "profile": "STYX_APP_KERNEL_V0_TRANSCRIPT_ONLY",
        "signatureHex": signature.hex(),
        "signatureSuiteId": 1,
        "synthetic": True,
        "testOnly": True,
        "transcriptHex": transcript.hex(),
    }


def _k_admission_vectors() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build connected K-admission histories distinct from transcript fixtures.

    Genesis acceptance itself remains an O-07 test-boundary premise.  These
    histories exercise only descendant K admission against a preaccepted,
    immutable genesis projection; they do not serialize or emulate a ceremony
    capability.
    """

    records: list[dict[str, Any]] = []
    scenarios: list[dict[str, Any]] = []

    def add_root_event(
        identifier: str,
        *,
        context: bytes,
        genesis_reference: bytes,
        seed_label: str,
        sequence: int,
        predecessor: str | None,
        role: str = "ORDINARY",
        parents: list[str] | None = None,
        content: dict[str, Any] | None = None,
        tail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        vector = _application_vector(
            identifier,
            _event_fields(
                identifier,
                role=role,
                sequence=sequence,
                predecessor=predecessor,
                parents=parents,
                content=content,
                tail=tail,
                credential=genesis_reference,
                context=context,
                genesis_reference=genesis_reference,
            ),
            seed_label,
        )
        records.append(vector)
        return vector

    # Scenario 1: one fully connected root-authored control history.  Every
    # control target/fresh grant is an actual earlier admitted GRANT.
    genesis = _genesis_vector(
        "k-linear-genesis",
        context_label="k-linear/context",
        policy_label="k-linear/policy",
        seed_label="k-linear/root",
    )
    records.append(genesis)
    context = bytes.fromhex(genesis["fields"]["contextIdentifierHex"])
    reference = bytes.fromhex(genesis["genesisReferenceHex"])
    chain: list[dict[str, Any]] = []
    previous: str | None = None
    required_content = b"connected-k-required-opening"
    required_commitment = encode_commitment(
        profile_id=1,
        profile_version=1,
        context=context,
        credential=reference,
        sequence=0,
        content_type=1,
        content=required_content,
        randomizer=synthetic_octets("k-linear/required-randomizer", 32),
    )
    ordinary = add_root_event(
        "k-linear-ordinary",
        context=context,
        genesis_reference=reference,
        seed_label="k-linear/root",
        sequence=0,
        predecessor=None,
        content={
            "class": "REQUIRED",
            "commitmentHex": required_commitment["commitmentHex"],
            "contentType": 1,
            "exactLength": len(required_content),
            "shape": "SINGLE",
        },
    )
    ordinary["opening"] = {
        "contentHex": required_content.hex(),
        "randomizerHex": required_commitment["randomizerHex"],
    }
    chain.append(ordinary)
    previous = ordinary["eventReferenceHex"]
    grant = add_root_event(
        "k-linear-grant-revoked",
        context=context,
        genesis_reference=reference,
        seed_label="k-linear/root",
        sequence=1,
        predecessor=previous,
        role="CREDENTIAL",
        tail={
            "granteeVerificationKeyHex": ed25519_sign(
                synthetic_octets("k-linear/revoked", 32), b""
            )[0].hex(),
            "kind": "GRANT",
        },
    )
    chain.append(grant)
    previous = grant["eventReferenceHex"]

    revoke = add_root_event(
        "k-linear-revoke",
        context=context,
        genesis_reference=reference,
        seed_label="k-linear/root",
        sequence=2,
        predecessor=previous,
        role="CREDENTIAL",
        tail={
            "kind": "REVOKE",
            "targetCredentialHex": chain[-1]["eventReferenceHex"],
        },
    )
    chain.append(revoke)
    previous = revoke["eventReferenceHex"]

    retiring = add_root_event(
        "k-linear-grant-retiring",
        context=context,
        genesis_reference=reference,
        seed_label="k-linear/root",
        sequence=3,
        predecessor=previous,
        role="CREDENTIAL",
        tail={
            "granteeVerificationKeyHex": ed25519_sign(
                synthetic_octets("k-linear/retiring", 32), b""
            )[0].hex(),
            "kind": "GRANT",
        },
    )
    chain.append(retiring)
    replacement = add_root_event(
        "k-linear-grant-replacement",
        context=context,
        genesis_reference=reference,
        seed_label="k-linear/root",
        sequence=4,
        predecessor=retiring["eventReferenceHex"],
        role="CREDENTIAL",
        tail={
            "granteeVerificationKeyHex": ed25519_sign(
                synthetic_octets("k-linear/replacement", 32), b""
            )[0].hex(),
            "kind": "GRANT",
        },
    )
    chain.append(replacement)
    rotate = add_root_event(
        "k-linear-rotate",
        context=context,
        genesis_reference=reference,
        seed_label="k-linear/root",
        sequence=5,
        predecessor=replacement["eventReferenceHex"],
        role="CREDENTIAL",
        tail={
            "kind": "ROTATE",
            "replacementGrantHex": replacement["eventReferenceHex"],
            "retiringCredentialHex": retiring["eventReferenceHex"],
        },
    )
    chain.append(rotate)
    recovery_grant = add_root_event(
        "k-linear-grant-recovery",
        context=context,
        genesis_reference=reference,
        seed_label="k-linear/root",
        sequence=6,
        predecessor=rotate["eventReferenceHex"],
        role="CREDENTIAL",
        tail={
            "granteeVerificationKeyHex": ed25519_sign(
                synthetic_octets("k-linear/recovery", 32), b""
            )[0].hex(),
            "kind": "GRANT",
        },
    )
    chain.append(recovery_grant)
    recover = add_root_event(
        "k-linear-recover",
        context=context,
        genesis_reference=reference,
        seed_label="k-linear/root",
        sequence=7,
        predecessor=recovery_grant["eventReferenceHex"],
        role="CREDENTIAL",
        tail={
            "kind": "RECOVER",
            "recoveryGrantHex": recovery_grant["eventReferenceHex"],
            "retiredCredentialHex": synthetic_octets(
                "k-linear/retired-annotation", 32
            ).hex(),
        },
    )
    chain.append(recover)
    for sequence, identifier, kind in (
        (8, "k-linear-policy", "POLICY"),
        (9, "k-linear-closure", "CLOSURE"),
    ):
        event = add_root_event(
            identifier,
            context=context,
            genesis_reference=reference,
            seed_label="k-linear/root",
            sequence=sequence,
            predecessor=chain[-1]["eventReferenceHex"],
            role="CREDENTIAL",
            tail={"kind": kind},
        )
        chain.append(event)
    scenarios.append(
        {
            "acceptedGenesisRecordId": genesis["id"],
            "id": "k-admission-linear-controls",
            "recordIds": [event["id"] for event in chain],
        }
    )

    # Scenario 2: two grant-rooted authors form incomparable branches which a
    # root event joins through an exact minimal causal frontier.
    join_genesis = _genesis_vector(
        "k-join-genesis",
        context_label="k-join/context",
        policy_label="k-join/policy",
        seed_label="k-join/root",
    )
    records.append(join_genesis)
    join_context = bytes.fromhex(join_genesis["fields"]["contextIdentifierHex"])
    join_reference = bytes.fromhex(join_genesis["genesisReferenceHex"])
    actor_rows: list[tuple[dict[str, Any], str]] = []
    root_previous: str | None = None
    for sequence, suffix in enumerate(("a", "b")):
        actor_seed = f"k-join/actor-{suffix}"
        actor_key, _ = ed25519_sign(synthetic_octets(actor_seed, 32), b"")
        grant = add_root_event(
            f"k-join-grant-{suffix}",
            context=join_context,
            genesis_reference=join_reference,
            seed_label="k-join/root",
            sequence=sequence,
            predecessor=root_previous,
            role="CREDENTIAL",
            tail={
                "granteeVerificationKeyHex": actor_key.hex(),
                "kind": "GRANT",
            },
        )
        root_previous = grant["eventReferenceHex"]
        actor = _application_vector(
            f"k-join-actor-{suffix}",
            _event_fields(
                f"k-join-actor-{suffix}",
                sequence=0,
                parents=[grant["eventReferenceHex"]],
                credential=bytes.fromhex(grant["eventReferenceHex"]),
                context=join_context,
                genesis_reference=join_reference,
            ),
            actor_seed,
        )
        records.append(actor)
        actor_rows.append((actor, suffix))
    joined = add_root_event(
        "k-join-root-event",
        context=join_context,
        genesis_reference=join_reference,
        seed_label="k-join/root",
        sequence=2,
        predecessor=root_previous,
        parents=sorted(actor["eventReferenceHex"] for actor, _ in actor_rows),
    )
    scenarios.append(
        {
            "acceptedGenesisRecordId": join_genesis["id"],
            "id": "k-admission-grant-rooted-join",
            "recordIds": [
                "k-join-grant-a",
                "k-join-grant-b",
                "k-join-actor-a",
                "k-join-actor-b",
                joined["id"],
            ],
        }
    )

    # Scenario 3: a non-root actor may address the already accepted genesis
    # credential directly.  O-02 exempts that root target from the ordinary
    # non-genesis binding-GRANT ancestry rule; the actor's own authority still
    # has to derive from its admitted GRANT.
    actor_a = actor_rows[0][0]
    revoke_genesis = _application_vector(
        "k-join-actor-a-revoke-genesis",
        _event_fields(
            "k-join-actor-a-revoke-genesis",
            role="CREDENTIAL",
            sequence=1,
            predecessor=actor_a["eventReferenceHex"],
            credential=bytes.fromhex(
                actor_a["fields"]["credentialIdentifierHex"]
            ),
            context=join_context,
            genesis_reference=join_reference,
            tail={
                "kind": "REVOKE",
                "targetCredentialHex": join_genesis["genesisReferenceHex"],
            },
        ),
        "k-join/actor-a",
    )
    records.append(revoke_genesis)
    scenarios.append(
        {
            "acceptedGenesisRecordId": join_genesis["id"],
            "id": "k-admission-genesis-revoke-exception",
            "recordIds": [
                "k-join-grant-a",
                "k-join-actor-a",
                revoke_genesis["id"],
            ],
        }
    )
    return sorted(records, key=lambda record: record["id"]), scenarios


def _k_admission_adversarial_scenarios(
    legacy_records: list[dict[str, Any]],
    connected_records: list[dict[str, Any]],
    connected_scenarios: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build transcript-valid hostile graphs with independent expected output."""

    connected_by_id = {record["id"]: record for record in connected_records}
    legacy_by_id = {record["id"]: record for record in legacy_records}
    scenario_by_id = {scenario["id"]: scenario for scenario in connected_scenarios}

    def source(identifier: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        scenario = scenario_by_id[identifier]
        return (
            connected_by_id[scenario["acceptedGenesisRecordId"]],
            [connected_by_id[value] for value in scenario["recordIds"]],
        )

    def resign(
        record: dict[str, Any],
        identifier: str,
        seed_label: str,
        mutate: Any,
    ) -> dict[str, Any]:
        value = json.loads(json.dumps(record))
        value["id"] = identifier
        mutate(value)
        transcript = encode_event(value["fields"])
        public, signature = ed25519_sign(
            synthetic_octets(seed_label, 32), transcript
        )
        value["binding"]["contextIdentifierHex"] = value["fields"][
            "contextIdentifierHex"
        ]
        value["binding"]["credentialIdentifierHex"] = value["fields"][
            "credentialIdentifierHex"
        ]
        value["binding"]["verificationKeyHex"] = public.hex()
        value["eventReferenceHex"] = framed_hash(
            DOMAINS["event_reference"], transcript
        ).hex()
        value["signatureHex"] = signature.hex()
        value["transcriptHex"] = transcript.hex()
        return value

    rows: list[dict[str, Any]] = []

    def add(
        identifier: str,
        genesis: dict[str, Any],
        records: list[dict[str, Any]],
    ) -> None:
        observations = evaluate_k_admission_graph(genesis, records)
        rows.append(
            {
                "acceptedGenesisRecord": genesis,
                "expectedObservations": observations,
                "id": identifier,
                "records": records,
            }
        )

    add(
        "k-hostile-legacy-transcript-not-admission",
        legacy_by_id["vec-genesis"],
        [legacy_by_id["vec-ordinary-none"]],
    )
    linear_genesis, linear = source("k-admission-linear-controls")
    add(
        "k-hostile-foreign-genesis",
        linear_genesis,
        [
            resign(
                linear[0],
                "k-hostile-foreign-genesis-event",
                "k-linear/root",
                lambda row: row["fields"].__setitem__(
                    "genesisReferenceHex", "ab" * 32
                ),
            )
        ],
    )
    add(
        "k-hostile-unknown-credential",
        linear_genesis,
        [
            resign(
                linear[0],
                "k-hostile-unknown-credential-event",
                "k-linear/root",
                lambda row: row["fields"].__setitem__(
                    "credentialIdentifierHex", "cd" * 32
                ),
            )
        ],
    )
    wrong_key = resign(
        linear[0],
        "k-hostile-wrong-bound-key",
        "k-hostile/wrong-key",
        lambda row: None,
    )
    add("k-hostile-binding-key-substitution", linear_genesis, [wrong_key])

    invalid_revoke = resign(
        linear[2],
        "k-hostile-revoke-unknown-target",
        "k-linear/root",
        lambda row: row["fields"]["tail"].__setitem__(
            "targetCredentialHex", "ef" * 32
        ),
    )
    add(
        "k-hostile-revoke-unknown-target",
        linear_genesis,
        [linear[0], linear[1], invalid_revoke],
    )
    invalid_descendant = resign(
        linear[3],
        "k-hostile-descendant-of-rejected-control",
        "k-linear/root",
        lambda row: row["fields"].__setitem__(
            "directPredecessorHex", invalid_revoke["eventReferenceHex"]
        ),
    )
    add(
        "k-hostile-transitive-rejection",
        linear_genesis,
        [linear[0], linear[1], invalid_revoke, invalid_descendant],
    )
    add(
        "k-hostile-rotate-grant-not-frontier",
        linear_genesis,
        [
            *linear[:5],
            resign(
                linear[5],
                "k-hostile-rotate-grant-not-frontier-event",
                "k-linear/root",
                lambda row: row["fields"]["tail"].__setitem__(
                    "replacementGrantHex", linear[1]["eventReferenceHex"]
                ),
            ),
        ],
    )
    add(
        "k-hostile-recover-grant-not-frontier",
        linear_genesis,
        [
            *linear[:7],
            resign(
                linear[7],
                "k-hostile-recover-grant-not-frontier-event",
                "k-linear/root",
                lambda row: row["fields"]["tail"].__setitem__(
                    "recoveryGrantHex", linear[4]["eventReferenceHex"]
                ),
            ),
        ],
    )
    add(
        "k-hostile-self-rotation",
        linear_genesis,
        [
            *linear[:5],
            resign(
                linear[5],
                "k-hostile-self-rotation-event",
                "k-linear/root",
                lambda row: row["fields"]["tail"].__setitem__(
                    "retiringCredentialHex",
                    linear_genesis["genesisReferenceHex"],
                ),
            ),
        ],
    )

    removal = _application_vector(
        "k-hostile-removal-absent-target-event",
        _event_fields(
            "k-hostile-removal-absent-target-event",
            role="REMOVAL",
            sequence=1,
            predecessor=linear[0]["eventReferenceHex"],
            credential=bytes.fromhex(linear_genesis["genesisReferenceHex"]),
            context=bytes.fromhex(
                linear_genesis["fields"]["contextIdentifierHex"]
            ),
            genesis_reference=bytes.fromhex(
                linear_genesis["genesisReferenceHex"]
            ),
            tail={
                "targetCommitmentHex": "ab" * 32,
                "targetEventReferenceHex": "cd" * 32,
            },
        ),
        "k-linear/root",
    )
    add(
        "k-hostile-removal-target-absence-is-not-k-rejection",
        linear_genesis,
        [linear[0], removal],
    )

    join_genesis, join = source("k-admission-grant-rooted-join")
    actor_without_grant = resign(
        join[2],
        "k-hostile-noncausal-grant-event",
        "k-join/actor-a",
        lambda row: row["fields"].__setitem__("causalParents", []),
    )
    add(
        "k-hostile-grant-not-in-actor-ancestry",
        join_genesis,
        [join[0], actor_without_grant],
    )

    # The target credential is globally resolvable (grant-b was admitted) but
    # is not in actor-a's causal ancestry.  Resolution must not substitute for
    # the non-genesis target-binding ancestry requirement.
    noncausal_revoke = _application_vector(
        "k-hostile-revoke-noncausal-target-event",
        _event_fields(
            "k-hostile-revoke-noncausal-target-event",
            role="CREDENTIAL",
            sequence=1,
            predecessor=join[2]["eventReferenceHex"],
            credential=bytes.fromhex(join[0]["eventReferenceHex"]),
            context=bytes.fromhex(join_genesis["fields"]["contextIdentifierHex"]),
            genesis_reference=bytes.fromhex(join_genesis["genesisReferenceHex"]),
            tail={
                "kind": "REVOKE",
                "targetCredentialHex": join[1]["eventReferenceHex"],
            },
        ),
        "k-join/actor-a",
    )
    add(
        "k-hostile-revoke-noncausal-target",
        join_genesis,
        [join[0], join[1], join[2], noncausal_revoke],
    )

    replacement_key, _ = ed25519_sign(
        synthetic_octets("k-hostile/rotate-replacement", 32), b""
    )
    noncausal_replacement = _application_vector(
        "k-hostile-rotate-noncausal-replacement-grant",
        _event_fields(
            "k-hostile-rotate-noncausal-replacement-grant",
            role="CREDENTIAL",
            sequence=1,
            predecessor=join[2]["eventReferenceHex"],
            credential=bytes.fromhex(join[0]["eventReferenceHex"]),
            context=bytes.fromhex(join_genesis["fields"]["contextIdentifierHex"]),
            genesis_reference=bytes.fromhex(join_genesis["genesisReferenceHex"]),
            tail={
                "granteeVerificationKeyHex": replacement_key.hex(),
                "kind": "GRANT",
            },
        ),
        "k-join/actor-a",
    )
    noncausal_rotate = _application_vector(
        "k-hostile-rotate-retiring-noncausal-event",
        _event_fields(
            "k-hostile-rotate-retiring-noncausal-event",
            role="CREDENTIAL",
            sequence=2,
            predecessor=noncausal_replacement["eventReferenceHex"],
            credential=bytes.fromhex(join[0]["eventReferenceHex"]),
            context=bytes.fromhex(join_genesis["fields"]["contextIdentifierHex"]),
            genesis_reference=bytes.fromhex(join_genesis["genesisReferenceHex"]),
            tail={
                "kind": "ROTATE",
                "replacementGrantHex": noncausal_replacement["eventReferenceHex"],
                "retiringCredentialHex": join[1]["eventReferenceHex"],
            },
        ),
        "k-join/actor-a",
    )
    add(
        "k-hostile-rotate-retiring-noncausal",
        join_genesis,
        [
            join[0],
            join[1],
            join[2],
            noncausal_replacement,
            noncausal_rotate,
        ],
    )

    # Connected event-local evidence must remain distinct from transcript
    # rejection.  A REQUIRED event without its opening is K-admitted but held
    # pending, and a child of that event is a distinct pending-ancestor case.
    pending_opening = json.loads(json.dumps(linear[0]))
    pending_opening["id"] = "k-hostile-required-opening-pending"
    pending_opening.pop("opening", None)
    pending_descendant = _application_vector(
        "k-hostile-pending-ancestor",
        _event_fields(
            "k-hostile-pending-ancestor",
            sequence=1,
            predecessor=pending_opening["eventReferenceHex"],
            credential=bytes.fromhex(linear_genesis["genesisReferenceHex"]),
            context=bytes.fromhex(
                linear_genesis["fields"]["contextIdentifierHex"]
            ),
            genesis_reference=bytes.fromhex(
                linear_genesis["genesisReferenceHex"]
            ),
        ),
        "k-linear/root",
    )
    add(
        "k-hostile-required-opening-and-pending-ancestor",
        linear_genesis,
        [pending_opening, pending_descendant],
    )

    # Two otherwise valid events occupying the same author/sequence slot are
    # both retained as authenticated fork evidence.  The graph evaluator reruns
    # from the preaccepted root after discovering the second sibling, so lexical
    # or arrival order cannot select a winner.  A correctly authenticated child
    # of either sibling remains in the admitted K graph: AP, not dependency
    # admission, owns the later LINEAGE_QUARANTINED disposition.
    fork_left = _application_vector(
        "k-hostile-fork-left",
        _event_fields(
            "k-hostile-fork-left",
            sequence=1,
            predecessor=linear[0]["eventReferenceHex"],
            credential=bytes.fromhex(linear_genesis["genesisReferenceHex"]),
            context=bytes.fromhex(
                linear_genesis["fields"]["contextIdentifierHex"]
            ),
            genesis_reference=bytes.fromhex(
                linear_genesis["genesisReferenceHex"]
            ),
        ),
        "k-linear/root",
    )
    fork_right = _application_vector(
        "k-hostile-fork-right",
        _event_fields(
            "k-hostile-fork-right",
            sequence=1,
            predecessor=linear[0]["eventReferenceHex"],
            credential=bytes.fromhex(linear_genesis["genesisReferenceHex"]),
            context=bytes.fromhex(
                linear_genesis["fields"]["contextIdentifierHex"]
            ),
            genesis_reference=bytes.fromhex(
                linear_genesis["genesisReferenceHex"]
            ),
        ),
        "k-linear/root",
    )
    fork_descendant = _application_vector(
        "k-hostile-fork-left-descendant",
        _event_fields(
            "k-hostile-fork-left-descendant",
            sequence=2,
            predecessor=fork_left["eventReferenceHex"],
            credential=bytes.fromhex(linear_genesis["genesisReferenceHex"]),
            context=bytes.fromhex(
                linear_genesis["fields"]["contextIdentifierHex"]
            ),
            genesis_reference=bytes.fromhex(
                linear_genesis["genesisReferenceHex"]
            ),
        ),
        "k-linear/root",
    )
    add(
        "k-hostile-connected-same-author-fork",
        linear_genesis,
        [linear[0], fork_left, fork_right, fork_descendant],
    )

    # PARENTS_PER_EVENT is an S4 capacity decision.  All bytes, reference,
    # signature and root binding remain valid before the selected envelope
    # rejects this graph candidate without parsing or signature ambiguity.
    over_parent_limit = _application_vector(
        "k-hostile-connected-parent-capacity",
        _event_fields(
            "k-hostile-connected-parent-capacity",
            sequence=10,
            predecessor=linear[9]["eventReferenceHex"],
            parents=[record["eventReferenceHex"] for record in linear[:9]],
            credential=bytes.fromhex(linear_genesis["genesisReferenceHex"]),
            context=bytes.fromhex(
                linear_genesis["fields"]["contextIdentifierHex"]
            ),
            genesis_reference=bytes.fromhex(
                linear_genesis["genesisReferenceHex"]
            ),
        ),
        "k-linear/root",
    )
    add(
        "k-hostile-connected-parent-capacity",
        linear_genesis,
        [*linear, over_parent_limit],
    )

    add(
        "k-hostile-reversed-arrival-is-equivalent",
        join_genesis,
        list(reversed(join)),
    )
    return sorted(rows, key=lambda row: row["id"])


def _valid_vectors(*, legacy_controls: bool = False) -> list[dict[str, Any]]:
    root_seed = synthetic_octets("seed/root", 32)
    root_key, _ = ed25519_sign(root_seed, b"")
    genesis_fields = {
        "applicationProfileId": 1,
        "applicationProfileVersion": 1,
        "contextIdentifierHex": synthetic_octets("context-primary", 32).hex(),
        "initialAuthorityPolicyHex": synthetic_octets("authority-policy", 12).hex(),
        "rootVerificationKeyHex": root_key.hex(),
    }
    genesis_transcript = encode_genesis(genesis_fields)
    _, genesis_signature = ed25519_sign(root_seed, genesis_transcript)
    vectors: list[dict[str, Any]] = [
        {
            "binding": {"verificationKeyHex": root_key.hex()},
            "citations": [
                {
                    "anchor": "O-07 fixes `T_genesis` as exactly:",
                    "path": "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
                }
            ],
            "fields": genesis_fields,
            "genesisReferenceHex": framed_hash(
                DOMAINS["genesis_reference"], genesis_transcript
            ).hex(),
            "id": "vec-genesis",
            "kind": "GENESIS",
            "profile": "STYX_APP_KERNEL_V0_TRANSCRIPT_ONLY",
            "signatureHex": genesis_signature.hex(),
            "signatureSuiteId": 1,
            "synthetic": True,
            "testOnly": True,
            "transcriptHex": genesis_transcript.hex(),
        }
    ]

    ordinary = _application_vector(
        "vec-ordinary-none", _event_fields("ordinary-none"), "seed/root"
    )
    vectors.append(ordinary)
    predecessor = ordinary["eventReferenceHex"]
    context = bytes.fromhex(ordinary["fields"]["contextIdentifierHex"])
    credential = bytes.fromhex(ordinary["fields"]["credentialIdentifierHex"])

    single_content = b"synthetic-c03-content"
    single_commitment = encode_commitment(
        profile_id=1,
        profile_version=1,
        context=context,
        credential=credential,
        sequence=1,
        content_type=1,
        content=single_content,
        randomizer=synthetic_octets("randomizer/single", 32),
    )
    single_descriptor = {
        "class": "REQUIRED",
        "commitmentHex": single_commitment["commitmentHex"],
        "contentType": 1,
        "exactLength": len(single_content),
        "shape": "SINGLE",
    }
    single = _application_vector(
        "vec-required-single",
        _event_fields(
            "required-single",
            sequence=1,
            predecessor=predecessor,
            content=single_descriptor,
        ),
        "seed/root",
    )
    single["opening"] = {
        "contentHex": single_content.hex(),
        "randomizerHex": single_commitment["randomizerHex"],
    }
    vectors.append(single)

    tree_content = synthetic_octets("tree-content", 4097)
    tree_commitment = encode_commitment(
        profile_id=1,
        profile_version=1,
        context=context,
        credential=credential,
        sequence=2,
        content_type=2,
        content=tree_content,
        randomizer=synthetic_octets("randomizer/tree", 32),
        chunk_size=4096,
    )
    tree_descriptor = {
        "class": "DETACHABLE",
        "commitmentHex": tree_commitment["commitmentHex"],
        "contentType": 2,
        "exactLength": len(tree_content),
        "geometry": tree_commitment["geometry"],
        "shape": "TREE",
    }
    tree = _application_vector(
        "vec-detachable-tree",
        _event_fields(
            "detachable-tree",
            sequence=2,
            predecessor=single["eventReferenceHex"],
            content=tree_descriptor,
        ),
        "seed/root",
    )
    tree["opening"] = {
        "contentHex": tree_content.hex(),
        "randomizerHex": tree_commitment["randomizerHex"],
    }
    vectors.append(tree)

    removal = _application_vector(
        "vec-removal",
        _event_fields(
            "removal",
            role="REMOVAL",
            sequence=3,
            predecessor=tree["eventReferenceHex"],
            tail={
                "targetCommitmentHex": tree_commitment["commitmentHex"],
                "targetEventReferenceHex": tree["eventReferenceHex"],
            },
        ),
        "seed/root",
    )
    vectors.append(removal)

    def append_control(
        identifier: str,
        *,
        sequence: int,
        predecessor: str,
        tail: dict[str, Any],
    ) -> dict[str, Any]:
        vector = _application_vector(
            f"vec-control-{identifier}",
            _event_fields(
                f"control-{identifier}",
                role="CREDENTIAL",
                sequence=sequence,
                predecessor=predecessor,
                tail=tail,
            ),
            "seed/root",
        )
        vectors.append(vector)
        return vector

    grant_key, _ = ed25519_sign(synthetic_octets("seed/grantee", 32), b"")
    grant = append_control(
        "grant",
        sequence=4,
        predecessor=removal["eventReferenceHex"],
        tail={"granteeVerificationKeyHex": grant_key.hex(), "kind": "GRANT"},
    )
    if legacy_controls:
        legacy_specs = (
            (
                "revoke",
                {
                    "kind": "REVOKE",
                    "targetCredentialHex": synthetic_octets(
                        "credential-target", 32
                    ).hex(),
                },
            ),
            (
                "rotate",
                {
                    "kind": "ROTATE",
                    "replacementGrantHex": synthetic_octets(
                        "replacement-grant", 32
                    ).hex(),
                    "retiringCredentialHex": synthetic_octets(
                        "credential-retiring", 32
                    ).hex(),
                },
            ),
            (
                "recover",
                {
                    "kind": "RECOVER",
                    "recoveryGrantHex": synthetic_octets("recovery-grant", 32).hex(),
                    "retiredCredentialHex": synthetic_octets(
                        "credential-retired", 32
                    ).hex(),
                },
            ),
            ("policy", {"kind": "POLICY"}),
            ("closure", {"kind": "CLOSURE"}),
        )
        previous = grant["eventReferenceHex"]
        sequence = 5
        for identifier, tail in legacy_specs:
            control = append_control(
                identifier,
                sequence=sequence,
                predecessor=previous,
                tail=tail,
            )
            previous = control["eventReferenceHex"]
            sequence += 1
    else:
        revoke = append_control(
            "revoke",
            sequence=5,
            predecessor=grant["eventReferenceHex"],
            tail={"kind": "REVOKE", "targetCredentialHex": grant["eventReferenceHex"]},
        )

        retiring_key, _ = ed25519_sign(
            synthetic_octets("seed/grantee-rotate-retiring", 32), b""
        )
        retiring_grant = append_control(
            "rotate-retiring-grant",
            sequence=6,
            predecessor=revoke["eventReferenceHex"],
            tail={"granteeVerificationKeyHex": retiring_key.hex(), "kind": "GRANT"},
        )
        replacement_key, _ = ed25519_sign(
            synthetic_octets("seed/grantee-rotate-replacement", 32), b""
        )
        replacement_grant = append_control(
            "rotate-replacement-grant",
            sequence=7,
            predecessor=retiring_grant["eventReferenceHex"],
            tail={"granteeVerificationKeyHex": replacement_key.hex(), "kind": "GRANT"},
        )
        rotate = append_control(
            "rotate",
            sequence=8,
            predecessor=replacement_grant["eventReferenceHex"],
            tail={
                "kind": "ROTATE",
                "replacementGrantHex": replacement_grant["eventReferenceHex"],
                "retiringCredentialHex": retiring_grant["eventReferenceHex"],
            },
        )

        recovery_key, _ = ed25519_sign(
            synthetic_octets("seed/grantee-recovery", 32), b""
        )
        recovery_grant = append_control(
            "recovery-grant",
            sequence=9,
            predecessor=rotate["eventReferenceHex"],
            tail={"granteeVerificationKeyHex": recovery_key.hex(), "kind": "GRANT"},
        )
        recover = append_control(
            "recover",
            sequence=10,
            predecessor=recovery_grant["eventReferenceHex"],
            tail={
                "kind": "RECOVER",
                "recoveryGrantHex": recovery_grant["eventReferenceHex"],
                "retiredCredentialHex": synthetic_octets(
                    "credential-retired", 32
                ).hex(),
            },
        )
        policy = append_control(
            "policy",
            sequence=11,
            predecessor=recover["eventReferenceHex"],
            tail={"kind": "POLICY"},
        )
        closure = append_control(
            "closure",
            sequence=12,
            predecessor=policy["eventReferenceHex"],
            tail={"kind": "CLOSURE"},
        )
        previous = closure["eventReferenceHex"]
        sequence = 13

    secondary = _application_vector(
        "vec-secondary-context-author",
        _event_fields(
            "secondary-context-author",
            credential=synthetic_octets("credential-secondary", 32),
            context=synthetic_octets("context-secondary", 32),
        ),
        "seed/secondary",
    )
    vectors.append(secondary)

    single_parent = _application_vector(
        "vec-parent-single",
        _event_fields(
            "parent-single",
            sequence=sequence,
            predecessor=previous,
            parents=[ordinary["eventReferenceHex"]],
        ),
        "seed/root",
    )
    vectors.append(single_parent)
    sequence += 1
    multiple_parents = _application_vector(
        "vec-parent-multiple",
        _event_fields(
            "parent-multiple",
            sequence=sequence,
            predecessor=single_parent["eventReferenceHex"],
            parents=[single["eventReferenceHex"], tree["eventReferenceHex"]],
        ),
        "seed/root",
    )
    vectors.append(multiple_parents)

    selected_content = synthetic_octets("selected-resource-content", 262144)
    selected_commitment = encode_commitment(
        profile_id=1,
        profile_version=1,
        context=context,
        credential=credential,
        sequence=4095,
        content_type=2,
        content=selected_content,
        randomizer=synthetic_octets("randomizer/selected-resource", 32),
        chunk_size=4096,
    )
    selected_fields = _event_fields(
        "selected-resource-boundaries",
        sequence=4095,
        predecessor=multiple_parents["eventReferenceHex"],
        parents=[synthetic_octets(f"selected-parent/{index}", 32).hex() for index in range(8)],
        content={
            "class": "DETACHABLE",
            "commitmentHex": selected_commitment["commitmentHex"],
            "contentType": 2,
            "exactLength": len(selected_content),
            "geometry": selected_commitment["geometry"],
            "shape": "TREE",
        },
    )
    selected_fields["transitionBlockHex"] = synthetic_octets("selected-transition-block", 4096).hex()
    selected = _application_vector(
        "vec-selected-resource-boundaries", selected_fields, "seed/root"
    )
    selected["opening"] = {
        "contentHex": selected_content.hex(),
        "randomizerHex": selected_commitment["randomizerHex"],
    }
    vectors.append(selected)

    selected_chunk_content = synthetic_octets("selected-chunk-octets", 32768)
    selected_chunk_commitment = encode_commitment(
        profile_id=1,
        profile_version=1,
        context=context,
        credential=credential,
        sequence=sequence + 1,
        content_type=2,
        content=selected_chunk_content,
        randomizer=synthetic_octets("randomizer/selected-chunk", 32),
        chunk_size=16384,
    )
    selected_chunk = _application_vector(
        "vec-selected-chunk-octets",
        _event_fields(
            "selected-chunk-octets",
            sequence=sequence + 1,
            predecessor=multiple_parents["eventReferenceHex"],
            content={
                "class": "DETACHABLE",
                "commitmentHex": selected_chunk_commitment["commitmentHex"],
                "contentType": 2,
                "exactLength": len(selected_chunk_content),
                "geometry": selected_chunk_commitment["geometry"],
                "shape": "TREE",
            },
        ),
        "seed/root",
    )
    selected_chunk["opening"] = {
        "contentHex": selected_chunk_content.hex(),
        "randomizerHex": selected_chunk_commitment["randomizerHex"],
    }
    vectors.append(selected_chunk)

    max_policy_fields = dict(genesis_fields)
    max_policy_fields["initialAuthorityPolicyHex"] = synthetic_octets(
        "selected-genesis-policy", 4096
    ).hex()
    max_policy_transcript = encode_genesis(max_policy_fields)
    _, max_policy_signature = ed25519_sign(root_seed, max_policy_transcript)
    vectors.append(
        {
            "binding": {"verificationKeyHex": root_key.hex()},
            "citations": vectors[0]["citations"],
            "fields": max_policy_fields,
            "genesisReferenceHex": framed_hash(
                DOMAINS["genesis_reference"], max_policy_transcript
            ).hex(),
            "id": "vec-selected-genesis-policy",
            "kind": "GENESIS",
            "profile": "STYX_APP_KERNEL_V0_TRANSCRIPT_ONLY",
            "signatureHex": max_policy_signature.hex(),
            "signatureSuiteId": 1,
            "synthetic": True,
            "testOnly": True,
            "transcriptHex": max_policy_transcript.hex(),
        }
    )
    return sorted(vectors, key=lambda record: record["id"])


def _mutated_vector(
    source: dict[str, Any], identifier: str, mutation: str, stage: str, outcome: str
) -> dict[str, Any]:
    value = json.loads(json.dumps(source))
    value["id"] = identifier
    value["mutation"] = mutation
    value["sourceVectorId"] = source["id"]
    value["expected"] = {
        "externalEffects": [],
        "firstFailingStage": stage,
        "localOutcome": outcome,
        "stateUnchanged": True,
    }
    return value


def _invalid_vectors(
    valid: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    base = next(item for item in valid if item["id"] == "vec-ordinary-none")
    single = next(item for item in valid if item["id"] == "vec-required-single")
    multiple_parents = next(item for item in valid if item["id"] == "vec-parent-multiple")
    control_revoke = next(item for item in valid if item["id"] == "vec-control-revoke")
    final_control = next(item for item in valid if item["id"] == "vec-control-closure")
    values: list[dict[str, Any]] = []
    ap_expectations: list[dict[str, Any]] = []

    def transcript_mutation(identifier: str, mutation: str, mutate: Any) -> None:
        record = _mutated_vector(base, identifier, mutation, "S3_KERNEL_STRUCTURAL", "STRUCTURAL_REJECTION")
        raw = bytearray.fromhex(record["transcriptHex"])
        mutate(raw)
        record["transcriptHex"] = raw.hex()
        values.append(record)

    transcript_mutation("inv-wrong-domain", "WRONG_DOMAIN", lambda raw: raw.__setitem__(15, 1))
    transcript_mutation("inv-body-length", "BODY_LENGTH_MISMATCH", lambda raw: raw.__setitem__(19, raw[19] ^ 1))

    signature = _mutated_vector(base, "inv-signature", "SIGNATURE_SUBSTITUTION", "S3_KERNEL_STRUCTURAL", "INVALID")
    sig = bytearray.fromhex(signature["signatureHex"])
    sig[0] ^= 1
    signature["signatureHex"] = sig.hex()
    values.append(signature)

    rejected_replay = json.loads(json.dumps(signature))
    rejected_replay["id"] = "inv-rejected-signature-representation"
    rejected_replay["mutation"] = "REJECTED_SIGNATURE_REPRESENTATION"
    rejected_replay["sourceVectorId"] = "inv-signature"
    rejected_replay["admissionContext"] = {
        "seenEventReferences": [base["eventReferenceHex"]],
        "admittedEventReferences": [],
    }
    values.append(rejected_replay)

    reference = _mutated_vector(base, "inv-reference", "REFERENCE_SUBSTITUTION", "S3_KERNEL_STRUCTURAL", "REFERENCE_COLLISION_UNSUPPORTED")
    reference["eventReferenceHex"] = synthetic_octets("wrong-reference", 32).hex()
    # A presented-reference mismatch is the unsupported-collision branch only
    # when the replica has already indexed that presented reference for
    # different canonical bytes. Keep that state explicit rather than asking
    # a clean-room reader to infer collision evidence from a bare mismatch.
    reference["admissionContext"] = {
        "seenEventReferences": [reference["eventReferenceHex"]]
    }
    values.append(reference)

    binding_context = _mutated_vector(base, "inv-binding-context", "CONTEXT_SUBSTITUTION", "S3_KERNEL_STRUCTURAL", "CREDENTIAL_BINDING_MISMATCH")
    binding_context["binding"]["contextIdentifierHex"] = synthetic_octets("other-context", 32).hex()
    values.append(binding_context)

    binding_credential = _mutated_vector(base, "inv-binding-credential", "CREDENTIAL_SUBSTITUTION", "S3_KERNEL_STRUCTURAL", "CREDENTIAL_BINDING_MISMATCH")
    binding_credential["binding"]["credentialIdentifierHex"] = synthetic_octets("other-credential", 32).hex()
    values.append(binding_credential)

    commitment = _mutated_vector(single, "inv-commitment", "OPENING_LENGTH_SUBSTITUTION", "S3_KERNEL_STRUCTURAL", "LENGTH_MISMATCH")
    commitment["opening"]["contentHex"] = b"different synthetic content".hex()
    values.append(commitment)

    commitment_equal = _mutated_vector(
        single,
        "inv-commitment-equal-length",
        "EQUAL_LENGTH_OPENING_SUBSTITUTION",
        "S3_KERNEL_STRUCTURAL",
        "COMMITMENT_MISMATCH",
    )
    commitment_equal["opening"]["contentHex"] = b"tampered-c03-content!".hex()
    values.append(commitment_equal)

    missing_opening = _mutated_vector(single, "inv-opening-missing", "REQUIRED_OPENING_REMOVAL", "EVENT_LOCAL", "PENDING_OPENING")
    missing_opening.pop("opening")
    values.append(missing_opening)

    detachable = next(
        item for item in valid if item["id"] == "vec-selected-chunk-octets"
    )
    missing_detachable = _mutated_vector(
        detachable,
        "inv-opening-missing-detachable",
        "DETACHABLE_OPENING_REMOVAL",
        "S3_KERNEL_STRUCTURAL",
        "OPENING_MISSING",
    )
    missing_detachable.pop("opening")
    values.append(missing_detachable)

    parent_order = _mutated_vector(
        multiple_parents,
        "inv-parent-order",
        "CAUSAL_PARENT_REORDERING",
        "S3_KERNEL_STRUCTURAL",
        "STRUCTURAL_REJECTION",
    )
    raw = bytearray.fromhex(parent_order["transcriptHex"])
    first, second = [bytes.fromhex(value) for value in multiple_parents["fields"]["causalParents"]]
    position = raw.find(first + second)
    if position < 0:
        raise ValueError("canonical parent sequence missing from transcript")
    raw[position : position + 64] = second + first
    parent_order["transcriptHex"] = raw.hex()
    values.append(parent_order)

    def generated_invalid(
        identifier: str,
        mutation: str,
        fields: dict[str, Any],
        *,
        stage: str = "S3_KERNEL_STRUCTURAL",
        outcome: str = "CURRENT_OBJECT_OUT_OF_PROFILE",
        seed: str = "seed/root",
        source: str = "vec-ordinary-none",
    ) -> None:
        record = _application_vector(identifier, fields, seed)
        record["mutation"] = mutation
        record["sourceVectorId"] = source
        record["expected"] = {
            "externalEffects": [],
            "firstFailingStage": stage,
            "localOutcome": outcome,
            "stateUnchanged": True,
        }
        values.append(record)

    profile_fields = json.loads(json.dumps(base["fields"]))
    profile_fields["applicationProfileId"] = 2
    generated_invalid(
        "inv-profile-substitution",
        "APPLICATION_PROFILE_SUBSTITUTION",
        profile_fields,
        outcome="STRUCTURAL_REJECTION",
    )

    self_lineage_fields = _event_fields(
        "self-lineage-reduction",
        role="CREDENTIAL",
        tail={
            "kind": "REVOKE",
            "targetCredentialHex": "00" * 32,
        },
    )
    self_lineage_fields["tail"]["targetCredentialHex"] = self_lineage_fields[
        "credentialIdentifierHex"
    ]
    generated_invalid(
        "inv-self-lineage",
        "SELF_LINEAGE_REDUCTION",
        self_lineage_fields,
        stage="EVENT_LOCAL",
        outcome="AUTHENTIC_BUT_UNAUTHORIZED",
        source="vec-control-revoke",
    )
    values[-1]["admissionContext"] = {
        "authorizedCredentialIdentifiers": [
            self_lineage_fields["credentialIdentifierHex"]
        ]
    }
    ap_expectations.append(values.pop())

    parent_limit_fields = _event_fields(
        "resource-parent-count",
        sequence=final_control["fields"]["authorSequence"] + 1,
        predecessor=final_control["eventReferenceHex"],
        parents=[synthetic_octets(f"resource-parent/{index}", 32).hex() for index in range(9)],
    )
    generated_invalid(
        "inv-resource-parent-count",
        "EXCEED_SELECTED_PARENTS_PER_EVENT",
        parent_limit_fields,
        stage="S4_GRAPH_ADMISSION",
        outcome="CONTEXT_CAPACITY_EXHAUSTED",
    )

    sequence_fields = _event_fields(
        "resource-sequence",
        sequence=4096,
        predecessor=final_control["eventReferenceHex"],
    )
    generated_invalid(
        "inv-resource-sequence",
        "EXCEED_SELECTED_SEQUENCE_VALUE",
        sequence_fields,
    )

    transition_fields = _event_fields(
        "resource-transition-block",
        sequence=final_control["fields"]["authorSequence"] + 1,
        predecessor=final_control["eventReferenceHex"],
    )
    transition_fields["transitionBlockHex"] = synthetic_octets("resource-transition-block", 4097).hex()
    generated_invalid(
        "inv-resource-transition-block",
        "EXCEED_SELECTED_AP_TRANSITION_BLOCK_OCTETS",
        transition_fields,
    )

    def tree_descriptor(*, chunk_size: int, chunk_count: int, final_length: int, exact_length: int = 1) -> dict[str, Any]:
        return {
            "class": "DETACHABLE",
            "commitmentHex": synthetic_octets("resource-commitment", 32).hex(),
            "contentType": 2,
            "exactLength": exact_length,
            "geometry": {
                "chunkCount": chunk_count,
                "chunkSize": chunk_size,
                "finalChunkLength": final_length,
            },
            "shape": "TREE",
        }

    generated_invalid(
        "inv-resource-chunk-size",
        "EXCEED_SELECTED_CHUNK_OCTETS",
        _event_fields(
            "resource-chunk-size",
            sequence=final_control["fields"]["authorSequence"] + 1,
            predecessor=final_control["eventReferenceHex"],
            content=tree_descriptor(
                chunk_size=8192,
                chunk_count=2,
                final_length=1,
                exact_length=8193,
            ),
        ),
    )
    generated_invalid(
        "inv-resource-chunk-count",
        "EXCEED_SELECTED_CHUNKS_PER_CONTENT",
        _event_fields(
            "resource-chunk-count",
            sequence=final_control["fields"]["authorSequence"] + 1,
            predecessor=final_control["eventReferenceHex"],
            content=tree_descriptor(
                chunk_size=4096,
                chunk_count=65,
                final_length=1,
                exact_length=262145,
            ),
        ),
    )
    generated_invalid(
        "inv-resource-content-length",
        "EXCEED_SELECTED_CONTENT_EXACT_OCTETS",
        _event_fields(
            "resource-content-length",
            sequence=final_control["fields"]["authorSequence"] + 1,
            predecessor=final_control["eventReferenceHex"],
            content={
                "class": "REQUIRED",
                "commitmentHex": synthetic_octets("resource-content-commitment", 32).hex(),
                "contentType": 1,
                "exactLength": 262145,
                "shape": "SINGLE",
            },
        ),
    )

    credential_id = base["fields"]["credentialIdentifierHex"]
    contextual = [
        (
            base,
            "inv-checkpoint-substitution",
            "CHECKPOINT_FOR_LIVE_DEPENDENCY",
            "S3_KERNEL_STRUCTURAL",
            "CURRENT_OBJECT_OUT_OF_PROFILE",
            {"checkpointEvidenceReferences": [synthetic_octets("checkpoint-substitution", 32).hex()]},
        ),
        (
            control_revoke,
            "inv-contested-standing",
            "CONTESTED_STANDING_SIBLING_FORK",
            "EVENT_LOCAL",
            "FORK_EVIDENCE",
            {"sameAuthorSequenceReferences": [synthetic_octets("contested-standing-sibling", 32).hex()]},
        ),
        (
            base,
            "inv-fork",
            "SAME_AUTHOR_FORK",
            "EVENT_LOCAL",
            "FORK_EVIDENCE",
            {"sameAuthorSequenceReferences": [synthetic_octets("hostile-sibling-reference", 32).hex()]},
        ),
        (
            base,
            "inv-duplicate",
            "DUPLICATE_REPLAY",
            "S3_KERNEL_STRUCTURAL",
            "DUPLICATE",
            {"admittedEventReferences": [base["eventReferenceHex"]]},
        ),
        (
            multiple_parents,
            "inv-missing-dependency",
            "DEPENDENCY_REMOVAL",
            "S4_GRAPH_ADMISSION",
            "DEPENDENCY_DEFERRED",
            {"availableDependencyReferences": []},
        ),
    ]
    for source, identifier, mutation, stage, outcome, context in contextual:
        record = _mutated_vector(source, identifier, mutation, stage, outcome)
        record["admissionContext"] = context
        values.append(record)

    pending_ancestor = _mutated_vector(
        multiple_parents,
        "inv-pending-ancestor",
        "KNOWN_PENDING_ROOT_DEPENDENCY",
        "EVENT_LOCAL",
        "PENDING_ANCESTOR",
    )
    pending_roots = list(multiple_parents["fields"]["causalParents"])
    if multiple_parents["fields"]["directPredecessorHex"] is not None:
        pending_roots.append(multiple_parents["fields"]["directPredecessorHex"])
    pending_ancestor["admissionContext"] = {
        "availableDependencyReferences": [],
        "knownPendingOpeningRoots": sorted(pending_roots),
    }
    values.append(pending_ancestor)

    collision = _mutated_vector(
        next(item for item in valid if item["id"] == "vec-control-grant"),
        "inv-credential-identifier-collision",
        "BOUNDED_CREDENTIAL_IDENTIFIER_COLLISION_INJECTION",
        "S3_KERNEL_STRUCTURAL",
        "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED",
    )
    collision["admissionContext"] = {"credentialIdentifierCollision": True}
    values.append(collision)

    unresolved = _mutated_vector(
        base,
        "inv-unresolved-credential-binding",
        "NON_GRANT_BINDING_CARDINALITY_ZERO",
        "S3_KERNEL_STRUCTURAL",
        "UNRESOLVED_CREDENTIAL_BINDING",
    )
    unresolved["admissionContext"] = {"credentialBindingMatchCount": 0}
    values.append(unresolved)

    for source, identifier, mutation, outcome, context in (
        (
            base,
            "inv-unauthorized",
            "AUTHORITY_LAUNDERING",
            "AUTHENTIC_BUT_UNAUTHORIZED",
            {"authorizedCredentialIdentifiers": []},
        ),
        (
            base,
            "inv-post-revocation",
            "POST_REVOCATION_ACTION",
            "POST_REVOCATION",
            {"revokedCredentialIdentifiers": [credential_id]},
        ),
    ):
        record = _mutated_vector(source, identifier, mutation, "EVENT_LOCAL", outcome)
        record["admissionContext"] = context
        record["expectationLayer"] = "AP_EXPECTATION_ONLY"
        ap_expectations.append(record)

    for record in ap_expectations:
        record["expectationLayer"] = "AP_EXPECTATION_ONLY"
    return (
        sorted(values, key=lambda record: record["id"]),
        sorted(ap_expectations, key=lambda record: record["id"]),
    )


def _scenarios(
    model: dict[str, Any],
    valid: list[dict[str, Any]],
    invalid: list[dict[str, Any]],
    ap_expectations: list[dict[str, Any]],
    k_records: list[dict[str, Any]],
    k_scenarios: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    default_input = "vec-ordinary-none"
    vector_by_id = {
        record["id"]: record
        for record in valid + invalid + ap_expectations
    }
    transcript_ids = {record["id"] for record in valid + ap_expectations}
    k_by_id = {record["id"]: record for record in k_records}
    k_scenario_by_id = {scenario["id"]: scenario for scenario in k_scenarios}
    scenarios: list[dict[str, Any]] = []

    def vector_expectation(vector_id: str) -> tuple[dict[str, Any], str]:
        result = (
            evaluate_transcript_conformance(vector_by_id[vector_id])
            if vector_id in transcript_ids
            else evaluate_vector(vector_by_id[vector_id])
        )
        post_state = (
            "UNCHANGED"
            if result["preStateDigest"] == result["postStateDigest"]
            else "READY_FOR_AP_FOLD"
        )
        return result, post_state

    def connected_expectation(
        scenario_id: str, record_id: str
    ) -> tuple[dict[str, Any], str]:
        scenario = k_scenario_by_id[scenario_id]
        genesis = k_by_id[scenario["acceptedGenesisRecordId"]]
        records = [k_by_id[identifier] for identifier in scenario["recordIds"]]
        result = next(
            observation
            for observation in evaluate_k_admission_scenario(genesis, records)
            if observation["id"] == record_id
        )
        if not transition_input_is_compatible(result):
            raise ValueError(
                f"connected K witness is not admitted: {scenario_id}:{record_id}"
            )
        return result, "READY_FOR_AP_FOLD"

    def step(
        *,
        action: str,
        vector_id: str | None,
        pre_state: str,
        required: list[str] | None = None,
        produced: str | None = None,
        transition_id: str | None = None,
        expected_outcome: str | None = None,
        expected_stage: str | None = None,
        expected_post_state: str | None = None,
        actor: str = "kernel",
        executed: bool = True,
        expected_dependency_status: str = "SATISFIED",
        ap_expectation_only: str | None = None,
        expected_result_layer: str | None = None,
        k_scenario_id: str | None = None,
        k_record_id: str | None = None,
    ) -> dict[str, Any]:
        connected = k_scenario_id is not None or k_record_id is not None
        if connected:
            if vector_id is not None or k_scenario_id is None or k_record_id is None:
                raise ValueError("connected K witness shape mismatch")
            result, post_state = connected_expectation(k_scenario_id, k_record_id)
        else:
            if vector_id is None:
                raise ValueError("missing vector witness")
            result, post_state = vector_expectation(vector_id)
        record = {
            "actor": actor,
            "candidateAction": action,
            "executed": executed,
            "expectedDependencyStatus": expected_dependency_status,
            "expectedPostState": expected_post_state or post_state,
            "expectedStage": expected_stage or result["stage"],
            "preState": pre_state,
            "providedEvidence": produced,
            "requiredPriorEvidence": required or [],
            "transitionId": transition_id,
        }
        if connected:
            record["inputKAdmissionRecordId"] = k_record_id
            record["inputKAdmissionScenarioId"] = k_scenario_id
            record["evidenceLayer"] = "CONNECTED_K_ADMISSION"
        else:
            record["inputVectorId"] = vector_id
            record["evidenceLayer"] = (
                "BOUNDARY_NOT_EXECUTED"
                if not executed
                else (
                    "TRANSCRIPT_CONFORMANCE"
                    if vector_id in transcript_ids
                    else "LOCAL_NEGATIVE"
                )
            )
        selected_outcome = expected_outcome or result.get("localOutcome")
        if selected_outcome is not None:
            record["expectedOutcome"] = selected_outcome
        selected_layer = expected_result_layer
        if selected_layer is None and transition_input_is_compatible(result):
            selected_layer = "K_ADMISSION_ONLY"
        if selected_layer is not None:
            record["expectedResultLayer"] = selected_layer
        if ap_expectation_only is not None:
            record["apExpectationOnly"] = ap_expectation_only
        return record

    for state_model in model["state_models"]:
        model_id = state_model["id"]
        for transition in state_model["transitions"]:
            from_state = transition["from"][0]
            scenario_id = f"scenario-state-{model_id}-{transition['id']}"
            transition_key = (model_id, transition["id"])
            if model_id == "ap_projection":
                transition_step = step(
                    action=transition["trigger"],
                    vector_id=default_input,
                    pre_state=from_state,
                    produced=f"evidence:{scenario_id}:0",
                    transition_id=transition["id"],
                    executed=False,
                    expected_outcome="NOT_EVALUATED",
                    expected_stage="BOUNDARY_NOT_EXECUTED",
                    expected_post_state="UNCHANGED",
                    ap_expectation_only=transition["outcome"],
                )
            elif transition_key in K_ADMISSION_ONLY_TRANSITIONS:
                witness_scenario, witness_record = CONNECTED_K_TRANSITION_WITNESSES[
                    transition_key
                ]
                transition_step = step(
                    action=transition["trigger"],
                    vector_id=None,
                    pre_state=from_state,
                    produced=f"evidence:{scenario_id}:0",
                    transition_id=transition["id"],
                    expected_post_state=transition["to"],
                    expected_result_layer="K_ADMISSION_ONLY",
                    k_scenario_id=witness_scenario,
                    k_record_id=witness_record,
                )
            else:
                vector_id = NEGATIVE_K_TRANSITION_VECTORS[transition_key]
                result = evaluate_vector(vector_by_id[vector_id])
                transition_step = step(
                    action=transition["trigger"],
                    vector_id=vector_id,
                    pre_state=from_state,
                    produced=f"evidence:{scenario_id}:0",
                    transition_id=transition["id"],
                    expected_outcome=transition["outcome"],
                    expected_stage=result["stage"],
                    expected_post_state=transition["to"],
                )
            scenarios.append(
                {
                    "citations": transition["citations"],
                    "id": scenario_id,
                    "modelId": model_id,
                    "steps": [transition_step],
                }
            )
    for counterexample in model["counterexamples"]:
        scenario_id = f"scenario-counterexample-{counterexample['id'].lower()}"
        vector_program = COUNTEREXAMPLE_VECTOR_PROGRAMS[counterexample["id"]]
        evidence: list[str] = []
        steps: list[dict[str, Any]] = []
        for index, (action, vector_id) in enumerate(zip(counterexample["steps"], vector_program, strict=True)):
            produced = f"evidence:{scenario_id}:{index}"
            steps.append(
                step(
                    action=action,
                    vector_id=vector_id,
                    pre_state="SYNTHETIC_BASELINE" if index == 0 else f"AFTER_{index - 1}",
                    required=list(evidence),
                    produced=produced,
                )
            )
            evidence.append(produced)
        scenarios.append(
            {
                "citations": counterexample["citations"],
                "counterexampleId": counterexample["id"],
                "id": scenario_id,
                "modelId": "counterexample",
                "steps": steps,
            }
        )
    for flow in model["flows"]:
        excluded = flow["id"] in {
            "secure_session_receive",
            "secure_session_send",
            "transport_publish",
        }
        scenarios.append(
            {
                "citations": flow["citations"],
                "flowId": flow["id"],
                "id": f"scenario-flow-{flow['id']}",
                "modelId": "flow",
                "steps": [
                    step(
                        action=flow["permitted_actions"][0],
                        vector_id=default_input,
                        pre_state="FLOW_READY",
                        produced=f"evidence:scenario-flow-{flow['id']}:0",
                        actor=flow["producer"],
                        executed=not excluded,
                        expected_outcome=None if not excluded else (
                            "TRANSPORT_PROFILE_REQUIRED" if flow["id"] == "transport_publish" else "SESSION_PROFILE_REQUIRED"
                        ),
                        expected_post_state="UNCHANGED",
                        expected_stage=(
                            "TRANSCRIPT_CONFORMANCE_COMPLETE"
                            if not excluded
                            else "BOUNDARY_NOT_EXECUTED"
                        ),
                    )
                ],
            }
        )

    # Every byte/context vector has an executable witness.  This prevents the
    # corpus from claiming coverage for vectors that no scenario ever consumes.
    for vector in valid + invalid + ap_expectations:
        scenario_id = f"scenario-vector-{vector['id']}"
        scenarios.append(
            {
                "citations": vector["citations"],
                "id": scenario_id,
                "modelId": "vector",
                "steps": [
                    step(
                        action=f"Evaluate exact vector {vector['id']}",
                        vector_id=vector["id"],
                        pre_state="VECTOR_BASELINE",
                        produced=f"evidence:{scenario_id}:0",
                    )
                ],
                "vectorId": vector["id"],
            }
        )

    # Invariant witnesses are intentionally one-to-one.  Shared setup bytes are
    # allowed, but the asserted invariant, scenario and hostile mutation are not.
    invariant_by_id = {record["id"]: record for record in model["invariants"]}
    for invariant_id, vector_id in INVARIANT_WITNESS_VECTORS.items():
        scenario_id = f"scenario-invariant-{invariant_id.lower()}"
        scenarios.append(
            {
                "citations": invariant_by_id[invariant_id]["citations"],
                "exercisedInvariantIds": [invariant_id],
                "id": scenario_id,
                "modelId": "invariant",
                "steps": [
                    step(
                        action=f"Falsify {invariant_id} with {vector_id}",
                        vector_id=vector_id,
                        pre_state="INVARIANT_BASELINE",
                        produced=f"evidence:{scenario_id}:0",
                    )
                ],
            }
        )

    # Explicitly exercise history-sensitive replay and sibling classification.
    for suffix, vector_program in (
        ("idempotent-replay", ["vec-ordinary-none", "inv-duplicate"]),
        ("sibling-fork", ["vec-ordinary-none", "inv-fork"]),
        ("revocation-effect", ["vec-control-revoke", "inv-post-revocation"]),
        ("rotation-effect", ["vec-control-rotate", "inv-unauthorized"]),
    ):
        scenario_id = f"scenario-history-{suffix}"
        first_evidence = f"evidence:{scenario_id}:0"
        scenarios.append(
            {
                "citations": COMMON_CITATIONS,
                "id": scenario_id,
                "modelId": "history",
                "steps": [
                    step(
                        action=f"Establish history for {suffix}",
                        vector_id=vector_program[0],
                        pre_state="HISTORY_EMPTY",
                        produced=first_evidence,
                    ),
                    step(
                        action=f"Exercise history-sensitive {suffix}",
                        vector_id=vector_program[1],
                        pre_state="HISTORY_ESTABLISHED",
                        required=[first_evidence],
                        produced=f"evidence:{scenario_id}:1",
                    ),
                ],
            }
        )

    scenarios.append(
        {
            "citations": COMMON_CITATIONS,
            "id": "scenario-dependency-missing",
            "modelId": "dependency",
            "steps": [
                step(
                    action="Reject one candidate whose required prior evidence is absent",
                    vector_id="inv-missing-dependency",
                    pre_state="DEPENDENCY_UNAVAILABLE",
                    required=["evidence:not-produced"],
                    produced="evidence:scenario-dependency-missing:0",
                    expected_dependency_status="MISSING",
                )
            ],
        }
    )
    ap_by_id = {record["id"]: record for record in ap_expectations}
    actual_ap_locators: set[str] = set()
    for scenario in scenarios:
        for index, scenario_step in enumerate(scenario["steps"]):
            locator = f"{scenario['id']}:{index}"
            if locator not in AP_EXPECTATION_ONLY_STEP_LOCATORS:
                continue
            vector_id = scenario_step["inputVectorId"]
            if vector_id not in AP_EXPECTATION_ONLY_VECTOR_IDS:
                raise ValueError(f"AP-only step does not use an AP-only vector: {locator}")
            scenario_step.pop("expectedOutcome", None)
            scenario_step["expectedResultLayer"] = "TRANSCRIPT_CONFORMANCE_ONLY"
            scenario_step["expectedPostState"] = "UNCHANGED"
            scenario_step["apExpectationOnly"] = ap_by_id[vector_id]["expected"]["localOutcome"]
            actual_ap_locators.add(locator)
    if actual_ap_locators != AP_EXPECTATION_ONLY_STEP_LOCATORS:
        raise ValueError("AP-expectation-only scenario locator set drifted")
    return sorted(scenarios, key=lambda record: record["id"])


def _traces(
    scenarios: list[dict[str, Any]],
    vector_by_id: dict[str, dict[str, Any]],
    k_records: list[dict[str, Any]],
    k_scenarios: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    k_by_id = {record["id"]: record for record in k_records}
    k_scenario_by_id = {scenario["id"]: scenario for scenario in k_scenarios}
    traces: list[dict[str, Any]] = []
    for scenario in scenarios:
        entries = []
        available_evidence: set[str] = set()
        for index, step in enumerate(scenario["steps"]):
            connected = step["evidenceLayer"] == "CONNECTED_K_ADMISSION"
            vector = None
            graph_records: list[dict[str, Any]] | None = None
            graph_genesis: dict[str, Any] | None = None
            if connected:
                graph_scenario = k_scenario_by_id[step["inputKAdmissionScenarioId"]]
                graph_genesis = k_by_id[graph_scenario["acceptedGenesisRecordId"]]
                graph_records = [
                    k_by_id[identifier] for identifier in graph_scenario["recordIds"]
                ]
                evaluated = next(
                    observation
                    for observation in evaluate_k_admission_scenario(
                        graph_genesis, graph_records
                    )
                    if observation["id"] == step["inputKAdmissionRecordId"]
                )
            else:
                vector = vector_by_id[step["inputVectorId"]]
                if not step.get("executed", True):
                    evaluated = None
                elif step["evidenceLayer"] == "TRANSCRIPT_CONFORMANCE":
                    evaluated = evaluate_transcript_conformance(vector)
                else:
                    evaluated = evaluate_vector(vector)
            pre_digest = sha256(
                f"styx-c03/state/{scenario['id']}/{step['preState']}".encode()
            ).hexdigest()
            unchanged = step["expectedPostState"] == "UNCHANGED" or not step.get("executed", True)
            post_digest = pre_digest if unchanged else sha256(
                f"styx-c03/state/{scenario['id']}/{step['expectedPostState']}".encode()
            ).hexdigest()
            requirements = set(step["requiredPriorEvidence"])
            dependency_status = "SATISFIED" if requirements <= available_evidence else "MISSING"
            if dependency_status != step["expectedDependencyStatus"]:
                raise ValueError(f"dependency-status mismatch: {scenario['id']}:{index}")
            if step["transitionId"] is not None and scenario["modelId"] != "ap_projection":
                if step.get("expectedResultLayer") == "K_ADMISSION_ONLY":
                    if not transition_input_is_compatible(evaluated or {}):
                        raise ValueError(f"incompatible positive K transition: {scenario['id']}:{index}")
                elif evaluated is None or evaluated.get("localOutcome") != step.get("expectedOutcome"):
                    raise ValueError(f"incompatible negative K transition: {scenario['id']}:{index}")
            if evaluated is None:
                observation = {
                    "apAuthorityResult": "NOT_EVALUATED",
                    "commitmentMatchVerification": "NOT_EVALUATED",
                    "commitmentVerification": "NOT_PRESENT",
                    "externalEffects": [],
                    **{f"geometryPredicate{number}": "NOT_EVALUATED" for number in range(1, 8)},
                    "kBindingAdmission": "NOT_EVALUATED",
                    "localOutcome": step["expectedOutcome"],
                    "outcomeEvaluated": False,
                    "remoteClass": "OPAQUE_REMOTE_FAILURE",
                    "signatureVerification": "NOT_EVALUATED",
                    "stage": step["expectedStage"],
                    "suppliedLengthVerification": "NOT_EVALUATED",
                    "transcriptVerification": "NOT_EVALUATED",
                }
            else:
                observation = {
                    key: value
                    for key, value in evaluated.items()
                    if key
                    not in {
                        "eventReferenceHex",
                        "id",
                        "preStateDigest",
                        "postStateDigest",
                        "protocolErrorCode",
                    }
                }
                observation["stage"] = step["expectedStage"]
            entry = {
                    "actionDigest": sha256(step["candidateAction"].encode()).hexdigest(),
                    "causalClassification": (
                        step["transitionId"]
                        or (
                            f"K_GRAPH:{step['inputKAdmissionScenarioId']}:{step['inputKAdmissionRecordId']}"
                            if connected
                            else f"VECTOR:{vector['id']}"
                        )
                    ),
                    "dependencyStatus": dependency_status,
                    "evidenceConsumed": sorted(requirements),
                    "evidenceProduced": step.get("providedEvidence"),
                    "executed": step.get("executed", True),
                    "inputDigest": (
                        semantic_k_graph_input_digest(
                            graph_genesis,
                            graph_records,
                            step["inputKAdmissionRecordId"],
                        )
                        if connected
                        else semantic_input_digest(vector)
                    ),
                    "postStateDigest": post_digest,
                    "preStateDigest": pre_digest,
                    "step": index,
                }
            entry.update(observation)
            if "apExpectationOnly" in step:
                entry["apExpectationOnly"] = step["apExpectationOnly"]
            entries.append(entry)
            if step.get("providedEvidence") is not None:
                available_evidence.add(step["providedEvidence"])
        trace = {"id": f"trace-{scenario['id']}", "scenarioId": scenario["id"], "steps": entries}
        trace["observationDigest"] = _digest({"scenarioId": scenario["id"], "steps": entries})
        trace["semanticObservationDigest"] = semantic_observation_digest(entries)
        traces.append(trace)
    return sorted(traces, key=lambda record: record["id"])


def _mutations(
    invalid: list[dict[str, Any]],
    inventory: dict[str, Any],
    reader: BaseReader,
    scenarios: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    mutations: list[dict[str, Any]] = []
    for record in invalid:
        mutations.append(
            {
                "detector": "INDEPENDENT_REPLAY_EXPECTATION_MISMATCH",
                "expectedOutcome": record["expected"]["localOutcome"],
                "expectedStage": record["expected"]["firstFailingStage"],
                "generatedTargetId": record["id"],
                "id": f"mutation-vector-{record['id']}",
                "sourceRecordId": record["sourceVectorId"],
                "transformation": record["mutation"],
                "mutationClass": "SEMANTIC_VECTOR",
                "violatedInvariant": INVALID_VECTOR_INVARIANTS[record["id"]],
            }
        )

    # Each executable invariant owns a distinct executable scenario and a
    # distinct legal-input substitution.  These are the only mutations used as
    # invariant falsification witnesses by the coverage map.
    scenario_ids = {record["id"] for record in scenarios}
    for invariant_id, witness_vector_id in sorted(INVARIANT_WITNESS_VECTORS.items()):
        scenario_id = f"scenario-invariant-{invariant_id.lower()}"
        if scenario_id not in scenario_ids:
            raise ValueError(f"missing invariant scenario: {invariant_id}")
        replacement = "vec-secondary-context-author" if witness_vector_id != "vec-secondary-context-author" else "vec-ordinary-none"
        mutations.append(
            {
                "detector": "INVARIANT_WITNESS_TRACE_MISMATCH",
                "expectedOutcome": "STRUCTURAL_REJECTION",
                "expectedStage": "CORPUS_REPLAY",
                "generatedTargetId": f"trace-{scenario_id}",
                "id": f"mutation-invariant-{invariant_id.lower()}",
                "mutationClass": "SEMANTIC_INVARIANT",
                "replacementVectorId": replacement,
                "sourceRecordId": scenario_id,
                "transformation": "SUBSTITUTE_LEGAL_VECTOR_IN_EXACT_INVARIANT_WITNESS",
                "violatedInvariant": invariant_id,
            }
        )
    mutations.extend(
        (
            {
                "detector": "INDEPENDENT_EXPECTED_STAGE_MISMATCH",
                "expectedOutcome": "STRUCTURAL_REJECTION",
                "expectedStage": "CORPUS_REPLAY",
                "generatedTargetId": invalid[0]["id"],
                "id": "mutation-expected-invalid-stage",
                "sourceRecordId": invalid[0]["id"],
                "transformation": "CORRUPT_EXPECTED_FIRST_FAILING_STAGE_ONLY",
                "mutationClass": "EXPECTED_RESULT",
                "violatedInvariant": "INV_OUTCOME_PRECEDENCE",
            },
            {
                "detector": "INDEPENDENT_EXPECTED_OUTCOME_MISMATCH",
                "expectedOutcome": "STRUCTURAL_REJECTION",
                "expectedStage": "CORPUS_REPLAY",
                "generatedTargetId": invalid[0]["id"],
                "id": "mutation-expected-invalid-outcome",
                "sourceRecordId": invalid[0]["id"],
                "transformation": "CORRUPT_EXPECTED_LOCAL_OUTCOME_ONLY",
                "mutationClass": "EXPECTED_RESULT",
                "violatedInvariant": "INV_OUTCOME_PRECEDENCE",
            },
            {
                "detector": "INDEPENDENT_EXPECTED_TRACE_MISMATCH",
                "expectedOutcome": "STRUCTURAL_REJECTION",
                "expectedStage": "CORPUS_REPLAY",
                "generatedTargetId": "trace-scenario-flow-author_application_event",
                "id": "mutation-expected-trace-outcome",
                "sourceRecordId": "trace-scenario-flow-author_application_event",
                "transformation": "CORRUPT_EXPECTED_TRACE_OUTCOME_ONLY",
                "mutationClass": "EXPECTED_RESULT",
                "violatedInvariant": "INV_OUTCOME_PRECEDENCE",
            },
            {
                "detector": "INDEPENDENT_EXPECTED_DEPENDENCY_STATUS_MISMATCH",
                "expectedOutcome": "STRUCTURAL_REJECTION",
                "expectedStage": "CORPUS_REPLAY",
                "generatedTargetId": "trace-scenario-dependency-missing",
                "id": "mutation-expected-trace-dependency-status",
                "sourceRecordId": "trace-scenario-dependency-missing",
                "transformation": "CORRUPT_EXPECTED_DEPENDENCY_STATUS_ONLY",
                "mutationClass": "EXPECTED_RESULT",
                "violatedInvariant": "INV_CAUSAL_TARGET_AVAILABILITY",
            },
        )
    )
    mutations.extend(
        {
            **record,
            "expectedOutcome": "MUTANT_REJECTED",
            "expectedStage": "SOURCE_MUTATION",
            "mutationClass": "SOURCE_ANCHORED_SECURITY",
            "sourceRecordId": record["sourcePath"],
        }
        for record in SOURCE_SECURITY_MUTATIONS
    )
    for dimension in sorted(
        identifier
        for role in (
            "C03_SEMANTIC_LIMIT",
            "C03_ACTIVATION_CAPABILITY_INPUT",
            "C03_EXPLICIT_ZERO_OR_UNSUPPORTED",
        )
        for identifier in inventory["o08_roles"][role]
    ):
        mutations.append(
            {
                "detector": "O08_EXACT_DIMENSION_SET",
                "expectedOutcome": "STRUCTURAL_REJECTION",
                "expectedStage": "CORPUS_VALIDATION",
                "generatedTargetId": dimension,
                "id": f"mutation-o08-{dimension.lower()}",
                "sourceRecordId": "manifest",
                "transformation": "REMOVE_SELECTED_O08_DIMENSION",
                "mutationClass": "EVIDENCE_INTEGRITY",
                "violatedInvariant": "INV_AUTHORITY_PROJECTION_LIMITS",
            }
        )
    for row in reader.json("tools/causal-flow-simulator/o07/required_atom_instances_v1.json")["rows"]:
        mutations.append(
            {
                "detector": "O07_EXACT_RELATION_SET",
                "expectedOutcome": "STRUCTURAL_REJECTION",
                "expectedStage": "CORPUS_VALIDATION",
                "generatedTargetId": row["atom_instance_id"],
                "id": f"mutation-o07-{row['atom_instance_id'].lower()}",
                "sourceRecordId": row["scenario_instance_id"],
                "transformation": "REMOVE_REQUIRED_O07_RELATION",
                "mutationClass": "EVIDENCE_INTEGRITY",
                "violatedInvariant": "INV_PROTECTION_SEPARATION",
            }
        )
    for row in reader.json("tools/causal-flow-simulator/o10/source-inventory.json")["rows"]:
        mutations.append(
            {
                "detector": "O10_EXACT_SOURCE_ROW_SET",
                "expectedOutcome": "STRUCTURAL_REJECTION",
                "expectedStage": "CORPUS_VALIDATION",
                "generatedTargetId": row["row_id"],
                "id": f"mutation-o10-{sha256(row['row_id'].encode()).hexdigest()[:16]}",
                "sourceRecordId": row["row_id"],
                "transformation": "REMOVE_REQUIRED_O10_ROW",
                "mutationClass": "EVIDENCE_INTEGRITY",
                "violatedInvariant": "INV_OUTCOME_PRECEDENCE",
            }
        )
    for target in CORPUS_FILES:
        mutations.append(
            {
                "detector": "MANIFEST_DIGEST_MISMATCH",
                "expectedOutcome": "STRUCTURAL_REJECTION",
                "expectedStage": "CORPUS_VALIDATION",
                "generatedTargetId": target,
                "id": f"mutation-manifest-{target.removesuffix('.json')}",
                "sourceRecordId": "manifest",
                "transformation": "CORRUPT_MANIFEST_DIGEST",
                "mutationClass": "EVIDENCE_INTEGRITY",
                "violatedInvariant": "INV_O06C_BOUNDED_EVIDENCE",
            }
        )
    return sorted(mutations, key=lambda record: record["id"])


def _coverage(
    model: dict[str, Any],
    inventory: dict[str, Any],
    scenarios: list[dict[str, Any]],
    mutations: list[dict[str, Any]],
    k_admission_hostile: list[dict[str, Any]],
    reader: BaseReader,
) -> dict[str, Any]:
    scenario_ids = [item["id"] for item in scenarios]
    transition_scenarios = {
        item["steps"][0]["transitionId"]: item["id"]
        for item in scenarios
        if item["steps"][0]["transitionId"] is not None
    }
    invariant_rows = []
    for record in model["invariants"]:
        if record["id"] in NONEXECUTABLE_INVARIANTS:
            invariant_rows.append(
                {
                    "branch": "NON_EXECUTABLE_NON_CLAIM",
                    "citations": record["citations"],
                    "id": record["id"],
                    "reason": "GOVERNANCE_OR_AUTHORIZATION_STATEMENT",
                }
            )
        else:
            witness_scenario = f"scenario-invariant-{record['id'].lower()}"
            hostile_mutation = f"mutation-invariant-{record['id'].lower()}"
            invariant_rows.append(
                {
                    "branch": "EXECUTABLE_WITNESS",
                    "hostileMutationIds": [hostile_mutation],
                    "id": record["id"],
                    "witnessScenarioIds": [witness_scenario],
                }
            )
    exercised_outcomes = {
        step["expectedOutcome"]
        for scenario in scenarios
        for step in scenario["steps"]
        if "expectedOutcome" in step
    }
    outcome_rows = []
    for primary in inventory["o10_primaries"]:
        if primary in PRODUCED_K_PRIMARIES:
            branch = "PRODUCED"
            matching = [
                item["id"]
                for item in scenarios
                if any(step.get("expectedOutcome") == primary for step in item["steps"])
            ]
            matching.extend(
                item["id"]
                for item in k_admission_hostile
                if any(
                    observation.get("protocolErrorCode") == primary
                    for observation in item["expectedObservations"]
                )
            )
            matching.sort()
        elif primary in AP_OWNED_EXCLUSIONS:
            branch = "AP_OWNED_EXCLUDED"
            matching = [
                item["id"]
                for item in scenarios
                if any(step.get("apExpectationOnly") == primary for step in item["steps"])
            ]
        elif primary in TRANSCRIPT_PROFILE_UNREACHABLE:
            branch = "TRANSCRIPT_PROFILE_UNREACHABLE"
            matching = []
        else:
            raise ValueError(f"unpartitioned O-10 primary: {primary}")
        outcome_rows.append(
            {
                "branch": branch,
                "citations": [{"anchor": "## Primary registry", "path": "docs/protocol/styx-app-kernel-v0-outcome-taxonomy.md"}],
                "id": primary,
                "scenarioIds": matching,
            }
        )
    for marker in inventory["o10_post_c03_markers"]:
        outcome_rows.append(
            {
                "branch": "UNREACHABLE_IN_TRANSCRIPT_ONLY_PROFILE",
                "citations": [{"anchor": "## Closed cardinalities", "path": "docs/protocol/styx-app-kernel-v0-outcome-taxonomy.md"}],
                "id": marker,
                "scenarioIds": [],
            }
        )
    source_rows = []
    produced_witnesses = inventory["o10_produced_source_row_witnesses"]
    for row in reader.json("tools/causal-flow-simulator/o10/source-inventory.json")["rows"]:
        row_id = row["row_id"]
        if row_id in produced_witnesses:
            primary = row["mapping"]["primary"]
            disposition = "PRODUCED"
            witnesses = []
            for witness in produced_witnesses[row_id]:
                scenario_id = (
                    f"scenario-vector-{witness['inputId']}"
                    if "inputId" in witness
                    else witness["inputKAdmissionScenarioId"]
                )
                witnesses.append({**witness, "scenarioId": scenario_id})
        elif "mapping" in row and row["mapping"]["primary"] in AP_OWNED_EXCLUSIONS:
            primary = row["mapping"]["primary"]
            disposition = "AP_OWNED_EXCLUDED"
            witnesses = []
        elif "mapping" in row:
            primary = row["mapping"]["primary"]
            disposition = "TRANSCRIPT_PROFILE_UNREACHABLE"
            witnesses = []
        else:
            primary = row["forbidden_identifier"]
            disposition = "TRANSCRIPT_PROFILE_UNREACHABLE"
            witnesses = []
        source_rows.append(
            {
                "disposition": disposition,
                "primary": primary,
                "rowId": row_id,
                "witnesses": witnesses,
            }
        )
    states = sorted(
        {f"{sm['id']}:{state}" for sm in model["state_models"] for state in sm["states"]}
    )
    transitions = sorted(
        {
            f"{sm['id']}:{transition['id']}"
            for sm in model["state_models"]
            for transition in sm["transitions"]
        }
    )
    return {
        "counterexamples": [
            {
                "id": record["id"],
                "scenarioId": f"scenario-counterexample-{record['id'].lower()}",
            }
            for record in model["counterexamples"]
        ],
        "flows": [
            {
                "branch": "BOUNDARY_NOT_EXECUTED" if record["id"] in {"secure_session_receive", "secure_session_send", "transport_publish"} else "EXECUTED",
                "id": record["id"],
                "scenarioId": f"scenario-flow-{record['id']}",
            }
            for record in model["flows"]
        ],
        "invariants": invariant_rows,
        "o07": {
            "coveredRelationIds": [row["atom_instance_id"] for row in reader.json("tools/causal-flow-simulator/o07/required_atom_instances_v1.json")["rows"]],
            "relationCount": 287,
        },
        "o08": {
            "excludedDimensions": sorted(inventory["o08_roles"]["POST_C03_LAYER_PROFILE"] + inventory["o08_roles"]["EVIDENCE_ONLY"]),
            "participatingDimensions": sorted(
                inventory["o08_roles"]["C03_SEMANTIC_LIMIT"]
                + inventory["o08_roles"]["C03_ACTIVATION_CAPABILITY_INPUT"]
                + inventory["o08_roles"]["C03_EXPLICIT_ZERO_OR_UNSUPPORTED"]
            ),
        },
        "o10": {
            "alias": inventory["o10_alias"],
            "coveredSourceRowIds": [row["row_id"] for row in reader.json("tools/causal-flow-simulator/o10/source-inventory.json")["rows"]],
            "outcomes": outcome_rows,
            "sourceRows": source_rows,
        },
        "reviewModel": {key: inventory["expected_review_model_ids"][key] for key in sorted(inventory["expected_review_model_ids"])},
        "states": states,
        "terminalStates": sorted(
            f"{sm['id']}:{state}"
            for sm in model["state_models"]
            for state in sm.get("terminal_states", [])
        ),
        "transitions": [
            {"id": value, "scenarioId": transition_scenarios[value.split(":", 1)[1]]}
            for value in transitions
        ],
    }


def generate(repo_root: Path, output: Path) -> dict[str, Any]:
    source_map, inventory = validate_base_inputs(repo_root)
    if inventory["invariant_witness_vectors"] != INVARIANT_WITNESS_VECTORS:
        raise ValueError("curated invariant witness-vector relation drifted")
    counterexample_programs = [tuple(value) for value in COUNTEREXAMPLE_VECTOR_PROGRAMS.values()]
    if len(counterexample_programs) != len(set(counterexample_programs)):
        raise ValueError("counterexample executable program collision")
    reader = BaseReader(repo_root)
    model = load_local_json(
        repo_root / "docs/protocol/review/styx-app-kernel-v0-review-model.json"
    )
    # Preserve the exact Base transcript fixtures as byte-level regressions.
    # Their historical K-admission claim is deliberately not reused: connected
    # admission is exercised by the separate graph corpus below.
    valid = _valid_vectors(legacy_controls=True)
    k_admission_records, k_admission_scenarios = _k_admission_vectors()
    k_admission_scenarios = sorted(
        k_admission_scenarios, key=lambda scenario: scenario["id"]
    )
    k_admission_hostile = _k_admission_adversarial_scenarios(
        valid,
        k_admission_records,
        k_admission_scenarios,
    )
    invalid, ap_expectations = _invalid_vectors(valid)
    scenarios = _scenarios(
        model,
        valid,
        invalid,
        ap_expectations,
        k_admission_records,
        k_admission_scenarios,
    )
    vectors = {
        item["id"]: item
        for item in valid + invalid + ap_expectations
    }
    traces = _traces(
        scenarios,
        vectors,
        k_admission_records,
        k_admission_scenarios,
    )
    mutations = _mutations(invalid, inventory, reader, scenarios)
    documents = {
        "valid-transcript-vectors.json": {
            "kAdmissionRecords": k_admission_records,
            "records": valid,
            "schema": "styx-c03-valid-transcripts/v2",
        },
        "invalid-transcript-vectors.json": {
            "apExpectationOnlyRecords": ap_expectations,
            "records": invalid,
            "schema": "styx-c03-invalid-transcripts/v2",
        },
        "state-machine-scenarios.json": {
            "kAdmissionScenarios": k_admission_scenarios,
            "records": scenarios,
            "schema": "styx-c03-state-scenarios/v2",
        },
        "adversarial-mutations.json": {
            "kAdmissionScenarios": k_admission_hostile,
            "records": mutations,
            "schema": "styx-c03-adversarial-mutations/v2",
        },
        "expected-traces.json": {"records": traces, "schema": "styx-c03-expected-traces/v2"},
    }
    output.mkdir(parents=True, exist_ok=True)
    for name, document in documents.items():
        store(output / name, document)
    source_entries = []
    for source in source_map["direct_sources"]:
        source_entries.append({"path": source["path"], "sha256": source["sha256"]})
    manifest = {
        "authority": {
            "blocks": inventory["c03_blocks"],
            "corpusConstruction": "COMPLETE",
            "c03Verdict": "NO_GO",
        },
        "corpusFormatVersion": 2,
        "coverage": _coverage(
            model,
            inventory,
            scenarios,
            mutations,
            k_admission_hostile,
            reader,
        ),
        "files": [
            {
                "path": name,
                "recordCount": len(documents[name]["records"]),
                **(
                    {
                        "kAdmissionRecordCount": len(
                            documents[name].get(
                                "kAdmissionRecords",
                                documents[name].get("kAdmissionScenarios", []),
                            )
                        )
                    }
                    if "kAdmissionRecords" in documents[name]
                    or "kAdmissionScenarios" in documents[name]
                    else {}
                ),
                "sha256": sha256_hex((output / name).read_bytes()),
            }
            for name in sorted(documents)
        ],
        "generator": {
            "path": "tools/causal-flow-simulator/c03/generate_corpus.py",
            "sha256": sha256_hex((repo_root / "tools/causal-flow-simulator/c03/generate_corpus.py").read_bytes()),
        },
        "nonClaims": [
            "NO_IMPLEMENTATION_ALIGNMENT",
            "NO_PRODUCT_OR_DEMO_READINESS",
            "NO_PRODUCTION_CEREMONY_OR_RECOVERY",
            "NO_RUNTIME_STORAGE_TRANSPORT_OR_WIRE_CLAIM",
            "NO_SECURITY_PROOF_OR_AUDIT",
            "NO_SENSITIVE_USE",
        ],
        "profile": "STYX_APP_KERNEL_V0_TRANSCRIPT_ONLY",
        "reproduction": {
            "command": "python3 tools/causal-flow-simulator/c03/generate_corpus.py --repo-root . --output OUTPUT",
            "git": ">=2.53.0",
            "node": ">=20",
            "python": ">=3.11",
            "reuse": "6.2.0 / REUSE-3.3",
        },
        "schema": "styx-c03-corpus-manifest/v2",
        "sourceInventory": {
            "base": BASE_SHA,
            "corpusInventorySha256": sha256_hex((repo_root / "tools/causal-flow-simulator/c03/corpus-inventory.json").read_bytes()),
            "corpusSourceMapSha256": sha256_hex((repo_root / "tools/causal-flow-simulator/c03/corpus-source-map.json").read_bytes()),
            "sources": sorted(source_entries, key=lambda item: item["path"]),
        },
        "synthetic": True,
        "upstreamBytes": "none",
    }
    store(output / "manifest.json", manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    generate(args.repo_root.resolve(), args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
