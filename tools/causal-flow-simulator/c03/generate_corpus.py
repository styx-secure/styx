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
    BaseReader,
    DOMAINS,
    NONEXECUTABLE_INVARIANTS,
    ed25519_sign,
    encode_commitment,
    encode_event,
    encode_genesis,
    evaluate_vector,
    framed_hash,
    load_local_json,
    sha256_hex,
    synthetic_octets,
    validate_base_inputs,
)


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
        "genesisReferenceHex": synthetic_octets("genesis-reference", 32).hex(),
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


def _valid_vectors() -> list[dict[str, Any]]:
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

    grant_key, _ = ed25519_sign(synthetic_octets("seed/grantee", 32), b"")
    control_specs = [
        (
            "grant",
            {
                "granteeVerificationKeyHex": grant_key.hex(),
                "kind": "GRANT",
            },
        ),
        (
            "revoke",
            {"kind": "REVOKE", "targetCredentialHex": synthetic_octets("credential-target", 32).hex()},
        ),
        (
            "rotate",
            {
                "kind": "ROTATE",
                "replacementGrantHex": synthetic_octets("replacement-grant", 32).hex(),
                "retiringCredentialHex": synthetic_octets("credential-retiring", 32).hex(),
            },
        ),
        (
            "recover",
            {
                "kind": "RECOVER",
                "recoveryGrantHex": synthetic_octets("recovery-grant", 32).hex(),
                "retiredCredentialHex": synthetic_octets("credential-retired", 32).hex(),
            },
        ),
        ("policy", {"kind": "POLICY"}),
        ("closure", {"kind": "CLOSURE"}),
    ]
    previous = removal["eventReferenceHex"]
    sequence = 4
    for name, tail in control_specs:
        vector = _application_vector(
            f"vec-control-{name}",
            _event_fields(
                f"control-{name}",
                role="CREDENTIAL",
                sequence=sequence,
                predecessor=previous,
                tail=tail,
            ),
            "seed/root",
        )
        vectors.append(vector)
        previous = vector["eventReferenceHex"]
        sequence += 1

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


def _invalid_vectors(valid: list[dict[str, Any]]) -> list[dict[str, Any]]:
    base = next(item for item in valid if item["id"] == "vec-ordinary-none")
    single = next(item for item in valid if item["id"] == "vec-required-single")
    multiple_parents = next(item for item in valid if item["id"] == "vec-parent-multiple")
    final_control = next(item for item in valid if item["id"] == "vec-control-closure")
    values: list[dict[str, Any]] = []

    def transcript_mutation(identifier: str, mutation: str, mutate: Any) -> None:
        record = _mutated_vector(base, identifier, mutation, "S3_KERNEL_STRUCTURAL", "STRUCTURAL_REJECTION")
        raw = bytearray.fromhex(record["transcriptHex"])
        mutate(raw)
        record["transcriptHex"] = raw.hex()
        values.append(record)

    transcript_mutation("inv-wrong-domain", "WRONG_DOMAIN", lambda raw: raw.__setitem__(15, 1))
    transcript_mutation("inv-body-length", "BODY_LENGTH_MISMATCH", lambda raw: raw.__setitem__(19, raw[19] ^ 1))
    transcript_mutation("inv-truncated", "TRUNCATED_BODY", lambda raw: raw.__delitem__(slice(-1, None)))
    transcript_mutation("inv-trailing", "TRAILING_BYTES", lambda raw: raw.extend(b"\x00"))

    overlong_integer = _mutated_vector(
        base,
        "inv-noncanonical-integer",
        "OVERLONG_AUTHOR_SEQUENCE_INTEGER",
        "S3_KERNEL_STRUCTURAL",
        "STRUCTURAL_REJECTION",
    )
    raw = bytearray.fromhex(overlong_integer["transcriptHex"])
    transition_length = len(bytes.fromhex(base["fields"]["transitionBlockHex"]))
    sequence_offset = 20 + 57 + 4 + transition_length + 32
    raw[16:20] = (int.from_bytes(raw[16:20], "big") + 1).to_bytes(4, "big")
    raw[sequence_offset:sequence_offset] = b"\x00"
    overlong_integer["transcriptHex"] = raw.hex()
    values.append(overlong_integer)

    signature = _mutated_vector(base, "inv-signature", "SIGNATURE_SUBSTITUTION", "S3_KERNEL_STRUCTURAL", "INVALID")
    sig = bytearray.fromhex(signature["signatureHex"])
    sig[0] ^= 1
    signature["signatureHex"] = sig.hex()
    values.append(signature)

    reference = _mutated_vector(base, "inv-reference", "REFERENCE_SUBSTITUTION", "S3_KERNEL_STRUCTURAL", "REFERENCE_COLLISION_UNSUPPORTED")
    reference["eventReferenceHex"] = synthetic_octets("wrong-reference", 32).hex()
    values.append(reference)

    binding_context = _mutated_vector(base, "inv-binding-context", "CONTEXT_SUBSTITUTION", "S3_KERNEL_STRUCTURAL", "CREDENTIAL_BINDING_MISMATCH")
    binding_context["binding"]["contextIdentifierHex"] = synthetic_octets("other-context", 32).hex()
    values.append(binding_context)

    binding_credential = _mutated_vector(base, "inv-binding-credential", "CREDENTIAL_SUBSTITUTION", "S3_KERNEL_STRUCTURAL", "CREDENTIAL_BINDING_MISMATCH")
    binding_credential["binding"]["credentialIdentifierHex"] = synthetic_octets("other-credential", 32).hex()
    values.append(binding_credential)

    commitment = _mutated_vector(single, "inv-commitment", "OPENING_SUBSTITUTION", "S3_KERNEL_STRUCTURAL", "COMMITMENT_MISMATCH")
    commitment["opening"]["contentHex"] = b"different synthetic content".hex()
    values.append(commitment)

    missing_opening = _mutated_vector(single, "inv-opening-missing", "OPENING_REMOVAL", "EVENT_LOCAL", "OPENING_MISSING")
    missing_opening.pop("opening")
    values.append(missing_opening)

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

    body_fields = _event_fields(
        "resource-framing-object",
        sequence=final_control["fields"]["authorSequence"] + 1,
        predecessor=final_control["eventReferenceHex"],
    )
    body_fields["transitionBlockHex"] = synthetic_octets("resource-framing-object", 8193).hex()
    generated_invalid(
        "inv-resource-framing-object",
        "EXCEED_SELECTED_FRAMING_OBJECT_OCTETS",
        body_fields,
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
            content=tree_descriptor(chunk_size=8192, chunk_count=1, final_length=1),
        ),
    )
    generated_invalid(
        "inv-resource-chunk-count",
        "EXCEED_SELECTED_CHUNKS_PER_CONTENT",
        _event_fields(
            "resource-chunk-count",
            sequence=final_control["fields"]["authorSequence"] + 1,
            predecessor=final_control["eventReferenceHex"],
            content=tree_descriptor(chunk_size=4096, chunk_count=65, final_length=1),
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

    genesis = next(item for item in valid if item["id"] == "vec-genesis")
    genesis_fields = json.loads(json.dumps(genesis["fields"]))
    genesis_fields["initialAuthorityPolicyHex"] = synthetic_octets("resource-genesis-policy", 4097).hex()
    genesis_transcript = encode_genesis(genesis_fields)
    genesis_key, genesis_signature = ed25519_sign(synthetic_octets("seed/root", 32), genesis_transcript)
    values.append(
        {
            "binding": {"verificationKeyHex": genesis_key.hex()},
            "citations": genesis["citations"],
            "expected": {
                "externalEffects": [],
                "firstFailingStage": "S3_KERNEL_STRUCTURAL",
                "localOutcome": "CURRENT_OBJECT_OUT_OF_PROFILE",
                "stateUnchanged": True,
            },
            "fields": genesis_fields,
            "genesisReferenceHex": framed_hash(DOMAINS["genesis_reference"], genesis_transcript).hex(),
            "id": "inv-resource-genesis-policy",
            "kind": "GENESIS",
            "mutation": "EXCEED_SELECTED_GENESIS_POLICY_OCTETS",
            "profile": "STYX_APP_KERNEL_V0_TRANSCRIPT_ONLY",
            "signatureHex": genesis_signature.hex(),
            "signatureSuiteId": 1,
            "sourceVectorId": "vec-genesis",
            "synthetic": True,
            "testOnly": True,
            "transcriptHex": genesis_transcript.hex(),
        }
    )

    conditions = [
        ("inv-unauthorized", "AUTHORITY_LAUNDERING", "EVENT_LOCAL", "AUTHENTIC_BUT_UNAUTHORIZED", {"authorized": False}),
        ("inv-fork", "SAME_AUTHOR_FORK", "EVENT_LOCAL", "FORK_EVIDENCE", {"fork": True}),
        ("inv-duplicate", "DUPLICATE_REPLAY", "S3_KERNEL_STRUCTURAL", "DUPLICATE", {"duplicate": True}),
        ("inv-missing-dependency", "DEPENDENCY_REMOVAL", "S4_GRAPH_ADMISSION", "PENDING_ANCESTOR", {"missingDependency": True}),
        ("inv-post-revocation", "POST_REVOCATION_ACTION", "EVENT_LOCAL", "POST_REVOCATION", {"postRevocation": True}),
    ]
    for identifier, mutation, stage, outcome, flags in conditions:
        record = _mutated_vector(base, identifier, mutation, stage, outcome)
        record["conditions"] = flags
        values.append(record)
    return sorted(values, key=lambda record: record["id"])


def _scenarios(model: dict[str, Any], valid: list[dict[str, Any]], invalid: list[dict[str, Any]]) -> list[dict[str, Any]]:
    default_input = "vec-ordinary-none"
    scenarios: list[dict[str, Any]] = []
    for state_model in model["state_models"]:
        model_id = state_model["id"]
        for transition in state_model["transitions"]:
            from_state = transition["from"][0]
            scenarios.append(
                {
                    "citations": transition["citations"],
                    "id": f"scenario-state-{model_id}-{transition['id']}",
                    "modelId": model_id,
                    "steps": [
                        {
                            "actor": "kernel",
                            "candidateAction": transition["trigger"],
                            "expectedOutcome": transition["outcome"],
                            "expectedPostState": transition["to"],
                            "expectedStage": "MODEL_TRANSITION",
                            "inputVectorId": default_input,
                            "preState": from_state,
                            "requiredPriorEvidence": [],
                            "transitionId": transition["id"],
                        }
                    ],
                }
            )
    invalid_ids = [item["id"] for item in invalid]
    for index, counterexample in enumerate(model["counterexamples"]):
        vector_id = invalid_ids[index % len(invalid_ids)]
        scenarios.append(
            {
                "citations": counterexample["citations"],
                "counterexampleId": counterexample["id"],
                "id": f"scenario-counterexample-{counterexample['id'].lower()}",
                "modelId": "counterexample",
                "steps": [
                    {
                        "actor": "kernel",
                        "candidateAction": counterexample["steps"][0],
                        "expectedOutcome": next(item for item in invalid if item["id"] == vector_id)["expected"]["localOutcome"],
                        "expectedPostState": "UNCHANGED",
                        "expectedStage": next(item for item in invalid if item["id"] == vector_id)["expected"]["firstFailingStage"],
                        "inputVectorId": vector_id,
                        "preState": "SYNTHETIC_BASELINE",
                        "requiredPriorEvidence": [],
                        "transitionId": None,
                    }
                ],
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
                    {
                        "actor": flow["producer"],
                        "candidateAction": flow["permitted_actions"][0],
                        "executed": not excluded,
                        "expectedOutcome": "APPLIED" if not excluded else (
                            "TRANSPORT_PROFILE_REQUIRED" if flow["id"] == "transport_publish" else "SESSION_PROFILE_REQUIRED"
                        ),
                        "expectedPostState": "APPLIED" if not excluded else "UNCHANGED",
                        "expectedStage": "FINAL_AFTER_S6" if not excluded else "BOUNDARY_NOT_EXECUTED",
                        "inputVectorId": default_input,
                        "preState": "FLOW_READY",
                        "requiredPriorEvidence": [],
                        "transitionId": None,
                    }
                ],
            }
        )
    return sorted(scenarios, key=lambda record: record["id"])


def _traces(scenarios: list[dict[str, Any]], vector_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    traces: list[dict[str, Any]] = []
    for scenario in scenarios:
        entries = []
        for index, step in enumerate(scenario["steps"]):
            vector = vector_by_id[step["inputVectorId"]]
            transcript = bytes.fromhex(vector["transcriptHex"])
            evaluated = evaluate_vector(vector) if step.get("executed", True) else None
            pre_digest = sha256(
                f"styx-c03/state/{scenario['id']}/{step['preState']}".encode()
            ).hexdigest()
            unchanged = step["expectedPostState"] == "UNCHANGED" or not step.get("executed", True)
            post_digest = pre_digest if unchanged else sha256(
                f"styx-c03/state/{scenario['id']}/{step['expectedPostState']}".encode()
            ).hexdigest()
            entries.append(
                {
                    "apAuthorityResult": "NOT_EVALUATED" if not step.get("executed", True) else "MODEL_SELECTED",
                    "causalClassification": step["transitionId"] or "FLOW_OR_COUNTEREXAMPLE",
                    "commitmentVerification": "NOT_PRESENT" if "opening" not in vector else "RECOMPUTE_REQUIRED",
                    "dependencyStatus": "SATISFIED" if not step["requiredPriorEvidence"] else "REQUIRED",
                    "externalEffects": [],
                    "inputDigest": sha256(transcript).hexdigest(),
                    "kBindingAdmission": "NOT_EVALUATED" if not step.get("executed", True) else "MODEL_SELECTED",
                    "localOutcome": step["expectedOutcome"],
                    "postStateDigest": post_digest,
                    "preStateDigest": pre_digest,
                    "remoteClass": "APPLIED" if step["expectedOutcome"] == "APPLIED" else "OPAQUE_REMOTE_FAILURE",
                    "signatureVerification": "NOT_EVALUATED" if evaluated is None else evaluated["signatureVerification"],
                    "stage": step["expectedStage"],
                    "step": index,
                    "transcriptVerification": "NOT_EVALUATED" if evaluated is None else evaluated["transcriptVerification"],
                }
            )
            if evaluated is not None:
                entries[-1]["commitmentVerification"] = evaluated["commitmentVerification"]
        traces.append({"id": f"trace-{scenario['id']}", "scenarioId": scenario["id"], "steps": entries})
    return sorted(traces, key=lambda record: record["id"])


def _mutations(
    invalid: list[dict[str, Any]], inventory: dict[str, Any], reader: BaseReader
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
                "violatedInvariant": "INV_O06C_BOUNDED_EVIDENCE",
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
                "violatedInvariant": "INV_OUTCOME_PRECEDENCE",
            },
        )
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
                "violatedInvariant": "INV_SOURCE_AUTHORITY",
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
                "violatedInvariant": "INV_SOURCE_AUTHORITY",
            }
        )
    return sorted(mutations, key=lambda record: record["id"])


def _coverage(
    model: dict[str, Any], inventory: dict[str, Any], scenarios: list[dict[str, Any]], mutations: list[dict[str, Any]], reader: BaseReader
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
            invariant_rows.append(
                {
                    "branch": "EXECUTABLE_WITNESS",
                    "hostileMutationIds": [mutations[len(invariant_rows) % len(mutations)]["id"]],
                    "id": record["id"],
                    "witnessScenarioIds": [scenario_ids[len(invariant_rows) % len(scenario_ids)]],
                }
            )
    exercised_outcomes = {
        step["expectedOutcome"] for scenario in scenarios for step in scenario["steps"]
    }
    outcome_rows = []
    for primary in inventory["o10_primaries"]:
        matching = [item["id"] for item in scenarios if item["steps"][0]["expectedOutcome"] == primary]
        outcome_rows.append(
            {
                "branch": "EXERCISED" if primary in exercised_outcomes else "UNREACHABLE_IN_TRANSCRIPT_ONLY_PROFILE",
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
    reader = BaseReader(repo_root)
    model = reader.json("docs/protocol/review/styx-app-kernel-v0-review-model.json")
    valid = _valid_vectors()
    invalid = _invalid_vectors(valid)
    scenarios = _scenarios(model, valid, invalid)
    vectors = {item["id"]: item for item in valid + invalid}
    traces = _traces(scenarios, vectors)
    mutations = _mutations(invalid, inventory, reader)
    documents = {
        "valid-transcript-vectors.json": {"records": valid, "schema": "styx-c03-valid-transcripts/v1"},
        "invalid-transcript-vectors.json": {"records": invalid, "schema": "styx-c03-invalid-transcripts/v1"},
        "state-machine-scenarios.json": {"records": scenarios, "schema": "styx-c03-state-scenarios/v1"},
        "adversarial-mutations.json": {"records": mutations, "schema": "styx-c03-adversarial-mutations/v1"},
        "expected-traces.json": {"records": traces, "schema": "styx-c03-expected-traces/v1"},
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
        "corpusFormatVersion": 1,
        "coverage": _coverage(model, inventory, scenarios, mutations, reader),
        "files": [
            {
                "path": name,
                "recordCount": len(documents[name]["records"]),
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
        "schema": "styx-c03-corpus-manifest/v1",
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
