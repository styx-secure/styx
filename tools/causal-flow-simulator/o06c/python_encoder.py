#!/usr/bin/env python3
"""Derive canonical O-06c vectors from semantic inputs using the Python model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

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
    DOMAINS,
    ROLE_CREDENTIAL,
    ROLE_ORDINARY,
    ROLE_REMOVAL,
    CommitmentContext,
    ContentDescriptor,
    CredentialTail,
    EventAssignment,
    ModelError,
    RemovalTail,
    build_commitment,
    descriptor_from_commitment,
    encode_content_descriptor,
    encode_event_transcript,
    event_reference,
    u32,
)


ROLE = {"ordinary": ROLE_ORDINARY, "removal": ROLE_REMOVAL, "credential": ROLE_CREDENTIAL}
CONTENT = {"none": CONTENT_NONE, "required": CONTENT_REQUIRED, "detachable": CONTENT_DETACHABLE}
CONTROL = {
    "grant": CONTROL_GRANT,
    "revoke": CONTROL_REVOKE,
    "rotate": CONTROL_ROTATE,
    "recover": CONTROL_RECOVER,
    "policy": CONTROL_POLICY,
    "closure": CONTROL_CLOSURE,
}


def octets(value: str, label: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise ModelError(f"{label} must be even-length hexadecimal")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ModelError(f"{label} is not hexadecimal") from exc


def resolve_credential(spec: object, references: dict[str, bytes]) -> bytes:
    if not isinstance(spec, dict) or len(spec) != 1:
        raise ModelError("credential selector must have exactly one arm")
    if "literal" in spec:
        return octets(spec["literal"], "literal credential")
    if "grant_reference" in spec and spec["grant_reference"] in references:
        return references[spec["grant_reference"]]
    raise ModelError("unresolved credential selector")


def content_for(
    raw: dict[str, object], context: CommitmentContext
) -> tuple[ContentDescriptor, dict[str, object] | None]:
    content_class = CONTENT.get(raw.get("class"))
    if content_class is None:
        raise ModelError("unknown semantic content class")
    if content_class == CONTENT_NONE:
        if set(raw) != {"class"}:
            raise ModelError("semantic NONE has unexpected fields")
        return ContentDescriptor(CONTENT_NONE, 0), None
    content = octets(raw["content"], "content")
    randomizer = octets(raw["randomizer"], "randomizer")
    shape = raw.get("shape")
    chunk_size = None if shape == "single" else raw.get("chunk_size")
    if shape not in ("single", "tree") or (shape == "tree" and not isinstance(chunk_size, int)):
        raise ModelError("invalid semantic commitment shape")
    commitment = build_commitment(
        context,
        int(raw["content_type_id"]),
        content,
        randomizer,
        chunk_size=chunk_size,
    )
    descriptor = descriptor_from_commitment(content_class, commitment)
    derived = {
        "context": context.encode().hex(),
        "content": content.hex(),
        "randomizer": randomizer.hex(),
        "leaf_preimages": [value.hex() for value in commitment.leaf_preimages],
        "leaf_digests": [value.hex() for value in commitment.leaf_digests],
        "node_preimages": [value.hex() for value in commitment.node_preimages],
        "root": commitment.root.hex(),
        "commitment_preimage": commitment.commitment_preimage.hex(),
        "commitment_value": commitment.commitment_value.hex(),
        "geometry": (
            None
            if commitment.geometry is None
            else {
                "chunk_size": commitment.geometry.chunk_size,
                "chunk_count": commitment.geometry.chunk_count,
                "final_chunk_length": commitment.geometry.final_chunk_length,
            }
        ),
    }
    return descriptor, derived


def tail_for(raw: dict[str, object], role: int) -> CredentialTail | RemovalTail | None:
    tail = raw.get("tail")
    if role == ROLE_ORDINARY:
        if tail is not None:
            raise ModelError("ordinary semantic event has a tail")
        return None
    if not isinstance(tail, dict):
        raise ModelError("control semantic event lacks a tail")
    if role == ROLE_REMOVAL:
        return RemovalTail(
            octets(tail["target_event_reference"], "target event"),
            octets(tail["target_commitment"], "target commitment"),
        )
    kind = CONTROL.get(tail.get("control_kind"))
    if kind is None:
        raise ModelError("unknown semantic control kind")
    values = {"control_kind": kind}
    for name in (
        "grantee_verification_key",
        "target_credential_id",
        "retiring_credential_id",
        "replacement_grant_reference",
        "retired_credential_id",
        "recovery_grant_reference",
    ):
        if name in tail:
            values[name] = octets(tail[name], name)
    if "grantee_suite_id" in tail:
        values["grantee_suite_id"] = int(tail["grantee_suite_id"])
    return CredentialTail(**values)


def derive_event(raw: dict[str, object], references: dict[str, bytes]) -> dict[str, object]:
    role = ROLE.get(raw.get("event_role"))
    if role is None:
        raise ModelError("unknown semantic event role")
    credential = resolve_credential(raw["credential_identifier"], references)
    context = CommitmentContext(
        int(raw["application_profile_id"]),
        int(raw["application_profile_version"]),
        octets(raw["context_identifier"], "context identifier"),
        credential,
        int(raw["author_sequence"]),
    )
    descriptor, commitment = content_for(raw["content"], context)
    event = EventAssignment(
        application_profile_id=context.application_profile_id,
        application_profile_version=context.application_profile_version,
        context_identifier=context.context_identifier,
        event_role=role,
        event_type_id=int(raw["event_type_id"]),
        schema_id=int(raw["schema_id"]),
        schema_version=int(raw["schema_version"]),
        transition_block=octets(raw["transition_block"], "transition block"),
        credential_identifier=credential,
        author_sequence=context.author_sequence,
        direct_predecessor=(
            None
            if raw["direct_predecessor"] is None
            else octets(raw["direct_predecessor"], "direct predecessor")
        ),
        causal_parents=tuple(octets(value, "causal parent") for value in raw["causal_parents"]),
        genesis_reference=octets(raw["genesis_reference"], "genesis reference"),
        content=descriptor,
        tail=tail_for(raw, role),
    )
    transcript = encode_event_transcript(event)
    reference_preimage = DOMAINS["event_reference"] + u32(len(transcript)) + transcript
    return {
        "id": raw["id"],
        "credential_identifier": credential.hex(),
        "content_descriptor": encode_content_descriptor(descriptor).hex(),
        "transcript": transcript.hex(),
        "reference_preimage": reference_preimage.hex(),
        "event_reference": event_reference(event).hex(),
        "commitment": commitment,
    }


def derive_registry(registry: dict[str, object]) -> dict[str, object]:
    if registry.get("format") != "styx-o06c-semantic-input-v1":
        raise ModelError("unknown semantic registry format")
    references: dict[str, bytes] = {}
    outputs = []
    for raw in registry.get("grants", []):
        result = derive_event(raw, references)
        references[str(raw["id"])] = bytes.fromhex(result["event_reference"])
        outputs.append(result)
    for raw in registry.get("cases", []):
        outputs.append(derive_event(raw, references))
    return {"format": "styx-o06c-derived-v1", "events": outputs}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    registry = json.loads(Path(args.input).read_text(encoding="utf-8"))
    result = derive_registry(registry)
    Path(args.output).write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
