#!/usr/bin/env python3
"""Build and verify the oracle-free C0.3 clean-room projection.

This is conformance evidence.  It deliberately keeps corpus identifiers,
expected dispositions and repository revision identities outside the public
reader kit.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from canonical_json import dumps, load, loads, store  # noqa: E402
from corpus_model import (  # noqa: E402
    CorpusModelError,
    evaluate_vector,
    parse_event,
    semantic_input_digest,
)


class BlindProjectionError(CorpusModelError):
    """The public kit, reader freeze or withheld integration is invalid."""


KIT_SCHEMA = "styx-c03-blind-kit/v1"
INPUT_SCHEMA = "styx-c03-blind-input/v1"
FREEZE_SCHEMA = "styx-c03-reader-freeze/v1"
INTEGRATION_SCHEMA = "styx-c03-blind-integration/v1"

SOURCE_PATHS = (
    "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
    "docs/protocol/styx-app-kernel-v0-decisions.md",
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
    "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
    "docs/security/STYX-THREAT-MODEL.md",
    "tools/causal-flow-simulator/o08/resource-envelope.candidate.json",
    "tools/causal-flow-simulator/o10/outcome-taxonomy.json",
    "tools/causal-flow-simulator/o10/source-inventory.json",
)
ROOT_FILES = (
    "README.md",
    "KIT-MANIFEST.json",
    "SHA256SUMS.txt",
    "SOURCE_SHA256SUMS.txt",
    "TOOLCHAIN.md",
    "VERIFY.py",
    "blind-input.json",
    "blind-input.schema.json",
)
KIT_PATHS = frozenset(ROOT_FILES + tuple(f"sources/{path}" for path in SOURCE_PATHS))
BLIND_ENVELOPE_DIMENSIONS = frozenset(
    {
        "AP_TRANSITION_BLOCK_OCTETS",
        "CHECKPOINT_REFERENCES",
        "CHUNKS_PER_CONTENT",
        "CHUNK_OCTETS",
        "CONTENT_EXACT_OCTETS",
        "FRAMING_OBJECT_OCTETS",
        "GENESIS_BODY_OCTETS",
        "GENESIS_POLICY_OCTETS",
        "PARENTS_PER_EVENT",
        "SEQUENCE_VALUE",
        "SIGNATURE_ATTEMPTS",
    }
)
PUBLIC_OBSERVATION_FIELDS = (
    "apAuthorityResult",
    "commitmentVerification",
    "kBindingAdmission",
    "localOutcomePresent",
    "outcomeEvaluated",
    "referenceVerification",
    "remoteClassPresent",
    "signatureVerification",
    "stage",
    "transcriptVerification",
)
FORBIDDEN_KEY_PARTS = frozenset(
    {
        "action",
        "base",
        "candidate",
        "diff",
        "evaluator",
        "expected",
        "head",
        "official",
        "outcome",
        "repository",
        "scenario",
        "stage",
        "trace",
        "transition",
        "tree",
        "vector",
    }
)
FORBIDDEN_VALUE = re.compile(r"(?:^|[^A-Za-z0-9])(?:vec|inv|scenario|trace)-", re.IGNORECASE)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BlindProjectionError(message)


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _regular_files(root: Path) -> dict[str, Path]:
    require(root.is_dir() and not root.is_symlink(), f"not a regular directory: {root}")
    result: dict[str, Path] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        require(not path.is_symlink(), f"symlink forbidden: {relative}")
        if path.is_dir():
            continue
        require(path.is_file(), f"non-regular path: {relative}")
        require(relative not in result, f"duplicate path: {relative}")
        result[relative] = path
    return result


def _parse_sums(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise BlindProjectionError("checksum file is not ASCII") from error
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/].*)", line)
        require(match is not None, f"invalid checksum line: {line!r}")
        digest, name = match.groups()
        require("/../" not in f"/{name}/" and not name.endswith("/.."), "unsafe checksum path")
        require(name not in result, f"duplicate checksum path: {name}")
        result[name] = digest
    return result


def _sums(entries: Iterable[tuple[str, bytes]]) -> bytes:
    return "".join(f"{_sha(data)}  {name}\n" for name, data in sorted(entries)).encode("ascii")


def _hex(value: Any, octets: int | None, name: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    require(isinstance(value, str), f"{name} is not a hex string")
    require(re.fullmatch(r"[0-9a-f]*", value) is not None, f"{name} is not lowercase hex")
    require(len(value) % 2 == 0, f"{name} has odd hex length")
    if octets is not None:
        require(len(value) == octets * 2, f"{name} has wrong length")


def _credential_bindings(record: dict[str, Any]) -> list[dict[str, str]]:
    if record["kind"] == "GENESIS":
        return []
    fields = record["fields"]
    binding = record["binding"]
    admission = record.get("admissionContext", {})
    if admission.get("credentialBindingMatchCount") == 0:
        return []
    ordinary = {
        "canonicalGrantPreimageHex": sha256(
            b"styx-c03/blind/admitted-grant/" + bytes.fromhex(fields["credentialIdentifierHex"])
        ).hexdigest(),
        "contextIdentifierHex": fields["contextIdentifierHex"],
        "credentialIdentifierHex": fields["credentialIdentifierHex"],
        "grantReferenceHex": fields["credentialIdentifierHex"],
        "verificationKeyHex": binding["verificationKeyHex"],
    }
    if admission.get("credentialIdentifierCollision") is not True:
        return [ordinary]
    collision = dict(ordinary)
    collision["canonicalGrantPreimageHex"] = sha256(
        b"styx-c03/blind/colliding-grant/" + bytes.fromhex(fields["credentialIdentifierHex"])
    ).hexdigest()
    return [ordinary, collision]


def _dependencies(record: dict[str, Any]) -> list[str]:
    if record["kind"] != "APPLICATION_EVENT":
        return []
    fields = record["fields"]
    values = set(fields.get("causalParents", []))
    predecessor = fields.get("directPredecessorHex")
    if predecessor is not None:
        values.add(predecessor)
    admission = record.get("admissionContext", {})
    if "availableDependencyReferences" in admission:
        values = set(admission["availableDependencyReferences"])
    return sorted(values)


def _opening_records(record: dict[str, Any]) -> list[dict[str, str]]:
    opening = record.get("opening")
    if opening is None:
        return []
    reference = record.get("eventReferenceHex")
    require(isinstance(reference, str), "opening belongs to a non-event")
    return [
        {
            "contentHex": opening["contentHex"],
            "eventReferenceHex": reference,
            "randomizerHex": opening["randomizerHex"],
        }
    ]


def _project_record(record: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    fields = record["fields"]
    admission = record.get("admissionContext", {})
    presented_reference = record.get("eventReferenceHex", record.get("genesisReferenceHex"))
    require(isinstance(presented_reference, str), "record has no presented reference")
    projected = {
        "acceptedGenesisReferenceHex": admission.get("acceptedGenesisReferenceHex"),
        "admittedCredentialBindings": _credential_bindings(record),
        "admittedEventReferences": _dependencies(record),
        "checkpointEvidenceReferences": sorted(admission.get("checkpointEvidenceReferences", [])),
        "claimedBinding": {
            key: record["binding"][key]
            for key in ("contextIdentifierHex", "credentialIdentifierHex")
            if key in record["binding"]
        },
        "kind": record["kind"],
        "knownPendingOpeningRoots": sorted(admission.get("knownPendingOpeningRoots", [])),
        "localGenesisAccepted": bool(admission.get("localGenesisAccepted", False)),
        "pendingOpeningDescendantReferences": sorted(admission.get("pendingOpeningDescendantReferences", [])),
        "presentedReferenceHex": presented_reference,
        "profile": {
            "applicationProfileId": fields["applicationProfileId"],
            "applicationProfileVersion": fields["applicationProfileVersion"],
            "commitmentSuiteId": 1,
            "signatureSuiteId": record["signatureSuiteId"],
            "styxProtocolVersion": 1,
        },
        "sameAuthorSequenceReferences": sorted(admission.get("sameAuthorSequenceReferences", [])),
        "seenEventReferences": sorted(admission.get("seenEventReferences", [])),
        "signatureHex": record["signatureHex"],
        "transcriptHex": record["transcriptHex"],
        "verificationKeyHex": record["binding"]["verificationKeyHex"],
        "verifiedOpenings": _opening_records(record),
    }
    opaque_id = f"case-{_sha(dumps(projected))}"
    return opaque_id, {"opaqueId": opaque_id, **projected}


def materialize_blind_evaluator_input(record: dict[str, Any]) -> dict[str, Any]:
    """Recreate evaluator inputs using only public, replica-owned fields.

    This helper is a projection-completeness check, not independent evidence.
    The counted clean-room reader must still be authored after the kit freezes.
    """

    _validate_record(record)
    materialized: dict[str, Any] = {
        "binding": {"verificationKeyHex": record["verificationKeyHex"], **record["claimedBinding"]},
        "kind": record["kind"],
        "signatureHex": record["signatureHex"],
        "transcriptHex": record["transcriptHex"],
    }
    reference_key = "genesisReferenceHex" if record["kind"] == "GENESIS" else "eventReferenceHex"
    materialized[reference_key] = record["presentedReferenceHex"]
    opening = next(
        (
            value
            for value in record["verifiedOpenings"]
            if value["eventReferenceHex"] == record["presentedReferenceHex"]
        ),
        None,
    )
    if opening is not None:
        materialized["opening"] = {
            "contentHex": opening["contentHex"],
            "randomizerHex": opening["randomizerHex"],
        }
    admission = {
        "availableDependencyReferences": record["admittedEventReferences"],
        "checkpointEvidenceReferences": record["checkpointEvidenceReferences"],
        "knownPendingOpeningRoots": record["knownPendingOpeningRoots"],
        "pendingOpeningDescendantReferences": record["pendingOpeningDescendantReferences"],
        "sameAuthorSequenceReferences": record["sameAuthorSequenceReferences"],
        "seenEventReferences": record["seenEventReferences"],
    }
    if record["kind"] == "APPLICATION_EVENT":
        try:
            fields = parse_event(bytes.fromhex(record["transcriptHex"]))
        except CorpusModelError:
            # Admission data is not consulted when framing already fails.  It
            # remains present in the kit but cannot become a hidden oracle.
            fields = None
        if fields is not None:
            matching = [
                binding
                for binding in record["admittedCredentialBindings"]
                if binding["contextIdentifierHex"] == fields["contextIdentifierHex"]
                and binding["credentialIdentifierHex"] == fields["credentialIdentifierHex"]
                and binding["verificationKeyHex"] == record["verificationKeyHex"]
            ]
            identifiers: dict[str, set[str]] = {}
            for binding in record["admittedCredentialBindings"]:
                identifiers.setdefault(binding["credentialIdentifierHex"], set()).add(
                    binding["canonicalGrantPreimageHex"]
                )
            admission["credentialBindingMatchCount"] = len(matching)
            admission["credentialIdentifierCollision"] = any(
                len(preimages) > 1 for preimages in identifiers.values()
            )
    materialized["admissionContext"] = admission
    return materialized


def _input_schema() -> dict[str, Any]:
    hex_string = {"pattern": "^[0-9a-f]*$", "type": "string"}
    ref = {"maxLength": 64, "minLength": 64, **hex_string}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {
            "records": {
                "items": {
                    "additionalProperties": False,
                    "properties": {
                        "acceptedGenesisReferenceHex": {"anyOf": [ref, {"type": "null"}]},
                        "admittedCredentialBindings": {"items": {"type": "object"}, "type": "array"},
                        "admittedEventReferences": {"items": ref, "type": "array"},
                        "checkpointEvidenceReferences": {"items": ref, "type": "array"},
                        "claimedBinding": {"type": "object"},
                        "kind": {"enum": ["APPLICATION_EVENT", "GENESIS"]},
                        "knownPendingOpeningRoots": {"items": ref, "type": "array"},
                        "localGenesisAccepted": {"type": "boolean"},
                        "opaqueId": {"pattern": "^case-[0-9a-f]{64}$", "type": "string"},
                        "pendingOpeningDescendantReferences": {"items": ref, "type": "array"},
                        "presentedReferenceHex": ref,
                        "profile": {"type": "object"},
                        "sameAuthorSequenceReferences": {"items": ref, "type": "array"},
                        "seenEventReferences": {"items": ref, "type": "array"},
                        "signatureHex": hex_string,
                        "transcriptHex": hex_string,
                        "verificationKeyHex": ref,
                        "verifiedOpenings": {"items": {"type": "object"}, "type": "array"},
                    },
                    "required": [
                        "acceptedGenesisReferenceHex", "admittedCredentialBindings",
                        "admittedEventReferences", "checkpointEvidenceReferences", "claimedBinding", "kind",
                        "knownPendingOpeningRoots", "localGenesisAccepted", "opaqueId",
                        "pendingOpeningDescendantReferences", "presentedReferenceHex", "profile",
                        "sameAuthorSequenceReferences", "seenEventReferences", "signatureHex",
                        "transcriptHex", "verificationKeyHex", "verifiedOpenings",
                    ],
                    "type": "object",
                },
                "maxItems": 43,
                "minItems": 43,
                "type": "array",
            },
            "schema": {"const": INPUT_SCHEMA},
            "selectedEnvelope": {"type": "object"},
        },
        "required": ["records", "schema", "selectedEnvelope"],
        "title": "Styx C0.3 oracle-free clean-room input",
        "type": "object",
    }


def _verify_script() -> bytes:
    return b'''#!/usr/bin/env python3
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parent
expected = set(json.loads((root / "KIT-MANIFEST.json").read_text())["paths"])
actual = set()
for path in root.rglob("*"):
    if path.is_symlink():
        raise SystemExit(f"symlink forbidden: {path}")
    if path.is_file():
        actual.add(path.relative_to(root).as_posix())
if actual != expected:
    raise SystemExit("kit path set mismatch")
sums = {}
for line in (root / "SHA256SUMS.txt").read_text("ascii").splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
    if not match or match.group(2) in sums:
        raise SystemExit("invalid checksum manifest")
    sums[match.group(2)] = match.group(1)
if set(sums) != expected - {"SHA256SUMS.txt"}:
    raise SystemExit("checksum path set mismatch")
for name, digest in sums.items():
    if sha256((root / name).read_bytes()).hexdigest() != digest:
        raise SystemExit(f"checksum mismatch: {name}")
document = json.loads((root / "blind-input.json").read_text("utf-8"))
if document.get("schema") != "styx-c03-blind-input/v1" or len(document.get("records", [])) != 43:
    raise SystemExit("blind input cardinality mismatch")
ids = [record.get("opaqueId") for record in document["records"]]
if ids != sorted(set(ids)) or not all(re.fullmatch(r"case-[0-9a-f]{64}", value or "") for value in ids):
    raise SystemExit("opaque identifier mismatch")
print("STYX_C03_BLIND_KIT_OK records=43")
'''


def _readme() -> bytes:
    return b"""# Styx C0.3 blind K-surface kit

This deterministic package contains raw transcript candidates and only the
replica-owned inputs enumerated by the ratified C0.3 contract.  It contains no
expected result, stage, transition, corpus identifier, repository revision or
integration mapping.

Implement a fresh reader that accepts `--input <file> --output <file>`.  For
each opaque record it must parse the transcript, recompute the presented
reference, verify the signature, verify any supplied opening and classify the
K admission at its exact primary/stage.  Application-policy authority is out of
scope: K admission is not AP authorization and must never be flattened to an
application success.

Run `python3 VERIFY.py` before using the package.  The withheld integration map
is created only after the reader source has been frozen.
"""


def _toolchain() -> bytes:
    return b"""# Reader toolchain contract

The reader may use any deterministic implementation language and standard or
documented cryptographic library.  It must expose exactly:

    reader --input <file> --output <file>

The output is canonical UTF-8 JSON with one final LF and no timestamps,
hostnames, paths, process identifiers or environment-derived ordering.
"""


def _scan_value(value: Any, location: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = re.sub(r"[^a-z]", "", key.lower())
            require(not any(part in lowered for part in FORBIDDEN_KEY_PARTS), f"forbidden key at {location}.{key}")
            _scan_value(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_value(child, f"{location}[{index}]")
    elif isinstance(value, str):
        require(FORBIDDEN_VALUE.search(value) is None, f"forbidden value at {location}")
        if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", value):
            try:
                decoded = bytes.fromhex(value).decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                return
            require(FORBIDDEN_VALUE.search(decoded) is None, f"hex-encoded forbidden value at {location}")


def _validate_record(record: dict[str, Any]) -> None:
    required = {
        "acceptedGenesisReferenceHex", "admittedCredentialBindings", "admittedEventReferences",
        "checkpointEvidenceReferences", "claimedBinding", "kind", "knownPendingOpeningRoots",
        "localGenesisAccepted", "opaqueId", "pendingOpeningDescendantReferences",
        "presentedReferenceHex", "profile", "sameAuthorSequenceReferences",
        "seenEventReferences", "signatureHex", "transcriptHex", "verificationKeyHex",
        "verifiedOpenings",
    }
    require(set(record) == required, f"blind record shape mismatch: {set(record) ^ required}")
    require(re.fullmatch(r"case-[0-9a-f]{64}", record["opaqueId"]) is not None, "invalid opaque id")
    require(record["kind"] in {"APPLICATION_EVENT", "GENESIS"}, "invalid object kind")
    _hex(record["presentedReferenceHex"], 32, "presentedReferenceHex")
    _hex(record["verificationKeyHex"], 32, "verificationKeyHex")
    _hex(record["signatureHex"], 64, "signatureHex")
    _hex(record["transcriptHex"], None, "transcriptHex")
    _hex(record["acceptedGenesisReferenceHex"], 32, "acceptedGenesisReferenceHex", nullable=True)
    claimed_binding = record["claimedBinding"]
    require(
        set(claimed_binding) in (set(), {"contextIdentifierHex", "credentialIdentifierHex"}),
        "claimed binding shape mismatch",
    )
    for name, value in claimed_binding.items():
        _hex(value, 32, f"claimedBinding.{name}")
    for name in (
        "admittedEventReferences", "checkpointEvidenceReferences", "knownPendingOpeningRoots",
        "pendingOpeningDescendantReferences", "sameAuthorSequenceReferences", "seenEventReferences",
    ):
        require(isinstance(record[name], list) and record[name] == sorted(set(record[name])), f"non-canonical set: {name}")
        for value in record[name]:
            _hex(value, 32, name)
    bindings = record["admittedCredentialBindings"]
    require(isinstance(bindings, list), "credential bindings are not a list")
    for binding in bindings:
        require(set(binding) == {"canonicalGrantPreimageHex", "contextIdentifierHex", "credentialIdentifierHex", "grantReferenceHex", "verificationKeyHex"}, "credential binding shape mismatch")
        for name in binding:
            _hex(binding[name], 32, f"binding.{name}")
    openings = record["verifiedOpenings"]
    require(isinstance(openings, list), "verified openings are not a list")
    for opening in openings:
        require(set(opening) == {"contentHex", "eventReferenceHex", "randomizerHex"}, "opening shape mismatch")
        _hex(opening["eventReferenceHex"], 32, "opening.eventReferenceHex")
        _hex(opening["randomizerHex"], 32, "opening.randomizerHex")
        _hex(opening["contentHex"], None, "opening.contentHex")
    profile = record["profile"]
    require(set(profile) == {"applicationProfileId", "applicationProfileVersion", "commitmentSuiteId", "signatureSuiteId", "styxProtocolVersion"}, "profile shape mismatch")
    require(all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in profile.values()), "profile value mismatch")
    projected = dict(record)
    projected.pop("opaqueId")
    require(record["opaqueId"] == f"case-{_sha(dumps(projected))}", "opaque id is not input-derived")


def validate_kit(kit: Path) -> dict[str, Any]:
    files = _regular_files(kit)
    require(set(files) == KIT_PATHS, f"kit path set mismatch: {sorted(set(files) ^ KIT_PATHS)}")
    manifest = load(files["KIT-MANIFEST.json"])
    require(manifest.get("schema") == KIT_SCHEMA, "kit schema mismatch")
    require(manifest.get("paths") == sorted(KIT_PATHS), "kit manifest path set mismatch")
    sums = _parse_sums(files["SHA256SUMS.txt"].read_bytes())
    require(set(sums) == KIT_PATHS - {"SHA256SUMS.txt"}, "kit checksum path set mismatch")
    for name, digest in sums.items():
        require(_sha(files[name].read_bytes()) == digest, f"kit checksum mismatch: {name}")
    source_sums = _parse_sums(files["SOURCE_SHA256SUMS.txt"].read_bytes())
    expected_sources = {f"sources/{path}" for path in SOURCE_PATHS}
    require(set(source_sums) == expected_sources, "source checksum path set mismatch")
    for name, digest in source_sums.items():
        require(_sha(files[name].read_bytes()) == digest, f"source checksum mismatch: {name}")
    blind = load(files["blind-input.json"])
    require(set(blind) == {"records", "schema", "selectedEnvelope"}, "blind input shape mismatch")
    require(blind["schema"] == INPUT_SCHEMA, "blind input schema mismatch")
    records = blind["records"]
    require(isinstance(records, list) and len(records) == 43, "blind input must contain 43 records")
    for record in records:
        _validate_record(record)
    identifiers = [record["opaqueId"] for record in records]
    require(identifiers == sorted(set(identifiers)), "opaque ids are not a sorted set")
    envelope = blind["selectedEnvelope"]
    require(set(envelope) == BLIND_ENVELOPE_DIMENSIONS, "blind envelope dimension set mismatch")
    # The selected O-08 dimension names are normative source vocabulary (for
    # example AP_TRANSITION_BLOCK_OCTETS), not hidden corpus metadata.  The
    # no-oracle scan therefore applies to the projected replica records.
    _scan_value({"records": records})
    require(load(files["blind-input.schema.json"]) == _input_schema(), "blind schema bytes drifted")
    return {
        "kitDigest": _sha(files["SHA256SUMS.txt"].read_bytes()),
        "records": len(records),
        "result": "PASS",
        "sources": len(SOURCE_PATHS),
    }


def build_kit(repo_root: Path, corpus: Path, output: Path) -> dict[str, Any]:
    require(not output.exists(), f"kit output already exists: {output}")
    valid = load(corpus / "valid-transcript-vectors.json")["records"]
    invalid_document = load(corpus / "invalid-transcript-vectors.json")
    invalid = invalid_document["records"]
    require(len(valid) == 17 and len(invalid) == 26, "public corpus cardinality mismatch")
    require(len(invalid_document.get("apExpectationOnlyRecords", [])) == 3, "AP-only partition mismatch")
    projected_pairs = [_project_record(record) for record in valid + invalid]
    require(len({opaque for opaque, _ in projected_pairs}) == 43, "opaque-id collision")
    for original, (_, projected) in zip(valid + invalid, projected_pairs, strict=True):
        require(
            _public_observation(original)
            == _public_observation(materialize_blind_evaluator_input(projected)),
            f"blind projection requires hidden input: {original['id']}",
        )
    envelope = load(repo_root / "tools/causal-flow-simulator/o08/resource-envelope.candidate.json")
    entries = envelope["entries"]
    require(BLIND_ENVELOPE_DIMENSIONS <= set(entries), "selected envelope is incomplete")
    selected = {
        identifier: {
            "closedValues": entries[identifier]["closed_values"],
            "comparison": entries[identifier]["comparison"],
            "selectedValue": entries[identifier]["selected_value"],
        }
        for identifier in sorted(BLIND_ENVELOPE_DIMENSIONS)
    }
    output.mkdir(parents=True)
    store(output / "blind-input.json", {"records": [record for _, record in sorted(projected_pairs)], "schema": INPUT_SCHEMA, "selectedEnvelope": selected})
    store(output / "blind-input.schema.json", _input_schema())
    (output / "README.md").write_bytes(_readme())
    (output / "TOOLCHAIN.md").write_bytes(_toolchain())
    (output / "VERIFY.py").write_bytes(_verify_script())
    os.chmod(output / "VERIFY.py", 0o755)
    source_entries: list[tuple[str, bytes]] = []
    for source in SOURCE_PATHS:
        source_path = repo_root / source
        require(source_path.is_file() and not source_path.is_symlink(), f"missing source: {source}")
        target = output / "sources" / source
        target.parent.mkdir(parents=True, exist_ok=True)
        data = source_path.read_bytes()
        target.write_bytes(data)
        source_entries.append((f"sources/{source}", data))
    (output / "SOURCE_SHA256SUMS.txt").write_bytes(_sums(source_entries))
    manifest = {
        "invalidRecordCount": 26,
        "paths": sorted(KIT_PATHS),
        "schema": KIT_SCHEMA,
        "sourceCount": len(SOURCE_PATHS),
        "validObservationCount": 68,
        "validRecordCount": 17,
    }
    store(output / "KIT-MANIFEST.json", manifest)
    checksum_entries = [(name, path.read_bytes()) for name, path in _regular_files(output).items() if name != "SHA256SUMS.txt"]
    (output / "SHA256SUMS.txt").write_bytes(_sums(checksum_entries))
    return validate_kit(output)


def freeze_reader(reader_root: Path, output: Path) -> dict[str, Any]:
    require(not output.exists(), f"freeze output already exists: {output}")
    files = _regular_files(reader_root)
    require("reader" in files and "TOOLCHAIN.md" in files, "reader package lacks reader or TOOLCHAIN.md")
    mode = stat.S_IMODE(files["reader"].stat().st_mode)
    require(mode & stat.S_IXUSR != 0, "reader is not executable")
    records = [
        {
            "executable": bool(stat.S_IMODE(path.stat().st_mode) & 0o111),
            "path": name,
            "sha256": _sha(path.read_bytes()),
        }
        for name, path in sorted(files.items())
    ]
    manifest = {
        "command": ["reader", "--input", "<file>", "--output", "<file>"],
        "files": records,
        "schema": FREEZE_SCHEMA,
    }
    store(output, manifest)
    return {"files": len(records), "freezeDigest": _sha(output.read_bytes()), "result": "PASS"}


def validate_reader_freeze(reader_root: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = load(manifest_path)
    require(manifest.get("schema") == FREEZE_SCHEMA, "reader freeze schema mismatch")
    require(manifest.get("command") == ["reader", "--input", "<file>", "--output", "<file>"], "reader command mismatch")
    files = _regular_files(reader_root)
    expected = {record["path"]: record for record in manifest.get("files", [])}
    require(set(files) == set(expected), "reader package path set changed after freeze")
    for name, row in expected.items():
        path = files[name]
        require(_sha(path.read_bytes()) == row["sha256"], f"reader byte drift: {name}")
        require(bool(stat.S_IMODE(path.stat().st_mode) & 0o111) == row["executable"], f"reader mode drift: {name}")
    return manifest


def _public_observation(record: dict[str, Any]) -> dict[str, Any]:
    observed = evaluate_vector(record)
    reference_rejected = observed.get("localOutcome") == "REFERENCE_COLLISION_UNSUPPORTED"
    reference_not_reached = observed["transcriptVerification"] != "VALID"
    result = {
        "apAuthorityResult": observed["apAuthorityResult"],
        "commitmentVerification": observed["commitmentVerification"],
        "kBindingAdmission": observed["kBindingAdmission"],
        "localOutcomePresent": "localOutcome" in observed,
        "outcomeEvaluated": observed["outcomeEvaluated"],
        "referenceVerification": "NOT_REACHED" if reference_not_reached else ("REJECTED" if reference_rejected else "VALID"),
        "remoteClassPresent": "remoteClass" in observed,
        "signatureVerification": observed["signatureVerification"],
        "stage": observed["stage"],
        "transcriptVerification": observed["transcriptVerification"],
    }
    if "localOutcome" in observed:
        result["localOutcome"] = observed["localOutcome"]
    if "remoteClass" in observed:
        result["remoteClass"] = observed["remoteClass"]
    return result


def build_integration(repo_root: Path, corpus: Path, kit: Path, freeze_manifest: Path, output: Path) -> dict[str, Any]:
    require(not output.exists(), f"integration output already exists: {output}")
    kit_report = validate_kit(kit)
    freeze = load(freeze_manifest)
    require(freeze.get("schema") == FREEZE_SCHEMA, "invalid reader freeze manifest")
    valid = load(corpus / "valid-transcript-vectors.json")["records"]
    invalid = load(corpus / "invalid-transcript-vectors.json")["records"]
    official = valid + invalid
    rows = []
    for record in official:
        opaque, _ = _project_record(record)
        rows.append(
            {
                "expectedPublicObservation": _public_observation(record),
                "inputDigest": semantic_input_digest(record),
                "officialId": record["id"],
                "opaqueId": opaque,
                "reportObservationId": f"scenario-vector-{record['id']}:0",
                "set": "VALID" if record in valid else "INVALID",
            }
        )
    require(len({row["opaqueId"] for row in rows}) == 43, "integration opaque-id collision")
    output.mkdir(parents=True)
    store(
        output / "integration-map.json",
        {
            "freezeManifestSha256": _sha(freeze_manifest.read_bytes()),
            "kitDigest": kit_report["kitDigest"],
            "records": sorted(rows, key=lambda row: row["opaqueId"]),
            "schema": INTEGRATION_SCHEMA,
        },
    )
    (output / "INTEGRATION-SHA256SUMS.txt").write_bytes(
        _sums([("integration-map.json", (output / "integration-map.json").read_bytes())])
    )
    return {"integrationDigest": _sha((output / "integration-map.json").read_bytes()), "records": 43, "result": "PASS"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build-kit")
    build.add_argument("--repo-root", type=Path, required=True)
    build.add_argument("--corpus", type=Path, required=True)
    build.add_argument("--kit-output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--kit", type=Path, required=True)
    validate.add_argument("--output", type=Path, required=True)
    freeze = subparsers.add_parser("freeze-reader")
    freeze.add_argument("--reader-root", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    integration = subparsers.add_parser("build-integration")
    integration.add_argument("--repo-root", type=Path, required=True)
    integration.add_argument("--corpus", type=Path, required=True)
    integration.add_argument("--kit", type=Path, required=True)
    integration.add_argument("--freeze-manifest", type=Path, required=True)
    integration.add_argument("--integration-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build-kit":
            report = build_kit(args.repo_root.resolve(), args.corpus.resolve(), args.kit_output.resolve())
        elif args.command == "validate":
            report = validate_kit(args.kit.resolve())
            store(args.output.resolve(), report)
            return 0
        elif args.command == "freeze-reader":
            report = freeze_reader(args.reader_root.resolve(), args.output.resolve())
        else:
            report = build_integration(args.repo_root.resolve(), args.corpus.resolve(), args.kit.resolve(), args.freeze_manifest.resolve(), args.integration_output.resolve())
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    except (BlindProjectionError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"c03_blind_projection_failure={error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
