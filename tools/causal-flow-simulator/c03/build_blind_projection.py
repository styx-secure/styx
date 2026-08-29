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
    evaluate_k_admission_graph,
    public_transcript_observation,
    parse_event,
    semantic_input_digest,
)


class BlindProjectionError(CorpusModelError):
    """The public kit, reader freeze or withheld integration is invalid."""


KIT_SCHEMA = "styx-c03-blind-kit/v2"
INPUT_SCHEMA = "styx-c03-blind-input/v2"
FREEZE_SCHEMA = "styx-c03-reader-freeze/v1"
INTEGRATION_SCHEMA = "styx-c03-blind-integration/v2"

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
    "commitmentMatchVerification",
    "commitmentVerification",
    "geometryPredicate1",
    "geometryPredicate2",
    "geometryPredicate3",
    "geometryPredicate4",
    "geometryPredicate5",
    "geometryPredicate6",
    "geometryPredicate7",
    "kBindingAdmission",
    "localOutcomePresent",
    "outcomeEvaluated",
    "referenceVerification",
    "remoteClassPresent",
    "signatureVerification",
    "stage",
    "suppliedLengthVerification",
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
    if "admittedEventReferences" in admission:
        values = set(admission["admittedEventReferences"])
    elif "availableDependencyReferences" in admission:
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
            # These are replica-selected active-profile inputs, not values
            # copied from an untrusted candidate transcript.
            "applicationProfileId": 1,
            "applicationProfileVersion": 1,
            "commitmentSuiteId": 1,
            "signatureSuiteId": 1,
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


def _project_graph_record(record: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    presented_reference = record.get(
        "eventReferenceHex", record.get("genesisReferenceHex")
    )
    require(isinstance(presented_reference, str), "graph record lacks reference")
    projected = {
        "kind": record["kind"],
        "opening": record.get("opening"),
        "presentedReferenceHex": presented_reference,
        "signatureHex": record["signatureHex"],
        "transcriptHex": record["transcriptHex"],
    }
    opaque_id = f"item-{_sha(dumps(projected))}"
    return opaque_id, {"opaqueId": opaque_id, **projected}


def _project_graph(
    genesis: dict[str, Any], records: list[dict[str, Any]]
) -> tuple[str, dict[str, Any]]:
    _, projected_genesis = _project_graph_record(genesis)
    events = [_project_graph_record(record)[1] for record in records]
    payload = {"acceptedGenesis": projected_genesis, "events": events}
    opaque_id = f"graph-{_sha(dumps(payload))}"
    return opaque_id, {"opaqueGraphId": opaque_id, **payload}


def _official_admission_graphs(corpus: Path) -> list[dict[str, Any]]:
    valid_document = load(corpus / "valid-transcript-vectors.json")
    k_by_id = {
        record["id"]: record
        for record in valid_document.get("kAdmissionRecords", [])
    }
    scenario_document = load(corpus / "state-machine-scenarios.json")
    rows: list[dict[str, Any]] = []
    for scenario in scenario_document.get("kAdmissionScenarios", []):
        genesis = k_by_id[scenario["acceptedGenesisRecordId"]]
        events = [k_by_id[identifier] for identifier in scenario["recordIds"]]
        rows.append(
            {
                "expectedObservations": evaluate_k_admission_graph(
                    genesis, events
                ),
                "genesis": genesis,
                "id": scenario["id"],
                "records": events,
                "set": "CONNECTED_POSITIVE",
            }
        )
    adversarial = load(corpus / "adversarial-mutations.json")
    for scenario in adversarial.get("kAdmissionScenarios", []):
        rows.append(
            {
                "expectedObservations": scenario["expectedObservations"],
                "genesis": scenario["acceptedGenesisRecord"],
                "id": scenario["id"],
                "records": scenario["records"],
                "set": "CONNECTED_HOSTILE",
            }
        )
    require(len(rows) == 20, "official admission graph cardinality mismatch")
    return sorted(rows, key=lambda row: row["id"])


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
        "admittedEventReferences": record["admittedEventReferences"],
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
    def graph_record(kind: str) -> dict[str, Any]:
        opening = {
            "additionalProperties": False,
            "properties": {
                "contentHex": hex_string,
                "randomizerHex": ref,
            },
            "required": ["contentHex", "randomizerHex"],
            "type": "object",
        }
        return {
        "additionalProperties": False,
        "properties": {
            "kind": {"const": kind},
            "opening": {"anyOf": [{"type": "null"}, opening]},
            "opaqueId": {
                "pattern": "^item-[0-9a-f]{64}$",
                "type": "string",
            },
            "presentedReferenceHex": ref,
            "signatureHex": hex_string,
            "transcriptHex": hex_string,
        },
        "required": [
            "kind",
            "opening",
            "opaqueId",
            "presentedReferenceHex",
            "signatureHex",
            "transcriptHex",
        ],
        "type": "object",
        }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {
            "admissionGraphs": {
                "items": {
                    "additionalProperties": False,
                    "properties": {
                        "acceptedGenesis": graph_record("GENESIS"),
                        "events": {
                            "items": graph_record("APPLICATION_EVENT"),
                            "minItems": 1,
                            "type": "array",
                        },
                        "opaqueGraphId": {
                            "pattern": "^graph-[0-9a-f]{64}$",
                            "type": "string",
                        },
                    },
                    "required": [
                        "acceptedGenesis",
                        "events",
                        "opaqueGraphId",
                    ],
                    "type": "object",
                },
                "maxItems": 20,
                "minItems": 20,
                "type": "array",
            },
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
                "maxItems": 44,
                "minItems": 44,
                "type": "array",
            },
            "schema": {"const": INPUT_SCHEMA},
            "selectedEnvelope": {"type": "object"},
        },
        "required": [
            "admissionGraphs",
            "records",
            "schema",
            "selectedEnvelope",
        ],
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
if document.get("schema") != "styx-c03-blind-input/v2" or len(document.get("records", [])) != 44 or len(document.get("admissionGraphs", [])) != 20:
    raise SystemExit("blind input cardinality mismatch")
ids = [record.get("opaqueId") for record in document["records"]]
if ids != sorted(set(ids)) or not all(re.fullmatch(r"case-[0-9a-f]{64}", value or "") for value in ids):
    raise SystemExit("opaque identifier mismatch")
graph_ids = [graph.get("opaqueGraphId") for graph in document["admissionGraphs"]]
if graph_ids != sorted(set(graph_ids)) or not all(re.fullmatch(r"graph-[0-9a-f]{64}", value or "") for value in graph_ids):
    raise SystemExit("opaque graph identifier mismatch")
print("STYX_C03_BLIND_KIT_OK records=44 admission_graphs=20")
'''


def _readme() -> bytes:
    return b"""# Styx C0.3 blind K-surface kit

This deterministic package separates 44 disconnected transcript/local-negative
fixtures from 20 connected admission graphs: three positive graphs with 18
observations and 17 hostile graphs with 66 observations.  It contains raw candidates and
only the replica-owned inputs enumerated by the C0.3 amendment.  It contains no
expected result, stage, transition, corpus identifier, repository revision or
integration mapping.

Implement a fresh reader that accepts `--input <file> --output <file>`.  For
each disconnected opaque record it must parse the transcript, recompute the
presented reference, verify the supplied conformance key/opening and classify
any local negative branch. A successful disconnected record reports transcript
conformance with K admission `NOT_EVALUATED`: synthetic local metadata is never
proof of a genesis/GRANT chain. For each admission graph, it derives the trusted
root only from the preaccepted genesis transcript and derives non-root keys only
from admitted GRANT events. Candidate records carry no verification key or
binding oracle. Each graph object also carries `opening`: either the exact raw
content/randomizer pair supplied to that replica or JSON `null` when no opening
was supplied. The reader must verify a non-null opening against the authenticated
commitment; its mere presence is not an oracle. A missing `REQUIRED` opening
selects the event-local pending rules below, while a valid supplied opening does
not. Application-policy authority is out of scope: K admission is not AP
authorization and must never be flattened to application success.

Run `python3 VERIFY.py` before using the package.  The withheld integration map
is created only after the reader source has been frozen.

The kit intentionally copies its eight normative source files from the exact
candidate working tree. Corpus provenance and historical gate validation remain
anchored independently to the Issue #266 Base blobs. This asymmetry is deliberate:
the reader implements the reconciled candidate semantics, while the corpus gate
proves that the candidate did not rewrite the frozen Base evidence.

## Required output contract

The reader output has schema `styx-c03-clean-room-report/v2` and exactly three
top-level members: `admissionGraphs`, `schema` and `observations`.
`observations` is a list sorted
by `opaqueId`, contains exactly one object for every input record and has no
duplicates. Each observation contains exactly these members:

```text
opaqueId
apAuthorityResult
commitmentMatchVerification
commitmentVerification
geometryPredicate1
geometryPredicate2
geometryPredicate3
geometryPredicate4
geometryPredicate5
geometryPredicate6
geometryPredicate7
kBindingAdmission
localOutcomePresent
outcomeEvaluated
referenceVerification
remoteClassPresent
signatureVerification
stage
suppliedLengthVerification
transcriptVerification
```

`localOutcomePresent`, `outcomeEvaluated` and `remoteClassPresent` are JSON
booleans; every other listed value is a JSON string. If and only if
`localOutcomePresent` is true, the object additionally contains the string
member `localOutcome`. If and only if `remoteClassPresent` is true, it
additionally contains the string member `remoteClass`. No other member is
permitted. Values are the exact locally observed vocabulary selected by the
supplied normative sources. To make independent output comparable without
leaking any per-record oracle, the complete value domains are:

```text
apAuthorityResult:
  AP_FOLD_NOT_EXECUTED | NOT_REACHED
commitmentMatchVerification:
  NOT_APPLICABLE | NOT_EVALUATED | REJECTED | VALID
commitmentVerification:
  NOT_EVALUATED | NOT_PRESENT | PENDING | REJECTED | VALID
geometryPredicate1..geometryPredicate7:
  NOT_APPLICABLE | NOT_EVALUATED | FAIL | PASS
kBindingAdmission:
  ADMITTED | NOT_EVALUATED | REJECTED
referenceVerification:
  NOT_REACHED | REJECTED | VALID
signatureVerification:
  NOT_EVALUATED | REJECTED | VALID
stage:
  EVENT_LOCAL | FINAL_AFTER_S6 | S3_KERNEL_STRUCTURAL |
  S4_GRAPH_ADMISSION | TRANSCRIPT_CONFORMANCE_COMPLETE
suppliedLengthVerification:
  NOT_APPLICABLE | NOT_EVALUATED | REJECTED | VALID
transcriptVerification:
  REJECTED | VALID
localOutcome:
  COMMITMENT_MISMATCH | CONTEXT_CAPACITY_EXHAUSTED |
  CREDENTIAL_BINDING_MISMATCH |
  CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED |
  CURRENT_OBJECT_OUT_OF_PROFILE | DEPENDENCY_DEFERRED | DUPLICATE |
  FORK_EVIDENCE | INVALID | LENGTH_MISMATCH | OPENING_MISSING |
  PENDING_ANCESTOR | PENDING_OPENING | REFERENCE_COLLISION_UNSUPPORTED |
  STRUCTURAL_REJECTION | UNRESOLVED_CREDENTIAL_BINDING
remoteClass:
  OPAQUE_REMOTE_FAILURE
```

`admissionGraphs` is sorted by `opaqueGraphId` and contains one row for every
input graph. Each row has exactly `opaqueGraphId` and `observations`.
Its observations are sorted by `opaqueId`, one per graph event, and contain
exactly:

```text
opaqueId
kBindingAdmission
protocolErrorCodePresent
stage
```

When `protocolErrorCodePresent` is true, `protocolErrorCode` is additionally
present; otherwise it is absent. The closed error vocabulary is
`CONTEXT_CAPACITY_EXHAUSTED | CREDENTIAL_BINDING_MISMATCH |
DEPENDENCY_DEFERRED | FORK_EVIDENCE | INVALID | PENDING_ANCESTOR |
PENDING_OPENING | STRUCTURAL_REJECTION | UNRESOLVABLE_CREDENTIAL |
UNRESOLVED_CREDENTIAL_BINDING`. The reader must not consult any
disconnected-fixture binding while evaluating a graph.

Evaluation is fail-closed and ordered. Transcript framing is evaluated first;
if it rejects, reference and signature are not reached. The recomputed
reference is then compared with `presentedReferenceHex`. A differing presented
reference selects `REFERENCE_COLLISION_UNSUPPORTED` only when the replica-owned
`seenEventReferences` also contains that presented value; that set is collision
history only and never proves admission. Without that collision-history match,
the same presented-reference mismatch selects `INVALID`. Checkpoint exact-zero
and other S3 profile checks precede protected work. Signature, claimed binding and reached
content checks follow. Duplicate classification occurs only after signature
and binding and only against `admittedEventReferences`. Bytes that were merely
seen or previously rejected must be evaluated again and retain their original
rejection unless admitted state has changed. S4 capacity, fork, dependency and
credential admission follow only when their prerequisites were reached.

The report fields describe reached protocol boundaries, not merely values that
a decoder happened to extract. A framing, closed-value, written-inverse,
length, reserved-field or cross-field failure makes
`transcriptVerification=REJECTED`; reference is `NOT_REACHED`, signature is
`NOT_EVALUATED`, and protected content predicates that were not reached remain
`NOT_EVALUATED`. For a canonical genesis or content class `NONE`, the
content-shape branch is complete immediately after the written inverse and all
shape-specific fields become `NOT_APPLICABLE` even if a later reference,
signature, binding or profile check fails. A
supplied-content length mismatch rejects both supplied-length verification and
the attempted commitment match; it is not reported as an unattempted match.

`kBindingAdmission` reports only K. Within a connected graph it remains
`ADMITTED` when transcript and binding admission succeeded even if an
event-local condition, such as a same-author fork, missing REQUIRED opening or
pending ancestor, prevents AP folding. A connected failure before K admission
reports K `REJECTED`. Every disconnected fixture, including a locally negative
fixture, reports K `NOT_EVALUATED`: the fixture has no connected authority
history from which K admission could be decided. Every disconnected fixture,
whether its transcript/local result is positive, negative or deferred, reports
`apAuthorityResult=NOT_REACHED`: without connected K admission the AP fold is
not a reachable boundary. Only a connected K success reports
`AP_FOLD_NOT_EXECUTED`; K was reached and admitted there, while AP itself
remains deliberately outside this task.

`profile` is the active profile selected by the receiving replica. Transcript
fields that disagree with it do not change the selected profile. The selected
v0 tuple in this kit is protocol/profile/profile-version/signature-suite/
commitment-suite `1/1/1/1/1`. A canonically encoded non-zero AP identifier or
version that differs from this selected tuple leaves
`transcriptVerification=VALID`; after reference verification it selects
`CURRENT_OBJECT_OUT_OF_PROFILE` at `S3_KERNEL_STRUCTURAL`, before signature or
content verification. Zero or non-canonical registry fields remain structural
transcript rejection.

For content class `NONE`, commitment match, supplied length and all seven
geometry predicates are `NOT_APPLICABLE`, while commitment verification is
`NOT_PRESENT`. For either committed-content class, a missing verified opening
sets `commitmentVerification=PENDING`, supplied-length and commitment-match
verification to `NOT_EVALUATED`. It is not the same as missing detachable
content bytes: `REQUIRED` selects `PENDING_OPENING` at `EVENT_LOCAL` and remains
K-admitted; `DETACHABLE` without its verified opening selects `OPENING_MISSING`
at `S3_KERNEL_STRUCTURAL` and is rejected by K. Detachability permits later
content-byte retrieval, not verification without an opening.

O-08 enforcement uses each dimension's source-selected stage rather than a
generic profile stage. In particular, `PARENTS_PER_EVENT` is enforced at
`S4_GRAPH_ADMISSION`, after transcript/reference/signature/binding, and selects
`CONTEXT_CAPACITY_EXHAUSTED`; structural and
closed-set envelope dimensions enforced at S3 retain their exact O-10 result.

A candidate whose authenticated dependency is pending on a verified REQUIRED
opening reports `PENDING_ANCESTOR` at `EVENT_LOCAL`. A candidate whose
dependency has been rejected for another reason reports `DEPENDENCY_DEFERRED`
at `S4_GRAPH_ADMISSION`, preserving the O-10 retry precondition
`AUTHENTICATED_DEPENDENCY_STATE_CHANGED`; dependency failure is not rewritten
as transcript corruption. Complete-graph evaluation is arrival-order
independent. When two otherwise valid candidates occupy the same author and
sequence slot, both report `FORK_EVIDENCE`; lexical order cannot select one.

A `ROTATE` replacement-grant reference or `RECOVER` recovery-grant reference
must name an already admitted same-context GRANT and must equal either the
event's direct predecessor or one member of its encoded causal-parent frontier.
Replica-local admission state cannot manufacture this signed causal relation.

For every connected candidate, its authenticated genesis reference is compared
with the graph's preaccepted genesis before credential lookup. A mismatch is
`CREDENTIAL_BINDING_MISMATCH`; only a candidate in the selected genesis context
can proceed to credential resolution. Non-root verification bindings then come
only from admitted same-context GRANT events. The binding GRANT for a non-root
candidate must also be causally available in that candidate's authenticated
dependency ancestry. An admitted same-context GRANT elsewhere in the bounded
graph does not bind the candidate; absence from its ancestry selects
`UNRESOLVED_CREDENTIAL_BINDING` at `S3_KERNEL_STRUCTURAL`. The preaccepted
genesis root is the only binding that needs no GRANT ancestor. A disconnected
fixture key or credential claim never supplies a connected binding.

REVOKE and the retiring side of ROTATE require their target credential to be
resolvable in admitted K history. A resolvable non-genesis target must also have
its binding GRANT in the candidate's authenticated causal ancestry. The
preaccepted genesis credential is the sole target-binding ancestry exception:
an otherwise valid REVOKE may name that root directly. This exception neither
creates a general target-absence rule nor permits non-genesis target
substitution. Removal-target absence remains AP-owned and does not by itself
invalidate an otherwise K-valid removal directive.

Successful connected-graph K admission has `stage=FINAL_AFTER_S6`,
`apAuthorityResult=AP_FOLD_NOT_EXECUTED`, `outcomeEvaluated=false`, and both
optional result fields absent. Successful disconnected transcript conformance
has `stage=TRANSCRIPT_CONFORMANCE_COMPLETE` and K `NOT_EVALUATED`. Every
negative or deferred classification has
`outcomeEvaluated=true` and both optional fields present. `NOT_REACHED`,
`NOT_EVALUATED` and `NOT_APPLICABLE` are distinct and must not be substituted.
This output contract supplies field names, semantics and closed vocabularies,
never an expected value for an individual input.

The whole document is canonical UTF-8 JSON: keys sorted by Unicode code point,
no insignificant whitespace and exactly one final LF. Missing, extra or
duplicate input/output records and unknown output fields fail closed.
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


def _validate_graph_record(record: dict[str, Any], *, genesis: bool) -> None:
    require(
        set(record)
        == {
            "kind",
            "opening",
            "opaqueId",
            "presentedReferenceHex",
            "signatureHex",
            "transcriptHex",
        },
        "blind graph record shape mismatch",
    )
    require(
        record["kind"] == ("GENESIS" if genesis else "APPLICATION_EVENT"),
        "blind graph object kind mismatch",
    )
    require(
        re.fullmatch(r"item-[0-9a-f]{64}", record["opaqueId"]) is not None,
        "invalid blind graph record id",
    )
    _hex(record["presentedReferenceHex"], 32, "presentedReferenceHex")
    _hex(record["signatureHex"], 64, "signatureHex")
    _hex(record["transcriptHex"], None, "transcriptHex")
    opening = record["opening"]
    if opening is not None:
        require(
            set(opening) == {"contentHex", "randomizerHex"},
            "blind graph opening shape mismatch",
        )
        _hex(opening["contentHex"], None, "contentHex")
        _hex(opening["randomizerHex"], 32, "randomizerHex")
    projected = dict(record)
    projected.pop("opaqueId")
    require(
        record["opaqueId"] == f"item-{_sha(dumps(projected))}",
        "blind graph record id is not input-derived",
    )


def _validate_graph(graph: dict[str, Any]) -> None:
    require(
        set(graph) == {"acceptedGenesis", "events", "opaqueGraphId"},
        "blind graph shape mismatch",
    )
    require(
        re.fullmatch(r"graph-[0-9a-f]{64}", graph["opaqueGraphId"])
        is not None,
        "invalid blind graph id",
    )
    _validate_graph_record(graph["acceptedGenesis"], genesis=True)
    require(
        isinstance(graph["events"], list) and bool(graph["events"]),
        "empty blind graph",
    )
    for event in graph["events"]:
        _validate_graph_record(event, genesis=False)
    event_ids = [event["opaqueId"] for event in graph["events"]]
    require(len(event_ids) == len(set(event_ids)), "duplicate blind graph event")
    projected = dict(graph)
    projected.pop("opaqueGraphId")
    require(
        graph["opaqueGraphId"] == f"graph-{_sha(dumps(projected))}",
        "blind graph id is not input-derived",
    )


def validate_kit(kit: Path) -> dict[str, Any]:
    files = _regular_files(kit)
    require(set(files) == KIT_PATHS, f"kit path set mismatch: {sorted(set(files) ^ KIT_PATHS)}")
    manifest = load(files["KIT-MANIFEST.json"])
    require(manifest.get("schema") == KIT_SCHEMA, "kit schema mismatch")
    require(
        set(manifest)
        == {
            "admissionGraphCount",
            "admissionObservationCount",
            "connectedHostileGraphCount",
            "connectedHostileObservationCount",
            "connectedPositiveGraphCount",
            "connectedPositiveObservationCount",
            "invalidRecordCount",
            "paths",
            "schema",
            "sourceCount",
            "transcriptConformanceRecordCount",
            "validRecordCount",
        },
        "kit manifest shape mismatch",
    )
    require(manifest["admissionGraphCount"] == 20, "kit graph count mismatch")
    require(
        manifest["admissionObservationCount"] == 84,
        "kit graph observation count mismatch",
    )
    require(
        manifest["connectedHostileGraphCount"] == 17
        and manifest["connectedHostileObservationCount"] == 66
        and manifest["connectedPositiveGraphCount"] == 3
        and manifest["connectedPositiveObservationCount"] == 18,
        "kit graph partition mismatch",
    )
    require(
        manifest["transcriptConformanceRecordCount"] == 17
        and manifest["validRecordCount"] == 17
        and manifest["invalidRecordCount"] == 27,
        "kit record partition mismatch",
    )
    require(manifest["sourceCount"] == len(SOURCE_PATHS), "kit source count mismatch")
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
    require(
        set(blind)
        == {"admissionGraphs", "records", "schema", "selectedEnvelope"},
        "blind input shape mismatch",
    )
    require(blind["schema"] == INPUT_SCHEMA, "blind input schema mismatch")
    records = blind["records"]
    require(isinstance(records, list) and len(records) == 44, "blind input must contain 44 records")
    for record in records:
        _validate_record(record)
    identifiers = [record["opaqueId"] for record in records]
    require(identifiers == sorted(set(identifiers)), "opaque ids are not a sorted set")
    graphs = blind["admissionGraphs"]
    require(
        isinstance(graphs, list) and len(graphs) == 20,
        "blind input must contain 20 admission graphs",
    )
    for graph in graphs:
        _validate_graph(graph)
    graph_ids = [graph["opaqueGraphId"] for graph in graphs]
    require(graph_ids == sorted(set(graph_ids)), "opaque graph ids are not sorted")
    envelope = blind["selectedEnvelope"]
    require(set(envelope) == BLIND_ENVELOPE_DIMENSIONS, "blind envelope dimension set mismatch")
    # The selected O-08 dimension names are normative source vocabulary (for
    # example AP_TRANSITION_BLOCK_OCTETS), not hidden corpus metadata.  The
    # no-oracle scan therefore applies to the projected replica records.
    _scan_value({"admissionGraphs": graphs, "records": records})
    require(load(files["blind-input.schema.json"]) == _input_schema(), "blind schema bytes drifted")
    return {
        "kitDigest": _sha(files["SHA256SUMS.txt"].read_bytes()),
        "admissionGraphs": len(graphs),
        "records": len(records),
        "result": "PASS",
        "sources": len(SOURCE_PATHS),
    }


def build_kit(repo_root: Path, corpus: Path, output: Path) -> dict[str, Any]:
    require(not output.exists(), f"kit output already exists: {output}")
    valid = load(corpus / "valid-transcript-vectors.json")["records"]
    invalid_document = load(corpus / "invalid-transcript-vectors.json")
    invalid = invalid_document["records"]
    require(len(valid) == 17 and len(invalid) == 27, "public corpus cardinality mismatch")
    require(len(invalid_document.get("apExpectationOnlyRecords", [])) == 3, "AP-only partition mismatch")
    projected_pairs = [_project_record(record) for record in valid + invalid]
    require(len({opaque for opaque, _ in projected_pairs}) == 44, "opaque-id collision")
    for original, (_, projected) in zip(valid + invalid, projected_pairs, strict=True):
        require(
            _public_observation(original)
            == _public_observation(materialize_blind_evaluator_input(projected)),
            f"blind projection requires hidden input: {original['id']}",
        )
    official_graphs = _official_admission_graphs(corpus)
    projected_graph_pairs = [
        _project_graph(row["genesis"], row["records"])
        for row in official_graphs
    ]
    require(
        len({opaque for opaque, _ in projected_graph_pairs}) == 20,
        "opaque graph-id collision",
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
    store(
        output / "blind-input.json",
        {
            "admissionGraphs": [
                graph for _, graph in sorted(projected_graph_pairs)
            ],
            "records": [record for _, record in sorted(projected_pairs)],
            "schema": INPUT_SCHEMA,
            "selectedEnvelope": selected,
        },
    )
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
        "admissionGraphCount": 20,
        "admissionObservationCount": 84,
        "connectedHostileGraphCount": 17,
        "connectedHostileObservationCount": 66,
        "connectedPositiveGraphCount": 3,
        "connectedPositiveObservationCount": 18,
        "invalidRecordCount": 27,
        "paths": sorted(KIT_PATHS),
        "schema": KIT_SCHEMA,
        "sourceCount": len(SOURCE_PATHS),
        "transcriptConformanceRecordCount": 17,
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
    return public_transcript_observation(record)


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
                "reportObservationId": record["id"],
                "set": "VALID" if record in valid else "INVALID",
            }
        )
    require(len({row["opaqueId"] for row in rows}) == 44, "integration opaque-id collision")
    graph_rows = []
    for graph in _official_admission_graphs(corpus):
        opaque_graph_id, _ = _project_graph(graph["genesis"], graph["records"])
        opaque_events = {
            record["id"]: _project_graph_record(record)[0]
            for record in graph["records"]
        }
        expected = []
        for observation in graph["expectedObservations"]:
            row = {
                "kBindingAdmission": observation["kBindingAdmission"],
                "opaqueId": opaque_events[observation["id"]],
                "protocolErrorCodePresent": observation["protocolErrorCode"]
                is not None,
                "stage": observation["stage"],
            }
            if observation["protocolErrorCode"] is not None:
                row["protocolErrorCode"] = observation["protocolErrorCode"]
            expected.append(row)
        graph_rows.append(
            {
                "expectedObservations": sorted(
                    expected, key=lambda row: row["opaqueId"]
                ),
                "officialId": graph["id"],
                "opaqueGraphId": opaque_graph_id,
                "set": graph["set"],
            }
        )
    require(
        len(graph_rows) == 20
        and len({row["opaqueGraphId"] for row in graph_rows}) == 20,
        "integration admission graph mismatch",
    )
    output.mkdir(parents=True)
    store(
        output / "integration-map.json",
        {
            "freezeManifestSha256": _sha(freeze_manifest.read_bytes()),
            "admissionGraphs": sorted(
                graph_rows, key=lambda row: row["opaqueGraphId"]
            ),
            "kitDigest": kit_report["kitDigest"],
            "records": sorted(rows, key=lambda row: row["opaqueId"]),
            "schema": INTEGRATION_SCHEMA,
        },
    )
    (output / "INTEGRATION-SHA256SUMS.txt").write_bytes(
        _sums([("integration-map.json", (output / "integration-map.json").read_bytes())])
    )
    return {
        "admissionGraphs": 20,
        "integrationDigest": _sha(
            (output / "integration-map.json").read_bytes()
        ),
        "records": 44,
        "result": "PASS",
    }


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
