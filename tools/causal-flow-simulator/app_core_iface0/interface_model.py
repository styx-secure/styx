"""Pure APP-CORE-IFACE-0 reference model foundations.

The module implements only the serializable conformance data plane.  It does
not create an accepted context, authority capability, durable record, session
state, transport action, or product result.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any, BinaryIO

from jsonschema.validators import Draft202012Validator

from canonical_json import CanonicalJsonError, loads as canonical_loads
from inventory import (
    BASE_SHA,
    InventoryError,
    run_ratified_package_validator,
    verify_contract_package,
)


INTERFACE_VERSION = "0"
SUPPORTED_PROFILE = {
    "applicationProfileId": "1",
    "applicationProfileVersion": "1",
    "styxProtocolVersion": "1",
}
SUPPORTED_OPERATIONS = [
    "DESCRIBE_PROFILE",
    "VALIDATE_TRANSCRIPT",
    "EVALUATE_GENESIS",
    "REPLAY_CONTEXT",
    "EVALUATE_CANDIDATE",
    "EVALUATE_EVIDENCE_UPDATE",
]
EXTERNAL_BOUNDARIES = [
    "GENESIS_CEREMONY_PROMOTION",
    "DURABLE_COMMIT_FINALIZATION",
]


class InterfaceModelError(ValueError):
    """The pinned contract/native authority or model input is inconsistent."""


class RequestRejected(ValueError):
    """A caller request is rejected with zero public response bytes."""


class HarnessFailure(RuntimeError):
    """The evidence harness is misconfigured or cannot complete safely."""


@dataclass(frozen=True)
class SignaturePathResult:
    """One exact ACV-068 path observation.

    This is conformance evidence only.  It is never a credential, authority
    capability, acceptance decision, or persistence result.
    """

    relation_id: str
    result_mapping: str
    signature_observation: str
    backend_invocations: int


@dataclass(frozen=True)
class NativeDependency:
    path: str
    sha256: str
    file_mode: str
    git_blob_oid: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise InterfaceModelError(f"invalid JSON authority: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InterfaceModelError(f"invalid JSON authority: {path}") from error


@lru_cache(maxsize=1)
def _load_pinned_c03_model(repo_root: str) -> ModuleType:
    """Load the Base-pinned C0.3 Ed25519 evidence backend.

    The APP-core model owns the O-14 guards and calls the backend exactly once
    only after those guards pass.  Loading this module does not import any
    product cryptography or make it runtime authority.
    """

    path = Path(repo_root) / "tools/causal-flow-simulator/c03/corpus_model.py"
    name = "_styx_app_core_pinned_c03_model"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise HarnessFailure("pinned C0.3 backend cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


def _dependency_rows(contract: Path) -> tuple[NativeDependency, ...]:
    registry = _read_json(
        contract / "APP-CORE-IFACE-0-NATIVE-DEPENDENCIES-CANDIDATE.json"
    )
    rows = registry.get("dependencies")
    if not isinstance(rows, list) or len(rows) != 63:
        raise InterfaceModelError("native dependency relation must contain 63 rows")
    result: list[NativeDependency] = []
    for row in rows:
        if not isinstance(row, dict):
            raise InterfaceModelError("malformed native dependency row")
        try:
            result.append(
                NativeDependency(
                    path=row["path"],
                    sha256=row["sha256"],
                    file_mode=row["fileMode"],
                    git_blob_oid=row["gitBlobOid"],
                )
            )
        except KeyError as error:
            raise InterfaceModelError("incomplete native dependency row") from error
    if len({row.path for row in result}) != len(result):
        raise InterfaceModelError("duplicate native dependency path")
    return tuple(result)


def verify_native_authority(repo_root: Path, contract: Path) -> None:
    """Verify every provider-bound Base artifact before request evaluation."""

    root = repo_root.resolve()
    for dependency in _dependency_rows(contract):
        path = root / dependency.path
        if not path.is_file() or path.is_symlink():
            raise InterfaceModelError(f"invalid native dependency: {dependency.path}")
        raw = path.read_bytes()
        if _sha256(raw) != dependency.sha256:
            raise InterfaceModelError(f"native dependency digest drift: {dependency.path}")
        completed = subprocess.run(
            ["git", "ls-tree", BASE_SHA, "--", dependency.path],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
        expected = (
            f"{dependency.file_mode} blob {dependency.git_blob_oid}"
            f"\t{dependency.path}\n"
        )
        if completed.returncode != 0 or completed.stdout != expected:
            raise InterfaceModelError(f"native dependency Git identity drift: {dependency.path}")


@dataclass(frozen=True)
class ContractAuthority:
    """Exact read-only authority needed by the pure reference evaluator."""

    repo_root: Path
    contract: Path
    schema: dict[str, Any]
    resource_envelope: dict[str, Any]
    native_dependencies: tuple[NativeDependency, ...]

    @classmethod
    def load(cls, repo_root: Path, contract: Path) -> "ContractAuthority":
        root = repo_root.resolve()
        package = contract.resolve()
        try:
            verify_contract_package(package)
            run_ratified_package_validator(root, package)
        except (InventoryError, OSError) as error:
            raise InterfaceModelError("ratified contract package verification failed") from error
        dependencies = _dependency_rows(package)
        verify_native_authority(root, package)
        schema = _read_json(package / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json")
        envelope = _read_json(
            root / "tools/causal-flow-simulator/o08/resource-envelope.candidate.json"
        )
        if envelope.get("candidate_id") != "balanced":
            raise InterfaceModelError("selected resource envelope is not balanced")
        return cls(root, package, schema, envelope, dependencies)

    def dependency(self, path: str) -> NativeDependency:
        for dependency in self.native_dependencies:
            if dependency.path == path:
                return dependency
        raise InterfaceModelError(f"unpinned descriptor authority: {path}")

    def interface_limits(self) -> dict[str, str]:
        definition = self.schema.get("$defs", {}).get("InterfaceLimitsV0")
        if not isinstance(definition, dict):
            raise InterfaceModelError("missing InterfaceLimitsV0")
        properties = definition.get("properties")
        required = definition.get("required")
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise InterfaceModelError("malformed InterfaceLimitsV0")
        result: dict[str, str] = {}
        for name in required:
            entry = properties.get(name)
            if not isinstance(entry, dict) or not isinstance(entry.get("const"), str):
                raise InterfaceModelError(f"non-literal interface limit: {name}")
            result[name] = entry["const"]
            envelope_entry = self.resource_envelope.get("entries", {}).get(name)
            if not isinstance(envelope_entry, dict):
                raise InterfaceModelError(f"resource-envelope dimension missing: {name}")
            if str(envelope_entry.get("selected_value")) != result[name]:
                raise InterfaceModelError(f"resource-envelope limit drift: {name}")
        if set(result) != set(properties):
            raise InterfaceModelError("interface-limit property closure drift")
        return result

    def capability_requirements(self) -> dict[str, dict[str, str]]:
        definitions = self.schema.get("$defs")
        if not isinstance(definitions, dict):
            raise InterfaceModelError("missing schema definitions")
        requirements = definitions.get("CapabilityRequirementsV0")
        requirement = definitions.get("CapabilityRequirementV0")
        if not isinstance(requirements, dict) or not isinstance(requirement, dict):
            raise InterfaceModelError("missing capability-requirement schema")
        properties = requirements.get("properties")
        required = requirements.get("required")
        fields = requirement.get("properties")
        if (
            not isinstance(properties, dict)
            or not isinstance(required, list)
            or not isinstance(fields, dict)
        ):
            raise InterfaceModelError("malformed capability-requirement schema")
        entries = self.resource_envelope.get("entries")
        if not isinstance(entries, dict):
            raise InterfaceModelError("malformed resource-envelope entries")
        selected = {
            name: row
            for name, row in entries.items()
            if isinstance(row, dict)
            and row.get("role") == "C03_ACTIVATION_CAPABILITY_INPUT"
        }
        if set(required) != set(properties) or set(required) != set(selected):
            raise InterfaceModelError("capability-requirement property closure drift")
        comparison_values = fields.get("comparison", {}).get("enum")
        unit_values = fields.get("unit", {}).get("enum")
        if not isinstance(comparison_values, list) or not isinstance(unit_values, list):
            raise InterfaceModelError("capability-requirement enum drift")
        result: dict[str, dict[str, str]] = {}
        for name in required:
            row = selected[name]
            comparison = row.get("comparison")
            value = row.get("selected_value")
            unit = row.get("unit")
            if comparison not in comparison_values:
                raise InterfaceModelError(f"invalid capability comparison: {name}")
            if unit not in unit_values:
                raise InterfaceModelError(f"invalid capability unit: {name}")
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise InterfaceModelError(f"invalid capability value: {name}")
            result[name] = {
                "comparison": comparison,
                "selectedValue": str(value),
                "unit": unit,
            }
        minimum_count = sum(
            row["comparison"] == "MINIMUM_CAPABILITY" for row in result.values()
        )
        if result.get("ACTIVATION_CAPABILITY_SET") != {
            "comparison": "EXACT_CLOSED_KEY_SET",
            "selectedValue": str(minimum_count),
            "unit": "COUNT",
        }:
            raise InterfaceModelError("activation capability-set count drift")
        return result

    def descriptor(self) -> dict[str, Any]:
        transcript = self.dependency(
            "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md"
        )
        taxonomy = self.dependency(
            "tools/causal-flow-simulator/o10/outcome-taxonomy.json"
        )
        envelope = self.dependency(
            "tools/causal-flow-simulator/o08/resource-envelope.candidate.json"
        )
        return {
            "authorityPins": {
                "outcomeTaxonomySha256Hex": taxonomy.sha256,
                "resourceEnvelopeCandidateId": "balanced",
                "resourceEnvelopeSha256Hex": envelope.sha256,
                "signatureOctets": "64",
                "signatureSuiteId": "1",
                "transcriptProfileSha256Hex": transcript.sha256,
                "verificationKeyOctets": "32",
            },
            "descriptorVersion": "0",
            "capabilityRequirements": self.capability_requirements(),
            "evidenceEncoding": {
                "byteStrings": "LOWERCASE_EVEN_HEX",
                "duplicateKeys": "REJECT",
                "integers": "CANONICAL_UNSIGNED_DECIMAL_TEXT",
                "jsonProfile": "STYX_CANONICAL_EVIDENCE_JSON_V0",
                "unknownFields": "REJECT",
            },
            "externalBoundaries": list(EXTERNAL_BOUNDARIES),
            "interfaceLimits": self.interface_limits(),
            "profile": dict(SUPPORTED_PROFILE),
            "supportedOperations": list(SUPPORTED_OPERATIONS),
        }


def _prime_order_point(module: ModuleType, encoded: bytes) -> bool:
    """Return whether one canonical Ed25519 encoding has exact prime order."""

    try:
        point = module._ed_decode(encoded)
    except module.ProtocolError:
        return False
    identity = (0, 1)
    return point != identity and module._ed_mul(module._L, point) == identity


def _signature_relation_row(
    authority: ContractAuthority, relation_id: str
) -> dict[str, Any]:
    relations = _read_json(
        authority.contract / "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"
    )
    rows = relations.get("signatureVerificationPathRelationV0")
    if not isinstance(rows, list) or len(rows) != 17:
        raise HarnessFailure("signature path relation is not the ratified 17-row set")
    matches = [row for row in rows if row.get("id") == relation_id]
    if len(matches) != 1:
        raise HarnessFailure("signature path relation identity drift")
    return matches[0]


def evaluate_signature_path(
    authority: ContractAuthority,
    *,
    operation: str,
    candidate_kind: str,
    transcript: bytes,
    signature: bytes,
    standalone_verification_key: bytes | None = None,
    parsed_genesis_root_key: bytes | None = None,
) -> SignaturePathResult:
    """Evaluate the exact bounded ACV-068 signature path.

    The length gate is first.  Standalone key material is accepted only for an
    application candidate under ``VALIDATE_TRANSCRIPT`` and never creates AP
    authority.  Genesis verification uses only the key parsed from the
    transcript.  The pinned backend is invoked exactly once after the selected
    O-14 point and scalar guards pass.
    """

    if operation not in {"VALIDATE_TRANSCRIPT", "EVALUATE_GENESIS"}:
        raise HarnessFailure("signature path received an unsupported operation")
    if candidate_kind not in {"APPLICATION_EVENT", "GENESIS"}:
        raise HarnessFailure("signature path received an unsupported candidate kind")
    if operation == "EVALUATE_GENESIS" and candidate_kind != "GENESIS":
        raise HarnessFailure("genesis evaluation requires a genesis candidate")
    if not all(isinstance(value, bytes) for value in (transcript, signature)):
        raise HarnessFailure("signature path inputs must already be bounded bytes")
    if standalone_verification_key is not None and not isinstance(
        standalone_verification_key, bytes
    ):
        raise HarnessFailure("standalone verification key must be bytes")
    if parsed_genesis_root_key is not None and not isinstance(
        parsed_genesis_root_key, bytes
    ):
        raise HarnessFailure("parsed genesis root key must be bytes")

    if candidate_kind == "GENESIS":
        if standalone_verification_key is not None:
            raise HarnessFailure("genesis cannot consume a standalone verification key")
        key_source = "PARSED_TRANSCRIPT_ROOT"
        key = parsed_genesis_root_key
        short_relation = "SVP-008" if operation == "VALIDATE_TRANSCRIPT" else "SVP-013"
    elif standalone_verification_key is None:
        if parsed_genesis_root_key is not None:
            raise HarnessFailure("application candidate cannot consume a genesis root key")
        key_source = "NONE"
        key = None
        short_relation = "SVP-001"
    else:
        if parsed_genesis_root_key is not None:
            raise HarnessFailure("application signature path has two key sources")
        key_source = "STANDALONE"
        key = standalone_verification_key
        short_relation = "SVP-003"

    if len(signature) < 64:
        relation_id = short_relation
        backend_invocations = 0
    elif len(signature) > 64:
        # ACV-067 rejects this during request admission, before ACV-068.
        raise RequestRejected()
    elif key_source == "NONE":
        relation_id = "SVP-002"
        backend_invocations = 0
    else:
        if key is None or len(key) != 32:
            raise HarnessFailure("parsed signature key has an impossible length")
        backend = _load_pinned_c03_model(str(authority.repo_root))
        if not _prime_order_point(backend, key):
            relation_id = (
                "SVP-004"
                if key_source == "STANDALONE"
                else ("SVP-009" if operation == "VALIDATE_TRANSCRIPT" else "SVP-014")
            )
            backend_invocations = 0
        else:
            scalar = int.from_bytes(signature[32:], "little")
            if not _prime_order_point(backend, signature[:32]) or scalar >= backend._L:
                relation_id = (
                    "SVP-005"
                    if key_source == "STANDALONE"
                    else ("SVP-010" if operation == "VALIDATE_TRANSCRIPT" else "SVP-015")
                )
                backend_invocations = 0
            else:
                accepted = backend.ed25519_verify(key, signature, transcript)
                backend_invocations = 1
                if key_source == "STANDALONE":
                    relation_id = "SVP-007" if accepted else "SVP-006"
                elif operation == "VALIDATE_TRANSCRIPT":
                    relation_id = "SVP-012" if accepted else "SVP-011"
                else:
                    relation_id = "SVP-017" if accepted else "SVP-016"

    row = _signature_relation_row(authority, relation_id)
    expected = {
        "operation": operation,
        "candidateKind": candidate_kind,
        "keySource": key_source,
        "backendInvocations": backend_invocations,
        "authorityEffect": "NONE",
    }
    if any(row.get(name) != value for name, value in expected.items()):
        raise HarnessFailure("computed signature path violates the ratified relation")
    return SignaturePathResult(
        relation_id=relation_id,
        result_mapping=row["resultMapping"],
        signature_observation=row["signatureObservation"],
        backend_invocations=backend_invocations,
    )


def describe_profile(
    authority: ContractAuthority, profile: dict[str, Any]
) -> dict[str, Any]:
    """Return the closed profile result without probing runtime capability."""

    if profile == SUPPORTED_PROFILE:
        return {"descriptor": authority.descriptor(), "disposition": "SUPPORTED"}
    return {"disposition": "UNSUPPORTED"}


def read_bounded_request(stream: BinaryIO, *, maximum_octets: int | None) -> bytes:
    """Read at most ``maximum_octets + 1`` bytes from an untrusted stream.

    The literal maximum remains a ratified-contract input.  Absence is a
    harness failure, never an implementation-selected default.  Reading one
    sentinel octet is sufficient to distinguish the closed boundary without
    consuming an arbitrarily large input.
    """

    if maximum_octets is None or isinstance(maximum_octets, bool):
        raise HarnessFailure("outer request-octet limit is not ratified")
    if not isinstance(maximum_octets, int) or maximum_octets < 1:
        raise HarnessFailure("outer request-octet limit is invalid")
    remaining = maximum_octets + 1
    chunks: list[bytes] = []
    while remaining:
        chunk = stream.read(remaining)
        if not isinstance(chunk, bytes):
            raise HarnessFailure("request stream did not return bytes")
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > maximum_octets:
        raise RequestRejected()
    return raw


def admit_canonical_request(raw: bytes, *, maximum_octets: int | None) -> dict[str, Any]:
    """Apply the parameterized V1 envelope and canonical-JSON admission.

    Structural dispatch and semantic evaluation are deliberately later phases.
    No parser diagnostic is included in :class:`RequestRejected`.
    """

    if maximum_octets is None or isinstance(maximum_octets, bool):
        raise HarnessFailure("outer request-octet limit is not ratified")
    if not isinstance(maximum_octets, int) or maximum_octets < 1:
        raise HarnessFailure("outer request-octet limit is invalid")
    if len(raw) > maximum_octets:
        raise RequestRejected()
    try:
        value = canonical_loads(raw)
    except CanonicalJsonError as error:
        raise RequestRejected() from error
    if not isinstance(value, dict):
        raise RequestRejected()
    return value


def _validate_response_shape_and_relation(
    authority: ContractAuthority, response: dict[str, Any]
) -> None:
    """Validate the response schema and the two exact reason/stage relations.

    Reachability is deliberately not checked here.  The ACV-066 source mutant
    is defined as this otherwise-complete validator with only the separate
    reserved-reachability detector removed.
    """

    validator = Draft202012Validator(
        {
            "$schema": authority.schema["$schema"],
            "$ref": "#/$defs/InterfaceResponseV0",
            "$defs": authority.schema["$defs"],
        }
    )
    if not validator.is_valid(response):
        raise HarnessFailure("generated response violates the interface schema")
    operation = response["operation"]
    if operation not in {"VALIDATE_TRANSCRIPT", "EVALUATE_GENESIS"}:
        return
    relations = _read_json(
        authority.contract / "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"
    )
    field = (
        "transcriptReasonStageRelationV0"
        if operation == "VALIDATE_TRANSCRIPT"
        else "genesisReasonStageRelationV0"
    )
    result = response["result"]
    observed = (result["kind"], result.get("reason"), result["stage"])
    allowed = {
        (row["kind"], row.get("reason"), row["stage"])
        for row in relations[field]
    }
    if observed not in allowed:
        raise HarnessFailure("generated response violates the exact reason/stage relation")


def validate_response_before_release(
    authority: ContractAuthority, response: dict[str, Any]
) -> dict[str, Any]:
    """Fail closed before releasing any reserved reference-mismatch result."""

    _validate_response_shape_and_relation(authority, response)
    result = response.get("result", {})
    observations = result.get("observations", {})
    if result.get("reason") == "REFERENCE_MISMATCH" or observations.get(
        "referenceVerification"
    ) == "REJECTED":
        raise HarnessFailure("APP-core v0 reserved reference mismatch was generated")
    return response
