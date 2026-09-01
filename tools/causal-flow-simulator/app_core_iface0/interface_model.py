"""Pure APP-CORE-IFACE-0 reference model foundations.

The module implements only the serializable conformance data plane.  It does
not create an accepted context, authority capability, durable record, session
state, transport action, or product result.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
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
