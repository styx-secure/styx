"""Pure APP-CORE-IFACE-0 reference model foundations.

The module implements only the serializable conformance data plane.  It does
not create an accepted context, authority capability, durable record, session
state, transport action, or product result.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any, BinaryIO, Mapping

from jsonschema.exceptions import ValidationError
from jsonschema import validators
from jsonschema.validators import Draft202012Validator

from authority_projection import (
    AuthorityFold,
    AuthorityProjectionUnavailable,
    authority_ready_width,
    build_events,
    fold_authority,
)
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
IMPLEMENTED_COLLECTION_BOUND_TARGETS = frozenset(
    {
        "$defs.AliasGroupV0.allOf[0]",
        "$defs.ApplicationEventProjectionV0.causalParentReferences",
        "$defs.AuthorityAvailableV0.necessaryCredentialIdentifiers",
        "$defs.AuthorityAvailableV0.possibleCredentialIdentifiers",
        "$defs.AuthorityAvailableV0.terminalCredentialIdentifiers",
        "$defs.ContentMaterialEvidenceV0.segments",
        "$defs.ContextProjectionV0.aliasGroups",
        "$defs.ContextProjectionV0.appliedControlReferences",
        "$defs.ContextProjectionV0.contentStates",
        "$defs.ContextProjectionV0.credentialBindings",
        "$defs.ContextProjectionV0.eventAuthority",
        "$defs.ContextProjectionV0.forkJoins",
        "$defs.ContextProjectionV0.forkedCredentialIdentifiers",
        "$defs.ContextProjectionV0.pendingReferences",
        "$defs.ContextProjectionV0.pendingRootReferences",
        "$defs.ContextProjectionV0.recordOutcomes",
        "$defs.ContextProjectionV0.records",
        "$defs.ContextProjectionV0.reductionStandings",
        "$defs.ContextProjectionV0.replayDependencyReferences",
        "$defs.ContextProjectionV0.revokedCredentialIdentifiers",
        "$defs.ContextProjectionV0.terminatedCredentialIdentifiers",
        "$defs.EvidenceProjectionV0.contentMaterial",
        "$defs.EvidenceProjectionV0.openingMaterial",
        "$defs.ForkJoinProjectionV0.lineageClosureCredentialIdentifiers",
        "$defs.ForkJoinProjectionV0.siblingReferences",
        "$defs.ProposedContextSnapshotV0.admittedCandidates",
        "$defs.ReplayContextInputV0.candidates",
    }
)


class InterfaceModelError(ValueError):
    """The pinned contract/native authority or model input is inconsistent."""


class RequestRejected(ValueError):
    """A caller request is rejected with zero public response bytes."""


class HarnessFailure(RuntimeError):
    """The evidence harness is misconfigured or cannot complete safely."""


@dataclass(frozen=True)
class _V2BranchTrace:
    """Closed, test-internal trace of the single complete-root V2 traversal."""

    top_level_arm_index: int
    nested_operation_arm_index: int


class EvidenceError(ValueError):
    """One raw evidence set violates the closed O-04 conformance relation."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


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
    byte_size: int
    mutation_policy: str
    repin: Mapping[str, Any] | None


@dataclass(frozen=True)
class ReplayCandidate:
    """One canonically referenced, parsed application candidate."""

    candidate: dict[str, str]
    reference_hex: str
    transcript: bytes
    fields: dict[str, Any]


@dataclass(frozen=True)
class ProofGroupReduction:
    """Internal result of reducing one exact-transcript proof group.

    This value is deliberately not part of the serializable interface.  It
    authenticates only one occurrence of a logical transcript and carries no
    K-admission, AP-authority, persistence, or content-verification claim.
    """

    authenticated: bool
    diagnostic: str | None
    fields: Mapping[str, Any] | None
    reference_hex: str | None
    retained_signature_hex: str | None
    signature_attempts: int
    transcript: bytes | None


@dataclass(frozen=True)
class ReplayClosure:
    """Validated K closure ready for the independent AP/O-04 projection."""

    proposed_genesis: dict[str, Any]
    candidates: tuple[ReplayCandidate, ...]
    evidence: dict[str, Any]
    k_observations: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class ReplayProjection:
    """Internal deterministic replay state before public result assembly."""

    closure: ReplayClosure
    records: tuple[dict[str, Any], ...]
    content_states: tuple[dict[str, str], ...]
    pending_roots: frozenset[str]
    pending_references: frozenset[str]
    fork_relation: Mapping[tuple[str, int], tuple[str, ...]]
    fork_references: frozenset[str]
    fork_joins: tuple[dict[str, Any], ...]
    credential_bindings: tuple[dict[str, str], ...]
    credential_aliases: tuple[tuple[str, ...], ...]
    authority: AuthorityFold | None
    authority_unavailable_branch: str | None


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
    if not isinstance(rows, list) or len(rows) != 65:
        raise InterfaceModelError("native dependency relation must contain 65 rows")
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
                    byte_size=row["byteSize"],
                    mutation_policy=row["mutationPolicy"],
                    repin=row.get("repin"),
                )
            )
        except KeyError as error:
            raise InterfaceModelError("incomplete native dependency row") from error
    if len({row.path for row in result}) != len(result):
        raise InterfaceModelError("duplicate native dependency path")
    return tuple(result)


def verify_native_authority(repo_root: Path, contract: Path) -> None:
    """Verify Base authority and role-specific working-tree obligations."""

    root = repo_root.resolve()
    seeded_extension_paths = {
        "docs/protocol/review/README.md",
        "docs/protocol/review/styx-app-kernel-v0-review-model.json",
        "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json",
        "tools/protocol-review-model/validate.py",
    }
    ratified_exact_repins = {
        "tools/causal-flow-simulator/c03/corpus_model.py": (
            "Issue #295 comment 5550502736, amendment V3 sections 3.2, 3.4 and 4: "
            "separate logical K admission from O-04 content/opening availability "
            "while preserving the legacy evidence evaluator as an explicitly "
            "distinct path"
        ),
    }
    observed_repins: set[str] = set()
    for dependency in _dependency_rows(contract):
        path = root / dependency.path
        if not path.is_file() or path.is_symlink():
            raise InterfaceModelError(f"invalid native dependency: {dependency.path}")
        tree_entry = subprocess.run(
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
        if tree_entry.returncode != 0 or tree_entry.stdout != expected:
            raise InterfaceModelError(f"native dependency Git identity drift: {dependency.path}")
        base_blob = subprocess.run(
            ["git", "cat-file", "blob", dependency.git_blob_oid],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        if (
            base_blob.returncode != 0
            or len(base_blob.stdout) != dependency.byte_size
            or _sha256(base_blob.stdout) != dependency.sha256
        ):
            raise InterfaceModelError(
                f"native dependency Base bytes drift: {dependency.path}"
            )
        if dependency.mutation_policy == "READ_ONLY_BYTE_IDENTICAL":
            if dependency.repin is not None:
                raise InterfaceModelError(
                    f"unexpected native dependency repin: {dependency.path}"
                )
            if path.read_bytes() != base_blob.stdout:
                raise InterfaceModelError(
                    f"read-only native dependency drift: {dependency.path}"
                )
        elif dependency.mutation_policy == "SEEDED_EXTENSION_ONLY_PRESERVE_BASE_SEMANTICS":
            if dependency.repin is not None:
                raise InterfaceModelError(
                    f"unexpected seeded-extension repin: {dependency.path}"
                )
            if dependency.path not in seeded_extension_paths:
                raise InterfaceModelError(
                    f"unauthorized seeded-extension path: {dependency.path}"
                )
        elif dependency.mutation_policy == "RATIFIED_H12_H3_EXACT_REPIN":
            expected_reason = ratified_exact_repins.get(dependency.path)
            repin = dependency.repin
            if expected_reason is None or not isinstance(repin, Mapping):
                raise InterfaceModelError(
                    f"unauthorized exact native dependency repin: {dependency.path}"
                )
            if set(repin) != {
                "oldSha256",
                "newSha256",
                "newGitBlobOid",
                "newByteSize",
                "reason",
            }:
                raise InterfaceModelError(
                    f"malformed exact native dependency repin: {dependency.path}"
                )
            current = path.read_bytes()
            object_id = subprocess.run(
                ["git", "hash-object", "--stdin"],
                cwd=root,
                input=current,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            if (
                repin["oldSha256"] != dependency.sha256
                or repin["newSha256"] == dependency.sha256
                or repin["newSha256"] != _sha256(current)
                or repin["newByteSize"] != len(current)
                or object_id.returncode != 0
                or repin["newGitBlobOid"] != object_id.stdout.decode().strip()
                or repin["reason"] != expected_reason
            ):
                raise InterfaceModelError(
                    f"exact native dependency repin drift: {dependency.path}"
                )
            observed_repins.add(dependency.path)
        else:
            raise InterfaceModelError(
                f"unknown native dependency mutation policy: {dependency.path}"
            )
    if observed_repins != set(ratified_exact_repins):
        raise InterfaceModelError("ratified exact native dependency repin set drift")


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
        semantics = _read_json(
            package / "APP-CORE-IFACE-0-SEMANTIC-CONSTRAINTS-CANDIDATE.json"
        )
        collection_targets = {
            target
            for row in semantics.get("rules", [])
            if isinstance(row, dict)
            and row.get("rule")
            in {
                "ARRAY_COUNT_LIMIT_BEFORE_ITEM_WORK",
                "DERIVED_ARRAY_COUNT_LIMIT_BEFORE_ITEM_WORK",
            }
            for target in row.get("targets", [])
            if isinstance(target, str)
        }
        if collection_targets != IMPLEMENTED_COLLECTION_BOUND_TARGETS:
            raise InterfaceModelError("implemented collection-bound target set drift")
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


def _complete_v2_validator(
    schema: dict[str, Any],
) -> tuple[Draft202012Validator, dict[str, list[list[int]]]]:
    """Build one complete-root validator with its private oneOf branch recorder."""

    traces: dict[str, list[list[int]]] = {
        "top": [],
        "request": [],
        "response": [],
    }
    try:
        top_one_of = schema["oneOf"]
        request_one_of = schema["$defs"]["InterfaceRequestV0"]["oneOf"]
        response_one_of = schema["$defs"]["InterfaceResponseV0"]["oneOf"]
    except (KeyError, TypeError) as error:
        raise HarnessFailure("structural validation failed") from error
    if not all(
        isinstance(value, list)
        for value in (top_one_of, request_one_of, response_one_of)
    ):
        raise HarnessFailure("structural validation failed")

    def one_of_with_trace(validator: Any, one_of: Any, instance: Any, node: Any) -> Any:
        if not isinstance(one_of, list):
            yield ValidationError("oneOf is not an array")
            return
        errors: list[ValidationError] = []
        matching: list[int] = []
        baseline = {name: len(rows) for name, rows in traces.items()}
        successful_deltas: dict[int, dict[str, list[list[int]]]] = {}
        for index, arm in enumerate(one_of):
            for name, length in baseline.items():
                del traces[name][length:]
            arm_errors = list(validator.descend(instance, arm, schema_path=index))
            if arm_errors:
                errors.extend(arm_errors)
            else:
                matching.append(index)
                successful_deltas[index] = {
                    name: list(rows[baseline[name]:]) for name, rows in traces.items()
                }
        for name, length in baseline.items():
            del traces[name][length:]
        if len(matching) == 1:
            for name, rows in successful_deltas[matching[0]].items():
                traces[name].extend(rows)
        if one_of is top_one_of:
            traces["top"].append(matching)
        elif one_of is request_one_of:
            traces["request"].append(matching)
        elif one_of is response_one_of:
            traces["response"].append(matching)
        if not matching:
            yield ValidationError(
                f"{instance!r} is not valid under any of the given schemas",
                context=errors,
            )
        elif len(matching) != 1:
            yield ValidationError(
                f"{instance!r} is valid under multiple oneOf arms: {matching!r}"
            )

    def unsigned_maximum(
        validator: Any, maximum: Any, instance: Any, node: Any
    ) -> Any:
        if not isinstance(instance, str):
            return
        if not isinstance(maximum, str) or re.fullmatch(r"[0-9]+", maximum) is None:
            yield ValidationError("x-styx-unsigned-maximum is malformed")
            return
        if (
            re.fullmatch(r"(?:0|[1-9][0-9]*)", instance) is not None
            and int(instance) > int(maximum)
        ):
            yield ValidationError("unsigned decimal exceeds maximum")

    def full_string_pattern(
        validator: Any, pattern: Any, instance: Any, node: Any
    ) -> Any:
        if not isinstance(instance, str):
            return
        if not isinstance(pattern, str):
            yield ValidationError("pattern is malformed")
            return
        try:
            matched = (
                re.fullmatch(pattern, instance)
                if pattern.startswith("^") and pattern.endswith("$")
                else re.search(pattern, instance)
            )
        except re.error:
            yield ValidationError("pattern is malformed")
            return
        if matched is None:
            yield ValidationError("string does not match pattern")

    validator_class = validators.extend(
        Draft202012Validator,
        {
            "oneOf": one_of_with_trace,
            "pattern": full_string_pattern,
            "x-styx-unsigned-maximum": unsigned_maximum,
        },
    )
    return validator_class(schema), traces


def _validate_complete_v2_document(
    authority: ContractAuthority,
    document: Any,
    *,
    trusted_direction: str,
    schema_override: dict[str, Any] | None = None,
) -> _V2BranchTrace:
    """Validate once at the root, then bind its private trace to trusted API state."""

    schema = authority.schema if schema_override is None else schema_override
    validator, traces = _complete_v2_validator(schema)
    errors = list(validator.iter_errors(document))
    failure = RequestRejected if trusted_direction == "REQUEST" else HarnessFailure
    if errors:
        raise failure()
    if not isinstance(document, Mapping):
        raise failure()
    top_index = 0 if trusted_direction == "REQUEST" else 1
    operation = document.get("operation")
    if not isinstance(operation, str) or operation not in SUPPORTED_OPERATIONS:
        raise failure()
    operation_index = SUPPORTED_OPERATIONS.index(operation)
    nested_key = trusted_direction.lower()
    if traces["top"] != [[top_index]] or traces[nested_key] != [[operation_index]]:
        raise failure()
    other_key = "response" if nested_key == "request" else "request"
    if any(matches for matches in traces[other_key]):
        raise failure()
    return _V2BranchTrace(top_index, operation_index)


def _validate_structural_v2_evidence(
    authority: ContractAuthority,
    raw_document: bytes,
    *,
    trusted_direction: str,
    schema_override: dict[str, Any] | None = None,
    v1_detector_mutant: bool = False,
) -> _V2BranchTrace:
    """Run the production-faithful canonical V1 and complete V2 boundary."""

    failure = RequestRejected if trusted_direction == "REQUEST" else HarnessFailure
    try:
        if v1_detector_mutant:
            document = json.loads(raw_document.decode("utf-8", "strict"))
        else:
            document = canonical_loads(raw_document)
    except (CanonicalJsonError, UnicodeError, json.JSONDecodeError) as error:
        raise failure() from error
    if not isinstance(document, Mapping):
        raise failure()

    if trusted_direction == "REQUEST":
        _preflight_request_collections(authority, document)
    elif trusted_direction == "RESPONSE":
        result = document.get("result")
        successor: Any = None
        if isinstance(result, dict):
            if document.get("operation") == "REPLAY_CONTEXT":
                successor = result.get("proposedContext")
            elif isinstance(document.get("operation"), str) and document.get("operation") in {
                "EVALUATE_CANDIDATE",
                "EVALUATE_EVIDENCE_UPDATE",
            }:
                evaluation = result.get("evaluation")
                if isinstance(evaluation, dict):
                    proposal = evaluation.get("proposal")
                    if isinstance(proposal, dict):
                        successor = proposal.get("successor")
        _preflight_snapshot_collections(authority, successor, request_side=False)
    else:
        raise HarnessFailure("invalid structural-evidence direction")
    return _validate_complete_v2_document(
        authority,
        document,
        trusted_direction=trusted_direction,
        schema_override=schema_override,
    )


def _require_collection_bound(
    value: Any,
    maximum: int,
    *,
    label: str,
    request_side: bool,
) -> None:
    """Reject an over-bound array before inspecting any of its members."""

    if isinstance(value, list) and len(value) > maximum:
        if request_side:
            raise RequestRejected()
        raise HarnessFailure(f"generated response exceeds {label}")


def _preflight_evidence_collections(
    authority: ContractAuthority,
    evidence: Any,
    *,
    request_side: bool,
) -> None:
    if not isinstance(evidence, dict):
        return
    limits = {name: int(value) for name, value in authority.interface_limits().items()}
    content = evidence.get("contentMaterial")
    opening = evidence.get("openingMaterial")
    _require_collection_bound(
        content,
        limits["RECORDS"],
        label="EvidenceProjectionV0.contentMaterial/RECORDS",
        request_side=request_side,
    )
    _require_collection_bound(
        opening,
        limits["RECORDS"],
        label="EvidenceProjectionV0.openingMaterial/RECORDS",
        request_side=request_side,
    )
    if isinstance(content, list):
        for row in content:
            if isinstance(row, dict):
                _require_collection_bound(
                    row.get("segments"),
                    limits["CHUNKS_PER_CONTENT"],
                    label="ContentMaterialEvidenceV0.segments/CHUNKS_PER_CONTENT",
                    request_side=request_side,
                )


def _preflight_snapshot_collections(
    authority: ContractAuthority,
    snapshot: Any,
    *,
    request_side: bool,
) -> None:
    """Enforce every request/response-reachable ACV-008..012 array bound."""

    if not isinstance(snapshot, dict):
        return
    limits = {name: int(value) for name, value in authority.interface_limits().items()}
    records_limit = limits["RECORDS"]
    _require_collection_bound(
        snapshot.get("admittedCandidates"),
        records_limit,
        label="ProposedContextSnapshotV0.admittedCandidates/RECORDS",
        request_side=request_side,
    )
    _preflight_evidence_collections(
        authority, snapshot.get("evidence"), request_side=request_side
    )
    projection = snapshot.get("projection")
    if not isinstance(projection, dict):
        return

    field_limits = {
        "records": records_limit,
        "recordOutcomes": records_limit,
        "credentialBindings": records_limit + 1,
        "aliasGroups": (records_limit + 1) // 2,
        "appliedControlReferences": limits["CONTROL_EVENTS"],
        "reductionStandings": limits["CONTROL_EVENTS"],
        "eventAuthority": records_limit,
        "revokedCredentialIdentifiers": limits["CREDENTIALS"],
        "terminatedCredentialIdentifiers": limits["CREDENTIALS"],
        "forkedCredentialIdentifiers": limits["CREDENTIALS"],
        "forkJoins": limits["FORK_SLOTS"],
        "pendingRootReferences": limits["PENDING_ROOTS"],
        "pendingReferences": limits["PENDING_DESCENDANTS"],
        "contentStates": records_limit,
        "replayDependencyReferences": records_limit,
    }
    for field, maximum in field_limits.items():
        _require_collection_bound(
            projection.get(field),
            maximum,
            label=f"ContextProjectionV0.{field}",
            request_side=request_side,
        )

    records = projection.get("records")
    if isinstance(records, list):
        for row in records:
            if isinstance(row, dict):
                _require_collection_bound(
                    row.get("causalParentReferences"),
                    limits["PARENTS_PER_EVENT"],
                    label="ApplicationEventProjectionV0.causalParentReferences/PARENTS_PER_EVENT",
                    request_side=request_side,
                )

    alias_groups = projection.get("aliasGroups")
    if isinstance(alias_groups, list):
        total_members = 0
        for group in alias_groups:
            _require_collection_bound(
                group,
                records_limit + 1,
                label="AliasGroupV0/RECORDS+1",
                request_side=request_side,
            )
            if isinstance(group, list):
                total_members += len(group)
        if total_members > records_limit + 1:
            if request_side:
                raise RequestRejected()
            raise HarnessFailure("generated response exceeds alias-group membership bound")

    fork_joins = projection.get("forkJoins")
    if isinstance(fork_joins, list):
        for row in fork_joins:
            if not isinstance(row, dict):
                continue
            _require_collection_bound(
                row.get("siblingReferences"),
                limits["SIBLINGS_PER_FORK"],
                label="ForkJoinProjectionV0.siblingReferences/SIBLINGS_PER_FORK",
                request_side=request_side,
            )
            _require_collection_bound(
                row.get("lineageClosureCredentialIdentifiers"),
                limits["CREDENTIALS"],
                label="ForkJoinProjectionV0.lineageClosureCredentialIdentifiers/CREDENTIALS",
                request_side=request_side,
            )

    authority_projection = projection.get("authority")
    if isinstance(authority_projection, dict):
        for field in (
            "possibleCredentialIdentifiers",
            "necessaryCredentialIdentifiers",
            "terminalCredentialIdentifiers",
        ):
            _require_collection_bound(
                authority_projection.get(field),
                limits["CREDENTIALS"],
                label=f"AuthorityAvailableV0.{field}/CREDENTIALS",
                request_side=request_side,
            )


def _preflight_request_collections(
    authority: ContractAuthority, request: Mapping[str, Any]
) -> None:
    operation = request.get("operation")
    value = request.get("input")
    if not isinstance(value, dict):
        return
    limits = {name: int(item) for name, item in authority.interface_limits().items()}
    if operation == "REPLAY_CONTEXT":
        _require_collection_bound(
            value.get("candidates"),
            limits["RECORDS"],
            label="ReplayContextInputV0.candidates/RECORDS",
            request_side=True,
        )
        _preflight_evidence_collections(
            authority, value.get("evidence"), request_side=True
        )
    elif operation == "EVALUATE_CANDIDATE":
        _preflight_snapshot_collections(
            authority, value.get("prior"), request_side=True
        )
        _preflight_evidence_collections(
            authority, value.get("evidence"), request_side=True
        )
    elif operation == "EVALUATE_EVIDENCE_UPDATE":
        _preflight_snapshot_collections(
            authority, value.get("prior"), request_side=True
        )
        _preflight_evidence_collections(
            authority, value.get("additions"), request_side=True
        )


def validate_request_structure(
    authority: ContractAuthority, request: dict[str, Any]
) -> None:
    """Apply the closed request shape and scalar bounds without diagnostics."""

    if not isinstance(request, dict):
        raise RequestRejected()
    _preflight_request_collections(authority, request)
    request_input = request.get("input")
    if not isinstance(request_input, Mapping):
        raise RequestRejected()
    candidate = request_input.get("candidate")
    if isinstance(candidate, dict):
        signature = candidate.get("signatureHex")
        transcript = candidate.get("transcriptHex")
        # These character-count checks precede hex decoding and therefore do
        # not allocate proportional decoded buffers for over-bound values.
        if isinstance(signature, str) and len(signature) > 2 * int(
            authority.interface_limits()["SIGNATURE_OCTETS"]
        ):
            raise RequestRejected()
        if isinstance(transcript, str) and isinstance(
            candidate.get("objectKind"), str
        ):
            dimension = (
                "GENESIS_BODY_OCTETS"
                if candidate["objectKind"] == "GENESIS"
                else "FRAMING_OBJECT_OCTETS"
            )
            # ``transcriptHex`` carries the selected body plus the exact
            # 16-octet domain and 4-octet body-length prefix.  This check is
            # deliberately on the hex-text length, before decoding.
            maximum_hex_characters = 2 * (
                int(authority.interface_limits()[dimension]) + 20
            )
            if len(transcript) > maximum_hex_characters:
                raise RequestRejected()
    _validate_complete_v2_document(
        authority, request, trusted_direction="REQUEST"
    )
    profile = request["profile"]
    maxima = {
        "styxProtocolVersion": (1 << 16) - 1,
        "applicationProfileId": (1 << 32) - 1,
        "applicationProfileVersion": (1 << 32) - 1,
    }
    if any(int(profile[name]) > maximum for name, maximum in maxima.items()):
        raise RequestRejected()


def _initial_observations(*, transcript_valid: bool) -> dict[str, str]:
    return {
        "commitmentMatchVerification": "NOT_EVALUATED",
        "commitmentVerification": "NOT_EVALUATED",
        "geometryPredicate1": "NOT_EVALUATED",
        "geometryPredicate2": "NOT_EVALUATED",
        "geometryPredicate3": "NOT_EVALUATED",
        "geometryPredicate4": "NOT_EVALUATED",
        "geometryPredicate5": "NOT_EVALUATED",
        "geometryPredicate6": "NOT_EVALUATED",
        "geometryPredicate7": "NOT_EVALUATED",
        "referenceVerification": "NOT_REACHED",
        "signatureVerification": "NOT_EVALUATED",
        "suppliedLengthVerification": "NOT_EVALUATED",
        "transcriptVerification": "VALID" if transcript_valid else "REJECTED",
    }


def _content_observations(fields: dict[str, Any]) -> dict[str, str]:
    observations = _initial_observations(transcript_valid=True)
    content = fields.get("content")
    if not isinstance(content, dict) or content.get("class") == "NONE":
        observations.update(
            {
                "commitmentMatchVerification": "NOT_APPLICABLE",
                "commitmentVerification": "NOT_PRESENT",
                "suppliedLengthVerification": "NOT_APPLICABLE",
                **{
                    f"geometryPredicate{index}": "NOT_APPLICABLE"
                    for index in range(1, 8)
                },
            }
        )
        return observations
    observations["commitmentVerification"] = "PENDING"
    observations.update(content.get("geometryPredicateResults", {}))
    return observations


def _framing_failure(
    module: ModuleType, candidate_kind: str, transcript: bytes
) -> tuple[str, str] | None:
    expected_domain = (
        module.DOMAINS["genesis_signature"]
        if candidate_kind == "GENESIS"
        else module.DOMAINS["application"]
    )
    if len(transcript) < 16:
        return "TRANSCRIPT_LENGTH_MISMATCH", "OUTER_FRAMING"
    if transcript[:16] != expected_domain:
        return "TRANSCRIPT_DOMAIN_REJECTED", "OUTER_FRAMING"
    if len(transcript) < 20:
        return "TRANSCRIPT_LENGTH_MISMATCH", "OUTER_FRAMING"
    declared = int.from_bytes(transcript[16:20], "big")
    actual = len(transcript) - 20
    if declared > (1 << 32) - 21:
        return "TRANSCRIPT_LENGTH_REJECTED", "OUTER_FRAMING"
    if declared != actual:
        return "TRANSCRIPT_LENGTH_MISMATCH", "OUTER_FRAMING"
    return None


def _protocol_error_reason(code: str) -> tuple[str, str]:
    if code.startswith("TRUNCATED_"):
        return "TRANSCRIPT_TRUNCATED", "TRANSCRIPT_BODY"
    if code in {"TRAILING_BODY", "TRAILING_GEOMETRY"}:
        return "TRANSCRIPT_TRAILING_BYTES", "TRANSCRIPT_BODY"
    if code in {
        "CONTENT_CLASS_UNKNOWN",
        "CONTENT_DESCRIPTOR_INVALID",
        "NONE_DESCRIPTOR_INVALID",
        "CONTROL_CONTENT_FORBIDDEN",
        "ORDINARY_TAIL_FORBIDDEN",
    }:
        return "CONTENT_DESCRIPTOR_REJECTED", "TRANSCRIPT_BODY"
    if code in {
        "CHUNK_GEOMETRY_INVALID",
        "CONTENT_GEOMETRY_INVALID",
        "SINGLE_GEOMETRY_PRESENT",
        "TREE_GEOMETRY_MISSING",
    }:
        return "COMMITMENT_GEOMETRY_REJECTED", "TRANSCRIPT_BODY"
    if code in {
        "GENESIS_FIELDS_INVALID",
        "PREDECESSOR_PRESENCE_INVALID",
        "CAUSAL_FRONTIER_NONCANONICAL",
        "SEQUENCE_PREDECESSOR_MISMATCH",
        "PREDECESSOR_DUPLICATED_IN_FRONTIER",
        "UNSUPPORTED_PROFILE_OR_REGISTRY",
        "CONTROL_KIND_UNKNOWN",
        "GRANTEE_SUITE_UNSUPPORTED",
        "GRANTEE_KEY_LENGTH_INVALID",
        "EVENT_ROLE_UNKNOWN",
        "NONCANONICAL_REENCODING",
    }:
        return "TRANSCRIPT_NONCANONICAL", "TRANSCRIPT_BODY"
    raise HarnessFailure(f"unclassified pinned parser code: {code}")


def _selected_envelope_failure(
    module: ModuleType,
    candidate_kind: str,
    transcript: bytes,
    fields: dict[str, Any],
) -> str | None:
    """Return the first selected-envelope code in the ratified order.

    The canonical parser and reference derivation have already succeeded.
    ``PARENTS_PER_EVENT`` is intentionally absent: it remains an S4 replay
    dimension and is not part of transcript validation.
    """

    if candidate_kind == "GENESIS":
        failure = module._genesis_profile_failure(transcript, fields)
        if failure is None:
            return None
        if failure.code not in {
            "GENESIS_BODY_OCTETS_LIMIT",
            "GENESIS_POLICY_OCTETS_LIMIT",
        }:
            raise HarnessFailure(
                f"unexpected genesis selected-envelope code: {failure.code}"
            )
        return failure.code

    s3_failure, _ = module._event_profile_failures(transcript, fields)
    if s3_failure is None:
        return None
    expected = {
        "APPLICATION_PROFILE_MISMATCH",
        "FRAMING_OBJECT_OCTETS_LIMIT",
        "AP_TRANSITION_BLOCK_OCTETS_LIMIT",
        "VERIFICATION_KEY_OCTETS_LIMIT",
        "SEQUENCE_VALUE_LIMIT",
        "CHUNK_OCTETS_LIMIT",
        "CHUNKS_PER_CONTENT_LIMIT",
        "CONTENT_EXACT_OCTETS_LIMIT",
    }
    if s3_failure.code not in expected:
        raise HarnessFailure(
            f"unexpected application selected-envelope code: {s3_failure.code}"
        )
    return s3_failure.code


def _parse_transcript_candidate(
    authority: ContractAuthority, candidate: dict[str, str]
) -> tuple[ModuleType, bytes, bytes, dict[str, Any], dict[str, str]] | tuple[
    None, None, None, None, tuple[str, str, dict[str, str]]
]:
    module = _load_pinned_c03_model(str(authority.repo_root))
    transcript = bytes.fromhex(candidate["transcriptHex"])
    signature = bytes.fromhex(candidate["signatureHex"])
    observations = _initial_observations(transcript_valid=False)
    framing = _framing_failure(module, candidate["objectKind"], transcript)
    if framing is not None:
        return None, None, None, None, (*framing, observations)
    try:
        fields = (
            module.parse_genesis(transcript)
            if candidate["objectKind"] == "GENESIS"
            else module.parse_event(transcript)
        )
    except module.ProtocolError as error:
        reason, stage = _protocol_error_reason(error.code)
        observations.update(error.observations)
        return None, None, None, None, (reason, stage, observations)
    observations = _content_observations(fields)
    observations["referenceVerification"] = "VALID"
    return module, transcript, signature, fields, observations


def _reduce_application_proof_group(
    authority: ContractAuthority,
    group: Mapping[str, Any],
    verification_key_hex: str,
) -> ProofGroupReduction:
    """Reduce a bounded proof set for one exact application transcript.

    The caller is an internal K-binding resolver, never a public request.  A
    transported presentation identifier is intentionally unread here.  The
    proof-count guard precedes transcript decoding, hashing, key parsing and
    signature verification, as required by the H12/H3 amendment.
    """

    proofs = group.get("proofs")
    if not isinstance(proofs, list):
        return ProofGroupReduction(
            False, "STRUCTURAL_REJECTION", None, None, None, 0, None
        )
    if len(proofs) > _selected_limit(authority, "SIGNATURE_ATTEMPTS"):
        return ProofGroupReduction(
            False, "PROOF_GROUP_LIMIT_EXCEEDED", None, None, None, 0, None
        )

    module = _load_pinned_c03_model(str(authority.repo_root))
    try:
        if group["objectKind"] != "APPLICATION_EVENT":
            raise ValueError("wrong object kind")
        transcript = bytes.fromhex(group["transcriptHex"])
    except (KeyError, TypeError, ValueError):
        return ProofGroupReduction(
            False, "STRUCTURAL_REJECTION", None, None, None, 0, None
        )
    framing = _framing_failure(module, "APPLICATION_EVENT", transcript)
    if framing is not None:
        return ProofGroupReduction(
            False, "STRUCTURAL_REJECTION", None, None, None, 0, transcript
        )
    try:
        fields = module.parse_event(transcript)
    except module.ProtocolError:
        return ProofGroupReduction(
            False, "STRUCTURAL_REJECTION", None, None, None, 0, transcript
        )
    reference_hex = module.framed_hash(
        module.DOMAINS["event_reference"], transcript
    ).hex()
    if group.get("carriedReferenceHex") != reference_hex:
        return ProofGroupReduction(
            False,
            "CARRIED_REFERENCE_MISMATCH",
            fields,
            reference_hex,
            None,
            0,
            transcript,
        )

    try:
        verification_key = bytes.fromhex(verification_key_hex)
        signatures = [bytes.fromhex(row["signatureHex"]) for row in proofs]
    except (KeyError, TypeError, ValueError):
        return ProofGroupReduction(
            False,
            "STRUCTURAL_REJECTION",
            fields,
            reference_hex,
            None,
            0,
            transcript,
        )
    if len(verification_key) != 32 or any(len(value) != 64 for value in signatures):
        return ProofGroupReduction(
            False,
            "STRUCTURAL_REJECTION",
            fields,
            reference_hex,
            None,
            0,
            transcript,
        )

    attempts = 0
    for signature in sorted(signatures):
        attempts += 1
        if module.ed25519_verify(verification_key, signature, transcript):
            return ProofGroupReduction(
                True,
                None,
                fields,
                reference_hex,
                signature.hex(),
                attempts,
                transcript,
            )
    return ProofGroupReduction(
        False,
        "NO_VALID_PROOF",
        fields,
        reference_hex,
        None,
        attempts,
        transcript,
    )


def _rejected_transcript_result(
    reason: str, stage: str, observations: dict[str, str]
) -> dict[str, Any]:
    return {
        "kind": "REJECTED",
        "observations": observations,
        "reason": reason,
        "stage": stage,
    }


def validate_transcript(
    authority: ContractAuthority,
    profile: dict[str, str],
    value: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate one transcript candidate without creating K/AP authority."""

    if profile != SUPPORTED_PROFILE:
        return _rejected_transcript_result(
            "PROFILE_ACTIVATION_UNSUPPORTED",
            "PROFILE_SELECTION",
            _initial_observations(transcript_valid=False),
        )
    candidate = value["candidate"]
    parsed = _parse_transcript_candidate(authority, candidate)
    if parsed[0] is None:
        reason, stage, observations = parsed[4]
        return _rejected_transcript_result(reason, stage, observations)
    module, transcript, signature, fields, observations = parsed
    envelope_failure = _selected_envelope_failure(
        module, candidate["objectKind"], transcript, fields
    )
    if envelope_failure == "APPLICATION_PROFILE_MISMATCH":
        return _rejected_transcript_result(
            "TRANSCRIPT_PROFILE_MISMATCH", "PROFILE_ENVELOPE", observations
        )
    if envelope_failure is not None:
        return _rejected_transcript_result(
            "SELECTED_ENVELOPE_REJECTED", "PROFILE_ENVELOPE", observations
        )
    standalone = value.get("standaloneVerification")
    signature_path = evaluate_signature_path(
        authority,
        operation="VALIDATE_TRANSCRIPT",
        candidate_kind=candidate["objectKind"],
        transcript=transcript,
        signature=signature,
        standalone_verification_key=(
            bytes.fromhex(standalone["verificationKeyHex"])
            if standalone is not None
            else None
        ),
        parsed_genesis_root_key=(
            bytes.fromhex(fields["rootVerificationKeyHex"])
            if candidate["objectKind"] == "GENESIS"
            else None
        ),
    )
    observations["signatureVerification"] = signature_path.signature_observation
    if signature_path.result_mapping.startswith("TRS-001"):
        return {
            "kind": "VALIDATED",
            "observations": observations,
            "stage": "TRANSCRIPT_COMPLETE",
        }
    reason = {
        "TRS-012": "SIGNATURE_LENGTH_MISMATCH",
        "TRS-013": "SIGNATURE_INVALID",
        "TRS-014": "STANDALONE_VERIFICATION_KEY_REJECTED",
    }[signature_path.result_mapping]
    return _rejected_transcript_result(
        reason, "SIGNATURE_VERIFICATION", observations
    )


def evaluate_genesis(
    authority: ContractAuthority,
    profile: dict[str, str],
    value: dict[str, Any],
) -> dict[str, Any]:
    """Produce one non-authoritative genesis proposal or a closed terminal."""

    if profile != SUPPORTED_PROFILE:
        return {
            "kind": "TERMINAL_NO_PROPOSAL",
            "reason": "PROFILE_ACTIVATION_UNSUPPORTED",
            "stage": "PROFILE_SELECTION",
        }
    candidate = value["candidate"]
    parsed = _parse_transcript_candidate(authority, candidate)
    if parsed[0] is None:
        reason, stage, _ = parsed[4]
        return {"kind": "TERMINAL_NO_PROPOSAL", "reason": reason, "stage": stage}
    module, transcript, signature, fields, _ = parsed
    envelope_failure = _selected_envelope_failure(
        module, "GENESIS", transcript, fields
    )
    if envelope_failure is not None:
        return {
            "kind": "TERMINAL_NO_PROPOSAL",
            "reason": "SELECTED_ENVELOPE_REJECTED",
            "stage": "PROFILE_ENVELOPE",
        }
    expected_context = value["expectedContextIdentifierHex"]
    if fields["contextIdentifierHex"] != expected_context:
        return {
            "kind": "TERMINAL_NO_PROPOSAL",
            "reason": "EXPECTED_CONTEXT_MISMATCH",
            "stage": "CONTEXT_BINDING",
        }
    signature_path = evaluate_signature_path(
        authority,
        operation="EVALUATE_GENESIS",
        candidate_kind="GENESIS",
        transcript=transcript,
        signature=signature,
        parsed_genesis_root_key=bytes.fromhex(fields["rootVerificationKeyHex"]),
    )
    if not signature_path.result_mapping.startswith("GRS-001"):
        return {
            "kind": "TERMINAL_NO_PROPOSAL",
            "reason": (
                "SIGNATURE_LENGTH_MISMATCH"
                if signature_path.result_mapping == "GRS-012"
                else "SIGNATURE_INVALID"
            ),
            "stage": "SIGNATURE_VERIFICATION",
        }
    genesis_reference = module.framed_hash(
        module.DOMAINS["genesis_reference"], transcript
    ).hex()
    proposed = {
        "candidate": candidate,
        "expectedContextIdentifierHex": expected_context,
        "profile": profile,
        "projection": {
            "context": {
                **profile,
                "contextIdentifierHex": fields["contextIdentifierHex"],
            },
            "genesisReferenceHex": genesis_reference,
            "initialAuthorityPolicyBlockHex": fields["initialAuthorityPolicyHex"],
            "rootCredentialIdentifierHex": genesis_reference,
            "rootSignatureSuiteId": "1",
            "rootVerificationKeyHex": fields["rootVerificationKeyHex"],
        },
    }
    return {
        "kind": "GENESIS_PROPOSAL_READY",
        "proposedGenesis": proposed,
        "stage": "GENESIS_PROPOSAL_COMPLETE",
    }


def _replay_input_terminal(reason: str, stage: str) -> dict[str, str]:
    return {
        "kind": "TERMINAL_INPUT_REJECTED",
        "reason": reason,
        "stage": stage,
    }


def _candidate_terminal(primary: str, stage: str) -> dict[str, str]:
    return {
        "kind": "TERMINAL_CANDIDATE_REJECTED",
        "primary": primary,
        "stage": stage,
    }


def _content_descriptors(
    candidates: tuple[ReplayCandidate, ...],
) -> dict[str, Mapping[str, Any]]:
    return {
        candidate.reference_hex: candidate.fields["content"]
        for candidate in candidates
    }


def _selected_limit(authority: ContractAuthority, dimension: str) -> int:
    row = authority.resource_envelope.get("entries", {}).get(dimension)
    if not isinstance(row, dict):
        raise HarnessFailure(f"selected envelope has no dimension: {dimension}")
    value = row.get("selected_value")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise HarnessFailure(f"selected envelope dimension is not bounded: {dimension}")
    return value


def _canonicalize_evidence(
    evidence: Mapping[str, Any],
    descriptors: Mapping[str, Mapping[str, Any]],
    *,
    unknown_code: str = "UNKNOWN_EVENT_REFERENCE",
) -> dict[str, Any]:
    """Validate and canonicalize one purpose-separated raw evidence set.

    JSON Schema owns the closed outer shape.  This function owns ACV-026,
    ACV-039 and ACV-051: purpose keys are unique by event, segments are sorted,
    non-overlapping and inside the signed exact content domain, and ``NONE``
    events can never acquire content/opening material.
    """

    content_rows = evidence.get("contentMaterial")
    opening_rows = evidence.get("openingMaterial")
    if not isinstance(content_rows, list) or not isinstance(opening_rows, list):
        raise EvidenceError("NONCANONICAL_MATERIAL")

    canonical_content: list[dict[str, Any]] = []
    seen_content: set[str] = set()
    for row in content_rows:
        if not isinstance(row, dict):
            raise EvidenceError("NONCANONICAL_MATERIAL")
        reference = row.get("eventReferenceHex")
        descriptor = descriptors.get(reference)
        if descriptor is None:
            raise EvidenceError(unknown_code)
        if reference in seen_content:
            raise EvidenceError("CONFLICTING_DUPLICATE")
        seen_content.add(reference)
        if descriptor.get("class") == "NONE":
            raise EvidenceError("NONCANONICAL_MATERIAL")
        exact_length = descriptor.get("exactLength")
        if not isinstance(exact_length, int) or isinstance(exact_length, bool):
            raise HarnessFailure("parsed content descriptor has no exact length")
        segments = row.get("segments")
        if not isinstance(segments, list):
            raise EvidenceError("NONCANONICAL_MATERIAL")
        if not segments and exact_length != 0:
            raise EvidenceError("NONCANONICAL_MATERIAL")
        canonical_segments: list[dict[str, str]] = []
        previous_end = 0
        for index, segment in enumerate(segments):
            if not isinstance(segment, dict):
                raise EvidenceError("NONCANONICAL_MATERIAL")
            try:
                offset_text = segment["offset"]
                octets_hex = segment["octetsHex"]
                offset = int(offset_text)
                octet_count = len(bytes.fromhex(octets_hex))
            except (KeyError, TypeError, ValueError):
                raise EvidenceError("NONCANONICAL_MATERIAL") from None
            if offset_text != str(offset) or octet_count < 1:
                raise EvidenceError("NONCANONICAL_MATERIAL")
            end = offset + octet_count
            if end > exact_length:
                raise EvidenceError("NONCANONICAL_MATERIAL")
            if index and offset < previous_end:
                raise EvidenceError("PARTIAL_OVERLAP")
            previous_end = end
            canonical_segments.append(
                {"offset": str(offset), "octetsHex": octets_hex}
            )
        canonical_content.append(
            {
                "eventReferenceHex": reference,
                "segments": canonical_segments,
            }
        )

    canonical_opening: list[dict[str, str]] = []
    seen_opening: set[str] = set()
    for row in opening_rows:
        if not isinstance(row, dict):
            raise EvidenceError("NONCANONICAL_MATERIAL")
        reference = row.get("eventReferenceHex")
        descriptor = descriptors.get(reference)
        if descriptor is None:
            raise EvidenceError(unknown_code)
        if reference in seen_opening:
            raise EvidenceError("CONFLICTING_DUPLICATE")
        seen_opening.add(reference)
        if descriptor.get("class") == "NONE":
            raise EvidenceError("NONCANONICAL_MATERIAL")
        opening = row.get("openingRandomizerHex")
        if not isinstance(opening, str):
            raise EvidenceError("NONCANONICAL_MATERIAL")
        canonical_opening.append(
            {
                "eventReferenceHex": reference,
                "openingRandomizerHex": opening,
            }
        )

    canonical = {
        "contentMaterial": sorted(
            canonical_content, key=lambda row: row["eventReferenceHex"]
        ),
        "openingMaterial": sorted(
            canonical_opening, key=lambda row: row["eventReferenceHex"]
        ),
    }
    if evidence != canonical:
        raise EvidenceError("NONCANONICAL_MATERIAL")
    return canonical


def _complete_content_hex(
    row: Mapping[str, Any] | None, exact_length: int
) -> str | None:
    """Return exact tiled content, or ``None`` for absent/partial material."""

    if row is None:
        return None
    segments = row["segments"]
    cursor = 0
    parts: list[str] = []
    for segment in segments:
        if int(segment["offset"]) != cursor:
            return None
        parts.append(segment["octetsHex"])
        cursor += len(bytes.fromhex(segment["octetsHex"]))
    return "".join(parts) if cursor == exact_length else None


def merge_evidence_additions(
    prior: Mapping[str, Any],
    additions: Mapping[str, Any],
    descriptors: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], bool]:
    """Merge one ACV-035/038/065 monotone evidence addition.

    The return flag distinguishes an exact idempotent repeat from any genuine
    addition.  No presentation order chooses a winner and no prior byte can be
    deleted, replaced or partially overwritten.
    """

    canonical_prior = _canonicalize_evidence(prior, descriptors)
    canonical_additions = _canonicalize_evidence(additions, descriptors)
    if not canonical_additions["contentMaterial"] and not canonical_additions[
        "openingMaterial"
    ]:
        raise EvidenceError("EMPTY_ADDITION_SET")

    content: dict[str, list[dict[str, str]]] = {
        row["eventReferenceHex"]: [dict(segment) for segment in row["segments"]]
        for row in canonical_prior["contentMaterial"]
    }
    openings: dict[str, str] = {
        row["eventReferenceHex"]: row["openingRandomizerHex"]
        for row in canonical_prior["openingMaterial"]
    }
    changed = False
    for row in canonical_additions["contentMaterial"]:
        reference = row["eventReferenceHex"]
        existed = reference in content
        existing = content.setdefault(reference, [])
        if not existed:
            # For exact zero-length content, row presence with an empty segment
            # array is the material fact and is distinct from absence.
            changed = True
        for addition in row["segments"]:
            start = int(addition["offset"])
            end = start + len(bytes.fromhex(addition["octetsHex"]))
            exact = next(
                (
                    segment
                    for segment in existing
                    if segment["offset"] == addition["offset"]
                    and segment["octetsHex"] == addition["octetsHex"]
                ),
                None,
            )
            if exact is not None:
                continue
            for segment in existing:
                prior_start = int(segment["offset"])
                prior_end = prior_start + len(bytes.fromhex(segment["octetsHex"]))
                if start < prior_end and prior_start < end:
                    if start == prior_start and end == prior_end:
                        raise EvidenceError("CONFLICTING_DUPLICATE")
                    raise EvidenceError("PARTIAL_OVERLAP")
            existing.append(dict(addition))
            existing.sort(key=lambda segment: int(segment["offset"]))
            changed = True

    for row in canonical_additions["openingMaterial"]:
        reference = row["eventReferenceHex"]
        opening = row["openingRandomizerHex"]
        previous = openings.get(reference)
        if previous is None:
            openings[reference] = opening
            changed = True
        elif previous != opening:
            raise EvidenceError("CONFLICTING_DUPLICATE")

    merged = {
        "contentMaterial": [
            {"eventReferenceHex": reference, "segments": segments}
            for reference, segments in sorted(content.items())
        ],
        "openingMaterial": [
            {
                "eventReferenceHex": reference,
                "openingRandomizerHex": opening,
            }
            for reference, opening in sorted(openings.items())
        ],
    }
    # Re-run the complete canonical and exact-domain checks over the result;
    # this is intentionally not inferred from the two input validations.
    return _canonicalize_evidence(merged, descriptors), changed


def _candidate_records_for_k(
    proposed_genesis: Mapping[str, Any],
    candidates: tuple[ReplayCandidate, ...],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    genesis_projection = proposed_genesis["projection"]
    genesis_candidate = proposed_genesis["candidate"]
    genesis_record = {
        "kind": "GENESIS",
        "genesisReferenceHex": genesis_projection["genesisReferenceHex"],
        "signatureHex": genesis_candidate["signatureHex"],
        "transcriptHex": genesis_candidate["transcriptHex"],
    }
    records: list[dict[str, Any]] = []
    for candidate in candidates:
        record: dict[str, Any] = {
            "id": candidate.reference_hex,
            "kind": "APPLICATION_EVENT",
            "eventReferenceHex": candidate.reference_hex,
            "signatureHex": candidate.candidate["signatureHex"],
            "transcriptHex": candidate.candidate["transcriptHex"],
        }
        records.append(record)
    return genesis_record, records


def _project_content_states(
    authority: ContractAuthority,
    candidates: tuple[ReplayCandidate, ...],
    evidence: Mapping[str, Any],
    *,
    logically_removed: frozenset[str] = frozenset(),
) -> tuple[list[dict[str, str]], frozenset[str]]:
    """Recompute the exact five-axis O-04 state for every retained record."""

    module = _load_pinned_c03_model(str(authority.repo_root))
    content_by_reference = {
        row["eventReferenceHex"]: row for row in evidence["contentMaterial"]
    }
    opening_by_reference = {
        row["eventReferenceHex"]: row for row in evidence["openingMaterial"]
    }
    rows: list[dict[str, str]] = []
    pending_roots: set[str] = set()
    for candidate in candidates:
        reference = candidate.reference_hex
        fields = candidate.fields
        descriptor = fields["content"]
        content_class = descriptor["class"]
        material = content_by_reference.get(reference)
        opening = opening_by_reference.get(reference)
        if content_class == "NONE":
            availability = "ABSENT"
            observation = "NOT_APPLICABLE"
            readiness = "READY"
        else:
            complete = _complete_content_hex(material, descriptor["exactLength"])
            availability = (
                "ABSENT"
                if material is None
                else "PRESENT"
                if complete is not None
                else "PARTIAL"
            )
            if availability != "PRESENT":
                observation = "NOT_CHECKED"
            elif opening is None:
                observation = "OPENING_MISSING"
            else:
                commitment = module.encode_commitment(
                    profile_id=fields["applicationProfileId"],
                    profile_version=fields["applicationProfileVersion"],
                    context=bytes.fromhex(fields["contextIdentifierHex"]),
                    credential=bytes.fromhex(fields["credentialIdentifierHex"]),
                    sequence=fields["authorSequence"],
                    content_type=descriptor["contentType"],
                    content=bytes.fromhex(complete),
                    randomizer=bytes.fromhex(opening["openingRandomizerHex"]),
                    chunk_size=(descriptor.get("geometry") or {}).get("chunkSize"),
                )
                observation = (
                    "VERIFIED"
                    if commitment["commitmentHex"] == descriptor["commitmentHex"]
                    else "COMMITMENT_MISMATCH"
                )
            readiness = (
                "READY"
                if content_class == "DETACHABLE" or observation == "VERIFIED"
                else "CONTENT_DEFERRED"
            )
            if readiness == "CONTENT_DEFERRED":
                pending_roots.add(reference)
        retention = (
            "LOGICALLY_REMOVED" if reference in logically_removed else "ACTIVE"
        )
        if retention == "LOGICALLY_REMOVED" and content_class != "DETACHABLE":
            raise HarnessFailure("logical removal selected a non-detachable record")
        rows.append(
            {
                "bindingObservation": observation,
                "contentClass": content_class,
                "eventReferenceHex": reference,
                "localAvailability": availability,
                "replayReadiness": readiness,
                "retentionState": retention,
            }
        )

    relations = _read_json(
        authority.contract / "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"
    )
    legal = {
        (
            row["contentClass"],
            row["localAvailability"],
            row["bindingObservation"],
            row["retentionState"],
            row["replayReadiness"],
        )
        for row in relations["contentAxisLegalRelationV0"]
    }
    for row in rows:
        observed = (
            row["contentClass"],
            row["localAvailability"],
            row["bindingObservation"],
            row["retentionState"],
            row["replayReadiness"],
        )
        if observed not in legal:
            raise HarnessFailure("derived O-04 state violates the exact axis relation")
    return sorted(rows, key=lambda row: row["eventReferenceHex"]), frozenset(
        pending_roots
    )


def _role_tail_projection(fields: Mapping[str, Any]) -> dict[str, str]:
    role = fields["eventRole"]
    if role == "ORDINARY":
        return {"kind": "ORDINARY"}
    tail = fields.get("tail")
    if not isinstance(tail, dict):
        raise HarnessFailure("parsed non-ordinary event has no role tail")
    if role == "REMOVAL":
        return {
            "kind": "LOGICAL_REMOVAL",
            "targetCommitmentHex": tail["targetCommitmentHex"],
            "targetEventReferenceHex": tail["targetEventReferenceHex"],
        }
    kind = tail["kind"]
    if kind == "GRANT":
        return {
            "granteeSignatureSuiteId": "1",
            "granteeVerificationKeyHex": tail["granteeVerificationKeyHex"],
            "kind": "GRANT",
        }
    if kind == "REVOKE":
        return {
            "kind": "REVOKE",
            "targetCredentialIdentifierHex": tail["targetCredentialHex"],
        }
    if kind == "ROTATE":
        return {
            "kind": "ROTATE",
            "replacementGrantReferenceHex": tail["replacementGrantHex"],
            "retiringCredentialIdentifierHex": tail["retiringCredentialHex"],
        }
    if kind == "RECOVER":
        return {
            "kind": "RECOVER",
            "recoveryGrantReferenceHex": tail["recoveryGrantHex"],
            "retiredCredentialIdentifierHex": tail["retiredCredentialHex"],
        }
    if kind in {"POLICY", "CLOSURE"}:
        return {"kind": kind}
    raise HarnessFailure("parsed credential-control kind is not closed")


def _event_projection(
    candidate: ReplayCandidate,
    *,
    fork_references: frozenset[str],
    pending_references: frozenset[str],
    pending_roots: frozenset[str],
) -> dict[str, Any]:
    fields = candidate.fields
    content = fields["content"]
    if content["class"] == "NONE":
        descriptor: dict[str, Any] = {
            "contentClass": "NONE",
            "exactContentLength": "0",
        }
    else:
        descriptor = {
            "commitmentShape": (
                "SINGLE" if content["shape"] == "SINGLE" else "CHUNK_TREE"
            ),
            "commitmentSuiteId": "1",
            "commitmentValueHex": content["commitmentHex"],
            "contentClass": content["class"],
            "contentTypeIdentifier": str(content["contentType"]),
            "exactContentLength": str(content["exactLength"]),
        }
        if content["shape"] == "TREE":
            geometry = content["geometry"]
            descriptor["chunkGeometry"] = {
                "chunkCount": str(geometry["chunkCount"]),
                "chunkSize": str(geometry["chunkSize"]),
                "finalChunkLength": str(geometry["finalChunkLength"]),
            }
    role = {
        "ORDINARY": "ORDINARY",
        "REMOVAL": "LOGICAL_REMOVAL",
        "CREDENTIAL": "CREDENTIAL_CONTROL",
    }[fields["eventRole"]]
    reference = candidate.reference_hex
    projected: dict[str, Any] = {
        "apTransitionBlockHex": fields["transitionBlockHex"],
        "applicationProfileId": str(fields["applicationProfileId"]),
        "applicationProfileVersion": str(fields["applicationProfileVersion"]),
        "authorSequence": str(fields["authorSequence"]),
        "causalParentReferences": list(fields["causalParents"]),
        "contentDescriptor": descriptor,
        "contextIdentifierHex": fields["contextIdentifierHex"],
        "credentialIdentifierHex": fields["credentialIdentifierHex"],
        "eventReferenceHex": reference,
        "eventRole": role,
        "eventTypeIdentifier": str(fields["eventTypeId"]),
        "genesisReferenceHex": fields["genesisReferenceHex"],
        "kAdmission": (
            "FORK_CLASSIFIED" if reference in fork_references else "ADMITTED"
        ),
        "objectKind": "APPLICATION_EVENT",
        "replayReadiness": (
            "PENDING_OPENING"
            if reference in pending_roots
            else "PENDING_ANCESTOR"
            if reference in pending_references
            else "READY_FOR_AP_FOLD"
        ),
        "roleTail": _role_tail_projection(fields),
        "schemaIdentifier": str(fields["schemaId"]),
        "schemaVersion": str(fields["schemaVersion"]),
        "styxProtocolVersion": "1",
    }
    if fields["directPredecessorHex"] is not None:
        projected["directPredecessorReferenceHex"] = fields[
            "directPredecessorHex"
        ]
    return projected


def _protocol_k_order(
    candidates: tuple[ReplayCandidate, ...],
) -> tuple[ReplayCandidate, ...]:
    """Return the K-06 greedy, reference-tiebroken topological schedule."""

    by_reference = {candidate.reference_hex: candidate for candidate in candidates}
    if len(by_reference) != len(candidates):
        raise HarnessFailure("protocol K order received duplicate references")
    remaining = set(by_reference)
    emitted: set[str] = set()
    ordered: list[ReplayCandidate] = []
    while remaining:
        ready = []
        for reference in remaining:
            fields = by_reference[reference].fields
            dependencies = set(fields["causalParents"])
            if fields["directPredecessorHex"] is not None:
                dependencies.add(fields["directPredecessorHex"])
            if not dependencies <= set(by_reference):
                raise HarnessFailure("protocol K order has a non-live dependency")
            if dependencies <= emitted:
                ready.append(reference)
        if not ready:
            raise HarnessFailure("protocol K order cannot complete a cyclic graph")
        selected = min(ready)
        remaining.remove(selected)
        emitted.add(selected)
        ordered.append(by_reference[selected])
    return tuple(ordered)


def _causal_ancestors(
    candidates: tuple[ReplayCandidate, ...],
) -> dict[str, frozenset[str]]:
    """Return the exact transitive live K ancestry for every retained record."""

    by_reference = {candidate.reference_hex: candidate for candidate in candidates}
    ancestors: dict[str, set[str]] = {}
    for candidate in candidates:
        fields = candidate.fields
        direct = set(fields["causalParents"])
        if fields["directPredecessorHex"] is not None:
            direct.add(fields["directPredecessorHex"])
        if not direct <= set(by_reference):
            raise HarnessFailure("K-admitted closure contains a non-live dependency")
        ancestors[candidate.reference_hex] = direct
    changed = True
    while changed:
        changed = False
        for reference, values in ancestors.items():
            expanded = set(values)
            for dependency in values:
                expanded.update(ancestors[dependency])
            if reference in expanded:
                raise HarnessFailure("K-admitted closure contains a causal cycle")
            if expanded != values:
                ancestors[reference] = expanded
                changed = True
    return {
        reference: frozenset(values)
        for reference, values in sorted(ancestors.items())
    }


def _fork_slots(
    authority: ContractAuthority,
    candidates: tuple[ReplayCandidate, ...],
) -> tuple[dict[tuple[str, int], tuple[str, ...]], frozenset[str]]:
    slots: dict[tuple[str, int], list[str]] = {}
    for candidate in candidates:
        fields = candidate.fields
        slots.setdefault(
            (fields["credentialIdentifierHex"], fields["authorSequence"]), []
        ).append(candidate.reference_hex)
    forks = {
        slot: tuple(sorted(references))
        for slot, references in slots.items()
        if len(references) >= 2
    }
    fork_references = frozenset(
        reference for references in forks.values() for reference in references
    )
    return dict(sorted(forks.items())), fork_references


def _pending_sets(
    candidates: tuple[ReplayCandidate, ...],
    pending_candidates: frozenset[str],
) -> tuple[frozenset[str], frozenset[str]]:
    """Split pending records into minimal roots and their causal descendants."""

    ancestors = _causal_ancestors(candidates)
    candidate_references = {candidate.reference_hex for candidate in candidates}
    if not pending_candidates <= candidate_references:
        raise HarnessFailure("pending classification names a non-live record")
    pending_roots = frozenset(
        reference
        for reference in pending_candidates
        if not (ancestors[reference] & pending_candidates)
    )
    descendants = {
        candidate.reference_hex
        for candidate in candidates
        if candidate.reference_hex not in pending_roots
        and ancestors[candidate.reference_hex] & pending_roots
    }
    if not pending_candidates <= pending_roots | descendants:
        raise HarnessFailure("pending-root minimization dropped a pending record")
    return pending_roots, frozenset(descendants)


def _replay_graph_capacity_failure(
    authority: ContractAuthority,
    candidates: tuple[ReplayCandidate, ...],
    unverified_required: frozenset[str],
) -> dict[str, str] | None:
    """Apply the five reachable V14 S4 rows in literal first-failure order."""

    limits = {key: int(value) for key, value in authority.interface_limits().items()}
    parent_offenders = sorted(
        candidate.reference_hex
        for candidate in candidates
        if len(candidate.fields["causalParents"]) > limits["PARENTS_PER_EVENT"]
    )
    if parent_offenders:
        return _candidate_terminal(
            "CONTEXT_CAPACITY_EXHAUSTED",
            "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT",
        )

    ancestors = _causal_ancestors(candidates)
    frontier = sorted(
        candidate.reference_hex
        for candidate in candidates
        if not any(
            candidate.reference_hex in other_ancestors
            for other_reference, other_ancestors in ancestors.items()
            if other_reference != candidate.reference_hex
        )
    )
    if len(frontier) > limits["ACTIVE_FRONTIER"]:
        return _candidate_terminal(
            "CONTEXT_CAPACITY_EXHAUSTED",
            "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT",
        )

    by_actor: dict[str, list[str]] = {}
    for candidate in candidates:
        by_actor.setdefault(
            candidate.fields["credentialIdentifierHex"], []
        ).append(candidate.reference_hex)
    evidence_offenders = sorted(
        reference
        for references in by_actor.values()
        if len(references) > limits["EVIDENCE_PER_CREDENTIAL"]
        for reference in references
    )
    if evidence_offenders:
        return _candidate_terminal(
            "CONTEXT_CAPACITY_EXHAUSTED",
            "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT",
        )

    if len(candidates) > limits["RECORDS"]:
        return _candidate_terminal(
            "CONTEXT_CAPACITY_EXHAUSTED",
            "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT",
        )

    if len(unverified_required) > limits["PENDING_ROOTS"]:
        return _candidate_terminal(
            "DEPENDENCY_DEFERRED",
            "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT",
        )
    return None


def _verify_k_projection_cross_checks(
    closure: ReplayClosure,
    *,
    fork_references: frozenset[str],
) -> None:
    """Prove K diagnostics without importing O-04 pending state."""

    observations = {
        row["eventReferenceHex"]: row for row in closure.k_observations
    }
    for candidate in closure.candidates:
        reference = candidate.reference_hex
        observation = observations[reference]
        if observation["kBindingAdmission"] != "ADMITTED":
            raise HarnessFailure("projection consumed a non-admitted K record")
        expected = "FORK_EVIDENCE" if reference in fork_references else None
        if observation["protocolErrorCode"] != expected:
            raise HarnessFailure(
                "independent K classification disagrees with replay projection"
            )


def _credential_projection(
    authority: ContractAuthority,
    proposed_genesis: Mapping[str, Any],
    candidates: tuple[ReplayCandidate, ...],
) -> tuple[
    list[dict[str, str]],
    list[list[str]],
    dict[str, tuple[str | None, str]],
]:
    """Derive grant-rooted bindings, visible aliases and issuer edges."""

    genesis = proposed_genesis["projection"]
    root = genesis["rootCredentialIdentifierHex"]
    bindings: dict[str, dict[str, str]] = {
        root: {
            "credentialIdentifierHex": root,
            "origin": "GENESIS",
            "signatureSuiteId": genesis["rootSignatureSuiteId"],
            "verificationKeyHex": genesis["rootVerificationKeyHex"],
        }
    }
    lineage: dict[str, tuple[str | None, str]] = {root: (None, root)}
    pending_grants = {
        candidate.reference_hex: candidate
        for candidate in candidates
        if candidate.fields["eventRole"] == "CREDENTIAL"
        and candidate.fields.get("tail", {}).get("kind") == "GRANT"
    }
    while pending_grants:
        ready = sorted(
            reference
            for reference, candidate in pending_grants.items()
            if candidate.fields["credentialIdentifierHex"] in bindings
        )
        if not ready:
            raise HarnessFailure("K admitted a grant with no issuer binding")
        for reference in ready:
            candidate = pending_grants.pop(reference)
            fields = candidate.fields
            tail = fields["tail"]
            if reference in bindings:
                raise HarnessFailure("K admitted a colliding credential identifier")
            issuer = fields["credentialIdentifierHex"]
            bindings[reference] = {
                "credentialIdentifierHex": reference,
                "grantReferenceHex": reference,
                "issuerCredentialIdentifierHex": issuer,
                "origin": "GRANT",
                "signatureSuiteId": "1",
                "verificationKeyHex": tail["granteeVerificationKeyHex"],
            }
            lineage[reference] = (issuer, reference)

    for credential in bindings:
        depth = 0
        seen: set[str] = set()
        cursor = credential
        while lineage[cursor][0] is not None:
            if cursor in seen:
                raise HarnessFailure("credential lineage contains a cycle")
            seen.add(cursor)
            cursor = lineage[cursor][0] or ""
            if cursor not in lineage:
                raise HarnessFailure("credential lineage issuer is absent")
            depth += 1

    aliases: dict[tuple[str, str], list[str]] = {}
    for credential, binding in bindings.items():
        aliases.setdefault(
            (binding["signatureSuiteId"], binding["verificationKeyHex"]), []
        ).append(credential)
    alias_groups = sorted(
        [sorted(group) for group in aliases.values() if len(group) >= 2]
    )
    return (
        [bindings[credential] for credential in sorted(bindings)],
        alias_groups,
        lineage,
    )


def _lineage_descendants(
    lineage: Mapping[str, tuple[str | None, str]], roots: set[str] | frozenset[str]
) -> frozenset[str]:
    descendants = set(roots)
    changed = True
    while changed:
        changed = False
        for credential, (issuer, _) in lineage.items():
            if issuer in descendants and credential not in descendants:
                descendants.add(credential)
                changed = True
    return frozenset(descendants)


def _branch_a_capacity_crossed(
    authority: ContractAuthority,
    fork_relation: Mapping[tuple[str, int], tuple[str, ...]],
    credential_bindings: list[dict[str, str]],
    credential_aliases: list[list[str]],
    lineage: Mapping[str, tuple[str | None, str]],
    candidates: tuple[ReplayCandidate, ...],
) -> bool:
    limits = {key: int(value) for key, value in authority.interface_limits().items()}
    maximum_depth = 0
    for credential in lineage:
        depth = 0
        cursor = credential
        seen: set[str] = set()
        while lineage[cursor][0] is not None:
            if cursor in seen:
                raise HarnessFailure("credential lineage contains a cycle")
            seen.add(cursor)
            parent = lineage[cursor][0]
            if parent is None or parent not in lineage:
                raise HarnessFailure("credential lineage issuer is absent")
            cursor = parent
            depth += 1
        maximum_depth = max(maximum_depth, depth)
    quantities = {
        "ACTORS": len(
            {candidate.fields["credentialIdentifierHex"] for candidate in candidates}
        ),
        "ALIASES_PER_CREDENTIAL": max(
            (len(group) for group in credential_aliases), default=0
        ),
        "CREDENTIALS": len(credential_bindings),
        "FORK_SLOTS": len(fork_relation),
        "LINEAGE_DEPTH": maximum_depth,
        "SIBLINGS_PER_FORK": max(
            (len(set(references)) for references in fork_relation.values()), default=0
        ),
    }
    return any(quantities[name] > limits[name] for name in quantities)


_FORK_JOIN_DOMAIN = b"STYX-APP-CORE-IFACE-0-FORK-JOIN-V0"


def _fork_join_projection(
    authority: ContractAuthority,
    fork_relation: Mapping[tuple[str, int], tuple[str, ...]],
    lineage: Mapping[str, tuple[str | None, str]],
    candidates: tuple[ReplayCandidate, ...],
) -> tuple[dict[str, Any], ...]:
    """Derive the exact V9 conformance-plane fork/join label relation."""

    sibling_limit = _selected_limit(authority, "SIBLINGS_PER_FORK")
    event_references = {candidate.reference_hex for candidate in candidates}
    credential_identifiers = set(lineage)
    rows: list[dict[str, Any]] = []
    preimages: dict[str, bytes] = {}
    for (credential, sequence), supplied_siblings in sorted(fork_relation.items()):
        siblings = tuple(sorted(set(supplied_siblings)))
        if (
            siblings != supplied_siblings
            or len(siblings) < 2
            or len(siblings) > sibling_limit
            or not set(siblings) <= event_references
        ):
            raise HarnessFailure("fork slot is not the exact bounded sibling set")
        if credential not in credential_identifiers:
            raise HarnessFailure("fork slot credential has no grant-rooted binding")
        if sequence < 0 or sequence >= 1 << 64:
            raise HarnessFailure("fork slot author sequence is outside u64")
        preimage = b"".join(
            (
                _FORK_JOIN_DOMAIN,
                b"\x00",
                bytes.fromhex(credential),
                sequence.to_bytes(8, "big"),
                len(siblings).to_bytes(4, "big"),
                *(bytes.fromhex(reference) for reference in siblings),
            )
        )
        label = hashlib.sha256(preimage).hexdigest()
        prior = preimages.get(label)
        if prior is not None and prior != preimage:
            raise HarnessFailure("distinct fork/join preimages collide")
        if label in event_references or label in credential_identifiers:
            raise HarnessFailure("fork/join label crossed into a reference domain")
        preimages[label] = preimage
        rows.append(
            {
                "authorSequence": str(sequence),
                "credentialIdentifierHex": credential,
                "joinLabelHex": label,
                "lineageClosureCredentialIdentifiers": sorted(
                    _lineage_descendants(lineage, {credential})
                ),
                "siblingReferences": list(siblings),
            }
        )
    rows.sort(key=lambda row: row["joinLabelHex"])
    if len({row["joinLabelHex"] for row in rows}) != len(rows):
        raise HarnessFailure("fork/join labels are not unique")
    return tuple(rows)


def prepare_replay_closure(
    authority: ContractAuthority,
    profile: dict[str, str],
    value: Mapping[str, Any],
) -> ReplayClosure | dict[str, str]:
    """Revalidate and retain the complete raw K closure.

    This is the shared security-critical prefix for all three stateful
    operations.  It deliberately stops before AP/O-04 projection, so a partial
    implementation cannot be dispatched as a successful public replay.
    """

    proposed_genesis = value["proposedGenesis"]
    if profile != SUPPORTED_PROFILE or proposed_genesis["profile"] != profile:
        return _replay_input_terminal("PROFILE_MISMATCH", "PROFILE_SELECTION")
    regenerated = evaluate_genesis(
        authority,
        profile,
        {
            "candidate": proposed_genesis["candidate"],
            "expectedContextIdentifierHex": proposed_genesis[
                "expectedContextIdentifierHex"
            ],
        },
    )
    if (
        regenerated.get("kind") != "GENESIS_PROPOSAL_READY"
        or regenerated.get("proposedGenesis") != proposed_genesis
    ):
        return _replay_input_terminal(
            "GENESIS_REVALIDATION_FAILED", "GENESIS_REVALIDATION"
        )

    module = _load_pinned_c03_model(str(authority.repo_root))
    parsed_candidates: list[ReplayCandidate] = []
    for candidate in value["candidates"]:
        transcript = bytes.fromhex(candidate["transcriptHex"])
        reference = module.framed_hash(
            module.DOMAINS["event_reference"], transcript
        ).hex()
        try:
            fields = module.parse_event(transcript)
        except module.ProtocolError as error:
            return _candidate_terminal("STRUCTURAL_REJECTION", error.stage)
        parsed_candidates.append(
            ReplayCandidate(candidate, reference, transcript, fields)
        )

    references = [candidate.reference_hex for candidate in parsed_candidates]
    if len(set(references)) != len(references):
        return _replay_input_terminal(
            "DUPLICATE_CANDIDATE_REFERENCE", "CANDIDATE_SET_VALIDATION"
        )
    if references != sorted(references):
        return _replay_input_terminal(
            "CANDIDATE_SET_NONCANONICAL", "CANDIDATE_SET_VALIDATION"
        )
    candidates = tuple(parsed_candidates)
    try:
        evidence = _canonicalize_evidence(
            value["evidence"], _content_descriptors(candidates)
        )
    except EvidenceError as error:
        reason = (
            "UNKNOWN_EVIDENCE_REFERENCE"
            if error.code == "UNKNOWN_EVENT_REFERENCE"
            else "EVIDENCE_NONCANONICAL"
        )
        return _replay_input_terminal(reason, "EVIDENCE_VALIDATION")

    genesis_record, records = _candidate_records_for_k(proposed_genesis, candidates)
    try:
        observations = module.evaluate_logical_k_admission_graph(
            genesis_record, records
        )
    except module.ProtocolError as error:
        raise HarnessFailure(
            f"complete K graph rejected its revalidated genesis: {error.code}"
        ) from error
    observation_by_reference = {
        row["eventReferenceHex"]: row for row in observations
    }
    for candidate in candidates:
        observation = observation_by_reference.get(candidate.reference_hex)
        if observation is None:
            raise HarnessFailure("complete K graph silently dropped a candidate")
        if observation["kBindingAdmission"] != "ADMITTED":
            return _candidate_terminal(
                observation["protocolErrorCode"], observation["stage"]
            )
    return ReplayClosure(
        proposed_genesis=proposed_genesis,
        candidates=candidates,
        evidence=evidence,
        k_observations=tuple(observations),
    )


def project_replay_state(
    authority: ContractAuthority,
    profile: dict[str, str],
    value: Mapping[str, Any],
) -> ReplayProjection | dict[str, str]:
    """Build the complete ratified internal replay prefix.

    The function combines K admission, O-04 pending classification, the exact
    fork/join-label relation and the independent Pass-0 authority fold.
    """

    closure = prepare_replay_closure(authority, profile, value)
    if isinstance(closure, dict):
        return closure
    content_states, pending_root_references = _project_content_states(
        authority, closure.candidates, closure.evidence
    )
    capacity_failure = _replay_graph_capacity_failure(
        authority, closure.candidates, pending_root_references
    )
    if capacity_failure is not None:
        return capacity_failure
    pending_roots, pending_references = _pending_sets(
        closure.candidates, pending_root_references
    )
    fork_relation, fork_references = _fork_slots(
        authority, closure.candidates
    )
    _verify_k_projection_cross_checks(
        closure,
        fork_references=fork_references,
    )
    credential_bindings, credential_aliases, lineage = _credential_projection(
        authority, closure.proposed_genesis, closure.candidates
    )
    ancestors = _causal_ancestors(closure.candidates)
    authority_events = build_events(
        tuple(
            {"reference": candidate.reference_hex, "fields": candidate.fields}
            for candidate in closure.candidates
        ),
        ancestors,
    )
    root_credential = closure.proposed_genesis["projection"][
        "rootCredentialIdentifierHex"
    ]
    unavailable_branch: str | None = None
    authority_fold: AuthorityFold | None = None
    branch_a = _branch_a_capacity_crossed(
        authority,
        fork_relation,
        credential_bindings,
        credential_aliases,
        lineage,
        closure.candidates,
    )
    fork_joins: tuple[dict[str, Any], ...] = ()
    if branch_a:
        unavailable_branch = "A"
    else:
        fork_joins = _fork_join_projection(
            authority, fork_relation, lineage, closure.candidates
        )
        control_events = sum(
            event.kind in {"GRANT", "RECOVER", "POLICY", "CLOSURE", "REVOKE", "ROTATE"}
            for event in authority_events
        )
        ready_width, _ = authority_ready_width(authority_events, fork_relation)
        removal_directives = sum(
            candidate.fields["eventRole"] == "REMOVAL"
            for candidate in closure.candidates
        )
        if control_events > _selected_limit(authority, "CONTROL_EVENTS"):
            unavailable_branch = "B"
        elif ready_width > _selected_limit(
            authority, "AUTHORITY_CONCURRENT_CONTROLS"
        ):
            unavailable_branch = "B"
        elif removal_directives > _selected_limit(
            authority, "REMOVAL_DIRECTIVES"
        ):
            unavailable_branch = "B"
        else:
            try:
                authority_fold = fold_authority(
                    authority_events,
                    lineage,
                    root_credential,
                    fork_relation,
                    state_limit=_selected_limit(authority, "AUTHORITY_STATES"),
                    transition_limit=_selected_limit(authority, "AUTHORITY_TRANSITIONS"),
                    concurrent_limit=None,
                )
                if (
                    authority_fold.ordinary_prefix_query_max
                    > _selected_limit(authority, "ORDINARY_PREFIX_QUERIES")
                ):
                    authority_fold = None
                    unavailable_branch = "B"
                elif (
                    authority_fold.replayed_event_work
                    > _selected_limit(authority, "REPLAYED_EVENT_WORK")
                ):
                    raise HarnessFailure(
                        "reserved REPLAYED_EVENT_WORK crossing became reachable"
                    )
            except AuthorityProjectionUnavailable:
                unavailable_branch = "B"
    records = tuple(
        _event_projection(
            candidate,
            fork_references=fork_references,
            pending_references=pending_references,
            pending_roots=pending_roots,
        )
        for candidate in _protocol_k_order(closure.candidates)
    )
    return ReplayProjection(
        closure=closure,
        records=records,
        content_states=tuple(content_states),
        pending_roots=pending_roots,
        pending_references=pending_references,
        fork_relation=fork_relation,
        fork_references=fork_references,
        fork_joins=fork_joins,
        credential_bindings=tuple(credential_bindings),
        credential_aliases=tuple(tuple(group) for group in credential_aliases),
        authority=authority_fold,
        authority_unavailable_branch=unavailable_branch,
    )


def _primary_stage(authority: ContractAuthority, primary: str) -> str:
    taxonomy = _read_json(
        authority.repo_root
        / "tools/causal-flow-simulator/o10/outcome-taxonomy.json"
    )
    matches = [row for row in taxonomy["primaries"] if row.get("id") == primary]
    if len(matches) != 1 or not isinstance(matches[0].get("stage"), str):
        raise HarnessFailure("record primary is absent from the pinned O-10 taxonomy")
    return matches[0]["stage"]


def _credential_ancestors(
    lineage: Mapping[str, tuple[str | None, str]], credential: str
) -> frozenset[str]:
    result: set[str] = set()
    cursor: str | None = credential
    while cursor is not None:
        if cursor in result or cursor not in lineage:
            raise HarnessFailure("credential lineage is cyclic or incomplete")
        result.add(cursor)
        cursor = lineage[cursor][0]
    return frozenset(result)


def _validate_context_projection(
    authority: ContractAuthority, result: dict[str, Any]
) -> dict[str, Any]:
    validator = Draft202012Validator(
        {
            "$schema": authority.schema["$schema"],
            "$ref": "#/$defs/ContextProjectionV0",
            "$defs": authority.schema["$defs"],
        }
    )
    errors = sorted(validator.iter_errors(result), key=lambda row: list(row.path))
    if errors:
        raise HarnessFailure(
            "assembled context projection violates the ratified schema at "
            + "/".join(str(item) for item in errors[0].absolute_path)
            + ": "
            + errors[0].message
        )
    return result


def _assemble_context_projection(
    authority: ContractAuthority, projection: ReplayProjection
) -> dict[str, Any]:
    """Release the exact available-authority V9 ContextProjectionV0."""

    candidates = projection.closure.candidates
    by_reference = {candidate.reference_hex: candidate for candidate in candidates}
    if projection.authority is None:
        branch = projection.authority_unavailable_branch
        if branch not in {"A", "B"}:
            raise HarnessFailure("unavailable authority has no exact V9 branch")
        forked = (
            []
            if branch == "A"
            else sorted({credential for credential, _ in projection.fork_relation})
        )
        result = {
            "aliasGroups": [list(group) for group in projection.credential_aliases],
            "appliedControlReferences": [],
            "authority": {
                "reason": "AUTHORITY_PROJECTION_UNAVAILABLE",
                "status": "UNAVAILABLE",
            },
            "checkpointEvidenceReferences": [],
            "contentStates": list(projection.content_states),
            "contextState": "AUTHORITY_UNAVAILABLE",
            "credentialBindings": list(projection.credential_bindings),
            "eventAuthority": [],
            "forkJoins": [] if branch == "A" else list(projection.fork_joins),
            "forkedCredentialIdentifiers": forked,
            "pendingReferences": sorted(projection.pending_references),
            "pendingRootReferences": sorted(projection.pending_roots),
            "recordOutcomes": [
                {
                    "disposition": "AUTHORITY_PROJECTION_UNAVAILABLE",
                    "eventReferenceHex": reference,
                    "stage": "S5_AUTHORITY_PROJECTION",
                }
                for reference in sorted(by_reference)
            ],
            "records": list(projection.records),
            "reductionStandings": [],
            "replayDependencyReferences": sorted(by_reference),
            "revokedCredentialIdentifiers": [],
            "terminatedCredentialIdentifiers": [],
        }
        return _validate_context_projection(authority, result)

    ancestors = _causal_ancestors(candidates)
    lineage: dict[str, tuple[str | None, str]] = {}
    for binding in projection.credential_bindings:
        credential = binding["credentialIdentifierHex"]
        if binding["origin"] == "GENESIS":
            lineage[credential] = (None, credential)
        else:
            lineage[credential] = (
                binding["issuerCredentialIdentifierHex"],
                binding["grantReferenceHex"],
            )

    removal_targets: dict[str, str] = {}
    removal_applicable: dict[str, bool] = {}
    for candidate in candidates:
        fields = candidate.fields
        if fields["eventRole"] != "REMOVAL":
            continue
        tail = fields["tail"]
        target_reference = tail["targetEventReferenceHex"]
        removal_targets[candidate.reference_hex] = target_reference
        target = by_reference.get(target_reference)
        target_content = None if target is None else target.fields["content"]
        removal_applicable[candidate.reference_hex] = bool(
            target is not None
            and target_reference in ancestors[candidate.reference_hex]
            and target_content["class"] == "DETACHABLE"
            and tail["targetCommitmentHex"] == target_content["commitmentHex"]
        )

    accepted_reductions: list[tuple[str, str]] = []
    for candidate in candidates:
        fields = candidate.fields
        tail = fields.get("tail", {})
        if (
            candidate.reference_hex in projection.authority.accepted_controls
            and fields["eventRole"] == "CREDENTIAL"
            and tail.get("kind") in {"REVOKE", "ROTATE"}
        ):
            target = (
                tail["targetCredentialHex"]
                if tail["kind"] == "REVOKE"
                else tail["retiringCredentialHex"]
            )
            accepted_reductions.append((candidate.reference_hex, target))

    primaries: dict[str, str] = {}
    for candidate in candidates:
        reference = candidate.reference_hex
        fields = candidate.fields
        if reference in projection.fork_references:
            primary = "FORK_EVIDENCE"
        elif reference in projection.pending_roots:
            primary = "PENDING_OPENING"
        elif reference in projection.pending_references:
            primary = "PENDING_ANCESTOR"
        elif fields["eventRole"] == "REMOVAL" and not removal_applicable[reference]:
            primary = "REMOVAL_INAPPLICABLE"
        elif fields["eventRole"] == "CREDENTIAL":
            primary = (
                "APPLIED"
                if reference in projection.authority.accepted_controls
                else "AUTHENTIC_BUT_UNAUTHORIZED"
            )
        elif projection.authority.event_authority[reference] == "MUST_AUTH":
            primary = "APPLIED"
        else:
            actor_ancestors = _credential_ancestors(
                lineage, fields["credentialIdentifierHex"]
            )
            post_revocation = any(
                reduction_reference in ancestors[reference]
                and target in actor_ancestors
                for reduction_reference, target in accepted_reductions
            )
            primary = (
                "POST_REVOCATION"
                if post_revocation
                else "LINEAGE_QUARANTINED"
                if fields["credentialIdentifierHex"]
                in projection.authority.terminated
                else "AUTHENTIC_BUT_UNAUTHORIZED"
            )
        primaries[reference] = primary

    logically_removed = {
        removal_targets[reference]
        for reference, primary in primaries.items()
        if primary == "APPLIED" and reference in removal_targets
    }
    content_states = []
    for row in projection.content_states:
        copied = dict(row)
        if copied["eventReferenceHex"] in logically_removed:
            if copied["contentClass"] != "DETACHABLE":
                raise HarnessFailure("applied removal selected non-detachable content")
            copied["retentionState"] = "LOGICALLY_REMOVED"
        content_states.append(copied)

    fold = projection.authority
    authority_row = {
        "necessaryCredentialIdentifiers": sorted(
            fold.necessary_terminal_authority
        ),
        "possibleCredentialIdentifiers": sorted(fold.possible_terminal_authority),
        "status": "AVAILABLE",
        "terminalCredentialIdentifiers": sorted(fold.terminal_authority),
    }
    context_state = (
        "NO_OPERATIONAL_AUTHORITY"
        if not fold.necessary_terminal_authority
        else "PARTIALLY_LINEAGE_QUARANTINED"
        if fold.forked_credentials
        else "PARTIALLY_PENDING"
        if projection.pending_roots
        else "ACTIVE"
    )
    result = {
        "aliasGroups": [list(group) for group in projection.credential_aliases],
        "appliedControlReferences": sorted(fold.accepted_controls),
        "authority": authority_row,
        "checkpointEvidenceReferences": [],
        "contentStates": sorted(
            content_states, key=lambda row: row["eventReferenceHex"]
        ),
        "contextState": context_state,
        "credentialBindings": list(projection.credential_bindings),
        "eventAuthority": [
            {"eventReferenceHex": reference, "verdict": verdict}
            for reference, verdict in sorted(fold.event_authority.items())
        ],
        "forkJoins": list(projection.fork_joins),
        "forkedCredentialIdentifiers": sorted(fold.forked_credentials),
        "pendingReferences": sorted(projection.pending_references),
        "pendingRootReferences": sorted(projection.pending_roots),
        "recordOutcomes": [
            {
                "disposition": primaries[reference],
                "eventReferenceHex": reference,
                "stage": _primary_stage(authority, primaries[reference]),
            }
            for reference in sorted(primaries)
        ],
        "records": list(projection.records),
        "reductionStandings": [
            {"eventReferenceHex": reference, "standing": standing}
            for reference, standing in sorted(fold.reduction_standing.items())
        ],
        "replayDependencyReferences": sorted(by_reference),
        "revokedCredentialIdentifiers": sorted(fold.revoked),
        "terminatedCredentialIdentifiers": sorted(fold.terminated),
    }
    return _validate_context_projection(authority, result)


def replay_context(
    authority: ContractAuthority, profile: dict[str, str], value: Mapping[str, Any]
) -> dict[str, Any]:
    projected = project_replay_state(authority, profile, value)
    if isinstance(projected, dict):
        return projected
    snapshot = {
        "admittedCandidates": [
            candidate.candidate for candidate in projected.closure.candidates
        ],
        "evidence": projected.closure.evidence,
        "genesis": projected.closure.proposed_genesis,
        "projection": _assemble_context_projection(authority, projected),
    }
    return {
        "kind": "REPLAY_PROPOSAL_READY",
        "proposedContext": snapshot,
        "stage": "REPLAY_COMPLETE",
    }


def _revalidate_prior_snapshot(
    authority: ContractAuthority,
    profile: dict[str, str],
    prior: Mapping[str, Any],
) -> ReplayProjection | None:
    """Recompute a supplied prior and require byte-for-byte semantic equality.

    A prior snapshot is serializable evidence, never an authority or cache.
    Stateful operations therefore reconstruct the complete closure and public
    projection before considering the new candidate or evidence additions.
    """

    replay_input = {
        "proposedGenesis": prior["genesis"],
        "candidates": prior["admittedCandidates"],
        "evidence": prior["evidence"],
    }
    projection = project_replay_state(authority, profile, replay_input)
    if isinstance(projection, dict):
        return None
    regenerated = {
        "admittedCandidates": [
            candidate.candidate for candidate in projection.closure.candidates
        ],
        "evidence": projection.closure.evidence,
        "genesis": projection.closure.proposed_genesis,
        "projection": _assemble_context_projection(authority, projection),
    }
    return projection if regenerated == prior else None


def _f13_relation(authority: ContractAuthority) -> dict[str, dict[str, Any]]:
    rows = _read_json(
        authority.contract / "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"
    ).get("candidateEvaluationPrimaryRelationV0")
    if not isinstance(rows, list):
        raise HarnessFailure("candidate F13 relation is absent")
    relation = {
        row["primary"]: row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("primary"), str)
    }
    if len(rows) != 25 or len(relation) != 25:
        raise HarnessFailure("candidate F13 relation is not the exact 25-row set")
    return relation


def _candidate_result_from_primary(
    authority: ContractAuthority,
    primary: str,
    *,
    successor: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = _f13_relation(authority).get(primary)
    if row is None:
        raise HarnessFailure(f"candidate primary is absent from F13: {primary}")
    kind = row["coreResultKind"]
    if kind == "TERMINAL_NO_SUCCESSOR":
        if successor is not None:
            raise HarnessFailure("F13 no-successor row received a successor")
        return {
            "kind": kind,
            "primary": primary,
            "stage": row["existingO10Stage"],
        }
    if kind != "PROPOSAL_READY" or successor is None:
        raise HarnessFailure("F13 successor relation is incomplete")
    if row.get("kRetentionEffect") != "RETAIN_NEW":
        raise HarnessFailure("F13 proposal row does not retain new K evidence")
    return {
        "kind": kind,
        "primaryOnCommit": primary,
        "proposal": {"successor": successor},
    }


def evaluate_candidate(
    authority: ContractAuthority,
    profile: dict[str, str],
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate one new event against an independently revalidated prior."""

    if profile != SUPPORTED_PROFILE:
        return {
            "evaluation": _candidate_result_from_primary(
                authority, "PROFILE_ACTIVATION_UNSUPPORTED"
            )
        }
    prior = value["prior"]
    prior_projection = _revalidate_prior_snapshot(authority, profile, prior)
    if prior_projection is None:
        # CandidateEvaluationResultV0 intentionally has no prior-error arm.
        # A semantically forged prior is therefore rejected as input and is
        # never collapsed into an event-local O-10 primary.
        raise RequestRejected()

    candidate = value["candidate"]
    parsed = _parse_transcript_candidate(authority, candidate)
    if parsed[0] is None:
        return {
            "evaluation": _candidate_result_from_primary(
                authority, "STRUCTURAL_REJECTION"
            )
        }
    module, transcript, _, fields, _ = parsed
    envelope_failure = _selected_envelope_failure(
        module, "APPLICATION_EVENT", transcript, fields
    )
    if envelope_failure is not None:
        return {
            "evaluation": _candidate_result_from_primary(
                authority, "CURRENT_OBJECT_OUT_OF_PROFILE"
            )
        }
    reference = module.framed_hash(module.DOMAINS["event_reference"], transcript).hex()
    prior_by_reference = {
        item.reference_hex: item for item in prior_projection.closure.candidates
    }

    parsed_candidate = ReplayCandidate(candidate, reference, transcript, fields)
    descriptors = _content_descriptors(
        prior_projection.closure.candidates + (parsed_candidate,)
    )
    try:
        call_evidence = _canonicalize_evidence(value["evidence"], descriptors)
        if call_evidence["contentMaterial"] or call_evidence["openingMaterial"]:
            merged_evidence, _ = merge_evidence_additions(
                prior_projection.closure.evidence, call_evidence, descriptors
            )
        else:
            merged_evidence = _canonicalize_evidence(
                prior_projection.closure.evidence, descriptors
            )
    except EvidenceError as error:
        raise RequestRejected() from error

    previous = prior_by_reference.get(reference)
    if previous is not None:
        primary = (
            "DUPLICATE"
            if previous.candidate == candidate
            else "REFERENCE_COLLISION_UNSUPPORTED"
        )
        return {"evaluation": _candidate_result_from_primary(authority, primary)}

    candidates = sorted(
        (*prior_projection.closure.candidates, parsed_candidate),
        key=lambda item: item.reference_hex,
    )
    replayed = replay_context(
        authority,
        profile,
        {
            "proposedGenesis": prior_projection.closure.proposed_genesis,
            "candidates": [item.candidate for item in candidates],
            "evidence": merged_evidence,
        },
    )
    if replayed.get("kind") == "TERMINAL_CANDIDATE_REJECTED":
        return {
            "evaluation": _candidate_result_from_primary(
                authority, replayed["primary"]
            )
        }
    if replayed.get("kind") != "REPLAY_PROPOSAL_READY":
        raise HarnessFailure("candidate full replay did not select an exact result")
    successor = replayed["proposedContext"]
    outcome = next(
        (
            row
            for row in successor["projection"]["recordOutcomes"]
            if row["eventReferenceHex"] == reference
        ),
        None,
    )
    if outcome is None:
        raise HarnessFailure("candidate full replay omitted the new record outcome")
    primary = outcome["disposition"]
    row = _f13_relation(authority).get(primary)
    if row is None or outcome["stage"] != row["existingO10Stage"]:
        raise HarnessFailure("candidate full replay violates the exact F13 stage")
    return {
        "evaluation": _candidate_result_from_primary(
            authority, primary, successor=successor
        )
    }


def evaluate_evidence_update(
    authority: ContractAuthority,
    profile: dict[str, str],
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate a purpose-keyed monotone evidence-only update."""

    prior_projection = _revalidate_prior_snapshot(authority, profile, value["prior"])
    if prior_projection is None:
        return {
            "evaluation": {
                "kind": "TERMINAL_REJECTED",
                "reason": "PRIOR_REVALIDATION_FAILED",
            }
        }
    descriptors = _content_descriptors(prior_projection.closure.candidates)
    try:
        merged, changed = merge_evidence_additions(
            prior_projection.closure.evidence, value["additions"], descriptors
        )
    except EvidenceError as error:
        return {
            "evaluation": {"kind": "TERMINAL_REJECTED", "reason": error.code}
        }
    if not changed:
        return {"evaluation": {"kind": "IDEMPOTENT_NO_CHANGE"}}

    replayed = replay_context(
        authority,
        profile,
        {
            "proposedGenesis": prior_projection.closure.proposed_genesis,
            "candidates": [
                item.candidate for item in prior_projection.closure.candidates
            ],
            "evidence": merged,
        },
    )
    if replayed.get("kind") == "TERMINAL_CANDIDATE_REJECTED":
        primary = replayed.get("primary")
        reason = (
            "EVIDENCE_COMMITMENT_MISMATCH"
            if primary == "COMMITMENT_MISMATCH"
            else "RESOURCE_LIMIT"
            if primary in {"CONTEXT_CAPACITY_EXHAUSTED", "DEPENDENCY_DEFERRED"}
            else "FULL_REPLAY_MISMATCH"
        )
        return {"evaluation": {"kind": "TERMINAL_REJECTED", "reason": reason}}
    if replayed.get("kind") != "REPLAY_PROPOSAL_READY":
        return {
            "evaluation": {
                "kind": "TERMINAL_REJECTED",
                "reason": "FULL_REPLAY_MISMATCH",
            }
        }
    return {
        "evaluation": {
            "kind": "PROPOSAL_READY",
            "evidenceEffect": "ADD_MONOTONE",
            "proposal": {"successor": replayed["proposedContext"]},
        }
    }


def evaluate_interface_request(
    authority: ContractAuthority, request: dict[str, Any]
) -> dict[str, Any]:
    """Evaluate one admitted request and reconstruct its response envelope."""

    validate_request_structure(authority, request)
    operation = request["operation"]
    profile = dict(request["profile"])
    if operation == "DESCRIBE_PROFILE":
        result = describe_profile(authority, profile)
    elif operation == "VALIDATE_TRANSCRIPT":
        result = validate_transcript(authority, profile, request["input"])
    elif operation == "EVALUATE_GENESIS":
        result = evaluate_genesis(authority, profile, request["input"])
    elif operation == "REPLAY_CONTEXT":
        result = replay_context(authority, profile, request["input"])
    elif operation == "EVALUATE_CANDIDATE":
        result = evaluate_candidate(authority, profile, request["input"])
    elif operation == "EVALUATE_EVIDENCE_UPDATE":
        result = evaluate_evidence_update(authority, profile, request["input"])
    else:
        raise HarnessFailure(f"operation evaluator is not implemented yet: {operation}")
    response = {
        "interfaceVersion": INTERFACE_VERSION,
        "operation": operation,
        "profile": profile,
        "result": result,
    }
    return validate_response_before_release(authority, response)


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

    operation = response.get("operation")
    result = response.get("result")
    if isinstance(result, dict):
        successor: Any = None
        if operation == "REPLAY_CONTEXT":
            successor = result.get("proposedContext")
        elif operation in {"EVALUATE_CANDIDATE", "EVALUATE_EVIDENCE_UPDATE"}:
            evaluation = result.get("evaluation")
            if isinstance(evaluation, dict):
                proposal = evaluation.get("proposal")
                if isinstance(proposal, dict):
                    successor = proposal.get("successor")
        _preflight_snapshot_collections(
            authority, successor, request_side=False
        )

    _validate_complete_v2_document(
        authority, response, trusted_direction="RESPONSE"
    )
    operation = response["operation"]
    if operation == "EVALUATE_CANDIDATE":
        rows = _f13_relation(authority)
        evaluation = response["result"]["evaluation"]
        primary = evaluation.get("primary", evaluation.get("primaryOnCommit"))
        row = rows.get(primary)
        if row is None or evaluation["kind"] != row["coreResultKind"]:
            raise HarnessFailure("generated candidate response violates F13")
        if (
            evaluation["kind"] == "TERMINAL_NO_SUCCESSOR"
            and evaluation["stage"] != row["existingO10Stage"]
        ):
            raise HarnessFailure("generated candidate response violates F13 stage")
        return
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
    if response.get("operation") == "EVALUATE_CANDIDATE":
        evaluation = result.get("evaluation", {})
        primary = evaluation.get("primary", evaluation.get("primaryOnCommit"))
        row = _f13_relation(authority).get(primary)
        if row is not None and row.get("reachability") == "RESERVED_UNREACHABLE_V0":
            raise HarnessFailure("APP-core v0 reserved F13 row was generated")
    observations = result.get("observations", {})
    relations = _read_json(
        authority.contract / "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"
    )
    reserved = {
        (row["operation"], row["result"]["kind"], row["result"].get("reason"), row["result"]["stage"])
        for row in relations.get("terminalPredicateRelationV0", [])
        if row.get("result", {}).get("reachability") == "RESERVED_UNREACHABLE_V0"
    }
    observed = (
        response.get("operation"),
        result.get("kind"),
        result.get("reason"),
        result.get("stage"),
    )
    if observed in reserved or observations.get("referenceVerification") == "REJECTED":
        raise HarnessFailure("APP-core v0 reserved terminal predicate was generated")
    return response
