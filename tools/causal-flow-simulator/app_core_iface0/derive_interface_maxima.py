#!/usr/bin/env python3
"""Derive exact APP-CORE-IFACE-0 canonical-envelope maxima.

The derivation is symbolic: large evidence values are measured without being
materialized.  It consumes only the closed candidate schema, semantic count
rules, carrier reachability relation and pinned balanced O-08 envelope.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from inventory import InventoryError, verify_contract_package


ROOT = Path(__file__).resolve().parent
CONTRACT = ROOT / "contract"
REPOSITORY = ROOT.parents[2]
SCHEMA_PATH = CONTRACT / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json"
SEMANTICS_PATH = CONTRACT / "APP-CORE-IFACE-0-SEMANTIC-CONSTRAINTS-CANDIDATE.json"
REACHABILITY_PATH = CONTRACT / "APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"
MANIFEST_PATH = CONTRACT / "APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json"
ENVELOPE_PATH = REPOSITORY / "tools/causal-flow-simulator/o08/resource-envelope.candidate.json"


class MaximaError(ValueError):
    """The closed derivation inputs do not define one finite exact maximum."""


@dataclass(frozen=True)
class Measure:
    json_octets: int
    decoded_octets: int = 0


def require(ok: bool, message: str) -> None:
    if not ok:
        raise MaximaError(message)


def load(path: Path) -> Any:
    require(path.is_file() and not path.is_symlink(), f"invalid input: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_string_octets(value: str) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


class Derivation:
    def __init__(self) -> None:
        try:
            verify_contract_package(CONTRACT)
        except InventoryError as error:
            raise MaximaError("contract package verification failed") from error
        self.schema = load(SCHEMA_PATH)
        self.semantics = load(SEMANTICS_PATH)
        self.reachability = load(REACHABILITY_PATH)
        self.envelope = load(ENVELOPE_PATH)
        require(self.envelope.get("candidate_id") == "balanced", "unselected resource envelope")
        require(self.reachability.get("schemaSha256") == sha256(SCHEMA_PATH), "schema/reachability drift")
        require(self.reachability.get("rootCount") == 12, "carrier-root drift")
        require(len(self.semantics.get("rules", [])) == 82, "semantic-rule drift")
        self.limits = {
            name: int(row["selected_value"])
            for name, row in self.envelope["entries"].items()
            if row.get("selected_value") is not None
        }
        self.array_bounds = self._array_bounds()
        self.relations = load(CONTRACT / "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json")

    def _array_bounds(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for row in self.semantics["rules"]:
            if row["rule"] not in {
                "ARRAY_COUNT_LIMIT_BEFORE_ITEM_WORK",
                "DERIVED_ARRAY_COUNT_LIMIT_BEFORE_ITEM_WORK",
            }:
                continue
            parameters = row["parameters"]
            by_target = parameters.get("parametersByTarget")
            target_parameters = (
                by_target
                if isinstance(by_target, dict)
                else {target: parameters for target in row["targets"]}
            )
            require(
                set(target_parameters) == set(row["targets"]),
                f"array target-parameter drift: {row['id']}",
            )
            for target, target_parameter in target_parameters.items():
                require(target not in result, f"duplicate array bound: {target}")
                if "dimension" in target_parameter:
                    dimension = target_parameter["dimension"]
                    require(
                        dimension in self.limits,
                        f"unknown array dimension: {dimension}",
                    )
                    result[target] = self.limits[dimension]
                else:
                    expression = target_parameter.get("expression")
                    selected = int(target_parameter.get("selectedValue", "-1"))
                    expected = {
                        "RECORDS + 1": self.limits["RECORDS"] + 1,
                        "floor((RECORDS + 1) / 2)": (
                            self.limits["RECORDS"] + 1
                        )
                        // 2,
                    }
                    require(
                        expression in expected and selected == expected[expression],
                        f"unknown or mismatched derived array expression: {target}",
                    )
                    result[target] = selected
        expected = {
            "$defs.ContentMaterialEvidenceV0.segments",
            "$defs.ProposedContextSnapshotV0.admittedCandidates",
            "$defs.ContextProjectionV0.records",
            "$defs.ContextProjectionV0.recordOutcomes",
            "$defs.ContextProjectionV0.contentStates",
            "$defs.ReplayContextInputV0.candidates",
            "$defs.ContextProjectionV0.credentialBindings",
            "$defs.ApplicationEventProjectionV0.causalParentReferences",
            "$defs.EvidenceProjectionV0.contentMaterial",
            "$defs.EvidenceProjectionV0.openingMaterial",
            "$defs.AuthorityAvailableV0.possibleCredentialIdentifiers",
            "$defs.AuthorityAvailableV0.necessaryCredentialIdentifiers",
            "$defs.AuthorityAvailableV0.terminalCredentialIdentifiers",
            "$defs.ForkJoinProjectionV0.siblingReferences",
            "$defs.ForkJoinProjectionV0.lineageClosureCredentialIdentifiers",
            "$defs.AliasGroupV0.allOf[0]",
            "$defs.ContextProjectionV0.aliasGroups",
            "$defs.ContextProjectionV0.appliedControlReferences",
            "$defs.ContextProjectionV0.reductionStandings",
            "$defs.ContextProjectionV0.eventAuthority",
            "$defs.ContextProjectionV0.revokedCredentialIdentifiers",
            "$defs.ContextProjectionV0.terminatedCredentialIdentifiers",
            "$defs.ContextProjectionV0.forkedCredentialIdentifiers",
            "$defs.ContextProjectionV0.forkJoins",
            "$defs.ContextProjectionV0.pendingRootReferences",
            "$defs.ContextProjectionV0.pendingReferences",
            "$defs.ContextProjectionV0.replayDependencyReferences",
        }
        require(set(result) == expected, "bounded array-use partition drift")
        return result

    def _ref_name(self, reference: str) -> str:
        prefix = "#/$defs/"
        require(reference.startswith(prefix), f"non-local reference: {reference}")
        name = reference.removeprefix(prefix)
        require(name in self.schema["$defs"], f"unknown reference: {reference}")
        return name

    @staticmethod
    def _object(properties: dict[str, Measure]) -> Measure:
        keys = sorted(properties)
        syntax = 2 + max(0, len(keys) - 1)
        syntax += sum(json_string_octets(key) + 1 for key in keys)
        return Measure(
            syntax + sum(properties[key].json_octets for key in keys),
            sum(properties[key].decoded_octets for key in keys),
        )

    @staticmethod
    def _array(item: Measure, count: int) -> Measure:
        require(count >= 0, "negative array count")
        return Measure(
            2 + count * item.json_octets + max(0, count - 1),
            count * item.decoded_octets,
        )

    @staticmethod
    def _literal(value: Any) -> Measure:
        return Measure(len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")))

    def _fixed_hex(self, octets: int) -> Measure:
        return Measure(2 + 2 * octets, octets)

    def _capabilities(self) -> Measure:
        definition = self.schema["$defs"]["CapabilityRequirementsV0"]
        required = definition.get("required")
        properties = definition.get("properties")
        row_definition = self.schema["$defs"]["CapabilityRequirementV0"]
        row_properties = row_definition.get("properties")
        require(isinstance(required, list), "capability required-set is malformed")
        require(isinstance(properties, dict), "capability property-set is malformed")
        require(isinstance(row_properties, dict), "capability row schema is malformed")
        comparisons = row_properties.get("comparison", {}).get("enum")
        units = row_properties.get("unit", {}).get("enum")
        require(isinstance(comparisons, list), "capability comparison enum is malformed")
        require(isinstance(units, list), "capability unit enum is malformed")
        envelope_rows = {
            name: row
            for name, row in self.envelope["entries"].items()
            if row.get("role") == "C03_ACTIVATION_CAPABILITY_INPUT"
        }
        require(
            set(required) == set(properties) == set(envelope_rows),
            "capability requirement closure drift",
        )
        rows: dict[str, tuple[str, str, str]] = {}
        for name in required:
            row = envelope_rows[name]
            comparison = row.get("comparison")
            selected = row.get("selected_value")
            unit = row.get("unit")
            require(isinstance(comparison, str), f"invalid capability comparison: {name}")
            require(comparison in comparisons, f"unknown capability comparison: {name}")
            require(
                isinstance(selected, int) and not isinstance(selected, bool) and selected >= 0,
                f"invalid capability value: {name}",
            )
            require(isinstance(unit, str), f"invalid capability unit: {name}")
            require(unit in units, f"unknown capability unit: {name}")
            rows[name] = (comparison, str(selected), unit)
        minimum_count = sum(
            comparison == "MINIMUM_CAPABILITY"
            for comparison, _, _ in rows.values()
        )
        require(
            rows.get("ACTIVATION_CAPABILITY_SET")
            == ("EXACT_CLOSED_KEY_SET", str(minimum_count), "COUNT"),
            "activation capability-set count drift",
        )
        return self._object({
            name: self._object({
                "comparison": self._literal(comparison),
                "selectedValue": self._literal(value),
                "unit": self._literal(unit),
            })
            for name, (comparison, value, unit) in rows.items()
        })

    def _content_segments(self) -> Measure:
        count = self.array_bounds["$defs.ContentMaterialEvidenceV0.segments"]
        total_octets = self.limits["CONTENT_EXACT_OCTETS"]
        maximum_segment_octets = self.limits["CHUNK_OCTETS"]
        require(count > 0, "content segment count is not positive")
        require(
            count <= total_octets <= count * maximum_segment_octets,
            "content segment tiling is not representable",
        )
        remaining = total_octets
        offset = 0
        items: list[Measure] = []
        for index in range(count):
            remaining_slots = count - index - 1
            length = min(maximum_segment_octets, remaining - remaining_slots)
            require(
                1 <= length <= maximum_segment_octets,
                "content segment length is outside its exact bound",
            )
            item = self._object({
                "offset": self._literal(str(offset)),
                "octetsHex": self._literal(""),
            })
            items.append(Measure(item.json_octets + 2 * length, length))
            offset += length
            remaining -= length
        require(offset == total_octets and remaining == 0, "content tiling drift")
        return Measure(
            2 + sum(item.json_octets for item in items) + max(0, count - 1),
            sum(item.decoded_octets for item in items),
        )

    def _alias_groups(self) -> Measure:
        group_count = self.array_bounds["$defs.ContextProjectionV0.aliasGroups"]
        total_members = self.array_bounds["$defs.AliasGroupV0.allOf[0]"]
        require(
            group_count == 64 and total_members == 129,
            "alias maximizing cardinality drift",
        )
        groups = [self._array(self._fixed_hex(32), 2) for _ in range(group_count - 1)]
        groups.append(self._array(self._fixed_hex(32), 3))
        result = Measure(
            2 + sum(group.json_octets for group in groups) + group_count - 1,
            sum(group.decoded_octets for group in groups),
        )
        require(
            result.json_octets == 8772 and result.decoded_octets == 4128,
            "alias maximizing measurement drift",
        )
        return result

    def _relation_object(self, definition: str) -> Measure:
        if definition == "ContentStateProjectionV0":
            rows = self.relations["contentAxisLegalRelationV0"]
            candidates = [
                self._object({
                    "eventReferenceHex": self._fixed_hex(32),
                    "contentClass": self._literal(row["contentClass"]),
                    "localAvailability": self._literal(row["localAvailability"]),
                    "bindingObservation": self._literal(row["bindingObservation"]),
                    "retentionState": self._literal(row["retentionState"]),
                    "replayReadiness": self._literal(row["replayReadiness"]),
                })
                for row in rows
            ]
        else:
            rows = self.relations["candidateEvaluationPrimaryRelationV0"]
            candidates = [
                self._object({
                    "eventReferenceHex": self._fixed_hex(32),
                    "disposition": self._literal(row["primary"]),
                    "stage": self._literal(row["existingO10Stage"]),
                })
                for row in rows
            ]
        return max(candidates, key=lambda item: (item.json_octets, item.decoded_octets))

    def definition(self, name: str, use_site: str | None = None) -> Measure:
        exact_content_octets = self.limits["CONTENT_EXACT_OCTETS"]
        chunk_octets = self.limits["CHUNK_OCTETS"]
        require(
            exact_content_octets % chunk_octets == 0,
            "maximal chunk geometry is not integral",
        )
        scalar_overrides = {
            "$defs.ContentDescriptorSingleV0.exactContentLength": str(exact_content_octets),
            "$defs.ContentDescriptorChunkTreeV0.exactContentLength": str(exact_content_octets),
            "$defs.ChunkGeometryProjectionV0.chunkSize": str(chunk_octets),
            "$defs.ChunkGeometryProjectionV0.chunkCount": str(exact_content_octets // chunk_octets),
            "$defs.ChunkGeometryProjectionV0.finalChunkLength": str(chunk_octets),
        }
        if use_site in scalar_overrides:
            return self._literal(scalar_overrides[use_site])
        if name == "FixedHex32":
            return self._fixed_hex(32)
        if name == "SignatureHex":
            return self._fixed_hex(self.limits["SIGNATURE_OCTETS"])
        if name in {"U16Text", "U32Text", "U64Text"}:
            maximum = {"U16Text": "65535", "U32Text": "4294967295", "U64Text": "18446744073709551615"}[name]
            return self._literal(maximum)
        if name in {"TranscriptHex", "ApTransitionBlockHex", "GenesisPolicyBlockHex", "ContentSegmentHex"}:
            dimension = {
                "TranscriptHex": "FRAMING_OBJECT_OCTETS",
                "ApTransitionBlockHex": "AP_TRANSITION_BLOCK_OCTETS",
                "GenesisPolicyBlockHex": "GENESIS_POLICY_OCTETS",
                "ContentSegmentHex": "CHUNK_OCTETS",
            }[name]
            return self._fixed_hex(self.limits[dimension])
        if name == "CapabilityRequirementsV0":
            return self._capabilities()
        if name in {"RecordOutcomeV0", "ContentStateProjectionV0"}:
            return self._relation_object(name)
        if name == "EvidenceAdditionSetV0":
            return self.definition("EvidenceProjectionV0")
        if name == "AliasGroupV0":
            return self._array(self._fixed_hex(32), self.array_bounds["$defs.AliasGroupV0.allOf[0]"])
        if name == "CanonicalReferenceArray":
            require(use_site is not None, "generic reference array has no use site")
            return self.node(self.schema["$defs"][name], use_site, name)
        return self.node(self.schema["$defs"][name], f"$defs.{name}", name)

    def node(self, node: dict[str, Any], use_site: str, owner_definition: str) -> Measure:
        body_plus_prefix = node.get("x-styx-o08-body-plus-prefix-limit")
        if body_plus_prefix is not None:
            require(
                set(body_plus_prefix) == {"dimension", "prefixOctets"},
                f"malformed body-plus-prefix annotation: {use_site}",
            )
            expected_dimensions = {
                "$defs.GenesisTranscriptCandidateV0.transcriptHex": "GENESIS_BODY_OCTETS",
                "$defs.ApplicationTranscriptCandidateV0.transcriptHex": "FRAMING_OBJECT_OCTETS",
            }
            require(
                use_site in expected_dimensions
                and node.get("$ref") == "#/$defs/TranscriptHex"
                and body_plus_prefix
                == {
                    "dimension": expected_dimensions[use_site],
                    "prefixOctets": "20",
                },
                f"body-plus-prefix annotation binding drift: {use_site}",
            )
            return self._fixed_hex(
                self.limits[body_plus_prefix["dimension"]]
                + int(body_plus_prefix["prefixOctets"])
            )
        if "$ref" in node:
            return self.definition(self._ref_name(node["$ref"]), use_site)
        if "const" in node:
            return self._literal(node["const"])
        if "enum" in node:
            return max((self._literal(value) for value in node["enum"]), key=lambda item: item.json_octets)
        if "oneOf" in node:
            return max(
                (self.node(arm, f"{use_site}.oneOf[{index}]", owner_definition) for index, arm in enumerate(node["oneOf"])),
                key=lambda item: (item.json_octets, item.decoded_octets),
            )
        if "anyOf" in node and "type" not in node and "$ref" not in node:
            return max(
                (self.node(arm, f"{use_site}.anyOf[{index}]", owner_definition) for index, arm in enumerate(node["anyOf"])),
                key=lambda item: (item.json_octets, item.decoded_octets),
            )
        if "allOf" in node and "type" not in node:
            reference_arms = [arm for arm in node["allOf"] if "$ref" in arm]
            require(len(reference_arms) == 1, f"unsupported allOf: {use_site}")
            return self.definition(self._ref_name(reference_arms[0]["$ref"]), f"{use_site}.allOf[0]")
        if node.get("type") == "array":
            if use_site == "$defs.ContentMaterialEvidenceV0.segments":
                return self._content_segments()
            if use_site == "$defs.ContextProjectionV0.aliasGroups":
                return self._alias_groups()
            require(use_site in self.array_bounds, f"unbounded reachable array: {use_site}")
            return self._array(
                self.node(node["items"], f"{use_site}.*", owner_definition),
                self.array_bounds[use_site],
            )
        if node.get("type") == "object":
            properties = node.get("properties", {})
            values = {
                name: self.node(child, f"$defs.{owner_definition}.{name}", owner_definition)
                for name, child in properties.items()
            }
            return self._object(values)
        if node.get("type") == "string":
            pattern = node.get("pattern")
            if pattern == "^[0-9a-f]{64}$":
                return self._fixed_hex(32)
            if pattern == "^[0-9a-f]{128}$":
                return self._fixed_hex(64)
            maximum = node.get("maxLength")
            require(isinstance(maximum, int), f"unbounded reachable string: {use_site}")
            return Measure(maximum + 2)
        raise MaximaError(f"unsupported reachable schema node: {use_site}")

    def root_breakdown(self, wrapper: str) -> tuple[Measure, list[dict[str, Any]]]:
        node = self.schema["$defs"][wrapper]
        require(node.get("type") == "object", f"root is not object: {wrapper}")
        properties = {
            name: self.node(child, f"$defs.{wrapper}.{name}", wrapper)
            for name, child in node["properties"].items()
        }
        total = self._object(properties)
        syntax = total.json_octets - sum(value.json_octets for value in properties.values()) + 1
        rows = [{"component": "canonical-syntax-keys-and-final-lf", "jsonOctets": syntax, "representedDecodedOctets": 0}]
        rows.extend(
            {"component": name, "jsonOctets": properties[name].json_octets, "representedDecodedOctets": properties[name].decoded_octets}
            for name in sorted(properties)
        )
        return Measure(total.json_octets + 1, total.decoded_octets), rows

    def retained_decoded_octets(self, root_id: str, represented: int) -> int:
        """Apply the ratified streaming/deduplicating retention model."""

        if root_id == "REQUEST-EVALUATE_CANDIDATE":
            return (
                self.definition("ProposedContextSnapshotV0").decoded_octets
                + self.definition("ApplicationTranscriptCandidateV0").decoded_octets
            )
        if root_id == "REQUEST-EVALUATE_EVIDENCE_UPDATE":
            return self.definition("ProposedContextSnapshotV0").decoded_octets
        return represented

    def report(self) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        for root in self.reachability["roots"]:
            wrapper = root["wrapperSchemaPointer"].removeprefix("/$defs/")
            measured, breakdown = self.root_breakdown(wrapper)
            rows.append({
                "breakdown": breakdown,
                "direction": root["direction"],
                "jsonOctets": measured.json_octets,
                "operation": root["operation"],
                "representedDecodedOctets": measured.decoded_octets,
                "retainedDecodedOctets": self.retained_decoded_octets(root["rootId"], measured.decoded_octets),
                "rootId": root["rootId"],
            })
        rows.sort(key=lambda row: row["rootId"])
        request = max((row for row in rows if row["direction"] == "REQUEST"), key=lambda row: (row["jsonOctets"], row["rootId"]))
        response = max((row for row in rows if row["direction"] == "RESPONSE"), key=lambda row: (row["jsonOctets"], row["rootId"]))
        decoded = max(rows, key=lambda row: (row["retainedDecodedOctets"], row["rootId"]))
        return {
            "derivationVersion": "APP-CORE-IFACE-0-INTERFACE-MAXIMA-V1",
            "maxRetainedDecodedOctets": decoded["retainedDecodedOctets"],
            "maxRetainedDecodedRoot": decoded["rootId"],
            "outerRequestOctets": request["jsonOctets"],
            "outerRequestRoot": request["rootId"],
            "outerResponseOctets": response["jsonOctets"],
            "outerResponseRoot": response["rootId"],
            "rootMeasurements": rows,
        }

    @staticmethod
    def embedded_summary(report: dict[str, Any]) -> dict[str, Any]:
        roots = {
            report["outerRequestRoot"],
            report["outerResponseRoot"],
            report["maxRetainedDecodedRoot"],
        }
        measurements = [
            row for row in report["rootMeasurements"] if row["rootId"] in roots
        ]
        return {
            "derivationVersion": report["derivationVersion"],
            "maxRetainedDecodedOctets": report["maxRetainedDecodedOctets"],
            "maxRetainedDecodedRoot": report["maxRetainedDecodedRoot"],
            "maximizingRootBreakdowns": measurements,
            "outerRequestOctets": report["outerRequestOctets"],
            "outerRequestRoot": report["outerRequestRoot"],
            "outerResponseOctets": report["outerResponseOctets"],
            "outerResponseRoot": report["outerResponseRoot"],
            "rootMeasurementSetSha256": hashlib.sha256(
                canonical_bytes(report["rootMeasurements"])
            ).hexdigest(),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = Derivation().report()
    if args.check:
        manifest = load(MANIFEST_PATH)
        require(
            manifest.get("derivedInterfaceMaxima")
            == Derivation.embedded_summary(report),
            "embedded interface maxima drift",
        )
    print(canonical_bytes(report).decode("utf-8"), end="")


if __name__ == "__main__":
    main()
