#!/usr/bin/env python3
"""Compare two first-party C0.3 runs with one frozen clean-room reader."""

from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from build_blind_projection import (  # noqa: E402
    FREEZE_SCHEMA,
    INTEGRATION_SCHEMA,
    PUBLIC_OBSERVATION_FIELDS,
    BlindProjectionError,
    validate_kit,
    validate_reader_freeze,
)
from canonical_json import load, store  # noqa: E402
from corpus_model import CorpusModelError  # noqa: E402


THIRD_REPORT_SCHEMA = "styx-c03-clean-room-report/v2"


class CleanRoomComparisonError(CorpusModelError):
    """The frozen reader does not corroborate the public C0.3 surface."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CleanRoomComparisonError(message)


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _observation_shape(observation: dict[str, Any]) -> None:
    required = {"opaqueId", *PUBLIC_OBSERVATION_FIELDS}
    if observation.get("localOutcomePresent") is True:
        required.add("localOutcome")
    if observation.get("remoteClassPresent") is True:
        required.add("remoteClass")
    require(set(observation) == required, f"third observation shape mismatch: {set(observation) ^ required}")
    require(isinstance(observation["opaqueId"], str), "third opaque id is not a string")
    for field in ("localOutcomePresent", "outcomeEvaluated", "remoteClassPresent"):
        require(isinstance(observation[field], bool), f"third {field} is not boolean")
    for field in set(PUBLIC_OBSERVATION_FIELDS) - {"localOutcomePresent", "outcomeEvaluated", "remoteClassPresent"}:
        require(isinstance(observation[field], str), f"third {field} is not text")
    require(("localOutcome" in observation) == observation["localOutcomePresent"], "third local outcome presence mismatch")
    require(("remoteClass" in observation) == observation["remoteClassPresent"], "third remote class presence mismatch")


def _graph_observation_shape(observation: dict[str, Any]) -> None:
    required = {
        "kBindingAdmission",
        "opaqueId",
        "protocolErrorCodePresent",
        "stage",
    }
    if observation.get("protocolErrorCodePresent") is True:
        required.add("protocolErrorCode")
    require(
        set(observation) == required,
        f"third graph observation shape mismatch: {set(observation) ^ required}",
    )
    require(
        isinstance(observation["protocolErrorCodePresent"], bool),
        "third graph error presence is not boolean",
    )
    require(
        all(
            isinstance(observation[field], str)
            for field in ("kBindingAdmission", "opaqueId", "stage")
        ),
        "third graph observation text mismatch",
    )
    require(
        ("protocolErrorCode" in observation)
        == observation["protocolErrorCodePresent"],
        "third graph error presence mismatch",
    )
    if observation["protocolErrorCodePresent"]:
        require(
            isinstance(observation["protocolErrorCode"], str),
            "third graph error code is not text",
        )


def _load_third(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    document = load(path)
    require(
        set(document) == {"admissionGraphs", "observations", "schema"},
        "third report shape mismatch",
    )
    require(document["schema"] == THIRD_REPORT_SCHEMA, "third report schema mismatch")
    observations = document["observations"]
    require(isinstance(observations, list), "third observations are not a list")
    result: dict[str, dict[str, Any]] = {}
    for observation in observations:
        require(isinstance(observation, dict), "third observation is not an object")
        _observation_shape(observation)
        identifier = observation["opaqueId"]
        require(identifier not in result, f"duplicate third observation: {identifier}")
        result[identifier] = observation
    graph_result: dict[str, list[dict[str, Any]]] = {}
    graphs = document["admissionGraphs"]
    require(isinstance(graphs, list), "third admission graphs are not a list")
    for graph in graphs:
        require(
            set(graph) == {"observations", "opaqueGraphId"},
            "third admission graph shape mismatch",
        )
        identifier = graph["opaqueGraphId"]
        require(
            isinstance(identifier, str) and identifier not in graph_result,
            "duplicate third admission graph",
        )
        values = graph["observations"]
        require(isinstance(values, list), "third graph observations are not a list")
        for observation in values:
            _graph_observation_shape(observation)
        require(
            [row["opaqueId"] for row in values]
            == sorted({row["opaqueId"] for row in values}),
            "third graph observations are not a sorted set",
        )
        graph_result[identifier] = values
    return result, graph_result


def _load_first_party(
    path: Path,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, list[dict[str, Any]]],
    dict[str, Any],
]:
    report = load(path)
    require(report.get("result") == "PASS", "first-party report is not PASS")
    observations = report.get("blindTranscriptObservations")
    require(isinstance(observations, list), "first-party observations are absent")
    result: dict[str, dict[str, Any]] = {}
    for observation in observations:
        identifier = observation.get("id")
        require(isinstance(identifier, str) and identifier not in result, "first-party observation id mismatch")
        result[identifier] = observation
    graphs = report.get("blindAdmissionGraphs")
    require(isinstance(graphs, list), "first-party admission graphs are absent")
    graph_result = {}
    for graph in graphs:
        identifier = graph.get("id")
        require(
            isinstance(identifier, str) and identifier not in graph_result,
            "first-party admission graph id mismatch",
        )
        graph_result[identifier] = graph["observations"]
    return result, graph_result, report


def _common_expected(expected: dict[str, Any]) -> dict[str, Any]:
    return dict(expected)


def _common_actual(actual: dict[str, Any]) -> dict[str, Any]:
    result = {key: actual[key] for key in PUBLIC_OBSERVATION_FIELDS}
    if actual["localOutcomePresent"]:
        result["localOutcome"] = actual["localOutcome"]
    if actual["remoteClassPresent"]:
        result["remoteClass"] = actual["remoteClass"]
    return result


def compare(
    kit: Path,
    integration: Path,
    python_report: Path,
    node_report: Path,
    third_report: Path,
    freeze_manifest: Path,
    reader_root: Path,
) -> dict[str, Any]:
    kit_result = validate_kit(kit)
    freeze = validate_reader_freeze(reader_root, freeze_manifest)
    require(freeze.get("schema") == FREEZE_SCHEMA, "freeze schema mismatch")
    integration_path = integration / "integration-map.json"
    mapping = load(integration_path)
    require(mapping.get("schema") == INTEGRATION_SCHEMA, "integration schema mismatch")
    require(mapping.get("kitDigest") == kit_result["kitDigest"], "integration kit digest mismatch")
    require(mapping.get("freezeManifestSha256") == _sha(freeze_manifest), "integration freeze digest mismatch")
    rows = mapping.get("records")
    require(isinstance(rows, list) and len(rows) == 53, "integration record count mismatch")
    by_opaque: dict[str, dict[str, Any]] = {}
    official_ids: set[str] = set()
    report_ids: set[str] = set()
    for row in rows:
        require(set(row) == {"expectedPublicObservation", "inputDigest", "officialId", "opaqueId", "reportObservationId", "set"}, "integration row shape mismatch")
        require(row["opaqueId"] not in by_opaque, "duplicate integration opaque id")
        require(row["officialId"] not in official_ids, "duplicate integration official id")
        require(row["reportObservationId"] not in report_ids, "duplicate integration report id")
        require(row["set"] in {"VALID", "INVALID"}, "integration set mismatch")
        by_opaque[row["opaqueId"]] = row
        official_ids.add(row["officialId"])
        report_ids.add(row["reportObservationId"])
    public_input = load(kit / "blind-input.json")
    kit_ids = {record["opaqueId"] for record in public_input["records"]}
    require(set(by_opaque) == kit_ids, "integration and kit opaque sets differ")
    third, third_graphs = _load_third(third_report)
    require(set(third) == kit_ids, "third report has missing or extra observations")
    python, python_graphs, python_document = _load_first_party(python_report)
    node, node_graphs, node_document = _load_first_party(node_report)
    mismatches: list[dict[str, str]] = []

    def mismatch(kind: str, identifier: str, detail: str) -> None:
        mismatches.append(
            {"detail": detail, "identifier": identifier, "kind": kind}
        )

    if python_report.read_bytes() != node_report.read_bytes():
        mismatch("REPORT_BYTES", "first-party", "Python and JavaScript reports are not byte-identical")
    if set(python) != set(node):
        mismatch("RECORD_SET", "first-party", "Python and JavaScript observation sets differ")

    valid_observations = 0
    invalid_classifications = 0
    for opaque_id, row in sorted(by_opaque.items()):
        expected = row["expectedPublicObservation"]
        observed = dict(third[opaque_id])
        observed.pop("opaqueId")
        if observed != expected:
            mismatch("THIRD_RECORD", opaque_id, "third-reader observation differs")
        report_id = row["reportObservationId"]
        if report_id not in python or report_id not in node:
            mismatch("FIRST_PARTY_RECORD_MISSING", report_id, "direct observation is absent")
        else:
            if _common_actual(python[report_id]) != _common_expected(expected):
                mismatch("PYTHON_RECORD", report_id, "public observation differs")
            if _common_actual(node[report_id]) != _common_expected(expected):
                mismatch("JAVASCRIPT_RECORD", report_id, "public observation differs")
        if row["set"] == "VALID":
            for field, value in (
                ("transcriptVerification", "VALID"),
                ("referenceVerification", "VALID"),
                ("signatureVerification", "VALID"),
            ):
                if expected[field] != value:
                    mismatch("VALID_RECORD_INVARIANT", opaque_id, f"{field} differs")
                valid_observations += 1
            if expected["commitmentVerification"] not in {"NOT_PRESENT", "VALID"}:
                mismatch("VALID_RECORD_INVARIANT", opaque_id, "commitment verification differs")
            valid_observations += 1
            if not (
                expected["kBindingAdmission"] == "NOT_EVALUATED"
                and expected["apAuthorityResult"] == "NOT_REACHED"
                and expected["stage"] == "TRANSCRIPT_CONFORMANCE_COMPLETE"
            ):
                mismatch("LAYER_INVARIANT", opaque_id, "disconnected success crossed the K/AP boundary")
        else:
            if not (expected["localOutcomePresent"] and expected["outcomeEvaluated"]):
                mismatch("INVALID_RECORD_INVARIANT", opaque_id, "classification is absent")
            if not (isinstance(expected.get("localOutcome"), str) and isinstance(expected["stage"], str)):
                mismatch("INVALID_RECORD_INVARIANT", opaque_id, "classification is malformed")
            if expected["kBindingAdmission"] != "NOT_EVALUATED" or expected["apAuthorityResult"] != "NOT_REACHED":
                mismatch("LAYER_INVARIANT", opaque_id, "disconnected negative crossed the K/AP boundary")
            invalid_classifications += 1
    if valid_observations != 68:
        mismatch("COUNT", "valid-observations", f"observed {valid_observations}, expected 68")
    if invalid_classifications != 36:
        mismatch("COUNT", "invalid-classifications", f"observed {invalid_classifications}, expected 36")
    if not (python_document["validVectors"] == 17 and python_document["invalidVectors"] == 36):
        mismatch("COUNT", "python-vectors", "first-party vector count differs")

    graph_rows = mapping.get("admissionGraphs")
    require(
        isinstance(graph_rows, list) and len(graph_rows) == 20,
        "integration admission graph count mismatch",
    )
    graph_by_opaque = {}
    graph_official_ids = set()
    for row in graph_rows:
        require(
            set(row)
            == {
                "expectedObservations",
                "officialId",
                "opaqueGraphId",
                "set",
            },
            "integration admission graph shape mismatch",
        )
        require(
            row["opaqueGraphId"] not in graph_by_opaque
            and row["officialId"] not in graph_official_ids
            and row["set"] in {"CONNECTED_HOSTILE", "CONNECTED_POSITIVE"},
            "integration admission graph identity mismatch",
        )
        graph_by_opaque[row["opaqueGraphId"]] = row
        graph_official_ids.add(row["officialId"])
    kit_graph_ids = {
        graph["opaqueGraphId"] for graph in public_input["admissionGraphs"]
    }
    require(set(graph_by_opaque) == kit_graph_ids, "integration and kit graph sets differ")
    require(set(third_graphs) == kit_graph_ids, "third admission graph set mismatch")
    if set(python_graphs) != graph_official_ids:
        mismatch("GRAPH_SET", "python", "admission graph set differs")
    if set(node_graphs) != graph_official_ids:
        mismatch("GRAPH_SET", "javascript", "admission graph set differs")
    connected_admitted = 0
    connected_rejected = 0
    for opaque_id, row in sorted(graph_by_opaque.items()):
        expected = row["expectedObservations"]
        if third_graphs[opaque_id] != expected:
            mismatch("THIRD_GRAPH", opaque_id, "graph observations differ")
        official_id = row["officialId"]
        expected_by_opaque = {value["opaqueId"]: value for value in expected}
        event_map = {
            event["opaqueId"]: event
            for graph in public_input["admissionGraphs"]
            if graph["opaqueGraphId"] == opaque_id
            for event in graph["events"]
        }
        require(set(expected_by_opaque) == set(event_map), f"graph event set mismatch: {opaque_id}")
        official_expected = []
        for observation in python_graphs.get(official_id, []):
            projected_id = next((
                key
                for key, event in event_map.items()
                if event["presentedReferenceHex"] == observation["eventReferenceHex"]
            ), None)
            if projected_id is None:
                mismatch("GRAPH_MAPPING", official_id, f"unknown reference {observation['eventReferenceHex']}")
                continue
            value = {
                "kBindingAdmission": observation["kBindingAdmission"],
                "opaqueId": projected_id,
                "protocolErrorCodePresent": observation["protocolErrorCode"]
                is not None,
                "stage": observation["stage"],
            }
            if observation["protocolErrorCode"] is not None:
                value["protocolErrorCode"] = observation["protocolErrorCode"]
            official_expected.append(value)
        official_expected.sort(key=lambda value: value["opaqueId"])
        if official_expected != expected:
            mismatch("PYTHON_GRAPH", official_id, "projected graph observations differ")
        if node_graphs.get(official_id) != python_graphs.get(official_id):
            mismatch("JAVASCRIPT_GRAPH", official_id, "graph observations differ from Python")
        connected_admitted += sum(
            value["kBindingAdmission"] == "ADMITTED" for value in expected
        )
        connected_rejected += sum(
            value["kBindingAdmission"] == "REJECTED" for value in expected
        )
    if not (connected_admitted > 0 and connected_rejected > 0):
        mismatch("GRAPH_INVARIANT", "polarity", "connected admitted/rejected polarity is missing")
    report = {
        "agreementDigest": sha256(
            python_report.read_bytes()
            + third_report.read_bytes()
            + integration_path.read_bytes()
            + freeze_manifest.read_bytes()
        ).hexdigest(),
        "invalidClassifications": invalid_classifications,
        "connectedAdmissions": connected_admitted,
        "connectedRejections": connected_rejected,
        "admissionGraphs": 20,
        "kitDigest": kit_result["kitDigest"],
        "records": 53,
        "mismatchCount": len(mismatches),
        "mismatches": mismatches,
        "result": "PASS" if not mismatches else "FAIL",
        "runtimes": ["javascript", "python", "third-clean-room"],
        "transcriptConformanceChecks": valid_observations,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("compare")
    command.add_argument("--kit", type=Path, required=True)
    command.add_argument("--integration", type=Path, required=True)
    command.add_argument("--python-report", type=Path, required=True)
    command.add_argument("--node-report", type=Path, required=True)
    command.add_argument("--third-report", type=Path, required=True)
    command.add_argument("--freeze-manifest", type=Path, required=True)
    command.add_argument("--reader-root", type=Path, required=True)
    command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = compare(
            args.kit.resolve(), args.integration.resolve(), args.python_report.resolve(),
            args.node_report.resolve(), args.third_report.resolve(),
            args.freeze_manifest.resolve(), args.reader_root.resolve(),
        )
        store(args.output.resolve(), report)
        return 0 if report["result"] == "PASS" else 2
    except (BlindProjectionError, CleanRoomComparisonError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"c03_clean_room_comparison_failure={error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
