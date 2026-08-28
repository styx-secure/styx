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


THIRD_REPORT_SCHEMA = "styx-c03-clean-room-report/v1"


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


def _load_third(path: Path) -> dict[str, dict[str, Any]]:
    document = load(path)
    require(set(document) == {"observations", "schema"}, "third report shape mismatch")
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
    return result


def _load_first_party(path: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    report = load(path)
    require(report.get("result") == "PASS", "first-party report is not PASS")
    observations = report.get("observations")
    require(isinstance(observations, list), "first-party observations are absent")
    result: dict[str, dict[str, Any]] = {}
    for observation in observations:
        identifier = observation.get("id")
        require(isinstance(identifier, str) and identifier not in result, "first-party observation id mismatch")
        result[identifier] = observation
    return result, report


def _common_expected(expected: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in expected.items()
        if key != "referenceVerification"
    }


def _common_actual(actual: dict[str, Any]) -> dict[str, Any]:
    keys = set(PUBLIC_OBSERVATION_FIELDS) - {"referenceVerification"}
    result = {key: actual[key] for key in keys}
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
    require(isinstance(rows, list) and len(rows) == 43, "integration record count mismatch")
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
    third = _load_third(third_report)
    require(set(third) == kit_ids, "third report has missing or extra observations")
    python, python_document = _load_first_party(python_report)
    node, node_document = _load_first_party(node_report)
    require(python_report.read_bytes() == node_report.read_bytes(), "Python and JavaScript reports are not byte-identical")
    require(set(python) == set(node), "first-party observation sets differ")

    valid_observations = 0
    invalid_classifications = 0
    for opaque_id, row in sorted(by_opaque.items()):
        expected = row["expectedPublicObservation"]
        observed = dict(third[opaque_id])
        observed.pop("opaqueId")
        require(observed == expected, f"third-reader mismatch: {opaque_id}")
        report_id = row["reportObservationId"]
        require(report_id in python and report_id in node, f"missing first-party direct observation: {report_id}")
        require(_common_actual(python[report_id]) == _common_expected(expected), f"Python public observation mismatch: {report_id}")
        require(_common_actual(node[report_id]) == _common_expected(expected), f"JavaScript public observation mismatch: {report_id}")
        if row["set"] == "VALID":
            for field, value in (
                ("transcriptVerification", "VALID"),
                ("referenceVerification", "VALID"),
                ("signatureVerification", "VALID"),
            ):
                require(expected[field] == value, f"valid {field} mismatch: {opaque_id}")
                valid_observations += 1
            require(expected["commitmentVerification"] in {"NOT_PRESENT", "VALID"}, f"valid commitment mismatch: {opaque_id}")
            valid_observations += 1
            require(expected["kBindingAdmission"] == "ADMITTED", f"valid K admission mismatch: {opaque_id}")
        else:
            require(expected["localOutcomePresent"] and expected["outcomeEvaluated"], f"invalid classification absent: {opaque_id}")
            require(isinstance(expected.get("localOutcome"), str) and isinstance(expected["stage"], str), f"invalid classification malformed: {opaque_id}")
            invalid_classifications += 1
    require(valid_observations == 68, "valid observation count mismatch")
    require(invalid_classifications == 26, "invalid classification count mismatch")
    require(python_document["validVectors"] == 17 and python_document["invalidVectors"] == 26, "first-party vector count mismatch")
    return {
        "agreementDigest": sha256(
            python_report.read_bytes()
            + third_report.read_bytes()
            + integration_path.read_bytes()
            + freeze_manifest.read_bytes()
        ).hexdigest(),
        "invalidClassifications": invalid_classifications,
        "kitDigest": kit_result["kitDigest"],
        "records": 43,
        "result": "PASS",
        "runtimes": ["javascript", "python", "third-clean-room"],
        "validObservations": valid_observations,
    }


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
    except (BlindProjectionError, CleanRoomComparisonError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"c03_clean_room_comparison_failure={error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
