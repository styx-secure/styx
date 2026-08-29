#!/usr/bin/env python3
"""Build the static C0.3 evidence-explorer projection from pinned corpus bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PINNED_SHA256 = {
    "manifest.json": "9df88db2c9d606baf501f4f5ef8cfb71a212056f09ca7cd5f6ec4e2dcc753f44",
    "valid-transcript-vectors.json": "bd298de0f49a735fc753cdc8591c941169200444092bfbd913cfd8007fd961dd",
    "invalid-transcript-vectors.json": "54de44a9d301de118a6ce96eaf1b575cb5463fc2f39a6c29cded261729b67ba4",
    "expected-traces.json": "92bf9799675705fb82ad6de72d7a5f4c4bb15401e25c4eb1e5a4ccfb6c989c08",
    "state-machine-scenarios.json": "98eb17f87eb28568c5654ce306b8d4e2a4cae07647f2cd9cb9808e200ca986cc",
    "adversarial-mutations.json": "3b67430539406e23573369c583b4f115452529ffb1a7f2827e0403dc124fbfa4",
}

EXPECTED_COUNTS = {
    "validVectors": 17,
    "invalidVectors": 29,
    "scenarios": 118,
    "traces": 118,
    "mutations": 501,
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_pinned(corpus: Path, name: str) -> dict[str, Any]:
    path = corpus / name
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"missing or unsafe corpus file: {path}")
    raw = path.read_bytes()
    actual = _sha256(raw)
    expected = PINNED_SHA256[name]
    if actual != expected:
        raise SystemExit(f"corpus digest mismatch for {name}: {actual} != {expected}")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise SystemExit(f"corpus root must be an object: {name}")
    return value


def _records(document: dict[str, Any], name: str) -> list[dict[str, Any]]:
    records = document.get("records")
    if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
        raise SystemExit(f"invalid records array: {name}")
    identifiers = [item.get("id") for item in records]
    if any(not isinstance(identifier, str) or not identifier for identifier in identifiers):
        raise SystemExit(f"missing record identifier: {name}")
    if len(identifiers) != len(set(identifiers)):
        raise SystemExit(f"duplicate record identifier: {name}")
    return records


def _vector_summary(record: dict[str, Any], validity: str) -> dict[str, Any]:
    fields = record.get("fields") or {}
    transcript_hex = record.get("transcriptHex", "")
    if not isinstance(fields, dict) or not isinstance(transcript_hex, str):
        raise SystemExit(f"invalid vector structure: {record.get('id')}")
    summary: dict[str, Any] = {
        "id": record["id"],
        "validity": validity,
        "kind": record.get("kind"),
        "eventRole": fields.get("eventRole"),
        "eventTypeId": fields.get("eventTypeId"),
        "authorSequence": fields.get("authorSequence"),
        "causalParentCount": len(fields.get("causalParents") or []),
        "contentClass": (fields.get("content") or {}).get("class"),
        "signatureSuiteId": record.get("signatureSuiteId"),
        "transcriptOctets": len(transcript_hex) // 2,
        "synthetic": record.get("synthetic"),
        "testOnly": record.get("testOnly"),
    }
    if validity == "INVALID":
        summary["mutation"] = record.get("mutation")
        summary["sourceVectorId"] = record.get("sourceVectorId")
        summary["expected"] = record.get("expected")
    return summary


def build_projection(repo_root: Path) -> dict[str, Any]:
    corpus = repo_root / "conformance" / "application-protocol" / "c03"
    documents = {name: _load_pinned(corpus, name) for name in PINNED_SHA256}
    manifest = documents["manifest.json"]

    valid = _records(documents["valid-transcript-vectors.json"], "valid vectors")
    invalid = _records(documents["invalid-transcript-vectors.json"], "invalid vectors")
    scenarios = _records(documents["state-machine-scenarios.json"], "scenarios")
    traces = _records(documents["expected-traces.json"], "traces")
    mutations = _records(documents["adversarial-mutations.json"], "mutations")

    actual_counts = {
        "validVectors": len(valid),
        "invalidVectors": len(invalid),
        "scenarios": len(scenarios),
        "traces": len(traces),
        "mutations": len(mutations),
    }
    if actual_counts != EXPECTED_COUNTS:
        raise SystemExit(f"unexpected corpus counts: {actual_counts}")

    traces_by_scenario = {trace.get("scenarioId"): trace for trace in traces}
    scenario_ids = {scenario["id"] for scenario in scenarios}
    if set(traces_by_scenario) != scenario_ids:
        raise SystemExit("scenario/trace identifier relation is not exact")

    projected_scenarios = []
    for scenario in scenarios:
        trace = traces_by_scenario[scenario["id"]]
        expected_steps = scenario.get("steps")
        observed_steps = trace.get("steps")
        if not isinstance(expected_steps, list) or not isinstance(observed_steps, list):
            raise SystemExit(f"invalid steps: {scenario['id']}")
        if len(expected_steps) != len(observed_steps):
            raise SystemExit(f"step-count mismatch: {scenario['id']}")
        for index, observed in enumerate(observed_steps):
            if observed.get("step") != index:
                raise SystemExit(f"non-canonical trace step: {scenario['id']}:{index}")
        identity = {
            key: scenario[key]
            for key in ("flowId", "counterexampleId", "vectorId", "exercisedInvariantIds")
            if key in scenario
        }
        projected_scenarios.append(
            {
                "id": scenario["id"],
                "modelId": scenario.get("modelId"),
                "identity": identity,
                "citations": scenario.get("citations", []),
                "observationDigest": trace.get("observationDigest"),
                "semanticObservationDigest": trace.get("semanticObservationDigest"),
                "steps": [
                    {"expected": expected, "observed": observed}
                    for expected, observed in zip(expected_steps, observed_steps, strict=True)
                ],
            }
        )

    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, list):
        raise SystemExit("manifest files must be an array")
    manifest_digests = {item.get("path"): item.get("sha256") for item in manifest_files}
    for name in PINNED_SHA256:
        if name == "manifest.json":
            continue
        if manifest_digests.get(name) != PINNED_SHA256[name]:
            raise SystemExit(f"manifest does not bind pinned source: {name}")

    return {
        "schema": "styx-c03-evidence-explorer/v1",
        "source": {
            "profile": manifest.get("profile"),
            "synthetic": manifest.get("synthetic"),
            "manifestSha256": PINNED_SHA256["manifest.json"],
            "corpusFormatVersion": manifest.get("corpusFormatVersion"),
            "generatorBase": (manifest.get("sourceInventory") or {}).get("base"),
            "files": [
                {"path": name, "sha256": digest}
                for name, digest in sorted(PINNED_SHA256.items())
            ],
        },
        "authority": manifest.get("authority"),
        "nonClaims": manifest.get("nonClaims"),
        "counts": actual_counts,
        "vectors": [
            *(_vector_summary(record, "VALID") for record in valid),
            *(_vector_summary(record, "INVALID") for record in invalid),
        ],
        "scenarios": projected_scenarios,
        "mutations": mutations,
    }


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    output = args.output.resolve()
    projection = build_projection(repo_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_bytes(projection))


if __name__ == "__main__":
    main()
