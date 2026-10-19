#!/usr/bin/env python3
"""Replay the tracked C0.3 corpus without using expected traces as an oracle."""

from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from canonical_json import dumps, load, store  # noqa: E402
from corpus_model import (  # noqa: E402
    BaseReader,
    CorpusModelError,
    evaluate_k_admission_graph,
    evaluate_k_admission_scenario,
    evaluate_transcript_conformance,
    evaluate_vector,
    load_local_json,
    semantic_input_digest,
    semantic_k_graph_input_digest,
    semantic_observation_digest,
    transition_input_is_compatible,
    validate_base_inputs,
    SEMANTIC_OBSERVATION_FIELDS,
    OPTIONAL_SEMANTIC_OBSERVATION_FIELDS,
    public_transcript_observation,
)
from validate_corpus import validate  # noqa: E402


class ReplayError(CorpusModelError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayError(message)


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _transition_index(model: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (machine["id"], transition["id"]): transition
        for machine in model["state_models"]
        for transition in machine["transitions"]
    }


def _compute_step(
    scenario: dict[str, Any],
    step: dict[str, Any],
    index: int,
    vector: dict[str, Any] | None,
    transitions: dict[tuple[str, str], dict[str, Any]],
    k_records: dict[str, dict[str, Any]],
    k_scenarios: dict[str, dict[str, Any]],
    available_evidence: set[str] | None = None,
) -> dict[str, Any]:
    executed = step.get("executed", True)
    layer = step["evidenceLayer"]
    input_digest: str
    input_label: str
    if not executed:
        require(vector is not None, "boundary step has no vector")
        evaluated = None
        input_digest = semantic_input_digest(vector)
        input_label = f"VECTOR:{vector['id']}"
    elif layer == "CONNECTED_K_ADMISSION":
        scenario_id = step.get("inputKAdmissionScenarioId")
        target_id = step.get("inputKAdmissionRecordId")
        connected = k_scenarios.get(scenario_id)
        require(connected is not None, f"unknown connected K scenario: {scenario_id}")
        genesis = k_records.get(connected["acceptedGenesisRecordId"])
        records = [k_records.get(identifier) for identifier in connected["recordIds"]]
        require(genesis is not None and all(record is not None for record in records), "connected K record missing")
        typed_records = [record for record in records if record is not None]
        observations = evaluate_k_admission_scenario(genesis, typed_records)
        evaluated = next((row for row in observations if row["id"] == target_id), None)
        require(evaluated is not None, f"unknown connected K target: {target_id}")
        input_digest = semantic_k_graph_input_digest(genesis, typed_records, target_id)
        input_label = f"K_GRAPH:{scenario_id}:{target_id}"
    else:
        require(vector is not None, f"{layer} step has no vector")
        if layer == "TRANSCRIPT_CONFORMANCE":
            evaluated = evaluate_transcript_conformance(vector)
        elif layer == "LOCAL_NEGATIVE":
            evaluated = evaluate_vector(vector)
        else:
            raise ReplayError(f"unknown evidence layer: {layer}")
        input_digest = semantic_input_digest(vector)
        input_label = f"VECTOR:{vector['id']}"
    pre_digest = _digest(f"styx-c03/state/{scenario['id']}/{step['preState']}")

    if not executed:
        require(
            scenario["modelId"] in {"flow", "ap_projection"},
            "only a flow or AP projection may expose a non-executed boundary",
        )
        if scenario["modelId"] == "flow":
            flow_id = scenario["id"].removeprefix("scenario-flow-")
            local_outcome = (
                "TRANSPORT_PROFILE_REQUIRED"
                if flow_id == "transport_publish"
                else "SESSION_PROFILE_REQUIRED"
            )
        else:
            local_outcome = "NOT_EVALUATED"
        observation = {
            "apAuthorityResult": "NOT_EVALUATED",
            "commitmentMatchVerification": "NOT_EVALUATED",
            "commitmentVerification": "NOT_PRESENT",
            "externalEffects": [],
            **{f"geometryPredicate{number}": "NOT_EVALUATED" for number in range(1, 8)},
            "kBindingAdmission": "NOT_EVALUATED",
            "localOutcome": local_outcome,
            "outcomeEvaluated": False,
            "remoteClass": "OPAQUE_REMOTE_FAILURE",
            "signatureVerification": "NOT_EVALUATED",
            "stage": "BOUNDARY_NOT_EXECUTED",
            "suppliedLengthVerification": "NOT_EVALUATED",
            "transcriptVerification": "NOT_EVALUATED",
        }
        post_state = "UNCHANGED"
    elif step["transitionId"] is not None:
        transition = transitions.get((scenario["modelId"], step["transitionId"]))
        require(transition is not None, f"unknown transition: {scenario['id']}:{index}")
        require(step["preState"] in transition["from"], f"invalid transition source: {scenario['id']}:{index}")
        if transition.get("result_layer") == "K_ADMISSION_ONLY":
            require(
                transition_input_is_compatible(evaluated or {}),
                f"incompatible positive K transition: {scenario['id']}:{index}",
            )
        else:
            require(
                evaluated is not None
                and evaluated.get("outcomeEvaluated") is True
                and evaluated.get("localOutcome") == transition["outcome"],
                f"incompatible negative K transition: {scenario['id']}:{index}",
            )
        observation = {
            key: value
            for key, value in (evaluated or {}).items()
            if key not in {
                "eventReferenceHex",
                "id",
                "preStateDigest",
                "postStateDigest",
                "protocolErrorCode",
            }
        }
        post_state = transition["to"]
    else:
        require(evaluated is not None, "executed step has no evaluation")
        observation = {
            key: value
            for key, value in evaluated.items()
            if key not in {
                "eventReferenceHex",
                "id",
                "preStateDigest",
                "postStateDigest",
                "protocolErrorCode",
            }
        }
        post_state = (
            "UNCHANGED"
            if layer == "TRANSCRIPT_CONFORMANCE"
            or evaluated["postStateDigest"] == evaluated["preStateDigest"]
            else "READY_FOR_AP_FOLD"
        )

    unchanged = post_state == "UNCHANGED" or not executed
    post_digest = pre_digest if unchanged else _digest(f"styx-c03/state/{scenario['id']}/{post_state}")
    available = available_evidence or set()
    requirements = set(step["requiredPriorEvidence"])
    dependency_status = "SATISFIED" if requirements <= available else "MISSING"
    require(
        dependency_status == step["expectedDependencyStatus"],
        f"dependency status mismatch: {scenario['id']}:{index}",
    )
    result = {
        "actionDigest": sha256(step["candidateAction"].encode()).hexdigest(),
        "causalClassification": step["transitionId"] or input_label,
        "dependencyStatus": dependency_status,
        "evidenceConsumed": sorted(requirements),
        "evidenceProduced": step.get("providedEvidence"),
        "executed": executed,
        "inputDigest": input_digest,
        "postStateDigest": post_digest,
        "preStateDigest": pre_digest,
        "step": index,
    }
    result.update(observation)
    if "apExpectationOnly" in step:
        result["apExpectationOnly"] = step["apExpectationOnly"]
    return result


def compute_trace(
    scenario: dict[str, Any],
    vectors: dict[str, dict[str, Any]],
    transitions: dict[tuple[str, str], dict[str, Any]],
    k_records: dict[str, dict[str, Any]] | None = None,
    k_scenarios: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    k_records = k_records or {}
    k_scenarios = k_scenarios or {}
    available_evidence: set[str] = set()
    steps: list[dict[str, Any]] = []
    for index, step in enumerate(scenario["steps"]):
        computed = _compute_step(
            scenario,
            step,
            index,
            vectors.get(step.get("inputVectorId")),
            transitions,
            k_records,
            k_scenarios,
            available_evidence,
        )
        steps.append(computed)
        if step.get("providedEvidence") is not None:
            available_evidence.add(step["providedEvidence"])
    trace = {"id": f"trace-{scenario['id']}", "scenarioId": scenario["id"], "steps": steps}
    trace["observationDigest"] = sha256(
        dumps({"scenarioId": scenario["id"], "steps": steps})
    ).hexdigest()
    trace["semanticObservationDigest"] = semantic_observation_digest(steps)
    return trace


def replay(repo_root: Path, corpus: Path) -> dict[str, Any]:
    validate_base_inputs(repo_root)
    validation = validate(repo_root, corpus)
    model = load_local_json(
        repo_root / "docs/protocol/review/styx-app-kernel-v0-review-model.json"
    )
    transitions = _transition_index(model)
    valid_document = load(corpus / "valid-transcript-vectors.json")
    valid = valid_document["records"]
    invalid_document = load(corpus / "invalid-transcript-vectors.json")
    invalid = invalid_document["records"]
    ap_expectations = invalid_document["apExpectationOnlyRecords"]
    vectors = {
        record["id"]: record
        for record in valid + invalid + ap_expectations
    }
    scenario_document = load(corpus / "state-machine-scenarios.json")
    scenarios = scenario_document["records"]
    k_by_id = {
        record["id"]: record
        for record in valid_document["kAdmissionRecords"]
    }
    k_scenario_by_id = {
        scenario["id"]: scenario
        for scenario in scenario_document["kAdmissionScenarios"]
    }
    expected = load(corpus / "expected-traces.json")["records"]
    expected_by_scenario = {record["scenarioId"]: record for record in expected}
    computed: list[dict[str, Any]] = []
    for scenario in scenarios:
        trace = compute_trace(
            scenario,
            vectors,
            transitions,
            k_by_id,
            k_scenario_by_id,
        )
        require(trace == expected_by_scenario.get(scenario["id"]), f"trace mismatch: {scenario['id']}")
        computed.append(trace)
    require(len(computed) == len(expected_by_scenario), "unexpected expected trace")
    observations = []
    for trace in computed:
        for step in trace["steps"]:
            observation = {
                "id": f"{trace['scenarioId']}:{step['step']}",
                **{field: step[field] for field in SEMANTIC_OBSERVATION_FIELDS},
            }
            for field in OPTIONAL_SEMANTIC_OBSERVATION_FIELDS:
                present = field in step
                observation[f"{field}Present"] = present
                if present:
                    observation[field] = step[field]
            observations.append(observation)
    blind_transcript_observations = [
        {"id": record["id"], **public_transcript_observation(record)}
        for record in sorted(valid + invalid, key=lambda row: row["id"])
    ]
    blind_admission_graphs = []
    for scenario in scenario_document["kAdmissionScenarios"]:
        blind_admission_graphs.append(
            {
                "id": scenario["id"],
                "observations": evaluate_k_admission_graph(
                    k_by_id[scenario["acceptedGenesisRecordId"]],
                    [k_by_id[identifier] for identifier in scenario["recordIds"]],
                ),
            }
        )
    adversarial = load(corpus / "adversarial-mutations.json")
    for scenario in adversarial["kAdmissionScenarios"]:
        blind_admission_graphs.append(
            {
                "id": scenario["id"],
                "observations": evaluate_k_admission_graph(
                    scenario["acceptedGenesisRecord"], scenario["records"]
                ),
            }
        )
    return {
        "blindAdmissionGraphs": sorted(
            blind_admission_graphs, key=lambda row: row["id"]
        ),
        "blindTranscriptObservations": blind_transcript_observations,
        "corpusDigest": validation["corpusDigest"],
        "invalidVectors": len(invalid),
        "kAdmissionDigest": validation["kAdmissionDigest"],
        "kAdmissionHostileScenarios": validation[
            "kAdmissionHostileScenarios"
        ],
        "kAdmissionRecords": validation["kAdmissionRecords"],
        "kAdmissionScenarios": validation["kAdmissionScenarios"],
        "observations": sorted(observations, key=lambda record: record["id"]),
        "result": "PASS",
        "scenarios": len(computed),
        "traceDigest": sha256(b"".join(
            (corpus / "expected-traces.json").read_bytes() for _ in range(1)
        )).hexdigest(),
        "validVectors": len(valid),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = replay(args.repo_root.resolve(), args.corpus.resolve())
        store(args.output.resolve(), report)
    except (CorpusModelError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"c03_replay_failure={error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
