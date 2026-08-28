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
    evaluate_vector,
    load_local_json,
    semantic_input_digest,
    semantic_observation_digest,
    transition_input_is_compatible,
    validate_base_inputs,
    SEMANTIC_OBSERVATION_FIELDS,
    OPTIONAL_SEMANTIC_OBSERVATION_FIELDS,
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
    vector: dict[str, Any],
    transitions: dict[tuple[str, str], dict[str, Any]],
    available_evidence: set[str] | None = None,
) -> dict[str, Any]:
    executed = step.get("executed", True)
    evaluated = evaluate_vector(vector) if executed else None
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
            if key not in {"preStateDigest", "postStateDigest"}
        }
        post_state = transition["to"]
    else:
        require(evaluated is not None, "executed step has no evaluation")
        observation = {
            key: value
            for key, value in evaluated.items()
            if key not in {"preStateDigest", "postStateDigest"}
        }
        post_state = (
            "UNCHANGED"
            if evaluated["postStateDigest"] == evaluated["preStateDigest"]
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
        "causalClassification": step["transitionId"] or f"VECTOR:{vector['id']}",
        "dependencyStatus": dependency_status,
        "evidenceConsumed": sorted(requirements),
        "evidenceProduced": step.get("providedEvidence"),
        "executed": executed,
        "inputDigest": semantic_input_digest(vector),
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
) -> dict[str, Any]:
    available_evidence: set[str] = set()
    steps: list[dict[str, Any]] = []
    for index, step in enumerate(scenario["steps"]):
        computed = _compute_step(
            scenario,
            step,
            index,
            vectors[step["inputVectorId"]],
            transitions,
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
    valid = load(corpus / "valid-transcript-vectors.json")["records"]
    invalid_document = load(corpus / "invalid-transcript-vectors.json")
    invalid = invalid_document["records"]
    ap_expectations = invalid_document["apExpectationOnlyRecords"]
    vectors = {
        record["id"]: record
        for record in valid + invalid + ap_expectations
    }
    scenarios = load(corpus / "state-machine-scenarios.json")["records"]
    expected = load(corpus / "expected-traces.json")["records"]
    expected_by_scenario = {record["scenarioId"]: record for record in expected}
    computed: list[dict[str, Any]] = []
    for scenario in scenarios:
        trace = compute_trace(scenario, vectors, transitions)
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
    return {
        "corpusDigest": validation["corpusDigest"],
        "invalidVectors": len(invalid),
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
