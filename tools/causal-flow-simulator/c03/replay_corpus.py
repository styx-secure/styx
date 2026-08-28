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
from corpus_model import BaseReader, CorpusModelError, evaluate_vector, validate_base_inputs  # noqa: E402
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
        require(scenario["modelId"] == "flow", "only a flow may expose a non-executed boundary")
        flow_id = scenario["id"].removeprefix("scenario-flow-")
        local_outcome = "TRANSPORT_PROFILE_REQUIRED" if flow_id == "transport_publish" else "SESSION_PROFILE_REQUIRED"
        stage = "BOUNDARY_NOT_EXECUTED"
        post_state = "UNCHANGED"
    elif step["transitionId"] is not None:
        transition = transitions.get((scenario["modelId"], step["transitionId"]))
        require(transition is not None, f"unknown transition: {scenario['id']}:{index}")
        require(step["preState"] in transition["from"], f"invalid transition source: {scenario['id']}:{index}")
        local_outcome = transition["outcome"]
        stage = "MODEL_TRANSITION"
        post_state = transition["to"]
    else:
        require(evaluated is not None, "executed step has no evaluation")
        local_outcome = evaluated["localOutcome"]
        stage = evaluated["stage"]
        post_state = "UNCHANGED" if evaluated["postStateDigest"] == evaluated["preStateDigest"] else "APPLIED"

    unchanged = post_state == "UNCHANGED" or not executed
    post_digest = pre_digest if unchanged else _digest(f"styx-c03/state/{scenario['id']}/{post_state}")
    available = available_evidence or set()
    requirements = set(step["requiredPriorEvidence"])
    dependency_status = "SATISFIED" if requirements <= available else "MISSING"
    if evaluated is None:
        k_admission = "NOT_EVALUATED"
        ap_result = "NOT_EVALUATED"
    elif evaluated["transcriptVerification"] != "VALID" or evaluated["signatureVerification"] == "REJECTED" or evaluated["localOutcome"] in {"CREDENTIAL_BINDING_MISMATCH", "REFERENCE_COLLISION_UNSUPPORTED"}:
        k_admission = "REJECTED"
        ap_result = "NOT_REACHED"
    else:
        k_admission = "ADMITTED"
        ap_result = "APPLIED" if evaluated["localOutcome"] == "APPLIED" else "REJECTED_OR_DEFERRED"
    return {
        "actionDigest": sha256(step["candidateAction"].encode()).hexdigest(),
        "apAuthorityResult": ap_result,
        "causalClassification": step["transitionId"] or f"VECTOR:{vector['id']}",
        "commitmentVerification": "NOT_PRESENT" if evaluated is None else evaluated["commitmentVerification"],
        "dependencyStatus": dependency_status,
        "evidenceConsumed": sorted(requirements),
        "evidenceProduced": step.get("providedEvidence"),
        "executed": executed,
        "externalEffects": [],
        "inputDigest": sha256(bytes.fromhex(vector["transcriptHex"])).hexdigest(),
        "kBindingAdmission": k_admission,
        "localOutcome": local_outcome,
        "postStateDigest": post_digest,
        "preStateDigest": pre_digest,
        "remoteClass": "APPLIED" if local_outcome == "APPLIED" else "OPAQUE_REMOTE_FAILURE",
        "signatureVerification": "NOT_EVALUATED" if evaluated is None else evaluated["signatureVerification"],
        "stage": stage,
        "step": index,
        "transcriptVerification": "NOT_EVALUATED" if evaluated is None else evaluated["transcriptVerification"],
    }


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
    return trace


def replay(repo_root: Path, corpus: Path) -> dict[str, Any]:
    validate_base_inputs(repo_root)
    validation = validate(repo_root, corpus)
    reader = BaseReader(repo_root)
    model = reader.json("docs/protocol/review/styx-app-kernel-v0-review-model.json")
    transitions = _transition_index(model)
    valid = load(corpus / "valid-transcript-vectors.json")["records"]
    invalid = load(corpus / "invalid-transcript-vectors.json")["records"]
    vectors = {record["id"]: record for record in valid + invalid}
    scenarios = load(corpus / "state-machine-scenarios.json")["records"]
    expected = load(corpus / "expected-traces.json")["records"]
    expected_by_scenario = {record["scenarioId"]: record for record in expected}
    computed: list[dict[str, Any]] = []
    for scenario in scenarios:
        trace = compute_trace(scenario, vectors, transitions)
        require(trace == expected_by_scenario.get(scenario["id"]), f"trace mismatch: {scenario['id']}")
        computed.append(trace)
    require(len(computed) == len(expected_by_scenario), "unexpected expected trace")
    return {
        "corpusDigest": validation["corpusDigest"],
        "invalidVectors": len(invalid),
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
