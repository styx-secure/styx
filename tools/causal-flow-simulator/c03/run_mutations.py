#!/usr/bin/env python3
"""Kill every closed C0.3 adversarial mutant in Python and JavaScript."""

from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from canonical_json import load, store  # noqa: E402
from corpus_model import (  # noqa: E402
    MAX_U32,
    BaseReader,
    CorpusModelError,
    ProtocolError,
    evaluate_vector,
    load_local_json,
    o10_result,
    select_o10_result,
    sha256_hex,
    transition_input_is_compatible,
    validate_base_inputs,
    validate_geometry_predicates,
)
from replay_corpus import _transition_index, compute_trace  # noqa: E402
from validate_corpus import (  # noqa: E402
    EXPECTED_FILES,
    ValidationError,
    validate,
    validate_file_manifest,
    validate_source_coverage,
)


class MutationError(CorpusModelError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MutationError(message)


def _validator_rejects(operation: Any) -> bool:
    try:
        operation()
    except (ValidationError, CorpusModelError, KeyError, TypeError, ValueError):
        return True
    return False


def _computed_trace(
    scenario: dict[str, Any],
    vectors: dict[str, dict[str, Any]],
    transitions: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    return compute_trace(scenario, vectors, transitions)


def _geometry_predicate_mutant_is_killed(number: int) -> bool:
    cases: dict[int, tuple[int, str, dict[str, int] | None, str]] = {
        1: (0, "TREE", {"chunkSize": 1, "chunkCount": 2, "finalChunkLength": 1}, "FAIL"),
        2: (MAX_U32 - 131, "SINGLE", None, "FAIL"),
        3: (8, "TREE", {"chunkSize": 0, "chunkCount": 2, "finalChunkLength": 8}, "FAIL"),
        4: (8, "TREE", {"chunkSize": 8, "chunkCount": 2, "finalChunkLength": 1}, "FAIL"),
        5: (9, "TREE", {"chunkSize": 4, "chunkCount": 2, "finalChunkLength": 5}, "FAIL"),
        6: (9, "TREE", {"chunkSize": 4, "chunkCount": 3, "finalChunkLength": 2}, "FAIL"),
        # Predicate 7 follows algebraically from 4-6.  The source mutant makes
        # its inclusive upper boundary exclusive; this exact boundary kills it.
        7: (8, "TREE", {"chunkSize": 4, "chunkCount": 2, "finalChunkLength": 4}, "PASS"),
    }
    exact_length, shape, geometry, expected = cases[number]
    try:
        observations = validate_geometry_predicates(exact_length, shape, geometry)
    except ProtocolError as error:
        observations = error.observations
    return observations.get(f"geometryPredicate{number}") == expected


def _python_kills(repo_root: Path, corpus: Path) -> dict[str, Any]:
    _, inventory = validate_base_inputs(repo_root)
    validate(repo_root, corpus)
    reader = BaseReader(repo_root)
    valid = load(corpus / "valid-transcript-vectors.json")["records"]
    invalid_document = load(corpus / "invalid-transcript-vectors.json")
    invalid = invalid_document["records"]
    ap_expectations = invalid_document["apExpectationOnlyRecords"]
    vectors = {
        record["id"]: record
        for record in valid + invalid + ap_expectations
    }
    scenarios = load(corpus / "state-machine-scenarios.json")["records"]
    scenario_by_trace = {f"trace-{record['id']}": record for record in scenarios}
    expected = load(corpus / "expected-traces.json")["records"]
    expected_by_id = {record["id"]: record for record in expected}
    mutations = load(corpus / "adversarial-mutations.json")["records"]
    manifest = load(corpus / "manifest.json")
    documents = {name: load(corpus / name) for name in EXPECTED_FILES}
    manifest_files = {record["path"]: record for record in manifest["files"]}
    model = load_local_json(
        repo_root / "docs/protocol/review/styx-app-kernel-v0-review-model.json"
    )
    transitions = _transition_index(model)
    o07 = {
        row["atom_instance_id"]
        for row in reader.json("tools/causal-flow-simulator/o07/required_atom_instances_v1.json")["rows"]
    }
    o08 = {
        identifier
        for role in (
            "C03_SEMANTIC_LIMIT",
            "C03_ACTIVATION_CAPABILITY_INPUT",
            "C03_EXPLICIT_ZERO_OR_UNSUPPORTED",
        )
        for identifier in inventory["o08_roles"][role]
    }
    o10 = {
        row["row_id"]
        for row in reader.json("tools/causal-flow-simulator/o10/source-inventory.json")["rows"]
    }
    killed: list[str] = []
    for mutation in mutations:
        detector = mutation["detector"]
        detected = False
        if detector == "INDEPENDENT_REPLAY_EXPECTATION_MISMATCH":
            observed = evaluate_vector(vectors[mutation["generatedTargetId"]])
            detected = observed["localOutcome"] == mutation["expectedOutcome"] and observed["stage"] == mutation["expectedStage"]
        elif detector == "INDEPENDENT_EXPECTED_STAGE_MISMATCH":
            corrupted = deepcopy(vectors[mutation["generatedTargetId"]])
            corrupted["expected"]["firstFailingStage"] = "FINAL_AFTER_S6"
            detected = evaluate_vector(corrupted)["stage"] != corrupted["expected"]["firstFailingStage"]
        elif detector == "INDEPENDENT_EXPECTED_OUTCOME_MISMATCH":
            corrupted = deepcopy(vectors[mutation["generatedTargetId"]])
            corrupted["expected"]["localOutcome"] = "APPLIED"
            detected = evaluate_vector(corrupted)["localOutcome"] != corrupted["expected"]["localOutcome"]
        elif detector == "INDEPENDENT_EXPECTED_TRACE_MISMATCH":
            scenario = scenario_by_trace[mutation["generatedTargetId"]]
            computed = _computed_trace(scenario, vectors, transitions)
            corrupted = deepcopy(expected_by_id[mutation["generatedTargetId"]])
            corrupted["steps"][0]["localOutcome"] = "INVALID"
            detected = computed != corrupted
        elif detector == "INDEPENDENT_EXPECTED_DEPENDENCY_STATUS_MISMATCH":
            scenario = scenario_by_trace[mutation["generatedTargetId"]]
            computed = _computed_trace(scenario, vectors, transitions)
            corrupted = deepcopy(expected_by_id[mutation["generatedTargetId"]])
            corrupted["steps"][0]["dependencyStatus"] = "SATISFIED"
            detected = computed != corrupted
        elif detector == "INVARIANT_WITNESS_TRACE_MISMATCH":
            scenario = deepcopy(scenario_by_trace[mutation["generatedTargetId"]])
            scenario["steps"][0]["inputVectorId"] = mutation["replacementVectorId"]
            detected = _computed_trace(scenario, vectors, transitions) != expected_by_id[mutation["generatedTargetId"]]
        elif detector == "MANIFEST_DIGEST_MISMATCH":
            mutated_manifest = deepcopy(manifest)
            row = next(item for item in mutated_manifest["files"] if item["path"] == mutation["generatedTargetId"])
            alternatives = [item["sha256"] for item in mutated_manifest["files"] if item["path"] != row["path"]]
            row["sha256"] = alternatives[0]
            detected = _validator_rejects(lambda: validate_file_manifest(corpus, documents, mutated_manifest))
        elif detector == "O07_EXACT_RELATION_SET":
            target = mutation["generatedTargetId"]
            mutated_manifest = deepcopy(manifest)
            mutated_manifest["coverage"]["o07"]["coveredRelationIds"].remove(target)
            detected = target in o07 and _validator_rejects(lambda: validate_source_coverage(reader, inventory, mutated_manifest["coverage"]))
        elif detector == "O08_EXACT_DIMENSION_SET":
            target = mutation["generatedTargetId"]
            mutated_manifest = deepcopy(manifest)
            mutated_manifest["coverage"]["o08"]["participatingDimensions"].remove(target)
            detected = target in o08 and _validator_rejects(lambda: validate_source_coverage(reader, inventory, mutated_manifest["coverage"]))
        elif detector == "O10_EXACT_SOURCE_ROW_SET":
            target = mutation["generatedTargetId"]
            mutated_manifest = deepcopy(manifest)
            mutated_manifest["coverage"]["o10"]["coveredSourceRowIds"].remove(target)
            detected = target in o10 and _validator_rejects(lambda: validate_source_coverage(reader, inventory, mutated_manifest["coverage"]))
        elif detector == "SOURCE_O10_CLASS_MEMBERSHIP":
            detected = _validator_rejects(
                lambda: o10_result("APPLIED", "FINAL_AFTER_S6")
            )
        elif detector == "SOURCE_O10_APPLICABILITY":
            detected = _validator_rejects(
                lambda: o10_result("LENGTH_MISMATCH", "EVENT_LOCAL")
            )
        elif detector == "SOURCE_O10_PRECEDENCE":
            selected = select_o10_result(
                [
                    ("COMMITMENT_MISMATCH", "S3_KERNEL_STRUCTURAL"),
                    ("LENGTH_MISMATCH", "S3_KERNEL_STRUCTURAL"),
                ]
            )
            detected = selected["localOutcome"] == "LENGTH_MISMATCH"
        elif detector == "SOURCE_CHECKPOINT_BEFORE_PROTECTED_WORK":
            corrupted = deepcopy(vectors[mutation["generatedTargetId"]])
            corrupted.setdefault("admissionContext", {})[
                "checkpointEvidenceReferences"
            ] = ["00" * 32]
            observed = evaluate_vector(corrupted)
            detected = (
                observed.get("localOutcome") == "CURRENT_OBJECT_OUT_OF_PROFILE"
                and observed.get("signatureVerification") == "NOT_EVALUATED"
                and observed.get("commitmentVerification") == "NOT_PRESENT"
            )
        elif detector == "SOURCE_GEOMETRY_PREDICATE":
            detected = _geometry_predicate_mutant_is_killed(
                mutation["predicateNumber"]
            )
        elif detector == "SOURCE_R6_CLASSIFICATION":
            observed = evaluate_vector(vectors[mutation["generatedTargetId"]])
            detected = (
                observed.get("localOutcome") == "CURRENT_OBJECT_OUT_OF_PROFILE"
                and observed.get("stage") == "S3_KERNEL_STRUCTURAL"
                and observed.get("signatureVerification") == "NOT_EVALUATED"
                and all(
                    observed.get(f"geometryPredicate{number}") == "PASS"
                    for number in (1, 3, 4, 5, 6, 7)
                )
            )
        elif detector == "SOURCE_R5_LAYERING":
            observed = evaluate_vector(vectors[mutation["generatedTargetId"]])
            detected = (
                transition_input_is_compatible(observed)
                and observed.get("apAuthorityResult") == "AP_FOLD_NOT_EXECUTED"
                and observed.get("outcomeEvaluated") is False
                and "localOutcome" not in observed
                and "remoteClass" not in observed
            )
        require(detected, f"surviving Python mutation: {mutation['id']}")
        killed.append(mutation["id"])
    killed.sort()
    return {
        "killDigest": sha256(("\n".join(killed) + "\n").encode()).hexdigest(),
        "killed": len(killed),
        "result": "PASS",
    }


def run(repo_root: Path, corpus: Path) -> dict[str, Any]:
    python_report = _python_kills(repo_root, corpus)
    with tempfile.TemporaryDirectory(prefix="styx-c03-mutations-") as directory:
        node_path = Path(directory) / "node.json"
        completed = subprocess.run(
            ["node", str(ROOT / "node_adapter.mjs"), "--repo-root", str(repo_root),
             "--corpus", str(corpus), "--output", str(node_path), "--mode", "mutations"],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
        )
        require(completed.returncode == 0, f"JavaScript mutation run failed: {completed.stderr.strip()}")
        node_report = load(node_path)
    require(node_report == python_report, "Python and JavaScript mutation reports differ")
    return {**python_report, "runtimes": ["javascript", "python"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        store(args.output.resolve(), run(args.repo_root.resolve(), args.corpus.resolve()))
    except (CorpusModelError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"c03_mutation_failure={error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
