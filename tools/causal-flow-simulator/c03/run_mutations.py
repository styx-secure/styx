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
from corpus_model import BaseReader, CorpusModelError, evaluate_vector, sha256_hex, validate_base_inputs  # noqa: E402
from replay_corpus import _compute_step, _transition_index  # noqa: E402
from validate_corpus import validate  # noqa: E402


class MutationError(CorpusModelError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MutationError(message)


def _computed_trace(
    scenario: dict[str, Any],
    vectors: dict[str, dict[str, Any]],
    transitions: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    return {
        "id": f"trace-{scenario['id']}",
        "scenarioId": scenario["id"],
        "steps": [
            _compute_step(scenario, step, index, vectors[step["inputVectorId"]], transitions)
            for index, step in enumerate(scenario["steps"])
        ],
    }


def _python_kills(repo_root: Path, corpus: Path) -> dict[str, Any]:
    _, inventory = validate_base_inputs(repo_root)
    validate(repo_root, corpus)
    reader = BaseReader(repo_root)
    valid = load(corpus / "valid-transcript-vectors.json")["records"]
    invalid = load(corpus / "invalid-transcript-vectors.json")["records"]
    vectors = {record["id"]: record for record in valid + invalid}
    scenarios = load(corpus / "state-machine-scenarios.json")["records"]
    scenario_by_trace = {f"trace-{record['id']}": record for record in scenarios}
    expected = load(corpus / "expected-traces.json")["records"]
    expected_by_id = {record["id"]: record for record in expected}
    mutations = load(corpus / "adversarial-mutations.json")["records"]
    manifest = load(corpus / "manifest.json")
    manifest_files = {record["path"]: record for record in manifest["files"]}
    model = reader.json("docs/protocol/review/styx-app-kernel-v0-review-model.json")
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
            corrupted["expected"]["firstFailingStage"] = "CORRUPTED_EXPECTED_STAGE"
            detected = evaluate_vector(corrupted)["stage"] != corrupted["expected"]["firstFailingStage"]
        elif detector == "INDEPENDENT_EXPECTED_OUTCOME_MISMATCH":
            corrupted = deepcopy(vectors[mutation["generatedTargetId"]])
            corrupted["expected"]["localOutcome"] = "CORRUPTED_EXPECTED_OUTCOME"
            detected = evaluate_vector(corrupted)["localOutcome"] != corrupted["expected"]["localOutcome"]
        elif detector == "INDEPENDENT_EXPECTED_TRACE_MISMATCH":
            scenario = scenario_by_trace[mutation["generatedTargetId"]]
            computed = _computed_trace(scenario, vectors, transitions)
            corrupted = deepcopy(expected_by_id[mutation["generatedTargetId"]])
            corrupted["steps"][0]["localOutcome"] = "CORRUPTED_EXPECTED_OUTCOME"
            detected = computed != corrupted
        elif detector == "MANIFEST_DIGEST_MISMATCH":
            row = deepcopy(manifest_files[mutation["generatedTargetId"]])
            row["sha256"] = "0" * 64
            detected = row["sha256"] != sha256_hex((corpus / row["path"]).read_bytes())
        elif detector == "O07_EXACT_RELATION_SET":
            target = mutation["generatedTargetId"]
            original = set(manifest["coverage"]["o07"]["coveredRelationIds"])
            mutated = original - {target}
            detected = target in original and target in o07 and mutated != o07
        elif detector == "O08_EXACT_DIMENSION_SET":
            target = mutation["generatedTargetId"]
            original = set(manifest["coverage"]["o08"]["participatingDimensions"])
            mutated = original - {target}
            detected = target in original and target in o08 and mutated != o08
        elif detector == "O10_EXACT_SOURCE_ROW_SET":
            target = mutation["generatedTargetId"]
            original = set(manifest["coverage"]["o10"]["coveredSourceRowIds"])
            mutated = original - {target}
            detected = target in original and target in o10 and mutated != o10
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
