#!/usr/bin/env python3
"""Fail-closed validator for the six-file transcript-only C0.3 corpus."""

from __future__ import annotations

import argparse
from hashlib import sha256
import re
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from canonical_json import load, store  # noqa: E402
from corpus_model import (  # noqa: E402
    BASE_SHA,
    BaseReader,
    CorpusModelError,
    NONEXECUTABLE_INVARIANTS,
    O08_CHUNK_OCTETS,
    O08_LIMITS,
    evaluate_vector,
    load_local_json,
    sha256_hex,
    validate_base_inputs,
)


EXPECTED_FILES = frozenset(
    {
        "adversarial-mutations.json",
        "expected-traces.json",
        "invalid-transcript-vectors.json",
        "manifest.json",
        "state-machine-scenarios.json",
        "valid-transcript-vectors.json",
    }
)
SCHEMAS = {
    "adversarial-mutations.json": "styx-c03-adversarial-mutations/v1",
    "expected-traces.json": "styx-c03-expected-traces/v1",
    "invalid-transcript-vectors.json": "styx-c03-invalid-transcripts/v1",
    "manifest.json": "styx-c03-corpus-manifest/v1",
    "state-machine-scenarios.json": "styx-c03-state-scenarios/v1",
    "valid-transcript-vectors.json": "styx-c03-valid-transcripts/v1",
}
ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:/(?:[^\s/][^\s]*|(?=$|[\],;}]))|"
    r"\\(?:[^\s\\][^\s]*|(?=$|[\],;}]))|[A-Za-z]:[\\/]|\\\\[^\\\s]+[\\/])"
)
TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
RUNTIME_VALUE = re.compile(r"\b(?:elapsed|duration|runtime|hostname|username|pid)\s*[:=]", re.I)


class ValidationError(CorpusModelError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _walk_hygiene(value: Any, location: str = "$") -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        raise ValidationError(f"float in canonical corpus: {location}")
    if isinstance(value, str):
        if ABSOLUTE_PATH.search(value) or TIMESTAMP.search(value) or RUNTIME_VALUE.search(value):
            raise ValidationError(f"environment-derived value in canonical corpus: {location}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _walk_hygiene(item, f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"timestamp", "elapsed", "duration", "hostname", "username", "pid"}:
                raise ValidationError(f"environment-derived key in canonical corpus: {location}.{key}")
            _walk_hygiene(item, f"{location}.{key}")
        return
    raise ValidationError(f"unsupported value in canonical corpus: {location}")


def _unique_sorted(records: Any, label: str) -> list[dict[str, Any]]:
    require(isinstance(records, list), f"{label} records are not a list")
    identifiers = [record.get("id") for record in records if isinstance(record, dict)]
    require(len(identifiers) == len(records), f"{label} record is not an object")
    require(all(isinstance(identifier, str) and identifier.isascii() for identifier in identifiers), f"{label} identifier invalid")
    require(identifiers == sorted(identifiers), f"{label} records are not identifier-sorted")
    require(len(identifiers) == len(set(identifiers)), f"{label} duplicate identifier")
    return records


def _citation_valid(
    reader: BaseReader,
    source_paths: dict[str, str],
    citation: dict[str, Any],
) -> bool:
    if set(citation) == {"anchor", "source_id"}:
        path = source_paths.get(citation["source_id"])
    elif set(citation) == {"anchor", "path"}:
        path = citation["path"] if citation["path"] in set(source_paths.values()) else None
    else:
        return False
    if path is None:
        return False
    try:
        text = reader.read(path).decode("utf-8")
    except (CorpusModelError, UnicodeDecodeError):
        return False
    return isinstance(citation["anchor"], str) and text.count(citation["anchor"]) == 1


def validate_source_coverage(
    reader: BaseReader,
    inventory: dict[str, Any],
    coverage: dict[str, Any],
) -> None:
    """Validate source-derived exact sets using the production corpus gate."""

    expected_o07 = {
        row["atom_instance_id"]
        for row in reader.json("tools/causal-flow-simulator/o07/required_atom_instances_v1.json")["rows"]
    }
    expected_o08 = {
        identifier
        for role in (
            "C03_SEMANTIC_LIMIT",
            "C03_ACTIVATION_CAPABILITY_INPUT",
            "C03_EXPLICIT_ZERO_OR_UNSUPPORTED",
        )
        for identifier in inventory["o08_roles"][role]
    }
    excluded_o08 = set(inventory["o08_roles"]["POST_C03_LAYER_PROFILE"] + inventory["o08_roles"]["EVIDENCE_ONLY"])
    expected_o10 = {
        row["row_id"]
        for row in reader.json("tools/causal-flow-simulator/o10/source-inventory.json")["rows"]
    }
    require(
        coverage["o07"]["relationCount"] == len(expected_o07)
        and set(coverage["o07"]["coveredRelationIds"]) == expected_o07
        and len(coverage["o07"]["coveredRelationIds"]) == len(expected_o07),
        "O-07 coverage mismatch",
    )
    require(
        set(coverage["o08"]["participatingDimensions"]) == expected_o08
        and len(coverage["o08"]["participatingDimensions"]) == len(expected_o08)
        and set(coverage["o08"]["excludedDimensions"]) == excluded_o08
        and len(coverage["o08"]["excludedDimensions"]) == len(excluded_o08),
        "O-08 coverage mismatch",
    )
    require(
        set(coverage["o10"]["coveredSourceRowIds"]) == expected_o10
        and len(coverage["o10"]["coveredSourceRowIds"]) == len(expected_o10),
        "O-10 source coverage mismatch",
    )


def validate_file_manifest(
    corpus: Path,
    documents: dict[str, dict[str, Any]],
    manifest: dict[str, Any],
) -> None:
    expected_entries = []
    for name in sorted(EXPECTED_FILES - {"manifest.json"}):
        records = _unique_sorted(documents[name].get("records"), name)
        expected_entries.append(
            {"path": name, "recordCount": len(records), "sha256": sha256_hex((corpus / name).read_bytes())}
        )
    require(manifest.get("files") == expected_entries, "manifest file digests/counts mismatch")


def validate(repo_root: Path, corpus: Path) -> dict[str, Any]:
    source_map, inventory = validate_base_inputs(repo_root)
    reader = BaseReader(repo_root)
    model = reader.json("docs/protocol/review/styx-app-kernel-v0-review-model.json")
    source_paths = {source["id"]: source["path"] for source in model["sources"]}
    source_paths.update({source["id"]: source["path"] for source in source_map["direct_sources"]})
    entries = list(corpus.rglob("*"))
    require(
        all(
            not path.is_symlink()
            and path.is_file()
            and len(path.relative_to(corpus).parts) == 1
            for path in entries
        ),
        "corpus entries must be regular top-level files",
    )
    actual_files = {path.name for path in entries}
    require(actual_files == EXPECTED_FILES, "corpus file set mismatch")
    documents: dict[str, dict[str, Any]] = {}
    for name in sorted(EXPECTED_FILES):
        document = load(corpus / name)
        require(isinstance(document, dict), f"{name} must contain one object")
        require(document.get("schema") == SCHEMAS[name], f"{name} schema mismatch")
        _walk_hygiene(document)
        documents[name] = document

    manifest = documents["manifest.json"]
    require(manifest.get("synthetic") is True and manifest.get("upstreamBytes") == "none", "provenance mismatch")
    require(manifest.get("authority") == {
        "blocks": ["demo", "implementation_alignment", "product", "sensitive_use"],
        "c03Verdict": "NO_GO",
        "corpusConstruction": "COMPLETE",
    }, "C0.3 authority boundary mismatch")
    validate_file_manifest(corpus, documents, manifest)
    require(
        manifest.get("generator", {}).get("sha256")
        == sha256_hex((repo_root / "tools/causal-flow-simulator/c03/generate_corpus.py").read_bytes()),
        "generator digest mismatch",
    )
    require(
        manifest.get("sourceInventory", {}).get("base") == BASE_SHA
        and manifest["sourceInventory"].get("corpusInventorySha256")
        == sha256_hex((repo_root / "tools/causal-flow-simulator/c03/corpus-inventory.json").read_bytes())
        and manifest["sourceInventory"].get("corpusSourceMapSha256")
        == sha256_hex((repo_root / "tools/causal-flow-simulator/c03/corpus-source-map.json").read_bytes()),
        "source inventory digest mismatch",
    )
    expected_sources = sorted(
        ({"path": source["path"], "sha256": source["sha256"]} for source in source_map["direct_sources"]),
        key=lambda item: item["path"],
    )
    require(manifest["sourceInventory"].get("sources") == expected_sources, "manifest source set mismatch")

    valid = _unique_sorted(documents["valid-transcript-vectors.json"]["records"], "valid vectors")
    invalid = _unique_sorted(documents["invalid-transcript-vectors.json"]["records"], "invalid vectors")
    vector_ids = {record["id"] for record in valid + invalid}
    for record in valid:
        require(all(_citation_valid(reader, source_paths, citation) for citation in record["citations"]), f"stale citation: {record['id']}")
        result = evaluate_vector(record)
        require(result["localOutcome"] == "APPLIED", f"valid vector rejected: {record['id']}")
    for record in invalid:
        result = evaluate_vector(record)
        expected = record["expected"]
        require(result["localOutcome"] == expected["localOutcome"], f"invalid outcome mismatch: {record['id']}")
        require(result["stage"] == expected["firstFailingStage"], f"invalid stage mismatch: {record['id']}")
        require(result["preStateDigest"] == result["postStateDigest"], f"invalid vector mutated state: {record['id']}")
        require(result["externalEffects"] == [], f"invalid vector emitted effect: {record['id']}")

    transition_index = {
        (state_model["id"], transition["id"]): transition
        for state_model in model["state_models"]
        for transition in state_model["transitions"]
    }
    scenarios = _unique_sorted(documents["state-machine-scenarios.json"]["records"], "scenarios")
    scenario_ids = {record["id"] for record in scenarios}
    used_vector_ids: set[str] = set()
    exercised_transitions: set[tuple[str, str]] = set()
    reached_states: set[tuple[str, str]] = set()
    for scenario in scenarios:
        require(all(_citation_valid(reader, source_paths, citation) for citation in scenario["citations"]), f"stale scenario citation: {scenario['id']}")
        require(isinstance(scenario.get("steps"), list) and scenario["steps"], f"empty scenario: {scenario['id']}")
        available_evidence: set[str] = set()
        for step in scenario["steps"]:
            require(step["inputVectorId"] in vector_ids, f"unknown vector reference: {scenario['id']}")
            used_vector_ids.add(step["inputVectorId"])
            required_evidence = step.get("requiredPriorEvidence")
            require(isinstance(required_evidence, list), f"invalid prior evidence: {scenario['id']}")
            require(set(required_evidence) <= available_evidence, f"unsatisfied prior evidence: {scenario['id']}")
            produced = step.get("providedEvidence")
            require(isinstance(produced, str) and bool(produced), f"missing produced evidence: {scenario['id']}")
            require(produced not in available_evidence, f"duplicate produced evidence: {scenario['id']}")
            available_evidence.add(produced)
            transition_id = step["transitionId"]
            if transition_id is not None:
                key = (scenario["modelId"], transition_id)
                require(key in transition_index, f"unknown model transition: {key}")
                transition = transition_index[key]
                require(step["preState"] in transition["from"], f"transition pre-state mismatch: {key}")
                require(step["expectedPostState"] == transition["to"], f"transition post-state mismatch: {key}")
                require(step["expectedOutcome"] == transition["outcome"], f"transition outcome mismatch: {key}")
                exercised_transitions.add(key)
                reached_states.add((scenario["modelId"], step["preState"]))
                reached_states.add((scenario["modelId"], step["expectedPostState"]))
    require(used_vector_ids == vector_ids, "vector execution coverage mismatch")
    require(exercised_transitions == set(transition_index), "state-transition coverage mismatch")
    expected_states = {(state_model["id"], state) for state_model in model["state_models"] for state in state_model["states"]}
    require(reached_states == expected_states, "state coverage mismatch")

    traces = _unique_sorted(documents["expected-traces.json"]["records"], "traces")
    require({trace["scenarioId"] for trace in traces} == scenario_ids, "trace/scenario reference mismatch")
    for trace in traces:
        require(all(step["externalEffects"] == [] for step in trace["steps"]), f"trace contains external effect: {trace['id']}")
        require(len(trace["steps"]) == len(next(row for row in scenarios if row["id"] == trace["scenarioId"])["steps"]), f"trace step count mismatch: {trace['id']}")
        require(isinstance(trace.get("observationDigest"), str) and len(trace["observationDigest"]) == 64, f"missing trace observation: {trace['id']}")

    counterexample_by_id = {record["id"]: record for record in model["counterexamples"]}
    counterexample_scenarios = {record["counterexampleId"]: record for record in scenarios if "counterexampleId" in record}
    require(set(counterexample_scenarios) == set(counterexample_by_id), "counterexample scenario coverage mismatch")
    for identifier, scenario in counterexample_scenarios.items():
        require(len(scenario["steps"]) == 3, f"counterexample must have three executed steps: {identifier}")
        require([step["candidateAction"] for step in scenario["steps"]] == counterexample_by_id[identifier]["steps"], f"counterexample program mismatch: {identifier}")
        require(all(step.get("executed", True) for step in scenario["steps"]), f"counterexample boundary skipped: {identifier}")
    trace_by_scenario = {record["scenarioId"]: record for record in traces}
    counterexample_observations = [trace_by_scenario[row["id"]]["observationDigest"] for row in counterexample_scenarios.values()]
    require(len(counterexample_observations) == len(set(counterexample_observations)), "counterexample observation collision")

    mutations = _unique_sorted(documents["adversarial-mutations.json"]["records"], "mutations")
    mutation_ids = {record["id"] for record in mutations}
    mutation_by_id = {record["id"]: record for record in mutations}
    require(len(mutation_ids) == len(mutations), "mutation identifier collision")
    require({record["sourceVectorId"] for record in invalid} <= vector_ids, "invalid source vector missing")

    coverage = manifest["coverage"]
    require(coverage["reviewModel"] == inventory["expected_review_model_ids"], "review-model coverage mismatch")
    expected_counterexamples = [
        {"id": record["id"], "scenarioId": f"scenario-counterexample-{record['id'].lower()}"}
        for record in model["counterexamples"]
    ]
    require(coverage["counterexamples"] == expected_counterexamples, "counterexample coverage relation mismatch")
    expected_flows = [
        {
            "branch": "BOUNDARY_NOT_EXECUTED" if record["id"] in {"secure_session_receive", "secure_session_send", "transport_publish"} else "EXECUTED",
            "id": record["id"],
            "scenarioId": f"scenario-flow-{record['id']}",
        }
        for record in model["flows"]
    ]
    require(coverage["flows"] == expected_flows, "flow coverage relation mismatch")
    validate_source_coverage(reader, inventory, coverage)
    require(coverage["o10"]["alias"] == inventory["o10_alias"], "O-10 alias mismatch")
    expected_outcome_rows = []
    for outcome in inventory["o10_primaries"]:
        matching = [scenario["id"] for scenario in scenarios if any(step["expectedOutcome"] == outcome for step in scenario["steps"])]
        expected_outcome_rows.append(
            {
                "branch": "EXERCISED" if matching else "UNREACHABLE_IN_TRANSCRIPT_ONLY_PROFILE",
                "citations": [{"anchor": "## Primary registry", "path": "docs/protocol/styx-app-kernel-v0-outcome-taxonomy.md"}],
                "id": outcome,
                "scenarioIds": matching,
            }
        )
    expected_outcome_rows.extend(
        {
            "branch": "UNREACHABLE_IN_TRANSCRIPT_ONLY_PROFILE",
            "citations": [{"anchor": "## Closed cardinalities", "path": "docs/protocol/styx-app-kernel-v0-outcome-taxonomy.md"}],
            "id": marker,
            "scenarioIds": [],
        }
        for marker in inventory["o10_post_c03_markers"]
    )
    require(coverage["o10"]["outcomes"] == expected_outcome_rows, "O-10 outcome coverage mismatch")
    expected_invariants = {row["id"] for row in model["invariants"]}
    require(
        {row["id"] for row in coverage["invariants"]} == expected_invariants
        and len(coverage["invariants"]) == len(expected_invariants),
        "invariant coverage mismatch",
    )
    require(
        {
            row["id"]
            for row in coverage["invariants"]
            if row["branch"] == "NON_EXECUTABLE_NON_CLAIM"
        }
        == NONEXECUTABLE_INVARIANTS,
        "invariant branch assignment mismatch",
    )
    for row in coverage["invariants"]:
        if row["branch"] == "EXECUTABLE_WITNESS":
            require(
                bool(row["witnessScenarioIds"])
                and set(row["witnessScenarioIds"]) <= scenario_ids,
                f"unknown or empty invariant witness: {row['id']}",
            )
            require(
                bool(row["hostileMutationIds"])
                and set(row["hostileMutationIds"]) <= mutation_ids,
                f"unknown or empty invariant mutation: {row['id']}",
            )
            require(len(row["witnessScenarioIds"]) == 1 and len(row["hostileMutationIds"]) == 1, f"non-atomic invariant evidence: {row['id']}")
            witness = next(record for record in scenarios if record["id"] == row["witnessScenarioIds"][0])
            require(witness.get("exercisedInvariantIds") == [row["id"]], f"invariant witness semantic mismatch: {row['id']}")
            mutation = mutation_by_id[row["hostileMutationIds"][0]]
            require(
                mutation.get("mutationClass") == "SEMANTIC_INVARIANT"
                and mutation.get("violatedInvariant") == row["id"]
                and mutation.get("sourceRecordId") == witness["id"]
                and mutation.get("generatedTargetId") == f"trace-{witness['id']}",
                f"invariant mutation semantic mismatch: {row['id']}",
            )
        else:
            require(row["branch"] == "NON_EXECUTABLE_NON_CLAIM", f"invalid invariant branch: {row['id']}")
            require(isinstance(row.get("reason"), str) and bool(row["reason"]), f"missing invariant non-claim reason: {row['id']}")
            require(
                isinstance(row.get("citations"), list)
                and bool(row["citations"])
                and all(_citation_valid(reader, source_paths, citation) for citation in row["citations"]),
                f"stale invariant non-claim citation: {row['id']}",
            )

    executable_rows = [row for row in coverage["invariants"] if row["branch"] == "EXECUTABLE_WITNESS"]
    require(len({row["witnessScenarioIds"][0] for row in executable_rows}) == len(executable_rows), "shared sole invariant witness")
    require(len({row["hostileMutationIds"][0] for row in executable_rows}) == len(executable_rows), "shared sole invariant mutation")
    require(
        not any(record.get("mutationClass", "").startswith("SEMANTIC") and record.get("violatedInvariant") in NONEXECUTABLE_INVARIANTS for record in mutations),
        "non-executable invariant claimed by semantic mutation",
    )

    expected_state_rows = sorted(f"{machine['id']}:{state}" for machine in model["state_models"] for state in machine["states"])
    expected_terminal_rows = sorted(f"{machine['id']}:{state}" for machine in model["state_models"] for state in machine.get("terminal_states", []))
    expected_transition_rows = []
    for machine in model["state_models"]:
        for transition in machine["transitions"]:
            matches = [scenario["id"] for scenario in scenarios if scenario["modelId"] == machine["id"] and any(step["transitionId"] == transition["id"] for step in scenario["steps"])]
            require(len(matches) == 1, f"transition witness cardinality mismatch: {machine['id']}:{transition['id']}")
            expected_transition_rows.append({"id": f"{machine['id']}:{transition['id']}", "scenarioId": matches[0]})
    require(coverage["states"] == expected_state_rows, "state coverage relation mismatch")
    require(coverage["terminalStates"] == expected_terminal_rows, "terminal-state coverage relation mismatch")
    require(coverage["transitions"] == sorted(expected_transition_rows, key=lambda row: row["id"]), "transition coverage relation mismatch")

    envelope = reader.json("tools/causal-flow-simulator/o08/resource-envelope.candidate.json")
    selected_limits = {
        identifier: envelope["entries"][identifier]["selected_value"]
        for identifier in O08_LIMITS
    }
    require(selected_limits == O08_LIMITS, "O-08 selected numeric limits drifted")
    require(
        set(envelope["entries"]["CHUNK_OCTETS"]["closed_values"]) == O08_CHUNK_OCTETS,
        "O-08 selected chunk set drifted",
    )

    return {
        "corpusDigest": sha256(
            b"".join((corpus / name).read_bytes() for name in sorted(EXPECTED_FILES))
        ).hexdigest(),
        "invalidVectors": len(invalid),
        "mutations": len(mutations),
        "result": "PASS",
        "scenarios": len(scenarios),
        "validVectors": len(valid),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = validate(args.repo_root.resolve(), args.corpus.resolve())
        store(args.output.resolve(), report)
    except (CorpusModelError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"c03_validation_failure={error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
