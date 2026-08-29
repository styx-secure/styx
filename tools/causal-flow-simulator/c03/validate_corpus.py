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

from canonical_json import dumps, load, store  # noqa: E402
from corpus_model import (  # noqa: E402
    AP_OWNED_EXCLUSIONS,
    AP_EXPECTATION_ONLY_STEP_LOCATORS,
    BASE_SHA,
    BaseReader,
    CorpusModelError,
    NONEXECUTABLE_INVARIANTS,
    O08_CHUNK_OCTETS,
    O08_LIMITS,
    PRODUCED_K_PRIMARIES,
    TRANSCRIPT_PROFILE_UNREACHABLE,
    evaluate_k_admission_graph,
    evaluate_k_admission_scenario,
    evaluate_transcript_conformance,
    evaluate_vector,
    load_local_json,
    semantic_observation_digest,
    sha256_hex,
    transition_input_is_compatible,
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
    "adversarial-mutations.json": "styx-c03-adversarial-mutations/v2",
    "expected-traces.json": "styx-c03-expected-traces/v2",
    "invalid-transcript-vectors.json": "styx-c03-invalid-transcripts/v2",
    "manifest.json": "styx-c03-corpus-manifest/v2",
    "state-machine-scenarios.json": "styx-c03-state-scenarios/v2",
    "valid-transcript-vectors.json": "styx-c03-valid-transcripts/v2",
}
ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:/(?:[^\s/][^\s]*|(?=$|[\],;}]))|"
    r"\\(?:[^\s\\][^\s]*|(?=$|[\],;}]))|[A-Za-z]:[\\/]|\\\\[^\\\s]+[\\/])"
)
TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
RUNTIME_VALUE = re.compile(r"\b(?:elapsed|duration|runtime|hostname|username|pid)\s*[:=]", re.I)
EXPECTED_SOURCE_SECURITY_MUTATION_IDS = frozenset(
    {
        "mutation-source-checkpoint-after-protected-work",
        "mutation-source-o10-applicability",
        "mutation-source-o10-class-membership",
        "mutation-source-o10-precedence",
        "mutation-source-r5-flatten-k-admission",
        "mutation-source-r6-classification",
        "mutation-source-fork-descendant-dependency-rejection",
        *(f"mutation-source-geometry-predicate-{number}" for number in range(1, 8)),
    }
)


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
        entry = {
            "path": name,
            "recordCount": len(records),
            "sha256": sha256_hex((corpus / name).read_bytes()),
        }
        if "kAdmissionRecords" in documents[name]:
            entry["kAdmissionRecordCount"] = len(
                documents[name]["kAdmissionRecords"]
            )
        elif "kAdmissionScenarios" in documents[name]:
            entry["kAdmissionRecordCount"] = len(
                documents[name]["kAdmissionScenarios"]
            )
        expected_entries.append(entry)
    require(manifest.get("files") == expected_entries, "manifest file digests/counts mismatch")


def validate(repo_root: Path, corpus: Path) -> dict[str, Any]:
    source_map, inventory = validate_base_inputs(repo_root)
    reader = BaseReader(repo_root)
    model = load_local_json(
        repo_root / "docs/protocol/review/styx-app-kernel-v0-review-model.json"
    )
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
    require(manifest.get("corpusFormatVersion") == 2, "corpus format version mismatch")
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
    invalid_document = documents["invalid-transcript-vectors.json"]
    invalid = _unique_sorted(invalid_document["records"], "invalid vectors")
    ap_expectations = _unique_sorted(
        invalid_document.get("apExpectationOnlyRecords"),
        "AP expectation-only vectors",
    )
    require(len(valid) == 17 and len(invalid) == 27, "R7 vector cardinality mismatch")
    require(
        {record["id"] for record in ap_expectations}
        == {"inv-post-revocation", "inv-self-lineage", "inv-unauthorized"},
        "AP expectation-only vector set mismatch",
    )
    vector_ids = {record["id"] for record in valid + invalid + ap_expectations}
    for record in valid:
        require(all(_citation_valid(reader, source_paths, citation) for citation in record["citations"]), f"stale citation: {record['id']}")
        result = evaluate_transcript_conformance(record)
        require(
            result.get("transcriptVerification") == "VALID"
            and result.get("signatureVerification") == "VALID"
            and result.get("kBindingAdmission") == "NOT_EVALUATED"
            and result.get("apAuthorityResult") == "NOT_REACHED"
            and result.get("outcomeEvaluated") is False
            and "localOutcome" not in result
            and "remoteClass" not in result,
            f"valid transcript fixture rejected or overclaimed: {record['id']}",
        )
    for record in invalid:
        result = evaluate_vector(record)
        expected = record["expected"]
        require(result["localOutcome"] == expected["localOutcome"], f"invalid outcome mismatch: {record['id']}")
        require(result["stage"] == expected["firstFailingStage"], f"invalid stage mismatch: {record['id']}")
        require(result["preStateDigest"] == result["postStateDigest"], f"invalid vector mutated state: {record['id']}")
        require(result["externalEffects"] == [], f"invalid vector emitted effect: {record['id']}")
    for record in ap_expectations:
        require(record.get("expectationLayer") == "AP_EXPECTATION_ONLY", f"AP layer mismatch: {record['id']}")
        require(
            record.get("expected", {}).get("localOutcome")
            in {"AUTHENTIC_BUT_UNAUTHORIZED", "POST_REVOCATION"},
            f"AP expectation mismatch: {record['id']}",
        )
        require(
            evaluate_transcript_conformance(record).get("kBindingAdmission")
            == "NOT_EVALUATED",
            f"AP-only vector claims disconnected K admission: {record['id']}",
        )

    k_records = _unique_sorted(
        documents["valid-transcript-vectors.json"].get("kAdmissionRecords"),
        "connected K-admission records",
    )
    k_scenarios = _unique_sorted(
        documents["state-machine-scenarios.json"].get("kAdmissionScenarios"),
        "connected K-admission scenarios",
    )
    require(
        len(k_records) == 18 and len(k_scenarios) == 3,
        "connected K-admission cardinality mismatch",
    )
    k_by_id = {record["id"]: record for record in k_records}
    used_k_records: set[str] = set()
    k_observations: list[dict[str, Any]] = []
    for scenario in k_scenarios:
        genesis_id = scenario.get("acceptedGenesisRecordId")
        record_ids = scenario.get("recordIds")
        require(
            genesis_id in k_by_id
            and k_by_id[genesis_id].get("kind") == "GENESIS"
            and isinstance(record_ids, list)
            and bool(record_ids)
            and len(record_ids) == len(set(record_ids))
            and set(record_ids) <= set(k_by_id),
            f"invalid connected K scenario: {scenario['id']}",
        )
        used_k_records.add(genesis_id)
        used_k_records.update(record_ids)
        observations = evaluate_k_admission_graph(
            k_by_id[genesis_id],
            [k_by_id[identifier] for identifier in reversed(record_ids)],
        )
        require(
            len(observations) == len(record_ids)
            and all(
                row["kBindingAdmission"] == "ADMITTED"
                and row["protocolErrorCode"] is None
                for row in observations
            ),
            f"connected K scenario rejected: {scenario['id']}",
        )
        k_observations.append(
            {"id": scenario["id"], "observations": observations}
        )
    require(used_k_records == set(k_by_id), "unexecuted connected K record")
    require(
        sum(len(row["observations"]) for row in k_observations) == 18,
        "positive connected K observation cardinality mismatch",
    )

    legacy_by_id = {record["id"]: record for record in valid}
    legacy_observation = evaluate_k_admission_graph(
        legacy_by_id["vec-genesis"],
        [legacy_by_id["vec-ordinary-none"]],
    )[0]
    require(
        legacy_observation["kBindingAdmission"] == "REJECTED"
        and legacy_observation["protocolErrorCode"]
        == "CREDENTIAL_BINDING_MISMATCH",
        "legacy transcript fixture incorrectly proves K admission",
    )

    k_hostile = _unique_sorted(
        documents["adversarial-mutations.json"].get("kAdmissionScenarios"),
        "hostile connected K-admission scenarios",
    )
    require(len(k_hostile) == 17, "hostile connected K cardinality mismatch")
    hostile_observations: list[dict[str, Any]] = []
    observed_error_codes: set[str] = set()
    for scenario in k_hostile:
        require(
            set(scenario)
            == {
                "acceptedGenesisRecord",
                "expectedObservations",
                "id",
                "records",
            }
            and isinstance(scenario["records"], list)
            and bool(scenario["records"]),
            f"invalid hostile connected K scenario: {scenario['id']}",
        )
        observations = evaluate_k_admission_graph(
            scenario["acceptedGenesisRecord"], scenario["records"]
        )
        require(
            observations == scenario["expectedObservations"],
            f"hostile connected K oracle mismatch: {scenario['id']}",
        )
        observed_error_codes.update(
            row["protocolErrorCode"]
            for row in observations
            if row["protocolErrorCode"] is not None
        )
        hostile_observations.append(
            {"id": scenario["id"], "observations": observations}
        )
    require(
        sum(len(row["observations"]) for row in hostile_observations) == 66,
        "hostile connected K observation cardinality mismatch",
    )
    require(
        {
            "CREDENTIAL_BINDING_MISMATCH",
            "INVALID",
            "STRUCTURAL_REJECTION",
            "UNRESOLVABLE_CREDENTIAL",
            "UNRESOLVED_CREDENTIAL_BINDING",
        }
        <= observed_error_codes,
        "hostile connected K class coverage mismatch",
    )
    removal_observations = next(
        row["observations"]
        for row in hostile_observations
        if row["id"]
        == "k-hostile-removal-target-absence-is-not-k-rejection"
    )
    require(
        all(row["kBindingAdmission"] == "ADMITTED" for row in removal_observations),
        "removal target absence incorrectly rejected by K",
    )

    transition_index = {
        (state_model["id"], transition["id"]): transition
        for state_model in model["state_models"]
        for transition in state_model["transitions"]
    }
    scenarios = _unique_sorted(documents["state-machine-scenarios.json"]["records"], "scenarios")
    scenario_ids = {record["id"] for record in scenarios}
    transcript_conformance_vector_ids = {
        record["id"] for record in valid + ap_expectations
    }
    invalid_vector_ids = {record["id"] for record in invalid}
    used_vector_ids: set[str] = set()
    exercised_transitions: set[tuple[str, str]] = set()
    reached_states: set[tuple[str, str]] = set()
    for scenario in scenarios:
        require(all(_citation_valid(reader, source_paths, citation) for citation in scenario["citations"]), f"stale scenario citation: {scenario['id']}")
        require(isinstance(scenario.get("steps"), list) and scenario["steps"], f"empty scenario: {scenario['id']}")
        available_evidence: set[str] = set()
        for step in scenario["steps"]:
            layer = step.get("evidenceLayer")
            require(
                (layer == "BOUNDARY_NOT_EXECUTED")
                == (step.get("executed") is False),
                f"boundary execution-layer mismatch: {scenario['id']}",
            )
            if layer == "CONNECTED_K_ADMISSION":
                require(
                    "inputVectorId" not in step
                    and step.get("inputKAdmissionScenarioId")
                    in {row["id"] for row in k_scenarios}
                    and isinstance(step.get("inputKAdmissionRecordId"), str),
                    f"invalid connected K step input: {scenario['id']}",
                )
                connected = next(
                    row
                    for row in k_scenarios
                    if row["id"] == step["inputKAdmissionScenarioId"]
                )
                require(
                    step["inputKAdmissionRecordId"] in connected["recordIds"],
                    f"connected K target outside scenario: {scenario['id']}",
                )
            else:
                require(
                    layer
                    in {
                        "BOUNDARY_NOT_EXECUTED",
                        "LOCAL_NEGATIVE",
                        "TRANSCRIPT_CONFORMANCE",
                    }
                    and step.get("inputVectorId") in vector_ids
                    and "inputKAdmissionScenarioId" not in step
                    and "inputKAdmissionRecordId" not in step,
                    f"invalid vector-backed step input: {scenario['id']}",
                )
                if layer == "TRANSCRIPT_CONFORMANCE":
                    require(
                        step["inputVectorId"] in transcript_conformance_vector_ids,
                        f"transcript-conformance layer references a non-valid vector: {scenario['id']}",
                    )
                elif layer == "LOCAL_NEGATIVE":
                    require(
                        step["inputVectorId"] in invalid_vector_ids,
                        f"local-negative layer references a non-invalid vector: {scenario['id']}",
                    )
                used_vector_ids.add(step["inputVectorId"])
            required_evidence = step.get("requiredPriorEvidence")
            require(isinstance(required_evidence, list), f"invalid prior evidence: {scenario['id']}")
            dependency_status = "SATISFIED" if set(required_evidence) <= available_evidence else "MISSING"
            require(
                step.get("expectedDependencyStatus") == dependency_status,
                f"dependency expectation mismatch: {scenario['id']}",
            )
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
                if layer == "CONNECTED_K_ADMISSION":
                    connected = next(
                        row
                        for row in k_scenarios
                        if row["id"] == step["inputKAdmissionScenarioId"]
                    )
                    observations = evaluate_k_admission_scenario(
                        k_by_id[connected["acceptedGenesisRecordId"]],
                        [k_by_id[identifier] for identifier in connected["recordIds"]],
                    )
                    evaluated = next(
                        row
                        for row in observations
                        if row["id"] == step["inputKAdmissionRecordId"]
                    )
                else:
                    vector = next(
                        record
                        for record in valid + invalid + ap_expectations
                        if record["id"] == step["inputVectorId"]
                    )
                    evaluated = (
                        evaluate_transcript_conformance(vector)
                        if layer == "TRANSCRIPT_CONFORMANCE"
                        else evaluate_vector(vector)
                    )
                if scenario["modelId"] == "ap_projection":
                    require(step.get("executed") is False, f"AP transition executed: {key}")
                    require(step["expectedPostState"] == "UNCHANGED", f"AP transition mutated K state: {key}")
                    require(step.get("apExpectationOnly") == transition["outcome"], f"AP transition expectation mismatch: {key}")
                elif transition.get("result_layer") == "K_ADMISSION_ONLY":
                    require(step["expectedPostState"] == transition["to"], f"transition post-state mismatch: {key}")
                    require("expectedOutcome" not in step, f"positive K transition has outcome: {key}")
                    require(step.get("expectedResultLayer") == "K_ADMISSION_ONLY", f"positive K layer mismatch: {key}")
                    require(transition_input_is_compatible(evaluated), f"incompatible positive transition input: {key}")
                else:
                    require(step["expectedPostState"] == transition["to"], f"transition post-state mismatch: {key}")
                    require(step.get("expectedOutcome") == transition["outcome"], f"transition outcome mismatch: {key}")
                    require(
                        evaluated.get("outcomeEvaluated") is True
                        and evaluated.get("localOutcome") == transition["outcome"]
                        and evaluated.get("stage") == step["expectedStage"],
                        f"incompatible negative transition input: {key}",
                    )
                exercised_transitions.add(key)
                reached_states.add((scenario["modelId"], step["preState"]))
                reached_states.add((scenario["modelId"], transition["to"]))
    require(used_vector_ids == vector_ids, "vector execution coverage mismatch")
    require(exercised_transitions == set(transition_index), "state-transition coverage mismatch")
    ap_transition_steps = [
        step
        for scenario in scenarios
        if scenario["modelId"] == "ap_projection"
        for step in scenario["steps"]
        if "apExpectationOnly" in step
    ]
    ap_ordinary_locators = {
        f"{scenario['id']}:{index}"
        for scenario in scenarios
        if scenario["modelId"] != "ap_projection"
        for index, step in enumerate(scenario["steps"])
        if "apExpectationOnly" in step
    }
    require(len(ap_transition_steps) == 8, "AP transition exclusion cardinality mismatch")
    require(
        ap_ordinary_locators == AP_EXPECTATION_ONLY_STEP_LOCATORS,
        "AP expectation-only step locator mismatch",
    )
    require(
        {
            layer: sum(
                step.get("evidenceLayer") == layer
                for scenario in scenarios
                for step in scenario["steps"]
            )
            for layer in {
                "BOUNDARY_NOT_EXECUTED",
                "CONNECTED_K_ADMISSION",
                "LOCAL_NEGATIVE",
                "TRANSCRIPT_CONFORMANCE",
            }
        }
        == {
            "BOUNDARY_NOT_EXECUTED": 11,
            "CONNECTED_K_ADMISSION": 4,
            "LOCAL_NEGATIVE": 59,
            "TRANSCRIPT_CONFORMANCE": 81,
        },
        "scenario evidence-layer cardinality mismatch",
    )
    require(
        not any(
            step.get("expectedPostState") == "READY_FOR_AP_FOLD"
            and step.get("evidenceLayer") == "TRANSCRIPT_CONFORMANCE"
            for scenario in scenarios
            for step in scenario["steps"]
        ),
        "disconnected transcript fixture mutates K state",
    )
    require(
        not any(
            step.get("expectedOutcome") == "APPLIED"
            and scenario["modelId"] != "ap_projection"
            for scenario in scenarios
            for step in scenario["steps"]
        ),
        "K-only path emits APPLIED",
    )
    expected_states = {(state_model["id"], state) for state_model in model["state_models"] for state in state_model["states"]}
    require(reached_states == expected_states, "state coverage mismatch")

    traces = _unique_sorted(documents["expected-traces.json"]["records"], "traces")
    require({trace["scenarioId"] for trace in traces} == scenario_ids, "trace/scenario reference mismatch")
    for trace in traces:
        require(all(step["externalEffects"] == [] for step in trace["steps"]), f"trace contains external effect: {trace['id']}")
        require(len(trace["steps"]) == len(next(row for row in scenarios if row["id"] == trace["scenarioId"])["steps"]), f"trace step count mismatch: {trace['id']}")
        require(
            trace.get("observationDigest")
            == sha256(dumps({"scenarioId": trace["scenarioId"], "steps": trace["steps"]})).hexdigest(),
            f"trace observation mismatch: {trace['id']}",
        )
        require(
            trace.get("semanticObservationDigest") == semantic_observation_digest(trace["steps"]),
            f"semantic observation mismatch: {trace['id']}",
        )

    counterexample_by_id = {record["id"]: record for record in model["counterexamples"]}
    counterexample_scenarios = {record["counterexampleId"]: record for record in scenarios if "counterexampleId" in record}
    require(set(counterexample_scenarios) == set(counterexample_by_id), "counterexample scenario coverage mismatch")
    for identifier, scenario in counterexample_scenarios.items():
        require(len(scenario["steps"]) == 3, f"counterexample must have three executed steps: {identifier}")
        require([step["candidateAction"] for step in scenario["steps"]] == counterexample_by_id[identifier]["steps"], f"counterexample program mismatch: {identifier}")
        require(all(step.get("executed", True) for step in scenario["steps"]), f"counterexample boundary skipped: {identifier}")
    trace_by_scenario = {record["scenarioId"]: record for record in traces}
    counterexample_observations = [trace_by_scenario[row["id"]]["semanticObservationDigest"] for row in counterexample_scenarios.values()]
    require(len(counterexample_observations) == len(set(counterexample_observations)), "counterexample observation collision")

    mutations = _unique_sorted(documents["adversarial-mutations.json"]["records"], "mutations")
    mutation_ids = {record["id"] for record in mutations}
    mutation_by_id = {record["id"]: record for record in mutations}
    require(len(mutation_ids) == len(mutations), "mutation identifier collision")
    require({record["sourceVectorId"] for record in invalid} <= vector_ids, "invalid source vector missing")
    source_mutations = [
        record
        for record in mutations
        if record.get("mutationClass") == "SOURCE_ANCHORED_SECURITY"
    ]
    require(
        {record["id"] for record in source_mutations}
        == EXPECTED_SOURCE_SECURITY_MUTATION_IDS,
        "source-anchored mutation set mismatch",
    )
    source_row_ids = {
        row["row_id"]
        for row in reader.json(
            "tools/causal-flow-simulator/o10/source-inventory.json"
        )["rows"]
    }
    for mutation in source_mutations:
        source_path = mutation.get("sourcePath")
        source_anchor = mutation.get("sourceAnchor")
        rows = mutation.get("sourceRowIds")
        require(
            isinstance(source_path, str)
            and isinstance(source_anchor, str)
            and bool(source_anchor)
            and source_anchor.encode() in reader.read(source_path),
            f"stale source mutation anchor: {mutation['id']}",
        )
        require(
            isinstance(rows, list)
            and bool(rows)
            and len(rows) == len(set(rows))
            and set(rows) <= source_row_ids,
            f"invalid source mutation rows: {mutation['id']}",
        )

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
        if outcome in PRODUCED_K_PRIMARIES:
            branch = "PRODUCED"
            matching = [scenario["id"] for scenario in scenarios if any(step.get("expectedOutcome") == outcome for step in scenario["steps"])]
            matching.extend(
                scenario["id"]
                for scenario in k_hostile
                if any(
                    observation.get("protocolErrorCode") == outcome
                    for observation in scenario["expectedObservations"]
                )
            )
            matching.sort()
        elif outcome in AP_OWNED_EXCLUSIONS:
            branch = "AP_OWNED_EXCLUDED"
            matching = [scenario["id"] for scenario in scenarios if any(step.get("apExpectationOnly") == outcome for step in scenario["steps"])]
        elif outcome in TRANSCRIPT_PROFILE_UNREACHABLE:
            branch = "TRANSCRIPT_PROFILE_UNREACHABLE"
            matching = []
        else:
            raise ValidationError(f"unpartitioned O-10 primary: {outcome}")
        expected_outcome_rows.append(
            {
                "branch": branch,
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
    expected_source_rows = []
    produced_witnesses = inventory["o10_produced_source_row_witnesses"]
    vector_by_id = {
        record["id"]: record for record in valid + invalid + ap_expectations
    }
    for row in reader.json("tools/causal-flow-simulator/o10/source-inventory.json")["rows"]:
        row_id = row["row_id"]
        if row_id in produced_witnesses:
            primary = row["mapping"]["primary"]
            disposition = "PRODUCED"
            witnesses = []
            for witness in produced_witnesses[row_id]:
                scenario_id = (
                    f"scenario-vector-{witness['inputId']}"
                    if "inputId" in witness
                    else witness["inputKAdmissionScenarioId"]
                )
                witnesses.append({**witness, "scenarioId": scenario_id})
            for witness in witnesses:
                if "inputId" in witness:
                    input_id = witness["inputId"]
                    require(input_id in vector_by_id, f"unknown O-10 row input: {row_id}")
                    require(
                        witness["scenarioId"] in scenario_ids
                        and any(
                            step["inputVectorId"] == input_id
                            for step in next(
                                scenario
                                for scenario in scenarios
                                if scenario["id"] == witness["scenarioId"]
                            )["steps"]
                        ),
                        f"missing O-10 row scenario: {row_id}:{input_id}",
                    )
                    observed = evaluate_vector(vector_by_id[input_id])
                    observed_outcome = observed.get("localOutcome")
                    observed_stage = observed.get("stage")
                else:
                    input_id = witness["inputKAdmissionRecordId"]
                    scenario = next(
                        (
                            item
                            for item in k_hostile
                            if item["id"] == witness["inputKAdmissionScenarioId"]
                        ),
                        None,
                    )
                    require(scenario is not None, f"unknown connected O-10 scenario: {row_id}")
                    observed = next(
                        (
                            item
                            for item in evaluate_k_admission_graph(
                                scenario["acceptedGenesisRecord"], scenario["records"]
                            )
                            if item["id"] == input_id
                        ),
                        None,
                    )
                    require(observed is not None, f"unknown connected O-10 record: {row_id}:{input_id}")
                    observed_outcome = observed.get("protocolErrorCode")
                    observed_stage = observed.get("stage")
                require(
                    observed_outcome == primary
                    and observed_stage == row["mapping"]["stage"],
                    f"O-10 row witness result mismatch: {row_id}:{input_id}",
                )
        elif "mapping" in row and row["mapping"]["primary"] in AP_OWNED_EXCLUSIONS:
            primary = row["mapping"]["primary"]
            disposition = "AP_OWNED_EXCLUDED"
            witnesses = []
        elif "mapping" in row:
            primary = row["mapping"]["primary"]
            disposition = "TRANSCRIPT_PROFILE_UNREACHABLE"
            witnesses = []
        else:
            primary = row["forbidden_identifier"]
            disposition = "TRANSCRIPT_PROFILE_UNREACHABLE"
            witnesses = []
        expected_source_rows.append(
            {
                "disposition": disposition,
                "primary": primary,
                "rowId": row_id,
                "witnesses": witnesses,
            }
        )
    require(coverage["o10"].get("sourceRows") == expected_source_rows, "O-10 source-row partition mismatch")
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
    require(
        set(inventory["invariant_witness_vectors"])
        == expected_invariants - NONEXECUTABLE_INVARIANTS
        and len(set(inventory["invariant_witness_vectors"].values()))
        == len(inventory["invariant_witness_vectors"]),
        "invariant witness inventory mismatch",
    )
    invariant_vectors: set[str] = set()
    invariant_observations: set[str] = set()
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
            witness_vector = witness["steps"][0]["inputVectorId"]
            require(
                witness_vector == inventory["invariant_witness_vectors"][row["id"]],
                f"invariant witness-vector mismatch: {row['id']}",
            )
            require(witness_vector not in invariant_vectors, f"shared invariant witness vector: {row['id']}")
            invariant_vectors.add(witness_vector)
            witness_observation = trace_by_scenario[witness["id"]]["semanticObservationDigest"]
            require(
                witness_observation not in invariant_observations,
                f"shared invariant semantic observation: {row['id']}",
            )
            invariant_observations.add(witness_observation)
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
        "kAdmissionDigest": sha256(
            dumps(
                {
                    "hostile": hostile_observations,
                    "positive": k_observations,
                }
            )
        ).hexdigest(),
        "kAdmissionHostileScenarios": len(k_hostile),
        "kAdmissionRecords": len(k_records),
        "kAdmissionScenarios": len(k_scenarios),
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
