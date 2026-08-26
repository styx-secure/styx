from __future__ import annotations

import json
import copy
import subprocess
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from envelope_model import evaluate_observation, materialize_candidate, validate_candidate_set
from scenario_generator import combined_scenarios
from run_measurements import _canonical_trace, _load_v3, structural_evidence
from run_mutations import (
    _contention_mutation_rows, _partial_contention,
    _replay_coupling_mutation_row,
)
from semantic_registry import CANDIDATES_PATH, load_json, load_source_registry


class CrossRuntimeTests(unittest.TestCase):
    def test_all_named_contention_mutants_are_killed(self):
        rows = _contention_mutation_rows()
        self.assertEqual(len(rows), 12)
        self.assertTrue(all(row["killed"] for row in rows))
        self.assertEqual(len({row["mutant_id"] for row in rows}), len(rows))
        self.assertTrue(_replay_coupling_mutation_row()["killed"])

    def test_raw_trace_path_perturbation_fails_closed_in_javascript(self):
        model, scenarios = _load_v3(ROOT.parents[2])
        trace = _canonical_trace(_partial_contention(model, scenarios))
        baseline = {
            "schema": "styx-o08-oracle-request/v1", "cases": [],
            "authority_traces": [{
                "witness_id": "path-negative",
                "limits": {
                    "authority_states": 64, "authority_transitions": 128,
                    "authority_width": 3,
                },
                "trace": trace,
            }],
        }
        hostile = copy.deepcopy(baseline)
        hostile["authority_traces"][0]["trace"]["events"][1]["predecessor"] = None
        def invoke(request):
            return json.loads(subprocess.run(
                ["node", str(ROOT / "independent_oracle.mjs")],
                input=json.dumps(request), text=True, capture_output=True, check=True,
            ).stdout)["authority_traces"][0]
        accepted = invoke(baseline)
        rejected = invoke(hostile)
        self.assertEqual(len(accepted["admitted_references"]), 3)
        self.assertLess(len(rejected["admitted_references"]), 3)
        self.assertNotEqual(accepted["authority_contention_bound"], rejected["authority_contention_bound"])

    def test_python_and_javascript_agree_on_canonical_adversarial_witnesses(self):
        candidate = validate_candidate_set(load_json(CANDIDATES_PATH))[1]
        evidence = structural_evidence(
            ROOT.parents[2], candidate, "0" * 40, "node"
        )
        rows = {row["witness_id"]: row for row in evidence["rows"]}
        self.assertEqual(rows["W301"]["authority_contention_bound"], 3375)
        self.assertEqual(rows["W301"]["reference_characterization"]["reachable_states"], 301)
        self.assertEqual(rows["W301"]["reference_characterization"]["transitions"], 708)
        self.assertEqual(rows["W1211"]["authority_contention_bound"], 8370)
        self.assertEqual(rows["W1211"]["reference_characterization"]["reachable_states"], 1211)
        self.assertEqual(rows["W1211"]["reference_characterization"]["transitions"], 2298)

    def test_node_oracle_rejects_above_maximum(self):
        envelope = materialize_candidate(validate_candidate_set(load_json(CANDIDATES_PATH))[1])
        selected = envelope["entries"]["EVENTS_ADMITTED"]["selected_value"]
        request = {
            "schema": "styx-o08-oracle-request/v1", "envelope": envelope,
            "cases": [{"dimension": "EVENTS_ADMITTED", "stage": "S4_GRAPH_ADMISSION", "observed": selected + 1}],
        }
        completed = subprocess.run(
            ["node", str(ROOT / "independent_oracle.mjs")], input=json.dumps(request),
            text=True, capture_output=True, check=True,
        )
        response = json.loads(completed.stdout)
        self.assertEqual(response["results"][0]["disposition"], "CONTEXT_CAPACITY_EXHAUSTED")
        self.assertFalse(response["results"][0]["authoritative_state_mutated"])
        expected = evaluate_observation(
            envelope, "EVENTS_ADMITTED", selected + 1, stage="S4_GRAPH_ADMISSION"
        )
        self.assertEqual(response["results"][0]["authoritative_state_before"], expected.authoritative_state_before)
        self.assertEqual(response["results"][0]["authoritative_state_after"], expected.authoritative_state_after)

    def test_node_oracle_preserves_max_safe_plus_one_as_decimal(self):
        envelope = materialize_candidate(validate_candidate_set(load_json(CANDIDATES_PATH))[1])
        request = {
            "schema": "styx-o08-oracle-request/v1", "envelope": envelope,
            "cases": [{
                "dimension": "SEQUENCE_VALUE", "stage": "S3_KERNEL_STRUCTURAL",
                "observed": "9007199254740992",
            }],
        }
        completed = subprocess.run(
            ["node", str(ROOT / "independent_oracle.mjs")], input=json.dumps(request),
            text=True, capture_output=True, check=True,
        )
        response = json.loads(completed.stdout)
        self.assertEqual(response["results"][0]["observed"], "9007199254740992")
        self.assertEqual(response["results"][0]["disposition"], "CURRENT_OBJECT_OUT_OF_PROFILE")

    def test_exact_maximum_antichain_width(self):
        from scenario_generator import maximum_antichain_width

        self.assertEqual(maximum_antichain_width({
            "a": frozenset(), "b": frozenset(), "c": frozenset({"a"}),
            "d": frozenset({"b"}),
        }), 2)
        self.assertEqual(maximum_antichain_width({
            "a": frozenset(), "b": frozenset({"a"}), "c": frozenset({"b"}),
        }), 1)
        with self.assertRaises(ValueError):
            maximum_antichain_width({"a": frozenset({"b"}), "b": frozenset({"a"})})

    def test_coupling_oracle_uses_the_same_canonical_order(self):
        registry = load_source_registry()
        envelope = materialize_candidate(
            validate_candidate_set(load_json(CANDIDATES_PATH), registry)[1], registry
        )
        names = {
            "AUTHORITY_WIDTH_STRUCTURAL_CAPACITY",
            "AUTHORITY_TRANSITION_CAPACITY", "DIRECT_EDGE_REPLAY_WORK",
            "EVENT_SIGNATURE_WORK", "FRESH_REPLAY_WORK_CAPACITY",
        }
        expected = sorted((
            predicate
            for row in combined_scenarios(envelope, registry)
            for predicate in row["predicates"]
            if predicate["observation"] in names
        ), key=lambda item: item["observation"])
        completed = subprocess.run(
            ["node", str(ROOT / "independent_oracle.mjs")],
            input=json.dumps({
                "schema": "styx-o08-oracle-request/v1", "envelope": envelope,
                "cases": [], "include_couplings": True,
            }), text=True, capture_output=True, check=True,
        )
        response = json.loads(completed.stdout)
        self.assertEqual(response["couplings"], expected)
        self.assertEqual(response["authority_traces"], [])


if __name__ == "__main__":
    unittest.main()
