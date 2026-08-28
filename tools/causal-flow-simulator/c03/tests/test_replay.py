from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))

from canonical_json import dumps, load, loads  # noqa: E402
from corpus_model import (  # noqa: E402
    CorpusModelError,
    DOMAINS,
    ProtocolError,
    ed25519_sign,
    encode_event,
    evaluate_k_admission_graph,
    evaluate_k_admission_scenario,
    evaluate_vector,
    framed_hash,
    load_local_json,
    synthetic_octets,
)
from generate_corpus import (  # noqa: E402
    _application_vector,
    _event_fields,
    _k_admission_vectors,
    _valid_vectors,
)
from replay_corpus import _transition_index, compute_trace, replay  # noqa: E402


class ReplayTests(unittest.TestCase):
    def test_all_vectors_and_scenarios_replay(self) -> None:
        report = replay(REPO, CORPUS)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["validVectors"], len(load(CORPUS / "valid-transcript-vectors.json")["records"]))
        self.assertEqual(report["invalidVectors"], len(load(CORPUS / "invalid-transcript-vectors.json")["records"]))
        self.assertEqual(report["scenarios"], len(load(CORPUS / "state-machine-scenarios.json")["records"]))
        self.assertRegex(report["corpusDigest"], r"^[0-9a-f]{64}$")
        self.assertRegex(report["traceDigest"], r"^[0-9a-f]{64}$")

    def test_expected_traces_are_closed_and_effect_free(self) -> None:
        traces = load(CORPUS / "expected-traces.json")["records"]
        scenarios = load(CORPUS / "state-machine-scenarios.json")["records"]
        self.assertEqual(
            {trace["scenarioId"] for trace in traces},
            {scenario["id"] for scenario in scenarios},
        )
        step_count = 0
        for trace in traces:
            self.assertEqual(trace["id"], f"trace-{trace['scenarioId']}")
            self.assertTrue(trace["steps"])
            for position, step in enumerate(trace["steps"]):
                self.assertEqual(step["step"], position)
                self.assertEqual(step["externalEffects"], [])
                self.assertRegex(step["preStateDigest"], r"^[0-9a-f]{64}$")
                self.assertRegex(step["postStateDigest"], r"^[0-9a-f]{64}$")
                step_count += 1
        self.assertEqual(step_count, sum(len(scenario["steps"]) for scenario in scenarios))
        self.assertGreater(step_count, len(scenarios))

    def test_missing_dependency_is_exercised(self) -> None:
        traces = load(CORPUS / "expected-traces.json")["records"]
        missing = [
            step
            for trace in traces
            for step in trace["steps"]
            if step["dependencyStatus"] == "MISSING"
        ]
        self.assertTrue(missing)
        self.assertTrue(all(step["localOutcome"] == "DEPENDENCY_DEFERRED" for step in missing))

    def test_disconnected_records_never_claim_k_or_ap_authority(self) -> None:
        report = replay(REPO, CORPUS)
        observations = report["blindTranscriptObservations"]
        self.assertEqual(len(observations), 44)
        self.assertTrue(
            all(row["kBindingAdmission"] == "NOT_EVALUATED" for row in observations)
        )
        self.assertTrue(
            all(row["apAuthorityResult"] == "NOT_REACHED" for row in observations)
        )

        rejected_replay = next(
            row
            for row in observations
            if row["id"] == "inv-rejected-signature-representation"
        )
        self.assertEqual(rejected_replay["referenceVerification"], "VALID")
        self.assertEqual(rejected_replay["signatureVerification"], "REJECTED")
        self.assertEqual(rejected_replay["localOutcome"], "INVALID")
        self.assertNotEqual(rejected_replay["localOutcome"], "DUPLICATE")

    def test_transition_rejects_an_incompatible_vector(self) -> None:
        scenarios = load(CORPUS / "state-machine-scenarios.json")["records"]
        scenario = deepcopy(
            next(
                row
                for row in scenarios
                if row["modelId"] == "k_admission"
                and row["steps"][0].get("expectedResultLayer") == "K_ADMISSION_ONLY"
            )
        )
        scenario["steps"][0]["evidenceLayer"] = "LOCAL_NEGATIVE"
        scenario["steps"][0]["inputVectorId"] = "inv-signature"
        scenario["steps"][0].pop("inputKAdmissionScenarioId")
        scenario["steps"][0].pop("inputKAdmissionRecordId")
        valid = load(CORPUS / "valid-transcript-vectors.json")["records"]
        invalid = load(CORPUS / "invalid-transcript-vectors.json")["records"]
        vectors = {row["id"]: row for row in valid + invalid}
        model = load_local_json(REPO / "docs/protocol/review/styx-app-kernel-v0-review-model.json")
        with self.assertRaisesRegex(CorpusModelError, "incompatible positive K transition"):
            compute_trace(scenario, vectors, _transition_index(model))

    def test_vectors_cover_identity_parent_and_selected_resource_boundaries(self) -> None:
        valid = load(CORPUS / "valid-transcript-vectors.json")["records"]
        invalid = load(CORPUS / "invalid-transcript-vectors.json")["records"]
        events = [record for record in valid if record["kind"] == "APPLICATION_EVENT"]
        self.assertGreaterEqual(len({record["fields"]["contextIdentifierHex"] for record in events}), 2)
        self.assertGreaterEqual(len({record["fields"]["credentialIdentifierHex"] for record in events}), 2)
        self.assertGreaterEqual(len({record["binding"]["verificationKeyHex"] for record in events}), 2)
        self.assertTrue({0, 1, 2} <= {len(record["fields"]["causalParents"]) for record in events})

        selected = next(record for record in valid if record["id"] == "vec-selected-resource-boundaries")
        self.assertEqual(selected["fields"]["authorSequence"], 4095)
        self.assertEqual(len(selected["fields"]["causalParents"]), 8)
        self.assertEqual(len(bytes.fromhex(selected["fields"]["transitionBlockHex"])), 4096)
        self.assertEqual(selected["fields"]["content"]["exactLength"], 262144)
        self.assertEqual(selected["fields"]["content"]["geometry"]["chunkCount"], 64)
        self.assertEqual(
            next(record for record in valid if record["id"] == "vec-selected-chunk-octets")["fields"]["content"]["geometry"]["chunkSize"],
            16384,
        )
        self.assertEqual(
            len(bytes.fromhex(next(record for record in valid if record["id"] == "vec-selected-genesis-policy")["fields"]["initialAuthorityPolicyHex"])),
            4096,
        )
        self.assertTrue(
            {
                "inv-parent-order",
                "inv-profile-substitution",
                "inv-resource-parent-count",
                "inv-resource-sequence",
                "inv-resource-transition-block",
                "inv-resource-chunk-size",
                "inv-resource-chunk-count",
                "inv-resource-content-length",
                "inv-commitment-equal-length",
                "inv-opening-missing-detachable",
                "inv-pending-ancestor",
                "inv-credential-identifier-collision",
                "inv-unresolved-credential-binding",
            }
            <= {record["id"] for record in invalid}
        )


class KAdmissionScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        records, self.scenarios = _k_admission_vectors()
        self.by_id = {record["id"]: record for record in records}

    def _scenario(self, identifier: str):
        scenario = next(row for row in self.scenarios if row["id"] == identifier)
        genesis = self.by_id[scenario["acceptedGenesisRecordId"]]
        records = [self.by_id[value] for value in scenario["recordIds"]]
        return genesis, records

    @staticmethod
    def _resign(record, seed_label):
        value = deepcopy(record)
        transcript = encode_event(value["fields"])
        public, signature = ed25519_sign(synthetic_octets(seed_label, 32), transcript)
        value["binding"]["verificationKeyHex"] = public.hex()
        value["signatureHex"] = signature.hex()
        value["transcriptHex"] = transcript.hex()
        value["eventReferenceHex"] = framed_hash(
            DOMAINS["event_reference"], transcript
        ).hex()
        return value

    def test_connected_histories_are_admitted(self) -> None:
        counts = {}
        for scenario in self.scenarios:
            genesis, records = self._scenario(scenario["id"])
            observations = evaluate_k_admission_scenario(genesis, records)
            self.assertTrue(
                all(row["kBindingAdmission"] == "ADMITTED" for row in observations)
            )
            counts[scenario["id"]] = len(observations)
        self.assertEqual(
            counts,
            {
                "k-admission-genesis-revoke-exception": 3,
                "k-admission-grant-rooted-join": 5,
                "k-admission-linear-controls": 10,
            },
        )

    def test_javascript_adapter_matches_python_byte_for_byte(self) -> None:
        scenarios = []
        expected_observations = []
        for scenario in self.scenarios:
            genesis, records = self._scenario(scenario["id"])
            scenarios.append(
                {
                    "acceptedGenesisRecord": genesis,
                    "id": scenario["id"],
                    "records": records,
                }
            )
            expected_observations.append(
                {
                    "id": scenario["id"],
                    "observations": evaluate_k_admission_scenario(genesis, records),
                }
            )
        expected = dumps({"observations": expected_observations, "result": "PASS"})
        with tempfile.TemporaryDirectory(prefix="styx-c03-k-admission-") as tmp:
            input_path = Path(tmp) / "input.json"
            output_path = Path(tmp) / "output.json"
            input_path.write_bytes(dumps({"scenarios": scenarios}))
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--k-scenario-input",
                    str(input_path),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            observed = output_path.read_bytes()
            loads(observed)
            self.assertEqual(observed, expected)

    def test_graph_evaluation_is_arrival_order_independent(self) -> None:
        for scenario in self.scenarios:
            genesis, records = self._scenario(scenario["id"])
            self.assertEqual(
                evaluate_k_admission_graph(genesis, records),
                evaluate_k_admission_graph(genesis, list(reversed(records))),
            )

    def test_connected_fork_pending_capacity_and_dependency_semantics(self) -> None:
        hostiles = {
            row["id"]: row
            for row in load(CORPUS / "adversarial-mutations.json")[
                "kAdmissionScenarios"
            ]
        }

        fork = hostiles["k-hostile-connected-same-author-fork"]
        fork_observations = evaluate_k_admission_graph(
            fork["acceptedGenesisRecord"], fork["records"]
        )
        fork_rows = [
            row for row in fork_observations if row["protocolErrorCode"] == "FORK_EVIDENCE"
        ]
        self.assertEqual(len(fork_rows), 2)
        self.assertTrue(
            all(row["kBindingAdmission"] == "ADMITTED" for row in fork_rows)
        )
        fork_descendant = next(
            row
            for row in fork_observations
            if row["id"] == "k-hostile-fork-left-descendant"
        )
        self.assertEqual(fork_descendant["kBindingAdmission"], "ADMITTED")
        self.assertIsNone(fork_descendant["protocolErrorCode"])

        pending = hostiles["k-hostile-required-opening-and-pending-ancestor"]
        pending_observations = evaluate_k_admission_graph(
            pending["acceptedGenesisRecord"], pending["records"]
        )
        self.assertEqual(
            {
                row["protocolErrorCode"]: (row["kBindingAdmission"], row["stage"])
                for row in pending_observations
            },
            {
                "PENDING_ANCESTOR": ("ADMITTED", "EVENT_LOCAL"),
                "PENDING_OPENING": ("ADMITTED", "EVENT_LOCAL"),
            },
        )

        capacity = hostiles["k-hostile-connected-parent-capacity"]
        capacity_record = next(
            row
            for row in capacity["records"]
            if row["id"] == "k-hostile-connected-parent-capacity"
        )
        capacity_observation = evaluate_vector(capacity_record)
        self.assertEqual(capacity_observation["transcriptVerification"], "VALID")
        self.assertEqual(capacity_observation["referenceVerification"], "VALID")
        self.assertEqual(capacity_observation["signatureVerification"], "VALID")
        self.assertEqual(
            (capacity_observation["localOutcome"], capacity_observation["stage"]),
            ("CONTEXT_CAPACITY_EXHAUSTED", "S4_GRAPH_ADMISSION"),
        )

        transitive = hostiles["k-hostile-transitive-rejection"]
        transitive_observations = evaluate_k_admission_graph(
            transitive["acceptedGenesisRecord"], transitive["records"]
        )
        descendant = next(
            row
            for row in transitive_observations
            if row["id"] == "k-hostile-descendant-of-rejected-control"
        )
        self.assertEqual(
            (descendant["protocolErrorCode"], descendant["stage"]),
            ("DEPENDENCY_DEFERRED", "S4_GRAPH_ADMISSION"),
        )

    def test_rejected_dependency_is_closed_transitively(self) -> None:
        genesis, records = self._scenario("k-admission-linear-controls")
        invalid_revoke = deepcopy(records[2])
        invalid_revoke["fields"]["tail"]["targetCredentialHex"] = "ef" * 32
        invalid_revoke = self._resign(invalid_revoke, "k-linear/root")
        descendant = deepcopy(records[3])
        descendant["fields"]["directPredecessorHex"] = invalid_revoke[
            "eventReferenceHex"
        ]
        descendant = self._resign(descendant, "k-linear/root")
        observations = evaluate_k_admission_graph(
            genesis,
            [records[0], records[1], invalid_revoke, descendant],
        )
        by_id = {row["id"]: row for row in observations}
        self.assertEqual(
            by_id[invalid_revoke["id"]]["protocolErrorCode"],
            "UNRESOLVABLE_CREDENTIAL",
        )
        self.assertEqual(
            by_id[descendant["id"]]["protocolErrorCode"],
            "DEPENDENCY_DEFERRED",
        )

    def test_removal_target_absence_does_not_break_k_admission(self) -> None:
        genesis, records = self._scenario("k-admission-linear-controls")
        root = records[0]
        removal = _application_vector(
            "k-removal-missing-target",
            _event_fields(
                "k-removal-missing-target",
                role="REMOVAL",
                sequence=1,
                predecessor=root["eventReferenceHex"],
                credential=bytes.fromhex(genesis["genesisReferenceHex"]),
                context=bytes.fromhex(genesis["fields"]["contextIdentifierHex"]),
                genesis_reference=bytes.fromhex(genesis["genesisReferenceHex"]),
                tail={
                    "targetCommitmentHex": "ab" * 32,
                    "targetEventReferenceHex": "cd" * 32,
                },
            ),
            "k-linear/root",
        )
        observations = evaluate_k_admission_graph(genesis, [root, removal])
        self.assertEqual(
            {row["id"]: row["kBindingAdmission"] for row in observations},
            {root["id"]: "ADMITTED", removal["id"]: "ADMITTED"},
        )

    def test_foreign_genesis_and_unknown_credential_are_rejected(self) -> None:
        genesis, records = self._scenario("k-admission-linear-controls")
        foreign = deepcopy(records[0])
        foreign["fields"]["genesisReferenceHex"] = "ab" * 32
        foreign = self._resign(foreign, "k-linear/root")
        with self.assertRaisesRegex(
            ProtocolError, "CREDENTIAL_BINDING_MISMATCH"
        ):
            evaluate_k_admission_scenario(genesis, [foreign])

        unknown = deepcopy(records[0])
        unknown["fields"]["credentialIdentifierHex"] = "cd" * 32
        unknown = self._resign(unknown, "k-linear/root")
        with self.assertRaisesRegex(ProtocolError, "UNRESOLVED_CREDENTIAL_BINDING"):
            evaluate_k_admission_scenario(genesis, [unknown])

    def test_legacy_transcript_does_not_prove_k_admission(self) -> None:
        legacy = _valid_vectors(legacy_controls=True)
        genesis = next(row for row in legacy if row["id"] == "vec-genesis")
        ordinary = next(row for row in legacy if row["id"] == "vec-ordinary-none")
        with self.assertRaisesRegex(
            ProtocolError, "CREDENTIAL_BINDING_MISMATCH"
        ):
            evaluate_k_admission_scenario(genesis, [ordinary])

    def test_control_lifecycle_requires_admitted_targets_and_frontier(self) -> None:
        genesis, records = self._scenario("k-admission-linear-controls")
        revoke_prefix = deepcopy(records[:3])
        revoke_prefix[-1]["fields"]["tail"]["targetCredentialHex"] = "ef" * 32
        revoke_prefix[-1] = self._resign(revoke_prefix[-1], "k-linear/root")
        with self.assertRaisesRegex(ProtocolError, "UNRESOLVABLE_CREDENTIAL"):
            evaluate_k_admission_scenario(genesis, revoke_prefix)

        rotate_prefix = deepcopy(records[:6])
        rotate_prefix[-1]["fields"]["tail"]["replacementGrantHex"] = (
            rotate_prefix[1]["eventReferenceHex"]
        )
        rotate_prefix[-1] = self._resign(rotate_prefix[-1], "k-linear/root")
        with self.assertRaisesRegex(ProtocolError, "STRUCTURAL_REJECTION"):
            evaluate_k_admission_scenario(genesis, rotate_prefix)

    def test_genesis_exception_and_noncausal_control_targets_are_explicit(self) -> None:
        genesis, records = self._scenario("k-admission-genesis-revoke-exception")
        observations = evaluate_k_admission_scenario(genesis, records)
        self.assertEqual(observations[-1]["kBindingAdmission"], "ADMITTED")

        hostiles = {
            row["id"]: row
            for row in load(CORPUS / "adversarial-mutations.json")[
                "kAdmissionScenarios"
            ]
        }
        for identifier in (
            "k-hostile-revoke-noncausal-target",
            "k-hostile-rotate-retiring-noncausal",
        ):
            row = hostiles[identifier]
            observations = evaluate_k_admission_graph(
                row["acceptedGenesisRecord"], row["records"]
            )
            self.assertEqual(observations, row["expectedObservations"])
            rejected = next(
                observation
                for observation in observations
                if observation["id"].startswith(identifier)
            )
            self.assertEqual(
                rejected["protocolErrorCode"],
                "STRUCTURAL_REJECTION",
            )
            self.assertEqual(
                rejected["stage"],
                "S3_KERNEL_STRUCTURAL",
            )


if __name__ == "__main__":
    unittest.main()
