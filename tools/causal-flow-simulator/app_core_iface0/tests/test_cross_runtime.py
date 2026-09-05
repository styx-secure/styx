from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generate_seed_registry import (  # noqa: E402
    RESPONSE_STATE_POINTERS,
    SchemaSynthesizer,
    SeedGenerationError,
    _derive_response_state_pointers,
    _enforce_cross_case_response_state_non_disclosure,
    _load_json,
    _ordered_roots,
    _pointer_to_dotted,
    _positive_population,
    _semantic_request_carriers,
    generate_phase_a,
    prove_positive_carrier_closure,
    prove_reachability,
    prove_reference_round_trip,
)
from canonical_json import dumps  # noqa: E402
from authority_witness import isolated_authority_states_witness  # noqa: E402
from interface_model import ContractAuthority, evaluate_interface_request  # noqa: E402
from run_cross_runtime import build_report as build_javascript_release_report  # noqa: E402
from run_probe import build_report as build_reference_probe_report  # noqa: E402
import run_probe  # noqa: E402


class SeedReachabilityTests(unittest.TestCase):
    def test_response_snapshot_pointer_derivation_is_exact_and_closed(self) -> None:
        schema = _load_json(ROOT / "contract/APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json")
        reachability = _load_json(
            ROOT / "contract/APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"
        )
        self.assertEqual(
            set(_derive_response_state_pointers(schema, reachability)),
            set(RESPONSE_STATE_POINTERS),
        )

    def test_semantic_fixture_transplants_fail_at_disclosure_gate(self) -> None:
        repo = ROOT.parents[2]
        contract = ROOT / "contract"
        authority = ContractAuthority.load(repo, contract)
        requests = _semantic_request_carriers(authority)
        public_genesis = evaluate_interface_request(authority, requests[2])["result"][
            "proposedGenesis"
        ]
        evidence_successor = evaluate_interface_request(authority, requests[7])[
            "result"
        ]["evaluation"]["proposal"]["successor"]

        mutants = []
        genesis_replay = json.loads(json.dumps(requests))
        genesis_replay[4]["input"]["proposedGenesis"] = public_genesis
        mutants.append(genesis_replay)

        successor_idempotent = json.loads(json.dumps(requests))
        successor_idempotent[8]["input"]["prior"] = evidence_successor
        mutants.append(successor_idempotent)

        genesis_in_evidence_prior = json.loads(json.dumps(requests))
        genesis_in_evidence_prior[7]["input"]["prior"]["genesis"] = public_genesis
        mutants.append(genesis_in_evidence_prior)

        for mutant in mutants:
            with self.subTest(operation=mutant[7]["operation"]):
                with patch(
                    "generate_seed_registry._semantic_request_carriers",
                    return_value=mutant,
                ):
                    with self.assertRaisesRegex(
                        SeedGenerationError,
                        "CROSS_CASE_RESPONSE_STATE_DISCLOSURE",
                    ):
                        _positive_population(repo, contract)

    def test_disclosure_walk_finds_nested_nodes_without_partial_false_positive(self) -> None:
        schema = _load_json(ROOT / "contract/APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json")
        reachability = _load_json(
            ROOT / "contract/APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"
        )
        successor = {"projection": {"a": 1, "b": 2}, "state": "READY"}
        response = {
            "operation": "EVALUATE_EVIDENCE_UPDATE",
            "result": {"evaluation": {"proposal": {"successor": successor}}},
        }
        with self.assertRaisesRegex(
            SeedGenerationError, "CROSS_CASE_RESPONSE_STATE_DISCLOSURE"
        ):
            _enforce_cross_case_response_state_non_disclosure(
                schema,
                reachability,
                [{"nested": [{"value": successor}]}],
                [response],
            )
        _enforce_cross_case_response_state_non_disclosure(
            schema,
            reachability,
            [{"scalar": 1, "properPartial": {"a": 1}}],
            [response],
        )

    def test_javascript_contract_reader_rejects_symlink_without_toctou_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            contract = Path(raw) / "contract"
            shutil.copytree(ROOT / "contract", contract)
            schema = contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json"
            schema.unlink()
            schema.symlink_to("APP-CORE-IFACE-0-SEMANTIC-CONSTRAINTS-CANDIDATE.json")
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--preflight-collections",
                    "--contract",
                    str(contract),
                ],
                input=json.dumps({"direction": "REQUEST", "message": {}}),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, "")

    def test_javascript_contract_reader_binds_artifacts_to_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            contract = Path(raw) / "contract"
            shutil.copytree(ROOT / "contract", contract)
            schema = contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json"
            schema.write_bytes(schema.read_bytes() + b" ")
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--preflight-collections",
                    "--contract",
                    str(contract),
                ],
                input=json.dumps({"direction": "REQUEST", "message": {}}),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("candidate manifest digest mismatch", completed.stderr)

    def test_javascript_contract_reader_rejects_symlinked_contract_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            contract = root / "real" / "contract"
            contract.parent.mkdir()
            shutil.copytree(ROOT / "contract", contract)
            alias = root / "alias"
            alias.symlink_to(contract.parent, target_is_directory=True)
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--preflight-collections",
                    "--contract",
                    str(alias / "contract"),
                ],
                input=json.dumps({"direction": "REQUEST", "message": {}}),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("contract path or ancestor is a symlink", completed.stderr)

    def test_every_ratified_object_and_union_arm_has_a_valid_carrier(self) -> None:
        self.assertEqual(
            prove_reachability(ROOT / "contract"),
            {"object_schema_count": 78, "one_of_arm_count": 54},
        )

    def test_every_operation_has_a_releasable_reference_round_trip(self) -> None:
        self.assertEqual(
            prove_reference_round_trip(ROOT.parents[2], ROOT / "contract"),
            {"request_count": 6, "response_count": 6},
        )

    def test_blind_requests_and_reference_responses_close_carrier_coverage(self) -> None:
        self.assertEqual(
            prove_positive_carrier_closure(ROOT.parents[2], ROOT / "contract"),
            {
                "request_case_count": 65,
                "response_case_count": 15,
                "root_count": 12,
                "object_schema_count": 78,
                "one_of_arm_count": 54,
            },
        )

    def test_repeated_required_schema_locations_are_enumerated(self) -> None:
        contract = ROOT / "contract"
        schema = _load_json(contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json")
        reachability = _load_json(
            contract / "APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"
        )
        roots = _ordered_roots(reachability)
        synthesizer = SchemaSynthesizer(schema)
        target = "/$defs/CapabilityRequirementV0"
        coverage = next(
            row
            for row in reachability["objectCoverage"]
            if row["objectSchemaPointer"] == target
        )
        self.assertEqual(coverage["eligibleRootIds"], ["RESPONSE-DESCRIBE_PROFILE"])
        root = roots["RESPONSE-DESCRIBE_PROFILE"]
        carrier = synthesizer.carrier(root, target_pointer=target)
        self.assertEqual(
            carrier.target_json_pointer,
            "/result/descriptor/capabilityRequirements/ACTIVATION_CAPABILITY_SET",
        )
        self.assertEqual(
            synthesizer.target_locations(root, carrier.value, target),
            [
                "/result/descriptor/capabilityRequirements/ACTIVATION_CAPABILITY_SET",
                "/result/descriptor/capabilityRequirements/CUSTODY_REDUNDANCY",
                "/result/descriptor/capabilityRequirements/DURABLE_RECORDS",
                "/result/descriptor/capabilityRequirements/DURABLE_REQUIRED_OCTETS",
                "/result/descriptor/capabilityRequirements/TRANSIENT_MEMORY_CAPABILITY",
            ],
        )

    def test_independent_javascript_fork_join_label_matches_v9_vector(self) -> None:
        witness = {
            "credentialIdentifierHex": "11" * 32,
            "authorSequence": "7",
            "siblingReferences": ["22" * 32, "33" * 32],
        }
        command = [
            "node",
            str(ROOT / "node_adapter.mjs"),
            "--derive-fork-join",
            "--contract",
            str(ROOT / "contract"),
        ]
        completed = subprocess.run(
            command,
            input=json.dumps(witness),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            json.loads(completed.stdout),
            {
                "joinLabelHex": "6c0e9469f72779ab48f96a90a76f088c23ec88674a3290a19baef8418c49c073"
            },
        )

        noncanonical = dict(witness)
        noncanonical["siblingReferences"] = list(
            reversed(witness["siblingReferences"])
        )
        rejected = subprocess.run(
            command,
            input=json.dumps(noncanonical),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("not bytewise canonical", rejected.stderr)

    def test_independent_javascript_authority_witness_matches_v9_metrics(self) -> None:
        command = [
            "node",
            str(ROOT / "node_adapter.mjs"),
            "--authority-metrics",
            "--contract",
            str(ROOT / "contract"),
        ]
        unbounded = subprocess.run(
            command,
            input=json.dumps(
                isolated_authority_states_witness(
                    state_limit=1000, transition_limit=1000
                )
            ),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            json.loads(unbounded.stdout),
            {
                "kind": "AVAILABLE",
                "maxConcurrentControls": 3,
                "ordinaryPrefixQueryMax": 9,
                "reachableStateCount": 273,
                "replayedEventWork": 1199,
                "transitionCount": 500,
            },
        )
        protected = subprocess.run(
            command,
            input=json.dumps(
                isolated_authority_states_witness(
                    state_limit=256, transition_limit=512
                )
            ),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            json.loads(protected.stdout),
            {"kind": "UNAVAILABLE", "reason": "AUTHORITY_STATES"},
        )

    def test_independent_javascript_graph_projection_is_greedy_and_pending_exact(self) -> None:
        parent = "22" * 32
        newly_ready = "11" * 32
        concurrent = "33" * 32
        fork_left = "44" * 32
        fork_right = "55" * 32
        root = "66" * 32
        fork_actor = "77" * 32
        value = {
            "events": [
                {"reference": parent, "credential": root, "sequence": 0, "dependencies": []},
                {"reference": newly_ready, "credential": root, "sequence": 1, "dependencies": [parent]},
                {"reference": concurrent, "credential": "88" * 32, "sequence": 0, "dependencies": []},
                {"reference": fork_left, "credential": fork_actor, "sequence": 7, "dependencies": []},
                {"reference": fork_right, "credential": fork_actor, "sequence": 7, "dependencies": []},
            ],
            "unverifiedRequiredReferences": [parent],
        }
        completed = subprocess.run(
            [
                "node",
                str(ROOT / "node_adapter.mjs"),
                "--graph-projection",
                "--contract",
                str(ROOT / "contract"),
            ],
            input=json.dumps(value),
            text=True,
            capture_output=True,
            check=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["protocolKOrder"],
            [parent, newly_ready, concurrent, fork_left, fork_right],
        )
        self.assertEqual(result["pendingRootReferences"], [parent])
        self.assertEqual(result["pendingReferences"], [newly_ready])
        self.assertEqual(
            result["forks"],
            [
                {
                    "credential": fork_actor,
                    "sequence": 7,
                    "siblings": [fork_left, fork_right],
                }
            ],
        )
        ancestors = {
            row["reference"]: row["ancestors"] for row in result["ancestors"]
        }
        self.assertEqual(ancestors[newly_ready], [parent])
        self.assertEqual(ancestors[concurrent], [])

    def test_independent_javascript_credential_projection_is_grant_rooted(self) -> None:
        root = "11" * 32
        first = "22" * 32
        child = "33" * 32
        shared_key = "aa" * 32
        child_key = "bb" * 32
        command = [
            "node",
            str(ROOT / "node_adapter.mjs"),
            "--credential-projection",
            "--contract",
            str(ROOT / "contract"),
        ]
        value = {
            "root": {
                "credentialIdentifierHex": root,
                "signatureSuiteId": "1",
                "verificationKeyHex": shared_key,
            },
            # The dependent grant appears first: input order is not authority.
            "grants": [
                {
                    "reference": child,
                    "issuerCredentialIdentifierHex": first,
                    "verificationKeyHex": child_key,
                },
                {
                    "reference": first,
                    "issuerCredentialIdentifierHex": root,
                    "verificationKeyHex": shared_key,
                },
            ],
        }
        completed = subprocess.run(
            command,
            input=json.dumps(value),
            text=True,
            capture_output=True,
            check=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["aliasGroups"], [[root, first]])
        self.assertEqual(
            [row["credentialIdentifierHex"] for row in result["credentialBindings"]],
            [root, first, child],
        )
        self.assertEqual(
            result["credentialBindings"][2]["issuerCredentialIdentifierHex"],
            first,
        )

        unbound = json.loads(json.dumps(value))
        unbound["grants"][1]["issuerCredentialIdentifierHex"] = "ff" * 32
        rejected = subprocess.run(
            command,
            input=json.dumps(unbound),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("no issuer binding", rejected.stderr)

    def test_independent_javascript_rejects_reserved_f13_before_release(self) -> None:
        command = [
            "node",
            str(ROOT / "node_adapter.mjs"),
            "--validate-response",
            "--contract",
            str(ROOT / "contract"),
        ]
        profile = {
            "applicationProfileId": "1",
            "applicationProfileVersion": "1",
            "styxProtocolVersion": "1",
        }

        reachable = {
            "interfaceVersion": "0",
            "operation": "EVALUATE_CANDIDATE",
            "profile": profile,
            "result": {
                "evaluation": {
                    "kind": "TERMINAL_NO_SUCCESSOR",
                    "primary": "DUPLICATE",
                    "stage": "S3_KERNEL_STRUCTURAL",
                }
            },
        }
        accepted = subprocess.run(
            command,
            input=dumps(reachable),
            capture_output=True,
            check=True,
        )
        self.assertEqual(json.loads(accepted.stdout), {"verdict": "PASS"})

        reserved = json.loads(json.dumps(reachable))
        reserved["result"]["evaluation"]["primary"] = "LENGTH_MISMATCH"
        rejected = subprocess.run(
            command,
            input=dumps(reserved),
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"reserved F13", rejected.stderr)

    def test_independent_javascript_preflights_closed_collection_bounds(self) -> None:
        command = [
            "node",
            str(ROOT / "node_adapter.mjs"),
            "--preflight-collections",
            "--contract",
            str(ROOT / "contract"),
        ]
        request = {
            "direction": "REQUEST",
            "message": {
                "operation": "REPLAY_CONTEXT",
                "input": {
                    "candidates": [],
                    "evidence": {"contentMaterial": [], "openingMaterial": []},
                },
            },
        }
        accepted = subprocess.run(
            command,
            input=json.dumps(request),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(json.loads(accepted.stdout), {"verdict": "PASS"})

        over_bound = json.loads(json.dumps(request))
        over_bound["message"]["input"]["candidates"] = [
            {} for _ in range(129)
        ]
        rejected = subprocess.run(
            command,
            input=json.dumps(over_bound),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("ReplayContextInputV0.candidates", rejected.stderr)

        response = {
            "direction": "RESPONSE",
            "message": {
                "operation": "REPLAY_CONTEXT",
                "result": {
                    "proposedContext": {
                        "admittedCandidates": [],
                        "evidence": {
                            "contentMaterial": [],
                            "openingMaterial": [],
                        },
                        "projection": {"records": [{} for _ in range(129)]},
                    }
                },
            },
        }
        rejected_response = subprocess.run(
            command,
            input=json.dumps(response),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected_response.returncode, 2)
        self.assertIn("ContextProjectionV0.records", rejected_response.stderr)

    def test_independent_javascript_applies_exact_outcome_and_state_precedence(self) -> None:
        command = [
            "node",
            str(ROOT / "node_adapter.mjs"),
            "--outcome-projection",
            "--contract",
            str(ROOT / "contract"),
        ]

        def row(index: int, **changes: object) -> dict[str, object]:
            value: dict[str, object] = {
                "appliedControl": False,
                "eventAuthority": "MUST_NOT_AUTH",
                "forkSibling": False,
                "lineageTerminated": False,
                "pendingDescendant": False,
                "pendingRoot": False,
                "postRevocation": False,
                "reference": f"{index:064x}",
                "removalApplicable": True,
                "role": "ORDINARY",
            }
            value.update(changes)
            return value

        value = {
            "authorityUnavailable": False,
            "forkedCredentials": ["ee" * 32],
            "necessaryAuthority": ["ff" * 32],
            "pendingRoots": ["dd" * 32],
            "records": [
                row(1, role="REMOVAL", forkSibling=True, pendingRoot=True, removalApplicable=False),
                row(2, role="REMOVAL", pendingRoot=True, pendingDescendant=True, removalApplicable=False),
                row(3, role="REMOVAL", pendingDescendant=True, removalApplicable=False),
                row(4, role="REMOVAL", removalApplicable=False, postRevocation=True),
                row(5, role="CREDENTIAL", postRevocation=True, lineageTerminated=True),
                row(6, role="CREDENTIAL", appliedControl=True),
                row(7, eventAuthority="MUST_AUTH", postRevocation=True, lineageTerminated=True),
                row(8, postRevocation=True, lineageTerminated=True),
                row(9, lineageTerminated=True),
                row(10),
            ],
        }
        completed = subprocess.run(
            command,
            input=json.dumps(value),
            text=True,
            capture_output=True,
            check=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["contextState"], "PARTIALLY_LINEAGE_QUARANTINED")
        self.assertEqual(
            [item["primary"] for item in result["outcomes"]],
            [
                "FORK_EVIDENCE",
                "PENDING_OPENING",
                "PENDING_ANCESTOR",
                "REMOVAL_INAPPLICABLE",
                "AUTHENTIC_BUT_UNAUTHORIZED",
                "APPLIED",
                "APPLIED",
                "POST_REVOCATION",
                "LINEAGE_QUARANTINED",
                "AUTHENTIC_BUT_UNAUTHORIZED",
            ],
        )

        no_authority = json.loads(json.dumps(value))
        no_authority["necessaryAuthority"] = []
        no_authority_result = subprocess.run(
            command,
            input=json.dumps(no_authority),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            json.loads(no_authority_result.stdout)["contextState"],
            "NO_OPERATIONAL_AUTHORITY",
        )

        unavailable = json.loads(json.dumps(value))
        unavailable["authorityUnavailable"] = True
        unavailable_result = subprocess.run(
            command,
            input=json.dumps(unavailable),
            text=True,
            capture_output=True,
            check=True,
        )
        unavailable_body = json.loads(unavailable_result.stdout)
        self.assertEqual(unavailable_body["contextState"], "AUTHORITY_UNAVAILABLE")
        self.assertEqual(
            {item["primary"] for item in unavailable_body["outcomes"]},
            {"AUTHORITY_PROJECTION_UNAVAILABLE"},
        )


class PhaseAReaderIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.evidence = Path(cls._temporary.name) / "evidence"
        generate_phase_a(ROOT.parents[2], ROOT / "contract", cls.evidence)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def test_reference_reader_freezes_all_requests_before_oracle_comparison(self) -> None:
        inventory = json.loads(
            (self.evidence / "positive-carrier-inventory.json").read_bytes()
        )
        response_files = {
            row["carrierFile"]
            for row in inventory["cases"]
            if row["direction"] == "RESPONSE"
        }
        evaluation_count = 0
        original_object_reader = run_probe._canonical_object
        original_evaluator = run_probe.evaluate_interface_request

        def observed_object_reader(path: Path) -> tuple[object, bytes]:
            if path.name in response_files and evaluation_count != 65:
                self.fail("withheld response carrier was read before all outputs froze")
            return original_object_reader(path)

        def observed_evaluator(*args: object, **kwargs: object) -> dict[str, object]:
            nonlocal evaluation_count
            response = original_evaluator(*args, **kwargs)
            evaluation_count += 1
            return response

        with (
            patch("run_probe._canonical_object", side_effect=observed_object_reader),
            patch("run_probe.evaluate_interface_request", side_effect=observed_evaluator),
        ):
            report = build_reference_probe_report(
                ROOT.parents[2], ROOT / "contract", self.evidence
            )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(evaluation_count, 65)
        self.assertEqual(report["request_case_count"], 65)
        self.assertEqual(report["response_case_count"], 15)
        self.assertEqual(len(report["observations"]), 65)

    def test_package_records_exact_first_retained_request_provenance(self) -> None:
        package = json.loads(
            (self.evidence / "phase-a-package-report.json").read_bytes()
        )
        rows = package["requestProvenance"]
        self.assertEqual(len(rows), 65)
        self.assertEqual(
            [row["caseId"] for row in rows],
            sorted(row["caseId"] for row in rows),
        )
        self.assertEqual(
            {key for row in rows for key in row},
            {
                "caseId",
                "eligibleRootId",
                "generatorKind",
                "generatorOrdinal",
                "sourceIdentity",
            },
        )
        self.assertEqual(
            {kind: sum(row["generatorKind"] == kind for row in rows) for kind in {
                "OBJECT_COVERAGE", "ONEOF_ARM_COVERAGE", "SEMANTIC_FIXTURE"
            }},
            {
                "OBJECT_COVERAGE": 56,
                "ONEOF_ARM_COVERAGE": 0,
                "SEMANTIC_FIXTURE": 9,
            },
        )
        self.assertEqual(_pointer_to_dotted("/$defs/a~1b~0c"), "$defs.a/b~c")

    def test_javascript_reader_admits_every_released_response(self) -> None:
        report = build_javascript_release_report(
            ROOT.parents[2], ROOT / "contract", self.evidence, "node"
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["response_case_count"], 15)
        self.assertRegex(report["response_set_sha256"], r"^[0-9a-f]{64}$")

    def test_javascript_response_mode_rejects_requests_and_noncanonical_bytes(self) -> None:
        inventory = json.loads(
            (self.evidence / "positive-carrier-inventory.json").read_bytes()
        )
        request_rows = [row for row in inventory["cases"] if row["direction"] == "REQUEST"]
        response_row = next(
            row for row in inventory["cases"] if row["direction"] == "RESPONSE"
        )
        command = [
            "node",
            str(ROOT / "node_adapter.mjs"),
            "--validate-response",
            "--contract",
            str(ROOT / "contract"),
        ]
        for row in request_rows:
            rejected = subprocess.run(
                command,
                input=(self.evidence / row["carrierFile"]).read_bytes(),
                capture_output=True,
                check=False,
            )
            self.assertEqual(rejected.returncode, 2, row["caseId"])
            self.assertNotIn(b"TypeError", rejected.stderr, row["caseId"])
        canonical = (self.evidence / response_row["carrierFile"]).read_bytes()
        noncanonical = canonical[:-1] + b" \n"
        rejected = subprocess.run(
            command,
            input=noncanonical,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"not canonical", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
