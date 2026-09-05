from __future__ import annotations

import copy
import sys
from dataclasses import replace
from io import BytesIO
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema.validators import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
sys.path.insert(0, str(ROOT))

from canonical_json import dumps as canonical_dumps  # noqa: E402
from interface_model import (  # noqa: E402
    ContractAuthority,
    EvidenceError,
    HarnessFailure,
    InterfaceModelError,
    ReplayCandidate,
    ReplayClosure,
    ReplayProjection,
    RequestRejected,
    SUPPORTED_OPERATIONS,
    SUPPORTED_PROFILE,
    _load_pinned_c03_model,
    _framing_failure,
    _canonicalize_evidence,
    _assemble_context_projection,
    _branch_a_capacity_crossed,
    _event_projection,
    _credential_projection,
    _fork_join_projection,
    _fork_slots,
    _pending_sets,
    _protocol_k_order,
    _project_content_states,
    _replay_graph_capacity_failure,
    _protocol_error_reason,
    _reduce_application_proof_group,
    _reduce_complete_evidence_attempts,
    _selected_envelope_failure,
    _validate_complete_v2_document,
    _validate_structural_v2_evidence,
    _validate_response_shape_and_relation,
    admit_canonical_request,
    describe_profile,
    evaluate_signature_path,
    evaluate_candidate,
    evaluate_evidence_update,
    evaluate_interface_request,
    evaluate_genesis,
    merge_verified_complete_evidence,
    prepare_replay_closure,
    project_replay_state,
    replay_context,
    read_bounded_request,
    validate_response_before_release,
    validate_request_structure,
    validate_transcript,
    verify_native_authority,
)


class InterfaceModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = ContractAuthority.load(REPO, ROOT / "contract")

    def test_descriptor_is_derived_only_from_pinned_authority(self) -> None:
        descriptor = self.authority.descriptor()
        self.assertEqual(descriptor["profile"], SUPPORTED_PROFILE)
        self.assertEqual(descriptor["supportedOperations"], SUPPORTED_OPERATIONS)
        self.assertEqual(
            descriptor["authorityPins"],
            {
                "outcomeTaxonomySha256Hex": "9565280a5e9a8c8035188cb1c652e2bed3c9496ad05ad0883b0acc07befb7e24",
                "resourceEnvelopeCandidateId": "balanced",
                "resourceEnvelopeSha256Hex": "3f66c0620699b260d11ba014a7355ec5234db1aad12a3e4d9ce797e5b98c5b3e",
                "signatureOctets": "64",
                "signatureSuiteId": "1",
                "transcriptProfileSha256Hex": "62ae2733753c9dabeae3980eec996de33a7f63146e8d16bdd7d55a441e299dbb",
                "verificationKeyOctets": "32",
            },
        )
        self.assertEqual(len(descriptor["interfaceLimits"]), 37)
        self.assertEqual(
            descriptor["capabilityRequirements"],
            {
                "ACTIVATION_CAPABILITY_SET": {
                    "comparison": "EXACT_CLOSED_KEY_SET",
                    "selectedValue": "4",
                    "unit": "COUNT",
                },
                "CUSTODY_REDUNDANCY": {
                    "comparison": "MINIMUM_CAPABILITY",
                    "selectedValue": "1",
                    "unit": "DECLARED_FAILURE_DOMAIN_COPIES",
                },
                "DURABLE_RECORDS": {
                    "comparison": "MINIMUM_CAPABILITY",
                    "selectedValue": "512",
                    "unit": "COUNT",
                },
                "DURABLE_REQUIRED_OCTETS": {
                    "comparison": "MINIMUM_CAPABILITY",
                    "selectedValue": "4194304",
                    "unit": "OCTETS",
                },
                "TRANSIENT_MEMORY_CAPABILITY": {
                    "comparison": "MINIMUM_CAPABILITY",
                    "selectedValue": "134217728",
                    "unit": "OCTETS",
                },
            },
        )
        validator = Draft202012Validator(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$ref": "#/$defs/ProfileDescriptorV0",
                "$defs": self.authority.schema["$defs"],
            }
        )
        self.assertEqual(list(validator.iter_errors(descriptor)), [])

    def test_proof_group_reduction_is_signature_ordered_and_id_agnostic(self) -> None:
        proposed, candidate = self._replay_fixture(event_type=1)
        self.assertIsNotNone(candidate)
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        transcript = bytes.fromhex(candidate["transcriptHex"])
        reference = backend.framed_hash(
            backend.DOMAINS["event_reference"], transcript
        ).hex()
        invalid = bytes.fromhex("10" * 64)
        first_valid = bytes.fromhex("20" * 64)
        later_valid = bytes.fromhex("30" * 64)
        group = {
            "objectKind": "APPLICATION_EVENT",
            "transcriptHex": candidate["transcriptHex"],
            "carriedReferenceHex": reference,
            "proofs": [
                {"presentationId": "same", "signatureHex": later_valid.hex()},
                {"presentationId": "same", "signatureHex": invalid.hex()},
                {"presentationId": "ignored", "signatureHex": first_valid.hex()},
            ],
        }

        def verify(_key: bytes, signature: bytes, _message: bytes) -> bool:
            return signature in {first_valid, later_valid}

        with patch.object(backend, "ed25519_verify", side_effect=verify):
            forward = _reduce_application_proof_group(
                self.authority, group, "44" * 32
            )
            reversed_group = copy.deepcopy(group)
            reversed_group["proofs"].reverse()
            reverse = _reduce_application_proof_group(
                self.authority, reversed_group, "44" * 32
            )
        self.assertTrue(forward.authenticated)
        self.assertEqual(forward, reverse)
        self.assertEqual(forward.retained_signature_hex, first_valid.hex())
        self.assertEqual(forward.signature_attempts, 2)
        self.assertNotIn("presentationId", vars(forward))

    def test_proof_group_limit_precedes_transcript_and_crypto_work(self) -> None:
        group = {
            "objectKind": "APPLICATION_EVENT",
            "transcriptHex": "not-hex",
            "carriedReferenceHex": "00" * 32,
            "proofs": [
                {"presentationId": str(index), "signatureHex": "00" * 64}
                for index in range(65)
            ],
        }
        result = _reduce_application_proof_group(self.authority, group, "00" * 32)
        self.assertFalse(result.authenticated)
        self.assertEqual(result.diagnostic, "PROOF_GROUP_LIMIT_EXCEEDED")
        self.assertEqual(result.signature_attempts, 0)
        self.assertIsNone(result.transcript)

    def test_carried_reference_mismatch_precedes_signature_verification(self) -> None:
        _, candidate = self._replay_fixture(event_type=1)
        self.assertIsNotNone(candidate)
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        group = {
            "objectKind": "APPLICATION_EVENT",
            "transcriptHex": candidate["transcriptHex"],
            "carriedReferenceHex": "ff" * 32,
            "proofs": [
                {"presentationId": "diagnostic-only", "signatureHex": "00" * 64}
            ],
        }
        with patch.object(
            backend,
            "ed25519_verify",
            side_effect=AssertionError("signature verification must not run"),
        ):
            result = _reduce_application_proof_group(
                self.authority, group, "44" * 32
            )
        self.assertFalse(result.authenticated)
        self.assertEqual(result.diagnostic, "CARRIED_REFERENCE_MISMATCH")
        self.assertEqual(result.signature_attempts, 0)

    def test_complete_v2_branch_trace_is_bound_to_direction_and_operation(self) -> None:
        request = {
            "input": {},
            "interfaceVersion": "0",
            "operation": "DESCRIBE_PROFILE",
            "profile": dict(SUPPORTED_PROFILE),
        }
        trace = _validate_complete_v2_document(
            self.authority, request, trusted_direction="REQUEST"
        )
        self.assertEqual(trace.top_level_arm_index, 0)
        self.assertEqual(trace.nested_operation_arm_index, 0)
        with self.assertRaises(HarnessFailure):
            _validate_complete_v2_document(
                self.authority, request, trusted_direction="RESPONSE"
            )

    def test_complete_v2_trace_uses_schema_position_after_arm_mutation(self) -> None:
        request = {
            "input": {},
            "interfaceVersion": "0",
            "operation": "DESCRIBE_PROFILE",
            "profile": dict(SUPPORTED_PROFILE),
        }
        schema = copy.deepcopy(self.authority.schema)
        request_arm = schema["$defs"]["InterfaceRequestV0"]["oneOf"][0]
        schema["$defs"]["InterfaceRequestV0"]["oneOf"][0] = {
            "allOf": [request_arm]
        }
        trace = _validate_structural_v2_evidence(
            self.authority,
            canonical_dumps(request),
            trusted_direction="REQUEST",
            schema_override=schema,
        )
        self.assertEqual(trace.top_level_arm_index, 0)
        self.assertEqual(trace.nested_operation_arm_index, 0)

    def test_structural_boundary_rejects_non_object_roots_and_members(self) -> None:
        for direction, raw, failure in (
            ("REQUEST", b"null\n", RequestRejected),
            ("RESPONSE", b"[]\n", HarnessFailure),
        ):
            with self.subTest(direction=direction):
                with self.assertRaises(failure):
                    _validate_structural_v2_evidence(
                        self.authority,
                        raw,
                        trusted_direction=direction,
                    )

        for invalid_input in (None, [], "", 0):
            request = {
                "input": invalid_input,
                "interfaceVersion": "0",
                "operation": "DESCRIBE_PROFILE",
                "profile": dict(SUPPORTED_PROFILE),
            }
            with self.subTest(input=invalid_input):
                with self.assertRaises(RequestRejected):
                    validate_request_structure(self.authority, request)

        malformed_response = {
            "interfaceVersion": "0",
            "operation": [],
            "profile": dict(SUPPORTED_PROFILE),
            "result": {},
        }
        with self.assertRaises(HarnessFailure):
            _validate_structural_v2_evidence(
                self.authority,
                canonical_dumps(malformed_response),
                trusted_direction="RESPONSE",
            )

    def test_complete_v2_generically_enforces_unsigned_maximum(self) -> None:
        request = {
            "input": {},
            "interfaceVersion": "0",
            "operation": "DESCRIBE_PROFILE",
            "profile": {
                **SUPPORTED_PROFILE,
                "applicationProfileId": str(1 << 32),
            },
        }
        with self.assertRaises(RequestRejected):
            _validate_complete_v2_document(
                self.authority, request, trusted_direction="REQUEST"
            )

        newline = copy.deepcopy(request)
        newline["profile"]["applicationProfileId"] = "1\n"
        with self.assertRaises(RequestRejected):
            _validate_complete_v2_document(
                self.authority, newline, trusted_direction="REQUEST"
            )

    def test_seeded_delta_is_allowed_but_exact_repin_and_read_only_drift_fail(self) -> None:
        selection_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as raw:
            checkout = Path(raw) / "checkout"
            subprocess.run(
                ["git", "clone", "--quiet", "--shared", str(REPO), str(checkout)],
                check=True,
            )
            subprocess.run(
                ["git", "checkout", "--quiet", "--detach", selection_head],
                cwd=checkout,
                check=True,
            )
            contract = checkout / "tools/causal-flow-simulator/app_core_iface0/contract"
            seeded = checkout / "docs/protocol/review/README.md"
            seeded.write_bytes(seeded.read_bytes() + b"\nseeded-role-test\n")
            verify_native_authority(checkout, contract)

            repinned = checkout / "tools/causal-flow-simulator/c03/corpus_model.py"
            repinned_bytes = repinned.read_bytes()
            repinned.write_bytes(repinned_bytes + b"\n")
            with self.assertRaisesRegex(
                InterfaceModelError, "exact native dependency repin drift"
            ):
                verify_native_authority(checkout, contract)
            repinned.write_bytes(repinned_bytes)

            frozen = checkout / "conformance/application-protocol/c03/manifest.json"
            frozen.write_bytes(frozen.read_bytes() + b" ")
            with self.assertRaisesRegex(
                InterfaceModelError, "read-only native dependency drift"
            ):
                verify_native_authority(checkout, contract)

    def test_describe_profile_has_only_supported_or_unsupported_result(self) -> None:
        supported = describe_profile(self.authority, dict(SUPPORTED_PROFILE))
        self.assertEqual(supported["disposition"], "SUPPORTED")
        self.assertIn("descriptor", supported)

        mismatched = dict(SUPPORTED_PROFILE)
        mismatched["applicationProfileVersion"] = "2"
        self.assertEqual(
            describe_profile(self.authority, mismatched),
            {"disposition": "UNSUPPORTED"},
        )

    def test_v1_limit_is_required_and_never_implementation_selected(self) -> None:
        canonical = b'{"input":{},"interfaceVersion":"0","operation":"DESCRIBE_PROFILE","profile":{"applicationProfileId":"1","applicationProfileVersion":"1","styxProtocolVersion":"1"}}\n'
        with self.assertRaises(HarnessFailure):
            admit_canonical_request(canonical, maximum_octets=None)
        with self.assertRaises(RequestRejected):
            admit_canonical_request(canonical, maximum_octets=len(canonical) - 1)
        self.assertEqual(
            admit_canonical_request(canonical, maximum_octets=len(canonical))["operation"],
            "DESCRIBE_PROFILE",
        )

    def test_bounded_reader_consumes_only_one_sentinel_octet(self) -> None:
        stream = BytesIO(b"x" * 1000)
        with self.assertRaises(RequestRejected):
            read_bounded_request(stream, maximum_octets=16)
        self.assertEqual(stream.tell(), 17)
        with self.assertRaises(HarnessFailure):
            read_bounded_request(BytesIO(b"{}\n"), maximum_octets=None)

    def test_bounded_reader_handles_short_reads_without_early_eof(self) -> None:
        class ShortReadStream(BytesIO):
            def read(self, size: int = -1) -> bytes:
                return super().read(min(size, 3))

        accepted = b'{"a":1}\n'
        self.assertEqual(
            read_bounded_request(
                ShortReadStream(accepted), maximum_octets=len(accepted)
            ),
            accepted,
        )
        stream = ShortReadStream(accepted + b"x")
        with self.assertRaises(RequestRejected):
            read_bounded_request(stream, maximum_octets=len(accepted))
        self.assertEqual(stream.tell(), len(accepted) + 1)

    @staticmethod
    def _reference_observations() -> dict[str, str]:
        return {
            "commitmentMatchVerification": "NOT_APPLICABLE",
            "commitmentVerification": "NOT_PRESENT",
            "geometryPredicate1": "NOT_APPLICABLE",
            "geometryPredicate2": "NOT_APPLICABLE",
            "geometryPredicate3": "NOT_APPLICABLE",
            "geometryPredicate4": "NOT_APPLICABLE",
            "geometryPredicate5": "NOT_APPLICABLE",
            "geometryPredicate6": "NOT_APPLICABLE",
            "geometryPredicate7": "NOT_APPLICABLE",
            "referenceVerification": "REJECTED",
            "signatureVerification": "NOT_EVALUATED",
            "suppliedLengthVerification": "NOT_APPLICABLE",
            "transcriptVerification": "VALID",
        }

    def test_acv066_row_coherent_reserved_results_are_rejected_only_by_acv066(self) -> None:
        relations = json.loads(
            (
                self.authority.contract
                / "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"
            ).read_text(encoding="utf-8")
        )
        reserved_rows = [
            row
            for row in relations["terminalPredicateRelationV0"]
            if row["result"]["reachability"] == "RESERVED_UNREACHABLE_V0"
        ]
        self.assertEqual(
            sorted(row["relationRowId"] for row in reserved_rows),
            ["GRS-009", "GRS-010", "GRS-011", "GRS-015", "GRS-016", "TRS-011"],
        )
        fixtures = []
        for row in reserved_rows:
            result = {
                "kind": row["result"]["kind"],
                "reason": row["result"]["reason"],
                "stage": row["result"]["stage"],
            }
            if row["operation"] == "VALIDATE_TRANSCRIPT":
                result["observations"] = self._reference_observations()
            fixtures.append(
                {
                    "interfaceVersion": "0",
                    "operation": row["operation"],
                    "profile": dict(SUPPORTED_PROFILE),
                    "result": result,
                }
            )
        observation = {
            "interfaceVersion": "0",
            "operation": "VALIDATE_TRANSCRIPT",
            "profile": dict(SUPPORTED_PROFILE),
            "result": {
                "kind": "REJECTED",
                "reason": "SIGNATURE_LENGTH_MISMATCH",
                "stage": "SIGNATURE_VERIFICATION",
                "observations": self._reference_observations(),
            },
        }
        fixtures.append(observation)
        self.assertEqual(len(fixtures), 7)
        for response in fixtures:
            # This is the exact ACV-066 source mutant: schema and relation
            # validation remain active, while only reserved reachability is
            # removed.  The row-coherent response must therefore be admitted.
            _validate_response_shape_and_relation(self.authority, response)
            with self.assertRaisesRegex(HarnessFailure, "reserved terminal predicate"):
                validate_response_before_release(self.authority, response)

    def test_app_core_inputs_cannot_supply_an_expected_reference(self) -> None:
        definitions = self.authority.schema["$defs"]
        candidate_properties = {
            "objectKind",
            "signatureHex",
            "transcriptHex",
        }
        self.assertEqual(
            set(definitions["GenesisTranscriptCandidateV0"]["properties"]),
            candidate_properties,
        )
        self.assertEqual(
            set(definitions["ApplicationTranscriptCandidateV0"]["properties"]),
            candidate_properties,
        )
        self.assertEqual(
            set(definitions["EvaluateGenesisInputV0"]["properties"]),
            {"candidate", "expectedContextIdentifierHex"},
        )
        for arm in definitions["ValidateTranscriptInputV0"]["oneOf"]:
            self.assertNotIn("expectedReferenceHex", arm.get("properties", {}))

    def test_signature_schema_and_o08_boundary_are_distinct(self) -> None:
        definitions = self.authority.schema["$defs"]
        signature = definitions["SignatureHex"]
        self.assertEqual(signature["x-styx-o08-limit"], "SIGNATURE_OCTETS")
        self.assertEqual(
            signature["allOf"], [{"$ref": "#/$defs/EvenLowerHex"}]
        )
        candidate_validator = Draft202012Validator(
            {
                "$schema": self.authority.schema["$schema"],
                "$ref": "#/$defs/ApplicationTranscriptCandidateV0",
                "$defs": definitions,
            }
        )
        base = {
            "objectKind": "APPLICATION_EVENT",
            "transcriptHex": "00",
            "signatureHex": "",
        }
        self.assertTrue(candidate_validator.is_valid(base))
        for malformed in ("0", "AA", "gg"):
            self.assertFalse(
                candidate_validator.is_valid({**base, "signatureHex": malformed})
            )
        with self.assertRaises(RequestRejected):
            evaluate_signature_path(
                self.authority,
                operation="VALIDATE_TRANSCRIPT",
                candidate_kind="APPLICATION_EVENT",
                transcript=b"t",
                signature=bytes(65),
            )

    def test_signature_path_relation_enforces_all_guard_boundaries(self) -> None:
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        transcript = b"app-core-signature-path"
        key, signature = backend.ed25519_sign(bytes(range(32)), transcript)

        short_without_key = evaluate_signature_path(
            self.authority,
            operation="VALIDATE_TRANSCRIPT",
            candidate_kind="APPLICATION_EVENT",
            transcript=transcript,
            signature=b"",
        )
        self.assertEqual(short_without_key.relation_id, "SVP-001")
        self.assertEqual(short_without_key.backend_invocations, 0)

        no_key = evaluate_signature_path(
            self.authority,
            operation="VALIDATE_TRANSCRIPT",
            candidate_kind="APPLICATION_EVENT",
            transcript=transcript,
            signature=signature,
        )
        self.assertEqual(no_key.relation_id, "SVP-002")
        self.assertEqual(no_key.signature_observation, "NOT_EVALUATED")

        short_with_key = evaluate_signature_path(
            self.authority,
            operation="VALIDATE_TRANSCRIPT",
            candidate_kind="APPLICATION_EVENT",
            transcript=transcript,
            signature=signature[:-1],
            standalone_verification_key=key,
        )
        self.assertEqual(short_with_key.relation_id, "SVP-003")

        rejected_key = evaluate_signature_path(
            self.authority,
            operation="VALIDATE_TRANSCRIPT",
            candidate_kind="APPLICATION_EVENT",
            transcript=transcript,
            signature=signature,
            standalone_verification_key=bytes(32),
        )
        self.assertEqual(rejected_key.relation_id, "SVP-004")

        rejected_rs = evaluate_signature_path(
            self.authority,
            operation="VALIDATE_TRANSCRIPT",
            candidate_kind="APPLICATION_EVENT",
            transcript=transcript,
            signature=bytes(32) + bytes(32),
            standalone_verification_key=key,
        )
        self.assertEqual(rejected_rs.relation_id, "SVP-005")

        changed = signature[:32] + bytes([signature[32] ^ 1]) + signature[33:]
        backend_rejected = evaluate_signature_path(
            self.authority,
            operation="VALIDATE_TRANSCRIPT",
            candidate_kind="APPLICATION_EVENT",
            transcript=transcript,
            signature=changed,
            standalone_verification_key=key,
        )
        self.assertEqual(backend_rejected.relation_id, "SVP-006")
        self.assertEqual(backend_rejected.backend_invocations, 1)

        accepted = evaluate_signature_path(
            self.authority,
            operation="VALIDATE_TRANSCRIPT",
            candidate_kind="APPLICATION_EVENT",
            transcript=transcript,
            signature=signature,
            standalone_verification_key=key,
        )
        self.assertEqual(accepted.relation_id, "SVP-007")
        self.assertEqual(accepted.backend_invocations, 1)
        self.assertEqual(accepted.signature_observation, "VALID")

        genesis_invalid_key = evaluate_signature_path(
            self.authority,
            operation="VALIDATE_TRANSCRIPT",
            candidate_kind="GENESIS",
            transcript=transcript,
            signature=signature,
            parsed_genesis_root_key=bytes(32),
        )
        self.assertEqual(genesis_invalid_key.relation_id, "SVP-009")
        self.assertEqual(genesis_invalid_key.result_mapping, "TRS-013")

        genesis_accepted = evaluate_signature_path(
            self.authority,
            operation="EVALUATE_GENESIS",
            candidate_kind="GENESIS",
            transcript=transcript,
            signature=signature,
            parsed_genesis_root_key=key,
        )
        self.assertEqual(genesis_accepted.relation_id, "SVP-017")
        self.assertEqual(genesis_accepted.result_mapping, "GRS-001_IF_ALL_REMAINING_GATES_PASS")
        self.assertEqual(genesis_accepted.backend_invocations, 1)

    def test_v3_outer_framing_has_one_exact_fail_closed_order(self) -> None:
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        domain = backend.DOMAINS["application"]
        self.assertEqual(
            _framing_failure(backend, "APPLICATION_EVENT", b""),
            ("TRANSCRIPT_LENGTH_MISMATCH", "OUTER_FRAMING"),
        )
        self.assertEqual(
            _framing_failure(backend, "APPLICATION_EVENT", bytes(16)),
            ("TRANSCRIPT_DOMAIN_REJECTED", "OUTER_FRAMING"),
        )
        self.assertEqual(
            _framing_failure(backend, "APPLICATION_EVENT", domain + bytes(3)),
            ("TRANSCRIPT_LENGTH_MISMATCH", "OUTER_FRAMING"),
        )
        self.assertEqual(
            _framing_failure(
                backend,
                "APPLICATION_EVENT",
                domain + ((1 << 32) - 20).to_bytes(4, "big"),
            ),
            ("TRANSCRIPT_LENGTH_REJECTED", "OUTER_FRAMING"),
        )
        for framed in (
            domain + (1).to_bytes(4, "big"),
            domain + (0).to_bytes(4, "big") + b"x",
        ):
            self.assertEqual(
                _framing_failure(backend, "APPLICATION_EVENT", framed),
                ("TRANSCRIPT_LENGTH_MISMATCH", "OUTER_FRAMING"),
            )
        self.assertIsNone(
            _framing_failure(
                backend, "APPLICATION_EVENT", domain + (0).to_bytes(4, "big")
            )
        )

    def test_v3_parser_diagnostic_mapping_is_closed(self) -> None:
        self.assertEqual(
            _protocol_error_reason("TRUNCATED_CONTEXT"),
            ("TRANSCRIPT_TRUNCATED", "TRANSCRIPT_BODY"),
        )
        self.assertEqual(
            _protocol_error_reason("TRAILING_GEOMETRY"),
            ("TRANSCRIPT_TRAILING_BYTES", "TRANSCRIPT_BODY"),
        )
        self.assertEqual(
            _protocol_error_reason("ORDINARY_TAIL_FORBIDDEN"),
            ("CONTENT_DESCRIPTOR_REJECTED", "TRANSCRIPT_BODY"),
        )
        self.assertEqual(
            _protocol_error_reason("TREE_GEOMETRY_MISSING"),
            ("COMMITMENT_GEOMETRY_REJECTED", "TRANSCRIPT_BODY"),
        )
        self.assertEqual(
            _protocol_error_reason("NONCANONICAL_REENCODING"),
            ("TRANSCRIPT_NONCANONICAL", "TRANSCRIPT_BODY"),
        )
        for code in (
            "CHUNK_OCTETS_LIMIT",
            "GENESIS_POLICY_OCTETS_LIMIT",
            "UNKNOWN_FUTURE_DIAGNOSTIC",
        ):
            with self.assertRaisesRegex(HarnessFailure, "unclassified"):
                _protocol_error_reason(code)

    @staticmethod
    def _application_fields(**updates: object) -> dict[str, object]:
        fields: dict[str, object] = {
            "applicationProfileId": 1,
            "applicationProfileVersion": 1,
            "authorSequence": 0,
            "causalParents": [],
            "content": {"class": "NONE", "exactLength": 0},
            "contextIdentifierHex": "11" * 32,
            "credentialIdentifierHex": "22" * 32,
            "directPredecessorHex": None,
            "eventRole": "ORDINARY",
            "eventTypeId": 1,
            "genesisReferenceHex": "33" * 32,
            "schemaId": 1,
            "schemaVersion": 1,
            "transitionBlockHex": "",
        }
        fields.update(updates)
        return fields

    def test_v3_profile_tuple_precedes_selected_envelope_and_signature(self) -> None:
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        fields = self._application_fields(
            applicationProfileVersion=2,
            transitionBlockHex="44" * 4097,
        )
        transcript = backend.encode_event(fields)
        result = validate_transcript(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "candidate": {
                    "objectKind": "APPLICATION_EVENT",
                    "signatureHex": "",
                    "transcriptHex": transcript.hex(),
                }
            },
        )
        self.assertEqual(
            (result["reason"], result["stage"]),
            ("TRANSCRIPT_PROFILE_MISMATCH", "PROFILE_ENVELOPE"),
        )

        fields["applicationProfileVersion"] = 1
        transcript = backend.encode_event(fields)
        parsed = backend.parse_event(transcript)
        self.assertEqual(
            _selected_envelope_failure(
                backend, "APPLICATION_EVENT", transcript, parsed
            ),
            "AP_TRANSITION_BLOCK_OCTETS_LIMIT",
        )
        result = validate_transcript(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "candidate": {
                    "objectKind": "APPLICATION_EVENT",
                    "signatureHex": "",
                    "transcriptHex": transcript.hex(),
                }
            },
        )
        self.assertEqual(
            (result["reason"], result["stage"]),
            ("SELECTED_ENVELOPE_REJECTED", "PROFILE_ENVELOPE"),
        )

    def test_v3_genesis_context_binding_precedes_signature(self) -> None:
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        seed = bytes(range(32))
        key, _ = backend.ed25519_sign(seed, b"")
        transcript = backend.encode_genesis(
            {
                "applicationProfileId": 1,
                "applicationProfileVersion": 1,
                "contextIdentifierHex": "11" * 32,
                "initialAuthorityPolicyHex": "01",
                "rootVerificationKeyHex": key.hex(),
            }
        )
        result = evaluate_genesis(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "candidate": {
                    "objectKind": "GENESIS",
                    "signatureHex": (bytes(64)).hex(),
                    "transcriptHex": transcript.hex(),
                },
                "expectedContextIdentifierHex": "ff" * 32,
            },
        )
        self.assertEqual(
            (result["reason"], result["stage"]),
            ("EXPECTED_CONTEXT_MISMATCH", "CONTEXT_BINDING"),
        )

    def test_v3_transcript_hex_limit_includes_exact_outer_prefix(self) -> None:
        base = {
            "interfaceVersion": "0",
            "operation": "VALIDATE_TRANSCRIPT",
            "profile": dict(SUPPORTED_PROFILE),
            "input": {
                "candidate": {
                    "objectKind": "APPLICATION_EVENT",
                    "signatureHex": "",
                    "transcriptHex": "00" * (8192 + 20),
                }
            },
        }
        validate_request_structure(self.authority, base)
        trailing_newline = json.loads(json.dumps(base))
        trailing_newline["input"]["candidate"]["transcriptHex"] = "00\n"
        with self.assertRaises(RequestRejected):
            validate_request_structure(self.authority, trailing_newline)
        too_large = json.loads(json.dumps(base))
        too_large["input"]["candidate"]["transcriptHex"] += "00"
        with self.assertRaises(RequestRejected):
            validate_request_structure(self.authority, too_large)

    def test_collection_bounds_fail_before_item_validation_and_release(self) -> None:
        over_bound_replay = {
            "interfaceVersion": "0",
            "operation": "REPLAY_CONTEXT",
            "profile": dict(SUPPORTED_PROFILE),
            "input": {
                "proposedGenesis": {},
                # Deliberately malformed elements prove the count check wins
                # before schema item validation or transcript work.
                "candidates": [{} for _ in range(129)],
                "evidence": {"contentMaterial": [], "openingMaterial": []},
            },
        }
        with self.assertRaises(RequestRejected):
            validate_request_structure(self.authority, over_bound_replay)

        proposed, candidate = self._replay_fixture(event_type=1)
        released = replay_context(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "proposedGenesis": proposed,
                "candidates": [candidate],
                "evidence": {"contentMaterial": [], "openingMaterial": []},
            },
        )
        response = {
            "interfaceVersion": "0",
            "operation": "REPLAY_CONTEXT",
            "profile": dict(SUPPORTED_PROFILE),
            "result": released,
        }
        record = response["result"]["proposedContext"]["projection"]["records"][0]
        response["result"]["proposedContext"]["projection"]["records"] = [
            json.loads(json.dumps(record)) for _ in range(129)
        ]
        with self.assertRaisesRegex(
            HarnessFailure, "exceeds ContextProjectionV0.records"
        ):
            validate_response_before_release(self.authority, response)

    def _replay_fixture(
        self, *, event_type: int | None = None
    ) -> tuple[dict[str, object], dict[str, str] | None]:
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        seed = bytes(range(32))
        root_key, _ = backend.ed25519_sign(seed, b"")
        context = "11" * 32
        genesis_transcript = backend.encode_genesis(
            {
                "applicationProfileId": 1,
                "applicationProfileVersion": 1,
                "contextIdentifierHex": context,
                "initialAuthorityPolicyHex": "01",
                "rootVerificationKeyHex": root_key.hex(),
            }
        )
        _, genesis_signature = backend.ed25519_sign(seed, genesis_transcript)
        genesis_result = evaluate_genesis(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "candidate": {
                    "objectKind": "GENESIS",
                    "signatureHex": genesis_signature.hex(),
                    "transcriptHex": genesis_transcript.hex(),
                },
                "expectedContextIdentifierHex": context,
            },
        )
        self.assertEqual(genesis_result["kind"], "GENESIS_PROPOSAL_READY")
        proposed = genesis_result["proposedGenesis"]
        if event_type is None:
            return proposed, None
        genesis_reference = proposed["projection"]["genesisReferenceHex"]
        transcript = backend.encode_event(
            self._application_fields(
                contextIdentifierHex=context,
                credentialIdentifierHex=genesis_reference,
                eventTypeId=event_type,
                genesisReferenceHex=genesis_reference,
            )
        )
        _, signature = backend.ed25519_sign(seed, transcript)
        return proposed, {
            "objectKind": "APPLICATION_EVENT",
            "signatureHex": signature.hex(),
            "transcriptHex": transcript.hex(),
        }

    def test_replay_security_prefix_revalidates_genesis_and_complete_k_set(self) -> None:
        proposed, candidate = self._replay_fixture(event_type=1)
        value = {
            "proposedGenesis": proposed,
            "candidates": [candidate],
            "evidence": {"contentMaterial": [], "openingMaterial": []},
        }
        closure = prepare_replay_closure(
            self.authority, dict(SUPPORTED_PROFILE), value
        )
        self.assertIsInstance(closure, ReplayClosure)
        self.assertEqual(len(closure.candidates), 1)
        self.assertEqual(closure.k_observations[0]["kBindingAdmission"], "ADMITTED")

        substituted = json.loads(json.dumps(value))
        substituted["proposedGenesis"]["projection"][
            "rootCredentialIdentifierHex"
        ] = "ff" * 32
        self.assertEqual(
            prepare_replay_closure(
                self.authority, dict(SUPPORTED_PROFILE), substituted
            ),
            {
                "kind": "TERMINAL_INPUT_REJECTED",
                "reason": "GENESIS_REVALIDATION_FAILED",
                "stage": "GENESIS_REVALIDATION",
            },
        )

    def test_internal_replay_projection_combines_k_pending_and_authority(self) -> None:
        proposed, candidate = self._replay_fixture(event_type=1)
        projection = project_replay_state(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "proposedGenesis": proposed,
                "candidates": [candidate],
                "evidence": {"contentMaterial": [], "openingMaterial": []},
            },
        )
        self.assertIsInstance(projection, ReplayProjection)
        self.assertEqual(len(projection.records), 1)
        self.assertEqual(projection.records[0]["kAdmission"], "ADMITTED")
        self.assertEqual(
            projection.records[0]["replayReadiness"], "READY_FOR_AP_FOLD"
        )
        self.assertEqual(projection.pending_roots, frozenset())
        self.assertEqual(projection.pending_references, frozenset())
        root = proposed["projection"]["rootCredentialIdentifierHex"]
        reference = projection.closure.candidates[0].reference_hex
        self.assertEqual(projection.authority.terminal_authority, frozenset({root}))
        self.assertEqual(projection.authority.event_authority[reference], "MUST_AUTH")
        assembled = _assemble_context_projection(self.authority, projection)
        self.assertEqual(assembled["contextState"], "ACTIVE")
        self.assertEqual(
            assembled["recordOutcomes"],
            [
                {
                    "disposition": "APPLIED",
                    "eventReferenceHex": reference,
                    "stage": "FINAL_AFTER_S6",
                }
            ],
        )
        self.assertEqual(assembled["replayDependencyReferences"], [reference])

        released = replay_context(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "proposedGenesis": proposed,
                "candidates": [candidate],
                "evidence": {"contentMaterial": [], "openingMaterial": []},
            },
        )
        self.assertEqual(released["kind"], "REPLAY_PROPOSAL_READY")
        self.assertEqual(released["stage"], "REPLAY_COMPLETE")
        self.assertEqual(
            released["proposedContext"]["projection"], assembled
        )
        response = evaluate_interface_request(
            self.authority,
            {
                "interfaceVersion": "0",
                "operation": "REPLAY_CONTEXT",
                "profile": dict(SUPPORTED_PROFILE),
                "input": {
                    "proposedGenesis": proposed,
                    "candidates": [candidate],
                    "evidence": {"contentMaterial": [], "openingMaterial": []},
                },
            },
        )
        self.assertEqual(response["result"], released)

        unavailable = _assemble_context_projection(
            self.authority,
            replace(
                projection,
                authority=None,
                authority_unavailable_branch="A",
                fork_joins=(),
            ),
        )
        self.assertEqual(unavailable["contextState"], "AUTHORITY_UNAVAILABLE")
        self.assertEqual(
            unavailable["recordOutcomes"][0]["disposition"],
            "AUTHORITY_PROJECTION_UNAVAILABLE",
        )
        self.assertEqual(unavailable["authority"]["status"], "UNAVAILABLE")

    def test_candidate_evaluation_revalidates_prior_and_equals_full_replay(self) -> None:
        proposed, candidate = self._replay_fixture(event_type=1)
        empty_replay = replay_context(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "proposedGenesis": proposed,
                "candidates": [],
                "evidence": {"contentMaterial": [], "openingMaterial": []},
            },
        )
        self.assertEqual(empty_replay["kind"], "REPLAY_PROPOSAL_READY")
        prior = empty_replay["proposedContext"]
        value = {
            "prior": prior,
            "candidate": candidate,
            "evidence": {"contentMaterial": [], "openingMaterial": []},
        }
        evaluated = evaluate_candidate(
            self.authority, dict(SUPPORTED_PROFILE), value
        )
        self.assertEqual(evaluated["evaluation"]["kind"], "PROPOSAL_READY")
        self.assertEqual(evaluated["evaluation"]["primaryOnCommit"], "APPLIED")
        full = replay_context(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "proposedGenesis": proposed,
                "candidates": [candidate],
                "evidence": {"contentMaterial": [], "openingMaterial": []},
            },
        )
        self.assertEqual(
            evaluated["evaluation"]["proposal"]["successor"],
            full["proposedContext"],
        )
        response = evaluate_interface_request(
            self.authority,
            {
                "interfaceVersion": "0",
                "operation": "EVALUATE_CANDIDATE",
                "profile": dict(SUPPORTED_PROFILE),
                "input": value,
            },
        )
        self.assertEqual(response["result"], evaluated)

        with self.assertRaises(RequestRejected):
            evaluate_candidate(
                self.authority,
                dict(SUPPORTED_PROFILE),
                {
                    **value,
                    "evidence": {
                        "contentMaterial": [
                            {
                                "eventReferenceHex": "00" * 32,
                                "segments": [],
                            }
                        ],
                        "openingMaterial": [],
                    },
                },
            )

        duplicate = evaluate_candidate(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "prior": full["proposedContext"],
                "candidate": candidate,
                "evidence": {"contentMaterial": [], "openingMaterial": []},
            },
        )
        self.assertEqual(
            duplicate,
            {
                "evaluation": {
                    "kind": "TERMINAL_NO_SUCCESSOR",
                    "primary": "DUPLICATE",
                    "stage": "S3_KERNEL_STRUCTURAL",
                }
            },
        )

        forged = json.loads(json.dumps(prior))
        forged["projection"]["contextState"] = "PARTIALLY_PENDING"
        with self.assertRaises(RequestRejected):
            evaluate_candidate(
                self.authority,
                dict(SUPPORTED_PROFILE),
                {**value, "prior": forged},
            )

        malformed = json.loads(json.dumps(candidate))
        malformed["transcriptHex"] = malformed["transcriptHex"][:-2]
        self.assertEqual(
            evaluate_candidate(
                self.authority,
                dict(SUPPORTED_PROFILE),
                {**value, "candidate": malformed},
            ),
            {
                "evaluation": {
                    "kind": "TERMINAL_NO_SUCCESSOR",
                    "primary": "STRUCTURAL_REJECTION",
                    "stage": "S3_KERNEL_STRUCTURAL",
                }
            },
        )

        reserved = {
            "interfaceVersion": "0",
            "operation": "EVALUATE_CANDIDATE",
            "profile": dict(SUPPORTED_PROFILE),
            "result": {
                "evaluation": {
                    "kind": "TERMINAL_NO_SUCCESSOR",
                    "primary": "LENGTH_MISMATCH",
                    "stage": "S3_KERNEL_STRUCTURAL",
                }
            },
        }
        _validate_response_shape_and_relation(self.authority, reserved)
        with self.assertRaisesRegex(HarnessFailure, "reserved F13"):
            validate_response_before_release(self.authority, reserved)

    def test_evidence_update_is_monotone_prior_bound_and_full_replay_equal(self) -> None:
        proposed, _ = self._replay_fixture()
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        root = proposed["projection"]["rootCredentialIdentifierHex"]
        context = proposed["projection"]["context"]["contextIdentifierHex"]
        content = b"late"
        opening = "45" * 32
        commitment = backend.encode_commitment(
            profile_id=1,
            profile_version=1,
            context=bytes.fromhex(context),
            credential=bytes.fromhex(root),
            sequence=0,
            content_type=1,
            content=content,
            randomizer=bytes.fromhex(opening),
            chunk_size=None,
        )
        transcript = backend.encode_event(
            self._application_fields(
                contextIdentifierHex=context,
                credentialIdentifierHex=root,
                genesisReferenceHex=root,
                content={
                    "class": "REQUIRED",
                    "commitmentHex": commitment["commitmentHex"],
                    "contentType": 1,
                    "exactLength": len(content),
                    "geometryPredicateResults": {
                        f"geometryPredicate{index}": "NOT_APPLICABLE"
                        for index in range(1, 8)
                    },
                    "shape": "SINGLE",
                },
            )
        )
        _, signature = backend.ed25519_sign(bytes(range(32)), transcript)
        candidate = {
            "objectKind": "APPLICATION_EVENT",
            "signatureHex": signature.hex(),
            "transcriptHex": transcript.hex(),
        }
        pending = replay_context(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "proposedGenesis": proposed,
                "candidates": [candidate],
                "evidence": {"contentMaterial": [], "openingMaterial": []},
            },
        )["proposedContext"]
        reference = pending["projection"]["records"][0]["eventReferenceHex"]
        additions = {
            "contentMaterial": [
                {
                    "eventReferenceHex": reference,
                    "segments": [{"offset": "0", "octetsHex": content.hex()}],
                }
            ],
            "openingMaterial": [
                {
                    "eventReferenceHex": reference,
                    "openingRandomizerHex": opening,
                }
            ],
        }
        evaluated = evaluate_evidence_update(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {"prior": pending, "additions": additions},
        )
        self.assertEqual(evaluated["evaluation"]["kind"], "PROPOSAL_READY")
        self.assertEqual(evaluated["evaluation"]["evidenceEffect"], "ADD_MONOTONE")
        successor = evaluated["evaluation"]["proposal"]["successor"]
        full = replay_context(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "proposedGenesis": proposed,
                "candidates": [candidate],
                "evidence": additions,
            },
        )
        self.assertEqual(successor, full["proposedContext"])
        self.assertEqual(
            successor["projection"]["recordOutcomes"][0]["disposition"],
            "APPLIED",
        )
        self.assertEqual(
            evaluate_evidence_update(
                self.authority,
                dict(SUPPORTED_PROFILE),
                {"prior": successor, "additions": additions},
            ),
            {"evaluation": {"kind": "IDEMPOTENT_NO_CHANGE"}},
        )
        partial = {**additions, "openingMaterial": []}
        self.assertEqual(
            evaluate_evidence_update(
                self.authority,
                dict(SUPPORTED_PROFILE),
                {"prior": pending, "additions": partial},
            ),
            {
                "evaluation": {
                    "kind": "TERMINAL_REJECTED",
                    "reason": "NONCANONICAL_MATERIAL",
                }
            },
        )
        mismatched = json.loads(json.dumps(additions))
        mismatched["openingMaterial"][0]["openingRandomizerHex"] = "46" * 32
        self.assertEqual(
            evaluate_evidence_update(
                self.authority,
                dict(SUPPORTED_PROFILE),
                {"prior": pending, "additions": mismatched},
            ),
            {
                "evaluation": {
                    "kind": "TERMINAL_REJECTED",
                    "reason": "EVIDENCE_COMMITMENT_MISMATCH",
                }
            },
        )
        response = evaluate_interface_request(
            self.authority,
            {
                "interfaceVersion": "0",
                "operation": "EVALUATE_EVIDENCE_UPDATE",
                "profile": dict(SUPPORTED_PROFILE),
                "input": {"prior": pending, "additions": additions},
            },
        )
        self.assertEqual(response["result"], evaluated)

    def test_internal_replay_projection_cross_checks_complete_k_fork(self) -> None:
        proposed, first = self._replay_fixture(event_type=1)
        _, second = self._replay_fixture(event_type=2)
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        candidates = [first, second]
        candidates.sort(
            key=lambda item: backend.framed_hash(
                backend.DOMAINS["event_reference"],
                bytes.fromhex(item["transcriptHex"]),
            ).hex()
        )
        projection = project_replay_state(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                "proposedGenesis": proposed,
                "candidates": candidates,
                "evidence": {"contentMaterial": [], "openingMaterial": []},
            },
        )
        self.assertIsInstance(projection, ReplayProjection)
        self.assertEqual(len(projection.fork_relation), 1)
        self.assertEqual(
            {record["kAdmission"] for record in projection.records},
            {"FORK_CLASSIFIED"},
        )
        self.assertEqual(
            projection.authority.forked_credentials,
            frozenset({proposed["projection"]["rootCredentialIdentifierHex"]}),
        )
        assembled = _assemble_context_projection(self.authority, projection)
        self.assertEqual(assembled["contextState"], "NO_OPERATIONAL_AUTHORITY")
        self.assertEqual(len(assembled["forkJoins"]), 1)
        self.assertEqual(
            {row["disposition"] for row in assembled["recordOutcomes"]},
            {"FORK_EVIDENCE"},
        )
        unavailable = _assemble_context_projection(
            self.authority,
            replace(
                projection,
                authority=None,
                authority_unavailable_branch="B",
            ),
        )
        self.assertEqual(unavailable["forkJoins"], assembled["forkJoins"])
        self.assertEqual(
            unavailable["forkedCredentialIdentifiers"],
            [proposed["projection"]["rootCredentialIdentifierHex"]],
        )

    def test_branch_a_capacity_is_measured_before_authority_fold(self) -> None:
        candidates = tuple(
            ReplayCandidate(
                {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
                f"{index + 1:064x}",
                b"",
                self._application_fields(
                    credentialIdentifierHex=f"{index + 1:064x}"
                ),
            )
            for index in range(9)
        )
        bindings = [
            {
                "credentialIdentifierHex": candidate.fields["credentialIdentifierHex"],
                "origin": "GENESIS",
                "signatureSuiteId": "1",
                "verificationKeyHex": f"{index + 20:064x}",
            }
            for index, candidate in enumerate(candidates)
        ]
        lineage = {
            row["credentialIdentifierHex"]: (None, row["credentialIdentifierHex"])
            for row in bindings
        }
        self.assertTrue(
            _branch_a_capacity_crossed(
                self.authority, {}, bindings, [], lineage, candidates
            )
        )

    def test_replay_s4_capacity_uses_literal_first_failure_results(self) -> None:
        over_parent = ReplayCandidate(
            {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
            "aa" * 32,
            b"",
            self._application_fields(causalParents=[f"{index + 1:064x}" for index in range(9)]),
        )
        self.assertEqual(
            _replay_graph_capacity_failure(
                self.authority, (over_parent,), frozenset()
            ),
            {
                "kind": "TERMINAL_CANDIDATE_REJECTED",
                "primary": "CONTEXT_CAPACITY_EXHAUSTED",
                "stage": "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT",
            },
        )

        frontier = tuple(
            ReplayCandidate(
                {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
                f"{index + 1:064x}",
                b"",
                self._application_fields(
                    credentialIdentifierHex=f"{index + 30:064x}"
                ),
            )
            for index in range(17)
        )
        self.assertEqual(
            _replay_graph_capacity_failure(
                self.authority, frontier, frozenset()
            )["primary"],
            "CONTEXT_CAPACITY_EXHAUSTED",
        )

        single = frontier[:1]
        self.assertEqual(
            _replay_graph_capacity_failure(
                self.authority,
                single,
                frozenset(f"{index + 1:064x}" for index in range(17)),
            )["primary"],
            "DEPENDENCY_DEFERRED",
        )

        retained = tuple(
            ReplayCandidate(
                {
                    "objectKind": "APPLICATION_EVENT",
                    "signatureHex": "",
                    "transcriptHex": "",
                },
                f"{index + 1:064x}",
                b"",
                self._application_fields(authorSequence=index),
            )
            for index in range(129)
        )
        self.assertEqual(
            _replay_graph_capacity_failure(
                self.authority, retained, frozenset()
            ),
            {
                "kind": "TERMINAL_CANDIDATE_REJECTED",
                "primary": "CONTEXT_CAPACITY_EXHAUSTED",
                "stage": "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT",
            },
        )

    def test_logical_k_admission_is_independent_of_content_and_opening(self) -> None:
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        proposed, _ = self._replay_fixture()
        context = proposed["projection"]["context"]["contextIdentifierHex"]
        root = proposed["projection"]["rootCredentialIdentifierHex"]
        opening = "34" * 32
        content = b"bounded-content"

        def candidate(content_class: str, event_type: int) -> dict[str, str]:
            commitment = backend.encode_commitment(
                profile_id=1,
                profile_version=1,
                context=bytes.fromhex(context),
                credential=bytes.fromhex(root),
                sequence=0,
                content_type=1,
                content=content,
                randomizer=bytes.fromhex(opening),
                chunk_size=None,
            )
            transcript = backend.encode_event(
                self._application_fields(
                    contextIdentifierHex=context,
                    credentialIdentifierHex=root,
                    eventTypeId=event_type,
                    genesisReferenceHex=proposed["projection"][
                        "genesisReferenceHex"
                    ],
                    content={
                        "class": content_class,
                        "commitmentHex": commitment["commitmentHex"],
                        "contentType": 1,
                        "exactLength": len(content),
                        "geometryPredicateResults": {
                            f"geometryPredicate{index}": "NOT_APPLICABLE"
                            for index in range(1, 8)
                        },
                        "shape": "SINGLE",
                    },
                )
            )
            _, signature = backend.ed25519_sign(bytes(range(32)), transcript)
            return {
                "objectKind": "APPLICATION_EVENT",
                "signatureHex": signature.hex(),
                "transcriptHex": transcript.hex(),
            }

        base = {
            "proposedGenesis": proposed,
            "evidence": {"contentMaterial": [], "openingMaterial": []},
        }
        required = project_replay_state(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {**base, "candidates": [candidate("REQUIRED", 1)]},
        )
        self.assertIsInstance(required, ReplayProjection)
        self.assertEqual(len(required.pending_roots), 1)
        self.assertEqual(required.records[0]["replayReadiness"], "PENDING_OPENING")

        detachable_value = {**base, "candidates": [candidate("DETACHABLE", 2)]}
        detachable_closure = prepare_replay_closure(
            self.authority,
            dict(SUPPORTED_PROFILE),
            detachable_value,
        )
        self.assertIsInstance(detachable_closure, ReplayClosure)
        self.assertEqual(detachable_closure.k_observations[0]["kBindingAdmission"], "ADMITTED")
        detachable = project_replay_state(
            self.authority, dict(SUPPORTED_PROFILE), detachable_value
        )
        self.assertIsInstance(detachable, ReplayProjection)
        self.assertEqual(detachable.content_states[0]["localAvailability"], "ABSENT")
        self.assertEqual(detachable.content_states[0]["bindingObservation"], "NOT_CHECKED")
        self.assertEqual(detachable.records[0]["replayReadiness"], "READY_FOR_AP_FOLD")

        verified_detachable = candidate("DETACHABLE", 3)
        detachable_reference = backend.framed_hash(
            backend.DOMAINS["event_reference"],
            bytes.fromhex(verified_detachable["transcriptHex"]),
        ).hex()
        verified_evidence = {
            "contentMaterial": [
                {
                    "eventReferenceHex": detachable_reference,
                    "segments": [
                        {"offset": "0", "octetsHex": content.hex()}
                    ],
                }
            ],
            "openingMaterial": [
                {
                    "eventReferenceHex": detachable_reference,
                    "openingRandomizerHex": opening,
                }
            ],
        }
        verified = project_replay_state(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                **base,
                "candidates": [verified_detachable],
                "evidence": verified_evidence,
            },
        )
        self.assertIsInstance(verified, ReplayProjection)
        self.assertEqual(verified.content_states[0]["contentClass"], "DETACHABLE")
        self.assertEqual(verified.content_states[0]["bindingObservation"], "VERIFIED")

        mismatched_evidence = {
            **verified_evidence,
            "openingMaterial": [
                {
                    "eventReferenceHex": detachable_reference,
                    "openingRandomizerHex": "56" * 32,
                }
            ],
        }
        absent_same_candidate = prepare_replay_closure(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {**base, "candidates": [verified_detachable]},
        )
        mismatched_same_candidate = prepare_replay_closure(
            self.authority,
            dict(SUPPORTED_PROFILE),
            {
                **base,
                "candidates": [verified_detachable],
                "evidence": mismatched_evidence,
            },
        )
        self.assertIsInstance(absent_same_candidate, ReplayClosure)
        self.assertIsInstance(mismatched_same_candidate, ReplayClosure)
        self.assertEqual(
            mismatched_same_candidate.evidence,
            {"contentMaterial": [], "openingMaterial": []},
        )
        self.assertEqual(
            absent_same_candidate.k_observations,
            mismatched_same_candidate.k_observations,
        )

    def test_replay_candidate_order_is_derived_from_references(self) -> None:
        proposed, first = self._replay_fixture(event_type=1)
        _, second = self._replay_fixture(event_type=2)
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        candidates = [first, second]
        candidates.sort(
            key=lambda item: backend.framed_hash(
                backend.DOMAINS["event_reference"],
                bytes.fromhex(item["transcriptHex"]),
            ).hex()
        )
        reversed_value = {
            "proposedGenesis": proposed,
            "candidates": list(reversed(candidates)),
            "evidence": {"contentMaterial": [], "openingMaterial": []},
        }
        self.assertEqual(
            prepare_replay_closure(
                self.authority, dict(SUPPORTED_PROFILE), reversed_value
            ),
            {
                "kind": "TERMINAL_INPUT_REJECTED",
                "reason": "CANDIDATE_SET_NONCANONICAL",
                "stage": "CANDIDATE_SET_VALIDATION",
            },
        )

    def test_evidence_canonicalization_is_purpose_keyed_and_fail_closed(self) -> None:
        reference = "22" * 32
        descriptors = {
            reference: {"class": "REQUIRED", "exactLength": 4},
        }
        valid = {
            "contentMaterial": [
                {
                    "eventReferenceHex": reference,
                    "segments": [
                        {"offset": "0", "octetsHex": "aabb"},
                        {"offset": "2", "octetsHex": "ccdd"},
                    ],
                }
            ],
            "openingMaterial": [
                {
                    "eventReferenceHex": reference,
                    "openingRandomizerHex": "33" * 32,
                }
            ],
        }
        self.assertEqual(_canonicalize_evidence(valid, descriptors), valid)

        overlap = json.loads(json.dumps(valid))
        overlap["contentMaterial"][0]["segments"][1]["offset"] = "1"
        with self.assertRaisesRegex(EvidenceError, "PARTIAL_OVERLAP"):
            _canonicalize_evidence(overlap, descriptors)

        with self.assertRaisesRegex(EvidenceError, "UNKNOWN_EVENT_REFERENCE"):
            _canonicalize_evidence(valid, {})

        with self.assertRaisesRegex(EvidenceError, "NONCANONICAL_MATERIAL"):
            _canonicalize_evidence(
                valid, {reference: {"class": "NONE", "exactLength": 0}}
            )

    def test_verified_evidence_merge_has_no_partial_or_arrival_winner(self) -> None:
        reference = "44" * 32
        prior = {
            "contentMaterial": [
                {
                    "eventReferenceHex": reference,
                    "segments": [{"offset": "0", "octetsHex": "aabbccdd"}],
                }
            ],
            "openingMaterial": [
                {
                    "eventReferenceHex": reference,
                    "openingRandomizerHex": "55" * 32,
                }
            ],
        }
        duplicate = json.loads(json.dumps(prior))
        self.assertEqual(
            merge_verified_complete_evidence(prior, duplicate),
            (prior, False),
        )

        second_reference = "66" * 32
        addition = {
            "contentMaterial": [
                {
                    "eventReferenceHex": second_reference,
                    "segments": [{"offset": "0", "octetsHex": "eeff"}],
                }
            ],
            "openingMaterial": [
                {
                    "eventReferenceHex": second_reference,
                    "openingRandomizerHex": "77" * 32,
                }
            ],
        }
        merged, changed = merge_verified_complete_evidence(prior, addition)
        self.assertTrue(changed)
        self.assertEqual(
            [row["eventReferenceHex"] for row in merged["contentMaterial"]],
            [reference, second_reference],
        )

        conflicting = json.loads(json.dumps(prior))
        conflicting["contentMaterial"][0]["segments"][0]["octetsHex"] = "ffff"
        with self.assertRaisesRegex(EvidenceError, "PRIMITIVE_ASSUMPTION_FAILURE"):
            merge_verified_complete_evidence(prior, conflicting)

        unpaired = {"contentMaterial": prior["contentMaterial"], "openingMaterial": []}
        with self.assertRaisesRegex(EvidenceError, "NONCANONICAL_MATERIAL"):
            merge_verified_complete_evidence(
                {"contentMaterial": [], "openingMaterial": []}, unpaired
            )

    def test_content_and_event_projection_are_recomputed_from_raw_material(self) -> None:
        backend = _load_pinned_c03_model(str(self.authority.repo_root))
        reference = "77" * 32
        context = "11" * 32
        credential = "22" * 32
        opening = "33" * 32
        content = b"test"
        commitment = backend.encode_commitment(
            profile_id=1,
            profile_version=1,
            context=bytes.fromhex(context),
            credential=bytes.fromhex(credential),
            sequence=0,
            content_type=1,
            content=content,
            randomizer=bytes.fromhex(opening),
            chunk_size=None,
        )
        fields = self._application_fields(
            contextIdentifierHex=context,
            credentialIdentifierHex=credential,
            content={
                "class": "REQUIRED",
                "commitmentHex": commitment["commitmentHex"],
                "contentType": 1,
                "exactLength": len(content),
                "geometryPredicateResults": {
                    f"geometryPredicate{index}": "NOT_APPLICABLE"
                    for index in range(1, 8)
                },
                "shape": "SINGLE",
            },
        )
        candidate = ReplayCandidate(
            candidate={
                "objectKind": "APPLICATION_EVENT",
                "signatureHex": "",
                "transcriptHex": "",
            },
            reference_hex=reference,
            transcript=b"",
            fields=fields,
        )
        complete = {
            "contentMaterial": [
                {
                    "eventReferenceHex": reference,
                    "segments": [
                        {"offset": "0", "octetsHex": content.hex()}
                    ],
                }
            ],
            "openingMaterial": [
                {
                    "eventReferenceHex": reference,
                    "openingRandomizerHex": opening,
                }
            ],
        }
        verified = _reduce_complete_evidence_attempts(
            self.authority, (candidate,), complete
        )
        self.assertEqual(verified, complete)
        states, roots = _project_content_states(self.authority, (candidate,), verified)
        self.assertEqual(roots, frozenset())
        self.assertEqual(states[0]["bindingObservation"], "VERIFIED")
        self.assertEqual(states[0]["replayReadiness"], "READY")

        missing_opening = {**complete, "openingMaterial": []}
        reduced_missing = _reduce_complete_evidence_attempts(
            self.authority, (candidate,), missing_opening
        )
        self.assertEqual(
            reduced_missing, {"contentMaterial": [], "openingMaterial": []}
        )
        pending_states, roots = _project_content_states(
            self.authority, (candidate,), reduced_missing
        )
        self.assertEqual(roots, frozenset({reference}))
        self.assertEqual(pending_states[0]["bindingObservation"], "NOT_CHECKED")
        self.assertEqual(
            pending_states[0]["replayReadiness"], "CONTENT_DEFERRED"
        )

        mismatched = {
            **complete,
            "openingMaterial": [
                {
                    "eventReferenceHex": reference,
                    "openingRandomizerHex": "44" * 32,
                }
            ],
        }
        self.assertEqual(
            _reduce_complete_evidence_attempts(
                self.authority, (candidate,), mismatched
            ),
            {"contentMaterial": [], "openingMaterial": []},
        )

        projected = _event_projection(
            candidate,
            fork_references=frozenset(),
            pending_references=frozenset({reference}),
            pending_roots=frozenset({reference}),
        )
        self.assertEqual(projected["eventReferenceHex"], reference)
        self.assertEqual(projected["contentDescriptor"]["commitmentShape"], "SINGLE")
        self.assertEqual(projected["replayReadiness"], "PENDING_OPENING")

    def test_projection_foundations_derive_forks_pending_and_grant_bindings(self) -> None:
        proposed, _ = self._replay_fixture()
        root = proposed["projection"]["rootCredentialIdentifierHex"]
        first_fields = self._application_fields(
            credentialIdentifierHex=root,
            contextIdentifierHex=proposed["projection"]["context"][
                "contextIdentifierHex"
            ],
            genesisReferenceHex=proposed["projection"]["genesisReferenceHex"],
        )
        second_fields = dict(first_fields)
        first = ReplayCandidate(
            {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
            "88" * 32,
            b"",
            first_fields,
        )
        second = ReplayCandidate(
            {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
            "99" * 32,
            b"",
            second_fields,
        )
        forks, fork_references = _fork_slots(self.authority, (first, second))
        self.assertEqual(len(forks), 1)
        self.assertEqual(fork_references, frozenset({"88" * 32, "99" * 32}))

        child_fields = self._application_fields(
            authorSequence=1,
            causalParents=[],
            credentialIdentifierHex=root,
            contextIdentifierHex=first_fields["contextIdentifierHex"],
            directPredecessorHex=first.reference_hex,
            genesisReferenceHex=first_fields["genesisReferenceHex"],
        )
        child = ReplayCandidate(
            {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
            "aa" * 32,
            b"",
            child_fields,
        )
        roots, descendants = _pending_sets(
            (first, child), frozenset({first.reference_hex})
        )
        self.assertEqual(roots, frozenset({first.reference_hex}))
        self.assertEqual(descendants, frozenset({child.reference_hex}))

        nested_roots, nested_descendants = _pending_sets(
            (first, child),
            frozenset({first.reference_hex, child.reference_hex}),
        )
        self.assertEqual(nested_roots, frozenset({first.reference_hex}))
        self.assertEqual(nested_descendants, frozenset({child.reference_hex}))

        grant_fields = self._application_fields(
            credentialIdentifierHex=root,
            contextIdentifierHex=first_fields["contextIdentifierHex"],
            eventRole="CREDENTIAL",
            genesisReferenceHex=first_fields["genesisReferenceHex"],
            tail={"kind": "GRANT", "granteeVerificationKeyHex": "ab" * 32},
        )
        grant = ReplayCandidate(
            {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
            "bb" * 32,
            b"",
            grant_fields,
        )
        bindings, aliases, lineage = _credential_projection(
            self.authority, proposed, (grant,)
        )
        self.assertEqual(len(bindings), 2)
        self.assertEqual(bindings[1]["origin"], "GRANT")
        self.assertEqual(bindings[1]["issuerCredentialIdentifierHex"], root)
        self.assertEqual(aliases, [])
        self.assertEqual(lineage[grant.reference_hex][0], root)

        child_grant_fields = self._application_fields(
            credentialIdentifierHex=grant.reference_hex,
            contextIdentifierHex=first_fields["contextIdentifierHex"],
            eventRole="CREDENTIAL",
            genesisReferenceHex=first_fields["genesisReferenceHex"],
            tail={"kind": "GRANT", "granteeVerificationKeyHex": "cd" * 32},
        )
        child_grant = ReplayCandidate(
            {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
            "aa" * 32,
            b"",
            child_grant_fields,
        )
        # The child reference sorts before its issuer grant. Binding derivation
        # must follow issuer closure, never presentation/reference order.
        nested_bindings, _, nested_lineage = _credential_projection(
            self.authority, proposed, (child_grant, grant)
        )
        self.assertEqual(len(nested_bindings), 3)
        self.assertEqual(
            nested_lineage[child_grant.reference_hex][0], grant.reference_hex
        )

    def test_fork_join_projection_uses_the_exact_v9_preimage(self) -> None:
        credential = "11" * 32
        first = ReplayCandidate(
            {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
            "22" * 32,
            b"",
            self._application_fields(credentialIdentifierHex=credential, authorSequence=7),
        )
        second = ReplayCandidate(
            {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
            "33" * 32,
            b"",
            self._application_fields(credentialIdentifierHex=credential, authorSequence=7),
        )
        rows = _fork_join_projection(
            self.authority,
            {(credential, 7): (first.reference_hex, second.reference_hex)},
            {credential: (None, credential)},
            (first, second),
        )
        self.assertEqual(
            rows,
            (
                {
                    "authorSequence": "7",
                    "credentialIdentifierHex": credential,
                    "joinLabelHex": "6c0e9469f72779ab48f96a90a76f088c23ec88674a3290a19baef8418c49c073",
                    "lineageClosureCredentialIdentifiers": [credential],
                    "siblingReferences": [first.reference_hex, second.reference_hex],
                },
            ),
        )

    def test_protocol_k_order_recomputes_ready_set_after_every_record(self) -> None:
        fields = self._application_fields()
        ancestor = ReplayCandidate(
            {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
            "20" * 32,
            b"",
            fields,
        )
        concurrent = ReplayCandidate(
            {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
            "30" * 32,
            b"",
            fields,
        )
        descendant_fields = self._application_fields(
            causalParents=[ancestor.reference_hex]
        )
        descendant = ReplayCandidate(
            {"objectKind": "APPLICATION_EVENT", "signatureHex": "", "transcriptHex": ""},
            "10" * 32,
            b"",
            descendant_fields,
        )
        self.assertEqual(
            [
                candidate.reference_hex
                for candidate in _protocol_k_order(
                    (descendant, ancestor, concurrent)
                )
            ],
            [
                ancestor.reference_hex,
                descendant.reference_hex,
                concurrent.reference_hex,
            ],
        )

    def test_independent_javascript_adapter_rejects_all_acv066_positions(self) -> None:
        completed = subprocess.run(
            [
                "node",
                str(ROOT / "node_adapter.mjs"),
                "--self-test-acv066",
                "--contract",
                str(ROOT / "contract"),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        self.assertEqual(
            json.loads(completed.stdout),
            {
                "mutantAccepted": 7,
                "normalRejected": 7,
                "relationAccepted": 7,
                "verdict": "PASS",
            },
        )
        self.assertEqual(completed.stderr, "")

    def test_native_reference_mismatches_have_external_expected_sources(self) -> None:
        sources = {
            path: (REPO / path).read_text(encoding="utf-8")
            for path in (
                "tools/causal-flow-simulator/c03/corpus_model.py",
                "tools/causal-flow-simulator/c03/node_adapter.mjs",
                "tools/causal-flow-simulator/o07/genesis_model.py",
                "tools/causal-flow-simulator/o07/node_adapter.mjs",
            )
        }
        c03_python = sources["tools/causal-flow-simulator/c03/corpus_model.py"]
        self.assertIn('expected_reference = record["genesisReferenceHex"]', c03_python)
        self.assertIn('expected_reference = record["eventReferenceHex"]', c03_python)
        self.assertIn("if reference != expected_reference:", c03_python)

        c03_javascript = sources["tools/causal-flow-simulator/c03/node_adapter.mjs"]
        self.assertIn("expected = record.genesisReferenceHex", c03_javascript)
        self.assertIn("expected = record.eventReferenceHex", c03_javascript)
        self.assertIn("if (reference !== expected)", c03_javascript)

        o07_python = sources["tools/causal-flow-simulator/o07/genesis_model.py"]
        self.assertIn(
            "if reference != ceremony.expected_genesis_reference:", o07_python
        )
        self.assertIn(
            "if genesis_reference != state.genesis_reference:", o07_python
        )
        self.assertIn(
            "if field16_reference != projection.genesis_reference:", o07_python
        )

        o07_javascript = sources["tools/causal-flow-simulator/o07/node_adapter.mjs"]
        self.assertIn("function makeHarness(context, expectedReference", o07_javascript)
        self.assertIn(
            "if (!derived.equals(ceremony.expectedReference))", o07_javascript
        )


if __name__ == "__main__":
    unittest.main()
