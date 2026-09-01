from __future__ import annotations

import sys
from io import BytesIO
import json
import subprocess
import unittest
from pathlib import Path

from jsonschema.validators import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
sys.path.insert(0, str(ROOT))

from interface_model import (  # noqa: E402
    ContractAuthority,
    HarnessFailure,
    RequestRejected,
    SUPPORTED_OPERATIONS,
    SUPPORTED_PROFILE,
    _validate_response_shape_and_relation,
    admit_canonical_request,
    describe_profile,
    read_bounded_request,
    validate_response_before_release,
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
        self.assertEqual(len(descriptor["interfaceLimits"]), 22)
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
        transcript = {
            "interfaceVersion": "0",
            "operation": "VALIDATE_TRANSCRIPT",
            "profile": dict(SUPPORTED_PROFILE),
            "result": {
                "kind": "REJECTED",
                "reason": "REFERENCE_MISMATCH",
                "stage": "REFERENCE_DERIVATION",
                "observations": self._reference_observations(),
            },
        }
        genesis = {
            "interfaceVersion": "0",
            "operation": "EVALUATE_GENESIS",
            "profile": dict(SUPPORTED_PROFILE),
            "result": {
                "kind": "TERMINAL_NO_PROPOSAL",
                "reason": "REFERENCE_MISMATCH",
                "stage": "REFERENCE_DERIVATION",
            },
        }
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
        for response in (transcript, genesis, observation):
            # This is the exact ACV-066 source mutant: schema and relation
            # validation remain active, while only reserved reachability is
            # removed.  The row-coherent response must therefore be admitted.
            _validate_response_shape_and_relation(self.authority, response)
            with self.assertRaisesRegex(HarnessFailure, "reserved reference"):
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
                "mutantAccepted": 3,
                "normalRejected": 3,
                "relationAccepted": 3,
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
