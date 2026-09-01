from __future__ import annotations

import sys
from io import BytesIO
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
    admit_canonical_request,
    describe_profile,
    read_bounded_request,
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


if __name__ == "__main__":
    unittest.main()
