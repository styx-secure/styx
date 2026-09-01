from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
sys.path.insert(0, str(ROOT))

from interface_model import (  # noqa: E402
    ContractAuthority,
    SUPPORTED_OPERATIONS,
    SUPPORTED_PROFILE,
    describe_profile,
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


if __name__ == "__main__":
    unittest.main()
