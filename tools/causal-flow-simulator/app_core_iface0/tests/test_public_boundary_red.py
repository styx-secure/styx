from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generate_seed_registry import _semantic_request_carriers  # noqa: E402
from interface_model import (  # noqa: E402
    ContractAuthority,
    RequestRejected,
    evaluate_interface_request,
)


class PublicBoundaryRedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        cls.requests = [copy.deepcopy(case.request) for case in _semantic_request_carriers(cls.authority)]

    def request_for(self, operation: str) -> dict:
        return copy.deepcopy(next(row for row in self.requests if row["operation"] == operation))

    def assert_defined_rejection(self, request: dict) -> None:
        with self.assertRaises(RequestRejected):
            evaluate_interface_request(self.authority, request)

    def test_non_string_container_operation_is_defined_rejection(self) -> None:
        for operation in ([], {}):
            with self.subTest(operation=operation):
                request = self.request_for("DESCRIBE_PROFILE")
                request["operation"] = operation
                self.assert_defined_rejection(request)

    def test_5000_digit_decimal_is_defined_rejection(self) -> None:
        request = self.request_for("DESCRIBE_PROFILE")
        request["profile"]["applicationProfileId"] = "9" * 5000
        self.assert_defined_rejection(request)

    def test_reference_mismatch_is_defined_rejection(self) -> None:
        for operation in ("VALIDATE_TRANSCRIPT", "EVALUATE_GENESIS"):
            for field in ("carriedReferenceHex", "logicalReferenceHex"):
                with self.subTest(operation=operation, field=field):
                    request = self.request_for(operation)
                    candidate = request["input"]["candidate"]
                    if field == "carriedReferenceHex":
                        candidate[field] = "00" * 32
                    else:
                        logical_field = (
                            "genesisReferenceHex"
                            if operation == "EVALUATE_GENESIS"
                            else "eventReferenceHex"
                        )
                        candidate["logicalEvent"][logical_field] = "00" * 32
                    self.assert_defined_rejection(request)

    def test_63_byte_signature_is_defined_rejection(self) -> None:
        for octets in (0, 63, 65):
            with self.subTest(octets=octets):
                request = self.request_for("EVALUATE_CANDIDATE")
                request["input"]["candidate"]["proofs"][0]["signatureHex"] = "00" * octets
                self.assert_defined_rejection(request)

        request = self.request_for("EVALUATE_CANDIDATE")
        request["input"]["candidate"]["proofs"][0]["signatureHex"] = "00" * 64
        try:
            evaluate_interface_request(self.authority, request)
        except RequestRejected as error:  # pragma: no cover - assertion detail
            self.fail(f"64-byte signature was rejected: {error}")

    def test_content_equivalent_split_prior_revalidates(self) -> None:
        request = copy.deepcopy(
            next(
                row
                for row in self.requests
                if row["operation"] == "EVALUATE_EVIDENCE_UPDATE"
                and row["input"]["prior"]["localRevalidation"]["evidence"][
                    "verifiedComplete"
                ]
            )
        )
        row = request["input"]["prior"]["localRevalidation"]["evidence"][
            "verifiedComplete"
        ][0]["contentMaterial"]["segments"][0]
        octets = row["octetsHex"]
        cut = 2 * max(1, len(octets) // 4)
        request["input"]["prior"]["localRevalidation"]["evidence"][
            "verifiedComplete"
        ][0]["contentMaterial"]["segments"] = [
            {"offset": row["offset"], "octetsHex": octets[:cut]},
            {
                "offset": str(int(row["offset"]) + cut // 2),
                "octetsHex": octets[cut:],
            },
        ]

        result = evaluate_interface_request(self.authority, request)["result"]

        self.assertNotEqual(
            result.get("evaluation", {}).get("reason"),
            "PRIOR_REVALIDATION_FAILED",
        )


if __name__ == "__main__":
    unittest.main()
