from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from derive_interface_maxima import Derivation  # noqa: E402


class InterfaceMaximaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.derivation = Derivation()
        self.report = self.derivation.report()

    def test_exact_maxima_and_maximizing_roots(self) -> None:
        self.assertEqual(self.report["outerRequestOctets"], 138499357)
        self.assertEqual(self.report["outerRequestRoot"], "REQUEST-EVALUATE_CANDIDATE")
        self.assertEqual(self.report["outerResponseOctets"], 71052634)
        self.assertEqual(self.report["outerResponseRoot"], "RESPONSE-EVALUATE_CANDIDATE")
        self.assertEqual(self.report["maxRetainedDecodedOctets"], 35284168)
        self.assertEqual(self.report["maxRetainedDecodedRoot"], "REQUEST-EVALUATE_CANDIDATE")

    def test_all_twelve_carrier_roots_are_measured_once(self) -> None:
        rows = self.report["rootMeasurements"]
        root_ids = [row["rootId"] for row in rows]
        self.assertEqual(len(root_ids), 12)
        self.assertEqual(len(set(root_ids)), 12)
        self.assertEqual(root_ids, sorted(root_ids))

    def test_all_twenty_seven_concrete_array_uses_are_bounded(self) -> None:
        self.assertEqual(len(self.derivation.array_bounds), 27)
        self.assertEqual(
            self.derivation.array_bounds["$defs.ContextProjectionV0.aliasGroups"],
            64,
        )
        self.assertEqual(
            self.derivation.array_bounds["$defs.ApplicationEventProjectionV0.causalParentReferences"],
            8,
        )

    def test_content_retention_uses_exact_content_not_segment_product(self) -> None:
        segments = self.derivation._content_segments()
        self.assertEqual(segments.json_octets, 526518)
        self.assertEqual(segments.decoded_octets, 262144)
        self.assertLess(
            segments.decoded_octets,
            self.derivation.limits["CHUNKS_PER_CONTENT"]
            * self.derivation.limits["CHUNK_OCTETS"],
        )

    def test_candidate_repeat_increases_wire_not_retained_material(self) -> None:
        row = next(
            item
            for item in self.report["rootMeasurements"]
            if item["rootId"] == "REQUEST-EVALUATE_CANDIDATE"
        )
        self.assertGreater(
            row["representedDecodedOctets"], row["retainedDecodedOctets"]
        )

    def test_cli_is_canonical_and_byte_stable(self) -> None:
        command = [sys.executable, str(ROOT / "derive_interface_maxima.py")]
        first = subprocess.run(command, check=True, stdout=subprocess.PIPE).stdout
        second = subprocess.run(command, check=True, stdout=subprocess.PIPE).stdout
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        self.assertEqual(json.loads(first), self.report)


if __name__ == "__main__":
    unittest.main()
