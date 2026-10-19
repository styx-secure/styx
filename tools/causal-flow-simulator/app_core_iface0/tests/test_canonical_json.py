from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from canonical_json import CanonicalJsonError, dumps, loads


class CanonicalJsonTests(unittest.TestCase):
    def test_round_trip_is_sorted_and_lf_terminated(self) -> None:
        payload = dumps({"z": [2, 1], "a": "é"})
        self.assertEqual(payload, b'{"a":"\xc3\xa9","z":[2,1]}\n')
        self.assertEqual(loads(payload), {"a": "é", "z": [2, 1]})

    def test_duplicate_bom_float_and_noncanonical_bytes_fail(self) -> None:
        invalid = (
            b'{"a":1,"a":2}\n',
            b"\xef\xbb\xbf{}\n",
            b'{"a":1.0}\n',
            b'{"b":1, "a":2}\n',
            b"{}",
            b"{}\n\n",
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(CanonicalJsonError):
                    loads(payload)


if __name__ == "__main__":
    unittest.main()

