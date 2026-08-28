from __future__ import annotations

import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from canonical_json import CanonicalJsonError, dumps, loads  # noqa: E402


class CanonicalJsonTests(unittest.TestCase):
    def test_round_trip_is_sorted_and_has_one_final_lf(self) -> None:
        encoded = dumps({"z": [1, True, None], "a": "value"})
        self.assertEqual(encoded, b'{"a":"value","z":[1,true,null]}\n')
        self.assertEqual(loads(encoded), {"a": "value", "z": [1, True, None]})

    def test_rejects_duplicate_keys_float_bom_and_noncanonical_spacing(self) -> None:
        invalid = (
            b'{"a":1,"a":2}\n',
            b'{"a":1.5}\n',
            b'\xef\xbb\xbf{"a":1}\n',
            b'{"a": 1}\n',
            b'{"a":1}\n\n',
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(CanonicalJsonError):
                loads(value)


if __name__ == "__main__":
    unittest.main()
