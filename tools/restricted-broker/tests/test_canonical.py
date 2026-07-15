import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canonical  # noqa: E402


class TestCanonical(unittest.TestCase):
    def test_canonical_bytes_are_sorted_compact_lf_terminated(self):
        self.assertEqual(canonical.canonical_bytes({"b": 1, "a": 2}), b'{"a":2,"b":1}\n')

    def test_sha256_hex_known_vector(self):
        self.assertEqual(
            canonical.sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_canonical_sha256_is_hash_of_canonical_bytes(self):
        value = {"x": [1, 2], "y": "à"}
        self.assertEqual(
            canonical.canonical_sha256(value),
            canonical.sha256_hex(canonical.canonical_bytes(value)),
        )

    def test_non_ascii_preserved(self):
        self.assertEqual(canonical.canonical_bytes({"k": "à"}), '{"k":"à"}\n'.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
