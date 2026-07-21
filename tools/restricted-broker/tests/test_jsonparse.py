import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jsonparse  # noqa: E402
from model import EvidenceError  # noqa: E402


class TestJsonParse(unittest.TestCase):
    def test_parses_object(self):
        self.assertEqual(jsonparse.load_object(b'{"a":1}'), {"a": 1})

    def test_rejects_duplicate_keys(self):
        with self.assertRaises(EvidenceError):
            jsonparse.load_object(b'{"a":1,"a":2}')

    def test_rejects_nested_duplicate_keys(self):
        with self.assertRaises(EvidenceError):
            jsonparse.load_object(b'{"x":{"a":1,"a":2}}')

    def test_rejects_non_object_root(self):
        for raw in (b"[1,2]", b'"s"', b"5", b"null"):
            with self.assertRaises(EvidenceError):
                jsonparse.load_object(raw)

    def test_rejects_malformed_json(self):
        with self.assertRaises(EvidenceError):
            jsonparse.load_object(b"{not json}")


if __name__ == "__main__":
    unittest.main()
