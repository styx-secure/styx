import json
import os
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SCHEMA_DIR = os.path.join(_REPO_ROOT, "docs", "governance", "schemas")
FILES = [
    "restricted-broker-request-v1.schema.json",
    "restricted-broker-response-v1.schema.json",
    "restricted-broker-audit-v1.schema.json",
]


class TestSchemas(unittest.TestCase):
    def test_schema_files_are_valid_json_closed_and_versioned(self):
        for name in FILES:
            with open(os.path.join(SCHEMA_DIR, name), "rb") as handle:
                doc = json.load(handle)
            self.assertIs(doc["additionalProperties"], False)
            self.assertIn("$schema", doc)
            self.assertTrue(doc["properties"]["schema"]["const"].startswith("styx.restricted-broker-"))
            self.assertIn("required", doc)


if __name__ == "__main__":
    unittest.main()
