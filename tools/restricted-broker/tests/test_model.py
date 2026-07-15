import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import model  # noqa: E402
from model import EvidenceError  # noqa: E402


def _valid_obj(operation="push_task_branch"):
    return {
        "schema": "styx.restricted-broker-request/v1",
        "operation": operation,
        "issue_number": 53,
        "execution_id": "issue-53",
        "idempotency_key": "k1",
        "evidence": {
            "scope_report": {"a": 1},
            "runner_status": {"b": 2},
            "hook_attestation": {"c": 3},
        },
    }


class TestBuildRequest(unittest.TestCase):
    def test_builds_valid_request_and_keeps_operation_string(self):
        req = model.build_request(_valid_obj("anything-goes-structurally"))
        self.assertEqual(req.operation, "anything-goes-structurally")
        self.assertEqual(req.issue_number, 53)
        self.assertEqual(req.evidence.scope_report, b'{"a":1}\n')

    def test_rejects_unknown_top_level_field(self):
        obj = _valid_obj()
        obj["extra"] = 1
        with self.assertRaises(EvidenceError):
            model.build_request(obj)

    def test_rejects_missing_field(self):
        obj = _valid_obj()
        del obj["execution_id"]
        with self.assertRaises(EvidenceError):
            model.build_request(obj)

    def test_rejects_unknown_evidence_field(self):
        obj = _valid_obj()
        obj["evidence"]["surprise"] = {}
        with self.assertRaises(EvidenceError):
            model.build_request(obj)

    def test_rejects_wrong_schema_const(self):
        obj = _valid_obj()
        obj["schema"] = "wrong"
        with self.assertRaises(EvidenceError):
            model.build_request(obj)

    def test_rejects_non_int_issue_number(self):
        obj = _valid_obj()
        obj["issue_number"] = "53"
        with self.assertRaises(EvidenceError):
            model.build_request(obj)

    def test_rejects_bool_issue_number(self):
        obj = _valid_obj()
        obj["issue_number"] = True
        with self.assertRaises(EvidenceError):
            model.build_request(obj)


if __name__ == "__main__":
    unittest.main()
