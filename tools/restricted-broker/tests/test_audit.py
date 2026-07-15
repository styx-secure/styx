import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit  # noqa: E402


def _event(**over):
    base = dict(
        request_sha256="a" * 64,
        execution_id="issue-53",
        issue_number=53,
        operation="push_task_branch",
        idempotency_key="k",
        evidence_hashes={
            "scope_report_sha256": "1" * 64,
            "runner_status_sha256": "2" * 64,
            "hook_attestation_sha256": "3" * 64,
        },
        decision="SUCCESS",
        derived={"repository": "styx-secure/styx"},
        outcome={"ok": True},
    )
    base.update(over)
    return audit.AuditEvent(**base)


class TestAudit(unittest.TestCase):
    def test_append_assigns_monotonic_sequence(self):
        sink = audit.InMemoryAuditSink()
        r0 = sink.append(_event())
        r1 = sink.append(_event())
        self.assertEqual((r0.sequence, r1.sequence), (0, 1))

    def test_audit_id_is_deterministic_hash(self):
        sink = audit.InMemoryAuditSink()
        r = sink.append(_event())
        self.assertRegex(r.audit_id, r"^[0-9a-f]{64}$")

    def test_records_are_append_only_snapshot(self):
        sink = audit.InMemoryAuditSink()
        sink.append(_event())
        records = sink.records
        records.clear()  # external mutation must not affect the sink
        self.assertEqual(len(sink.records), 1)

    def test_null_identifiers_allowed_for_early_denial(self):
        sink = audit.InMemoryAuditSink()
        r = sink.append(
            _event(
                execution_id=None,
                issue_number=None,
                operation=None,
                idempotency_key=None,
                evidence_hashes=None,
                derived=None,
                decision="DENIED_EVIDENCE",
                outcome={"reason": "malformed"},
            )
        )
        j = r.to_json()
        self.assertIsNone(j["execution_id"])
        self.assertIsNone(j["evidence_hashes"])
        self.assertEqual(j["request_sha256"], "a" * 64)
        self.assertEqual(j["schema"], "styx.restricted-broker-audit/v1")

    def test_sanitize_redacts_tokens(self):
        redacted = audit.sanitize("token ghp_abcdefghijklmnopqrstuvwx0123456789")
        self.assertNotIn("ghp_", redacted)
        self.assertIn("[redacted]", redacted)

    def test_outcome_is_sanitized_in_record(self):
        sink = audit.InMemoryAuditSink()
        r = sink.append(_event(outcome={"reason": "leak ghp_abcdefghijklmnopqrstuvwx01"}))
        self.assertNotIn("ghp_", r.to_json()["outcome"]["reason"])


if __name__ == "__main__":
    unittest.main()
