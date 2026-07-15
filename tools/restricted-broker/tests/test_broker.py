import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit  # noqa: E402
import broker  # noqa: E402
import fake_github  # noqa: E402
import idempotency  # noqa: E402
import model  # noqa: E402
import repository  # noqa: E402
import support  # noqa: E402


def _raw(operation="push_task_branch", **over):
    evidence = {
        "scope_report": support.make_scope_report(),
        "runner_status": support.make_runner_status(),
        "hook_attestation": support.make_attestation(),
    }
    obj = {
        "schema": "styx.restricted-broker-request/v1",
        "operation": operation,
        "issue_number": 53,
        "execution_id": "issue-53",
        "idempotency_key": "k1",
        "evidence": evidence,
    }
    obj.update(over)
    return json.dumps(obj).encode("utf-8")


def _good_state():
    return repository.RepoState(
        repository="styx-secure/styx",
        worktree=support.WORKTREE,
        branch=support.BRANCH,
        head_sha=support.HEAD_SHA,
        base_is_ancestor=True,
        clean=True,
        changed_paths=tuple(support.CHANGED),
        symlink_paths=(),
    )


def _broker(inspector=None, client=None):
    return broker.RestrictedBroker(
        fake_client=client or fake_github.FakeGitHubClient(),
        idempotency_store=idempotency.InMemoryIdempotencyStore(),
        audit_sink=audit.InMemoryAuditSink(),
        repository_inspector=inspector or repository.FakeRepositoryInspector(_good_state()),
    )


class _CountingClient(fake_github.FakeGitHubClient):
    def __init__(self, calls, fail_with=None):
        super().__init__(fail_with=fail_with)
        self._calls = calls

    def publish_task_branch(self, target):
        self._calls.append("push")
        return super().publish_task_branch(target)

    def create_draft_pr(self, target):
        self._calls.append("pr")
        return super().create_draft_pr(target)


class TestBroker(unittest.TestCase):
    def test_push_success(self):
        b = _broker()
        resp = b.execute(_raw("push_task_branch"))
        self.assertEqual(resp["result"], "SUCCESS")
        self.assertFalse(resp["replayed"])
        self.assertEqual(resp["operation"], "push_task_branch")
        self.assertRegex(resp["audit_id"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(b._audit_sink.records), 1)

    def test_open_draft_pr_success(self):
        resp = _broker().execute(_raw("open_draft_pr"))
        self.assertEqual(resp["result"], "SUCCESS")
        self.assertTrue(resp["outcome"]["draft"])

    def test_unknown_operation_is_denied_policy(self):
        resp = _broker().execute(_raw("delete_branch"))
        self.assertEqual(resp["result"], "DENIED_POLICY")

    def test_malformed_json_denied_with_null_identifiers(self):
        b = _broker()
        resp = b.execute(b"{not json}")
        self.assertEqual(resp["result"], "DENIED_EVIDENCE")
        rec = b._audit_sink.records[0].to_json()
        self.assertIsNone(rec["execution_id"])
        self.assertIsNone(rec["evidence_hashes"])
        self.assertIsNone(rec["operation"])
        self.assertRegex(rec["request_sha256"], r"^[0-9a-f]{64}$")

    def test_duplicate_key_request_denied_and_audited(self):
        b = _broker()
        resp = b.execute(b'{"a":1,"a":2}')
        self.assertEqual(resp["result"], "DENIED_EVIDENCE")
        self.assertEqual(len(b._audit_sink.records), 1)

    def test_identical_replay_no_new_fake_call_new_audit(self):
        calls = []
        b = broker.RestrictedBroker(
            fake_client=_CountingClient(calls),
            idempotency_store=idempotency.InMemoryIdempotencyStore(),
            audit_sink=audit.InMemoryAuditSink(),
            repository_inspector=repository.FakeRepositoryInspector(_good_state()),
        )
        r1 = b.execute(_raw("push_task_branch"))
        r2 = b.execute(_raw("push_task_branch"))
        self.assertEqual(len(calls), 1)  # no new fake call on replay
        self.assertTrue(r2["replayed"])
        self.assertEqual(r1["outcome"], r2["outcome"])  # same application outcome
        self.assertEqual(len(b._audit_sink.records), 2)  # new audit record
        self.assertNotEqual(r1["audit_id"], r2["audit_id"])  # new audit_id

    def test_conflicting_key_denied(self):
        b = _broker()
        b.execute(_raw("push_task_branch", idempotency_key="dup"))
        resp = b.execute(_raw("open_draft_pr", idempotency_key="dup"))
        self.assertEqual(resp["result"], "CONFLICT_IDEMPOTENT")

    def test_head_change_between_validations_blocks_fake_call(self):
        calls = []
        moved = repository.RepoState(**{**_good_state().__dict__, "head_sha": "0" * 40})
        b = broker.RestrictedBroker(
            fake_client=_CountingClient(calls),
            idempotency_store=idempotency.InMemoryIdempotencyStore(),
            audit_sink=audit.InMemoryAuditSink(),
            repository_inspector=repository.FakeRepositoryInspector(moved),
        )
        resp = b.execute(_raw("push_task_branch"))
        self.assertEqual(resp["result"], "DENIED_EVIDENCE")
        self.assertEqual(len(calls), 0)  # fake client NOT called

    def test_between_validations_seam_blocks_fake_call(self):
        calls = []
        b = broker.RestrictedBroker(
            fake_client=_CountingClient(calls),
            idempotency_store=idempotency.InMemoryIdempotencyStore(),
            audit_sink=audit.InMemoryAuditSink(),
            repository_inspector=repository.FakeRepositoryInspector(_good_state()),
        )

        def seam():
            b._repository_inspector = repository.FakeRepositoryInspector(
                repository.RepoState(**{**_good_state().__dict__, "branch": "task/53-moved"})
            )

        resp = b.execute(_raw("push_task_branch"), _between_validations=seam)
        self.assertEqual(resp["result"], "DENIED_EVIDENCE")
        self.assertEqual(len(calls), 0)

    def test_remote_failure_sanitized(self):
        client = fake_github.FakeGitHubClient(
            fail_with=model.RemoteFailure("ghp_aaaaaaaaaaaaaaaaaaaaaaaa leaked")
        )
        resp = _broker(client=client).execute(_raw("push_task_branch"))
        self.assertEqual(resp["result"], "REMOTE_FAILURE")
        self.assertNotIn("ghp_", json.dumps(resp))

    def test_auth_unavailable_mapped(self):
        client = fake_github.FakeGitHubClient(fail_with=model.AuthUnavailable("no auth"))
        resp = _broker(client=client).execute(_raw("open_draft_pr"))
        self.assertEqual(resp["result"], "AUTH_UNAVAILABLE")

    def test_response_is_closed_shape(self):
        resp = _broker().execute(_raw("push_task_branch"))
        self.assertEqual(
            set(resp),
            {"schema", "result", "operation", "idempotency_key", "replayed", "audit_id", "outcome"},
        )

    def test_request_issue_number_bound_to_evidence(self):
        resp = _broker().execute(_raw("push_task_branch", issue_number=99))
        self.assertEqual(resp["result"], "DENIED_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
