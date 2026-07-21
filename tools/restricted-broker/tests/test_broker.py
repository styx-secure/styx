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


def _raw(operation="push_task_branch", runner=None, **over):
    evidence = {
        "scope_report": support.make_scope_report(),
        "runner_status": runner if runner is not None else support.make_runner_status(),
        "hook_attestation": support.make_attestation(
            runner_status=runner if runner is not None else support.make_runner_status()
        ),
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


def _good_state(**over):
    base = dict(
        repository="styx-secure/styx",
        worktree=support.WORKTREE,
        branch=support.BRANCH,
        head_sha=support.HEAD_SHA,
        base_sha=support.BASE_SHA,
        base_is_ancestor=True,
        clean=True,
        changed_paths=tuple(support.CHANGED),
        symlink_paths=(),
    )
    base.update(over)
    return repository.RepoState(**base)


def _broker(inspector=None, client=None, store=None, audit_sink=None):
    return broker.RestrictedBroker(
        fake_client=client or fake_github.FakeGitHubClient(),
        idempotency_store=store or idempotency.InMemoryIdempotencyStore(),
        audit_sink=audit_sink or audit.InMemoryAuditSink(),
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


class _FailingAuditSink(audit.AuditSink):
    def append(self, event):
        raise RuntimeError("append-only log unavailable")


class _NoneReturningAuditSink(audit.AuditSink):
    def append(self, event):
        return None  # contract violation: returns instead of raising


class _PendingStore(idempotency.IdempotencyStore):
    def begin(self, key, fingerprint):
        return idempotency.PENDING

    def abort(self, key):
        raise AssertionError("abort must not be called on PENDING")

    def complete(self, key, outcome):
        raise AssertionError("complete must not be called on PENDING")

    def recorded_outcome(self, key):
        raise AssertionError("recorded_outcome must not be called on PENDING")


class TestBroker(unittest.TestCase):
    # --- baseline behavior ---
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
        self.assertEqual(_broker().execute(_raw("delete_branch"))["result"], "DENIED_POLICY")

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

    def test_conflicting_key_denied(self):
        b = _broker()
        b.execute(_raw("push_task_branch", idempotency_key="dup"))
        resp = b.execute(_raw("open_draft_pr", idempotency_key="dup"))
        self.assertEqual(resp["result"], "CONFLICT_IDEMPOTENT")

    def test_response_is_closed_shape(self):
        resp = _broker().execute(_raw("push_task_branch"))
        self.assertEqual(
            set(resp),
            {"schema", "result", "operation", "idempotency_key", "replayed", "audit_id", "outcome"},
        )

    def test_request_issue_number_bound_to_evidence(self):
        self.assertEqual(_broker().execute(_raw("push_task_branch", issue_number=99))["result"], "DENIED_EVIDENCE")

    def test_auth_unavailable_mapped(self):
        client = fake_github.FakeGitHubClient(fail_with=model.AuthUnavailable("no auth"))
        self.assertEqual(_broker(client=client).execute(_raw("open_draft_pr"))["result"], "AUTH_UNAVAILABLE")

    # --- HIGH-1: idempotency reservation lifecycle ---
    def test_identical_replay_no_new_fake_call_new_audit(self):
        calls = []
        b = _broker(client=_CountingClient(calls))
        r1 = b.execute(_raw("push_task_branch"))
        r2 = b.execute(_raw("push_task_branch"))
        self.assertEqual(len(calls), 1)
        self.assertTrue(r2["replayed"])
        self.assertEqual(r1["outcome"], r2["outcome"])
        self.assertEqual(len(b._audit_sink.records), 2)
        self.assertNotEqual(r1["audit_id"], r2["audit_id"])

    def test_pre_call_failure_releases_key_for_retry(self):
        store = idempotency.InMemoryIdempotencyStore()
        calls = []
        # attempt 1: repository drift is a PRE-CALL failure -> reservation aborted
        drifted = _broker(
            inspector=repository.FakeRepositoryInspector(_good_state(head_sha="0" * 40)),
            client=_CountingClient(calls),
            store=store,
        )
        r1 = drifted.execute(_raw("push_task_branch"))
        self.assertEqual(r1["result"], "DENIED_EVIDENCE")
        self.assertEqual(len(calls), 0)
        # attempt 2: SAME key, healthy repo -> retryable, succeeds
        healthy = _broker(client=_CountingClient(calls), store=store)
        r2 = healthy.execute(_raw("push_task_branch"))
        self.assertEqual(r2["result"], "SUCCESS")
        self.assertFalse(r2["replayed"])
        self.assertEqual(len(calls), 1)

    def test_remote_failure_is_terminal_replay_without_new_call_or_keyerror(self):
        store = idempotency.InMemoryIdempotencyStore()
        calls = []
        failing = _broker(client=_CountingClient(calls, fail_with=model.RemoteFailure("transient")), store=store)
        r1 = failing.execute(_raw("push_task_branch"))
        self.assertEqual(r1["result"], "REMOTE_FAILURE")
        self.assertEqual(len(calls), 1)
        # retry with SAME key and a healthy client: no second call, recorded terminal returned
        healthy = _broker(client=_CountingClient(calls), store=store)
        r2 = healthy.execute(_raw("push_task_branch"))
        self.assertEqual(r2["result"], "REMOTE_FAILURE")
        self.assertTrue(r2["replayed"])
        self.assertEqual(len(calls), 1)  # no new fake call, no KeyError, no exception

    def test_pending_reservation_is_conflict_fail_closed(self):
        calls = []
        b = _broker(client=_CountingClient(calls), store=_PendingStore())
        resp = b.execute(_raw("push_task_branch"))
        self.assertEqual(resp["result"], "CONFLICT_IDEMPOTENT")
        self.assertEqual(len(calls), 0)

    def test_remote_failure_sanitized(self):
        client = fake_github.FakeGitHubClient(fail_with=model.RemoteFailure("ghp_aaaaaaaaaaaaaaaaaaaaaaaa leaked"))
        resp = _broker(client=client).execute(_raw("push_task_branch"))
        self.assertEqual(resp["result"], "REMOTE_FAILURE")
        self.assertNotIn("ghp_", json.dumps(resp))

    # --- HIGH-1/fresh-state: pre-call blocks the fake call ---
    def test_head_change_between_validations_blocks_fake_call(self):
        calls = []
        b = _broker(inspector=repository.FakeRepositoryInspector(_good_state(head_sha="0" * 40)),
                    client=_CountingClient(calls))
        resp = b.execute(_raw("push_task_branch"))
        self.assertEqual(resp["result"], "DENIED_EVIDENCE")
        self.assertEqual(len(calls), 0)

    def test_between_validations_seam_blocks_fake_call(self):
        calls = []
        b = _broker(client=_CountingClient(calls))

        def seam():
            b._repository_inspector = repository.FakeRepositoryInspector(_good_state(branch="task/53-moved"))

        resp = b.execute(_raw("push_task_branch"), _between_validations=seam)
        self.assertEqual(resp["result"], "DENIED_EVIDENCE")
        self.assertEqual(len(calls), 0)

    # --- LOW-MEDIUM-4: base binding ---
    def test_base_sha_drift_blocks_fake_call(self):
        calls = []
        b = _broker(inspector=repository.FakeRepositoryInspector(_good_state(base_sha="0" * 40)),
                    client=_CountingClient(calls))
        resp = b.execute(_raw("push_task_branch"))
        self.assertEqual(resp["result"], "DENIED_EVIDENCE")
        self.assertEqual(len(calls), 0)

    # --- LOW-MEDIUM-3: branch control characters ---
    def test_branch_with_newline_denied_policy(self):
        runner = support.make_runner_status(worktree={"path": support.WORKTREE, "branch": "task/53-restricted-broker\n"})
        self.assertEqual(_broker().execute(_raw("push_task_branch", runner=runner))["result"], "DENIED_POLICY")

    def test_branch_with_carriage_return_denied_policy(self):
        runner = support.make_runner_status(worktree={"path": support.WORKTREE, "branch": "task/53-restricted-broker\r"})
        self.assertEqual(_broker().execute(_raw("push_task_branch", runner=runner))["result"], "DENIED_POLICY")

    def test_valid_branch_still_passes(self):
        self.assertEqual(_broker().execute(_raw("push_task_branch"))["result"], "SUCCESS")

    # --- HIGH-2: audit failure is fail-closed and non-recursive ---
    def test_audit_failure_before_response_returns_internal_error(self):
        b = _broker(audit_sink=_FailingAuditSink())
        resp = b.execute(_raw("delete_branch"))  # would be DENIED_POLICY, but audit fails
        self.assertEqual(resp["result"], "INTERNAL_ERROR")
        self.assertEqual(resp["outcome"], {"reason": "audit_sink_failure"})
        self.assertEqual(len(b._emergency_sink.records), 1)
        self.assertEqual(b._emergency_sink.records[0].decision, "INTERNAL_ERROR")

    def test_audit_failure_after_fake_success_is_fail_closed_and_key_terminal(self):
        calls = []
        b = _broker(client=_CountingClient(calls), audit_sink=_FailingAuditSink())
        r1 = b.execute(_raw("open_draft_pr"))
        self.assertEqual(r1["result"], "INTERNAL_ERROR")  # degraded, no exception escaped
        self.assertEqual(len(calls), 1)  # fake call happened once
        self.assertEqual(len(b._emergency_sink.records), 1)
        # replay: key is terminal, so NO second fake call even though primary audit still fails
        r2 = b.execute(_raw("open_draft_pr"))
        self.assertEqual(len(calls), 1)  # no second side effect
        self.assertEqual(r2["result"], "INTERNAL_ERROR")

    def test_execute_always_returns_response_even_when_audit_fails(self):
        b = _broker(audit_sink=_FailingAuditSink())
        resp = b.execute(_raw("push_task_branch"))
        self.assertIn("audit_id", resp)
        self.assertRegex(resp["audit_id"], r"^[0-9a-f]{64}$")

    def test_audit_sink_returning_non_record_does_not_escape(self):
        b = _broker(audit_sink=_NoneReturningAuditSink())
        resp = b.execute(_raw("delete_branch"))  # deny path: no nested try around _deny
        self.assertEqual(resp["result"], "INTERNAL_ERROR")
        self.assertRegex(resp["audit_id"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(b._emergency_sink.records), 1)


if __name__ == "__main__":
    unittest.main()
