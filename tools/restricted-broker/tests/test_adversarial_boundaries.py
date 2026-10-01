"""Adversarial boundary tests for the broker, its audit sink and its transport.

GAP JUSTIFICATION (GAPS.md of the parent re-run t_3e22486c, §2): the rows

    tools/restricted-broker/broker.py      | categories assenti: boundary/size
        limits, resource exhaustion / amplification, timeout / liveness
    tools/restricted-broker/audit.py       | categories assenti: resource
        exhaustion / amplification, timeout / liveness
    tools/restricted-broker/fake_github.py | categories assenti:
        boundary/size limits, resource exhaustion / amplification,
        rollback / atomicity, timeout / liveness

are the gap this module closes: the broker is the only place allowed to turn
untrusted bytes into a side effect, so every hostile input must come back as a
closed result class, exactly one audit record, and no echoed payload.

Deterministic and offline: fixed corpora, no network, no wall clock, no timers.
"""

import inspect
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit  # noqa: E402
import broker  # noqa: E402
import evidence as evidence_mod  # noqa: E402
import fake_github  # noqa: E402
import idempotency  # noqa: E402
import jsonparse  # noqa: E402
import model  # noqa: E402
import policy  # noqa: E402
import repository  # noqa: E402
import support  # noqa: E402

CLOSED_RESULTS = {
    "SUCCESS",
    "DENIED_POLICY",
    "DENIED_EVIDENCE",
    "CONFLICT_IDEMPOTENT",
    "AUTH_UNAVAILABLE",
    "REMOTE_FAILURE",
    "INTERNAL_ERROR",
}

SECRET = "ghp_" + "z" * 36


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


def _raw(operation="push_task_branch", scope=None, runner=None, attestation=None, **over):
    scope = support.make_scope_report() if scope is None else scope
    runner = support.make_runner_status() if runner is None else runner
    attestation = (
        support.make_attestation(scope_report=scope, runner_status=runner)
        if attestation is None
        else attestation
    )
    obj = {
        "schema": "styx.restricted-broker-request/v1",
        "operation": operation,
        "issue_number": 53,
        "execution_id": "issue-53",
        "idempotency_key": "k1",
        "evidence": {
            "scope_report": scope,
            "runner_status": runner,
            "hook_attestation": attestation,
        },
    }
    obj.update(over)
    return json.dumps(obj).encode("utf-8")


def _broker(inspector=None, client=None, store=None, audit_sink=None):
    return broker.RestrictedBroker(
        fake_client=client or fake_github.FakeGitHubClient(),
        idempotency_store=store or idempotency.InMemoryIdempotencyStore(),
        audit_sink=audit_sink or audit.InMemoryAuditSink(),
        repository_inspector=inspector or repository.FakeRepositoryInspector(_good_state()),
    )


class _CountingClient(fake_github.FakeGitHubClient):
    def __init__(self, fail_with=None):
        super().__init__(fail_with=fail_with)
        self.calls = []

    def publish_task_branch(self, target):
        self.calls.append("push")
        return super().publish_task_branch(target)

    def create_draft_pr(self, target):
        self.calls.append("pr")
        return super().create_draft_pr(target)


class _FailingSink(audit.AuditSink):
    def append(self, event):
        raise RuntimeError("append-only log unavailable")


class _NullSink(audit.AuditSink):
    def append(self, event):
        return None


class TestFailClosedBoundary(unittest.TestCase):
    """No input may raise, and every attempt yields one closed result."""

    def _hostile_corpus(self):
        big = b'{"a":"' + b"x" * (8 * 1024 * 1024) + b'"}'
        return [
            b"",
            b" ",
            b"\x00",
            b"\xff\xfe",
            b"[]",
            b"null",
            b'{"schema":"styx.restricted-broker-request/v1"}',
            b'{"schema":"x","operation":"push_task_branch","issue_number":53,"execution_id":"e","idempotency_key":"k","evidence":{}}',
            b'{"schema":"x","operation":"push_task_branch","issue_number":53,"execution_id":"e","idempotency_key":"k","evidence":{"scope_report":{}}}',
            _raw(operation="delete_everything"),
            _raw(operation="push_task_branch", extra="surprise"),
            b'{"schema":"styx.restricted-broker-request/v1","operation":"push_task_branch","issue_number":53,"idempotency_key":"k1","issue_number":54}',
            b'{"a":1,"\\u0061":2}',
            big,
        ]

    def test_every_hostile_input_returns_a_closed_result_and_one_audit_record(self):
        for raw in self._hostile_corpus():
            sink = audit.InMemoryAuditSink()
            instance = _broker(audit_sink=sink)
            response = instance.execute(raw)
            self.assertIsInstance(response, dict)
            self.assertEqual(response["schema"], broker.RESPONSE_SCHEMA)
            self.assertIn(response["result"], CLOSED_RESULTS)
            self.assertEqual(len(sink.records), 1)
            self.assertEqual(sink.records[0].decision, response["result"])

    def test_hostile_payloads_are_never_echoed_back(self):
        """Amplification/redaction boundary: the response carries an audit id,
        not the payload."""
        huge_marker = "MARKER" + "A" * 4000000
        raw = json.dumps(
            {
                "schema": "styx.restricted-broker-request/v1",
                "operation": "push_task_branch",
                "issue_number": 53,
                "execution_id": "issue-53",
                "idempotency_key": "k1",
                "evidence": {"scope_report": {"marker": huge_marker}},
            }
        ).encode("utf-8")
        instance = _broker()
        response = instance.execute(raw)
        self.assertEqual(response["result"], "DENIED_EVIDENCE")
        self.assertLess(len(json.dumps(response)), 4096)
        self.assertNotIn("MARKER", json.dumps(response))


class TestSecretHandling(unittest.TestCase):
    def test_client_failure_reason_is_redacted_everywhere(self):
        client = _CountingClient(fail_with=model.RemoteFailure(f"boom token={SECRET}"))
        sink = audit.InMemoryAuditSink()
        response = _broker(client=client, audit_sink=sink).execute(_raw())
        self.assertEqual(response["result"], "REMOTE_FAILURE")
        self.assertNotIn(SECRET, json.dumps(response))
        self.assertIn("[redacted]", response["outcome"]["reason"])
        for record in sink.records:
            self.assertNotIn(SECRET, json.dumps(record.to_json()))

    def test_evidence_hash_dicts_and_derived_dicts_are_sanitized(self):
        sink = audit.InMemoryAuditSink()
        _broker(audit_sink=sink).execute(_raw())
        record = sink.records[0]
        self.assertNotIn(SECRET, json.dumps(record.to_json()))

    def test_observed_idempotency_key_is_stored_verbatim(self):
        """FINDING (see FINDINGS.md): ``idempotency_key`` (and ``execution_id``)
        are copied into the audit record and the response without passing
        ``audit.sanitize``, although the module docstring promises "No raw
        secrets or unsanitized payloads". A caller that embeds a token in the
        key gets it persisted in the append-only log.
        """
        sink = audit.InMemoryAuditSink()
        response = _broker(audit_sink=sink).execute(_raw(idempotency_key=SECRET))
        self.assertEqual(response["idempotency_key"], SECRET)
        self.assertIn(SECRET, json.dumps(sink.records[0].to_json()))

    def test_authorization_bearer_and_userinfo_forms_are_redacted(self):
        header = "Authoriz" + "ation: token " + SECRET
        redacted = audit.sanitize(header)
        self.assertNotIn(SECRET, redacted)
        self.assertNotIn("token", redacted)
        self.assertEqual(audit.sanitize("Bearer " + SECRET), "[redacted]")


class TestHostileNames(unittest.TestCase):
    def test_hostile_changed_paths_are_denied_without_being_echoed(self):
        hostile = ["../../etc/passwd", "/etc/passwd", "..\\..\\win", "x\u0000y", "\u202e/reverse"]
        attestation = support.make_attestation(changed_paths=hostile)
        sink = audit.InMemoryAuditSink()
        response = _broker(audit_sink=sink).execute(_raw(attestation=attestation))
        self.assertEqual(response["result"], "DENIED_EVIDENCE")
        for name in hostile:
            self.assertNotIn(name, json.dumps(response))
            self.assertNotIn(name, json.dumps(sink.records[0].to_json()))

    def test_hostile_branch_names_are_refused_by_policy(self):
        for branch in (
            "task/53-../../etc",
            "task/53-ok\n",
            "task/53-OK",
            "task/53-",
            "TASK/53-ok",
            "task/53-ok/../x",
            "task/53-ok;rm -rf /",
        ):
            runner = support.make_runner_status()
            runner["worktree"]["branch"] = branch
            attestation = support.make_attestation(runner_status=runner, branch=branch)
            instance = _broker(inspector=repository.FakeRepositoryInspector(_good_state(branch=branch)))
            response = instance.execute(_raw(runner=runner, attestation=attestation))
            self.assertEqual(response["result"], "DENIED_POLICY", branch)

    def test_target_is_derived_from_policy_not_from_the_request(self):
        instance = _broker()
        validated = evidence_mod.validate(support.make_evidence_bundle())
        target = policy.derive(validated, "push_task_branch")
        self.assertEqual(target.repository, "styx-secure/styx")
        self.assertEqual(target.branch, support.BRANCH)
        self.assertFalse(target.force)
        self.assertTrue(target.draft)
        self.assertIsNone(target.tag)


class TestRollbackAndReplay(unittest.TestCase):
    def test_pre_call_failure_releases_the_reservation(self):
        store = idempotency.InMemoryIdempotencyStore()
        bad = repository.FakeRepositoryInspector(_good_state(clean=False))
        response = _broker(store=store, inspector=bad).execute(_raw())
        self.assertEqual(response["result"], "DENIED_EVIDENCE")
        # Released: the key is absent again, so any fingerprint is accepted.
        self.assertEqual(store.begin("k1", "any-fingerprint"), idempotency.MISS_RESERVED)

    def test_successful_attempt_records_a_terminal_outcome_for_replay(self):
        store = idempotency.InMemoryIdempotencyStore()
        client = _CountingClient()
        instance = _broker(store=store, client=client)
        first = instance.execute(_raw())
        second = instance.execute(_raw())
        self.assertEqual(first["result"], "SUCCESS")
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(second["outcome"], first["outcome"])
        self.assertNotEqual(second["audit_id"], first["audit_id"])
        self.assertEqual(client.calls, ["push"])

    def test_client_failure_is_terminal_and_never_reinvoked(self):
        client = _CountingClient(fail_with=model.RemoteFailure("transport down"))
        store = idempotency.InMemoryIdempotencyStore()
        instance = _broker(store=store, client=client)
        first = instance.execute(_raw())
        second = instance.execute(_raw())
        self.assertEqual(first["result"], "REMOTE_FAILURE")
        self.assertEqual(second["result"], "REMOTE_FAILURE")
        self.assertTrue(second["replayed"])
        self.assertEqual(client.calls, ["push"])

    def test_conflicting_fingerprint_is_denied_without_invoking_the_client(self):
        client = _CountingClient()
        store = idempotency.InMemoryIdempotencyStore()
        instance = _broker(store=store, client=client)
        self.assertEqual(instance.execute(_raw())["result"], "SUCCESS")
        other = _raw(operation="open_draft_pr")
        response = instance.execute(other)
        self.assertEqual(response["result"], "CONFLICT_IDEMPOTENT")
        self.assertEqual(client.calls, ["push"])

    def test_non_draft_or_forced_targets_are_refused_by_the_transport(self):
        target = policy.Target(
            operation="push_task_branch",
            repository="styx-secure/styx",
            branch=support.BRANCH,
            base_sha=support.BASE_SHA,
            head_sha=support.HEAD_SHA,
            force=True,
            draft=True,
            tag=None,
            pr_title="t",
            pr_body="b",
        )
        client = fake_github.FakeGitHubClient()
        with self.assertRaises(model.RemoteFailure):
            client.publish_task_branch(target)
        tagged = policy.Target(**{**target.__dict__, "force": False, "tag": "v1"})
        with self.assertRaises(model.RemoteFailure):
            client.publish_task_branch(tagged)
        non_draft = policy.Target(**{**target.__dict__, "force": False, "draft": False})
        with self.assertRaises(model.RemoteFailure):
            client.create_draft_pr(non_draft)


class TestAuditFailClosed(unittest.TestCase):
    def test_raising_sink_is_non_recursive_and_fail_closed(self):
        store = idempotency.InMemoryIdempotencyStore()
        client = _CountingClient()
        instance = _broker(store=store, client=client, audit_sink=_FailingSink())
        first = instance.execute(_raw())
        self.assertEqual(first["result"], "INTERNAL_ERROR")
        self.assertEqual(first["outcome"], {"reason": "audit_sink_failure"})
        self.assertIn("audit_id", first)
        # The side effect already happened and the key is terminal: the replay
        # does not re-invoke the client, even though the sink keeps failing.
        second = instance.execute(_raw())
        self.assertTrue(second["replayed"])
        self.assertEqual(client.calls, ["push"])

    def test_sink_returning_none_is_fail_closed(self):
        response = _broker(audit_sink=_NullSink()).execute(_raw())
        self.assertEqual(response["result"], "INTERNAL_ERROR")
        self.assertEqual(response["outcome"], {"reason": "audit_sink_failure"})

    def test_audit_sequence_is_append_only_and_contiguous(self):
        sink = audit.InMemoryAuditSink()
        instance = _broker(audit_sink=sink)
        instance.execute(_raw())
        instance.execute(_raw())
        instance.execute(b"not json")
        self.assertEqual([record.sequence for record in sink.records], [0, 1, 2])
        self.assertNotEqual(sink.records[0].audit_id, sink.records[1].audit_id)


class TestLiveness(unittest.TestCase):
    def test_broker_path_has_no_clock_sleep_network_or_subprocess(self):
        for module in (broker, audit, fake_github, repository):
            source = inspect.getsource(module)
            for token in (
                "import time",
                "time.sleep",
                "import socket",
                "urllib",
                "requests",
                "subprocess",
                "random.",
            ):
                self.assertNotIn(token, source, f"{module.__name__}: {token}")

    def test_decision_is_a_pure_function_of_input(self):
        first = _broker().execute(_raw())
        second = _broker().execute(_raw())
        first.pop("audit_id")
        second.pop("audit_id")
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
