import dataclasses
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence  # noqa: E402
import fake_github  # noqa: E402
import policy  # noqa: E402
import support  # noqa: E402
from model import OPEN_PR, PUSH, AuthUnavailable, RemoteFailure  # noqa: E402


def _target(op):
    return policy.derive(evidence.validate(support.make_evidence_bundle()), op)


class TestFakeGitHub(unittest.TestCase):
    def test_publish_returns_nonforce_result(self):
        r = fake_github.FakeGitHubClient().publish_task_branch(_target(PUSH))
        self.assertFalse(r.forced)
        self.assertEqual(r.branch, support.BRANCH)

    def test_create_draft_pr_is_draft(self):
        r = fake_github.FakeGitHubClient().create_draft_pr(_target(OPEN_PR))
        self.assertTrue(r.draft)
        self.assertEqual(r.base_sha, support.BASE_SHA)

    def test_exposes_only_two_public_methods(self):
        public = [n for n in dir(fake_github.FakeGitHubClient) if not n.startswith("_")]
        self.assertEqual(sorted(public), ["create_draft_pr", "publish_task_branch"])

    def test_no_generic_method_names(self):
        for forbidden in (
            "request", "api", "execute", "graphql", "merge", "review",
            "approve", "label", "comment", "project",
        ):
            self.assertFalse(hasattr(fake_github.FakeGitHubClient, forbidden))

    def test_scripted_remote_failure(self):
        client = fake_github.FakeGitHubClient(fail_with=RemoteFailure("boom"))
        with self.assertRaises(RemoteFailure):
            client.publish_task_branch(_target(PUSH))

    def test_scripted_auth_unavailable(self):
        client = fake_github.FakeGitHubClient(fail_with=AuthUnavailable("no auth"))
        with self.assertRaises(AuthUnavailable):
            client.create_draft_pr(_target(OPEN_PR))

    def test_rejects_force_target(self):
        bad = dataclasses.replace(_target(PUSH), force=True)
        with self.assertRaises(RemoteFailure):
            fake_github.FakeGitHubClient().publish_task_branch(bad)


if __name__ == "__main__":
    unittest.main()
