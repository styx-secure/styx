import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence  # noqa: E402
import policy  # noqa: E402
import support  # noqa: E402
from model import OPEN_PR, PUSH, PolicyError  # noqa: E402


def valid_ev():
    return evidence.validate(support.make_evidence_bundle())


class TestPolicy(unittest.TestCase):
    def test_push_target_forces_nonforce(self):
        t = policy.derive(valid_ev(), PUSH)
        self.assertFalse(t.force)
        self.assertEqual(t.branch, support.BRANCH)
        self.assertEqual(t.base_sha, support.BASE_SHA)
        self.assertIsNone(t.tag)

    def test_pr_target_is_draft_with_derived_template(self):
        t = policy.derive(valid_ev(), OPEN_PR)
        self.assertTrue(t.draft)
        self.assertIn("53", t.pr_title)
        self.assertIn(support.BRANCH, t.pr_body)

    def test_branch_off_pattern_denied(self):
        ev = evidence.validate(
            support.make_evidence_bundle(
                runner=support.make_runner_status(worktree={"path": support.WORKTREE, "branch": "feature/53-x"})
            )
        )
        with self.assertRaises(PolicyError):
            policy.derive(ev, PUSH)

    def test_unknown_operation_denied(self):
        with self.assertRaises(PolicyError):
            policy.derive(valid_ev(), "delete_branch")


if __name__ == "__main__":
    unittest.main()
