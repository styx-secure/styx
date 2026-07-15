import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence  # noqa: E402
import policy  # noqa: E402
import repository  # noqa: E402
import support  # noqa: E402
from model import PUSH, EvidenceError  # noqa: E402


def _ev_target():
    ev = evidence.validate(support.make_evidence_bundle())
    return ev, policy.derive(ev, PUSH)


def _good_state():
    return repository.RepoState(
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


def _state_with(**over):
    return repository.RepoState(**{**_good_state().__dict__, **over})


class TestRepository(unittest.TestCase):
    def test_matching_state_passes(self):
        ev, target = _ev_target()
        repository.validate_fresh_state(repository.FakeRepositoryInspector(_good_state()), ev, target)

    def test_head_change_fails(self):
        ev, target = _ev_target()
        with self.assertRaises(EvidenceError):
            repository.validate_fresh_state(
                repository.FakeRepositoryInspector(_state_with(head_sha="0" * 40)), ev, target
            )

    def test_branch_change_fails(self):
        ev, target = _ev_target()
        with self.assertRaises(EvidenceError):
            repository.validate_fresh_state(
                repository.FakeRepositoryInspector(_state_with(branch="task/53-other")), ev, target
            )

    def test_dirty_worktree_fails(self):
        ev, target = _ev_target()
        with self.assertRaises(EvidenceError):
            repository.validate_fresh_state(
                repository.FakeRepositoryInspector(_state_with(clean=False)), ev, target
            )

    def test_symlink_change_fails(self):
        ev, target = _ev_target()
        with self.assertRaises(EvidenceError):
            repository.validate_fresh_state(
                repository.FakeRepositoryInspector(_state_with(symlink_paths=("x",))), ev, target
            )

    def test_base_not_ancestor_fails(self):
        ev, target = _ev_target()
        with self.assertRaises(EvidenceError):
            repository.validate_fresh_state(
                repository.FakeRepositoryInspector(_state_with(base_is_ancestor=False)), ev, target
            )

    def test_base_sha_mismatch_fails_even_when_ancestor_true(self):
        ev, target = _ev_target()
        # ancestor boolean is True but the observed base differs from the declared base
        bad = _state_with(base_sha="0" * 40, base_is_ancestor=True)
        with self.assertRaises(EvidenceError):
            repository.validate_fresh_state(repository.FakeRepositoryInspector(bad), ev, target)

    def test_changed_paths_mismatch_fails(self):
        ev, target = _ev_target()
        with self.assertRaises(EvidenceError):
            repository.validate_fresh_state(
                repository.FakeRepositoryInspector(_state_with(changed_paths=("other.py",))), ev, target
            )

    def test_repository_mismatch_fails(self):
        ev, target = _ev_target()
        with self.assertRaises(EvidenceError):
            repository.validate_fresh_state(
                repository.FakeRepositoryInspector(_state_with(repository="evil/repo")), ev, target
            )


if __name__ == "__main__":
    unittest.main()
