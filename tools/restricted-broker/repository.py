"""Local, read-only repository state inspection used to revalidate the real
working tree immediately before each simulated client call. No network.

The core depends only on the ``RepositoryInspector`` ABC. A real ``git``-based
inspector is deferred to runner integration (a separate authorized task); v1
ships a deterministic in-memory reference inspector used by the tests.
"""
from __future__ import annotations

import abc
import dataclasses

from evidence import ValidatedEvidence
from model import EvidenceError
from policy import Target


@dataclasses.dataclass(frozen=True)
class RepoState:
    repository: str
    worktree: str
    branch: str
    head_sha: str
    # ``base_sha`` is the concrete base the inspector observed; ``base_is_ancestor``
    # MUST be computed as "``base_sha`` is an ancestor of ``head_sha``" so the
    # ancestry claim is self-consistent. ``validate_fresh_state`` additionally binds
    # ``base_sha`` to the declared target base, so a context-free boolean can never
    # stand in for the attested base.
    base_sha: str
    base_is_ancestor: bool
    clean: bool
    changed_paths: tuple
    symlink_paths: tuple


class RepositoryInspector(abc.ABC):
    @abc.abstractmethod
    def snapshot(self) -> RepoState:
        ...


class FakeRepositoryInspector(RepositoryInspector):
    """Deterministic reference inspector. Not a weak mock: it returns a fixed
    immutable RepoState captured at construction time."""

    def __init__(self, state: RepoState):
        self._state = state

    def snapshot(self) -> RepoState:
        return self._state


def validate_fresh_state(inspector: RepositoryInspector, ev: ValidatedEvidence, target: Target) -> None:
    state = inspector.snapshot()
    if state.repository != target.repository:
        raise EvidenceError("repository changed since validation")
    if state.branch != target.branch:
        raise EvidenceError("branch changed since validation")
    if state.head_sha != target.head_sha:
        raise EvidenceError("HEAD changed since validation")
    if state.base_sha != target.base_sha:
        raise EvidenceError("declared base changed since validation")
    if not state.base_is_ancestor:
        raise EvidenceError("declared base is no longer an ancestor of HEAD")
    if not state.clean:
        raise EvidenceError("worktree is not clean")
    if state.symlink_paths:
        raise EvidenceError("symlink or path replacement detected")
    if tuple(state.changed_paths) != tuple(ev.changed_paths):
        raise EvidenceError("changed paths diverge from attested evidence")
