"""Injected fake GitHub client. Exactly two capabilities; no network, no
credentials, and no generic request surface. The module imports no network
stack (proven by tests/test_no_network.py)."""
from __future__ import annotations

import dataclasses
from typing import Protocol

from model import RemoteFailure
from policy import Target


@dataclasses.dataclass(frozen=True)
class PublishResult:
    branch: str
    head_sha: str
    base_sha: str
    forced: bool


@dataclasses.dataclass(frozen=True)
class DraftPrResult:
    pr_number: int
    branch: str
    base_sha: str
    draft: bool


class GitHubTransport(Protocol):
    def publish_task_branch(self, target: Target) -> PublishResult:
        ...

    def create_draft_pr(self, target: Target) -> DraftPrResult:
        ...


class FakeGitHubClient:
    """Deterministic reference transport with exactly two methods."""

    def __init__(self, fail_with=None):
        self._fail_with = fail_with

    def publish_task_branch(self, target: Target) -> PublishResult:
        if self._fail_with is not None:
            raise self._fail_with
        if target.force:
            raise RemoteFailure("refusing forced publication")
        if target.tag is not None:
            raise RemoteFailure("refusing tag operation")
        return PublishResult(
            branch=target.branch, head_sha=target.head_sha, base_sha=target.base_sha, forced=False
        )

    def create_draft_pr(self, target: Target) -> DraftPrResult:
        if self._fail_with is not None:
            raise self._fail_with
        if not target.draft:
            raise RemoteFailure("refusing non-draft pull request")
        return DraftPrResult(pr_number=1, branch=target.branch, base_sha=target.base_sha, draft=True)
