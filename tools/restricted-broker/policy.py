"""Derive the fixed operation target from validated evidence. No target value is
ever taken from the request: repository, branch, base, HEAD, force and PR mode
are fixed policy or come from validated evidence."""
from __future__ import annotations

import dataclasses
import re

from evidence import ValidatedEvidence
from model import OPEN_PR, PUSH, PolicyError

REPOSITORY = "styx-secure/styx"


@dataclasses.dataclass(frozen=True)
class Target:
    operation: str
    repository: str
    branch: str
    base_sha: str
    head_sha: str
    force: bool
    draft: bool
    tag: None
    pr_title: str
    pr_body: str


def derive(ev: ValidatedEvidence, operation: str) -> Target:
    if operation not in (PUSH, OPEN_PR):
        raise PolicyError(f"operation not permitted: {operation!r}")
    if ev.repository != REPOSITORY:
        raise PolicyError("repository is not the authorized repository")
    if not re.match(rf"^task/{ev.issue_number}-[a-z0-9-]+$", ev.branch):
        raise PolicyError(f"branch does not match task-branch policy: {ev.branch!r}")
    pr_title = f"[task] #{ev.issue_number} restricted broker (Draft)"
    pr_body = (
        f"Draft PR for issue #{ev.issue_number} from branch {ev.branch} "
        f"at {ev.head_sha} onto base {ev.base_sha}. Refs #{ev.issue_number}."
    )
    return Target(
        operation=operation,
        repository=REPOSITORY,
        branch=ev.branch,
        base_sha=ev.base_sha,
        head_sha=ev.head_sha,
        force=False,
        draft=True,
        tag=None,
        pr_title=pr_title,
        pr_body=pr_body,
    )
