#!/usr/bin/env python3
"""Runner-owned Git object store and worktree isolation for the Styx CLI."""

from __future__ import annotations

import contextlib
import hashlib
import json
from pathlib import Path
import shutil
import sys
from typing import Any, Mapping


def object_store(paths: Any) -> Path:
    return (paths.state / "git" / "styx.git").resolve()


def _bare_git(runner: Any, paths: Any, args: list[str], *, check: bool = True):
    return runner.run_command(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            f"--git-dir={object_store(paths)}",
            *args,
        ],
        cwd=paths.state,
        check=check,
    )


def ensure_object_store(runner: Any, paths: Any, base_sha: str) -> None:
    paths.ensure()
    store = object_store(paths)
    store.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        store.parent.chmod(0o700)
    if store.exists():
        if not store.is_dir():
            raise runner.RepositoryError("runner object-store path exists but is not a directory")
        result = _bare_git(runner, paths, ["rev-parse", "--is-bare-repository"], check=False)
        if result.returncode != 0 or result.stdout.strip() != "true":
            raise runner.RepositoryError("runner object store is not a valid bare Git repository")
    else:
        result = runner.run_command(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "clone",
                "--bare",
                "--no-hardlinks",
                "--no-tags",
                str(paths.repo),
                str(store),
            ],
            cwd=paths.state,
            check=False,
            timeout=300,
        )
        if result.returncode != 0:
            raise runner.RepositoryError(
                f"unable to create runner object store: {runner.redact_text(result.stderr.strip())}"
            )
        # The future broker owns publication. Task worktrees intentionally have no
        # generic push destination, even when local user credentials are broader.
        _bare_git(runner, paths, ["remote", "remove", "origin"], check=False)

    imported = _bare_git(
        runner,
        paths,
        ["fetch", "--no-tags", "--no-write-fetch-head", str(paths.repo), base_sha],
        check=False,
    )
    if imported.returncode != 0:
        raise runner.RepositoryError(
            "unable to import declared base into runner object store: "
            + runner.redact_text(imported.stderr.strip())
        )
    if _bare_git(runner, paths, ["cat-file", "-e", f"{base_sha}^{{commit}}"], check=False).returncode != 0:
        raise runner.RepositoryError("declared base is absent from the runner object store")


def _worktree_entries(runner: Any, paths: Any) -> list[dict[str, str]]:
    raw = _bare_git(runner, paths, ["worktree", "list", "--porcelain"]).stdout
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in raw.splitlines():
        if not line:
            if current:
                entries.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        current[key] = value
    if current:
        entries.append(current)
    return entries


def _prepare_worktree(runner: Any, paths: Any, contract: Any) -> tuple[Path, str, str]:
    runner.verify_repository(paths.repo, contract, require_clean=True)
    ensure_object_store(runner, paths, contract.base_sha)
    branch = f"task/{contract.issue_number}-{runner.slugify(contract.title)}"
    worktree = (paths.worktrees / f"issue-{contract.issue_number}").resolve()
    existing = _worktree_entries(runner, paths)
    branch_ref = f"refs/heads/{branch}"
    branch_result = _bare_git(
        runner,
        paths,
        ["show-ref", "--verify", "--hash", branch_ref],
        check=False,
    )
    branch_sha = branch_result.stdout.strip() if branch_result.returncode == 0 else None
    matching = [entry for entry in existing if Path(entry.get("worktree", "")).resolve() == worktree]
    if worktree.exists() or matching or branch_sha is not None:
        if len(matching) != 1:
            raise runner.RepositoryError("branch/worktree collision requires operator cleanup")
        entry = matching[0]
        if entry.get("branch") != branch_ref:
            raise runner.RepositoryError("existing worktree is attached to a different branch")
        current = runner.git(worktree, ["rev-parse", "HEAD"]).stdout.strip()
        if _bare_git(
            runner,
            paths,
            ["merge-base", "--is-ancestor", contract.base_sha, current],
            check=False,
        ).returncode != 0:
            raise runner.RepositoryError("existing task branch does not descend from the declared base")
        return worktree, branch, current
    result = _bare_git(
        runner,
        paths,
        ["worktree", "add", "-b", branch, str(worktree), contract.base_sha],
        check=False,
    )
    if result.returncode != 0:
        raise runner.RepositoryError(
            f"unable to create task worktree: {runner.redact_text(result.stderr.strip())}"
        )
    return worktree, branch, contract.base_sha


def _scope_error(runner: Any, report_path: Path, message: str):
    return {
        "exit_code": runner.EXIT_ERROR,
        "verdict": "ERROR",
        "report_path": str(report_path),
        "report_sha256": None,
    }, message


def _run_scope_guard(
    runner: Any,
    paths: Any,
    contract: Any,
    worktree: Path,
    head_sha: str,
    execution_id: str,
):
    del worktree
    evidence_dir = paths.state / "evidence" / execution_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    body_path = evidence_dir / "issue-body.md"
    report_path = evidence_dir / "task-scope-report.json"
    runner.atomic_write(body_path, contract.body_bytes, 0o600)

    if _bare_git(
        runner,
        paths,
        ["cat-file", "-e", f"{head_sha}^{{commit}}"],
        check=False,
    ).returncode != 0:
        return _scope_error(runner, report_path, "task head is absent from the runner object store")

    guard_root = paths.state / "guard-worktrees"
    guard_root.mkdir(parents=True, exist_ok=True)
    guard_worktree = guard_root / f"{execution_id}-{contract.base_sha[:12]}"
    if guard_worktree.exists():
        return _scope_error(runner, report_path, "deterministic guard worktree path already exists")

    added = _bare_git(
        runner,
        paths,
        ["worktree", "add", "--detach", str(guard_worktree), contract.base_sha],
        check=False,
    )
    if added.returncode != 0:
        return _scope_error(
            runner,
            report_path,
            "unable to create trusted-base guard worktree: " + runner.redact_text(added.stderr.strip()),
        )

    guard = paths.repo / "tools/agent-enforcement/scope_guard.py"
    try:
        completed = runner.run_command(
            [
                sys.executable,
                str(guard),
                "--issue-number",
                str(contract.issue_number),
                "--issue-body-file",
                str(body_path),
                "--base-sha",
                contract.base_sha,
                "--head-sha",
                head_sha,
                "--worktree-sha",
                contract.base_sha,
                "--execution-id",
                execution_id,
                "--output",
                str(report_path),
                "--repo",
                str(guard_worktree),
            ],
            cwd=paths.repo,
            check=False,
            timeout=600,
        )
        exit_code = completed.returncode
    except runner.RunnerError as exc:
        return _scope_error(runner, report_path, exc.message)
    finally:
        _bare_git(
            runner,
            paths,
            ["worktree", "remove", "--force", str(guard_worktree)],
            check=False,
        )
        with contextlib.suppress(OSError):
            shutil.rmtree(guard_worktree)

    report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest() if report_path.is_file() else None
    verdict = None
    if report_path.is_file():
        try:
            parsed = json.loads(report_path.read_text(encoding="utf-8"))
            verdict = parsed.get("verdict")
        except (OSError, json.JSONDecodeError):
            verdict = None
    result = {
        "exit_code": exit_code,
        "verdict": verdict,
        "report_path": str(report_path),
        "report_sha256": report_sha,
    }
    if exit_code != 0 or verdict != "PASS":
        return result, f"scope guard did not PASS: exit={exit_code} verdict={verdict}"
    return result, None


def apply(runner: Any) -> None:
    """Install isolation controls into the base runner module exactly once."""
    if getattr(runner, "_STYX_ISOLATED_GIT_APPLIED", False):
        return
    original_verify = runner.verify_repository

    def verify_repository(repo: Path, contract: Any | None = None, *, require_clean: bool = True):
        result = original_verify(repo, contract, require_clean=require_clean)
        if contract is not None and result.get("head_sha") != contract.base_sha:
            raise runner.RepositoryError(
                f"source checkout HEAD is {result.get('head_sha')}, expected the declared base {contract.base_sha}"
            )
        return result

    runner.verify_repository = verify_repository
    runner.prepare_worktree = lambda paths, contract: _prepare_worktree(runner, paths, contract)
    runner.run_scope_guard = (
        lambda paths, contract, worktree, head_sha, execution_id: _run_scope_guard(
            runner, paths, contract, worktree, head_sha, execution_id
        )
    )
    runner._STYX_ISOLATED_GIT_APPLIED = True
