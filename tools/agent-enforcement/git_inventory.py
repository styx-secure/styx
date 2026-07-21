"""Read-only Git inventory for the Styx scope guard."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
from typing import Sequence

from contract import validate_repo_path
from model import ChangedEntry, Diagnostic, GitInputError, RepositoryStateError, TreeObject

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SUPPORTED_STATUSES = {"A", "M", "D", "R", "C"}


def run_git(
    repo: Path,
    args: Sequence[str],
    *,
    text: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes] | subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(key, None)
    for key in tuple(environment):
        if key == "GIT_CONFIG_COUNT" or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key, None)
    environment.update(
        {
            # Neutralize global/system configuration so host-level settings
            # cannot alter diff, status or object inspection semantics.
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    try:
        return subprocess.run(
            [
                "git",
                "-c",
                "core.quotepath=false",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                *args,
            ],
            cwd=repo,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
            env=environment,
        )
    except FileNotFoundError as exc:
        raise GitInputError("git executable was not found") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else exc.stderr
        raise GitInputError(stderr.strip() or f"git exited with status {exc.returncode}") from exc


def literal_pathspec(path: str) -> str:
    """Return a pathspec that treats every character literally.

    Without the ``:(literal)`` magic a repository file whose name starts with
    ``:`` would be parsed as pathspec magic, and glob characters would expand.
    """

    return ":(literal)" + path


def repository_toplevel(repo: Path) -> Path | None:
    """Return the resolved worktree root containing ``repo``, if any."""

    try:
        result = run_git(repo, ["rev-parse", "--show-toplevel"], text=True, check=False)
    except GitInputError:
        return None
    if result.returncode != 0:
        return None
    top = result.stdout.strip()
    return Path(top).resolve() if top else None


def output_is_inside_repository(repo: Path, output_path: Path) -> bool:
    try:
        output_path.resolve(strict=False).relative_to(repo.resolve(strict=False))
    except ValueError:
        return False
    return True


def verify_repository(
    repo: Path,
    base_sha: str,
    head_sha: str,
    *,
    worktree_sha: str | None = None,
) -> bytes:
    """Verify immutable inputs and a clean checkout used only for object inspection.

    By default the worktree must be checked out at ``head_sha``. Trusted-base CI
    may set ``worktree_sha`` to the event base SHA, allowing the guard to inspect
    the pull-request head strictly as Git object data without checking it out.
    """

    expected_worktree_sha = head_sha if worktree_sha is None else worktree_sha
    for label, sha in (
        ("base", base_sha),
        ("head", head_sha),
        ("worktree", expected_worktree_sha),
    ):
        if not SHA_RE.fullmatch(sha):
            raise GitInputError(f"{label} must be a lowercase full 40-hex commit SHA")
    repo = repo.resolve()
    if not repo.is_dir():
        raise RepositoryStateError(f"repository path does not exist: {repo}")
    top = run_git(repo, ["rev-parse", "--show-toplevel"], text=True).stdout.strip()
    if Path(top).resolve() != repo:
        raise RepositoryStateError("--repo must point to the Git worktree root")
    if run_git(repo, ["rev-parse", "--is-shallow-repository"], text=True).stdout.strip() == "true":
        raise RepositoryStateError("shallow repositories are not accepted in v1")

    checked_objects: set[str] = set()
    for label, sha in (
        ("base", base_sha),
        ("head", head_sha),
        ("worktree", expected_worktree_sha),
    ):
        if sha in checked_objects:
            continue
        checked_objects.add(sha)
        result = run_git(repo, ["cat-file", "-e", f"{sha}^{{commit}}"], check=False)
        if result.returncode != 0:
            raise GitInputError(f"{label} SHA does not resolve to a local commit object")
    if run_git(repo, ["merge-base", "--is-ancestor", base_sha, head_sha], check=False).returncode != 0:
        raise GitInputError("base SHA is not an ancestor of head SHA")
    if run_git(repo, ["rev-parse", "HEAD"], text=True).stdout.strip() != expected_worktree_sha:
        raise RepositoryStateError("worktree HEAD does not equal the declared worktree SHA")

    status = run_git(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]).stdout
    if status:
        raise RepositoryStateError("repository worktree or index is dirty")
    return status


def parse_changed_entries(raw: bytes) -> tuple[ChangedEntry, ...]:
    tokens = raw.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    entries: list[ChangedEntry] = []
    index = 0
    while index < len(tokens):
        try:
            status_token = tokens[index].decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise GitInputError("non-ASCII Git status token") from exc
        index += 1
        if not status_token:
            raise GitInputError("empty Git status token")
        status, score_text = status_token[0], status_token[1:]
        score: int | None = None
        if status in {"R", "C"}:
            if not score_text.isdigit() or index + 1 >= len(tokens):
                raise GitInputError(f"invalid or truncated rename/copy record: {status_token!r}")
            score = int(score_text)
            old_path = tokens[index].decode("utf-8", "strict")
            new_path = tokens[index + 1].decode("utf-8", "strict")
            index += 2
        else:
            if score_text or index >= len(tokens):
                raise GitInputError(f"invalid or truncated changed-path record: {status_token!r}")
            path = tokens[index].decode("utf-8", "strict")
            index += 1
            old_path = None if status == "A" else path
            new_path = path if status in {"A", "M"} else None
        if status not in SUPPORTED_STATUSES:
            raise GitInputError(f"unsupported Git status: {status_token}")
        if old_path is not None:
            validate_repo_path(old_path)
        if new_path is not None:
            validate_repo_path(new_path)
        entries.append(ChangedEntry(status, score, old_path, new_path))

    return tuple(
        sorted(
            entries,
            key=lambda item: (
                item.old_path or "",
                item.new_path or "",
                item.status,
                item.score if item.score is not None else -1,
            ),
        )
    )


def inventory_changes(repo: Path, base_sha: str, head_sha: str) -> tuple[ChangedEntry, ...]:
    result = run_git(
        repo,
        [
            "diff-tree",
            "-r",
            "--no-commit-id",
            "--name-status",
            "-z",
            "-M",
            "-C",
            "--find-copies-harder",
            base_sha,
            head_sha,
        ],
    )
    return parse_changed_entries(result.stdout)


def tree_object(repo: Path, commit_sha: str, path: str) -> TreeObject | None:
    raw = run_git(repo, ["ls-tree", "-z", commit_sha, "--", literal_pathspec(path)]).stdout
    if not raw:
        return None
    records = [record for record in raw.split(b"\0") if record]
    if len(records) != 1:
        raise GitInputError(f"ambiguous tree lookup for {path!r}")
    header, raw_path = records[0].split(b"\t", 1)
    mode, object_type, object_sha = header.decode("ascii", "strict").split(" ")
    decoded_path = raw_path.decode("utf-8", "strict")
    if decoded_path != path:
        raise GitInputError(f"tree lookup path mismatch for {path!r}")
    return TreeObject(mode, object_type, object_sha, decoded_path)


def _entry_is_binary(repo: Path, base_sha: str, head_sha: str, entry: ChangedEntry) -> bool:
    raw = run_git(
        repo,
        [
            "diff",
            "--numstat",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
            base_sha,
            head_sha,
            "--",
            *(literal_pathspec(path) for path in entry.checked_paths()),
        ],
    ).stdout
    return raw.startswith(b"-\t-\t") or b"\0-\t-\t" in raw


def content_diagnostics(
    repo: Path, base_sha: str, head_sha: str, entries: Sequence[ChangedEntry]
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    checked_blobs: set[str] = set()
    for entry in entries:
        if _entry_is_binary(repo, base_sha, head_sha, entry):
            diagnostics.append(
                Diagnostic(
                    "P_BINARY_GIT",
                    "Git classifies the changed entry as binary",
                    "error",
                    entry.new_path or entry.old_path,
                )
            )
        candidates: list[tuple[str, str]] = []
        if entry.old_path is not None:
            candidates.append((base_sha, entry.old_path))
        if entry.new_path is not None:
            candidates.append((head_sha, entry.new_path))
        for commit_sha, path in candidates:
            obj = tree_object(repo, commit_sha, path)
            if obj is None:
                diagnostics.append(
                    Diagnostic("E_TREE_OBJECT_MISSING", "changed path is missing from expected tree", "error", path)
                )
                continue
            if obj.mode == "120000":
                diagnostics.append(Diagnostic("P_SYMLINK", "symlinks are forbidden in contract v1", "error", path))
                continue
            if obj.mode == "160000" or obj.object_type == "commit":
                diagnostics.append(
                    Diagnostic("P_GITLINK", "gitlinks/submodules are forbidden in contract v1", "error", path)
                )
                continue
            if obj.object_type != "blob" or not obj.mode.startswith("100"):
                diagnostics.append(
                    Diagnostic(
                        "P_UNSUPPORTED_OBJECT",
                        f"unsupported Git object mode/type: {obj.mode} {obj.object_type}",
                        "error",
                        path,
                    )
                )
                continue
            if obj.object_sha not in checked_blobs:
                checked_blobs.add(obj.object_sha)
                if b"\x00" in run_git(repo, ["cat-file", "blob", obj.object_sha]).stdout:
                    diagnostics.append(
                        Diagnostic("P_BINARY_NUL", "blob contains NUL bytes and is treated as binary", "error", path)
                    )
    return diagnostics
