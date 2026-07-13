#!/usr/bin/env python3
"""Post-review hardening for the nested task-test sandbox."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Mapping

ADDITIONAL_DIRECTORY_STORES = (
    ".aws",
    ".gnupg",
    ".config/git",
)
ADDITIONAL_FILE_STORES = (
    ".docker/config.json",
    ".gitconfig",
)
ADDITIONAL_SENSITIVE_PATTERN = (
    r"|(?:~|\$HOME|\$\{HOME\})/"
    r"(?:\.aws(?:/|$)|\.gnupg(?:/|$)|\.config/git(?:/|$)|"
    r"\.docker/config\.json(?:$|[\s'\"])|\.gitconfig(?:$|[\s'\"]))"
)


def apply(security: Any) -> None:
    """Extend credential masking without weakening the original sandbox."""

    if getattr(security, "_STYX_REVIEW_HARDENING_APPLIED", False):
        return

    original_bwrap_command = security._bwrap_command

    def hardened_bwrap_command(
        bwrap: str,
        worktree: Path,
        command: str,
        environment: Mapping[str, str],
    ) -> list[str]:
        args = original_bwrap_command(bwrap, worktree, command, environment)
        try:
            clearenv_index = args.index("--clearenv")
        except ValueError as exc:
            raise RuntimeError("bubblewrap command is missing --clearenv") from exc

        home = Path(environment["HOME"]).resolve()
        masks: list[str] = []
        for relative in ADDITIONAL_DIRECTORY_STORES:
            path = home / relative
            if path.exists() or path.is_symlink():
                masks.extend(["--tmpfs", str(path)])
        for relative in ADDITIONAL_FILE_STORES:
            path = home / relative
            if path.exists() or path.is_symlink():
                masks.extend(["--ro-bind", "/dev/null", str(path)])
        return [*args[:clearenv_index], *masks, *args[clearenv_index:]]

    security._bwrap_command = hardened_bwrap_command
    security.PROHIBITED_TEST_RE = re.compile(
        security.PROHIBITED_TEST_RE.pattern + ADDITIONAL_SENSITIVE_PATTERN,
        security.PROHIBITED_TEST_RE.flags,
    )
    security._STYX_REVIEW_HARDENING_APPLIED = True
