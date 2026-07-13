"""Command safety policy for the Styx automatic test orchestrator.

Every command that the planner accepts and the executor runs must satisfy
this policy. Commands are argv vectors executed without a shell; the policy
therefore rejects shell control tokens outright instead of quoting them.
Network access is denied by construction: only offline interpreters and
read-only git subcommands are eligible, and namespace isolation is added
on top by the executor when bubblewrap is available.
"""

from __future__ import annotations

import re
import shlex

from model import (
    CommandPolicyError,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_OUTPUT_BYTES,
    MAX_TIMEOUT_SECONDS,
)

ALLOWED_EXECUTABLES = ("python3", "git")

PYTHON_MODULE_ALLOWLIST = ("unittest", "json.tool", "py_compile", "compileall")

GIT_SUBCOMMAND_ALLOWLIST = (
    "cat-file",
    "diff",
    "ls-files",
    "ls-tree",
    "merge-base",
    "rev-parse",
    "status",
)
GIT_FORBIDDEN_ARG_RE = re.compile(
    r"^(-c|-C|--exec-path(=.*)?|--git-dir(=.*)?|--work-tree(=.*)?"
    r"|--namespace(=.*)?|--config-env(=.*)?|--upload-pack(=.*)?|--receive-pack(=.*)?)$"
)

NETWORK_TOOL_TOKENS = frozenset(
    {"curl", "wget", "ssh", "scp", "sftp", "nc", "ncat", "socat", "gh", "pip", "pip3", "npm", "npx"}
)
SHELL_CONTROL_RE = re.compile(r"[;&|`$<>\n\r\x00]")
DEVNULL_REDIRECTION = ">/dev/null"


def split_shell_command(command: str) -> tuple[tuple[str, ...], bool]:
    """Split a contract shell command into argv, honouring one safe redirection.

    The only redirection accepted is a trailing ``>/dev/null`` because the
    repository task contracts use it for JSON well-formedness checks. Every
    other shell construct is rejected by ``validate_command``.
    """

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise CommandPolicyError(f"unparseable command: {exc}") from exc
    if not tokens:
        raise CommandPolicyError("empty command")
    discard_stdout = False
    if tokens[-1] == DEVNULL_REDIRECTION or tokens[-2:] == [">", "/dev/null"]:
        discard_stdout = True
        tokens = tokens[:-1] if tokens[-1] == DEVNULL_REDIRECTION else tokens[:-2]
        if not tokens:
            raise CommandPolicyError("redirection without a command")
    return tuple(tokens), discard_stdout


def validate_command(argv: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Validate one argv vector against the offline execution policy."""

    if not argv:
        raise CommandPolicyError("empty command")
    vector = tuple(argv)
    for token in vector:
        if not isinstance(token, str) or token == "":
            raise CommandPolicyError("command tokens must be non-empty strings")
        if any(ord(char) < 32 or ord(char) == 127 for char in token):
            raise CommandPolicyError("command token contains control characters")
        if SHELL_CONTROL_RE.search(token):
            raise CommandPolicyError(f"shell control token is not allowed: {token!r}")
        if token in NETWORK_TOOL_TOKENS:
            raise CommandPolicyError(f"network-capable tool is not allowed: {token!r}")

    executable = vector[0]
    if executable not in ALLOWED_EXECUTABLES:
        raise CommandPolicyError(f"executable is not allowlisted: {executable!r}")
    if executable == "python3":
        _validate_python(vector)
    else:
        _validate_git(vector)
    return vector


def _validate_python(vector: tuple[str, ...]) -> None:
    if len(vector) < 3 or vector[1] != "-m":
        raise CommandPolicyError("python3 commands must use '-m <module>'")
    if vector[2] not in PYTHON_MODULE_ALLOWLIST:
        raise CommandPolicyError(f"python module is not allowlisted: {vector[2]!r}")
    for token in vector[3:]:
        if token == "-c":
            raise CommandPolicyError("arbitrary python code execution is not allowed")
        if token.startswith("/") and not token.startswith("/dev/null"):
            raise CommandPolicyError(f"absolute paths are not allowed: {token!r}")


def _validate_git(vector: tuple[str, ...]) -> None:
    if len(vector) < 2:
        raise CommandPolicyError("git commands must name a subcommand")
    if vector[1] not in GIT_SUBCOMMAND_ALLOWLIST:
        raise CommandPolicyError(f"git subcommand is not allowlisted: {vector[1]!r}")
    for token in vector[1:]:
        if GIT_FORBIDDEN_ARG_RE.match(token):
            raise CommandPolicyError(f"git argument is not allowed: {token!r}")


def validate_resource_policy(timeout_seconds: object, max_output_bytes: object) -> tuple[int, int]:
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool):
        raise CommandPolicyError("timeout_seconds must be an integer")
    if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool):
        raise CommandPolicyError("max_output_bytes must be an integer")
    if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise CommandPolicyError(f"timeout_seconds must be within [1, {MAX_TIMEOUT_SECONDS}]")
    if not 1 <= max_output_bytes <= MAX_OUTPUT_BYTES:
        raise CommandPolicyError(f"max_output_bytes must be within [1, {MAX_OUTPUT_BYTES}]")
    return timeout_seconds, max_output_bytes


def default_resource_policy() -> tuple[int, int]:
    return DEFAULT_TIMEOUT_SECONDS, DEFAULT_MAX_OUTPUT_BYTES
