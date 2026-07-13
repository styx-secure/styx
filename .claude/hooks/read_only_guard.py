#!/usr/bin/env python3
"""Deny commands that cannot be proven read-only at the Claude hook boundary."""

from __future__ import annotations

import json
from pathlib import Path
import shlex
import sys
from typing import Any, Mapping

DENIED_EXECUTABLES = {"find", "sed"}


def inspect(payload: Mapping[str, Any]) -> str | None:
    if payload.get("tool_name") != "Bash":
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return "Bash tool input is missing or malformed"
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return "Bash command is missing"
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return "Bash command could not be parsed safely"
    if not parts:
        return "Bash command is empty"
    executable = Path(parts[0]).name
    if executable in DENIED_EXECUTABLES:
        return (
            f"{executable} is denied by the Styx read-only gate because its "
            "mutating forms cannot be distinguished safely at this boundary"
        )
    return None


def deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be an object")
        reason = inspect(payload)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        reason = f"Styx read-only guard failed closed: {exc}"
    if reason:
        print(json.dumps(deny(reason), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
