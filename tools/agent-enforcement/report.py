"""Canonical JSON report generation for the Styx scope guard."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Sequence

from model import ChangedEntry, Contract, Diagnostic, PathEvaluation, SCHEMA_ID, TOOL_VERSION


def _entry_as_dict(entry: ChangedEntry, evaluations: dict[str, PathEvaluation]) -> dict[str, object]:
    return {
        "status": entry.status,
        "score": entry.score,
        "old_path": entry.old_path,
        "new_path": entry.new_path,
        "paths": [evaluations[path].as_dict() for path in entry.checked_paths()],
    }


def canonical_json_bytes(report: dict[str, object]) -> bytes:
    return (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def build_report(
    *,
    issue_number: int,
    execution_id: str,
    base_sha: str,
    head_sha: str,
    issue_body_sha256: str,
    contract: Contract | None,
    entries: Sequence[ChangedEntry],
    evaluations: dict[str, PathEvaluation],
    diagnostics: Sequence[Diagnostic],
    verdict: str,
) -> dict[str, object]:
    ordered_diagnostics = sorted(
        diagnostics,
        key=lambda item: (item.code, item.path or "", item.message, item.severity),
    )
    return {
        "allowed_patterns": list(contract.allowed_patterns) if contract else [],
        "base_sha": base_sha,
        "changed_entries": [_entry_as_dict(entry, evaluations) for entry in entries],
        "contract_version": contract.version if contract else None,
        "diagnostics": [item.as_dict() for item in ordered_diagnostics],
        "execution_id": execution_id,
        "forbidden_patterns": list(contract.forbidden_patterns) if contract else [],
        "generation": {
            "canonical_json": "RFC8259-sort-keys-utf8-lf",
            "timestamp_omitted": True,
        },
        "head_sha": head_sha,
        "issue_body_sha256": issue_body_sha256,
        "issue_number": issue_number,
        "schema": SCHEMA_ID,
        "tool_version": TOOL_VERSION,
        "verdict": verdict,
    }


def write_report(output_path: Path, report: dict[str, object]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temp_path = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    temp_path = Path(raw_temp_path)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json_bytes(report))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, output_path)
    except BaseException:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise
