#!/usr/bin/env python3
"""Fail-closed scope and exact validator-delta guard for Issue #252."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
O07 = HERE.parent / "o07"
sys.path.insert(0, str(O07))

from scope_guard_o07 import (  # noqa: E402
    ScopeViolation as FrozenScopeViolation,
    enforce_declared_validator_ast_delta,
)

from canonical_report import ReportError, store_report  # noqa: E402


BASE_SHA = "d35052dfbf0631c726f250933bc401f424602f31"
VALIDATOR_PATH = "tools/protocol-review-model/validate.py"
EXPECTED_BASE_SOURCE_SHA256 = "e3d5ab45ec9a7933e690375661d2303b2b7915bf2f4c22e0f52acf559e3bc192"
EXPECTED_FUNCTION_SHA256 = "fadc98da71affdc8ec308fe1aa866c4240d211ca38d9b5aa42b61ab27a9ba431"
EXPECTED_MAIN_SHA256 = "3757e3802088f2f4d8aca18157003bdb7d91eb633f5238b2a65e5920b08802e1"
EXPECTED_COMPLETE_SHA256 = "a77067d559270c1779353d870c4663705951cea8ce19150c325014726d59629d"
EXPECTED_C03_SYNC_COMPLETE_SHA256 = (
    "c4ad483f76afdf5b5c51d1481611fa2fc59b53fda3ec1670d29473ee6d6bf376"
)
EXPECTED_C03_SYNC_VALIDATE_DOMAIN_SHA256 = (
    "bff89b7b2044d429be024a0cc1b7d1267aba9f8a089f51e138c4b672b04ff8b3"
)
EXPECTED_C03_CORPUS_COMPLETE_SHA256 = (
    "be9eb2249ff04469f4698f4f4b80d454f3bb196839b8dd0a6b8f5b31722b523d"
)
EXPECTED_C03_GATE_CACHE_KEY_SHA256 = (
    "c19afe3b84d2ee8a5138fdfe03dfe494783cf51f05c3f03a5a388df62cfea2cb"
)
EXPECTED_C03_GATE_SHA256 = (
    "363d85b93f78f0c570a627c762c226f92f7e165b887452f82a812c00d6c9e2e5"
)
EXPECTED_C03_VALIDATE_SHA256 = (
    "7c4b14bcf740c47fc7f8883e83ee95106b976d56044742a7672a7be70a178a30"
)
EXPECTED_C03_OUTPUT_BOUNDARY_SHA256 = (
    "c0f70c009f0f80e7081292fb835d326dd207e13df0d10249f8781954c41de92a"
)
MAIN_ADDITION = "        findings.extend(validate_o10_outcome_taxonomy(model, args.repo_root))\n"
ALLOWED_EXACT = frozenset(
    {
        "docs/protocol/protocol-hardening-plan.md",
        "docs/protocol/review/README.md",
        "docs/protocol/review/styx-app-kernel-v0-review-model.json",
        "docs/protocol/styx-app-kernel-v0-decisions.md",
        "docs/protocol/styx-app-kernel-v0-outcome-taxonomy.md",
        "docs/protocol/styx-app-kernel-v0-outcome-taxonomy-falsification-report.md",
        "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
        "docs/security/STYX-THREAT-MODEL.md",
        "tools/causal-flow-simulator/README.md",
        VALIDATOR_PATH,
        "tools/protocol-review-model/tests/test_o10_outcome_taxonomy.py",
        "tools/protocol-review-model/tests/fixtures/o10-outcome-taxonomy.json",
    }
)
REPORT_FIELDS = frozenset(
    {
        "changed_relation",
        "complete_source_sha256",
        "function_sha256",
        "main_sha256",
        "record_count",
        "schema",
        "verdict",
    }
)


class ScopeError(ValueError):
    """The candidate differs from the ratified scope or frozen AST."""


def _git(repo: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise ScopeError("git evidence command failed")
    return completed.stdout


def _function_segment(source: str, name: str) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ScopeError("validator source does not parse") from exc
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    if len(matches) != 1:
        raise ScopeError(f"validator function cardinality drift: {name}")
    node = matches[0]
    lines = source.splitlines(keepends=True)
    segment = "".join(lines[node.lineno - 1 : node.end_lineno])
    if node.end_lineno < len(lines) and not segment.endswith("\n\n"):
        segment += "\n"
    return segment


def expected_validator_source(before_source: str, actual_source: str) -> str:
    if hashlib.sha256(before_source.encode("utf-8")).hexdigest() != EXPECTED_BASE_SOURCE_SHA256:
        raise ScopeError("Base validator source digest drift")
    function_source = _function_segment(actual_source, "validate_o10_outcome_taxonomy")
    if hashlib.sha256(function_source.encode("utf-8")).hexdigest() != EXPECTED_FUNCTION_SHA256:
        raise ScopeError("O-10 validator function body drift")
    status_before = '        "O-10": "OPEN",\n'
    status_after = '        "O-10": "DECIDED",\n'
    if before_source.count(status_before) != 1:
        raise ScopeError("O-10 Base status anchor drift")
    expected = before_source.replace(status_before, status_after)
    gate_before = '        "C0.3_CORPUS_PATH_APPROVAL": "OPEN",\n'
    gate_after = '        "C0.3_CORPUS_PATH_APPROVAL": "DECIDED",\n'
    if expected.count(gate_before) != 1:
        raise ScopeError("C0.3 gate Base status anchor drift")
    expected = expected.replace(gate_before, gate_after)
    main_anchor = "def main(argv: list[str] | None = None) -> int:\n"
    if expected.count(main_anchor) != 1:
        raise ScopeError("main declaration anchor drift")
    expected = expected.replace(main_anchor, function_source + "\n" + main_anchor)
    call_anchor = "        findings = validate(model, schema, args.repo_root)\n"
    if expected.count(call_anchor) != 1:
        raise ScopeError("main registration anchor drift")
    expected = expected.replace(call_anchor, call_anchor + MAIN_ADDITION)
    if hashlib.sha256(expected.encode("utf-8")).hexdigest() != EXPECTED_COMPLETE_SHA256:
        raise ScopeError("complete expected validator digest drift")
    if hashlib.sha256(_function_segment(expected, "main").encode("utf-8")).hexdigest() != EXPECTED_MAIN_SHA256:
        raise ScopeError("complete expected main digest drift")
    return expected


def validate_historical_validator_delta(
    before_source: str, actual_source: str
) -> dict[str, str]:
    expected = expected_validator_source(before_source, actual_source)
    if actual_source.encode("utf-8") != expected.encode("utf-8"):
        raise ScopeError("actual validator bytes differ from complete expected bytes")
    projection = expected.replace(MAIN_ADDITION, "")
    if projection == expected or projection.count(MAIN_ADDITION):
        raise ScopeError("main projection failed")
    try:
        enforce_declared_validator_ast_delta(
            before_source,
            projection,
            projection,
            allowed_assignments={"EXPECTED_STATUS_BY_COLLECTION"},
            allowed_functions={"validate_o10_outcome_taxonomy"},
            allowed_literal_changes={
                ("EXPECTED_STATUS_BY_COLLECTION", "blockers", "O-10"),
                (
                    "EXPECTED_STATUS_BY_COLLECTION",
                    "blockers",
                    "C0.3_CORPUS_PATH_APPROVAL",
                ),
            },
            allowed_function_call_additions={},
            protected_literal_paths={
                ("EXPECTED_STATUS_BY_COLLECTION", "blockers", "O-14")
            },
        )
    except FrozenScopeViolation as exc:
        raise ScopeError("frozen O-07 AST guard rejected the projection") from exc
    return {
        "complete_source_sha256": hashlib.sha256(expected.encode("utf-8")).hexdigest(),
        "function_sha256": hashlib.sha256(
            _function_segment(expected, "validate_o10_outcome_taxonomy").encode("utf-8")
        ).hexdigest(),
        "main_sha256": hashlib.sha256(_function_segment(expected, "main").encode("utf-8")).hexdigest(),
    }


def _replace_once(source: str, before: str, after: str, label: str) -> str:
    if source.count(before) != 1:
        raise ScopeError(f"C0.3 synchronization anchor drift: {label}")
    return source.replace(before, after, 1)


def expected_c03_sync_validator_source(
    before_source: str, actual_source: str
) -> tuple[str, str]:
    """Layer the exact Issue #262 delta over the frozen O-10 validator."""

    historical = expected_validator_source(before_source, actual_source)
    expected = _replace_once(
        historical,
        '}\n\nCONTRACT_BASE_COMMIT = "ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3"\n',
        '}\n\nAUTHORIZED_UNBLOCKED_CAPABILITIES = {"corpus"}\n\n'
        'CONTRACT_BASE_COMMIT = "ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3"\n',
        "authorized capability assignment",
    )
    expected = _replace_once(
        expected,
        '    "C0.3": "294c90766317a495004a86e300e1c1b6b81de66b377cefe47676b9e67c1f6d14",\n',
        '    "C0.3": "8c825da422bcc2fe6c330353dcbb1952346ebfdc07f7df9ee65e73d5781931f5",\n',
        "C0.3 blocker-edge digest",
    )
    expected = _replace_once(
        expected,
        "        if not unresolved_gates:\n",
        "        if (\n"
        "            not unresolved_gates\n"
        "            and capability not in AUTHORIZED_UNBLOCKED_CAPABILITIES\n"
        "        ):\n",
        "authorized capability validation",
    )
    if (
        hashlib.sha256(expected.encode("utf-8")).hexdigest()
        != EXPECTED_C03_SYNC_COMPLETE_SHA256
    ):
        raise ScopeError("complete C0.3 synchronization validator digest drift")
    if (
        hashlib.sha256(
            _function_segment(expected, "validate_domain").encode("utf-8")
        ).hexdigest()
        != EXPECTED_C03_SYNC_VALIDATE_DOMAIN_SHA256
    ):
        raise ScopeError("C0.3 synchronization validate_domain function digest drift")
    return historical, expected


def validate_validator_delta(before_source: str, actual_source: str) -> dict[str, str]:
    """Validate the exact current validator while preserving frozen O-10 proof."""

    historical, synchronized = expected_c03_sync_validator_source(
        before_source, actual_source
    )
    actual_digest = hashlib.sha256(actual_source.encode("utf-8")).hexdigest()
    if actual_digest != EXPECTED_C03_CORPUS_COMPLETE_SHA256:
        raise ScopeError("actual validator bytes differ from C0.3 corpus-completion bytes")

    historical_validate = _function_segment(historical, "validate_domain")
    synchronized_validate = _function_segment(synchronized, "validate_domain")
    projection = synchronized.replace(
        synchronized_validate, historical_validate, 1
    )
    try:
        enforce_declared_validator_ast_delta(
            historical,
            projection,
            projection,
            allowed_assignments={
                "AUTHORIZED_UNBLOCKED_CAPABILITIES",
                "EXPECTED_BLOCKER_EDGES_DIGEST",
            },
            allowed_functions=set(),
            allowed_literal_changes={
                ("AUTHORIZED_UNBLOCKED_CAPABILITIES",),
                ("EXPECTED_BLOCKER_EDGES_DIGEST", "C0.3"),
            },
            allowed_function_call_additions={},
            protected_literal_paths={
                ("EXPECTED_STATUS_BY_COLLECTION", "blockers", "O-10"),
                (
                    "EXPECTED_STATUS_BY_COLLECTION",
                    "blockers",
                    "C0.3_CORPUS_PATH_APPROVAL",
                ),
                ("EXPECTED_STATUS_BY_COLLECTION", "blockers", "O-14"),
            },
        )
    except FrozenScopeViolation as exc:
        raise ScopeError(
            "frozen O-07 AST guard rejected C0.3 synchronization"
        ) from exc

    expected_functions = {
        "_c03_gate_cache_key": EXPECTED_C03_GATE_CACHE_KEY_SHA256,
        "_validate_c03_corpus_gate": EXPECTED_C03_GATE_SHA256,
        "_validate_output_boundary": EXPECTED_C03_OUTPUT_BOUNDARY_SHA256,
        "validate": EXPECTED_C03_VALIDATE_SHA256,
        "validate_domain": EXPECTED_C03_SYNC_VALIDATE_DOMAIN_SHA256,
        "validate_o10_outcome_taxonomy": EXPECTED_FUNCTION_SHA256,
    }
    for name, expected_digest in expected_functions.items():
        actual_function_digest = hashlib.sha256(
            _function_segment(actual_source, name).encode("utf-8")
        ).hexdigest()
        if actual_function_digest != expected_digest:
            raise ScopeError(f"C0.3 corpus validator function drift: {name}")
    if (
        hashlib.sha256(_function_segment(actual_source, "main").encode("utf-8")).hexdigest()
        != EXPECTED_MAIN_SHA256
    ):
        raise ScopeError("C0.3 corpus validator main function drift")
    return {
        "complete_source_sha256": actual_digest,
        "function_sha256": hashlib.sha256(
            _function_segment(actual_source, "validate_o10_outcome_taxonomy").encode("utf-8")
        ).hexdigest(),
        "main_sha256": hashlib.sha256(
            _function_segment(actual_source, "main").encode("utf-8")
        ).hexdigest(),
    }


def _allowed(path: str) -> bool:
    return path in ALLOWED_EXACT or path.startswith("tools/causal-flow-simulator/o10/")


def _blob(repo: Path, revision: str, path: str) -> bytes | None:
    completed = subprocess.run(
        ["git", "-C", str(repo), "show", f"{revision}:{path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout if completed.returncode == 0 else None


def build_report(repo: Path, base: str, candidate: str) -> dict[str, Any]:
    if base != BASE_SHA:
        raise ScopeError("contract Base mismatch")
    if _git(repo, "rev-parse", candidate).decode().strip() != candidate:
        raise ScopeError("candidate must be an exact commit identity")
    if _git(repo, "merge-base", "--is-ancestor", base, candidate) != b"":
        raise ScopeError("unexpected merge-base output")
    status = _git(repo, "diff", "--name-status", "--find-renames=25%", "--find-copies=25%", base, candidate).decode()
    changed: list[dict[str, str | None]] = []
    for line in status.splitlines():
        fields = line.split("\t")
        code = fields[0]
        if code.startswith(("R", "C")) or len(fields) != 2:
            raise ScopeError("rename/copy or malformed change record")
        path = fields[1]
        if not _allowed(path):
            raise ScopeError(f"out-of-scope path: {path}")
        before = _blob(repo, base, path)
        after = _blob(repo, candidate, path)
        changed.append(
            {
                "base_digest": hashlib.sha256(before).hexdigest() if before is not None else None,
                "final_digest": hashlib.sha256(after).hexdigest() if after is not None else None,
                "path": path,
            }
        )
    numstat = _git(repo, "diff", "--numstat", base, candidate).decode().splitlines()
    if any(line.split("\t", 2)[:2] == ["-", "-"] for line in numstat):
        raise ScopeError("binary change is forbidden")
    modes = _git(repo, "ls-tree", "-r", candidate).decode().splitlines()
    changed_paths = {item["path"] for item in changed}
    for line in modes:
        metadata, path = line.split("\t", 1)
        if path in changed_paths and not metadata.startswith("100644 "):
            raise ScopeError("non-regular changed path is forbidden")
    before_validator = _blob(repo, base, VALIDATOR_PATH)
    after_validator = _blob(repo, candidate, VALIDATOR_PATH)
    if before_validator is None or after_validator is None:
        raise ScopeError("validator blob missing")
    try:
        hashes = validate_historical_validator_delta(
            before_validator.decode("utf-8"), after_validator.decode("utf-8")
        )
    except UnicodeDecodeError as exc:
        raise ScopeError("validator is not UTF-8") from exc
    return {
        "changed_relation": sorted(changed, key=lambda item: str(item["path"])),
        **hashes,
        "record_count": len(changed),
        "schema": "styx.o10-scope-report.v1",
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--mode", required=True, choices=("strict",))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.repo_root.resolve(), args.base, args.candidate)
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (OSError, ValueError, ReportError) as exc:
        print(f"O-10 scope: FAIL: {exc}", file=sys.stderr)
        return 2
    print(f"O-10 scope: PASS records={report['record_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
