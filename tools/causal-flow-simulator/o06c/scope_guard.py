#!/usr/bin/env python3
"""Canonical path, AST, text-boundary and artifact scope guard for Issue #243."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True

from common import sha256_hex, write_report


BASE_SHA = "3f439189e0cbe4071f642c693dbb196b477a48ea"
SCHEMA = "styx-o06c-scope-report/v1"
VALIDATOR = "tools/protocol-review-model/validate.py"
REVIEW_TESTS = "tools/protocol-review-model/tests/"
ALLOWED_EXACT = {
    "docs/protocol/protocol-hardening-plan.md",
    "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
    "docs/protocol/styx-app-kernel-v0-decisions.md",
    "docs/protocol/styx-app-kernel-v0-identifier-derivation-analysis.md",
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
    "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
    "docs/protocol/styx-app-kernel-v0-identifier-commitment-falsification-report.md",
    "docs/protocol/review/README.md",
    "docs/protocol/review/styx-app-kernel-v0-review-model.json",
    "docs/security/STYX-THREAT-MODEL.md",
    "tools/causal-flow-simulator/README.md",
    VALIDATOR,
}
ALLOWED_PREFIXES = ("tools/causal-flow-simulator/o06c/", REVIEW_TESTS)
FORBIDDEN_EXACT = {
    "CODEOWNERS", "AGENTS.md", "CLAUDE.md", "LICENSE", "REUSE.toml",
    "pubspec.yaml", "package.json", "package-lock.json",
    "docs/protocol/styx-app-kernel-v0-causal-falsification-report.md",
    "docs/protocol/styx-app-kernel-v0-payload-state-falsification-report.md",
    "docs/protocol/styx-app-kernel-v0-pending-subtree-falsification-report.md",
    "docs/protocol/styx-app-kernel-v0-credential-succession-falsification-report.md",
    "docs/protocol/styx-app-kernel-v0-commitment-context-falsification-report.md",
    "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json",
    "tools/causal-flow-simulator/model.py",
    "tools/causal-flow-simulator/payload_model.py",
    "tools/causal-flow-simulator/scenarios.py",
    "tools/causal-flow-simulator/payload_scenarios.py",
    "tools/causal-flow-simulator/causal_flow_simulator.py",
}
FORBIDDEN_PREFIXES = (
    ".github/", "LICENSES/", "conformance/", "styx-js/", "packages/",
    "push_bridge_server/", "tools/causal-flow-simulator/tests/",
    "tools/causal-flow-simulator/v2/", "tools/causal-flow-simulator/v3/",
    "tools/causal-flow-simulator/c02k/",
)
ALLOWED_VALIDATOR_ASSIGNMENTS = {
    "EXPECTED_SOURCE_RECORDS",
    "CONTRACT_BASE_COMMIT",
    "EXPECTED_STATUS_BY_COLLECTION",
    "EXPECTED_IDS_BY_COLLECTION",
    "EXPECTED_INVARIANT_REFS_DIGEST",
    "EXPECTED_BLOCKER_EDGES_DIGEST",
}


class ScopeError(ValueError):
    pass


def git(repo: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *arguments])


def forbidden(path: str) -> bool:
    if path in FORBIDDEN_EXACT or path.startswith(FORBIDDEN_PREFIXES):
        return True
    name = path.rsplit("/", 1)[-1]
    if name in {"package.json", "package-lock.json", "pubspec.yaml", "pubspec.lock"}:
        return True
    if path.endswith(".wasm"):
        return True
    if path.startswith("tools/causal-flow-simulator/o06c/") and path.endswith((".json", ".bin")):
        return True
    return False


def allowed(path: str) -> bool:
    return path in ALLOWED_EXACT or path.startswith(ALLOWED_PREFIXES)


def changed_records(repo: Path, base: str, candidate: str) -> list[dict[str, object]]:
    raw = git(
        repo, "diff-tree", "-r", "-M", "-C", "--find-copies-harder",
        "--name-status", "-z", "--no-commit-id", base, candidate,
    )
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    records = []
    index = 0
    while index < len(parts):
        status = parts[index].decode("ascii")
        index += 1
        endpoint_count = 2 if status[:1] in {"R", "C"} else 1
        if index + endpoint_count > len(parts):
            raise ScopeError("truncated diff-tree relation")
        paths = [parts[index + offset].decode("utf-8") for offset in range(endpoint_count)]
        index += endpoint_count
        for path in paths:
            if forbidden(path):
                raise ScopeError(f"forbidden {status} endpoint: {path}")
            if not allowed(path):
                raise ScopeError(f"out-of-scope {status} endpoint: {path}")
        records.append({"status": status, "paths": paths})
    return records


def blob(repo: Path, revision: str, path: str) -> bytes:
    return git(repo, "cat-file", "blob", f"{revision}:{path}")


def tree_mode(repo: Path, revision: str, path: str) -> str:
    raw = git(repo, "ls-tree", revision, "--", path).decode("utf-8")
    if not raw:
        raise ScopeError(f"missing tree endpoint: {revision}:{path}")
    return raw.split(None, 1)[0]


def enforce_text_artifacts(repo: Path, base: str, candidate: str, records: list[dict[str, object]]) -> None:
    for record in records:
        status = str(record["status"])
        paths = list(record["paths"])
        endpoints: list[tuple[str, str]]
        if status.startswith(("R", "C")):
            endpoints = [(base, paths[0]), (candidate, paths[1])]
        elif status.startswith("D"):
            endpoints = [(base, paths[0])]
        else:
            endpoints = [(candidate, paths[0])]
        for revision, path in endpoints:
            mode = tree_mode(repo, revision, path)
            if mode in {"120000", "160000"}:
                raise ScopeError(f"symlink/submodule endpoint: {revision}:{path}")
            data = blob(repo, revision, path)
            if b"\0" in data:
                raise ScopeError(f"binary endpoint: {revision}:{path}")


def assignments(tree: ast.Module) -> tuple[dict[str, ast.expr | None], list[str]]:
    values = {}
    other = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            values[node.targets[0].id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            values[node.target.id] = node.value
        else:
            other.append(ast.dump(node, include_attributes=False))
    return values, other


def enforce_validator_ast(repo: Path, base: str, candidate: str) -> list[str]:
    base_assign, base_other = assignments(ast.parse(blob(repo, base, VALIDATOR)))
    head_assign, head_other = assignments(ast.parse(blob(repo, candidate, VALIDATOR)))
    if base_other != head_other:
        raise ScopeError("validator control flow/import/function/class AST drift")
    names = set(base_assign) | set(head_assign)
    changed = sorted(
        name for name in names
        if name not in base_assign or name not in head_assign
        or ast.dump(base_assign[name], include_attributes=False)
        != ast.dump(head_assign[name], include_attributes=False)
    )
    unauthorized = set(changed) - ALLOWED_VALIDATOR_ASSIGNMENTS
    if unauthorized:
        raise ScopeError("unauthorized validator assignments: " + ",".join(sorted(unauthorized)))
    for name in changed:
        try:
            ast.literal_eval(head_assign[name])
        except Exception as error:
            raise ScopeError(f"non-literal validator assignment {name}: {error}") from error
    return changed


def enforce_review_tests(repo: Path, base: str, candidate: str, records: list[dict[str, object]]) -> list[str]:
    existing = git(repo, "ls-tree", "-r", "--name-only", base, REVIEW_TESTS).decode().splitlines()
    negative_fixture = REVIEW_TESTS + "fixtures/negative-cases.json"
    for path in existing:
        if path == negative_fixture:
            continue
        if blob(repo, candidate, path) != blob(repo, base, path):
            raise ScopeError(f"pre-existing validator test/fixture drift: {path}")

    base_negative = json.loads(blob(repo, base, negative_fixture))
    head_negative_bytes = blob(repo, candidate, negative_fixture)
    head_negative = json.loads(head_negative_bytes)
    canonical_head = (
        json.dumps(head_negative, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if head_negative_bytes != canonical_head:
        raise ScopeError("negative fixture is not canonical JSON")
    if len(base_negative) != 71 or len(head_negative) != 71:
        raise ScopeError("negative fixture inventory-size drift")
    base_by_id = {case["id"]: case for case in base_negative}
    head_by_id = {case["id"]: case for case in head_negative}
    if len(base_by_id) != 71 or set(base_by_id) != set(head_by_id):
        raise ScopeError("negative fixture ID drift")
    legacy_id = "gated-capability-loses-last-open-gate"
    expected_base = {
        "expected_code": "GATED_CAPABILITY_UNBLOCKED",
        "id": legacy_id,
        "mutation": {
            "operation": "set",
            "path": "/blockers/4/blocks",
            "value": ["C0.3"],
        },
    }
    expected_head = {
        "expected_code": "GATED_CAPABILITY_UNBLOCKED",
        "id": legacy_id,
        "mutation": {
            "operation": "remove-value",
            "path": "/blockers/2/blocks",
            "value": "demo",
        },
    }
    if base_by_id.pop(legacy_id, None) != expected_base:
        raise ScopeError("unexpected base legacy gate fixture")
    if head_by_id.pop(legacy_id, None) != expected_head:
        raise ScopeError("unauthorized replacement gate fixture")
    if base_by_id != head_by_id:
        raise ScopeError("unrelated pre-existing negative fixture drift")

    new_files = []
    for record in records:
        status = str(record["status"])
        for path in record["paths"]:
            if not path.startswith(REVIEW_TESTS) or path in existing:
                continue
            relative = path[len(REVIEW_TESTS):]
            valid = (
                "/" not in relative and relative.startswith("test_o06c_") and relative.endswith(".py")
            ) or (
                relative.startswith("fixtures/o06c-") and relative.endswith(".json")
                and "/" not in relative[len("fixtures/"):]
            )
            if status[:1] != "A" or not valid:
                raise ScopeError(f"invalid new validator test artifact: {status} {path}")
            new_files.append(path)
    return sorted(set(new_files))


def normalize_regions(data: bytes, path: str, selectors: tuple[tuple[str, str | tuple[str, ...]], ...]) -> bytes:
    lines = data.decode("utf-8").splitlines(keepends=True)
    counts = [0] * len(selectors)
    output = []
    index = 0
    while index < len(lines):
        matches = []
        for selector_index, (kind, prefixes) in enumerate(selectors):
            choices = (prefixes,) if isinstance(prefixes, str) else prefixes
            if any(lines[index].startswith(prefix) for prefix in choices):
                matches.append((selector_index, kind))
        if len(matches) > 1:
            raise ScopeError(f"overlapping named regions in {path}")
        if not matches:
            output.append(lines[index])
            index += 1
            continue
        selector_index, kind = matches[0]
        counts[selector_index] += 1
        output.append(f"@@STYX_ALLOWED_REGION_{selector_index}@@\n")
        index += 1
        if kind == "bullet":
            while index < len(lines) and lines[index].startswith("  "):
                index += 1
        elif kind == "paragraph":
            while index < len(lines) and lines[index].strip():
                index += 1
        elif kind != "row":
            raise ScopeError(f"unknown region kind: {kind}")
    if any(count != 1 for count in counts):
        raise ScopeError(f"named-region selector count drift in {path}")
    return "".join(output).encode("utf-8")


REGIONS = {
    "docs/security/STYX-THREAT-MODEL.md": (
        ("bullet", "- **C0.2f/O-06 amendments:**"),
        ("bullet", "- **C0.2j amendment:**"),
        ("row", "| Payload commitment and retained opening |"),
        ("row", "| A1 malformed-input sender |"),
        ("bullet", "- C0.2a through C0.2h selected"),
    ),
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md": (
        ("bullet", "- **Status:**"), ("bullet", "- **Authority:**"),
        ("bullet", ("- **C0.2k evidence baseline:**", "- **O-06c evidence baseline:**")),
        ("bullet", "- **Decision effect:**"),
        *(("row", f"| `OB-K{number:02d}` |") for number in (5, 6, 7, 8, 9, 10, 13, 18, 19)),
        ("row", "| O-04 payload commitment/detachment |"),
        ("row", "| O-06 event/content identifiers |"),
        ("paragraph", "Security consequence:"),
    ),
}


def enforce_named_regions(repo: Path, base: str, candidate: str) -> dict[str, str]:
    digests = {}
    for path, selectors in REGIONS.items():
        before = normalize_regions(blob(repo, base, path), path, selectors)
        after = normalize_regions(blob(repo, candidate, path), path, selectors)
        if before != after:
            raise ScopeError(f"unnamed normative-document drift: {path}")
        digests[path] = sha256_hex(after)
    return digests


def build_report(repo: Path, base_argument: str, candidate_argument: str) -> dict[str, object]:
    base = git(repo, "rev-parse", f"{base_argument}^{{commit}}").decode().strip()
    candidate = git(repo, "rev-parse", f"{candidate_argument}^{{commit}}").decode().strip()
    if base_argument != BASE_SHA or base != BASE_SHA:
        raise ScopeError("contract base mismatch")
    records = changed_records(repo, base, candidate)
    enforce_text_artifacts(repo, base, candidate, records)
    validator_assignments = enforce_validator_ast(repo, base, candidate)
    new_review_tests = enforce_review_tests(repo, base, candidate, records)
    region_digests = enforce_named_regions(repo, base, candidate)
    return {
        "schema": SCHEMA,
        "base_commit": base,
        # The canonical changed relation is stable once the path set is
        # fixed.  Exact candidate commit/tree/diff identity is recorded in
        # immutable PR evidence so embedding this report digest in a
        # tracked normative document cannot create a hash fixed-point.
        "candidate_identity_location": "immutable_pr_evidence",
        "changed_relation": records,
        "changed_endpoint_count": sum(len(record["paths"]) for record in records),
        "validator_assignments_changed": validator_assignments,
        "new_review_tests": new_review_tests,
        "normalized_region_sha256": region_digests,
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    repo = args.repo_root.resolve()
    try:
        report = build_report(repo, args.base, args.candidate)
        write_report(args.output, report)
    except (ScopeError, OSError, UnicodeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"O-06c scope failure: {error}", file=sys.stderr)
        return 2
    print(
        "O-06c scope verdict=PASS "
        f"records={len(report['changed_relation'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
