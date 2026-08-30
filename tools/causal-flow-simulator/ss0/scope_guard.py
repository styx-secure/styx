#!/usr/bin/env python3
"""Fail-closed SS-0 scope and frozen-byte guard."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from canonical_report import store
from inventory import load_unique


BASE_SHA = "bd13fac2df51e8585db6487fff7217fb68fb6242"
PHASE_A_SHA = "bd9a06f08131c6fcd4edbaa1e0eeae38d8e28eb5"
MODEL_SYNC_SHA = "c8430b2fbcb4bd9d0668e5877210d0244ff8bf81"
VALIDATOR_SHA256 = "e79caecde38c457ed79036d339c67b7aa7a394e37708ba76f0aa715ce0092f3b"
VALIDATE_DOMAIN_SHA256 = "f31ebaa85d6a5247772a38ee7fbb1ea3addcf4bae55ec6db86259e31913786c5"
TEST_VALIDATE_SHA256 = "b96634a57f47b6e0526177870efb218f11a61efe4949e6ec2701a774fcca1ed3"

FROZEN_PHASE_A = frozenset(
    {
        "docs/protocol/protocol-hardening-plan.md",
        "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
        "docs/protocol/styx-secure-session-v0-decisions.md",
        "docs/security/STYX-THREAT-MODEL.md",
        "tools/causal-flow-simulator/ss0/verify_gate_a.py",
    }
)
ALLOWED_EXACT = frozenset(
    {
        *FROZEN_PHASE_A,
        "docs/protocol/review/README.md",
        "docs/protocol/review/styx-app-kernel-v0-review-model.json",
        "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json",
        "tools/causal-flow-simulator/README.md",
        "tools/causal-flow-simulator/o10/scope_guard.py",
        "tools/protocol-review-model/tests/fixtures/negative-cases.json",
        "tools/protocol-review-model/tests/test_c03_corpus_path_approval.py",
        "tools/protocol-review-model/tests/test_secure_session_profile.py",
        "tools/protocol-review-model/tests/test_validate.py",
        "tools/protocol-review-model/validate.py",
    }
)
ALLOWED_PREFIX = "tools/causal-flow-simulator/ss0/"
FORBIDDEN_PREFIXES = (
    ".github/",
    "conformance/",
    "docs/archive/",
    "packages/",
    "push_bridge/",
    "push_bridge_server/",
    "specs/",
    "styx-js/",
    "tools/causal-flow-simulator/o06c/",
    "tools/causal-flow-simulator/o07/",
    "tools/causal-flow-simulator/o08/",
    "tools/causal-flow-simulator/o10/tests/",
    "vendor/",
    "website/",
)
FORBIDDEN_LOCKFILES = frozenset(
    {
        "Cargo.lock",
        "Gemfile.lock",
        "Pipfile.lock",
        "bun.lock",
        "bun.lockb",
        "composer.lock",
        "npm-shrinkwrap.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pubspec.lock",
        "uv.lock",
        "yarn.lock",
    }
)
FORBIDDEN_RUNTIME_MANIFESTS = frozenset(
    {
        "Cargo.toml",
        "Gemfile",
        "Pipfile",
        "composer.json",
        "package.json",
        "pubspec.yaml",
        "pyproject.toml",
    }
)


class ScopeViolation(ValueError):
    pass


def _git(repo: Path, *arguments: str) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    completed = subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=repo,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise ScopeViolation("git operation failed")
    return completed.stdout


def _top_level(tree: ast.Module) -> dict[tuple[str, str], ast.AST]:
    records: dict[tuple[str, str], ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            records[("function", node.name)] = node
        elif isinstance(node, ast.ClassDef):
            records[("class", node.name)] = node
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    records[("assignment", target.id)] = node
    return records


def _function_segment(source: str, name: str) -> str:
    matches = [
        node
        for node in ast.parse(source).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    if len(matches) != 1:
        raise ScopeViolation(f"validator function cardinality drift: {name}")
    node = matches[0]
    lines = source.splitlines(keepends=True)
    segment = "".join(lines[node.lineno - 1 : node.end_lineno])
    if node.end_lineno < len(lines) and not segment.endswith("\n\n"):
        segment += "\n"
    return segment


def _load_o07_guard(repo: Path) -> Any:
    path = repo / "tools/causal-flow-simulator/o07/scope_guard_o07.py"
    sys.path.insert(0, str(path.parent))
    try:
        specification = importlib.util.spec_from_file_location("_styx_o07_frozen_guard", path)
        if specification is None or specification.loader is None:
            raise ScopeViolation("cannot load frozen O-07 guard")
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def _assignment_value(node: ast.AST) -> ast.AST:
    if isinstance(node, ast.Assign):
        return node.value
    if isinstance(node, ast.AnnAssign):
        return node.value
    raise ScopeViolation("not an assignment")


def _registry_decisions(node: ast.AST) -> list[str]:
    value = _assignment_value(node)
    if not isinstance(value, ast.Dict):
        raise ScopeViolation("registry assignment is not a dictionary")
    for key, child in zip(value.keys, value.values, strict=True):
        if isinstance(key, ast.Constant) and key.value == "decisions":
            result = ast.literal_eval(child)
            if not isinstance(result, list) or not all(isinstance(item, str) for item in result):
                raise ScopeViolation("decision registry is not a literal string list")
            return result
    raise ScopeViolation("decision registry is absent")


def _validate_disposition_disjointness(repo: Path) -> None:
    inventory = load_unique(repo / "tools/causal-flow-simulator/ss0/source-inventory.json")
    taxonomy = load_unique(repo / "tools/causal-flow-simulator/o10/outcome-taxonomy.json")
    dispositions = inventory.get("closed_dispositions")
    primaries = taxonomy.get("primaries")
    alias = taxonomy.get("alias")
    markers = taxonomy.get("post_c03_markers")
    remote = taxonomy.get("remote_collapse")
    if (
        not isinstance(dispositions, list)
        or not dispositions
        or any(not isinstance(item, str) or not item for item in dispositions)
        or len(dispositions) != len(set(dispositions))
        or not isinstance(primaries, list)
        or any(not isinstance(item, dict) or not isinstance(item.get("id"), str) for item in primaries)
        or not isinstance(alias, dict)
        or set(alias) != {"id", "primary"}
        or any(not isinstance(alias[item], str) for item in alias)
        or not isinstance(markers, list)
        or any(not isinstance(item, str) for item in markers)
        or not isinstance(remote, str)
    ):
        raise ScopeViolation("SS-0 or O-10 disposition registry shape mismatch")
    o10_identifiers = {
        *(item["id"] for item in primaries),
        alias["id"],
        alias["primary"],
        *markers,
        remote,
    }
    overlap = set(dispositions) & o10_identifiers
    if overlap:
        raise ScopeViolation("SS-0 model-only dispositions overlap the stable O-10 registry")


def _validate_frozen_bytes(
    repo: Path, before: str, after: str, paths: frozenset[str] = FROZEN_PHASE_A
) -> None:
    for path in paths:
        if _git(repo, "show", f"{before}:{path}") != _git(repo, "show", f"{after}:{path}"):
            raise ScopeViolation("Gate-A-frozen byte drift")


def _validate_validator_projection(repo: Path, base: str, head: str) -> None:
    path = "tools/protocol-review-model/validate.py"
    before_source = _git(repo, "show", f"{base}:{path}").decode("utf-8")
    actual_source = _git(repo, "show", f"{head}:{path}").decode("utf-8")
    if hashlib.sha256(actual_source.encode()).hexdigest() != VALIDATOR_SHA256:
        raise ScopeViolation("complete SS-0 validator digest mismatch")
    before_tree = ast.parse(before_source)
    actual_tree = ast.parse(actual_source)
    before = _top_level(before_tree)
    actual = _top_level(actual_tree)
    changed = {
        coordinate
        for coordinate in set(before) | set(actual)
        if coordinate not in before
        or coordinate not in actual
        or ast.dump(before[coordinate], include_attributes=False)
        != ast.dump(actual[coordinate], include_attributes=False)
    }
    assignments = {
        "APPLICATION_KERNEL_DECISIONS",
        "EXPECTED_DECISION_SOURCES",
        "EXPECTED_MODELED_SCOPE",
        "EXPECTED_REGISTRIES",
        "EXPECTED_SCHEMA_SHA256",
        "EXPECTED_SOURCE_RECORDS",
        "EXPECTED_SS_DECISION_REFS",
        "EXPECTED_SS_FORBIDDEN_INFERENCES",
        "EXPECTED_SS_OBLIGATION_REFS",
        "SECURE_SESSION_EVIDENCE_DECISIONS",
    }
    expected_changed = {("assignment", name) for name in assignments} | {
        ("function", "validate_domain")
    }
    if changed != expected_changed:
        raise ScopeViolation("undeclared complete validator AST drift")
    decisions = _registry_decisions(actual[("assignment", "EXPECTED_REGISTRIES")])
    base_decisions = _registry_decisions(before[("assignment", "EXPECTED_REGISTRIES")])
    if decisions != [*base_decisions, *(f"SSD-{index:02d}" for index in range(1, 12))]:
        raise ScopeViolation("secure-session decision registry projection mismatch")
    function_digest = hashlib.sha256(
        _function_segment(actual_source, "validate_domain").encode("utf-8")
    ).hexdigest()
    if function_digest != VALIDATE_DOMAIN_SHA256:
        raise ScopeViolation("validate_domain projection digest mismatch")

    projected = copy.deepcopy(actual_tree)
    projected_records = _top_level(projected)
    for coordinate in (
        ("assignment", "EXPECTED_REGISTRIES"),
        ("function", "validate_domain"),
    ):
        replacement = copy.deepcopy(before[coordinate])
        target = projected_records[coordinate]
        index = projected.body.index(target)
        projected.body[index] = replacement
    projected_source = ast.unparse(ast.fix_missing_locations(projected))
    guard = _load_o07_guard(repo)
    allowed_assignments = assignments - {"EXPECTED_REGISTRIES"}
    guard.enforce_declared_validator_ast_delta(
        before_source,
        projected_source,
        projected_source,
        allowed_assignments=allowed_assignments,
        allowed_functions=frozenset(),
        allowed_literal_changes={
            ("APPLICATION_KERNEL_DECISIONS",),
            ("EXPECTED_DECISION_SOURCES",),
            ("EXPECTED_MODELED_SCOPE",),
            ("EXPECTED_SCHEMA_SHA256",),
            ("EXPECTED_SOURCE_RECORDS", "secure_session_decisions"),
            ("EXPECTED_SS_DECISION_REFS",),
            ("EXPECTED_SS_FORBIDDEN_INFERENCES",),
            ("EXPECTED_SS_OBLIGATION_REFS",),
            ("SECURE_SESSION_EVIDENCE_DECISIONS",),
        },
        allowed_function_call_additions={},
        protected_literal_paths=frozenset(),
    )


def _changed_relation(repo: Path, base: str, head: str) -> list[dict[str, object]]:
    fields = _git(
        repo,
        "-c",
        "diff.renameLimit=0",
        "diff-tree",
        "-r",
        "--no-commit-id",
        "--name-status",
        "-z",
        "-M",
        "-C",
        "--find-copies-harder",
        "-l0",
        base,
        head,
    ).split(b"\0")
    if fields and not fields[-1]:
        fields.pop()
    relation: list[dict[str, object]] = []
    cursor = 0
    while cursor < len(fields):
        status = fields[cursor].decode("ascii")
        cursor += 1
        width = 2 if status[0] in "CR" else 1
        endpoints = [fields[cursor + offset].decode("utf-8") for offset in range(width)]
        cursor += width
        if status[0] in "CR":
            raise ScopeViolation("copy or rename relation is forbidden")
        if status[0] == "D":
            raise ScopeViolation("deletion is forbidden")
        for endpoint in endpoints:
            leaf = endpoint.rsplit("/", 1)[-1]
            if (
                endpoint.startswith(FORBIDDEN_PREFIXES)
                or endpoint in {"CODEOWNERS", "LICENSING.md", "REUSE.toml"}
                or endpoint.endswith((".lock", ".wasm"))
                or leaf in FORBIDDEN_LOCKFILES
                or leaf in FORBIDDEN_RUNTIME_MANIFESTS
            ):
                raise ScopeViolation("forbidden endpoint")
            if endpoint not in ALLOWED_EXACT and not endpoint.startswith(ALLOWED_PREFIX):
                raise ScopeViolation("out-of-scope endpoint")
            row = _git(repo, "ls-tree", head, "--", endpoint).decode().strip()
            if not row:
                raise ScopeViolation("missing changed endpoint")
            mode, kind, _object_id = row.split("\t", 1)[0].split()
            if kind != "blob" or mode not in {"100644", "100755"}:
                raise ScopeViolation("non-regular endpoint")
            payload = _git(repo, "show", f"{head}:{endpoint}")
            if b"\0" in payload:
                raise ScopeViolation("binary endpoint")
        relation.append({"endpoints": endpoints, "status": status})
    if not relation:
        raise ScopeViolation("empty changed relation")
    return relation


def build_report(repo: Path, base: str, head: str, phase_a: str) -> dict[str, object]:
    if base != BASE_SHA or phase_a != PHASE_A_SHA:
        raise ScopeViolation("contract identity mismatch")
    if _git(repo, "merge-base", base, head).decode().strip() != base:
        raise ScopeViolation("candidate is not descended from Base")
    if _git(repo, "merge-base", MODEL_SYNC_SHA, head).decode().strip() != MODEL_SYNC_SHA:
        raise ScopeViolation("candidate is not descended from the model-sync commit")
    relation = _changed_relation(repo, base, head)
    _validate_frozen_bytes(repo, phase_a, head)
    _validate_validator_projection(repo, base, head)
    test_validate_path = "tools/protocol-review-model/tests/test_validate.py"
    model_sync_test = _git(repo, "show", f"{MODEL_SYNC_SHA}:{test_validate_path}")
    candidate_test = _git(repo, "show", f"{head}:{test_validate_path}")
    if model_sync_test != candidate_test:
        raise ScopeViolation("test_validate.py drift after the model-sync commit")
    if hashlib.sha256(candidate_test).hexdigest() != TEST_VALIDATE_SHA256:
        raise ScopeViolation("test_validate.py digest mismatch")
    model = load_unique(repo / "docs/protocol/review/styx-app-kernel-v0-review-model.json")
    if model.get("artifact", {}).get("c03_verdict") != "NO_GO":
        raise ScopeViolation("C0.3 verdict drift")
    if "implementation_alignment" in model.get("authorized_unblocked_capabilities", []):
        raise ScopeViolation("implementation alignment became authorized")
    _validate_disposition_disjointness(repo)
    return {
        "changed": relation,
        "result": "PASS",
        "schema": "styx.ss0.scope-report.v1",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--phase-a-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    repo = arguments.repo.resolve(strict=True)
    store(build_report(repo, arguments.base, arguments.head, arguments.phase_a_head), arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
