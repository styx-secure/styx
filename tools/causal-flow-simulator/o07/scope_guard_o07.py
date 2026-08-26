#!/usr/bin/env python3
"""Fail-closed path, provenance and literal-delta guard for Issue #248."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys


sys.dont_write_bytecode = True

from report_schema import (
    FinalEvidenceIdentityContext,
    SCOPE_SCHEMA,
    final_evidence_hygiene_context,
    validate_canonical_report,
)

BASE_SHA = "86c3f2dbd630e445d737a25c09889de2777ee185"
COPY_THRESHOLD = 25
REPORT_SCHEMA = SCOPE_SCHEMA
VALIDATOR_PATH = "tools/protocol-review-model/validate.py"
MODEL_PATH = "docs/protocol/review/styx-app-kernel-v0-review-model.json"
O07_PREFIX = "tools/causal-flow-simulator/o07/"
PREDECESSOR_REVIEW_TEST_PREFIX = "tools/protocol-review-model/tests/"
EXPECTED_PREDECESSOR_TEST_MODULES = 3

ALLOWED_FILES = frozenset(
    {
        "docs/protocol/protocol-hardening-plan.md",
        "docs/protocol/review/README.md",
        MODEL_PATH,
        "docs/protocol/styx-app-kernel-v0-decisions.md",
        "docs/protocol/styx-app-kernel-v0-genesis-checkpoint-analysis.md",
        "docs/protocol/styx-app-kernel-v0-genesis-checkpoint-falsification-report.md",
        "docs/protocol/styx-app-kernel-v0-identifier-derivation-analysis.md",
        "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
        "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
        "docs/security/STYX-THREAT-MODEL.md",
        "tools/causal-flow-simulator/README.md",
        VALIDATOR_PATH,
    }
)
ALLOWED_TREES = (O07_PREFIX, "tools/protocol-review-model/tests/")
FORBIDDEN_FILES = frozenset(
    {
        "AGENTS.md",
        "CLAUDE.md",
        "CODEOWNERS",
        "LICENSE",
        "LICENSING.md",
        "REUSE.toml",
        "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json",
        "package-lock.json",
        "package.json",
        "pubspec.yaml",
        "tools/causal-flow-simulator/causal_flow_simulator.py",
        "tools/causal-flow-simulator/model.py",
        "tools/causal-flow-simulator/payload_model.py",
        "tools/causal-flow-simulator/payload_scenarios.py",
        "tools/causal-flow-simulator/scenarios.py",
    }
)
FORBIDDEN_TREES = (
    ".github/",
    "LICENSES/",
    "conformance/",
    "packages/",
    "push_bridge_server/",
    "specs/",
    "styx-js/",
    "tools/causal-flow-simulator/c02k/",
    "tools/causal-flow-simulator/o06c/",
    "tools/causal-flow-simulator/o14/",
    "tools/causal-flow-simulator/tests/",
    "tools/causal-flow-simulator/v2/",
    "tools/causal-flow-simulator/v3/",
)

EXPECTED_ARTIFACT_SHA256 = {
    "docs/protocol/protocol-hardening-plan.md": "f1807c555d147ee55b8bc3bcb960459306c9ed0017f4a2bab51afdf4ec4ee904",
    "docs/protocol/review/README.md": "05ccd3af87bcf43c8fbdc2a622c9a3fbdf02929901e326ffefadb504c59d7a4c",
    MODEL_PATH: "9984ff007f10d24811bc3dae211825cbeae20134ab713d48223d806d13c907a2",
    "docs/protocol/styx-app-kernel-v0-decisions.md": "9d8aac228077e8614f3b63af2cf43327dc26440793ba213f971703f3f3d51ddd",
    "docs/protocol/styx-app-kernel-v0-genesis-checkpoint-analysis.md": "7758c6d0bdbbc1eb2ebbe93fac85c94d056ecaab744c1700de21160f3dc9e63e",
    "docs/protocol/styx-app-kernel-v0-genesis-checkpoint-falsification-report.md": "c3f96e79dcf8d7f5d96d5a7165b7b8b7ca4fd08c19a64317c16223e4e59208e0",
    "docs/protocol/styx-app-kernel-v0-identifier-derivation-analysis.md": "a2fdef0e9daad20ea62e2f511c29d0b6517b86550b98572e58518039c0d2dec0",
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md": "7d1e10e9d89fbac35082ad823176c58b29835d07b9b4ee4057aa7f02c6230bec",
    "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md": "ad68985fde0c0d3bcc5916446ff04c7c1a3572f8147c3522fde5b6496166eecf",
    "docs/security/STYX-THREAT-MODEL.md": "c6599f136ca222b9e1739c714c9339b4fd181c5af779b776f597e2a65763e5f5",
    "tools/causal-flow-simulator/README.md": "e8cd3cabca3899e928c2a75199c5e496101e798a5a69f03a5d278df9f34faded",
}


class ScopeViolation(ValueError):
    """A contract boundary was crossed."""


def _git(repo: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _commit(repo: Path, expression: str) -> str:
    return _git(repo, "rev-parse", f"{expression}^{{commit}}").stdout.decode().strip()


def _blob(repo: Path, revision: str, path: str) -> bytes:
    return _git(repo, "cat-file", "blob", f"{revision}:{path}").stdout


def _tree_entry(repo: Path, revision: str, path: str) -> tuple[str, str]:
    line = _git(repo, "ls-tree", revision, "--", path).stdout.decode().strip()
    if not line:
        raise ScopeViolation(f"missing endpoint: {revision}:{path}")
    metadata, _ = line.split("\t", 1)
    mode, kind, object_id = metadata.split()
    if kind != "blob":
        raise ScopeViolation(f"non-blob endpoint: {revision}:{path}")
    return mode, object_id


def _path_is_allowed(path: str) -> bool:
    return path in ALLOWED_FILES or path.startswith(ALLOWED_TREES)


def _path_is_forbidden(path: str) -> bool:
    leaf = path.rsplit("/", 1)[-1]
    return (
        path in FORBIDDEN_FILES
        or path.startswith(FORBIDDEN_TREES)
        or leaf in {"package.json", "package-lock.json", "pubspec.yaml", "pubspec.lock"}
        or path.endswith(".wasm")
    )


def changed_relation(repo: Path, base: str, candidate: str) -> list[dict[str, object]]:
    command = (
        "diff-tree",
        "-r",
        f"--find-renames={COPY_THRESHOLD}%",
        f"--find-copies={COPY_THRESHOLD}%",
        "--find-copies-harder",
        "-l0",
        "--name-status",
        "-z",
        "--no-commit-id",
        base,
        candidate,
    )
    fields = _git(repo, *command).stdout.split(b"\0")
    if fields and not fields[-1]:
        fields.pop()
    relation: list[dict[str, object]] = []
    cursor = 0
    while cursor < len(fields):
        status = fields[cursor].decode("ascii")
        cursor += 1
        width = 2 if status[:1] in {"C", "R"} else 1
        if cursor + width > len(fields):
            raise ScopeViolation("truncated git relation")
        paths = [fields[cursor + offset].decode("utf-8") for offset in range(width)]
        cursor += width
        if status[:1] in {"C", "R"}:
            raise ScopeViolation(f"copy/rename relation forbidden at 25%: {status} {paths}")
        for path in paths:
            if _path_is_forbidden(path):
                raise ScopeViolation(f"forbidden {status} endpoint: {path}")
            if not _path_is_allowed(path):
                raise ScopeViolation(f"out-of-scope {status} endpoint: {path}")
        relation.append({"status": status, "paths": paths})
    return relation


def _base_blob_ids(repo: Path, base: str) -> set[str]:
    records = _git(repo, "ls-tree", "-r", "-z", base).stdout.split(b"\0")
    result: set[str] = set()
    for record in records:
        if not record:
            continue
        metadata = record.split(b"\t", 1)[0].decode("ascii")
        _, kind, object_id = metadata.split()
        if kind == "blob":
            result.add(object_id)
    return result


def enforce_endpoint_types_and_identity(
    repo: Path,
    base: str,
    candidate: str,
    relation: list[dict[str, object]],
) -> None:
    base_ids = _base_blob_ids(repo, base)
    for record in relation:
        status = str(record["status"])
        path = str(record["paths"][0])
        revision = base if status.startswith("D") else candidate
        mode, object_id = _tree_entry(repo, revision, path)
        if mode in {"120000", "160000"}:
            raise ScopeViolation(f"symlink/submodule endpoint: {revision}:{path}")
        content = _blob(repo, revision, path)
        if b"\0" in content:
            raise ScopeViolation(f"binary endpoint: {revision}:{path}")
        if status.startswith("A") and path.startswith(O07_PREFIX) and object_id in base_ids:
            raise ScopeViolation(f"byte-identical O-07 Base blob: {path}")


def _assignments(source: str) -> tuple[dict[str, ast.expr | None], list[str]]:
    assigned: dict[str, ast.expr | None] = {}
    fixed_nodes: list[str] = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            assigned[node.targets[0].id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            assigned[node.target.id] = node.value
        else:
            fixed_nodes.append(ast.dump(node, include_attributes=False))
    return assigned, fixed_nodes


def _literal(assignments: dict[str, ast.expr | None], name: str) -> object:
    node = assignments.get(name)
    if node is None:
        raise ScopeViolation(f"missing validator assignment: {name}")
    try:
        return ast.literal_eval(node)
    except Exception as error:
        raise ScopeViolation(f"non-literal validator assignment: {name}") from error


def _expected_validator_values(base_values: dict[str, object]) -> dict[str, object]:
    expected: dict[str, object] = {}
    expected["CONTRACT_BASE_COMMIT"] = BASE_SHA

    sources = dict(base_values["EXPECTED_SOURCE_RECORDS"])
    sources.update(
        {
            "genesis_checkpoint_analysis": (
                "docs/protocol/styx-app-kernel-v0-genesis-checkpoint-analysis.md",
                "evidence",
            ),
            "genesis_checkpoint_report": (
                "docs/protocol/styx-app-kernel-v0-genesis-checkpoint-falsification-report.md",
                "evidence",
            ),
        }
    )
    expected["EXPECTED_SOURCE_RECORDS"] = sources

    statuses = copy.deepcopy(base_values["EXPECTED_STATUS_BY_COLLECTION"])
    statuses["blockers"]["O-07"] = "DECIDED"
    statuses["objects"]["checkpoint_evidence"] = "DECIDED"
    statuses["objects"]["genesis"] = "DECIDED"
    statuses["objects"]["genesis_acceptance_record"] = "DECIDED"
    statuses["residual_risks"]["RR_CHECKPOINT_STALENESS"] = "DECIDED"
    expected["EXPECTED_STATUS_BY_COLLECTION"] = statuses

    field_status = dict(base_values["EXPECTED_FIELD_STATUS"])
    for locator in (
        ("application_event", "genesis_reference"),
        ("checkpoint_evidence", "checkpoint_evidence_refs"),
        ("checkpoint_evidence", "replay_dependency_refs"),
        ("genesis", "derived_genesis_reference"),
        ("genesis", "genesis_body"),
    ):
        field_status[locator] = "DECIDED"
    for field in (
        "context_tuple",
        "expected_genesis_reference",
        "explicit_authorization_decision",
    ):
        field_status[("genesis_acceptance_record", field)] = "DECIDED"
    expected["EXPECTED_FIELD_STATUS"] = field_status

    digests = dict(base_values["EXPECTED_FIELD_SECURITY_DIGEST"])
    digests.update(
        {
            ("checkpoint_evidence", "checkpoint_evidence_refs"): "10a378b1809bbe2ee68902272d4b25bd2a319b59b2ae05b119e93041adf716ca",
            ("checkpoint_evidence", "replay_dependency_refs"): "dc56049d58952c866d9ffd2f9ab1b4be29508175413b898076c68f14e94237bd",
            ("genesis", "genesis_body"): "35db5f5cfde0fd3974c7dad5091ae95a16aa771ac3d382bb767aede8b57a48b5",
            ("genesis_acceptance_record", "context_tuple"): "05ee23d3b43ecb84653a1e55ca65d1e489ff3769884d88385bd7cd853b03191d",
            ("genesis_acceptance_record", "expected_genesis_reference"): "05ee23d3b43ecb84653a1e55ca65d1e489ff3769884d88385bd7cd853b03191d",
            ("genesis_acceptance_record", "explicit_authorization_decision"): "425959aafb7d75d7ff918d5f82417f21392cf1e6106bc2bae0257f874197ea39",
        }
    )
    expected["EXPECTED_FIELD_SECURITY_DIGEST"] = digests

    counterexamples = copy.deepcopy(base_values["EXPECTED_COUNTEREXAMPLE_BLOCKS"])
    counterexamples["CE_CHECKPOINT_STALE"] = ["O-08"]
    expected["EXPECTED_COUNTEREXAMPLE_BLOCKS"] = counterexamples

    protected = set(base_values["PROTECTED_UNRESOLVED_FIELDS"])
    removed = {
        ("application_event", "genesis_reference"),
        ("genesis", "derived_genesis_reference"),
        ("genesis", "genesis_body"),
    }
    result = protected - removed
    if len(result) != len(protected) - 3 or protected - result != removed:
        raise ScopeViolation("internal protected-set expectation is not exact")
    expected["PROTECTED_UNRESOLVED_FIELDS"] = result
    return expected


def enforce_validator_delta(repo: Path, base: str, candidate: str) -> list[str]:
    before = _blob(repo, base, VALIDATOR_PATH).decode("utf-8")
    after = _blob(repo, candidate, VALIDATOR_PATH).decode("utf-8")
    before_assign, before_fixed = _assignments(before)
    after_assign, after_fixed = _assignments(after)
    if before_fixed != after_fixed:
        raise ScopeViolation("validator control-flow/import/function/class AST drift")
    all_names = set(before_assign) | set(after_assign)
    changed = sorted(
        name
        for name in all_names
        if name not in before_assign
        or name not in after_assign
        or ast.dump(before_assign[name], include_attributes=False)
        != ast.dump(after_assign[name], include_attributes=False)
    )
    required = {
        "CONTRACT_BASE_COMMIT",
        "EXPECTED_COUNTEREXAMPLE_BLOCKS",
        "EXPECTED_FIELD_SECURITY_DIGEST",
        "EXPECTED_FIELD_STATUS",
        "EXPECTED_SOURCE_RECORDS",
        "EXPECTED_STATUS_BY_COLLECTION",
        "PROTECTED_UNRESOLVED_FIELDS",
    }
    if set(changed) != required:
        raise ScopeViolation("validator assignment delta is not exact: " + ",".join(changed))
    base_values = {name: _literal(before_assign, name) for name in required}
    expected = _expected_validator_values(base_values)
    for name in sorted(required):
        if _literal(after_assign, name) != expected[name]:
            raise ScopeViolation(f"validator literal delta is not exact: {name}")
    return changed


def enforce_exact_artifacts(repo: Path, candidate: str) -> dict[str, str]:
    observed: dict[str, str] = {}
    for path, expected in sorted(EXPECTED_ARTIFACT_SHA256.items()):
        digest = hashlib.sha256(_blob(repo, candidate, path)).hexdigest()
        if digest != expected:
            raise ScopeViolation(f"approved normative artifact drift: {path}")
        observed[path] = digest
    return observed


def enforce_predecessor_test_integrity(
    repo: Path, base: str, candidate: str
) -> dict[str, str]:
    """Require every pre-existing review test blob to remain byte-identical.

    Issue #248 permits additive review tests, but it does not permit an O-07
    change to delete, skip or weaken a predecessor assertion.  Pinning every
    tracked Base blob under the predecessor test tree is deliberately stronger
    than trying to infer whether an arbitrary source edit is a weakening.
    """

    listing = _git(
        repo,
        "ls-tree",
        "-r",
        "--name-only",
        base,
        "--",
        PREDECESSOR_REVIEW_TEST_PREFIX,
    ).stdout.decode().splitlines()
    if not listing:
        raise ScopeViolation("missing predecessor review-test inventory")

    candidate_listing = _git(
        repo,
        "ls-tree",
        "-r",
        "--name-only",
        candidate,
        "--",
        PREDECESSOR_REVIEW_TEST_PREFIX,
    ).stdout.decode().splitlines()
    candidate_test_modules = [
        path
        for path in candidate_listing
        if path.rsplit("/", 1)[-1].startswith("test_") and path.endswith(".py")
    ]
    if len(candidate_test_modules) != EXPECTED_PREDECESSOR_TEST_MODULES:
        raise ScopeViolation("predecessor review-test module count changed")

    observed: dict[str, str] = {}
    for path in sorted(listing):
        base_mode, base_object_id = _tree_entry(repo, base, path)
        try:
            candidate_mode, candidate_object_id = _tree_entry(repo, candidate, path)
        except (ScopeViolation, subprocess.CalledProcessError) as error:
            raise ScopeViolation(f"predecessor review test deleted: {path}") from error
        if candidate_mode != base_mode or candidate_object_id != base_object_id:
            raise ScopeViolation(f"predecessor review test changed: {path}")
        observed[path] = base_object_id
    return observed


def enforce_predecessor_isolation(repo: Path, candidate: str) -> None:
    listing = _git(repo, "ls-tree", "-r", "--name-only", candidate).stdout.decode().splitlines()
    source_suffixes = (".dart", ".js", ".mjs", ".py", ".ts")
    needles = ("causal-flow-simulator/o07", "causal_flow_simulator.o07", "from o07", "import o07")
    offenders: list[str] = []
    for path in listing:
        if path.startswith(O07_PREFIX) or not path.endswith(source_suffixes):
            continue
        text = _blob(repo, candidate, path).decode("utf-8", errors="strict")
        if any(needle in text for needle in needles):
            offenders.append(path)
    if offenders:
        raise ScopeViolation("O-07 imported outside its package: " + ",".join(sorted(offenders)))


def enforce_test_authenticator_isolation(repo: Path, candidate: str) -> None:
    """Keep the Python test ceremony issuer inside tests and test_helpers."""

    listing = _git(
        repo, "ls-tree", "-r", "--name-only", candidate, "--", O07_PREFIX
    ).stdout.decode().splitlines()
    forbidden_symbols = {
        "_TestBoundaryController",
        "_new_test_acceptance_domain",
        "_new_test_foreign_boundary_controller",
    }
    offenders: list[str] = []
    for path in listing:
        if not path.endswith(".py"):
            continue
        relative = path.removeprefix(O07_PREFIX)
        if relative.startswith("tests/") or relative.startswith("test_helpers/"):
            continue
        tree = ast.parse(_blob(repo, candidate, path).decode("utf-8"), filename=path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                imported = {alias.name for alias in node.names}
                if module.endswith("test_helpers.ceremony") or imported & forbidden_symbols:
                    offenders.append(path)
                    break
            if isinstance(node, ast.Import):
                if any(alias.name.endswith("test_helpers.ceremony") for alias in node.names):
                    offenders.append(path)
                    break
            if isinstance(node, ast.Attribute) and node.attr in forbidden_symbols:
                offenders.append(path)
                break
    if offenders:
        raise ScopeViolation(
            "test-only ceremony authenticator escaped its harness: "
            + ",".join(sorted(set(offenders)))
        )


def validate_scope_report(
    report: dict[str, object],
    *,
    hygiene_context: FinalEvidenceIdentityContext,
) -> dict[str, object]:
    return validate_canonical_report(report, hygiene_context=hygiene_context)


def build_report(
    repo: Path,
    base_argument: str,
    candidate_argument: str,
    *,
    hygiene_context: FinalEvidenceIdentityContext,
) -> dict[str, object]:
    base = _commit(repo, base_argument)
    candidate = _commit(repo, candidate_argument)
    if base_argument != BASE_SHA or base != BASE_SHA:
        raise ScopeViolation("contract base mismatch")
    relation = changed_relation(repo, base, candidate)
    enforce_endpoint_types_and_identity(repo, base, candidate, relation)
    validator_assignments = enforce_validator_delta(repo, base, candidate)
    artifact_digests = enforce_exact_artifacts(repo, candidate)
    predecessor_test_blobs = enforce_predecessor_test_integrity(repo, base, candidate)
    enforce_predecessor_isolation(repo, candidate)
    enforce_test_authenticator_isolation(repo, candidate)
    report = {
        "schema": REPORT_SCHEMA,
        "copy_threshold_percent": COPY_THRESHOLD,
        "changed_relation": relation,
        "changed_endpoint_count": sum(len(item["paths"]) for item in relation),
        "validator_assignments_changed": validator_assignments,
        "approved_artifact_count": len(artifact_digests),
        "predecessor_review_test_count": len(predecessor_test_blobs),
        "byte_identical_o07_base_blob_count": 0,
        "predecessor_import_count": 0,
        "verdict": "PASS",
    }
    validate_scope_report(
        report,
        hygiene_context=hygiene_context,
    )
    return report


def _store(path: Path, report: dict[str, object]) -> None:
    encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    path.write_bytes(encoded.encode("utf-8") + b"\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--mode", choices=("strict",), default="strict")
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        hygiene = final_evidence_hygiene_context(
            args.repo_root,
            args.base,
            args.candidate,
            bundle=args.bundle,
            bundle_sha256=args.bundle_sha256,
        )
        report = build_report(
            args.repo_root.resolve(),
            args.base,
            args.candidate,
            hygiene_context=hygiene,
        )
        _store(args.output, report)
    except (OSError, UnicodeError, subprocess.CalledProcessError, ScopeViolation, ValueError) as error:
        print(f"O-07 scope failure: {error.__class__.__name__}: {error}", file=sys.stderr)
        return 2
    print(
        f"O-07 scope verdict=PASS records={len(report['changed_relation'])} "
        f"bundle_sha256={args.bundle_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
