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

BASE_SHA = "86c3f2dbd630e445d737a25c09889de2777ee185"
COPY_THRESHOLD = 25
REPORT_SCHEMA = "styx-o07-scope-report/v1"
VALIDATOR_PATH = "tools/protocol-review-model/validate.py"
MODEL_PATH = "docs/protocol/review/styx-app-kernel-v0-review-model.json"
O07_PREFIX = "tools/causal-flow-simulator/o07/"

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
    MODEL_PATH: "c13ac6a65b302c087c1e2c0f7336890dc1046f7cba89bf4fe6b5cb25b799aaf0",
    "docs/protocol/styx-app-kernel-v0-decisions.md": "cd1e29b47ccf713b5480cce6967be7bf2172fd538abbc3bf705dc047398f68d5",
    "docs/protocol/styx-app-kernel-v0-genesis-checkpoint-analysis.md": "fd5fc333c244c772b2d88f30487f0d0e684ae50d4704879bc4e478c04b861aff",
    "docs/protocol/styx-app-kernel-v0-genesis-checkpoint-falsification-report.md": "67604d49118f0af9bd0b03f880e4f50ac044c23454baf5eef146673047191c70",
    "docs/protocol/styx-app-kernel-v0-identifier-derivation-analysis.md": "a2fdef0e9daad20ea62e2f511c29d0b6517b86550b98572e58518039c0d2dec0",
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md": "f34c1f76397dc67ff0880f4fffbbf9bfa0edaf49c93f9c73a76b393f06341b2b",
    "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md": "ad68985fde0c0d3bcc5916446ff04c7c1a3572f8147c3522fde5b6496166eecf",
    "docs/security/STYX-THREAT-MODEL.md": "9378a7d9f534039be749dae89e0a021862d53136ec2eebaf18ac107ab25e415c",
    "tools/causal-flow-simulator/README.md": "22831ecfd1a0b5c5baa1367fe14b0e2bc1f8fd41b25a1de6261330d5b404a811",
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
        "authenticated_provenance",
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
            ("genesis_acceptance_record", "authenticated_provenance"): "05ee23d3b43ecb84653a1e55ca65d1e489ff3769884d88385bd7cd853b03191d",
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


def build_report(repo: Path, base_argument: str, candidate_argument: str) -> dict[str, object]:
    base = _commit(repo, base_argument)
    candidate = _commit(repo, candidate_argument)
    if base_argument != BASE_SHA or base != BASE_SHA:
        raise ScopeViolation("contract base mismatch")
    relation = changed_relation(repo, base, candidate)
    enforce_endpoint_types_and_identity(repo, base, candidate, relation)
    validator_assignments = enforce_validator_delta(repo, base, candidate)
    artifact_digests = enforce_exact_artifacts(repo, candidate)
    enforce_predecessor_isolation(repo, candidate)
    return {
        "schema": REPORT_SCHEMA,
        "base_commit": base,
        "candidate_commit": candidate,
        "copy_threshold_percent": COPY_THRESHOLD,
        "changed_relation": relation,
        "changed_endpoint_count": sum(len(item["paths"]) for item in relation),
        "validator_assignments_changed": validator_assignments,
        "approved_artifact_sha256": artifact_digests,
        "byte_identical_o07_base_blobs": [],
        "predecessor_imports": [],
        "verdict": "PASS",
    }


def _store(path: Path, report: dict[str, object]) -> None:
    encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    path.write_bytes(encoded.encode("utf-8") + b"\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--mode", choices=("strict",), default="strict")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.repo_root.resolve(), args.base, args.candidate)
        _store(args.output, report)
    except (OSError, UnicodeError, subprocess.CalledProcessError, ScopeViolation, ValueError) as error:
        print(f"O-07 scope failure: {error.__class__.__name__}: {error}", file=sys.stderr)
        return 2
    print(f"O-07 scope verdict=PASS records={len(report['changed_relation'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
