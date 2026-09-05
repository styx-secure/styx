#!/usr/bin/env python3
"""Derive the exact APP-CORE-IFACE-0 native dependency inventory.

This tool reads objects from an exact Git commit.  It never reads dependency
bytes from the working tree and grants no repository or protocol authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Iterable


EXPECTED_BASE = "e0af4e1e2173deb2481eabdb24d8622282b33455"
OUTPUT_NAME = "APP-CORE-IFACE-0-NATIVE-DEPENDENCIES-CANDIDATE.json"

GOVERNANCE = (
    "AGENTS.md",
    "docs/protocol/protocol-hardening-plan.md",
)

NORMATIVE_SEMANTICS = (
    "docs/protocol/styx-app-kernel-v0-decisions.md",
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
    "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
    "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
    "docs/protocol/styx-app-kernel-v0-outcome-taxonomy.md",
    "docs/security/STYX-THREAT-MODEL.md",
)

RESOURCE_AND_REVIEW_MODEL = (
    "docs/protocol/styx-app-kernel-v0-resource-envelope-analysis.md",
    "docs/protocol/styx-app-kernel-v0-resource-envelope-falsification-report.md",
    "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json",
    "docs/protocol/review/styx-app-kernel-v0-review-model.json",
)

SELECTED_MACHINE_PROFILES = (
    "tools/causal-flow-simulator/o07/required_atom_instances_v1.json",
    "tools/causal-flow-simulator/o08/resource-envelope.candidate.json",
    "tools/causal-flow-simulator/o10/outcome-taxonomy.json",
    "tools/causal-flow-simulator/o10/source-inventory.json",
)

C03_CANONICAL_DATA = (
    "conformance/application-protocol/c03/manifest.json",
    "conformance/application-protocol/c03/valid-transcript-vectors.json",
    "conformance/application-protocol/c03/invalid-transcript-vectors.json",
    "conformance/application-protocol/c03/state-machine-scenarios.json",
    "conformance/application-protocol/c03/adversarial-mutations.json",
    "conformance/application-protocol/c03/expected-traces.json",
)

C03_EVIDENCE_IMPLEMENTATION = (
    "tools/causal-flow-simulator/c03/README.md",
    "tools/causal-flow-simulator/c03/build_blind_projection.py",
    "tools/causal-flow-simulator/c03/canonical_json.py",
    "tools/causal-flow-simulator/c03/compare_clean_room.py",
    "tools/causal-flow-simulator/c03/corpus-inventory.json",
    "tools/causal-flow-simulator/c03/corpus-source-map.json",
    "tools/causal-flow-simulator/c03/corpus_model.py",
    "tools/causal-flow-simulator/c03/generate_corpus.py",
    "tools/causal-flow-simulator/c03/h1_h2_relation.py",
    "tools/causal-flow-simulator/c03/node_adapter.mjs",
    "tools/causal-flow-simulator/c03/replay_corpus.py",
    "tools/causal-flow-simulator/c03/run_cross_runtime.py",
    "tools/causal-flow-simulator/c03/run_mutations.py",
    "tools/causal-flow-simulator/c03/scope_guard.py",
    "tools/causal-flow-simulator/c03/tests/test_blind_projection.py",
    "tools/causal-flow-simulator/c03/tests/test_canonical_json.py",
    "tools/causal-flow-simulator/c03/tests/test_compare_clean_room.py",
    "tools/causal-flow-simulator/c03/tests/test_coverage.py",
    "tools/causal-flow-simulator/c03/tests/test_cross_runtime.py",
    "tools/causal-flow-simulator/c03/tests/test_generation.py",
    "tools/causal-flow-simulator/c03/tests/test_h1_h2_relation.py",
    "tools/causal-flow-simulator/c03/tests/test_manifest.py",
    "tools/causal-flow-simulator/c03/tests/test_mutations.py",
    "tools/causal-flow-simulator/c03/tests/test_replay.py",
    "tools/causal-flow-simulator/c03/tests/test_scope_guard.py",
    "tools/causal-flow-simulator/c03/validate_corpus.py",
)

PROTOCOL_REVIEW_TOOL = (
    "tools/protocol-review-model/tests/__init__.py",
    "tools/protocol-review-model/tests/fixtures/duplicate-keys.json",
    "tools/protocol-review-model/tests/fixtures/malformed.json",
    "tools/protocol-review-model/tests/fixtures/negative-cases.json",
    "tools/protocol-review-model/tests/fixtures/o06c-capability-gates.json",
    "tools/protocol-review-model/tests/fixtures/o10-outcome-taxonomy.json",
    "tools/protocol-review-model/tests/support.py",
    "tools/protocol-review-model/tests/test_c03_corpus_path_approval.py",
    "tools/protocol-review-model/tests/test_c03_entry_authorization.py",
    "tools/protocol-review-model/tests/test_o06c_capability_gates.py",
    "tools/protocol-review-model/tests/test_o10_outcome_taxonomy.py",
    "tools/protocol-review-model/tests/test_o14_scope.py",
    "tools/protocol-review-model/tests/test_secure_session_profile.py",
    "tools/protocol-review-model/tests/test_ss0_corpus_path_approval.py",
    "tools/protocol-review-model/tests/test_validate.py",
    "tools/protocol-review-model/validate.py",
)

SEEDED_EXTENSION_PATHS = frozenset(
    {
        "docs/protocol/review/README.md",
        "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json",
        "docs/protocol/review/styx-app-kernel-v0-review-model.json",
        "tools/protocol-review-model/validate.py",
    }
)

CATEGORIES = (
    ("GOVERNANCE_AND_SEQUENCE", GOVERNANCE),
    ("NORMATIVE_SEMANTICS", NORMATIVE_SEMANTICS),
    ("RESOURCE_AND_REVIEW_MODEL", RESOURCE_AND_REVIEW_MODEL),
    ("SELECTED_MACHINE_PROFILES", SELECTED_MACHINE_PROFILES),
    ("C03_CANONICAL_DATA", C03_CANONICAL_DATA),
    ("C03_EVIDENCE_IMPLEMENTATION", C03_EVIDENCE_IMPLEMENTATION),
    ("PROTOCOL_REVIEW_TOOL", PROTOCOL_REVIEW_TOOL),
    ("SEEDED_REVIEW_DOCUMENTATION", ("docs/protocol/review/README.md",)),
)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(message)


def git(repository: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(
        completed.returncode == 0,
        f"git {' '.join(args)} failed: {completed.stderr.decode(errors='replace').strip()}",
    )
    return completed.stdout


def resolve_commit(repository: Path, reference: str) -> str:
    resolved = git(repository, "rev-parse", f"{reference}^{{commit}}").decode().strip()
    require(resolved == EXPECTED_BASE, f"unexpected Base: {resolved}")
    return resolved


def tree_paths(repository: Path, base: str, prefix: str) -> tuple[str, ...]:
    output = git(repository, "ls-tree", "-r", "--name-only", base, "--", prefix)
    return tuple(sorted(line for line in output.decode().splitlines() if line))


def digest_lines(lines: Iterable[str]) -> str:
    material = "".join(f"{line}\n" for line in sorted(lines)).encode()
    return hashlib.sha256(material).hexdigest()


def dependency(repository: Path, base: str, category: str, path: str) -> dict[str, object]:
    row = git(repository, "ls-tree", base, "--", path).decode().rstrip("\n")
    require(row, f"missing dependency at Base: {path}")
    metadata, observed_path = row.split("\t", 1)
    mode, object_type, object_id = metadata.split(" ", 2)
    require(observed_path == path, f"path mismatch: {path}")
    require(mode == "100644", f"non-regular or executable dependency: {path} ({mode})")
    require(object_type == "blob", f"non-blob dependency: {path} ({object_type})")
    content = git(repository, "cat-file", "blob", object_id)
    mutation_policy = (
        "SEEDED_EXTENSION_ONLY_PRESERVE_BASE_SEMANTICS"
        if path in SEEDED_EXTENSION_PATHS
        else "READ_ONLY_BYTE_IDENTICAL"
    )
    return {
        "path": path,
        "category": category,
        "mutationPolicy": mutation_policy,
        "fileMode": mode,
        "gitBlobOid": object_id,
        "byteSize": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def derive(repository: Path, base_ref: str) -> dict[str, object]:
    base = resolve_commit(repository, base_ref)
    require(
        tree_paths(repository, base, "tools/causal-flow-simulator/c03")
        == C03_EVIDENCE_IMPLEMENTATION,
        "C0.3 implementation/test path set drift",
    )
    observed_review_paths = tuple(
        path
        for path in tree_paths(repository, base, "tools/protocol-review-model")
        if path != "tools/protocol-review-model/.gitignore"
    )
    require(observed_review_paths == PROTOCOL_REVIEW_TOOL, "protocol-review tool path set drift")

    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for category, paths in CATEGORIES:
        for path in paths:
            require(path not in seen, f"duplicate dependency path: {path}")
            seen.add(path)
            rows.append(dependency(repository, base, category, path))

    frozen_paths = sorted(seen - SEEDED_EXTENSION_PATHS)
    seeded_paths = sorted(SEEDED_EXTENSION_PATHS)
    relation_lines = [
        "\0".join(
            (
                str(row["path"]),
                str(row["category"]),
                str(row["mutationPolicy"]),
                str(row["fileMode"]),
                str(row["gitBlobOid"]),
                str(row["byteSize"]),
                str(row["sha256"]),
            )
        )
        for row in rows
    ]
    return {
        "schema": "styx.app-core-iface0-native-dependencies-candidate.v1",
        "status": "PRE_RATIFICATION_WORKING_EVIDENCE",
        "authorityEffect": "NONE",
        "repository": "styx-secure/styx",
        "baseBranch": "main",
        "baseSha": base,
        "rules": {
            "contentDigest": "SHA-256 over exact Git blob bytes",
            "pathSet": "literal and closed at Base",
            "frozenPolicy": "read-only dependencies remain byte-identical",
            "seededPolicy": "only ratified additive projection changes; existing semantics remain covered",
            "workingTreeBytes": "never accepted as native dependency evidence",
        },
        "derivedCounts": {
            "dependencies": len(rows),
            "readOnlyDependencies": len(frozen_paths),
            "seededExtensionDependencies": len(seeded_paths),
            "c03CanonicalFiles": len(C03_CANONICAL_DATA),
            "c03ImplementationAndTestFiles": len(C03_EVIDENCE_IMPLEMENTATION),
            "protocolReviewToolFiles": len(PROTOCOL_REVIEW_TOOL),
        },
        "setDigests": {
            "allPathSetSha256": digest_lines(seen),
            "readOnlyPathSetSha256": digest_lines(frozen_paths),
            "seededExtensionPathSetSha256": digest_lines(seeded_paths),
            "dependencyRelationSha256": digest_lines(relation_lines),
        },
        "seededExtensionPaths": seeded_paths,
        "dependencies": rows,
    }


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base-ref", default=EXPECTED_BASE)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name(OUTPUT_NAME))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    result = canonical_bytes(derive(args.repository.resolve(), args.base_ref))
    if args.check:
        require(args.output.is_file() and not args.output.is_symlink(), "missing generated inventory")
        require(args.output.read_bytes() == result, "native dependency inventory drift")
    else:
        args.output.write_bytes(result)
    digest = hashlib.sha256(result).hexdigest()
    parsed = json.loads(result)
    counts = parsed["derivedCounts"]
    print(
        "PASS "
        f"base={parsed['baseSha']} dependencies={counts['dependencies']} "
        f"read_only={counts['readOnlyDependencies']} seeded={counts['seededExtensionDependencies']} "
        f"sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
