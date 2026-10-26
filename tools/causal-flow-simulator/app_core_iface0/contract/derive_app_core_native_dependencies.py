#!/usr/bin/env python3
"""Derive the exact APP-CORE-IFACE-0 native dependency inventory.

Base identity always comes from the exact Git commit.  A path explicitly
authorized for H12/H3 remediation is additionally pinned to its current bytes
so the final candidate can prove the literal old/new repin required by the
ratified Issue #295 amendment.  No other working-tree drift grants authority.
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

RATIFIED_EXACT_REPIN_REASONS = {
    "tools/causal-flow-simulator/c03/corpus_model.py": (
        "Issue #295 comment 5550502736, amendment V3 sections 3.2, 3.4 and 4: "
        "separate logical K admission from O-04 content/opening availability "
        "while preserving the legacy evidence evaluator as an explicitly "
        "distinct path"
    ),
}

GOVERNANCE_STATE_POLICY = "OWNER_MERGED_GOVERNANCE_EXACT_STATE"

# The two governance documents keep their Base identity in the relation, but
# the checkout may carry exactly one of these joint states.  Each pair of
# literal blob identities reached its branch through an owner-merged pull
# request.  Any other pair, including a mix of two listed states, fails.
# Recognizing a state only lifts the Base byte-identity obligation for these
# two documents; it grants no operational authority.
OWNER_MERGED_GOVERNANCE_STATES = (
    {
        "stateId": "BASE_E0AF4E1",
        "provenance": (
            "Base e0af4e1e2173deb2481eabdb24d8622282b33455 of Issue #295"
        ),
        "files": {
            "AGENTS.md": {
                "gitBlobOid": "328914da1864b7ad40fe746631190c9448f6d7be",
                "sha256": "ae4d3ca7dd7fc2123443c163462f16afddc31183a4287d9039ee66a8a9009078",
                "byteSize": 8689,
            },
            "docs/protocol/protocol-hardening-plan.md": {
                "gitBlobOid": "fc45fe12cfb6c377346ff6283558505f8d055582",
                "sha256": "2488352936788767341d8e2c902d6faabe22a3d5b30aa49b3b0af2c3e478b39c",
                "byteSize": 61955,
            },
        },
    },
    {
        "stateId": "M3_PROC_497",
        "provenance": (
            "m3/integration pull request #497 (contract #496), merged by the "
            "owner as 3410059d13210fabfaf58f884ae6604318562644"
        ),
        "files": {
            "AGENTS.md": {
                "gitBlobOid": "20f7135b4acfde9447fdf1a266fecf2b791e7cc4",
                "sha256": "476808a9fa1bd60b7cbcc91db90a32647eb216eeef1dce36fce426c7055de64e",
                "byteSize": 8868,
            },
            "docs/protocol/protocol-hardening-plan.md": {
                "gitBlobOid": "fc45fe12cfb6c377346ff6283558505f8d055582",
                "sha256": "2488352936788767341d8e2c902d6faabe22a3d5b30aa49b3b0af2c3e478b39c",
                "byteSize": 61955,
            },
        },
    },
    {
        "stateId": "MAIN_PHASE_480_490",
        "provenance": (
            "main pull requests #480 (merged by the owner as "
            "932841b75a24ae2ccc533d466a41795484c1ec2f) and #490 (contract "
            "#489, merged by the owner as "
            "4e23c3aa29ceb13eb6286c296556b8b1007eb0b8)"
        ),
        "files": {
            "AGENTS.md": {
                "gitBlobOid": "d04e0133788a8ee91b60d491774e06cff53daea7",
                "sha256": "6081e568c9bff5b24fb893b4c8afc702a4eb6be87354db67d4d1c8ecd95aecbb",
                "byteSize": 10226,
            },
            "docs/protocol/protocol-hardening-plan.md": {
                "gitBlobOid": "529ead4c0e42ffc70e51c502f0b5a15e49c6ae50",
                "sha256": "0c12117d4c8651b01f25d9f29a385b8a051478bbe29de7b246e233db2f6ed79d",
                "byteSize": 62782,
            },
        },
    },
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
    working_path = repository / path
    require(
        working_path.is_file() and not working_path.is_symlink(),
        f"invalid working-tree dependency: {path}",
    )
    working_content = working_path.read_bytes()
    changed = working_content != content
    if path in GOVERNANCE:
        # Base identity stays in the row; the joint working-tree state of both
        # governance documents is checked by verify_governance_state().
        mutation_policy = GOVERNANCE_STATE_POLICY
    elif changed and path in RATIFIED_EXACT_REPIN_REASONS:
        mutation_policy = "RATIFIED_H12_H3_EXACT_REPIN"
    elif path in SEEDED_EXTENSION_PATHS:
        mutation_policy = "SEEDED_EXTENSION_ONLY_PRESERVE_BASE_SEMANTICS"
    else:
        require(not changed, f"unauthorized native dependency drift: {path}")
        mutation_policy = "READ_ONLY_BYTE_IDENTICAL"
    result: dict[str, object] = {
        "path": path,
        "category": category,
        "mutationPolicy": mutation_policy,
        "fileMode": mode,
        "gitBlobOid": object_id,
        "byteSize": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    if mutation_policy == "RATIFIED_H12_H3_EXACT_REPIN":
        candidate_oid = git(repository, "hash-object", "--stdin", input_bytes=working_content)
        result["repin"] = {
            "oldSha256": hashlib.sha256(content).hexdigest(),
            "newSha256": hashlib.sha256(working_content).hexdigest(),
            "newGitBlobOid": candidate_oid.decode().strip(),
            "newByteSize": len(working_content),
            "reason": RATIFIED_EXACT_REPIN_REASONS[path],
        }
    return result


def verify_governance_state(
    repository: Path, rows: list[dict[str, object]]
) -> str:
    """Require the checkout to carry exactly one owner-merged governance state."""

    states = OWNER_MERGED_GOVERNANCE_STATES
    require(
        tuple(state["stateId"] for state in states)
        == ("BASE_E0AF4E1", "M3_PROC_497", "MAIN_PHASE_480_490"),
        "governance state set drift",
    )
    governance_rows = {
        str(row["path"]): row for row in rows if row["path"] in GOVERNANCE
    }
    require(
        tuple(sorted(governance_rows)) == tuple(sorted(GOVERNANCE))
        and all(
            row["mutationPolicy"] == GOVERNANCE_STATE_POLICY and "repin" not in row
            for row in governance_rows.values()
        )
        and all(
            row["mutationPolicy"] != GOVERNANCE_STATE_POLICY
            for row in rows
            if row["path"] not in GOVERNANCE
        ),
        "governance state path drift",
    )
    for state in states:
        files = state["files"]
        require(
            isinstance(files, dict) and tuple(sorted(files)) == tuple(sorted(GOVERNANCE)),
            f"governance state file set drift: {state['stateId']}",
        )
    base_files = states[0]["files"]
    for path, row in governance_rows.items():
        require(
            base_files[path]
            == {
                "gitBlobOid": row["gitBlobOid"],
                "sha256": row["sha256"],
                "byteSize": row["byteSize"],
            },
            f"Base governance state drift: {path}",
        )
    identities = [
        tuple(
            (path, state["files"][path]["gitBlobOid"]) for path in sorted(GOVERNANCE)
        )
        for state in states
    ]
    require(len(set(identities)) == len(identities), "duplicate governance state")

    observed: dict[str, dict[str, object]] = {}
    for path in GOVERNANCE:
        working_content = (repository / path).read_bytes()
        object_id = git(repository, "hash-object", "--stdin", input_bytes=working_content)
        observed[path] = {
            "gitBlobOid": object_id.decode().strip(),
            "sha256": hashlib.sha256(working_content).hexdigest(),
            "byteSize": len(working_content),
        }
    matches = [
        str(state["stateId"])
        for state in states
        if all(state["files"][path] == observed[path] for path in GOVERNANCE)
    ]
    require(
        len(matches) == 1,
        "unratified governance state: "
        + ", ".join(f"{path}={observed[path]['gitBlobOid']}" for path in GOVERNANCE),
    )
    return matches[0]


def derive(repository: Path, base_ref: str) -> tuple[dict[str, object], str]:
    """Return the branch-independent relation and the observed governance state."""

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

    governance_state = verify_governance_state(repository, rows)

    repinned_paths = sorted(
        str(row["path"])
        for row in rows
        if row["mutationPolicy"] == "RATIFIED_H12_H3_EXACT_REPIN"
    )
    frozen_paths = sorted(
        str(row["path"])
        for row in rows
        if row["mutationPolicy"] == "READ_ONLY_BYTE_IDENTICAL"
    )
    governance_paths = sorted(
        str(row["path"])
        for row in rows
        if row["mutationPolicy"] == GOVERNANCE_STATE_POLICY
    )
    governance_lines = [
        "\0".join(
            (
                str(state["stateId"]),
                path,
                str(state["files"][path]["gitBlobOid"]),
                str(state["files"][path]["byteSize"]),
                str(state["files"][path]["sha256"]),
            )
        )
        for state in OWNER_MERGED_GOVERNANCE_STATES
        for path in sorted(GOVERNANCE)
    ]
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
                json.dumps(row.get("repin"), sort_keys=True, separators=(",", ":")),
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
            "governanceStatePolicy": (
                "the two governance documents keep their Base identity; the "
                "checkout must carry exactly one listed owner-merged joint "
                "state of both documents, matched by Git blob id, SHA-256 and "
                "size; the match lifts only the Base byte-identity obligation "
                "and grants no operational authority"
            ),
        },
        "derivedCounts": {
            "dependencies": len(rows),
            "readOnlyDependencies": len(frozen_paths),
            "seededExtensionDependencies": len(seeded_paths),
            "ratifiedExactRepinDependencies": len(repinned_paths),
            "ownerMergedGovernanceStateDependencies": len(governance_paths),
            "ownerMergedGovernanceStates": len(OWNER_MERGED_GOVERNANCE_STATES),
            "c03CanonicalFiles": len(C03_CANONICAL_DATA),
            "c03ImplementationAndTestFiles": len(C03_EVIDENCE_IMPLEMENTATION),
            "protocolReviewToolFiles": len(PROTOCOL_REVIEW_TOOL),
        },
        "setDigests": {
            "allPathSetSha256": digest_lines(seen),
            "readOnlyPathSetSha256": digest_lines(frozen_paths),
            "seededExtensionPathSetSha256": digest_lines(seeded_paths),
            "ratifiedExactRepinPathSetSha256": digest_lines(repinned_paths),
            "ownerMergedGovernanceStatePathSetSha256": digest_lines(governance_paths),
            "ownerMergedGovernanceStateRelationSha256": digest_lines(governance_lines),
            "dependencyRelationSha256": digest_lines(relation_lines),
        },
        "seededExtensionPaths": seeded_paths,
        "ratifiedExactRepinPaths": repinned_paths,
        "ownerMergedGovernanceStatePaths": governance_paths,
        "ownerMergedGovernanceStates": [
            {
                "stateId": state["stateId"],
                "provenance": state["provenance"],
                "files": {
                    path: dict(state["files"][path]) for path in sorted(GOVERNANCE)
                },
            }
            for state in OWNER_MERGED_GOVERNANCE_STATES
        ],
        "dependencies": rows,
    }, governance_state


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base-ref", default=EXPECTED_BASE)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name(OUTPUT_NAME))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    relation, governance_state = derive(args.repository.resolve(), args.base_ref)
    result = canonical_bytes(relation)
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
        f"governance_state={governance_state} sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
