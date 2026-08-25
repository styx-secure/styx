#!/usr/bin/env python3
"""Compare Python and independent JavaScript O-07 interpretations."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

O07_ROOT = Path(__file__).resolve().parent
SIMULATOR_ROOT = O07_ROOT.parent
for entry in (O07_ROOT, SIMULATOR_ROOT):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from genesis_model import GenesisCandidate, GenesisError, accept_genesis
from o14.evidence_io import CanonicalJsonReport, public_failure
from run_genesis_checkpoint_probe import PROFILE_REGISTRY, RUNTIME_BODY_LIMIT, _fixture


SCHEMA = "styx-o07-cross-runtime/v1"


def _vector(identifier, candidate, ceremony) -> dict[str, object]:
    return {
        "id": identifier,
        "transcript_hex": candidate.transcript.hex(),
        "signature_hex": candidate.signature.hex(),
        "expected_reference_hex": ceremony.expected_genesis_reference.hex(),
        "ceremony_authenticated": ceremony.authenticated_provenance,
        "authorization_decision": ceremony.explicit_authorization_decision,
        "context": {
            "protocol_version": ceremony.context.protocol_version,
            "application_profile_id": ceremony.context.application_profile_id,
            "application_profile_version": ceremony.context.application_profile_version,
            "context_identifier_hex": ceremony.context.context_identifier.hex(),
        },
        "allowed_profiles": sorted(PROFILE_REGISTRY),
        "runtime_body_limit": RUNTIME_BODY_LIMIT,
    }


def _python_disposition(candidate, ceremony) -> tuple[str, str | None]:
    try:
        result = accept_genesis(None, candidate, ceremony, allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT)
        assert result.state is not None
        return result.disposition, result.state.genesis_reference.hex()
    except GenesisError as error:
        return error.code, None


def build_vectors():
    _, candidate, ceremony = _fixture()
    bad_signature = bytearray(candidate.signature)
    bad_signature[0] ^= 1
    return (
        ("positive", candidate, ceremony),
        ("unauthenticated-ceremony", candidate, replace(ceremony, authenticated_provenance=False)),
        ("wrong-reference", candidate, replace(ceremony, expected_genesis_reference=bytes(32))),
        ("wrong-signature", replace(candidate, signature=bytes(bad_signature)), ceremony),
        ("wrong-domain", GenesisCandidate(b"\x00\x03" + candidate.transcript[2:], candidate.signature), ceremony),
        ("trailing-byte", GenesisCandidate(candidate.transcript + b"\x00", candidate.signature), ceremony),
    )


def run_adapter(command: list[str], *, cwd: Path) -> dict[str, object]:
    completed = subprocess.run(command, cwd=cwd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return json.loads(completed.stdout)


def build_report(repo_root: Path, workspace: Path, javascript: str) -> tuple[dict[str, object], bool]:
    workspace.mkdir(parents=True, exist_ok=False)
    fixtures = build_vectors()
    vectors = [_vector(identifier, candidate, ceremony) for identifier, candidate, ceremony in fixtures]
    vector_path = workspace / "vectors.json"
    vector_path.write_bytes(CanonicalJsonReport.encode(vectors))
    node = shutil.which(javascript)
    if node is None:
        raise ValueError("required JavaScript runtime unavailable")
    payload = run_adapter([node, str(repo_root / "tools/causal-flow-simulator/o07/node_adapter.mjs"), str(vector_path)], cwd=workspace)
    javascript_by_id = {item["id"]: item for item in payload["results"]}
    comparisons = []
    for identifier, candidate, ceremony in fixtures:
        python_code, python_reference = _python_disposition(candidate, ceremony)
        javascript_result = javascript_by_id[identifier]
        exact = python_code == javascript_result["disposition"] and python_reference == javascript_result["reference_hex"]
        comparisons.append({
            "id": identifier,
            "python": {"disposition": python_code, "reference_hex": python_reference},
            "javascript": javascript_result,
            "exact": exact,
        })
    failed = [item["id"] for item in comparisons if not item["exact"]]
    report = {
        "schema": SCHEMA,
        "adapter_count": 2,
        "vector_count": len(comparisons),
        "comparisons": comparisons,
        "failed": failed,
        "verdict": "PASS" if not failed else "FAIL",
    }
    return report, not failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--javascript", required=True)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report, passed = build_report(args.repo_root.resolve(), args.workspace, args.javascript)
        CanonicalJsonReport.store(args.output, report)
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        print(f"O-07 cross-runtime failed: {public_failure(error)}", file=sys.stderr)
        return 2
    print(f"O-07 RUNTIME verdict={report['verdict']} vectors={report['vector_count']}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
