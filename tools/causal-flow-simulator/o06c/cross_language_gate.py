#!/usr/bin/env python3
"""Run isolated Python/JavaScript derivations and compare every selected octet."""

from __future__ import annotations

import argparse
import ast
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

from common import canonical_bytes, sha256_hex, write_report


SCHEMA = "styx-o06c-cross-language-report/v1"
EXPECTED_PYTHON = "Python 3.14.4"
EXPECTED_NODE = "v24.18.0"
EXPECTED_SEED = "o06c-v1-deterministic-test-seed"
FORBIDDEN_SEMANTIC_KEYS = {
    "content_descriptor",
    "transcript",
    "reference_preimage",
    "event_reference",
    "commitment_preimage",
    "commitment_value",
    "leaf_preimages",
    "leaf_digests",
    "node_preimages",
    "root",
}


class GateError(ValueError):
    pass


def _walk_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*( _walk_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_walk_keys(item) for item in value)) if value else set()
    return set()


def _static_isolation(source_root: Path) -> dict[str, object]:
    python_files = ("protocol_model.py", "python_encoder.py")
    allowed_import_roots = {
        "__future__", "argparse", "dataclasses", "hashlib", "json", "pathlib",
        "typing", "protocol_model",
    }
    imports: dict[str, list[str]] = {}
    for name in python_files:
        tree = ast.parse((source_root / name).read_bytes(), filename=name)
        found = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.extend(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                found.append((node.module or "").split(".", 1)[0])
        if not set(found) <= allowed_import_roots:
            raise GateError(f"Python isolation violation in {name}")
        imports[name] = sorted(set(found))
    javascript = (source_root / "javascript_encoder.mjs").read_text(encoding="utf-8")
    found_js = re.findall(r'^import\s+.*?\s+from\s+"([^"]+)";', javascript, re.MULTILINE)
    if sorted(found_js) != ["node:crypto", "node:fs"]:
        raise GateError("JavaScript isolation violation")
    forbidden_markers = ("../", "styx-js/", "packages/", "payload_model")
    for name in (*python_files, "javascript_encoder.mjs"):
        text = (source_root / name).read_text(encoding="utf-8")
        if any(marker in text for marker in forbidden_markers):
            raise GateError(f"forbidden shared-or-product marker in {name}")
    return {"python_imports": imports, "javascript_imports": sorted(found_js)}


def _run(command: list[str], cwd: Path, environment: dict[str, str]) -> None:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise GateError(
            f"isolated process failed ({command[0]}): "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )


def _derive_pair(
    input_path: Path,
    workspace: Path,
    source_root: Path,
    javascript: str,
    environment: dict[str, str],
    label: str,
) -> tuple[dict[str, object], bytes, bytes]:
    python_stage = workspace / f"python-{label}"
    javascript_stage = workspace / f"javascript-{label}"
    python_stage.mkdir(parents=True)
    javascript_stage.mkdir(parents=True)
    for name in ("protocol_model.py", "python_encoder.py"):
        shutil.copyfile(source_root / name, python_stage / name)
    shutil.copyfile(source_root / "javascript_encoder.mjs", javascript_stage / "javascript_encoder.mjs")
    python_output = python_stage / "derived.json"
    javascript_output = javascript_stage / "derived.json"
    _run(
        [sys.executable, "-B", "python_encoder.py", "--input", str(input_path), "--output", str(python_output)],
        python_stage,
        environment,
    )
    _run(
        [javascript, "javascript_encoder.mjs", "--input", str(input_path), "--output", str(javascript_output)],
        javascript_stage,
        environment,
    )
    python_bytes = python_output.read_bytes()
    javascript_bytes = javascript_output.read_bytes()
    python_value = json.loads(python_bytes)
    javascript_value = json.loads(javascript_bytes)
    if python_value != javascript_value:
        raise GateError(f"{label} Python/JavaScript derivation mismatch")
    # JSON member order is transport trivia.  The compared protocol octets and
    # digests are values inside this canonicalized object.
    return python_value, canonical_bytes(python_value), canonical_bytes(javascript_value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--javascript", required=True)
    parser.add_argument("--frozen-report", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    source_root = Path(__file__).resolve().parent
    repo_root = source_root.parents[2]
    workspace = args.workspace.resolve()
    try:
        if workspace == repo_root or workspace.is_relative_to(repo_root):
            raise GateError("generated workspace must be outside the repository")
        if workspace.exists():
            raise GateError("caller-selected workspace already exists")
        if os.environ.get("O06C_MODEL_SEED") != EXPECTED_SEED:
            raise GateError("O06C_MODEL_SEED mismatch")
        python_version = subprocess.check_output([sys.executable, "--version"], text=True).strip()
        node_version = subprocess.check_output([args.javascript, "--version"], text=True).strip()
        if python_version != EXPECTED_PYTHON or node_version != EXPECTED_NODE:
            raise GateError(f"ENVIRONMENT_MISMATCH:{python_version}:{node_version}")
        frozen_bytes = args.frozen_report.read_bytes()
        frozen = json.loads(frozen_bytes)
        if frozen.get("schema") != "styx-o06c-frozen-section-report/v1" or frozen.get("verdict") != "PASS":
            raise GateError("frozen-section report is not a PASS")
        isolation = _static_isolation(source_root)
        workspace.mkdir(parents=True)
        semantic_path = workspace / "semantic-input.json"
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        _run(
            [sys.executable, "-B", str(source_root / "semantic_registry.py"), "--output", str(semantic_path)],
            workspace,
            environment,
        )
        semantic = json.loads(semantic_path.read_bytes())
        forbidden = sorted(_walk_keys(semantic) & FORBIDDEN_SEMANTIC_KEYS)
        if forbidden:
            raise GateError("shared byte/digest oracle in semantic input: " + ",".join(forbidden))
        baseline, python_bytes, javascript_bytes = _derive_pair(
            semantic_path, workspace, source_root, args.javascript, environment, "baseline"
        )

        changed_semantic = copy.deepcopy(semantic)
        old_genesis = changed_semantic["grants"][0]["genesis_reference"]
        changed_semantic["grants"][0]["genesis_reference"] = (
            ("00" if old_genesis[:2] != "00" else "01") + old_genesis[2:]
        )
        changed_path = workspace / "semantic-input-changed-genesis.json"
        changed_path.write_bytes(canonical_bytes(changed_semantic))
        changed, changed_python, changed_javascript = _derive_pair(
            changed_path, workspace, source_root, args.javascript, environment, "changed-genesis"
        )
        baseline_by_id = {item["id"]: item for item in baseline["events"]}
        changed_by_id = {item["id"]: item for item in changed["events"]}
        grant_id = baseline_by_id["grant-root"]["event_reference"]
        grant_transcript = baseline_by_id["grant-root"]["transcript"]
        if grant_id in grant_transcript:
            raise GateError("GRANT reference appears in its own transcript")
        grant_rooted = [item for item in baseline["events"] if item["id"] != "grant-root"]
        if not grant_rooted or any(item["credential_identifier"] != grant_id for item in grant_rooted):
            raise GateError("positive case is not rooted in the encoded GRANT")
        if changed_by_id["grant-root"]["event_reference"] == grant_id:
            raise GateError("genesis change did not alter GRANT reference")
        commitment_cases = [item["id"] for item in grant_rooted if item["commitment"] is not None]
        propagation = []
        for identifier in commitment_cases:
            before = baseline_by_id[identifier]
            after = changed_by_id[identifier]
            checks = {
                "credential_identifier": before["credential_identifier"] != after["credential_identifier"],
                "leaf_preimages": before["commitment"]["leaf_preimages"] != after["commitment"]["leaf_preimages"],
                "commitment_preimage": before["commitment"]["commitment_preimage"] != after["commitment"]["commitment_preimage"],
                "commitment_value": before["commitment"]["commitment_value"] != after["commitment"]["commitment_value"],
            }
            if not all(checks.values()):
                raise GateError(f"genesis propagation failure for {identifier}")
            propagation.append({"id": identifier, "checks": checks})
        report = {
            "schema": SCHEMA,
            "suite": "required",
            "verdict": "PASS",
            "environment": {"python": python_version, "node": node_version},
            "frozen_report_sha256": sha256_hex(frozen_bytes),
            "semantic_input_sha256": sha256_hex(semantic_path.read_bytes()),
            "event_count": len(baseline["events"]),
            "event_ids": [item["id"] for item in baseline["events"]],
            "python_derivation_sha256": sha256_hex(python_bytes),
            "javascript_derivation_sha256": sha256_hex(javascript_bytes),
            "changed_python_derivation_sha256": sha256_hex(changed_python),
            "changed_javascript_derivation_sha256": sha256_hex(changed_javascript),
            "isolation": isolation,
            "grant_non_circular": True,
            "grant_rooted_case_count": len(grant_rooted),
            "genesis_propagation": propagation,
        }
        write_report(args.output, report)
    except (GateError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"cross-language gate failure: {error}", file=sys.stderr)
        return 2
    print(f"O-06c cross-language verdict=PASS events={report['event_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
