#!/usr/bin/env python3
"""Cross-runtime evidence for the integrated O-14/O-06c surface."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

from integrated_probe import _verify_execution_identity, build_report as build_probe
from integrated_registry import RUNTIME_SCHEMA
from o10.canonical_report import store_report


REPORT_FIELDS = frozenset(
    {
        "derived_event_count",
        "integrated_probe_digest",
        "interchange",
        "javascript_surface",
        "legacy_cross_language_digest",
        "python_surface",
        "schema",
        "shared_primitives",
        "toolchain_contract",
        "verdict",
    }
)
EXPECTED_PYTHON = "Python 3.14.4"
EXPECTED_NODE = "v24.18.0"


class RuntimeGateError(ValueError):
    """The independent runtime comparison is absent or inconsistent."""


def _run(command: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeGateError(f"{Path(command[0]).name} exited nonzero")
    if not completed.stdout.strip():
        raise RuntimeGateError("runtime command produced no status output")
    return completed.stdout


def build_report(repo_root: Path, javascript: str) -> dict[str, object]:
    python_version = subprocess.check_output(
        [sys.executable, "--version"], text=True
    ).strip()
    node_version = subprocess.check_output([javascript, "--version"], text=True).strip()
    if python_version != EXPECTED_PYTHON or node_version != EXPECTED_NODE:
        raise RuntimeGateError("canonical toolchain mismatch")
    source = repo_root / "tools/causal-flow-simulator/o06c"
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["O06C_MODEL_SEED"] = "o06c-v1-deterministic-test-seed"
    env.pop("PYTHONPATH", None)
    with tempfile.TemporaryDirectory(prefix="styx-integrated-runtime-") as temporary:
        root = Path(temporary)
        frozen = root / "frozen.json"
        legacy = root / "legacy-cross-runtime.json"
        _run(
            [
                sys.executable,
                "-B",
                str(source / "verify_frozen_sections.py"),
                "--repo-root",
                str(repo_root),
                "--candidate",
                "HEAD",
                "--expected-base",
                "3f439189e0cbe4071f642c693dbb196b477a48ea",
                "--mode",
                "strict",
                "--output",
                str(frozen),
            ],
            cwd=root,
            env=env,
        )
        _run(
            [
                sys.executable,
                "-B",
                str(source / "cross_language_gate.py"),
                "--suite",
                "required",
                "--javascript",
                javascript,
                "--frozen-report",
                str(frozen),
                "--workspace",
                str(root / "isolated"),
                "--output",
                str(legacy),
            ],
            cwd=root,
            env=env,
        )
        legacy_bytes = legacy.read_bytes()
        legacy_report = json.loads(legacy_bytes)
    if legacy_report.get("verdict") != "PASS":
        raise RuntimeGateError("frozen cross-language evidence is not PASS")
    event_ids = legacy_report.get("event_ids")
    if not isinstance(event_ids, list) or len(event_ids) != legacy_report.get("event_count"):
        raise RuntimeGateError("cross-language event inventory mismatch")
    probe = build_probe()
    if probe["verdict"] != "PASS":
        raise RuntimeGateError("integrated semantic probe is not PASS")
    probe_bytes = (
        json.dumps(probe, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return {
        "derived_event_count": len(event_ids),
        "integrated_probe_digest": sha256(probe_bytes).hexdigest(),
        "interchange": "TEST_ONLY_NOT_O11",
        "javascript_surface": "DEPENDENCY_FREE_FORWARD_O06C_ENCODER",
        "legacy_cross_language_digest": sha256(legacy_bytes).hexdigest(),
        "python_surface": "AUTHORITATIVE_O06C_TRANSCRIPT_AND_REFERENCE",
        "schema": RUNTIME_SCHEMA,
        "shared_primitives": [
            "SHA256",
            "FROZEN_O06B1_FIELD_ASSIGNMENT",
            "FROZEN_O06B2_COMMITMENT_ASSIGNMENT",
        ],
        "toolchain_contract": [EXPECTED_PYTHON, f"Node {EXPECTED_NODE}"],
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--javascript", required=True)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        repo = args.repo_root.resolve()
        _verify_execution_identity(
            repo,
            args.base,
            args.candidate,
            args.bundle.resolve(),
            args.bundle_sha256,
        )
        report = build_report(repo, args.javascript)
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (OSError, RuntimeGateError, subprocess.CalledProcessError, ValueError) as error:
        print(f"integrated cross-runtime failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(
        f"INTEGRATED RUNTIME verdict=PASS events={report['derived_event_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
