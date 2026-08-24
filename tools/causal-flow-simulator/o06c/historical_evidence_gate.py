#!/usr/bin/env python3
"""Re-run the closed seven-entry historical evidence registry in isolation."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

from common import sha256_hex, write_report


REPORT_SCHEMA = "styx-o06c-historical-evidence-report/v1"


@dataclass(frozen=True)
class HistoricalEntry:
    identifier: str
    path: str
    verdict: str
    digest: str


HISTORICAL_REGISTRY = (
    HistoricalEntry(
        "V1_BASELINE",
        "tools/causal-flow-simulator/causal_flow_simulator.py",
        "NO_COUNTEREXAMPLE_WITHIN_BOUNDS",
        "8bee78b7bde503597d331bea63bca1548bb3d8f006ea4505854b7973b3a5a3f7",
    ),
    HistoricalEntry(
        "V2_BASELINE",
        "tools/causal-flow-simulator/v2/causal_flow_simulator_v2.py",
        "NO_COUNTEREXAMPLE_WITHIN_BOUNDS",
        "fe50e619d8761c59477665714c3d6daa6385e448aa32fa2bfa500f7cf4c15249",
    ),
    HistoricalEntry(
        "V2_MUTATIONS",
        "tools/causal-flow-simulator/v2/mutation_harness_v2.py",
        "ALL_REQUIRED_MUTANTS_KILLED",
        "67469ca08f5bfb71dbfed6f630e335fc21a0613cb2e14ecb4fc6cbb866ed20e0",
    ),
    HistoricalEntry(
        "V3_BASELINE",
        "tools/causal-flow-simulator/v3/causal_flow_simulator_v3.py",
        "NO_COUNTEREXAMPLE_WITHIN_BOUNDS",
        "7e690789259489e5b7ddcc10ed6046904240fae75c68f4eba2ea507d7691d0a4",
    ),
    HistoricalEntry(
        "V3_MUTATIONS",
        "tools/causal-flow-simulator/v3/mutation_harness_v3.py",
        "ALL_REQUIRED_MUTANTS_KILLED",
        "de0af570dde02de491b997d44cb73487152325400e51115ff1ba8c98d808522d",
    ),
    HistoricalEntry(
        "C02K_BASELINE",
        "tools/causal-flow-simulator/c02k/commitment_context_probe.py",
        "BOUNDED_FALSIFICATION_PASSED",
        "67b5d837c15353e4b6b54f67fc28cbaad1b05533a50a0e6ba8a62a50859c5b77",
    ),
    HistoricalEntry(
        "C02K_MUTATIONS",
        "tools/causal-flow-simulator/c02k/mutation_harness_c02k.py",
        "ALL_REQUIRED_MUTANTS_KILLED",
        "5df59ab4e50f216dd1881bb991a795c26a1dba654e3a43d40ffa23b40cc4ed37",
    ),
)


class HistoricalGateError(ValueError):
    """Historical evidence cannot be reproduced exactly."""


def _historical_sources(repo: Path) -> tuple[Path, ...]:
    root = repo / "tools" / "causal-flow-simulator"
    return tuple(
        path
        for path in sorted(root.rglob("*.py"))
        if "tests" not in path.parts and "o06c" not in path.parts
    )


def _stage_sources(repo: Path, destination: Path) -> str:
    source_digests = []
    for source in _historical_sources(repo):
        relative = source.relative_to(repo)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(0o644)
        source_digests.append(f"{relative.as_posix()}\0{sha256_hex(source.read_bytes())}")
    for directory in sorted(
        (path for path in destination.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        directory.chmod(0o755)
    destination.chmod(0o755)
    return sha256_hex("\n".join(source_digests).encode("utf-8"))


def _execute_entry(
    repo: Path, staging_root: Path, entry: HistoricalEntry
) -> dict[str, object]:
    stage = staging_root / entry.identifier.lower()
    if stage.exists():
        raise HistoricalGateError(f"staging destination already exists: {entry.identifier}")
    stage.mkdir(parents=True, mode=0o755)
    support_digest = _stage_sources(repo, stage)
    source = stage / entry.path
    candidate_source = repo / entry.path
    if not source.is_file() or source.read_bytes() != candidate_source.read_bytes():
        raise HistoricalGateError(f"staged source mismatch: {entry.path}")
    output = stage / "report.json"
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
        "TZ": "UTC",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SOURCE_DATE_EPOCH": "0",
    }
    completed = subprocess.run(
        [sys.executable, source.name, "--suite", "required", "--output", str(output)],
        cwd=source.parent,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if not output.is_file():
        actual_digest = None
        observed_verdict = None
    else:
        report_bytes = output.read_bytes()
        actual_digest = sha256_hex(report_bytes)
        import json

        try:
            observed_verdict = json.loads(report_bytes)["verdict"]
        except (ValueError, KeyError, TypeError):
            observed_verdict = None
    passed = (
        completed.returncode == 0
        and actual_digest == entry.digest
        and observed_verdict == entry.verdict
    )
    return {
        "id": entry.identifier,
        "path": entry.path,
        "expected_exit": 0,
        "actual_exit": completed.returncode,
        "expected_verdict": entry.verdict,
        "actual_verdict": observed_verdict,
        "expected_sha256": entry.digest,
        "actual_sha256": actual_digest,
        "staged_source_sha256": sha256_hex(source.read_bytes()),
        "support_set_sha256": support_digest,
        "stdout_sha256": sha256_hex(completed.stdout),
        "stderr_sha256": sha256_hex(completed.stderr),
        "status": "PASS" if passed else "FAIL",
    }


def build_report(repo: Path, staging_root: Path) -> tuple[dict[str, object], bool]:
    if len(HISTORICAL_REGISTRY) != 7:
        raise HistoricalGateError("historical registry must contain exactly seven entries")
    staging_root.mkdir(parents=True, exist_ok=False)
    staging_root.chmod(0o755)
    records = [
        _execute_entry(repo, staging_root, entry) for entry in HISTORICAL_REGISTRY
    ]
    passed = len(records) == 7 and all(item["status"] == "PASS" for item in records)
    return (
        {
            "schema": REPORT_SCHEMA,
            "registry_size": 7,
            "entries": records,
            "verdict": "PASS" if passed else "FAIL",
        },
        passed,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--frozen-report", required=True, type=Path)
    parser.add_argument("--staging-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        import json

        frozen = json.loads(args.frozen_report.read_bytes())
        if frozen.get("verdict") != "PASS":
            raise HistoricalGateError("frozen-section report is not PASS")
        report, passed = build_report(
            args.repo_root.resolve(), args.staging_root.resolve()
        )
        write_report(args.output, report)
    except (HistoricalGateError, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"historical-evidence failure: {error}", file=sys.stderr)
        return 2
    print(f"O-06c historical evidence verdict={report['verdict']} count=7")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
