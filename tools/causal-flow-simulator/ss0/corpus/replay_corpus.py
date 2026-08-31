#!/usr/bin/env python3
"""Blindly replay the synthetic corpus through both frozen SS-0 readers."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

CORPUS_DIR = Path(__file__).resolve().parent
SS0_DIR = CORPUS_DIR.parent
sys.path.insert(0, str(SS0_DIR))

from canonical_report import store as store_report  # noqa: E402
from model import evaluate  # noqa: E402

sys.path.insert(0, str(CORPUS_DIR))
from canonical_json import canonical_bytes, load_canonical, store_atomic  # noqa: E402
from generate_corpus import CORPUS_PATHS  # noqa: E402
from validate_corpus import CorpusValidationError, validate_corpus  # noqa: E402


def load_input_records(repo: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name, collection in (
        (CORPUS_PATHS[1], "vectors"),
        (CORPUS_PATHS[2], "vectors"),
        (CORPUS_PATHS[3], "scenarios"),
    ):
        document = load_canonical(repo / name)
        records.extend(document[collection])
    return sorted(records, key=lambda row: row["sourceWitness"])


def build_child_inputs(
    records: list[dict[str, Any]], *, expose_provenance: bool = False
) -> list[dict[str, Any]]:
    inputs: list[dict[str, Any]] = []
    for row in records:
        candidate = row["input"]
        if expose_provenance:
            raise CorpusValidationError(
                "CDM-028", "reader input stream exposes corpus provenance"
            )
        if not isinstance(candidate, dict) or any(
            key in candidate
            for key in (
                "id", "sourceFile", "sourceFilename", "sourcePartition",
                "sourceWitness",
            )
        ):
            raise CorpusValidationError(
                "CDM-028", "reader input stream contains corpus provenance"
            )
        inputs.append(candidate)
    return inputs


def _javascript_observations(
    repo: Path, node: Path, inputs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    node = node.resolve(strict=True)
    completed = subprocess.run(
        [str(node), str(repo / "tools/causal-flow-simulator/ss0/node_adapter.mjs")],
        input=json.dumps(inputs, ensure_ascii=False, separators=(",", ":")),
        text=True,
        capture_output=True,
        check=False,
        cwd=repo,
        env={
            "PATH": f"{node.parent}:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        timeout=60,
    )
    if completed.returncode != 0 or completed.stderr:
        raise ValueError("independent JavaScript reader failed")
    value = json.loads(completed.stdout)
    if not isinstance(value, list):
        raise ValueError("independent JavaScript reader returned a non-array")
    return value


def replay(
    repo: Path, node: Path, corpus_dir: Path, output: Path
) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    validate_corpus(repo, corpus_dir)
    records = load_input_records(repo)
    inputs = build_child_inputs(records)
    javascript = _javascript_observations(repo, node, inputs)
    python = [evaluate(candidate) for candidate in inputs]
    if len(javascript) != len(records) or len(python) != len(records):
        raise ValueError("reader observation cardinality mismatch")

    output = output.resolve()
    raw_python = output.with_name(f"{output.stem}.python.raw.json")
    raw_javascript = output.with_name(f"{output.stem}.javascript.raw.json")
    store_atomic(raw_python, canonical_bytes(python))
    store_atomic(raw_javascript, canonical_bytes(javascript))

    # The expected trace file is deliberately opened only after both independent
    # raw streams have been atomically frozen above.
    trace_document = load_canonical(repo / CORPUS_PATHS[5])
    expected_rows = trace_document["traces"]
    expected = [row["expected"] for row in expected_rows]
    expected_ids = [row["id"] for row in expected_rows]
    record_ids = [row["sourceWitness"] for row in records]
    if expected_ids != record_ids:
        raise ValueError("trace order differs from blind reader input order")
    if python != javascript or python != expected:
        raise ValueError("SS-0 corpus replay mismatch")
    report: dict[str, Any] = {
        "caseCount": len(records),
        "observations": [
            {"id": identity, "observation": observation}
            for identity, observation in zip(record_ids, python, strict=True)
        ],
        "result": "PASS",
        "schema": "styx.ss0.corpus.replay-report.v1",
    }
    store_report(report, output)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    repo = arguments.repo_root.resolve(strict=True)
    corpus = arguments.corpus_dir if arguments.corpus_dir.is_absolute() else repo / arguments.corpus_dir
    if "PYTHONOPTIMIZE" in os.environ:
        raise ValueError("PYTHONOPTIMIZE must be unset")
    replay(repo, arguments.node, corpus, arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
