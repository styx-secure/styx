#!/usr/bin/env python3
"""Require byte-identical independent Python and JavaScript replay reports."""

from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from canonical_json import load, store  # noqa: E402
from corpus_model import CorpusModelError  # noqa: E402


class CrossRuntimeError(CorpusModelError):
    pass


def run(repo_root: Path, corpus: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="styx-c03-cross-") as directory:
        temporary = Path(directory)
        python_report = temporary / "python.json"
        node_report = temporary / "node.json"
        commands = (
            [sys.executable, str(ROOT / "replay_corpus.py"), "--repo-root", str(repo_root), "--corpus", str(corpus), "--output", str(python_report)],
            ["node", str(ROOT / "node_adapter.mjs"), "--repo-root", str(repo_root), "--corpus", str(corpus), "--output", str(node_report)],
        )
        for command in commands:
            completed = subprocess.run(command, cwd=repo_root, check=False, capture_output=True, text=True)
            if completed.returncode != 0:
                raise CrossRuntimeError(
                    f"runtime failed ({completed.returncode}): {completed.stderr.strip()}"
                )
        python_bytes = python_report.read_bytes()
        node_bytes = node_report.read_bytes()
        if python_bytes != node_bytes:
            raise CrossRuntimeError("Python and JavaScript canonical reports differ")
        report = load(python_report)
        if report.get("result") != "PASS":
            raise CrossRuntimeError("runtime report is not PASS")
        return {
            "reportDigest": sha256(python_bytes).hexdigest(),
            "result": "PASS",
            "runtimes": ["javascript", "python"],
            "scenarios": report["scenarios"],
            "vectors": report["validVectors"] + report["invalidVectors"],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        store(args.output.resolve(), run(args.repo_root.resolve(), args.corpus.resolve()))
    except (CorpusModelError, OSError, ValueError) as error:
        print(f"c03_cross_runtime_failure={error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
