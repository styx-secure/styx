#!/usr/bin/env python3
"""Kill the closed SS-0 source and corpus-data mutation registries."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

CORPUS_DIR = Path(__file__).resolve().parent
SS0_DIR = CORPUS_DIR.parent
sys.path.insert(0, str(SS0_DIR))

from canonical_report import canonical_bytes as report_bytes  # noqa: E402
from canonical_report import store as store_report  # noqa: E402

sys.path.insert(0, str(CORPUS_DIR))
from canonical_json import canonical_bytes, load_canonical, store_atomic  # noqa: E402
from generate_corpus import (  # noqa: E402
    CORPUS_PATHS,
    NORMATIVE_INPUTS,
    REPRODUCTION_INPUTS,
    SUPPLEMENTAL_MUTANTS,
)
from replay_corpus import build_child_inputs, load_input_records  # noqa: E402
from validate_corpus import (  # noqa: E402
    CorpusValidationError,
    validate_corpus,
)


DATA_MUTATIONS = (
    ("CDM-001", "missing manifest"),
    ("CDM-002", "missing non-manifest corpus file"),
    ("CDM-003", "unlisted seventh regular file"),
    ("CDM-004", "symlink replacing a corpus file"),
    ("CDM-005", "reordered generatedFiles relation"),
    ("CDM-006", "wrong generated-file digest"),
    ("CDM-007", "wrong manifestPayloadSha256"),
    ("CDM-008", "duplicate JSON object key"),
    ("CDM-009", "unknown top-level field"),
    ("CDM-010", "missing required top-level field"),
    ("CDM-011", "unknown schema identifier"),
    ("CDM-012", "non-canonical object-key order"),
    ("CDM-013", "absent final LF"),
    ("CDM-014", "UTF-8 BOM or invalid UTF-8"),
    ("CDM-015", "floating-point value outside frozen supplemental evidence"),
    ("CDM-016", "duplicate case identifier"),
    ("CDM-017", "missing source witness"),
    ("CDM-018", "extra source witness"),
    ("CDM-019", "witness moved to the wrong partition"),
    ("CDM-020", "trace/input identifier mismatch"),
    ("CDM-021", "expected result or disposition injected into reader input"),
    ("CDM-022", "assertion, detector or source-mutant data injected into reader input"),
    ("CDM-023", "synthetic false or upstreamBytes other than none"),
    ("CDM-024", "missing or extra mutation record"),
    ("CDM-025", "wrong mutation coverageClass or detector relation"),
    ("CDM-026", "changed owner/atom/relation/disposition count"),
    ("CDM-027", "runtime or repository provenance injected into a canonical report"),
    ("CDM-028", "input stream exposes source filename or partition membership"),
)
DATA_MUTATION_IDS = tuple(identity for identity, _ in DATA_MUTATIONS)
DETECTOR_OWNER = {
    **{identity: "validate_corpus.py" for identity in DATA_MUTATION_IDS[:26]},
    "CDM-027": "canonical_report.py",
    "CDM-028": "replay_corpus.py",
}


def _manifest_projection(document: dict[str, Any]) -> None:
    projection = dict(document)
    projection.pop("manifestPayloadSha256", None)
    document["manifestPayloadSha256"] = hashlib.sha256(
        canonical_bytes(projection)
    ).hexdigest()


def _write_document(root: Path, name: str, document: dict[str, Any]) -> None:
    store_atomic(root / name, canonical_bytes(document))


def _refresh_manifest_bindings(root: Path) -> None:
    manifest = load_canonical(root / CORPUS_PATHS[0])
    for row in manifest["generatedFiles"]:
        row["sha256"] = hashlib.sha256((root / row["path"]).read_bytes()).hexdigest()
    _manifest_projection(manifest)
    _write_document(root, CORPUS_PATHS[0], manifest)


def _copy_fixture(repo: Path, target: Path) -> None:
    for name, _ in (*NORMATIVE_INPUTS, *REPRODUCTION_INPUTS):
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo / name, destination)
    for name in CORPUS_PATHS:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo / name, destination)


def _collection(root: Path, name: str) -> tuple[dict[str, Any], str]:
    document = load_canonical(root / name)
    return document, "scenarios" if name == CORPUS_PATHS[3] else "vectors"


def _mutate_file(root: Path, identity: str) -> None:
    manifest_name = CORPUS_PATHS[0]
    manifest = load_canonical(root / manifest_name)
    if identity == "CDM-001":
        (root / manifest_name).unlink()
    elif identity == "CDM-002":
        (root / CORPUS_PATHS[1]).unlink()
    elif identity == "CDM-003":
        store_atomic(root / "conformance/secure-session/ss0/unlisted.json", b"{}\n")
    elif identity == "CDM-004":
        path = root / CORPUS_PATHS[1]
        path.unlink()
        path.symlink_to(Path(CORPUS_PATHS[2]).name)
    elif identity == "CDM-005":
        manifest["generatedFiles"].reverse()
        _manifest_projection(manifest)
        _write_document(root, manifest_name, manifest)
    elif identity == "CDM-006":
        manifest["generatedFiles"][0]["sha256"] = "0" * 64
        _manifest_projection(manifest)
        _write_document(root, manifest_name, manifest)
    elif identity == "CDM-007":
        manifest["manifestPayloadSha256"] = "0" * 64
        _write_document(root, manifest_name, manifest)
    elif identity == "CDM-008":
        path = root / manifest_name
        path.write_bytes(path.read_bytes().replace(b'{"authority":', b'{"authority":{},"authority":', 1))
    elif identity == "CDM-009":
        document, _ = _collection(root, CORPUS_PATHS[1])
        document["unknown"] = True
        _write_document(root, CORPUS_PATHS[1], document)
    elif identity == "CDM-010":
        document, _ = _collection(root, CORPUS_PATHS[1])
        del document["schema"]
        _write_document(root, CORPUS_PATHS[1], document)
    elif identity == "CDM-011":
        document, _ = _collection(root, CORPUS_PATHS[1])
        document["schema"] = "unknown"
        _write_document(root, CORPUS_PATHS[1], document)
    elif identity == "CDM-012":
        path = root / CORPUS_PATHS[1]
        document = load_canonical(path)
        path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif identity == "CDM-013":
        path = root / CORPUS_PATHS[1]
        path.write_bytes(path.read_bytes().removesuffix(b"\n"))
    elif identity == "CDM-014":
        path = root / CORPUS_PATHS[1]
        path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    elif identity == "CDM-015":
        path = root / CORPUS_PATHS[1]
        document = load_canonical(path)
        document["vectors"][0]["input"]["forbiddenFloat"] = 1.5
        path.write_text(json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
    elif identity == "CDM-016":
        document, collection = _collection(root, CORPUS_PATHS[1])
        document[collection].append(document[collection][0])
        _write_document(root, CORPUS_PATHS[1], document)
    elif identity == "CDM-017":
        document, collection = _collection(root, CORPUS_PATHS[1])
        document[collection].pop()
        _write_document(root, CORPUS_PATHS[1], document)
    elif identity == "CDM-018":
        document, collection = _collection(root, CORPUS_PATHS[1])
        extra = json.loads(json.dumps(document[collection][0]))
        extra["id"] = extra["sourceWitness"] = "W-EXTRA-SOURCE-WITNESS"
        document[collection].append(extra)
        _write_document(root, CORPUS_PATHS[1], document)
    elif identity == "CDM-019":
        source, source_collection = _collection(root, CORPUS_PATHS[1])
        target, target_collection = _collection(root, CORPUS_PATHS[2])
        target[target_collection].append(source[source_collection].pop())
        target[target_collection].sort(key=lambda row: row["id"])
        _write_document(root, CORPUS_PATHS[1], source)
        _write_document(root, CORPUS_PATHS[2], target)
    elif identity == "CDM-020":
        traces = load_canonical(root / CORPUS_PATHS[5])
        traces["traces"][0]["id"] = "W-MISMATCHED-TRACE"
        _write_document(root, CORPUS_PATHS[5], traces)
    elif identity in {"CDM-021", "CDM-022"}:
        document, collection = _collection(root, CORPUS_PATHS[1])
        key = "expected" if identity == "CDM-021" else "detector"
        document[collection][0]["input"][key] = "forbidden"
        _write_document(root, CORPUS_PATHS[1], document)
    elif identity == "CDM-023":
        manifest["synthetic"] = False
        _write_document(root, manifest_name, manifest)
    elif identity == "CDM-024":
        mutations = load_canonical(root / CORPUS_PATHS[4])
        mutations["mutations"].pop()
        _write_document(root, CORPUS_PATHS[4], mutations)
    elif identity == "CDM-025":
        mutations = load_canonical(root / CORPUS_PATHS[4])
        mutations["mutations"][0]["coverageClass"] = "FROZEN_SUPPLEMENTAL"
        _write_document(root, CORPUS_PATHS[4], mutations)
    elif identity == "CDM-026":
        manifest["counts"]["sourceWitnesses"] = 55
        _write_document(root, manifest_name, manifest)
    else:
        raise ValueError(f"file mutation has no implementation: {identity}")


def _kill_file_mutant(repo: Path, identity: str, temporary_root: Path) -> None:
    fixture = temporary_root / identity
    _copy_fixture(repo, fixture)
    _mutate_file(fixture, identity)
    if identity in {
        *(f"CDM-{index:03d}" for index in range(9, 23)),
        "CDM-024",
        "CDM-025",
    }:
        _refresh_manifest_bindings(fixture)
    try:
        validate_corpus(fixture, fixture / "conformance/secure-session/ss0")
    except CorpusValidationError as error:
        if error.code != identity:
            raise ValueError(
                f"wrong detector code for {identity}: {error.code}"
            ) from error
        return
    raise ValueError(f"surviving corpus-data mutant: {identity}")


def _kill_report_mutant() -> None:
    try:
        report_bytes(
            {
                "result": "PASS",
                "schema": "styx.ss0.corpus.mutation-probe.v1",
                "value": "provenance=/tmp/styx-ss0-corpus",
            }
        )
    except ValueError as error:
        raise CorpusValidationError("CDM-027", str(error)) from error
    raise ValueError("surviving canonical-report provenance mutant")


def _kill_stream_mutant(repo: Path) -> None:
    records = copy.deepcopy(load_input_records(repo))
    records[0]["input"]["sourceWitness"] = records[0]["sourceWitness"]
    build_child_inputs(records)
    raise ValueError("surviving reader-stream provenance mutant")


def _expect_code(identity: str, action: Callable[[], None]) -> None:
    try:
        action()
    except CorpusValidationError as error:
        if error.code != identity:
            raise ValueError(f"wrong detector code for {identity}: {error.code}") from error
        return
    raise ValueError(f"surviving corpus-data mutant: {identity}")


def run_data_mutations(repo: Path) -> list[dict[str, Any]]:
    validate_corpus(repo, repo / "conformance/secure-session/ss0")
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="styx-ss0-data-mutants-") as name:
        temporary_root = Path(name)
        for identity, _target in DATA_MUTATIONS:
            if identity <= "CDM-026":
                _kill_file_mutant(repo, identity, temporary_root)
            elif identity == "CDM-027":
                _expect_code(identity, _kill_report_mutant)
            else:
                _expect_code(identity, lambda: _kill_stream_mutant(repo))
            rows.append(
                {
                    "detectorOwner": DETECTOR_OWNER[identity],
                    "id": identity,
                    "killed": True,
                }
            )
    return rows


def _run_source_mutations(repo: Path, output: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [
            sys.executable,
            str(repo / "tools/causal-flow-simulator/ss0/run_mutations.py"),
            "--root", str(repo),
            "--output", str(output),
        ],
        cwd=repo,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if completed.returncode != 0 or completed.stderr:
        raise ValueError("frozen source-mutation runner failed")
    report = json.loads(output.read_text(encoding="utf-8"))
    if report.get("result") != "PASS" or report.get("killed") != 44:
        raise ValueError("frozen source-mutation report mismatch")
    return report


def run(repo: Path, output: Path) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    if "PYTHONOPTIMIZE" in os.environ:
        raise ValueError("PYTHONOPTIMIZE must be unset")
    corpus_mutations = load_canonical(repo / CORPUS_PATHS[4])["mutations"]
    if [row["id"] for row in corpus_mutations] != sorted(row["id"] for row in corpus_mutations):
        raise ValueError("source mutation relation order mismatch")
    coverage = {
        "corpusWitness": sum(row["coverageClass"] == "CORPUS_WITNESS" for row in corpus_mutations),
        "frozenSupplemental": sum(row["coverageClass"] == "FROZEN_SUPPLEMENTAL" for row in corpus_mutations),
    }
    if coverage != {"corpusWitness": 41, "frozenSupplemental": 3}:
        raise ValueError("source mutation coverage partition mismatch")
    with tempfile.TemporaryDirectory(prefix="styx-ss0-source-mutants-") as name:
        frozen = _run_source_mutations(repo, Path(name) / "frozen-mutations.json")
    data_rows = run_data_mutations(repo)
    report: dict[str, Any] = {
        "coverage": coverage,
        "dataMutations": data_rows,
        "dataMutationsKilled": len(data_rows),
        "result": "PASS",
        "schema": "styx.ss0.corpus.mutation-report.v1",
        "sourceMutationsKilled": frozen["killed"],
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
    validate_corpus(repo, corpus)
    if not arguments.node.resolve(strict=True).is_file():
        raise ValueError("Node capability is unavailable")
    run(repo, arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
