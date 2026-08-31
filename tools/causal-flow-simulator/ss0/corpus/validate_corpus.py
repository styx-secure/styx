#!/usr/bin/env python3
"""Fail-closed validator for the synthetic SS-0 corpus."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any

from canonical_json import CanonicalJsonError, canonical_bytes, loads_unique
from generate_corpus import (
    AUTHORITY,
    CORPUS_PATHS,
    EXPECTED_COUNTS,
    NON_CLAIMS,
    PROFILE,
    SUPPLEMENTAL_MUTANTS,
    build_files,
)


class CorpusValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise CorpusValidationError(code, message)


def _fields(value: Any, expected: set[str]) -> None:
    if not isinstance(value, dict):
        _fail("CDM-010", "object is required")
    missing = expected - set(value)
    if missing:
        _fail("CDM-010", f"missing fields: {sorted(missing)}")
    extra = set(value) - expected
    if extra:
        _fail("CDM-009", f"unknown fields: {sorted(extra)}")


def _read_document(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if not data.endswith(b"\n"):
        _fail("CDM-013", f"missing final LF: {path.name}")
    try:
        value = loads_unique(data)
    except CanonicalJsonError as error:
        message = str(error)
        if "duplicate object key" in message:
            _fail("CDM-008", message)
        if "floating-point" in message or "non-finite" in message:
            _fail("CDM-015", message)
        if "UTF-8" in message or "BOM" in message:
            _fail("CDM-014", message)
        _fail("CDM-012", message)
    if canonical_bytes(value) != data:
        _fail("CDM-012", f"non-canonical JSON: {path.name}")
    if not isinstance(value, dict):
        _fail("CDM-010", f"top-level object required: {path.name}")
    return value


def _walk_input(value: Any) -> None:
    if isinstance(value, list):
        for item in value:
            _walk_input(item)
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        normalized = key.replace("_", "").replace("-", "").lower()
        if normalized in {"expected", "disposition", "result"}:
            _fail("CDM-021", f"result oracle in reader input: {key}")
        if normalized in {"assertion", "assertions", "detector", "sourcemutant"}:
            _fail("CDM-022", f"detector oracle in reader input: {key}")
        _walk_input(item)


def validate_corpus(repo: Path, corpus_dir: Path) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    corpus_dir = corpus_dir.resolve(strict=False)
    expected_dir = (repo / "conformance/secure-session/ss0").resolve()
    if corpus_dir != expected_dir:
        _fail("CDM-003", "unexpected corpus directory")
    manifest_path = repo / CORPUS_PATHS[0]
    if not manifest_path.exists():
        _fail("CDM-001", "manifest is missing")
    for name in CORPUS_PATHS:
        path = repo / name
        if path.is_symlink():
            _fail("CDM-004", f"symlink corpus member: {name}")
        if not path.is_file():
            _fail("CDM-001" if name == CORPUS_PATHS[0] else "CDM-002", f"missing corpus member: {name}")
    observed_names = sorted(
        str(path.relative_to(repo)) for path in corpus_dir.iterdir() if path.name not in {".", ".."}
    )
    if observed_names != sorted(CORPUS_PATHS):
        _fail("CDM-003", "corpus file set mismatch")

    documents = {name: _read_document(repo / name) for name in CORPUS_PATHS}
    manifest = documents[CORPUS_PATHS[0]]
    _fields(manifest, {
        "authority", "counts", "generatedFiles", "generator",
        "manifestPayloadSha256", "nonClaims", "normativeInputs", "profile",
        "reproductionInputs", "schema", "synthetic", "upstreamBytes",
    })
    if manifest["schema"] != "styx.ss0.corpus.manifest.v1":
        _fail("CDM-011", "manifest schema mismatch")
    if manifest["synthetic"] is not True or manifest["upstreamBytes"] != "none":
        _fail("CDM-023", "synthetic/upstream boundary mismatch")
    if manifest["profile"] != PROFILE or manifest["authority"] != AUTHORITY or manifest["nonClaims"] != NON_CLAIMS:
        _fail("CORPUS-AUTHORITY", "manifest profile or authority mismatch")
    if manifest["counts"] != EXPECTED_COUNTS:
        _fail("CDM-026", "manifest count mismatch")
    expected_generated = list(CORPUS_PATHS[1:])
    generated = manifest["generatedFiles"]
    if not isinstance(generated, list) or [row.get("path") for row in generated if isinstance(row, dict)] != expected_generated:
        _fail("CDM-005", "generated file relation order mismatch")
    for row, name in zip(generated, expected_generated, strict=True):
        _fields(row, {"path", "sha256"})
        digest = hashlib.sha256((repo / name).read_bytes()).hexdigest()
        if row["sha256"] != digest:
            _fail("CDM-006", f"generated file digest mismatch: {name}")
    projection = dict(manifest)
    claimed_projection = projection.pop("manifestPayloadSha256")
    if claimed_projection != hashlib.sha256(canonical_bytes(projection)).hexdigest():
        _fail("CDM-007", "manifest self-projection mismatch")

    schemas = {
        CORPUS_PATHS[1]: ("styx.ss0.corpus.valid-session-vectors.v1", "vectors"),
        CORPUS_PATHS[2]: ("styx.ss0.corpus.invalid-session-vectors.v1", "vectors"),
        CORPUS_PATHS[3]: ("styx.ss0.corpus.state-machine-scenarios.v1", "scenarios"),
    }
    partitions: dict[str, str] = {}
    inputs: dict[str, Any] = {}
    for name, (schema, collection) in schemas.items():
        document = documents[name]
        _fields(document, {"schema", collection})
        if document["schema"] != schema:
            _fail("CDM-011", f"schema mismatch: {name}")
        if not isinstance(document[collection], list):
            _fail("CDM-010", f"collection mismatch: {name}")
        for row in document[collection]:
            _fields(row, {"id", "input", "sourceWitness"})
            identity = row["id"]
            if not isinstance(identity, str) or identity in partitions:
                _fail("CDM-016", f"duplicate or invalid case ID: {identity}")
            if row["sourceWitness"] != identity:
                _fail("CDM-020", f"source witness mismatch: {identity}")
            _walk_input(row["input"])
            partitions[identity] = name
            inputs[identity] = row["input"]

    traces = documents[CORPUS_PATHS[5]]
    _fields(traces, {"schema", "traces"})
    if traces["schema"] != "styx.ss0.corpus.expected-traces.v1":
        _fail("CDM-011", "trace schema mismatch")
    trace_ids: list[str] = []
    for row in traces["traces"]:
        _fields(row, {"expected", "id"})
        if row["id"] in trace_ids:
            _fail("CDM-016", f"duplicate trace ID: {row['id']}")
        trace_ids.append(row["id"])
    source = loads_unique((repo / "tools/causal-flow-simulator/ss0/source-inventory.json").read_bytes())
    source_rows = {row["id"]: row for row in source["witnesses"]}
    missing = set(source_rows) - set(partitions)
    extra = set(partitions) - set(source_rows)
    if missing:
        _fail("CDM-017", f"missing source witness: {sorted(missing)}")
    if extra:
        _fail("CDM-018", f"extra source witness: {sorted(extra)}")
    if set(trace_ids) != set(partitions):
        _fail("CDM-020", "trace/input ID relation mismatch")
    expected_files = build_files(repo)
    expected_docs = {name: loads_unique(data) for name, data in expected_files.items()}
    expected_partition = {}
    for name in CORPUS_PATHS[1:4]:
        collection = "scenarios" if name == CORPUS_PATHS[3] else "vectors"
        expected_partition.update({row["id"]: name for row in expected_docs[name][collection]})
    if partitions != expected_partition:
        _fail("CDM-019", "source witness partition mismatch")

    mutations = documents[CORPUS_PATHS[4]]
    _fields(mutations, {"mutations", "schema"})
    if mutations["schema"] != "styx.ss0.corpus.adversarial-mutations.v1":
        _fail("CDM-011", "mutation schema mismatch")
    expected_mutations = expected_docs[CORPUS_PATHS[4]]["mutations"]
    observed_mutations = mutations["mutations"]
    if not isinstance(observed_mutations, list) or {row.get("id") for row in observed_mutations if isinstance(row, dict)} != {row["id"] for row in expected_mutations}:
        _fail("CDM-024", "mutation record set mismatch")
    if observed_mutations != expected_mutations:
        _fail("CDM-025", "mutation detector relation mismatch")

    expected_traces = expected_docs[CORPUS_PATHS[5]]["traces"]
    if traces["traces"] != expected_traces or any(inputs[key] != source_rows[key]["input"] for key in inputs):
        _fail("CORPUS-CONTENT", "corpus content differs from pinned source")
    return {"cases": len(partitions), "mutations": len(observed_mutations), "result": "PASS"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    arguments = parser.parse_args()
    repo = arguments.repo_root.resolve(strict=True)
    corpus = arguments.corpus_dir if arguments.corpus_dir.is_absolute() else repo / arguments.corpus_dir
    validate_corpus(repo, corpus)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
