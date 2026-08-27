"""Closed Base-relative source and inventory model for C0.3 corpus generation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from typing import Any


BASE_SHA = "7768c32d3ddba230bd60f8b5db1b34d4bcb8ec3b"
ENTRY_ROLES = frozenset(
    {
        "C03_SEMANTIC_LIMIT",
        "C03_ACTIVATION_CAPABILITY_INPUT",
        "C03_EXPLICIT_ZERO_OR_UNSUPPORTED",
    }
)
EXPECTED_COUNTS = {
    "actors": 10,
    "blockers": 13,
    "counterexamples": 16,
    "flows": 12,
    "invariants": 23,
    "layers": 6,
    "non_claims": 12,
    "objects": 7,
    "outcomes": 24,
    "residual_risks": 14,
    "review_queries": 9,
    "sources": 20,
    "state_models": 3,
}


class CorpusModelError(ValueError):
    """Pinned corpus input or closed inventory is invalid."""


@dataclass(frozen=True)
class BaseReader:
    repo_root: Path
    base: str = BASE_SHA

    def read(self, path: str) -> bytes:
        if path.startswith("/") or ".." in Path(path).parts:
            raise CorpusModelError(f"unsafe repository path: {path}")
        result = subprocess.run(
            ["git", "show", f"{self.base}:{path}"],
            cwd=self.repo_root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode:
            raise CorpusModelError(f"missing Base blob: {path}")
        return result.stdout

    def json(self, path: str) -> Any:
        try:
            return json.loads(self.read(path))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise CorpusModelError(f"invalid Base JSON: {path}") from error


def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


def load_local_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise CorpusModelError(f"invalid tooling JSON: {path}") from error
    if not isinstance(value, dict):
        raise CorpusModelError(f"tooling JSON must be an object: {path}")
    return value


def _ids(records: Any, label: str) -> list[str]:
    if not isinstance(records, list):
        raise CorpusModelError(f"{label} must be a list")
    values = [record.get("id") for record in records if isinstance(record, dict)]
    if len(values) != len(records) or any(not isinstance(value, str) for value in values):
        raise CorpusModelError(f"{label} has a malformed identifier")
    if len(set(values)) != len(values):
        raise CorpusModelError(f"{label} identifiers are not unique")
    return values


def validate_sources(repo_root: Path) -> dict[str, Any]:
    tool_root = repo_root / "tools/causal-flow-simulator/c03"
    source_map = load_local_json(tool_root / "corpus-source-map.json")
    if source_map.get("schema") != "styx-c03-corpus-source-map/v1":
        raise CorpusModelError("source-map schema mismatch")
    if source_map.get("base") != BASE_SHA:
        raise CorpusModelError("source-map Base mismatch")
    reader = BaseReader(repo_root)
    seen_ids: set[str] = set()
    for source in source_map.get("direct_sources", []):
        if not isinstance(source, dict) or set(source) != {"anchors", "id", "path", "sha256"}:
            raise CorpusModelError("direct source schema mismatch")
        identifier = source["id"]
        if identifier in seen_ids:
            raise CorpusModelError(f"duplicate direct source: {identifier}")
        seen_ids.add(identifier)
        data = reader.read(source["path"])
        if sha256_hex(data) != source["sha256"]:
            raise CorpusModelError(f"Base source digest mismatch: {source['path']}")
        text = data.decode("utf-8")
        for anchor in source["anchors"]:
            if not isinstance(anchor, str) or not anchor or text.count(anchor) != 1:
                raise CorpusModelError(
                    f"source anchor is missing or ambiguous: {identifier}:{anchor}"
                )
    return source_map


def validate_inventory(repo_root: Path) -> dict[str, Any]:
    tool_root = repo_root / "tools/causal-flow-simulator/c03"
    inventory = load_local_json(tool_root / "corpus-inventory.json")
    if inventory.get("schema") != "styx-c03-corpus-inventory/v1":
        raise CorpusModelError("inventory schema mismatch")
    reader = BaseReader(repo_root)
    model = reader.json("docs/protocol/review/styx-app-kernel-v0-review-model.json")
    expected_ids = inventory.get("expected_review_model_ids")
    if not isinstance(expected_ids, dict) or set(expected_ids) != set(EXPECTED_COUNTS):
        raise CorpusModelError("review-model inventory keys mismatch")
    for key, count in EXPECTED_COUNTS.items():
        actual = _ids(model.get(key), key)
        if len(actual) != count or actual != expected_ids[key]:
            raise CorpusModelError(f"closed review-model set mismatch: {key}")

    envelope = reader.json("tools/causal-flow-simulator/o08/resource-envelope.candidate.json")
    entries = envelope.get("entries")
    if not isinstance(entries, dict):
        raise CorpusModelError("O-08 entries are missing")
    role_map = inventory.get("o08_roles")
    if not isinstance(role_map, dict):
        raise CorpusModelError("O-08 role inventory is missing")
    for role, expected in role_map.items():
        actual = sorted(
            identifier
            for identifier, entry in entries.items()
            if isinstance(entry, dict) and entry.get("role") == role
        )
        if actual != expected:
            raise CorpusModelError(f"O-08 role partition mismatch: {role}")
    if sum(len(role_map[role]) for role in ENTRY_ROLES) != 53:
        raise CorpusModelError("O-08 C0.3 entry cardinality mismatch")

    taxonomy = reader.json("tools/causal-flow-simulator/o10/outcome-taxonomy.json")
    if _ids(taxonomy.get("primaries"), "O-10 primaries") != inventory["o10_primaries"]:
        raise CorpusModelError("O-10 primary inventory mismatch")
    if taxonomy.get("post_c03_markers") != inventory["o10_post_c03_markers"]:
        raise CorpusModelError("O-10 post-marker inventory mismatch")
    if taxonomy.get("alias") != inventory["o10_alias"]:
        raise CorpusModelError("O-10 alias mismatch")

    o10_sources = reader.json("tools/causal-flow-simulator/o10/source-inventory.json")
    if len(o10_sources.get("rows", [])) != inventory["o10_source_row_count"]:
        raise CorpusModelError("O-10 source-row cardinality mismatch")
    o07 = reader.json("tools/causal-flow-simulator/o07/required_atom_instances_v1.json")
    if (
        o07.get("relation_count") != inventory["o07_relation_count"]
        or len(o07.get("rows", [])) != inventory["o07_relation_count"]
    ):
        raise CorpusModelError("O-07 relation cardinality mismatch")
    return inventory


def validate_base_inputs(repo_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fail closed before any corpus generation is attempted."""

    if subprocess.run(
        ["git", "cat-file", "-e", f"{BASE_SHA}^{{commit}}"], cwd=repo_root
    ).returncode:
        raise CorpusModelError("exact Base commit is unavailable")
    return validate_sources(repo_root), validate_inventory(repo_root)
