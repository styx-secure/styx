"""Closed 102-row source inventory construction and validation."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from taxonomy import (
    ALIAS,
    POST_C03_MARKERS,
    PRIMARY_ROWS,
    REMOTE_COLLAPSE,
)


BASE_SHA = "d35052dfbf0631c726f250933bc401f424602f31"
REVIEW_MODEL_PATH = "docs/protocol/review/styx-app-kernel-v0-review-model.json"
O08_HANDOFF_SHA256 = "1f35e253bf4ba041c9d949be0d810a9abacddac8c1df979b7e0c018652522dc5"
O08_ENVELOPE_ID = "317206449117fcad351f0338c719085a8eb623605d7768327e27d26fd48256fd"
ANCHOR_REPLACEMENTS = {
    "AUTHENTIC_BUT_UNAUTHORIZED": "`AUTHENTIC_BUT_UNAUTHORIZED` and apply no transition.",
    "SESSION_PROFILE_REQUIRED": "`OB-SS01` | Authenticate session members and bind the exact session profile",
}
NEGATIVE_IDENTIFIERS = frozenset({ALIAS, *POST_C03_MARKERS})
K_COMPETITORS = frozenset(
    {
        "COMMITMENT_MISMATCH",
        "CURRENT_OBJECT_OUT_OF_PROFILE",
        "CREDENTIAL_BINDING_MISMATCH",
        "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED",
        "DUPLICATE",
        "LENGTH_MISMATCH",
        "OPENING_MISSING",
        "REFERENCE_COLLISION_UNSUPPORTED",
        "STRUCTURAL_REJECTION",
        "UNRESOLVABLE_CREDENTIAL",
        "UNRESOLVED_CREDENTIAL_BINDING",
    }
)


class InventoryError(ValueError):
    """The literal inventory diverges from its ratified inputs."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _git(repo: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise InventoryError("git input lookup failed")
    return completed.stdout


def _base_json(repo: Path, path: str) -> dict[str, Any]:
    try:
        value = json.loads(_git(repo, "show", f"{BASE_SHA}:{path}"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("Base JSON input is invalid") from exc
    if not isinstance(value, dict):
        raise InventoryError("Base JSON root must be an object")
    return value


def _o08_handoff(repo: Path) -> dict[str, Any]:
    script = repo / "tools/causal-flow-simulator/o08/generate_handoff.py"
    with tempfile.TemporaryDirectory(prefix="styx-o10-handoff-") as directory:
        output = Path(directory) / "handoff.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(script),
                "--repo-root",
                str(repo),
                "--output",
                str(output),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode != 0:
            raise InventoryError("cannot regenerate frozen O-08 handoff")
        try:
            raw = output.read_bytes()
            report = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InventoryError("regenerated O-08 handoff is unreadable") from exc
        if raw != canonical_bytes(report):
            raise InventoryError("regenerated O-08 handoff is non-canonical")
    if hashlib.sha256(canonical_bytes(report)).hexdigest() != O08_HANDOFF_SHA256:
        raise InventoryError("O-08 handoff digest drift")
    if report.get("schema") != "styx-o08-o10-handoff/v1":
        raise InventoryError("O-08 handoff schema drift")
    rows = report.get("rows")
    if not isinstance(rows, list) or len(rows) != 66:
        raise InventoryError("O-08 handoff row count drift")
    return report


def _mapping(primary: str, *, stage: str | None = None, scope: str) -> dict[str, Any]:
    owner, table_stage, mutation, recovery, retry, observability = PRIMARY_ROWS[primary]
    return {
        "auxiliary": [],
        "mutation": mutation,
        "observability": observability,
        "owner": owner,
        "primary": primary,
        "recovery": recovery,
        "remote_collapse": "APPLIED" if primary == "APPLIED" else REMOTE_COLLAPSE,
        "retry_precondition": retry,
        "scope": scope,
        "stage": table_stage if stage is None else stage,
    }


def expected_inventory(repo: Path) -> dict[str, Any]:
    model = _base_json(repo, REVIEW_MODEL_PATH)
    sources = {record["id"]: record for record in model.get("sources", [])}
    outcomes = model.get("outcomes")
    if not isinstance(outcomes, list) or len(outcomes) != 24:
        raise InventoryError("Base outcome inventory drift")

    rows: list[dict[str, Any]] = []
    positive_by_primary: dict[str, list[str]] = {}
    for outcome in outcomes:
        outcome_id = outcome["id"]
        citations = outcome.get("citations")
        if not isinstance(citations, list):
            raise InventoryError("Base citation list is invalid")
        for index, citation in enumerate(citations):
            source = sources[citation["source_id"]]
            anchor = ANCHOR_REPLACEMENTS.get(outcome_id, citation["anchor"])
            row_id = f"BASE:{outcome_id}:{index:02d}"
            source_record = {
                "anchor": anchor,
                "authority": source["authority"],
                "base_digest": source["sha256"],
                "id": source["id"],
                "normative_owner": list(outcome.get("decision_refs", [])),
                "path": source["path"],
            }
            if outcome_id in NEGATIVE_IDENTIFIERS:
                rows.append(
                    {
                        "disposition": "UNKNOWN_PRIMARY",
                        "forbidden_identifier": outcome_id,
                        "kind": "negative",
                        "row_id": row_id,
                        "source": source_record,
                    }
                )
            else:
                if outcome_id not in PRIMARY_ROWS:
                    raise InventoryError("Base outcome has no primary contract")
                rows.append(
                    {
                        "kind": "positive",
                        "mapping": _mapping(outcome_id, scope="LOCAL_TRANSCRIPT"),
                        "residual_exclusions": {},
                        "row_id": row_id,
                        "source": source_record,
                    }
                )
                positive_by_primary.setdefault(outcome_id, []).append(row_id)

    handoff = _o08_handoff(repo)
    o08_s3_by_primary: dict[str, list[str]] = {}
    for item in handoff["rows"]:
        row_id = f"O08:{item['dimension']}:{item['stage']}"
        primary = item["recovery_class"]
        rows.append(
            {
                "kind": "positive",
                "mapping": _mapping(primary, stage=item["stage"], scope=item["scope"]),
                "residual_exclusions": {},
                "row_id": row_id,
                "source": {
                    "handoff_digest": O08_HANDOFF_SHA256,
                    "handoff_row": item,
                    "selected_envelope": O08_ENVELOPE_ID,
                },
            }
        )
        if item["stage"] == "S3_KERNEL_STRUCTURAL":
            o08_s3_by_primary.setdefault(primary, []).append(row_id)

    exclusions: dict[str, list[str]] = {}
    for competitor in sorted(K_COMPETITORS):
        if competitor == "CURRENT_OBJECT_OUT_OF_PROFILE":
            selected = sorted(o08_s3_by_primary.get(competitor, []))
        else:
            selected = sorted(positive_by_primary.get(competitor, []))
        if not selected:
            raise InventoryError(f"missing INVALID exclusion for {competitor}")
        exclusions[competitor] = selected
    for row in rows:
        if row.get("kind") == "positive" and row["mapping"]["primary"] == "INVALID":
            row["residual_exclusions"] = exclusions

    rows.sort(key=lambda item: item["row_id"])
    if len(rows) != 102 or len({item["row_id"] for item in rows}) != 102:
        raise InventoryError("literal row universe is not 102 unique rows")
    if sum(item["kind"] == "positive" for item in rows) != 99:
        raise InventoryError("positive row count drift")
    return {
        "base": BASE_SHA,
        "handoff_digest": O08_HANDOFF_SHA256,
        "rows": rows,
        "schema": "styx.o10-source-inventory.v1",
        "selected_envelope": O08_ENVELOPE_ID,
    }


def load_literal(repo: Path) -> dict[str, Any]:
    path = repo / "tools/causal-flow-simulator/o10/source-inventory.json"
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("literal inventory is unreadable") from exc
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        raise InventoryError("literal inventory is not canonical")
    return value


def validate_inventory_value(repo: Path, literal: dict[str, Any]) -> dict[str, Any]:
    """Validate an already parsed literal against every ratified input."""

    expected = expected_inventory(repo)
    if literal != expected:
        raise InventoryError("literal inventory differs from ratified inputs")
    for row in literal["rows"]:
        source = row["source"]
        if "path" not in source:
            continue
        text = _git(repo, "show", f"{BASE_SHA}:{source['path']}").decode("utf-8")
        if text.count(source["anchor"]) != 1:
            raise InventoryError(f"source anchor is not unique: {row['row_id']}")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != source["base_digest"]:
            raise InventoryError(f"Base source digest mismatch: {row['row_id']}")
    return literal


def validate_literal(repo: Path) -> dict[str, Any]:
    return validate_inventory_value(repo, load_literal(repo))
