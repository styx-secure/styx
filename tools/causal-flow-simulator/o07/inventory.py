"""Fail-closed validator for the literal O-07 Appendix-A evidence relation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any


O07_ROOT = Path(__file__).resolve().parent
REQUIRED_RELATION_PATH = O07_ROOT / "required_atom_instances_v1.json"
EVIDENCE_INVENTORY_PATH = O07_ROOT / "evidence_inventory_v1.json"
REQUIRED_RELATION_SHA256 = "6e91c6e2734b4c26d3320ad03ca0e8c00db3ae4c1f0e4437524e376ebd9612ed"
EVIDENCE_INVENTORY_SHA256 = "266caf3deb59fa0310d8ebe53436d76e982e778c3c75bdc594f6c64ecded3fb6"
REQUIRED_SCHEMA = "styx-o07-required-atom-instances/v1"
INVENTORY_SCHEMA = "styx-o07-evidence-inventory/v1"
SEMANTIC_FAMILIES = frozenset({"FRM", "DOM", "CER", "GAT", "LIN", "CHK", "ORD"})
GATE_FAMILY = "EVD"
EXPECTED_DISPOSITIONS = frozenset(
    {
        "ACCEPT",
        "GATE_PASS",
        "IDEMPOTENT",
        "LINEAGE_TERMINATED",
        "LIVE_REPLAY_REQUIRED",
        "ORDER_INDEPENDENT",
        "REJECT",
        "UNREACHABLE",
        "UNSUPPORTED",
    }
)


class InventoryError(ValueError):
    """The submitted evidence inventory does not equal the ratified relation."""


@dataclass(frozen=True)
class ValidatedInventory:
    required: tuple[dict[str, Any], ...]
    entries: tuple[dict[str, Any], ...]

    @property
    def semantic_entries(self) -> tuple[dict[str, Any], ...]:
        return tuple(entry for entry in self.entries if entry["evidence_kind"] == "semantic")

    @property
    def gate_entries(self) -> tuple[dict[str, Any], ...]:
        return tuple(entry for entry in self.entries if entry["evidence_kind"] == "gate")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise InventoryError(f"top-level object required: {path.name}")
    return value


def _family(atom_id: str) -> str:
    parts = atom_id.split("-")
    if len(parts) != 3 or parts[0] != "A" or not parts[2].isdigit():
        raise InventoryError(f"invalid atom identifier: {atom_id}")
    return parts[1]


def _unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise InventoryError(f"duplicate {label}")


def validate_inventory(
    *,
    required_path: Path = REQUIRED_RELATION_PATH,
    inventory_path: Path = EVIDENCE_INVENTORY_PATH,
    enforce_pins: bool = True,
) -> ValidatedInventory:
    if enforce_pins:
        if _digest(required_path) != REQUIRED_RELATION_SHA256:
            raise InventoryError("required Appendix-A relation digest mismatch")
        if _digest(inventory_path) != EVIDENCE_INVENTORY_SHA256:
            raise InventoryError("submitted evidence inventory digest mismatch")

    required_payload = _load(required_path)
    inventory_payload = _load(inventory_path)
    if required_payload.get("schema") != REQUIRED_SCHEMA:
        raise InventoryError("required relation schema mismatch")
    if inventory_payload.get("schema") != INVENTORY_SCHEMA:
        raise InventoryError("inventory schema mismatch")
    if inventory_payload.get("required_relation_schema") != REQUIRED_SCHEMA:
        raise InventoryError("inventory does not name the required relation schema")

    required = required_payload.get("rows")
    entries = inventory_payload.get("entries")
    if not isinstance(required, list) or not isinstance(entries, list):
        raise InventoryError("literal relation arrays required")
    if required_payload.get("relation_count") != len(required):
        raise InventoryError("required relation count mismatch")
    if inventory_payload.get("relation_count") != len(entries):
        raise InventoryError("inventory relation count mismatch")

    required_relation = []
    for row in required:
        if not isinstance(row, dict) or set(row) != {
            "atom_instance_id",
            "scenario_instance_id",
            "requirement",
        }:
            raise InventoryError("required relation row schema mismatch")
        required_relation.append((row["atom_instance_id"], row["scenario_instance_id"]))

    allowed_entry_fields = {
        "atom_instance_id",
        "scenario_instance_id",
        "evidence_kind",
        "violated_invariant",
        "o10_placeholder_class",
        "expected_disposition",
        "report_family",
        "mutation_relation",
        "assertion_id",
        "observation_id",
        "requirement",
    }
    observed_relation = []
    semantic_scenarios: list[str] = []
    semantic_mutations: list[str] = []
    semantic_assertions: list[str] = []
    semantic_observations: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != allowed_entry_fields:
            raise InventoryError("inventory entry schema mismatch")
        atom_id = entry["atom_instance_id"]
        scenario_id = entry["scenario_instance_id"]
        family = _family(atom_id)
        expected_kind = "gate" if family == GATE_FAMILY else "semantic"
        if family not in SEMANTIC_FAMILIES | {GATE_FAMILY}:
            raise InventoryError(f"unknown atom family: {family}")
        if entry["evidence_kind"] != expected_kind:
            raise InventoryError(f"wrong evidence kind: {atom_id}")
        if entry["expected_disposition"] not in EXPECTED_DISPOSITIONS:
            raise InventoryError(f"unknown expected disposition: {atom_id}")
        if entry["requirement"] in {"", None} or entry["violated_invariant"] in {"", None}:
            raise InventoryError(f"empty semantic metadata: {atom_id}")
        lowered = " ".join(str(entry[field]).lower() for field in allowed_entry_fields)
        if "wildcard" in lowered or "not applicable" in lowered or "n/a" in lowered:
            raise InventoryError(f"forbidden inventory qualifier: {atom_id}")
        if expected_kind == "semantic":
            if entry["o10_placeholder_class"] in {"", None}:
                raise InventoryError(f"missing O-10 placeholder class: {atom_id}")
            if entry["mutation_relation"] in {"", None}:
                raise InventoryError(f"missing mutation relation: {atom_id}")
            semantic_scenarios.append(scenario_id)
            semantic_mutations.append(entry["mutation_relation"])
            semantic_assertions.append(entry["assertion_id"])
            semantic_observations.append(entry["observation_id"])
        elif entry["o10_placeholder_class"] is not None or entry["mutation_relation"] is not None:
            raise InventoryError(f"gate atom claims semantic mutation evidence: {atom_id}")
        observed_relation.append((atom_id, scenario_id))

    if set(observed_relation) != set(required_relation) or len(observed_relation) != len(required_relation):
        raise InventoryError("inventory atom/scenario relation is not exact")
    _unique([atom for atom, _ in observed_relation], "atom identifier")
    _unique([scenario for _, scenario in observed_relation], "scenario/gate identifier")
    _unique(semantic_scenarios, "semantic scenario identifier")
    _unique(semantic_mutations, "semantic mutation relation")
    _unique(semantic_assertions, "semantic assertion")
    _unique(semantic_observations, "semantic observation")

    required_by_relation = {
        (row["atom_instance_id"], row["scenario_instance_id"]): row for row in required
    }
    for entry in entries:
        row = required_by_relation[(entry["atom_instance_id"], entry["scenario_instance_id"])]
        if entry["requirement"] != row["requirement"]:
            raise InventoryError(f"requirement drift: {entry['atom_instance_id']}")

    return ValidatedInventory(tuple(required), tuple(entries))
