from __future__ import annotations

import json
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from semantic_registry import RegistryError, SOURCES_PATH, load_source_registry


class InventoryTests(unittest.TestCase):
    def test_closed_inventory_counts(self):
        registry = load_source_registry()
        self.assertEqual((len(registry.dimensions), len(registry.anchors)), (67, 28))
        self.assertEqual((len(registry.entry_dimensions), len(registry.non_entry_dimensions)), (52, 15))
        self.assertEqual(len(registry.integer_field_coverage), len({
            row["field"] for row in registry.integer_field_coverage
        }))

    def test_missing_and_duplicate_dimensions_fail(self):
        source = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
        for mutation in ("missing", "duplicate"):
            value = json.loads(json.dumps(source))
            dimensions = value["groups"][0]["dimensions"]
            dimensions.pop() if mutation == "missing" else dimensions.append(dimensions[0])
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "sources.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(RegistryError):
                    load_source_registry(path)

    def test_integer_field_coverage_is_closed_and_has_no_generic_fallback(self):
        source = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
        mutations = []
        missing = json.loads(json.dumps(source)); missing["integer_field_coverage"].pop(); mutations.append(missing)
        duplicate = json.loads(json.dumps(source)); duplicate["integer_field_coverage"].append(duplicate["integer_field_coverage"][0]); mutations.append(duplicate)
        fallback = json.loads(json.dumps(source)); fallback["integer_field_coverage"][0]["dimension"] = "INTEGER_FIELD_RANGE"; mutations.append(fallback)
        with tempfile.TemporaryDirectory() as temporary:
            for index, value in enumerate(mutations):
                path = Path(temporary) / f"coverage-{index}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(RegistryError):
                    load_source_registry(path)

    def test_stale_base_unknown_role_duplicate_stage_and_promotions_fail(self):
        source = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
        mutations = []
        stale = json.loads(json.dumps(source)); stale["candidate_head"] = "0" * 40; mutations.append(stale)
        unknown = json.loads(json.dumps(source)); unknown["scope_roles"]["UNKNOWN"] = unknown["scope_roles"].pop("EVIDENCE_ONLY"); mutations.append(unknown)
        duplicated = json.loads(json.dumps(source)); duplicated["dimension_enforcement_stages"]["EVENTS_ADMITTED"].append("S4_GRAPH_ADMISSION"); mutations.append(duplicated)
        promoted_post = json.loads(json.dumps(source)); promoted_post["scope_roles"]["POST_C03_LAYER_PROFILE"].remove("RETRY_WORK"); promoted_post["scope_roles"]["C03_SEMANTIC_LIMIT"].append("RETRY_WORK"); mutations.append(promoted_post)
        promoted_evidence = json.loads(json.dumps(source)); promoted_evidence["scope_roles"]["EVIDENCE_ONLY"].remove("ORACLE_ORDER_WIDTH"); promoted_evidence["scope_roles"]["C03_SEMANTIC_LIMIT"].append("ORACLE_ORDER_WIDTH"); mutations.append(promoted_evidence)
        with tempfile.TemporaryDirectory() as temporary:
            for index, value in enumerate(mutations):
                path = Path(temporary) / f"{index}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(RegistryError):
                    load_source_registry(path)


if __name__ == "__main__":
    unittest.main()
