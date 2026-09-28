from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inventory import CONTRACT_FILES, InventoryError, verify_contract_package


class ContractPackageTests(unittest.TestCase):
    def test_exact_ratified_package_passes(self) -> None:
        manifest = verify_contract_package(ROOT / "contract")
        self.assertEqual(len(manifest["artifacts"]), 27)
        self.assertEqual(len(list((ROOT / "contract").iterdir())), CONTRACT_FILES)

    def test_missing_extra_symlink_and_altered_bytes_fail_closed(self) -> None:
        for mutation in ("missing", "extra", "symlink", "altered"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                package = Path(raw) / "contract"
                shutil.copytree(ROOT / "contract", package)
                target = package / "APP-CORE-FLOW-CLOSURE.md"
                if mutation == "missing":
                    target.unlink()
                elif mutation == "extra":
                    (package / "unexpected.txt").write_text("x", encoding="utf-8")
                elif mutation == "symlink":
                    target.unlink()
                    target.symlink_to("APP-CORE-EVIDENCE-UPDATE-CANDIDATE.md")
                else:
                    target.write_bytes(target.read_bytes() + b"x")
                with self.assertRaises((InventoryError, FileNotFoundError)):
                    verify_contract_package(package)

    def test_every_semantic_target_resolves_and_dangling_target_fails_closed(self) -> None:
        validator_path = ROOT / "contract" / "validate_app_core_contract_candidates.py"
        spec = importlib.util.spec_from_file_location("app_core_contract_validator", validator_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        schema = json.loads(
            (ROOT / "contract" / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json").read_text()
        )
        semantics = json.loads(
            (ROOT / "contract" / "APP-CORE-IFACE-0-SEMANTIC-CONSTRAINTS-CANDIDATE.json").read_text()
        )
        validator.validate_semantic_targets(schema, semantics)

        dangling = copy.deepcopy(semantics)
        dangling["rules"][0]["targets"][0] = "$defs.DoesNotExist"
        with self.assertRaisesRegex(SystemExit, "unresolved semantic target"):
            validator.validate_semantic_targets(schema, dangling)


if __name__ == "__main__":
    unittest.main()
