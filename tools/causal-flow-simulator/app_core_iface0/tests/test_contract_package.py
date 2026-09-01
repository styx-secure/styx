from __future__ import annotations

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
        self.assertEqual(len(manifest["artifacts"]), 26)
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


if __name__ == "__main__":
    unittest.main()

