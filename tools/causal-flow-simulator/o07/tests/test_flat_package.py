from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from verify_flat_package import MANIFEST_NAME, verify_flat_package  # noqa: E402


def _manifest(root: Path, names: list[str]) -> None:
    lines = [f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}" for name in names]
    (root / MANIFEST_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")


class FlatPackageTests(unittest.TestCase):
    def test_exact_flat_regular_file_set_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bundle.bin").write_bytes(b"bundle")
            (root / "report.json").write_text("{}\n")
            _manifest(root, ["bundle.bin", "report.json"])
            self.assertEqual(verify_flat_package(root), 2)

    def test_missing_or_unlisted_artifact_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "listed.txt").write_text("listed\n")
            _manifest(root, ["listed.txt"])
            (root / "extra.txt").write_text("extra\n")
            with self.assertRaisesRegex(ValueError, "artifact set"):
                verify_flat_package(root)
            (root / "extra.txt").unlink()
            (root / "listed.txt").unlink()
            with self.assertRaisesRegex(ValueError, "artifact set"):
                verify_flat_package(root)

    def test_directory_symlink_duplicate_and_separator_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.txt"
            artifact.write_text("artifact\n")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            manifest = root / MANIFEST_NAME

            manifest.write_text(f"{digest}  artifact.txt\n{digest}  artifact.txt\n")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                verify_flat_package(root)

            manifest.write_text(f"{digest}  nested/artifact.txt\n")
            with self.assertRaisesRegex(ValueError, "not canonical"):
                verify_flat_package(root)

            manifest.write_text(f"{digest}  artifact.txt\n")
            (root / "directory").mkdir()
            with self.assertRaisesRegex(ValueError, "non-regular"):
                verify_flat_package(root)
            (root / "directory").rmdir()

            (root / "link.txt").symlink_to(artifact)
            with self.assertRaisesRegex(ValueError, "non-regular"):
                verify_flat_package(root)


if __name__ == "__main__":
    unittest.main()
