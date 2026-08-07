from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "check.py"
SPEC = importlib.util.spec_from_file_location("docs_translation_sync", MODULE_PATH)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class TranslationSyncTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.platform = self.root / "docs" / "platform"
        self.platform.mkdir(parents=True)
        self.canonical = self.platform / "guide.md"
        self.mirror = self.platform / "guide_IT.md"
        self.manifest = self.platform / "translation-pairs.json"
        self.write_pair()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_manifest(self, pairs: list[dict[str, str]] | None = None) -> None:
        value = {
            "schema": "styx.docs.translation-pairs",
            "version": 1,
            "hash": "sha256",
            "pairs": pairs
            or [
                {
                    "canonical": "docs/platform/guide.md",
                    "mirror": "docs/platform/guide_IT.md",
                }
            ],
        }
        self.manifest.write_text(json.dumps(value), encoding="utf-8")

    def write_pair(self) -> None:
        self.canonical.write_text(
            '<!-- styx-canonical:v1 mirror="docs/platform/guide_IT.md" -->\n'
            "# Guide\n\n[Italian mirror](guide_IT.md)\n\n"
            "## 1. State\n\n**implemented** at `docs/example.md`.\n",
            encoding="utf-8",
        )
        self.mirror.write_text(
            '<!-- styx-translation:v1 canonical="docs/platform/guide.md" '
            f'sha256="{self.digest(self.canonical)}" -->\n'
            "# Guida\n\n[English canonical](guide.md)\n\n"
            "## 1. Stato\n\n**implemented** in `docs/example.md`.\n",
            encoding="utf-8",
        )
        self.write_manifest()

    def findings(self) -> list[str]:
        return CHECK.validate_manifest(self.manifest)

    def test_accepts_valid_pair(self) -> None:
        self.assertEqual([], self.findings())

    def test_rejects_missing_file(self) -> None:
        self.mirror.unlink()
        self.assertTrue(any("does not exist" in item for item in self.findings()))

    def test_rejects_missing_pair(self) -> None:
        (self.platform / "orphan.md").write_text("# Orphan\n", encoding="utf-8")
        self.assertTrue(any("missing from the manifest" in item for item in self.findings()))

    def test_rejects_stale_hash(self) -> None:
        self.canonical.write_text(self.canonical.read_text() + "Changed.\n")
        self.assertTrue(any("stale canonical SHA-256" in item for item in self.findings()))

    def test_rejects_path_escape(self) -> None:
        self.write_manifest(
            [
                {
                    "canonical": "docs/platform/../outside.md",
                    "mirror": "docs/platform/guide_IT.md",
                }
            ]
        )
        self.assertTrue(any("escapes docs/platform" in item for item in self.findings()))

    def test_rejects_duplicate_path(self) -> None:
        pair = {
            "canonical": "docs/platform/guide.md",
            "mirror": "docs/platform/guide_IT.md",
        }
        self.write_manifest([pair, pair])
        self.assertTrue(any("duplicates path" in item for item in self.findings()))

    def test_rejects_non_markdown_path(self) -> None:
        self.write_manifest(
            [
                {
                    "canonical": "docs/platform/guide.txt",
                    "mirror": "docs/platform/guide_IT.md",
                }
            ]
        )
        self.assertTrue(any("not Markdown" in item for item in self.findings()))

    def test_rejects_status_divergence(self) -> None:
        self.mirror.write_text(self.mirror.read_text().replace("**implemented**", "implemented"))
        self.assertTrue(any("divergent status labels" in item for item in self.findings()))

    def test_rejects_repository_path_divergence(self) -> None:
        self.mirror.write_text(self.mirror.read_text().replace("docs/example.md", "docs/other.md"))
        self.assertTrue(any("divergent repository paths" in item for item in self.findings()))

    def test_rejects_incompatible_structure(self) -> None:
        self.mirror.write_text(self.mirror.read_text().replace("## 1. Stato", "### 2. Stato"))
        self.assertTrue(any("incompatible heading structure" in item for item in self.findings()))

    def test_rejects_closed_schema_extension(self) -> None:
        value = json.loads(self.manifest.read_text())
        value["extra"] = True
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        self.assertTrue(any("exactly" in item for item in self.findings()))


if __name__ == "__main__":
    unittest.main()
