from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

# Discovery may cache this module before its body runs. This flag protects the
# later check.py import; the local .gitignore keeps all test bytecode from Git.
sys.dont_write_bytecode = True

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

    def test_rejects_permuted_status_labels(self) -> None:
        self.canonical.write_text(
            self.canonical.read_text() + "\n**missing** at `docs/second.md`.\n",
            encoding="utf-8",
        )
        text = self.mirror.read_text().replace("**implemented**", "**missing**")
        self.mirror.write_text(
            text + "\n**implemented** in `docs/second.md`.\n",
            encoding="utf-8",
        )
        self.assertTrue(any("divergent status labels" in item for item in self.findings()))

    def test_rejects_repository_path_divergence(self) -> None:
        self.mirror.write_text(self.mirror.read_text().replace("docs/example.md", "docs/other.md"))
        self.assertTrue(any("divergent repository paths" in item for item in self.findings()))

    def test_rejects_permuted_repository_paths(self) -> None:
        self.canonical.write_text(
            self.canonical.read_text() + "\nSee `docs/second.md`.\n",
            encoding="utf-8",
        )
        text = self.mirror.read_text().replace("docs/example.md", "docs/second.md")
        self.mirror.write_text(text + "\nVedi `docs/example.md`.\n", encoding="utf-8")
        self.assertTrue(any("divergent repository paths" in item for item in self.findings()))

    def test_checks_status_and_paths_inside_fenced_blocks(self) -> None:
        self.canonical.write_text(
            self.canonical.read_text()
            + "\n```text\n**missing** at `docs/fenced-example.md`.\n```\n",
            encoding="utf-8",
        )
        findings = self.findings()
        self.assertTrue(any("divergent status labels" in item for item in findings))
        self.assertTrue(any("divergent repository paths" in item for item in findings))

    def test_rejects_incompatible_structure(self) -> None:
        self.mirror.write_text(self.mirror.read_text().replace("## 1. Stato", "### 2. Stato"))
        self.assertTrue(any("incompatible heading structure" in item for item in self.findings()))

    def test_ignores_heading_like_text_in_fenced_blocks(self) -> None:
        self.mirror.write_text(self.mirror.read_text() + "\n```sh\n## not a heading\n```\n")
        self.assertFalse(any("incompatible heading structure" in item for item in self.findings()))

    def test_fenced_heading_cannot_replace_real_heading(self) -> None:
        text = self.mirror.read_text().replace("## 1. Stato", "Stato")
        self.mirror.write_text(text + "\n```text\n## 1. Stato\n```\n", encoding="utf-8")
        self.assertTrue(any("incompatible heading structure" in item for item in self.findings()))

    def test_rejects_duplicate_metadata(self) -> None:
        metadata = self.mirror.read_text().splitlines()[0]
        self.mirror.write_text(self.mirror.read_text() + f"\n{metadata}\n", encoding="utf-8")
        self.assertTrue(any("incorrect canonical metadata" in item for item in self.findings()))

    def test_rejects_displaced_metadata(self) -> None:
        self.mirror.write_text("\n" + self.mirror.read_text(), encoding="utf-8")
        self.assertTrue(any("incorrect canonical metadata" in item for item in self.findings()))

    def test_rejects_symlinked_markdown(self) -> None:
        target = self.root / "outside.md"
        target.write_text("# Outside\n", encoding="utf-8")
        try:
            (self.platform / "linked.md").symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        self.assertTrue(any("symlinked Markdown" in item for item in self.findings()))

    def test_requires_pair_to_share_a_directory(self) -> None:
        nested = self.platform / "nested"
        nested.mkdir()
        moved = nested / self.mirror.name
        self.mirror.rename(moved)
        self.canonical.write_text(
            self.canonical.read_text().replace(
                'mirror="docs/platform/guide_IT.md"',
                'mirror="docs/platform/nested/guide_IT.md"',
            ),
            encoding="utf-8",
        )
        self.write_manifest(
            [
                {
                    "canonical": "docs/platform/guide.md",
                    "mirror": "docs/platform/nested/guide_IT.md",
                }
            ]
        )
        self.assertTrue(any("must share a directory" in item for item in self.findings()))

    def test_rejects_closed_schema_extension(self) -> None:
        value = json.loads(self.manifest.read_text())
        value["extra"] = True
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        self.assertTrue(any("exactly" in item for item in self.findings()))

if __name__ == "__main__":
    unittest.main()
