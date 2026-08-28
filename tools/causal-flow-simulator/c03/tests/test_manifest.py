from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))

from validate_corpus import ValidationError, _walk_hygiene, validate  # noqa: E402


class ManifestTests(unittest.TestCase):
    def test_tracked_manifest_and_corpus_validate(self) -> None:
        report = validate(REPO, CORPUS)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["mutations"], 466)

    def test_hygiene_rejects_embedded_absolute_paths_but_not_reuse_label(self) -> None:
        for value in ("path=/", "provenance=/tmp/styx", "path=C:\\review", r"path=\\host\share"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                _walk_hygiene(value)
        _walk_hygiene("6.2.0 / REUSE-3.3")


if __name__ == "__main__":
    unittest.main()
