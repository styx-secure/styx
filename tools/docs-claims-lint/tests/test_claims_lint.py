"""Unit tests for the documentation claims linter."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from claims_lint import EXIT_FAIL, EXIT_PASS, lint_text, main  # noqa: E402


class LintTextTests(unittest.TestCase):
    def test_affirmative_claim_is_flagged(self):
        findings = lint_text("Styx ships a zero-server architecture.", "doc.md")
        self.assertEqual(len(findings), 1)
        self.assertIn("zero-server", findings[0])

    def test_each_forbidden_term_is_flagged(self):
        samples = [
            "A serverless design.",
            "It offers zero-knowledge storage.",
            "A zero-metadata transport.",
            "The relay cannot read your messages.",
            "Il relay non può leggere i messaggi.",
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(lint_text(sample, "doc.md"))

    def test_negation_on_same_line_is_allowed(self):
        text = 'This is not a zero-metadata or "serverless" system.'
        self.assertEqual(lint_text(text, "doc.md"), [])

    def test_italian_negation_is_allowed(self):
        text = "Non è un sistema zero-server né zero-knowledge."
        self.assertEqual(lint_text(text, "doc.md"), [])

    def test_negation_on_previous_line_is_allowed(self):
        text = "Do not introduce\n\"serverless\" or equivalent claims."
        self.assertEqual(lint_text(text, "doc.md"), [])

    def test_suppression_marker_is_honoured(self):
        text = "<!-- claims-lint: allow -->\nDiscussing the zero-server claim."
        self.assertEqual(lint_text(text, "doc.md"), [])

    def test_clean_text_passes(self):
        text = "Relays observe transport metadata. Honest framing only."
        self.assertEqual(lint_text(text, "doc.md"), [])

    def test_finding_reports_path_and_line(self):
        findings = lint_text("ok\n\nA serverless product.", "docs/x.md")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].startswith("docs/x.md:3:"))


class MainTests(unittest.TestCase):
    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            clean = Path(tmp) / "clean.md"
            clean.write_text("All honest here.\n", encoding="utf-8")
            dirty = Path(tmp) / "dirty.md"
            dirty.write_text("A zero-server marvel.\n", encoding="utf-8")
            self.assertEqual(main(["--scan", str(clean)]), EXIT_PASS)
            self.assertEqual(main(["--scan", str(dirty)]), EXIT_FAIL)
            self.assertEqual(main(["--scan", tmp]), EXIT_FAIL)

    def test_exclude_skips_file_and_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            historical = Path(tmp) / "history"
            historical.mkdir()
            (historical / "old-design.md").write_text(
                "A serverless design.\n", encoding="utf-8"
            )
            dirty = Path(tmp) / "dirty.md"
            dirty.write_text("A zero-server marvel.\n", encoding="utf-8")
            self.assertEqual(
                main(["--scan", tmp, "--exclude", str(historical), str(dirty)]),
                EXIT_PASS,
            )
            self.assertEqual(
                main(["--scan", tmp, "--exclude", str(historical)]),
                EXIT_FAIL,
            )


if __name__ == "__main__":
    unittest.main()
