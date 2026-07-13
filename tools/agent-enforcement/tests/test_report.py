from __future__ import annotations

import json
import unittest

from support import GuardIntegrationCase, MiniSchemaValidator, ROOT, SCHEMA, scope_guard


class ReportTests(GuardIntegrationCase):
    def test_deterministic_report_and_repository_immutability(self) -> None:
        base, head = self.simple_history()
        before = self.repo.snapshot()
        first = self.root / "first.json"
        second = self.root / "second.json"
        result1, report1, _ = self.invoke(base, head, output=first)
        result2, report2, _ = self.invoke(base, head, output=second)
        self.assert_verdict(result1, report1, "PASS", 0)
        self.assert_verdict(result2, report2, "PASS", 0)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(before, self.repo.snapshot())
        payload = first.read_text(encoding="utf-8")
        self.assertNotIn("generated_at", payload)
        self.assertNotIn("created_at", payload)

    def test_pass_and_error_reports_match_schema(self) -> None:
        base, head = self.simple_history()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = MiniSchemaValidator(schema)

        result, report, _ = self.invoke(base, head)
        self.assert_verdict(result, report, "PASS", 0)
        validator.validate(report)

        result, report, _ = self.invoke("main", head, output=self.root / "error.json")
        self.assert_verdict(result, report, "ERROR", 3)
        validator.validate(report)

    def test_golden_fixtures_match_schema_and_canonical_json(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = MiniSchemaValidator(schema)
        fixtures = sorted(
            (ROOT / "tools" / "agent-enforcement" / "tests" / "fixtures").glob("golden-*.json")
        )
        self.assertGreaterEqual(len(fixtures), 2)
        for fixture in fixtures:
            with self.subTest(fixture=fixture.name):
                raw = fixture.read_bytes()
                report = json.loads(raw.decode("utf-8"))
                validator.validate(report)
                self.assertEqual(scope_guard.canonical_json_bytes(report), raw)


if __name__ == "__main__":
    unittest.main()
