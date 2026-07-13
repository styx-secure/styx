from __future__ import annotations

import unittest

from support import contract_body, scope_guard


class ContractParserTests(unittest.TestCase):
    def test_marker_and_heading_fail_closed(self) -> None:
        cases = {
            "missing marker": contract_body(marker=""),
            "duplicate marker": contract_body() + "\n<!-- styx-task-contract:v1 -->\n",
            "unknown version": contract_body(marker="<!-- styx-task-contract:v2 -->"),
            "missing heading": contract_body().replace("## Rollback\n", "## Rollback removed\n"),
            "duplicate heading": contract_body() + "\n## Base\nsecond\n",
            "both test headings": contract_body() + "\n## Required verification\ntrue\n",
            "neither test heading": contract_body().replace("## Required tests", "## Optional tests"),
            "marker after heading": contract_body().replace(
                "<!-- styx-task-contract:v1 -->\n\n", ""
            ).replace("## Non-goals", "<!-- styx-task-contract:v1 -->\n\n## Non-goals", 1),
        }
        for name, body in cases.items():
            with self.subTest(name=name), self.assertRaises(scope_guard.ContractError):
                scope_guard.parse_contract(body.encode("utf-8"))

    def test_required_verification_is_accepted(self) -> None:
        parsed = scope_guard.parse_contract(
            contract_body(test_heading="Required verification").encode("utf-8")
        )
        self.assertEqual("v1", parsed.version)

    def test_malformed_patterns_are_errors(self) -> None:
        bad_patterns = (
            "/absolute",
            "../escape",
            "a/./b",
            "a//b",
            "a/",
            "a\\b",
            "a/**b",
            "a/[bc]",
            "a/{b,c}",
            "!secret/**",
            "x@(a|b)/**",
            "a ",
        )
        for pattern in bad_patterns:
            with self.subTest(pattern=pattern), self.assertRaises(scope_guard.ContractError):
                scope_guard.validate_pattern(pattern)

    def test_duplicate_patterns_are_errors(self) -> None:
        with self.assertRaises(scope_guard.ContractError):
            scope_guard.parse_contract(
                contract_body(allowed=("tools/**", "tools/**")).encode("utf-8")
            )

    def test_glob_semantics(self) -> None:
        cases = (
            ("a/*/c", "a/b/c", True),
            ("a/*/c", "a/b/d/c", False),
            ("a/**/c", "a/c", True),
            ("a/**/c", "a/b/d/c", True),
            ("a/?.txt", "a/x.txt", True),
            ("a/?.txt", "a/xy.txt", False),
        )
        for pattern, path, expected in cases:
            with self.subTest(pattern=pattern, path=path):
                self.assertEqual(expected, scope_guard.pattern_matches(pattern, path))


if __name__ == "__main__":
    unittest.main()
