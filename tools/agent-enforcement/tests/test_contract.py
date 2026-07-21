from __future__ import annotations

import sys
import unittest

from support import contract_body, scope_guard

import contract as contract_module


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

    def test_markers_and_headings_inside_fences_are_not_structural(self) -> None:
        body = contract_body().replace(
            "Test contract.",
            "Test contract.\n\n```text\n## Base\n<!-- styx-task-contract:v1 -->\n```",
        )
        parsed = scope_guard.parse_contract(body.encode("utf-8"))
        self.assertEqual("v1", parsed.version)

        only_fenced_marker = body.replace(
            "<!-- styx-task-contract:v1 -->\n\n", "", 1
        )
        with self.assertRaises(scope_guard.ContractError):
            scope_guard.parse_contract(only_fenced_marker.encode("utf-8"))

    def test_markers_and_headings_inside_tilde_fences_are_not_structural(self) -> None:
        body = contract_body().replace(
            "Test contract.",
            "Test contract.\n\n~~~text\n## Base\n<!-- styx-task-contract:v1 -->\n```\n~~~",
        )
        parsed = scope_guard.parse_contract(body.encode("utf-8"))
        self.assertEqual("v1", parsed.version)

        only_fenced_marker = body.replace("<!-- styx-task-contract:v1 -->\n\n", "", 1)
        with self.assertRaises(scope_guard.ContractError):
            scope_guard.parse_contract(only_fenced_marker.encode("utf-8"))

    def test_markers_and_headings_inside_indented_code_are_not_structural(self) -> None:
        body = contract_body().replace(
            "Test contract.",
            "Test contract.\n\n    ## Base\n    <!-- styx-task-contract:v1 -->\n\t<!-- styx-task-contract:v1 -->",
        )
        parsed = scope_guard.parse_contract(body.encode("utf-8"))
        self.assertEqual("v1", parsed.version)

        only_indented_marker = body.replace("<!-- styx-task-contract:v1 -->\n\n", "", 1)
        with self.assertRaises(scope_guard.ContractError):
            scope_guard.parse_contract(only_indented_marker.encode("utf-8"))

    def test_indented_fence_lookalike_does_not_open_a_block(self) -> None:
        # An indented ``` line is code, not a fence: the following heading
        # stays structural and duplicates a required section, failing closed.
        body = contract_body().replace(
            "Test contract.",
            "Test contract.\n\n    ```\n## Base\n    ```",
        )
        with self.assertRaises(scope_guard.ContractError):
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

    def test_adversarial_deep_paths_are_deterministic_errors(self) -> None:
        deep_pattern = "/".join(["a"] * (contract_module.MAX_PATH_SEGMENTS + 1))
        with self.assertRaises(scope_guard.ContractError):
            scope_guard.validate_pattern(deep_pattern)
        with self.assertRaises(contract_module.GitInputError):
            contract_module.validate_repo_path(deep_pattern)

        boundary = "/".join(["a"] * contract_module.MAX_PATH_SEGMENTS)
        self.assertEqual(boundary, scope_guard.validate_pattern(boundary))
        self.assertEqual(boundary, contract_module.validate_repo_path(boundary))

    def test_pattern_matching_is_iterative_under_low_recursion_limit(self) -> None:
        deep_path = "/".join(["a"] * 4000)
        frame, current_depth = sys._getframe(), 0
        while frame is not None:
            current_depth += 1
            frame = frame.f_back
        previous_limit = sys.getrecursionlimit()
        # A recursive matcher would need thousands of frames for this path;
        # leave only a small headroom above the current stack depth.
        sys.setrecursionlimit(current_depth + 80)
        try:
            self.assertTrue(scope_guard.pattern_matches("**", deep_path))
            self.assertTrue(scope_guard.pattern_matches("**/a", deep_path))
            self.assertFalse(scope_guard.pattern_matches("**/b", deep_path))
        finally:
            sys.setrecursionlimit(previous_limit)

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
