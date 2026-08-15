from __future__ import annotations

import sys
import unittest

from support import contract_body, scope_guard

import contract as contract_module


class ContractParserTests(unittest.TestCase):
    SHA256 = "1" * 64

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

    def test_binary_artifact_section_is_optional_and_strict(self) -> None:
        legacy = scope_guard.parse_contract(contract_body().encode("utf-8"))
        self.assertEqual((), legacy.allowed_binary_artifacts)

        declaration = f"{self.SHA256} 7 artifacts/blob with spaces.bin"
        parsed = scope_guard.parse_contract(
            contract_body(binary_artifacts=(declaration,)).encode("utf-8")
        )
        self.assertEqual(1, len(parsed.allowed_binary_artifacts))
        artifact = parsed.allowed_binary_artifacts[0]
        self.assertEqual(self.SHA256, artifact.sha256)
        self.assertEqual(7, artifact.byte_length)
        self.assertEqual("artifacts/blob with spaces.bin", artifact.path)

    def test_binary_artifact_declaration_rejects_malformed_values(self) -> None:
        good_path = "artifacts/blob.bin"
        cases = {
            "uppercase hash": f"{'A' * 64} 1 {good_path}",
            "short hash": f"{'1' * 63} 1 {good_path}",
            "non-hex hash": f"{'z' * 64} 1 {good_path}",
            "signed length": f"{self.SHA256} +1 {good_path}",
            "fractional length": f"{self.SHA256} 1.0 {good_path}",
            "zero length": f"{self.SHA256} 0 {good_path}",
            "leading-zero length": f"{self.SHA256} 01 {good_path}",
            "oversized length": f"{self.SHA256} 1073741825 {good_path}",
            "unbounded integer": f"{self.SHA256} {'9' * 5000} {good_path}",
            "missing path": f"{self.SHA256} 1",
            "tab separators": f"{self.SHA256}\t1\t{good_path}",
            "absolute path": f"{self.SHA256} 1 /artifact.bin",
            "dot path": f"{self.SHA256} 1 artifacts/../artifact.bin",
            "repeated slash": f"{self.SHA256} 1 artifacts//artifact.bin",
            "wildcard star": f"{self.SHA256} 1 artifacts/*.bin",
            "wildcard question": f"{self.SHA256} 1 artifacts/blob?.bin",
            "wildcard class": f"{self.SHA256} 1 artifacts/blob[0].bin",
            "control character": f"{self.SHA256} 1 artifacts/blob\x01.bin",
            "trailing space": f"{self.SHA256} 1 {good_path} ",
        }
        for name, declaration in cases.items():
            with self.subTest(name=name), self.assertRaises(scope_guard.ContractError):
                scope_guard.parse_contract(
                    contract_body(binary_artifacts=(declaration,)).encode("utf-8")
                )

    def test_binary_artifact_section_rejects_duplicates_limits_and_bad_fences(self) -> None:
        duplicate_path = contract_body(
            binary_artifacts=(
                f"{self.SHA256} 1 artifacts/blob.bin",
                f"{'2' * 64} 2 artifacts/blob.bin",
            )
        )
        too_many = tuple(
            f"{self.SHA256} 1 artifacts/blob-{index}.bin" for index in range(33)
        )
        empty = contract_body(binary_artifacts=())
        duplicate_heading = contract_body(
            binary_artifacts=(f"{self.SHA256} 1 artifacts/blob.bin",)
        ) + "\n## Allowed binary artifacts\n\n```text\nignored\n```\n"
        multiple_fences = contract_body(
            binary_artifacts=(f"{self.SHA256} 1 artifacts/blob.bin",)
        ).replace(
            "## Native dependencies",
            "```text\nsecond\n```\n\n## Native dependencies",
            1,
        )
        declaration = f"{self.SHA256} 1 artifacts/blob.bin"
        unterminated = contract_body(binary_artifacts=(declaration,)).replace(
            f"{declaration}\n```\n", f"{declaration}\n", 1
        )
        for name, body in {
            "duplicate path": duplicate_path,
            "too many": contract_body(binary_artifacts=too_many),
            "empty": empty,
            "duplicate heading": duplicate_heading,
            "multiple fences": multiple_fences,
            "unterminated fence": unterminated,
        }.items():
            with self.subTest(name=name), self.assertRaises(scope_guard.ContractError):
                scope_guard.parse_contract(body.encode("utf-8"))

    def test_binary_heading_inside_a_fence_is_not_structural(self) -> None:
        body = contract_body().replace(
            "Test contract.",
            "Test contract.\n\n```text\n## Allowed binary artifacts\ninvalid\n```",
        )
        parsed = scope_guard.parse_contract(body.encode("utf-8"))
        self.assertEqual((), parsed.allowed_binary_artifacts)

    def test_copy_source_section_is_optional_and_strict(self) -> None:
        legacy = scope_guard.parse_contract(contract_body().encode("utf-8"))
        self.assertEqual((), legacy.allowed_copy_sources)

        declaration = f"{self.SHA256} 7 legacy/source with spaces.mjs"
        parsed = scope_guard.parse_contract(
            contract_body(copy_sources=(declaration,)).encode("utf-8")
        )
        self.assertEqual(1, len(parsed.allowed_copy_sources))
        source = parsed.allowed_copy_sources[0]
        self.assertEqual(self.SHA256, source.sha256)
        self.assertEqual(7, source.byte_length)
        self.assertEqual("legacy/source with spaces.mjs", source.path)

        maximum = scope_guard.parse_contract(
            contract_body(
                copy_sources=(
                    f"{self.SHA256} {contract_module.MAX_COPY_SOURCE_SIZE} legacy/maximum.mjs",
                )
            ).encode("utf-8")
        )
        self.assertEqual(contract_module.MAX_COPY_SOURCE_SIZE, maximum.allowed_copy_sources[0].byte_length)

    def test_copy_source_declaration_rejects_malformed_values(self) -> None:
        good_path = "legacy/source.mjs"
        cases = {
            "uppercase hash": f"{'A' * 64} 1 {good_path}",
            "short hash": f"{'1' * 63} 1 {good_path}",
            "non-hex hash": f"{'z' * 64} 1 {good_path}",
            "signed length": f"{self.SHA256} +1 {good_path}",
            "fractional length": f"{self.SHA256} 1.0 {good_path}",
            "zero length": f"{self.SHA256} 0 {good_path}",
            "leading-zero length": f"{self.SHA256} 01 {good_path}",
            "oversized length": f"{self.SHA256} 67108865 {good_path}",
            "unbounded integer": f"{self.SHA256} {'9' * 5000} {good_path}",
            "missing path": f"{self.SHA256} 1",
            "tab separators": f"{self.SHA256}\t1\t{good_path}",
            "absolute path": f"{self.SHA256} 1 /source.mjs",
            "dot path": f"{self.SHA256} 1 legacy/../source.mjs",
            "repeated slash": f"{self.SHA256} 1 legacy//source.mjs",
            "wildcard star": f"{self.SHA256} 1 legacy/*.mjs",
            "wildcard question": f"{self.SHA256} 1 legacy/source?.mjs",
            "wildcard class": f"{self.SHA256} 1 legacy/source[0].mjs",
            "wildcard brace": f"{self.SHA256} 1 legacy/source{{0}}.mjs",
            "control character": f"{self.SHA256} 1 legacy/source\x01.mjs",
            "trailing space": f"{self.SHA256} 1 {good_path} ",
        }
        for name, declaration in cases.items():
            with self.subTest(name=name), self.assertRaises(scope_guard.ContractError):
                scope_guard.parse_contract(
                    contract_body(copy_sources=(declaration,)).encode("utf-8")
                )

    def test_copy_source_section_rejects_duplicates_limits_and_bad_fences(self) -> None:
        duplicate_path = contract_body(
            copy_sources=(
                f"{self.SHA256} 1 legacy/source.mjs",
                f"{'2' * 64} 2 legacy/source.mjs",
            )
        )
        too_many = tuple(
            f"{self.SHA256} 1 legacy/source-{index}.mjs" for index in range(33)
        )
        at_limit = tuple(
            f"{self.SHA256} 1 legacy/limit-{index}.mjs" for index in range(32)
        )
        parsed_at_limit = scope_guard.parse_contract(
            contract_body(copy_sources=at_limit).encode("utf-8")
        )
        self.assertEqual(contract_module.MAX_COPY_SOURCES, len(parsed_at_limit.allowed_copy_sources))
        declaration = f"{self.SHA256} 1 legacy/source.mjs"
        cases = {
            "duplicate path": duplicate_path,
            "too many": contract_body(copy_sources=too_many),
            "empty": contract_body(copy_sources=()),
            "duplicate heading": contract_body(copy_sources=(declaration,))
            + "\n## Allowed copy sources\n\n```text\nignored\n```\n",
            "multiple fences": contract_body(copy_sources=(declaration,)).replace(
                "## Native dependencies",
                "```text\nsecond\n```\n\n## Native dependencies",
                1,
            ),
            "unterminated fence": contract_body(copy_sources=(declaration,)).replace(
                f"{declaration}\n```\n", f"{declaration}\n", 1
            ),
        }
        for name, body in cases.items():
            with self.subTest(name=name), self.assertRaises(scope_guard.ContractError):
                scope_guard.parse_contract(body.encode("utf-8"))

    def test_copy_source_heading_inside_fence_is_not_structural(self) -> None:
        body = contract_body().replace(
            "Test contract.",
            "Test contract.\n\n```text\n## Allowed copy sources\ninvalid\n```",
        )
        parsed = scope_guard.parse_contract(body.encode("utf-8"))
        self.assertEqual((), parsed.allowed_copy_sources)

    def test_copy_source_marker_cannot_be_an_ordinary_pattern(self) -> None:
        marker = f"![styx-copy-source sha256={self.SHA256}]"
        with self.assertRaises(scope_guard.ContractError):
            scope_guard.validate_pattern(marker)

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
