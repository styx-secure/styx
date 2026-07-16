"""F3: the no-write-inside-a-repository guarantee is fail-closed by default.

The guarantee used to be enforced only when ``--repo-root`` was supplied, while
the flag itself was optional on both writing subcommands: omitting it let the
gate write its output anywhere, including into a working tree, turning a
contractual property into an opt-in one.

``--repo-root`` is now mandatory, and an output inside any detected git working
tree is refused independently of the declared root.
"""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import support
from support import evidence_pair, review_request_dict

from model import EXIT_ERROR, EXIT_PASS, OutputError, atomic_write, ensure_writable_output


def _tmp_names(tmp: Path) -> set[str]:
    return {entry.name for entry in tmp.iterdir()}


class RepoRootRequiredTest(unittest.TestCase):
    def test_review_without_repo_root_fails_to_parse(self):
        scope, test = evidence_pair()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    support.run_review(tmp, request=review_request_dict(verdict="GO"),
                                       scope_bytes=scope, test_bytes=test, repo_root=None)
            self.assertEqual(caught.exception.code, EXIT_ERROR)
            # Nothing was created: no output, no temporary file, no directory.
            self.assertNotIn("review-report.json", _tmp_names(tmp))
            self.assertFalse(any(name.endswith(".tmp") for name in _tmp_names(tmp)))

    def test_remediate_without_repo_root_fails_to_parse(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    support.run_remediate(tmp, review_report_bytes=b"{}", round_id=1, repo_root=None)
            self.assertEqual(caught.exception.code, EXIT_ERROR)
            self.assertNotIn("remediation.json", _tmp_names(tmp))

    def test_repo_root_is_mandatory_at_the_api_boundary(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with self.assertRaises(TypeError):
                ensure_writable_output(tmp / "out.json")  # type: ignore[call-arg]

    def test_missing_repo_root_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with self.assertRaises(OutputError):
                ensure_writable_output(tmp / "out.json", repo_root=None)  # type: ignore[arg-type]

    def test_nonexistent_repo_root_is_refused(self):
        # A root that does not exist cannot bound anything; believing it would
        # let a caller re-enable the write by naming a directory at random.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with self.assertRaises(OutputError):
                ensure_writable_output(tmp / "out.json", repo_root=tmp / "no-such-root")

    def test_file_repo_root_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            not_a_dir = support.write_bytes(tmp / "root-file", b"x")
            with self.assertRaises(OutputError):
                ensure_writable_output(tmp / "out.json", repo_root=not_a_dir)


class ContainmentTest(unittest.TestCase):
    def test_output_equal_to_root_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            root.mkdir()
            with self.assertRaises(OutputError):
                ensure_writable_output(root, repo_root=root)

    def test_output_directly_inside_root_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            root.mkdir()
            with self.assertRaises(OutputError):
                ensure_writable_output(root / "out.json", repo_root=root)

    def test_output_in_root_subdirectory_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            (root / "deep" / "nested").mkdir(parents=True)
            with self.assertRaises(OutputError):
                ensure_writable_output(root / "deep" / "nested" / "out.json", repo_root=root)

    def test_root_reached_through_a_symlinked_output_path_refused(self):
        # The output does not lexically mention the root, but resolves into it.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            root.mkdir()
            link = tmp / "link-to-repo"
            os.symlink(root, link)
            with self.assertRaises(OutputError):
                ensure_writable_output(link / "out.json", repo_root=root)

    def test_symlinked_root_declaration_still_contains_the_output_refused(self):
        # The mirror image: the declared root is a symlink, the output names the
        # real directory. Canonical resolution catches both directions.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            root.mkdir()
            link = tmp / "link-to-repo"
            os.symlink(root, link)
            with self.assertRaises(OutputError):
                ensure_writable_output(root / "out.json", repo_root=link)

    def test_symlinked_output_file_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            root.mkdir()
            target = support.write_bytes(tmp / "target.json", b"{}")
            output = tmp / "out.json"
            os.symlink(target, output)
            with self.assertRaises(OutputError):
                ensure_writable_output(output, repo_root=root)

    def test_parent_traversal_in_output_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            root.mkdir()
            with self.assertRaises(OutputError):
                ensure_writable_output(tmp / "sub" / ".." / "out.json", repo_root=root)

    def test_parent_traversal_reaching_into_root_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            root.mkdir()
            with self.assertRaises(OutputError):
                ensure_writable_output(tmp / "elsewhere" / ".." / "repo" / "out.json", repo_root=root)

    def test_relative_output_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            root.mkdir()
            with self.assertRaises(OutputError):
                ensure_writable_output(Path("out.json"), repo_root=root)

    def test_relative_repo_root_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with self.assertRaises(OutputError):
                ensure_writable_output(tmp / "out.json", repo_root=Path("repo"))

    def test_output_inside_an_undeclared_git_worktree_refused(self):
        # The declared root is honest but irrelevant: the output lands in a
        # different checkout. Detected from the filesystem, without running git.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            declared = tmp / "declared-root"
            declared.mkdir()
            checkout = tmp / "some-checkout"
            (checkout / ".git").mkdir(parents=True)
            with self.assertRaises(OutputError):
                ensure_writable_output(checkout / "out.json", repo_root=declared)

    def test_output_deep_inside_an_undeclared_git_worktree_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            declared = tmp / "declared-root"
            declared.mkdir()
            checkout = tmp / "some-checkout"
            (checkout / ".git").mkdir(parents=True)
            (checkout / "docs" / "evidence").mkdir(parents=True)
            with self.assertRaises(OutputError):
                ensure_writable_output(checkout / "docs" / "evidence" / "out.json", repo_root=declared)

    def test_output_inside_a_linked_worktree_refused(self):
        # A linked worktree marks itself with a .git *file*, not a directory.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            declared = tmp / "declared-root"
            declared.mkdir()
            worktree = tmp / "linked-worktree"
            worktree.mkdir()
            support.write_bytes(worktree / ".git", b"gitdir: /elsewhere/.git/worktrees/x\n")
            with self.assertRaises(OutputError):
                ensure_writable_output(worktree / "out.json", repo_root=declared)

    def test_valid_external_output_accepted(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            root.mkdir()
            ensure_writable_output(tmp / "outside" / "out.json", repo_root=root)


class NoPartialOutputTest(unittest.TestCase):
    def test_no_file_or_directory_created_when_output_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            root.mkdir()
            before = _tmp_names(tmp)
            with self.assertRaises(OutputError):
                ensure_writable_output(root / "deep" / "out.json", repo_root=root)
            self.assertEqual(_tmp_names(tmp), before)
            self.assertFalse((root / "deep").exists())

    def test_cli_output_inside_root_writes_nothing(self):
        scope, test = evidence_pair()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "repo"
            root.mkdir()
            request_path = support.write_json(tmp / "req.json", review_request_dict(verdict="GO"))
            scope_path = support.write_bytes(tmp / "scope.json", scope)
            test_path = support.write_bytes(tmp / "test.json", test)
            import review_gate
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = review_gate.main([
                    "review",
                    "--review-request", str(request_path),
                    "--scope-report", str(scope_path),
                    "--test-report", str(test_path),
                    "--repo-root", str(root),
                    "--output", str(root / "sub" / "out.json"),
                ])
            self.assertEqual(code, EXIT_ERROR)
            self.assertFalse((root / "sub").exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_existing_output_is_replaced_atomically(self):
        scope, test = evidence_pair()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            stale = support.write_bytes(tmp / "review-report.json", b"stale content\n")
            code, output = support.run_review(tmp, request=review_request_dict(verdict="GO"),
                                              scope_bytes=scope, test_bytes=test)
            self.assertEqual(code, EXIT_PASS)
            self.assertEqual(output, stale)
            body = support.read_json(output)
            self.assertEqual(body["schema"], "styx.review-report/v1")
            self.assertFalse(any(name.endswith(".tmp") for name in _tmp_names(tmp)))

    def test_temp_file_removed_when_the_write_raises(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            target = tmp / "out.json"
            with mock.patch("model.os.fsync", side_effect=OSError("disk gone")):
                with self.assertRaises(OSError):
                    atomic_write(target, b"payload\n")
            self.assertFalse(target.exists())
            self.assertEqual(_tmp_names(tmp), set())


if __name__ == "__main__":
    unittest.main()
