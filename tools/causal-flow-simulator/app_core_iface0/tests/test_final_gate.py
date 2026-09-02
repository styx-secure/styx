from __future__ import annotations

import json
import sys
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from final_gate import (  # noqa: E402
    FinalGateError,
    _fetch_json,
    _next_link,
    _tree,
    _verify_clean_checkout,
    run_phase_a_gate,
)
from inventory import BASE_SHA  # noqa: E402


class _Response:
    def __init__(self, url: str, value: object) -> None:
        self.status = 200
        self._url = url
        self._raw = json.dumps(value).encode("utf-8")
        self.headers = Message()

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def read(self) -> bytes:
        return self._raw


class _Opener:
    def __init__(self, response: _Response) -> None:
        self.response = response

    def open(self, _request: object, timeout: int) -> _Response:
        if timeout != 30:
            raise AssertionError("provider timeout drift")
        return self.response


class FinalGateTests(unittest.TestCase):
    def test_provider_fetch_preserves_object_or_array_shape(self) -> None:
        url = "https://api.github.com/repos/styx-secure/styx/issues/295/comments"
        for value in ({"id": 1}, [{"id": 1}]):
            with self.subTest(value=value), patch.dict("os.environ", {}, clear=True):
                with patch(
                    "final_gate.urllib.request.build_opener",
                    return_value=_Opener(_Response(url, value)),
                ):
                    observed, raw, _headers = _fetch_json(url)
            self.assertEqual(observed, value)
            self.assertEqual(json.loads(raw), value)

    def test_provider_environment_override_fails_before_network(self) -> None:
        with patch.dict("os.environ", {"GITHUB_TOKEN": "forbidden"}, clear=True):
            with self.assertRaisesRegex(FinalGateError, "override environment"):
                _fetch_json("https://api.github.com/repos/styx-secure/styx/pulls/296")

    def test_next_link_accepts_only_the_exact_next_relation(self) -> None:
        self.assertEqual(
            _next_link(
                {
                    "link": (
                        '<https://api.github.com/items?page=2>; rel="next", '
                        '<https://api.github.com/items?page=9>; rel="last"'
                    )
                }
            ),
            "https://api.github.com/items?page=2",
        )
        self.assertIsNone(_next_link({"link": "<x>; rel=next"}))

    def test_checkout_verification_requires_head_ancestry_and_full_cleanliness(self) -> None:
        selection_head = "a" * 40
        calls: list[tuple[str, ...]] = []

        def clean_git(_repo: Path, *arguments: str) -> str:
            calls.append(arguments)
            if arguments == ("rev-parse", "HEAD"):
                return selection_head + "\n"
            if arguments == (
                "merge-base",
                "--is-ancestor",
                BASE_SHA,
                selection_head,
            ):
                return ""
            if arguments[0] == "status":
                return ""
            raise AssertionError(arguments)

        with tempfile.TemporaryDirectory() as raw:
            with patch("final_gate._git", side_effect=clean_git):
                _verify_clean_checkout(Path(raw), selection_head)
        self.assertIn(
            ("status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"),
            calls,
        )

        def dirty_git(_repo: Path, *arguments: str) -> str:
            if arguments == ("rev-parse", "HEAD"):
                return selection_head + "\n"
            if arguments[0] == "merge-base":
                return ""
            return "?? generated.json\n"

        with tempfile.TemporaryDirectory() as raw:
            with patch("final_gate._git", side_effect=dirty_git):
                with self.assertRaisesRegex(FinalGateError, "not clean"):
                    _verify_clean_checkout(Path(raw), selection_head)

    def test_evidence_tree_rejects_symlinks_and_preserves_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "nested").mkdir()
            (root / "nested/evidence.json").write_bytes(b"{}\n")
            self.assertEqual(_tree(root), {"nested/evidence.json": b"{}\n"})
            (root / "alias").symlink_to("nested/evidence.json")
            with self.assertRaisesRegex(FinalGateError, "non-regular"):
                _tree(root)

    def test_phase_a_rejects_bad_identity_and_same_checkout_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with self.assertRaisesRegex(FinalGateError, "full lowercase"):
                run_phase_a_gate(root, root, root / "a", root / "b", "HEAD")
            with self.assertRaisesRegex(FinalGateError, "not distinct"):
                run_phase_a_gate(root, root, root / "a", root / "b", "a" * 40)


if __name__ == "__main__":
    unittest.main()
