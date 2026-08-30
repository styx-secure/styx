from __future__ import annotations

import hashlib
import subprocess
import sys
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[2]
sys.path.insert(0, str(PACKAGE))

from scope_guard import (  # noqa: E402
    BASE_SHA,
    MODEL_SYNC_SHA,
    PHASE_A_SHA,
    TEST_VALIDATE_SHA256,
    _validate_validator_projection,
    build_report,
)


class ScopeGuardTests(unittest.TestCase):
    def test_current_committed_projection_is_accepted(self) -> None:
        _validate_validator_projection(ROOT, BASE_SHA, "HEAD")
        report = build_report(ROOT, BASE_SHA, "HEAD", PHASE_A_SHA)
        self.assertEqual("PASS", report["result"])

    def test_ratified_test_validate_bytes_are_exact(self) -> None:
        path = ROOT / "tools/protocol-review-model/tests/test_validate.py"
        self.assertEqual(TEST_VALIDATE_SHA256, hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(
            path.read_bytes(),
            subprocess.run(
                [
                    "/usr/bin/git",
                    "show",
                    f"{MODEL_SYNC_SHA}:tools/protocol-review-model/tests/test_validate.py",
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
            ).stdout,
        )


if __name__ == "__main__":
    unittest.main()
