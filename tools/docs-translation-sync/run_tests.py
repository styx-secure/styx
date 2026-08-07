#!/usr/bin/env python3
"""Run translation-sync tests and fail closed when no test is collected."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

EXIT_PASS = 0
EXIT_FAIL = 2
EXIT_NO_TESTS = 3


def run(test_root: Path | None = None) -> int:
    root = test_root or Path(__file__).with_name("tests")
    suite = unittest.defaultTestLoader.discover(str(root), pattern="test_*.py")
    count = suite.countTestCases()
    if count == 0:
        print("translation-sync-tests: error: no tests collected", file=sys.stderr)
        return EXIT_NO_TESTS

    print(f"translation-sync-tests: collected {count} test(s)")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return EXIT_PASS if result.wasSuccessful() else EXIT_FAIL


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(run())
