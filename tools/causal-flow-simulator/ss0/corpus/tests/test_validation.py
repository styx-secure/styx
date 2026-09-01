from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
CORPUS_TOOL = ROOT / "tools/causal-flow-simulator/ss0/corpus"
sys.path.insert(0, str(CORPUS_TOOL))

from canonical_json import loads_unique  # noqa: E402
from generate_corpus import CORPUS_PATHS, build_files  # noqa: E402
from validate_corpus import (  # noqa: E402
    CorpusValidationError,
    _validate_manifest_source_bindings,
    validate_corpus,
)


class ValidationTests(unittest.TestCase):
    def test_manifest_source_bindings_are_exact(self) -> None:
        expected = loads_unique(build_files(ROOT)[CORPUS_PATHS[0]])
        for field in ("generator", "normativeInputs", "reproductionInputs"):
            with self.subTest(field=field):
                candidate = copy.deepcopy(expected)
                value = candidate[field]
                if isinstance(value, list):
                    value[0]["sha256"] = "0" * 64
                else:
                    value["version"] = "hostile"
                with self.assertRaises(CorpusValidationError) as raised:
                    _validate_manifest_source_bindings(candidate, expected)
                self.assertEqual(raised.exception.code, "CORPUS-AUTHORITY")

    def test_repository_corpus_is_valid(self) -> None:
        report = validate_corpus(ROOT, ROOT / "conformance/secure-session/ss0")
        self.assertEqual(report, {"cases": 56, "mutations": 44, "result": "PASS"})


if __name__ == "__main__":
    unittest.main()
