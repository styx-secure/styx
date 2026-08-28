from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
sys.path.insert(0, str(ROOT))

from generate_corpus import generate  # noqa: E402
from validate_corpus import EXPECTED_FILES  # noqa: E402


class GenerationTests(unittest.TestCase):
    def test_generation_reproduces_all_six_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory) / "generated"
            generate(REPO, generated)
            tracked = REPO / "conformance/application-protocol/c03"
            self.assertEqual({path.name for path in generated.iterdir()}, set(EXPECTED_FILES))
            for name in EXPECTED_FILES:
                self.assertEqual((generated / name).read_bytes(), (tracked / name).read_bytes(), name)


if __name__ == "__main__":
    unittest.main()
