from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "interface_model.py"
TARGET_TEST = Path(__file__).with_name("test_interface_model.py")
MANIFEST = Path(__file__).with_name("o04_evidence_mutants.json")


def _run_mutant(mutated_model: Path, killer: str) -> int:
    sys.path.insert(0, str(ROOT))
    model_spec = importlib.util.spec_from_file_location("interface_model", mutated_model)
    if model_spec is None or model_spec.loader is None:
        return 2
    model = importlib.util.module_from_spec(model_spec)
    sys.modules["interface_model"] = model
    model_spec.loader.exec_module(model)

    test_spec = importlib.util.spec_from_file_location("o04_mutant_target", TARGET_TEST)
    if test_spec is None or test_spec.loader is None:
        return 2
    tests = importlib.util.module_from_spec(test_spec)
    test_spec.loader.exec_module(tests)
    suite = unittest.TestSuite([tests.InterfaceModelTests(killer)])
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=0).run(suite)
    if result.wasSuccessful():
        return 0
    return 2 if result.errors else 1


class O04EvidenceMutantTests(unittest.TestCase):
    def test_each_declared_source_mutant_is_killed(self) -> None:
        source = MODEL.read_text()
        manifest = json.loads(MANIFEST.read_text())
        self.assertEqual(len(manifest), 5)
        for row in manifest:
            with self.subTest(mutant=row["id"]):
                self.assertEqual(source.count(row["find"]), 1)
                mutated = source.replace(row["find"], row["replace"], 1)
                compile(mutated, str(MODEL), "exec")
                with tempfile.TemporaryDirectory() as directory:
                    baseline_path = Path(directory) / "baseline_interface_model.py"
                    baseline_path.write_text(source)
                    baseline = subprocess.run(
                        [
                            sys.executable,
                            str(Path(__file__).resolve()),
                            str(baseline_path),
                            row["killedBy"],
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                        timeout=60,
                    )
                    self.assertEqual(
                        baseline.returncode,
                        0,
                        f"baseline control failed: {row['id']}\n"
                        f"{baseline.stderr.decode()}",
                    )
                    path = Path(directory) / "interface_model.py"
                    path.write_text(mutated)
                    completed = subprocess.run(
                        [
                            sys.executable,
                            str(Path(__file__).resolve()),
                            str(path),
                            row["killedBy"],
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                        timeout=60,
                    )
                self.assertEqual(
                    completed.returncode,
                    1,
                    f"mutant survived: {row['id']}\n{completed.stderr.decode()}",
                )


if __name__ == "__main__" and len(sys.argv) == 3:
    raise SystemExit(_run_mutant(Path(sys.argv[1]), sys.argv[2]))
elif __name__ == "__main__":
    unittest.main()
