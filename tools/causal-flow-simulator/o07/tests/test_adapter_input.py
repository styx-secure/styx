from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(O07_ROOT))

from run_cross_runtime import _adapter_input  # noqa: E402
from test_helpers.python_adapter import _load_input  # noqa: E402


class AdapterInputTests(unittest.TestCase):
    def _write(self, root: Path, payload: dict[str, object]) -> Path:
        path = root / "input.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _node_exit(self, path: Path) -> int:
        node = shutil.which("node")
        if node is None:
            self.fail("required JavaScript runtime unavailable")
        return subprocess.run(
            [node, str(O07_ROOT / "node_adapter.mjs"), str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        ).returncode

    def test_closed_adapter_input_is_accepted_by_both_runtimes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), _adapter_input())
            self.assertEqual(len(_load_input(path)), 229)
            self.assertEqual(self._node_exit(path), 0)

    def test_oracle_and_ceremony_fields_are_rejected_by_both_runtimes(self) -> None:
        forbidden = (
            "expected_disposition",
            "ceremony_capability",
            "capability_representation",
            "provenance",
            "authorization",
            "verifier_configuration",
            "issuer_witness",
            "trusted_ceremony_tuple",
            "trusted_ceremony_reference",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, field in enumerate(forbidden):
                payload = _adapter_input()
                scenarios = payload["scenarios"]
                assert isinstance(scenarios, list)
                scenario = dict(scenarios[0])
                scenario[field] = "forbidden"
                scenarios[0] = scenario
                path = self._write(root, payload)
                with self.subTest(field=field, runtime="python"):
                    with self.assertRaises(ValueError):
                        _load_input(path)
                with self.subTest(field=field, runtime="javascript"):
                    self.assertNotEqual(self._node_exit(path), 0)


if __name__ == "__main__":
    unittest.main()
