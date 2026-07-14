from __future__ import annotations

import sys

# Set before any further import so the suite does not write bytecode caches
# for the modules it loads (the scoped .gitignore covers the test modules
# themselves, which the interpreter caches before this line runs).
sys.dont_write_bytecode = True

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
TOOL_DIR = ROOT / "tools" / "test-orchestrator"
SCOPE_GUARD = ROOT / "tools" / "agent-enforcement" / "scope_guard.py"
SCHEMA_DIR = ROOT / "docs" / "governance" / "schemas"
PLAN_SCHEMA = SCHEMA_DIR / "test-plan-v1.schema.json"
REPORT_SCHEMA = SCHEMA_DIR / "test-report-v1.schema.json"
FAILURE_SCHEMA = SCHEMA_DIR / "test-failure-v1.schema.json"

sys.path.insert(0, str(TOOL_DIR))

spec = importlib.util.spec_from_file_location("orchestrator", TOOL_DIR / "orchestrator.py")
assert spec and spec.loader
orchestrator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = orchestrator
spec.loader.exec_module(orchestrator)

import contract_inputs  # noqa: E402  (resolved from TOOL_DIR)
import executor  # noqa: E402
import model  # noqa: E402
import planner  # noqa: E402
import safety  # noqa: E402

DEFAULT_REQUIRED_TESTS = (
    "python3 -m unittest discover -s tools/sample/tests -p 'test_*.py'",
    "python3 -m json.tool docs/governance/schemas/sample.schema.json >/dev/null",
)

PASSING_TEST = """import unittest


class SampleTest(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(2, 1 + 1)


if __name__ == "__main__":
    unittest.main()
"""

FAILING_TEST = """import unittest


class SampleTest(unittest.TestCase):
    def test_broken(self):
        print("leaked credential ghp_{token}")
        self.assertEqual(3, 1 + 1)


if __name__ == "__main__":
    unittest.main()
"""

SLOW_TEST = """import time
import unittest


class SlowTest(unittest.TestCase):
    def test_slow(self):
        time.sleep(3)


if __name__ == "__main__":
    unittest.main()
"""

NOISY_TEST = """import unittest


class NoisyTest(unittest.TestCase):
    def test_noisy(self):
        print("x" * 4096)


if __name__ == "__main__":
    unittest.main()
"""

INFINITE_OUTPUT_TEST = """import sys
import unittest


class InfiniteOutputTest(unittest.TestCase):
    def test_unbounded_output(self):
        while True:
            sys.stdout.write("x" * 8192)
            sys.stdout.flush()


if __name__ == "__main__":
    unittest.main()
"""

CHILD_WRITER_TEST = """import subprocess
import sys
import unittest


class ChildWriterTest(unittest.TestCase):
    def test_child_keeps_writing(self):
        writer = "import sys" + chr(10) + "while True:" + chr(10) + "    sys.stdout.write('y' * 4096)"
        subprocess.Popen([sys.executable, "-u", "-c", writer])


if __name__ == "__main__":
    unittest.main()
"""

FAKE_TOKEN = "a" * 24

# Deterministic stand-in for bubblewrap: it understands exactly the option
# grammar emitted by ExecutionEnvironment.command_prefix and the sandbox
# probe, honours --chdir, and execs the wrapped command. It provides NO
# kernel isolation and is NOT evidence of real network denial: it exists so
# the fail-closed wiring and prefix content stay testable on hosts without
# bwrap. Real isolation is exercised by RealSandboxIntegrationTest, which
# runs the actual bubblewrap binary when the host supports it.
FAKE_BWRAP = """#!/usr/bin/env python3
import os
import sys

args = sys.argv[1:]
flags = {"--die-with-parent", "--new-session", "--unshare-net"}
one_value = {"--dev", "--proc", "--tmpfs", "--chdir"}
two_values = {"--ro-bind", "--bind"}
chdir = None
index = 0
while index < len(args):
    argument = args[index]
    if argument in flags:
        index += 1
    elif argument in one_value:
        if argument == "--chdir":
            chdir = args[index + 1]
        index += 2
    elif argument in two_values:
        index += 3
    else:
        break
command = args[index:]
if not command:
    sys.exit(125)
if chdir is not None:
    os.chdir(chdir)
os.execvp(command[0], command)
"""

BROKEN_BWRAP = "#!/bin/sh\nexit 1\n"

_REAL_BWRAP_USABLE: bool | None = None


def real_bwrap_usable() -> bool:
    """True when the host has a bubblewrap that can create the namespace."""

    global _REAL_BWRAP_USABLE
    if _REAL_BWRAP_USABLE is None:
        path = executor.locate_bwrap()
        if path is None:
            _REAL_BWRAP_USABLE = False
        else:
            probe = [
                path,
                "--die-with-parent", "--new-session", "--unshare-net",
                "--ro-bind", "/", "/",
                "--dev", "/dev",
                "--proc", "/proc",
                "--tmpfs", "/tmp",
                "--chdir", "/",
                "/bin/true",
            ]
            try:
                _REAL_BWRAP_USABLE = (
                    subprocess.run(
                        probe,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=30,
                    ).returncode
                    == 0
                )
            except (OSError, subprocess.TimeoutExpired):
                _REAL_BWRAP_USABLE = False
    return _REAL_BWRAP_USABLE


def contract_body(
    base_sha: str,
    *,
    allowed: tuple[str, ...] = ("tools/sample/**", "docs/governance/schemas/**"),
    forbidden: tuple[str, ...] = (".github/**", "vendor/**"),
    required_tests: tuple[str, ...] = DEFAULT_REQUIRED_TESTS,
) -> str:
    newline = chr(10)
    return f"""<!-- styx-task-contract:v1 -->

## Observable outcome

Fixture contract for orchestrator tests.

## Non-goals

None.

## Allowed paths

```text
{newline.join(allowed)}
```

## Forbidden paths

```text
{newline.join(forbidden)}
```

## Native dependencies

None.

## Frozen shared interfaces

None.

## Acceptance criteria

- [ ] Fixture.

## Required tests

```bash
{newline.join(required_tests)}
```

## Rollback

Delete fixture files.

## Residual risks

None.

## Executor and reviewers

Executor and reviewer are distinct.

## Human gates

Human merge gate.

## Base

`main @ {base_sha}`
"""


def run(command: list[str], cwd: Path, *, check: bool = True):
    return subprocess.run(
        command,
        cwd=cwd,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={
            "PATH": str(Path(shutil.which("git") or "/usr/bin/git").parent) + ":/usr/bin:/bin",
            "LC_ALL": "C",
            "HOME": cwd.as_posix(),
        },
    )


class Repo:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        run(["git", "init", "-q"], self.root)
        run(["git", "config", "user.email", "tests@example.invalid"], self.root)
        run(["git", "config", "user.name", "Orchestrator Tests"], self.root)

    def write(self, relative: str, data: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")

    def commit(self, message: str) -> str:
        run(["git", "add", "-A"], self.root)
        run(["git", "commit", "-qm", message], self.root)
        return run(["git", "rev-parse", "HEAD"], self.root).stdout.strip()

    def status(self) -> str:
        return run(["git", "status", "--porcelain=v1", "--untracked-files=all"], self.root).stdout


class Fixture:
    """A fixture repository with contract, scope evidence and helpers."""

    def __init__(
        self,
        root: Path,
        *,
        failing_mandatory: bool = False,
        extra_files: dict[str, str] | None = None,
    ):
        self.root = root
        self.repo = Repo(root / "repo")
        self.evidence = root / "evidence"
        self.evidence.mkdir()

        for name in ("contract.py", "model.py"):
            source = (ROOT / "tools" / "agent-enforcement" / name).read_text(encoding="utf-8")
            self.repo.write(f"tools/agent-enforcement/{name}", source)
        self.repo.write("tools/sample/tests/test_sample.py", PASSING_TEST)
        self.repo.write("docs/governance/schemas/sample.schema.json", '{"type": "object"}\n')
        self.base_sha = self.repo.commit("base")

        test_body = FAILING_TEST.replace("{token}", FAKE_TOKEN) if failing_mandatory else PASSING_TEST
        self.repo.write("tools/sample/tests/test_sample.py", test_body)
        self.repo.write("tools/sample/newfile.py", "VALUE = 1\n")
        self.repo.write("tools/sample/slow/test_slow.py", SLOW_TEST)
        self.repo.write("tools/sample/noisy/test_noisy.py", NOISY_TEST)
        self.repo.write("tools/sample/infinite/test_infinite.py", INFINITE_OUTPUT_TEST)
        self.repo.write("tools/sample/childwriter/test_childwriter.py", CHILD_WRITER_TEST)
        for relative, content in (extra_files or {}).items():
            self.repo.write(relative, content)
        self.head_sha = self.repo.commit("head")

        self.issue_number = 54
        self.issue_body = self.root / "issue.md"
        self.issue_body.write_text(contract_body(self.base_sha), encoding="utf-8")
        self.scope_report_path = self.evidence / "scope-report.json"
        self.run_scope_guard()

    def run_scope_guard(self) -> None:
        result = subprocess.run(
            [
                "python3",
                str(SCOPE_GUARD),
                "--issue-number", str(self.issue_number),
                "--issue-body-file", str(self.issue_body),
                "--base-sha", self.base_sha,
                "--head-sha", self.head_sha,
                "--execution-id", "orchestrator-fixture-001",
                "--output", str(self.scope_report_path),
                "--repo", str(self.repo.root),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            raise AssertionError(f"fixture scope guard did not PASS: {result.stderr}")

    def plan_args(self, output: Path, *, proposals: Path | None = None) -> list[str]:
        args = [
            "plan",
            "--issue-number", str(self.issue_number),
            "--issue-body-file", str(self.issue_body),
            "--scope-report", str(self.scope_report_path),
            "--base-sha", self.base_sha,
            "--head-sha", self.head_sha,
            "--execution-id", "orchestrator-test-001",
            "--repo", str(self.repo.root),
            "--output", str(output),
        ]
        if proposals is not None:
            args.extend(["--proposals", str(proposals)])
        return args

    def execute_args(self, plan_path: Path, output: Path) -> list[str]:
        return [
            "execute",
            "--plan", str(plan_path),
            "--issue-body-file", str(self.issue_body),
            "--scope-report", str(self.scope_report_path),
            "--repo", str(self.repo.root),
            "--output", str(output),
        ]


class OrchestratorCase(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workdir = Path(self.temp.name)
        self._original_locate_bwrap = executor.locate_bwrap
        self.fake_bwrap = self._write_sandbox_stub("bwrap", FAKE_BWRAP)
        self.use_fake_bwrap()
        self.addCleanup(self._restore_bwrap)

    def _write_sandbox_stub(self, name: str, content: str) -> Path:
        stub_dir = self.workdir / "sandbox-stubs"
        stub_dir.mkdir(exist_ok=True)
        path = stub_dir / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
        return path

    def use_fake_bwrap(self) -> None:
        executor.locate_bwrap = lambda: str(self.fake_bwrap)

    def use_missing_bwrap(self) -> None:
        executor.locate_bwrap = lambda: None

    def use_broken_bwrap(self) -> None:
        broken = self._write_sandbox_stub("broken-bwrap", BROKEN_BWRAP)
        executor.locate_bwrap = lambda: str(broken)

    def use_real_bwrap(self) -> None:
        executor.locate_bwrap = self._original_locate_bwrap

    def _restore_bwrap(self) -> None:
        executor.locate_bwrap = self._original_locate_bwrap

    def fixture(self, **kwargs) -> Fixture:
        return Fixture(self.workdir, **kwargs)

    def invoke(self, args: list[str]) -> tuple[int, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = orchestrator.main(args)
        return code, stderr.getvalue()

    def build_plan(self, fixture: Fixture, *, proposals: object | None = None) -> tuple[Path, dict]:
        proposals_path = None
        if proposals is not None:
            proposals_path = self.workdir / "proposals.json"
            proposals_path.write_text(json.dumps(proposals), encoding="utf-8")
        plan_path = self.workdir / "plan.json"
        code, stderr = self.invoke(fixture.plan_args(plan_path, proposals=proposals_path))
        self.assertEqual(0, code, stderr)
        return plan_path, json.loads(plan_path.read_text(encoding="utf-8"))

    def execute_plan(self, fixture: Fixture, plan_path: Path) -> tuple[int, dict]:
        report_path = self.workdir / "report.json"
        code, _ = self.invoke(fixture.execute_args(plan_path, report_path))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return code, report

    def rewrite_plan(self, plan_path: Path, plan: dict) -> None:
        plan_path.write_bytes(model.canonical_json_bytes(plan))


def checks_of_class(plan: dict, execution_class: str) -> list[dict]:
    return [check for check in plan["checks"] if check["execution_class"] == execution_class]


def load_schema(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class MiniSchemaValidator:
    """Minimal standard-library validator for schema features used by v1."""

    def __init__(self, schema: dict):
        self.root = schema

    def resolve(self, ref: str) -> dict:
        self.assert_true(ref.startswith("#/$defs/"), f"unsupported ref: {ref}")
        return self.root["$defs"][ref.split("/")[-1]]

    @staticmethod
    def assert_true(condition: bool, message: str) -> None:
        if not condition:
            raise AssertionError(message)

    def validate(self, value, schema: dict | None = None, path: str = "$") -> None:
        schema = self.root if schema is None else schema
        if "$ref" in schema:
            return self.validate(value, self.resolve(schema["$ref"]), path)
        if "oneOf" in schema:
            successes = 0
            for option in schema["oneOf"]:
                try:
                    self.validate(value, option, path)
                except AssertionError:
                    pass
                else:
                    successes += 1
            self.assert_true(successes == 1, f"{path}: oneOf matched {successes} branches")
            return
        if "const" in schema:
            self.assert_true(value == schema["const"], f"{path}: const mismatch")
        if "enum" in schema:
            self.assert_true(value in schema["enum"], f"{path}: not in enum")

        kind = schema.get("type")
        if kind == "object":
            self.assert_true(isinstance(value, dict), f"{path}: expected object")
            for required in schema.get("required", []):
                self.assert_true(required in value, f"{path}: missing {required}")
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False:
                self.assert_true(set(value) <= set(properties), f"{path}: unknown properties")
            for key, child in value.items():
                if key in properties:
                    self.validate(child, properties[key], f"{path}.{key}")
        elif kind == "array":
            self.assert_true(isinstance(value, list), f"{path}: expected array")
            self.assert_true(len(value) >= schema.get("minItems", 0), f"{path}: too few items")
            if schema.get("uniqueItems"):
                encoded = [json.dumps(item, sort_keys=True) for item in value]
                self.assert_true(len(encoded) == len(set(encoded)), f"{path}: duplicate items")
            for index, item in enumerate(value):
                if "items" in schema:
                    self.validate(item, schema["items"], f"{path}[{index}]")
        elif kind == "string":
            self.assert_true(isinstance(value, str), f"{path}: expected string")
            self.assert_true(len(value) >= schema.get("minLength", 0), f"{path}: too short")
            if "pattern" in schema:
                self.assert_true(re.fullmatch(schema["pattern"], value) is not None, f"{path}: pattern")
        elif kind == "integer":
            self.assert_true(isinstance(value, int) and not isinstance(value, bool), f"{path}: integer")
            self.assert_true(value >= schema.get("minimum", value), f"{path}: minimum")
            self.assert_true(value <= schema.get("maximum", value), f"{path}: maximum")
        elif kind == "boolean":
            self.assert_true(isinstance(value, bool), f"{path}: expected boolean")
        elif kind == "null":
            self.assert_true(value is None, f"{path}: expected null")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
