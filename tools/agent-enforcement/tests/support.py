from __future__ import annotations

import sys

# Set before any further import so the suite does not write bytecode caches
# for the modules it loads (the scoped .gitignore covers the test modules
# themselves, which the interpreter caches before this line runs).
sys.dont_write_bytecode = True

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "tools" / "agent-enforcement" / "scope_guard.py"
SCHEMA = ROOT / "docs" / "governance" / "schemas" / "task-scope-report-v1.schema.json"
sys.path.insert(0, str(TOOL.parent))

spec = importlib.util.spec_from_file_location("scope_guard", TOOL)
assert spec and spec.loader
scope_guard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = scope_guard
spec.loader.exec_module(scope_guard)


def contract_body(
    *,
    allowed: tuple[str, ...] = ("tools/agent-enforcement/**",),
    forbidden: tuple[str, ...] = (".github/**",),
    marker: str = "<!-- styx-task-contract:v1 -->",
    test_heading: str = "Required tests",
) -> str:
    return f"""{marker}

## Observable outcome

Test contract.

## Non-goals

None.

## Allowed paths

```text
{chr(10).join(allowed)}
```

## Forbidden paths

```text
{chr(10).join(forbidden)}
```

## Native dependencies

None.

## Frozen shared interfaces

None.

## Acceptance criteria

- [ ] Test.

## {test_heading}

```shell
true
```

## Rollback

Delete test files.

## Residual risks

None.

## Executor and reviewers

Executor and reviewer are distinct.

## Human gates

Human merge gate.

## Base

Explicit SHA.
"""


def run(command: list[str], cwd: Path, *, check: bool = True, text: bool = True):
    return subprocess.run(
        command,
        cwd=cwd,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        env={
            "PATH": str(Path(shutil.which("git") or "/usr/bin/git").parent) + ":/usr/bin:/bin",
            "LC_ALL": "C",
        },
    )


class Repo:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        run(["git", "init", "-q"], self.root)
        run(["git", "config", "user.email", "tests@example.invalid"], self.root)
        run(["git", "config", "user.name", "Scope Guard Tests"], self.root)

    def write(self, relative: str, data: bytes | str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data) if isinstance(data, bytes) else path.write_text(data, encoding="utf-8")

    def remove(self, relative: str) -> None:
        path = self.root / relative
        shutil.rmtree(path) if path.is_dir() and not path.is_symlink() else path.unlink()

    def commit(self, message: str) -> str:
        run(["git", "add", "-A"], self.root)
        run(["git", "commit", "-qm", message], self.root)
        return run(["git", "rev-parse", "HEAD"], self.root).stdout.strip()

    def snapshot(self) -> dict[str, bytes | str]:
        index = self.root / ".git" / "index"
        return {
            "head": run(["git", "rev-parse", "HEAD"], self.root).stdout,
            "status": run(
                ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                self.root,
                text=False,
            ).stdout,
            "refs": run(["git", "show-ref"], self.root, check=False).stdout,
            "config": (self.root / ".git" / "config").read_bytes(),
            "index": hashlib.sha256(index.read_bytes()).hexdigest(),
        }


class GuardIntegrationCase(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = Repo(self.root / "repo")
        self.issue = self.root / "issue.md"
        self.output = self.root / "report.json"

    def invoke(
        self,
        base: str,
        head: str,
        *,
        body: str | None = None,
        output: Path | None = None,
        execution_id: str = "test-execution-001",
    ):
        self.issue.write_text(body if body is not None else contract_body(), encoding="utf-8")
        destination = output or self.output
        result = subprocess.run(
            [
                "python3",
                str(TOOL),
                "--issue-number",
                "46",
                "--issue-body-file",
                str(self.issue),
                "--base-sha",
                base,
                "--head-sha",
                head,
                "--execution-id",
                execution_id,
                "--output",
                str(destination),
                "--repo",
                str(self.repo.root),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        report = json.loads(destination.read_text(encoding="utf-8")) if destination.exists() else None
        return result, report, destination

    def simple_history(self, path: str = "tools/agent-enforcement/example.txt") -> tuple[str, str]:
        self.repo.write(path, "base\n")
        base = self.repo.commit("base")
        self.repo.write(path, "base\nhead\n")
        return base, self.repo.commit("head")

    def assert_verdict(self, result, report, verdict: str, exit_code: int) -> None:
        self.assertEqual(exit_code, result.returncode, result.stderr)
        self.assertEqual(verdict, report["verdict"])


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
        elif kind == "null":
            self.assert_true(value is None, f"{path}: expected null")
