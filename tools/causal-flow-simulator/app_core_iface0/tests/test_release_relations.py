"""V33 complete-reader controls; post-output controls earn no source-kill credit."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from canonical_json import dumps as canonical_dumps  # noqa: E402
from generate_seed_registry import _semantic_request_carriers  # noqa: E402
import interface_model as model  # noqa: E402


class ReleaseRelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = model.ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        cls.responses = {}
        for case in _semantic_request_carriers(cls.authority):
            if case.collision_oracle is None:
                digest = hashlib.sha256(canonical_dumps(case.request)).hexdigest()
                if digest in cls.responses:
                    raise AssertionError("duplicate semantic request")
                cls.responses[digest] = model.evaluate_interface_request(
                    cls.authority, case.request
                )

    def _node(self, mode, response):
        args = ["node", str(ROOT / "node_adapter.mjs"), mode,
                "--contract", str(ROOT / "contract")]
        if mode == "--validate-v2-evidence":
            args += ["--direction", "RESPONSE"]
        value = {"responses": [response]} if mode == "--validate-response-batch" else response
        return subprocess.run(args, input=canonical_dumps(value),
                              capture_output=True, timeout=30, check=False)

    def _assert_release(self, response, error=None):
        # Prove downstream attribution in BOTH structural readers first.
        model._validate_complete_v2_document(
            self.authority, response, trusted_direction="RESPONSE"
        )
        schema = self._node("--validate-v2-evidence", response)
        self.assertEqual(schema.returncode, 0, schema.stderr)
        with self.subTest(reader="python", expected=error):
            if error is None:
                self.assertEqual(model.validate_response_before_release(
                    self.authority, response), response)
            else:
                with self.assertRaisesRegex(model.HarnessFailure, error):
                    model.validate_response_before_release(self.authority, response)
        for mode in ("--validate-response", "--validate-response-batch"):
            with self.subTest(reader=mode, expected=error):
                actual = self._node(mode, response)
                self.assertEqual(actual.returncode, 0 if error is None else 2, actual.stderr)
                if error is None:
                    self.assertEqual(actual.stderr, b"")
                    expected = {"verdict": "PASS"}
                    if mode == "--validate-response-batch":
                        expected.update(responseCount=1, responseSha256s=[
                            hashlib.sha256(canonical_dumps(response)).hexdigest()
                        ])
                    self.assertEqual(json.loads(actual.stdout), expected)
                else:
                    self.assertEqual(actual.stdout, b"")
                    self.assertIn(error.encode(), actual.stderr)
                    if "reserved" not in error:
                        self.assertNotIn(b"reserved", actual.stderr)

    def _frozen_response(self, name, digest):
        request = json.loads((ROOT / "tests/release-relation-requests.json").read_text())[name]
        self.assertEqual(hashlib.sha256(canonical_dumps(request)).hexdigest(), digest)
        return model.evaluate_interface_request(self.authority, request)

    def _successor_controls(self):
        controls = (
            ("REPLAY_CONTEXT", "fa815f13e29e860f67874fb4e2627c17134b903d1273be690b337bd0ae53718a"),
            ("EVALUATE_CANDIDATE", "e33b32fd73d85e157a54461d4d32464c040708ba231d2f2a4384a274ab4bc48e"),
            ("EVALUATE_EVIDENCE_UPDATE", "ef56560cff4b25b1dd66450ad0f3a4db0d90e62dd2b143e931d9955d39bff91a"),
        )
        for operation, digest in controls:
            response = copy.deepcopy(self.responses[digest])
            self.assertEqual(response["operation"], operation)
            successor = (response["result"]["proposedContext"] if operation == "REPLAY_CONTEXT"
                         else response["result"]["evaluation"]["proposal"]["successor"])
            outcomes = successor["projection"]["recordOutcomes"]
            self.assertEqual(len(outcomes), 1)
            self.assertEqual((outcomes[0]["disposition"], outcomes[0]["stage"]),
                             ("APPLIED", "FINAL_AFTER_S6"))
            yield operation, response, outcomes

    def test_rn2_later_record_in_each_successor_arm_is_checked(self):
        # Permitted post-output reader-control construction, not a new request,
        # evaluator-produced multi-record witness, or source-mutant kill.
        for operation, response, outcomes in self._successor_controls():
            with self.subTest(control="R-N2", operation=operation):
                later = copy.deepcopy(outcomes[0])
                later["eventReferenceHex"] = "ff" * 32
                self.assertNotEqual(later["eventReferenceHex"], outcomes[0]["eventReferenceHex"])
                outcomes.append(later)
                self.assertEqual(len(outcomes), 2)
                self._assert_release(response)
                first = copy.deepcopy(outcomes[0])
                later["stage"] = "EVENT_LOCAL"
                self.assertEqual(outcomes[0], first)
                self._assert_release(response, "record-outcome relation")

    def test_rn3_unavailable_authority_requires_s5_stage(self):
        for operation, response, outcomes in self._successor_controls():
            with self.subTest(control="R-N3", operation=operation):
                outcomes[0].update(disposition="AUTHORITY_PROJECTION_UNAVAILABLE",
                                   stage="S5_AUTHORITY_PROJECTION")
                self._assert_release(response)
                outcomes[0]["stage"] = "EVENT_LOCAL"
                self._assert_release(response, "record-outcome relation")

    def test_rp1_reachable_rotation_with_candidate_propagation_is_admitted(self):
        # Full post-output pair rotation tests relation admission only.
        for operation, response, outcomes in self._successor_controls():
            with self.subTest(control="R-P1", operation=operation):
                outcomes[0].update(disposition="AUTHENTIC_BUT_UNAUTHORIZED", stage="EVENT_LOCAL")
                if operation == "EVALUATE_CANDIDATE":
                    response["result"]["evaluation"]["primaryOnCommit"] = "AUTHENTIC_BUT_UNAUTHORIZED"
                self._assert_release(response)

    def test_cn1_frozen_genesis_and_transcript_wrong_reason_stage(self):
        genesis = copy.deepcopy(self.responses[
            "2c2ca41b0a24c427e58c2610ce0fc5d7881a95d55be2291d6f429e19a3634ac3"
        ])
        transcript = self._frozen_response(
            "PCR-REQUEST-VALIDATE-TRANSCRIPT-0001.json",
            "178fc66d97f10206e7b7acb6d069dfa0d73dec2737a0c2963cc3e80a0b12f0d3",
        )
        for case, response, reason in (
            ("G0002", genesis, "EXPECTED_CONTEXT_MISMATCH"),
            ("T0001", transcript, "PROFILE_ACTIVATION_UNSUPPORTED"),
        ):
            with self.subTest(control="C-N1", case=case):
                self.assertEqual(response["result"]["reason"], reason)
                self._assert_release(response)
                response["result"]["stage"] = "OUTER_FRAMING"
                self._assert_release(response, "reason/stage relation")

    def test_cn2_candidate_pair_and_reserved_detector_are_separate(self):
        response = self._frozen_response(
            "PCR-REQUEST-EVALUATE-CANDIDATE-0016.json",
            "6f3b271461aa38af95c4211c99412cc9ba9b6f95291b0fe9a2d07bf4c78b6263",
        )
        evaluation = response["result"]["evaluation"]
        self.assertEqual(evaluation["primary"], "PROFILE_ACTIVATION_UNSUPPORTED")
        self.assertEqual(evaluation["kind"], "TERMINAL_NO_SUCCESSOR")
        self._assert_release(response)
        evaluation["stage"] = "S3_KERNEL_STRUCTURAL"
        self._assert_release(response, "F13")
        evaluation["primary"] = "LENGTH_MISMATCH"
        self._assert_relation_only(response)
        self._assert_release(response, "reserved F13 row")

    def _assert_relation_only(self, response):
        model._validate_response_shape_and_relation(self.authority, response)
        script = r'''
import fs from "node:fs";
import assert from "node:assert/strict";
const parts = fs.readFileSync(process.argv[1], "utf8").split("\ntry {\n  const {\n");
assert.equal(parts.length, 2, "CLI boundary drift");
const unit = await import("data:text/javascript;base64," + Buffer.from(
  parts[0] + "\nexport {validateResponseShapeAndRelation, validateBeforeRelease};\n"
).toString("base64"));
const relations = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const response = JSON.parse(fs.readFileSync(0, "utf8"));
unit.validateResponseShapeAndRelation(response, relations);
unit.validateBeforeRelease(response, relations, false);
assert.throws(() => unit.validateBeforeRelease(response, relations, true),
  /reserved F13 row/);
process.stdout.write("PASS\n");
'''
        actual = subprocess.run(
            ["node", "--input-type=module", "-e", script, str(ROOT / "node_adapter.mjs"),
             str(ROOT / "contract/APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json")],
            input=canonical_dumps(response), capture_output=True, timeout=30, check=False,
        )
        with self.subTest(reader="node-isolated-reserved-detector"):
            self.assertEqual(actual.returncode, 0, actual.stderr)
            self.assertEqual(actual.stdout, b"PASS\n")
            self.assertEqual(actual.stderr, b"")

    def _replay_terminal(self):
        matches = [r for r in self.responses.values()
                   if r["operation"] == "REPLAY_CONTEXT"
                   and r["result"].get("primary") == "CONTEXT_CAPACITY_EXHAUSTED"]
        self.assertEqual(len(matches), 1)
        return copy.deepcopy(matches[0])

    def test_rn5_replay_reserved_pair_reaches_separate_detector(self):
        response = self._replay_terminal()
        response["result"].update(primary="LENGTH_MISMATCH", stage="S3_KERNEL_STRUCTURAL")
        self._assert_relation_only(response)
        self._assert_release(response, "reserved F13 row")
        # A reachable primary with the wrong stage must fail the earlier matcher.
        response["result"].update(primary="CONTEXT_CAPACITY_EXHAUSTED", stage="EVENT_LOCAL")
        self._assert_release(response, "replay terminal pair")

    def test_rn4_replay_terminal_requires_exact_pipe_stage(self):
        response = self._replay_terminal()
        literal = "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT"
        self.assertEqual(response["result"]["stage"], literal)
        self._assert_release(response)
        mutant = copy.deepcopy(response)
        mutant["result"]["stage"] = "EVENT_LOCAL"
        self._assert_release(mutant, "replay terminal pair")
        for component in literal.split("|"):
            with self.subTest(schema_component=component):
                mutant["result"]["stage"] = component
                with self.assertRaises(model.HarnessFailure):
                    model._validate_complete_v2_document(
                        self.authority, mutant, trusted_direction="RESPONSE"
                    )
                for mode in ("--validate-v2-evidence", "--validate-response",
                             "--validate-response-batch"):
                    actual = self._node(mode, mutant)
                    self.assertEqual(actual.returncode, 2, actual.stderr)
                    self.assertEqual(actual.stdout, b"")
                    self.assertIn(b"schema oneOf is not exclusive", actual.stderr)

    def test_rn4_owning_pair_matchers_reject_single_pipe_components(self):
        # Unit-only access: no schema rejection can stand in for pair matching.
        result = self._replay_terminal()["result"]
        matcher = getattr(model, "_validate_replay_terminal_pair", None)
        self.assertTrue(callable(matcher), "owning Python pair matcher is absent")
        matcher(self.authority, result)
        for stage in ("EVENT_LOCAL", "S4_GRAPH_ADMISSION", "S6_DURABLE_COMMIT"):
            with self.subTest(unit_stage=stage):
                with self.assertRaisesRegex(model.HarnessFailure, "replay terminal pair"):
                    matcher(self.authority, {**result, "stage": stage})
        script = r'''
import fs from "node:fs";
import assert from "node:assert/strict";
const source = fs.readFileSync(process.argv[1], "utf8");
const parts = source.split("\ntry {\n  const {\n");
assert.equal(parts.length, 2, "CLI boundary drift");
// Import unchanged declarations only; never run the CLI in this unit control.
const unit = await import("data:text/javascript;base64," + Buffer.from(
  parts[0] + "\nexport {validateReplayTerminalPair, AdapterFailure};\n"
).toString("base64"));
const relations = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const result = JSON.parse(fs.readFileSync(0, "utf8"));
unit.validateReplayTerminalPair(result, relations);
for (const stage of ["EVENT_LOCAL", "S4_GRAPH_ADMISSION", "S6_DURABLE_COMMIT"]) {
  assert.throws(() => unit.validateReplayTerminalPair({...result, stage}, relations),
    error => error instanceof unit.AdapterFailure && /replay terminal pair/.test(error.message));
}
process.stdout.write("PASS\n");
'''
        actual = subprocess.run(
            ["node", "--input-type=module", "-e", script, str(ROOT / "node_adapter.mjs"),
             str(ROOT / "contract/APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json")],
            input=canonical_dumps(result), capture_output=True, timeout=30, check=False,
        )
        self.assertEqual(actual.returncode, 0, actual.stderr)
        self.assertEqual(actual.stdout, b"PASS\n")
        self.assertEqual(actual.stderr, b"")
