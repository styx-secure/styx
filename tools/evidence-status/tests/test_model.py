from __future__ import annotations

import copy
import unittest

import support
from model import (
    InputError,
    REASONS,
    STATES,
    build_report,
    canonical_json_bytes,
    classify_document,
    load_candidate,
)


class ExactCurrentTest(unittest.TestCase):
    def test_exact_evidence_is_current_independently(self):
        scope_raw, test_raw, review_raw = support.evidence_bytes()
        report = build_report(
            support.candidate(),
            {"scope": (scope_raw, None), "test": (test_raw, None), "review": (review_raw, None)},
        )
        self.assertEqual([item["kind"] for item in report["items"]], ["scope", "test", "review"])
        self.assertEqual([item["state"] for item in report["items"]], ["CURRENT"] * 3)
        self.assertEqual([item["reasons"] for item in report["items"]], [["IDENTITY_MATCH"]] * 3)
        raw = canonical_json_bytes(report)
        self.assertNotIn(b'"PASS"', raw)
        self.assertNotIn(b'"GO"', raw)
        self.assertNotIn(b'"MERGEABLE"', raw)

    def test_same_inputs_are_byte_identical(self):
        values = support.evidence_bytes()
        inputs = dict(zip(("scope", "test", "review"), ((raw, None) for raw in values)))
        first = canonical_json_bytes(build_report(support.candidate(), inputs))
        second = canonical_json_bytes(build_report(support.candidate(), inputs))
        self.assertEqual(first, second)


class RequiredSyntheticScenarioTest(unittest.TestCase):
    def report_for_candidate(self, candidate):
        scope_raw, test_raw, review_raw = support.evidence_bytes()
        return build_report(
            candidate,
            {"scope": (scope_raw, None), "test": (test_raw, None), "review": (review_raw, None)},
        )

    def test_content_identical_head_move_is_unprovable_not_reusable(self):
        candidate = support.candidate()
        candidate["head_sha"] = support.OTHER
        report = self.report_for_candidate(candidate)
        self.assertEqual([item["state"] for item in report["items"]], ["UNPROVABLE"] * 3)
        for item in report["items"]:
            self.assertIn("HEAD_MISMATCH", item["reasons"])
            self.assertIn("FIELD_NOT_AVAILABLE", item["reasons"])

    def test_issue_body_only_drift_is_stale(self):
        candidate = support.candidate()
        candidate["issue_body_sha256"] = "8" * 64
        report = self.report_for_candidate(candidate)
        self.assertEqual([item["state"] for item in report["items"]], ["STALE"] * 3)
        self.assertTrue(all("ISSUE_BODY_MISMATCH" in item["reasons"] for item in report["items"]))

    def test_base_only_drift_is_stale(self):
        candidate = support.candidate()
        candidate["base_sha"] = support.OTHER
        report = self.report_for_candidate(candidate)
        self.assertEqual([item["state"] for item in report["items"]], ["STALE"] * 3)
        self.assertTrue(all("BASE_MISMATCH" in item["reasons"] for item in report["items"]))

    def test_stale_review_head_is_detected_as_cross_artifact_contradiction(self):
        scope_raw, test_raw, _ = support.evidence_bytes()
        review_raw = canonical_json_bytes(support.review_report(scope_raw, test_raw, head_sha=support.OTHER))
        report = build_report(
            support.candidate(),
            {"scope": (scope_raw, None), "test": (test_raw, None), "review": (review_raw, None)},
        )
        review_item = report["items"][2]
        self.assertEqual(review_item["state"], "CONTRADICTORY")
        self.assertIn("HEAD_MISMATCH", review_item["reasons"])
        self.assertIn("CONTRADICTORY_ARTIFACTS", review_item["reasons"])

    def test_missing_ci_evidence_never_infers_success(self):
        scope_raw, test_raw, review_raw = support.evidence_bytes()
        report = build_report(
            support.candidate(),
            {"scope": (scope_raw, None), "test": (None, "FILE_MISSING"), "review": (review_raw, None)},
        )
        self.assertEqual(report["items"][1]["state"], "MISSING")
        self.assertEqual(report["items"][2]["state"], "UNPROVABLE")


class IndependentDimensionTest(unittest.TestCase):
    def classify(self, kind: str, document: dict[str, object]):
        item, _ = classify_document(kind, canonical_json_bytes(document), None, support.candidate())
        return item

    def test_scope_identity_dimensions(self):
        mutations = {
            "issue_number": (183, "ISSUE_MISMATCH", "STALE"),
            "issue_body_sha256": ("8" * 64, "ISSUE_BODY_MISMATCH", "STALE"),
            "base_sha": (support.OTHER, "BASE_MISMATCH", "STALE"),
            "head_sha": (support.OTHER, "HEAD_MISMATCH", "UNPROVABLE"),
            "tool_version": ("9.9.9", "TOOL_MISMATCH", "STALE"),
        }
        for field, (value, reason, state) in mutations.items():
            with self.subTest(field=field):
                item = self.classify("scope", support.scope_report(**{field: value}))
                self.assertEqual(item["state"], state)
                self.assertIn(reason, item["reasons"])

    def test_review_specific_dimensions(self):
        scope_raw, test_raw, _ = support.evidence_bytes()
        mutations = {
            "repository": ("other/repo", "REPOSITORY_MISMATCH"),
            "diff_sha256": ("8" * 64, "DIFF_MISMATCH"),
            "tool_version": ("9.9.9", "TOOL_MISMATCH"),
        }
        for field, (value, reason) in mutations.items():
            with self.subTest(field=field):
                document = support.review_report(scope_raw, test_raw, **{field: value})
                item = self.classify("review", document)
                self.assertEqual(item["state"], "STALE")
                self.assertIn(reason, item["reasons"])

    def test_non_green_conclusions_are_never_current(self):
        scope_raw, test_raw, _ = support.evidence_bytes()
        cases = (
            ("scope", support.scope_report(verdict="FAIL")),
            ("test", support.test_report(scope_raw, verdict="ERROR")),
            (
                "review",
                support.review_report(
                    scope_raw,
                    test_raw,
                    verdict="CHANGES_REQUESTED",
                    remediation_required=True,
                ),
            ),
        )
        for kind, document in cases:
            with self.subTest(kind=kind):
                item = self.classify(kind, document)
                self.assertEqual(item["state"], "STALE")
                self.assertIn("CONCLUSION_NOT_GREEN", item["reasons"])

    def test_nullable_scope_identity_is_unprovable(self):
        document = support.scope_report(
            issue_number=None,
            base_sha=None,
            head_sha=None,
            issue_body_sha256=None,
            contract_version=None,
            verdict="ERROR",
        )
        item = self.classify("scope", document)
        self.assertEqual(item["state"], "UNPROVABLE")
        self.assertIn("FIELD_NOT_AVAILABLE", item["reasons"])
        self.assertIn("CONCLUSION_NOT_GREEN", item["reasons"])


class InvalidEvidenceTest(unittest.TestCase):
    def item(self, raw: bytes | None, reason: str | None = None):
        return classify_document("scope", raw, reason, support.candidate())[0]

    def test_missing(self):
        item = self.item(None, "FILE_MISSING")
        self.assertEqual(item["state"], "MISSING")
        self.assertEqual(item["reasons"], ["FILE_MISSING"])

    def test_malformed_json(self):
        item = self.item(b"{not-json\n")
        self.assertEqual(item["state"], "INVALID")
        self.assertEqual(item["reasons"], ["MALFORMED_JSON"])

    def test_non_json_constants_are_malformed(self):
        baseline = canonical_json_bytes(support.scope_report())
        for token in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(token=token):
                raw = baseline.replace(
                    b'"changed_entries":[]',
                    b'"changed_entries":[' + token + b']',
                )
                item = self.item(raw)
                self.assertEqual(item["state"], "INVALID")
                self.assertEqual(item["reasons"], ["MALFORMED_JSON"])

    def test_lone_unicode_surrogate_is_malformed(self):
        baseline = canonical_json_bytes(support.scope_report())
        raw = baseline.replace(
            b'"diagnostics":[]',
            b'"diagnostics":[{"text":"\\ud800"}]',
        )
        item = self.item(raw)
        self.assertEqual(item["state"], "INVALID")
        self.assertEqual(item["reasons"], ["MALFORMED_JSON"])

    def test_duplicate_key(self):
        item = self.item(b'{"schema":"x","schema":"y"}\n')
        self.assertEqual(item["reasons"], ["DUPLICATE_KEY"])

    def test_non_object_root(self):
        item = self.item(b"[]\n")
        self.assertEqual(item["reasons"], ["SCHEMA_MISMATCH"])

    def test_noncanonical_json(self):
        item = self.item(b'{ "schema": "styx.task-scope-report/v1" }\n')
        self.assertEqual(item["reasons"], ["NON_CANONICAL_JSON"])

    def test_unknown_schema_and_extra_field(self):
        for document in (
            support.scope_report(schema="unknown/v1"),
            dict(support.scope_report(), unexpected=True),
        ):
            with self.subTest(keys=tuple(document)):
                item = self.item(canonical_json_bytes(document))
                self.assertEqual(item["reasons"], ["SCHEMA_MISMATCH"])

    def test_input_too_large(self):
        item = self.item(None, "INPUT_TOO_LARGE")
        self.assertEqual(item["state"], "INVALID")
        self.assertEqual(item["reasons"], ["INPUT_TOO_LARGE"])


class ContradictionTest(unittest.TestCase):
    def test_incompatible_claims_mark_every_valid_claimant(self):
        scope_raw, _, _ = support.evidence_bytes()
        test_raw = canonical_json_bytes(support.test_report(scope_raw, head_sha=support.OTHER))
        review_raw = canonical_json_bytes(support.review_report(scope_raw, test_raw))
        report = build_report(
            support.candidate(),
            {"scope": (scope_raw, None), "test": (test_raw, None), "review": (review_raw, None)},
        )
        self.assertTrue(all(item["state"] == "CONTRADICTORY" for item in report["items"]))
        self.assertTrue(all("CONTRADICTORY_ARTIFACTS" in item["reasons"] for item in report["items"]))

    def test_wrong_linked_hash_is_contradictory(self):
        scope_raw, _, _ = support.evidence_bytes()
        test_raw = canonical_json_bytes(support.test_report(scope_raw, scope_report_sha256=support.ZERO))
        review_raw = canonical_json_bytes(support.review_report(scope_raw, test_raw))
        report = build_report(
            support.candidate(),
            {"scope": (scope_raw, None), "test": (test_raw, None), "review": (review_raw, None)},
        )
        by_kind = {item["kind"]: item for item in report["items"]}
        self.assertEqual(by_kind["scope"]["state"], "CONTRADICTORY")
        self.assertEqual(by_kind["test"]["state"], "CONTRADICTORY")
        self.assertEqual(by_kind["review"]["state"], "CONTRADICTORY")

    def test_unavailable_linked_evidence_prevents_current_dependents(self):
        scope_raw, test_raw, review_raw = support.evidence_bytes()
        report = build_report(
            support.candidate(),
            {"scope": (None, "FILE_MISSING"), "test": (test_raw, None), "review": (review_raw, None)},
        )
        by_kind = {item["kind"]: item for item in report["items"]}
        self.assertEqual(by_kind["scope"]["state"], "MISSING")
        self.assertEqual(by_kind["test"]["state"], "UNPROVABLE")
        self.assertEqual(by_kind["review"]["state"], "UNPROVABLE")
        self.assertEqual(by_kind["test"]["reasons"], ["FIELD_NOT_AVAILABLE"])

    def test_non_green_linked_scope_contradicts_impossible_green_chain(self):
        scope_raw = canonical_json_bytes(support.scope_report(verdict="FAIL"))
        test_raw = canonical_json_bytes(support.test_report(scope_raw))
        review_raw = canonical_json_bytes(support.review_report(scope_raw, test_raw))
        report = build_report(
            support.candidate(),
            {"scope": (scope_raw, None), "test": (test_raw, None), "review": (review_raw, None)},
        )
        self.assertTrue(all(item["state"] == "CONTRADICTORY" for item in report["items"]))

    def test_unprovable_linked_scope_propagates_to_dependents(self):
        scope_raw = canonical_json_bytes(
            support.scope_report(
                issue_number=None,
                base_sha=None,
                head_sha=None,
                issue_body_sha256=None,
                contract_version=None,
            )
        )
        test_raw = canonical_json_bytes(support.test_report(scope_raw))
        review_raw = canonical_json_bytes(support.review_report(scope_raw, test_raw))
        report = build_report(
            support.candidate(),
            {"scope": (scope_raw, None), "test": (test_raw, None), "review": (review_raw, None)},
        )
        self.assertEqual([item["state"] for item in report["items"]], ["UNPROVABLE"] * 3)
        self.assertTrue(all("FIELD_NOT_AVAILABLE" in item["reasons"] for item in report["items"]))


class CandidateValidationTest(unittest.TestCase):
    def test_candidate_is_closed(self):
        value = support.candidate()
        value["extra"] = True
        with self.assertRaises(InputError):
            load_candidate(canonical_json_bytes(value))

    def test_candidate_rejects_bad_values(self):
        cases = [
            [],
            dict(support.candidate(), head_sha="short"),
            dict(support.candidate(), diff_sha256="A" * 64),
            dict(support.candidate(), issue_number=True),
            dict(support.candidate(), repository="<script>/repo"),
            dict(support.candidate(), tool_versions={"scope": "0.4.0"}),
        ]
        for value in cases:
            with self.subTest(value=value):
                raw = canonical_json_bytes(value) if isinstance(value, dict) else b"[]\n"
                with self.assertRaises(InputError):
                    load_candidate(raw)

    def test_candidate_rejects_duplicate_keys(self):
        with self.assertRaises(InputError):
            load_candidate(b'{"repository":"a","repository":"b"}\n')

    def test_candidate_rejects_non_json_constants_and_noncanonical_encoding(self):
        baseline = canonical_json_bytes(support.candidate())
        with self.assertRaises(InputError):
            load_candidate(baseline.replace(b'"issue_number":182', b'"issue_number":NaN'))
        with self.assertRaises(InputError):
            load_candidate(baseline.replace(b'"issue_number":182', b'"issue_number": 182'))


class SchemaModelConsistencyTest(unittest.TestCase):
    def test_state_and_reason_enums_match_published_schema(self):
        import json

        schema_path = (
            support.TOOL_ROOT.parents[1]
            / "docs/governance/schemas/evidence-status-v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(tuple(schema["$defs"]["state"]["enum"]), STATES)
        self.assertEqual(tuple(schema["$defs"]["reason"]["enum"]), REASONS)


if __name__ == "__main__":
    unittest.main()
