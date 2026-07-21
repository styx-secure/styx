"""F1: the implementer identity is derived from evidence, never from the claim.

The independence and self-review checks are only as trustworthy as the
implementer identity they compare against. Previously that identity was taken
from the reviewer-authored ``candidate.implementer_execution_id``, which no
evidence anchored: a self-reviewing implementer could declare a decoy id,
trivially differ from it, and obtain GO on its own work.

These tests pin the identity to the execution id carried by both halves of the
evidence pair, and pin the canonical form of every identifier.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import support
from support import evidence_pair, review_request_dict

from evidence import load_evidence
from model import CANONICAL_ID_PATTERN, EvidenceError, IdentityError, canonical_json_bytes
from review import build_review_report, validate_review_request

DECOY_EXECUTION_ID = "other-impl"
# A Cyrillic 'е' (U+0435) in place of the ASCII 'e' of "implementer": visually
# identical to the authoritative id, a different string to a byte comparison.
CONFUSABLE_IMPLEMENTER_ID = "issue-55-implеmenter-01"


def _build(request_dict, *, scope_bytes=None, test_bytes=None):
    if scope_bytes is None or test_bytes is None:
        scope_bytes, test_bytes = evidence_pair()
    request = validate_review_request(request_dict)
    evidence = load_evidence(scope_bytes, test_bytes)
    return build_review_report(request, evidence)


class DecoyImplementerIdTest(unittest.TestCase):
    """The exact attack the review demonstrated."""

    def test_self_review_behind_decoy_implementer_id_fails_closed(self):
        # Evidence says issue-55-implementer-01 produced the candidate.
        # The reviewer *is* issue-55-implementer-01 but declares a decoy
        # implementer id, so that reviewer != declared implementer.
        scope, test = evidence_pair(execution_id=support.IMPLEMENTER_EXECUTION_ID)
        reviewer = support.reviewer_dict(execution_id=support.IMPLEMENTER_EXECUTION_ID)
        candidate = support.candidate_dict(implementer_execution_id=DECOY_EXECUTION_ID)
        with self.assertRaises(IdentityError):
            _build(
                review_request_dict(verdict="GO", candidate=candidate, reviewer=reviewer),
                scope_bytes=scope, test_bytes=test,
            )

    def test_decoy_rejected_even_for_a_delegated_agent(self):
        scope, test = evidence_pair(execution_id=support.IMPLEMENTER_EXECUTION_ID)
        reviewer = support.reviewer_dict(
            reviewer_class="DELEGATED_AGENT",
            execution_id=support.IMPLEMENTER_EXECUTION_ID,
        )
        candidate = support.candidate_dict(implementer_execution_id=DECOY_EXECUTION_ID)
        with self.assertRaises(IdentityError):
            _build(
                review_request_dict(verdict="GO", candidate=candidate, reviewer=reviewer),
                scope_bytes=scope, test_bytes=test,
            )

    def test_candidate_implementer_id_must_restate_the_evidence(self):
        # Even with a genuinely independent reviewer, a candidate that misstates
        # who produced the work fails closed rather than being believed.
        candidate = support.candidate_dict(implementer_execution_id=DECOY_EXECUTION_ID)
        with self.assertRaises(IdentityError):
            _build(review_request_dict(verdict="GO", candidate=candidate))

    def test_report_records_the_evidence_derived_identity(self):
        report = _build(review_request_dict(verdict="GO"))
        self.assertEqual(report["implementer_execution_id"], support.IMPLEMENTER_EXECUTION_ID)


class EvidenceExecutionAgreementTest(unittest.TestCase):
    def test_scope_and_test_execution_id_must_agree(self):
        scope, test = evidence_pair(
            execution_id=support.IMPLEMENTER_EXECUTION_ID,
            test_execution_id="issue-55-implementer-02",
        )
        with self.assertRaises(IdentityError):
            load_evidence(scope, test)

    def test_disagreeing_evidence_cannot_produce_a_review(self):
        scope, test = evidence_pair(
            execution_id=support.IMPLEMENTER_EXECUTION_ID,
            test_execution_id="issue-55-implementer-02",
        )
        with self.assertRaises(IdentityError):
            _build(review_request_dict(verdict="GO"), scope_bytes=scope, test_bytes=test)

    def test_missing_scope_execution_id(self):
        scope, test = evidence_pair()
        broken = json.loads(scope.decode())
        del broken["execution_id"]
        with self.assertRaises(EvidenceError):
            load_evidence(canonical_json_bytes(broken), test)

    def test_missing_test_execution_id(self):
        scope, test = evidence_pair()
        broken = json.loads(test.decode())
        del broken["execution_id"]
        with self.assertRaises(EvidenceError):
            load_evidence(scope, canonical_json_bytes(broken))


class CanonicalIdentifierTest(unittest.TestCase):
    def test_empty_scope_execution_id(self):
        scope, test = evidence_pair(execution_id="")
        with self.assertRaises(EvidenceError):
            load_evidence(scope, test)

    def test_empty_candidate_implementer_id(self):
        with self.assertRaises(IdentityError):
            validate_review_request(review_request_dict(
                verdict="GO", candidate=support.candidate_dict(implementer_execution_id=""),
            ))

    def test_leading_whitespace_in_evidence_execution_id(self):
        scope, test = evidence_pair(execution_id=" issue-55-implementer-01")
        with self.assertRaises(EvidenceError):
            load_evidence(scope, test)

    def test_trailing_whitespace_in_evidence_execution_id(self):
        scope, test = evidence_pair(execution_id="issue-55-implementer-01 ")
        with self.assertRaises(EvidenceError):
            load_evidence(scope, test)

    def test_leading_whitespace_in_candidate_implementer_id(self):
        with self.assertRaises(IdentityError):
            validate_review_request(review_request_dict(
                verdict="GO",
                candidate=support.candidate_dict(
                    implementer_execution_id=f" {support.IMPLEMENTER_EXECUTION_ID}",
                ),
            ))

    def test_trailing_whitespace_in_reviewer_execution_id(self):
        with self.assertRaises(IdentityError):
            validate_review_request(review_request_dict(
                verdict="GO",
                reviewer=support.reviewer_dict(execution_id=f"{support.REVIEWER_EXECUTION_ID} "),
            ))

    def test_case_variant_candidate_id_does_not_bind(self):
        # Identity bindings are exact: a case variant is not the evidence's id.
        candidate = support.candidate_dict(
            implementer_execution_id=support.IMPLEMENTER_EXECUTION_ID.upper(),
        )
        with self.assertRaises(IdentityError):
            _build(review_request_dict(verdict="GO", candidate=candidate))

    def test_case_variant_reviewer_id_is_still_self_review(self):
        # The distinctness check folds ASCII case, so a reviewer cannot escape
        # self-review detection by re-typing the implementer id in other case.
        reviewer = support.reviewer_dict(execution_id="Issue-55-Implementer-01")
        with self.assertRaises(IdentityError):
            _build(review_request_dict(verdict="GO", reviewer=reviewer))

    def test_case_variant_reviewer_context_is_still_reused_context(self):
        reviewer = support.reviewer_dict(context_id=support.IMPLEMENTER_CONTEXT_ID.upper())
        with self.assertRaises(IdentityError):
            _build(review_request_dict(verdict="GO", reviewer=reviewer))

    def test_confusable_evidence_execution_id_rejected(self):
        scope, test = evidence_pair(execution_id=CONFUSABLE_IMPLEMENTER_ID)
        with self.assertRaises(EvidenceError):
            load_evidence(scope, test)

    def test_confusable_reviewer_id_cannot_impersonate_a_distinct_party(self):
        # A reviewer id that merely *looks* like a different party is refused
        # outright rather than folded onto, or apart from, the implementer's.
        reviewer = support.reviewer_dict(execution_id=CONFUSABLE_IMPLEMENTER_ID)
        with self.assertRaises(IdentityError):
            _build(review_request_dict(verdict="GO", reviewer=reviewer))

    def test_confusable_candidate_implementer_id_rejected(self):
        candidate = support.candidate_dict(implementer_execution_id=CONFUSABLE_IMPLEMENTER_ID)
        with self.assertRaises(IdentityError):
            _build(review_request_dict(verdict="GO", candidate=candidate))

    def test_non_string_execution_id_rejected(self):
        with self.assertRaises(IdentityError):
            validate_review_request(review_request_dict(
                verdict="GO", candidate=support.candidate_dict(implementer_execution_id=55),
            ))


class SchemaAgreementTest(unittest.TestCase):
    """The documented canonical form must not drift from the enforced one."""

    SCHEMA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "docs" / "governance" / "schemas"

    def test_schemas_publish_the_enforced_canonical_pattern(self):
        for name in ("review-report-v1.schema.json", "remediation-request-v1.schema.json"):
            schema = json.loads((self.SCHEMA_DIR / name).read_text(encoding="utf-8"))
            self.assertEqual(schema["$defs"]["canonicalId"]["pattern"], CANONICAL_ID_PATTERN, name)

    def test_identity_fields_reference_the_canonical_id_def(self):
        schema = json.loads((self.SCHEMA_DIR / "review-report-v1.schema.json").read_text(encoding="utf-8"))
        for field in ("reviewer_execution_id", "reviewer_context_id",
                      "implementer_execution_id", "implementer_context_id"):
            self.assertEqual(schema["properties"][field]["$ref"], "#/$defs/canonicalId", field)


class DistinctIdentitiesTest(unittest.TestCase):
    def test_genuinely_distinct_implementer_and_reviewer_pass(self):
        scope, test = evidence_pair(execution_id=support.IMPLEMENTER_EXECUTION_ID)
        report = _build(
            review_request_dict(verdict="GO"),
            scope_bytes=scope, test_bytes=test,
        )
        self.assertEqual(report["verdict"], "GO")
        self.assertEqual(report["implementer_execution_id"], support.IMPLEMENTER_EXECUTION_ID)
        self.assertEqual(report["reviewer_execution_id"], support.REVIEWER_EXECUTION_ID)
        self.assertNotEqual(report["implementer_execution_id"], report["reviewer_execution_id"])

    def test_distinct_delegated_agent_review_pass(self):
        reviewer = support.reviewer_dict(reviewer_class="DELEGATED_AGENT")
        report = _build(review_request_dict(verdict="GO", reviewer=reviewer))
        self.assertEqual(report["verdict"], "GO")
        self.assertTrue(report["independent"])

    def test_second_round_reviewer_identity_is_accepted(self):
        # The round-2 reviewer of this very Issue must be able to review the
        # round-1 implementer's work.
        reviewer = support.reviewer_dict(
            reviewer_class="DELEGATED_AGENT",
            execution_id="issue-55-security-review-02",
            context_id="issue-55-security-review-02-context",
        )
        report = _build(review_request_dict(verdict="GO", reviewer=reviewer))
        self.assertEqual(report["reviewer_execution_id"], "issue-55-security-review-02")


if __name__ == "__main__":
    unittest.main()
