"""F4: diff_sha256 is advisory metadata and gates nothing.

``candidate.diff_sha256`` is unauthenticated reviewer input: the consumed frozen
evidence interface carries no diff digest, so there is no bound source to verify
it against. Rather than invent one, the gate documents and demonstrates the
limit: the authoritative binding of the code state is ``base_sha`` +
``head_sha``, both stated by the evidence, and no security decision depends on
the digest.

These tests hold that line, so that a later change cannot quietly promote the
digest into evidence.
"""

from __future__ import annotations

import unittest

import support
from support import evidence_pair, review_request_dict

from evidence import load_evidence
from model import PreconditionError, sha256_hex
from review import acceptance_still_valid, build_review_report, validate_review_request

ARBITRARY_DIGEST = sha256_hex(b"a digest nobody ever produced from a real diff")
OTHER_ARBITRARY_DIGEST = sha256_hex(b"and another one")


def _build(candidate):
    scope, test = evidence_pair()
    request = validate_review_request(review_request_dict(verdict="GO", candidate=candidate))
    evidence = load_evidence(scope, test)
    return build_review_report(request, evidence)


class DigestDoesNotGateAcceptanceTest(unittest.TestCase):
    def test_arbitrary_digest_does_not_change_the_base_head_binding(self):
        # Same base/HEAD, wildly different digests -> same outcome. The digest
        # is recorded verbatim and decides nothing.
        honest = _build(support.candidate_dict(diff_sha256=support.DIFF_SHA256))
        arbitrary = _build(support.candidate_dict(diff_sha256=ARBITRARY_DIGEST))
        self.assertEqual(honest["verdict"], arbitrary["verdict"])
        self.assertEqual(honest["base_sha"], arbitrary["base_sha"])
        self.assertEqual(honest["head_sha"], arbitrary["head_sha"])
        self.assertEqual(arbitrary["diff_sha256"], ARBITRARY_DIGEST)

    def test_two_different_digests_both_accept(self):
        for digest in (ARBITRARY_DIGEST, OTHER_ARBITRARY_DIGEST):
            report = _build(support.candidate_dict(diff_sha256=digest))
            self.assertEqual(report["verdict"], "GO")

    def test_reports_differ_only_in_the_advisory_digest(self):
        honest = _build(support.candidate_dict(diff_sha256=support.DIFF_SHA256))
        arbitrary = _build(support.candidate_dict(diff_sha256=ARBITRARY_DIGEST))
        differing = {k for k in honest if honest[k] != arbitrary[k]}
        self.assertEqual(differing, {"diff_sha256"})

    def test_digest_is_not_verified_against_the_evidence(self):
        # Stated plainly: no field of either evidence document carries a diff
        # digest, so there is nothing to verify the candidate's value against.
        scope, test = evidence_pair()
        evidence = load_evidence(scope, test)
        self.assertNotIn("diff_sha256", evidence.scope_report)
        self.assertNotIn("diff_sha256", evidence.test_report)


class DigestCannotRescueInvalidEvidenceTest(unittest.TestCase):
    def test_digest_cannot_make_a_drifted_head_acceptable(self):
        # Evidence at OTHER_HEAD, candidate at HEAD: stale regardless of digest.
        for digest in (support.DIFF_SHA256, ARBITRARY_DIGEST):
            scope, test = evidence_pair(head_sha=support.OTHER_HEAD_SHA)
            request = validate_review_request(review_request_dict(
                verdict="GO", candidate=support.candidate_dict(diff_sha256=digest),
            ))
            evidence = load_evidence(scope, test)
            with self.assertRaises(PreconditionError):
                build_review_report(request, evidence)

    def test_digest_cannot_make_a_drifted_base_acceptable(self):
        scope, test = evidence_pair()
        request = validate_review_request(review_request_dict(
            verdict="GO",
            candidate=support.candidate_dict(base_sha="0" * 40, diff_sha256=ARBITRARY_DIGEST),
        ))
        evidence = load_evidence(scope, test)
        with self.assertRaises(PreconditionError):
            build_review_report(request, evidence)

    def test_digest_cannot_make_failed_evidence_acceptable(self):
        scope, test = evidence_pair(test_verdict="FAIL")
        request = validate_review_request(review_request_dict(
            verdict="GO", candidate=support.candidate_dict(diff_sha256=ARBITRARY_DIGEST),
        ))
        evidence = load_evidence(scope, test)
        with self.assertRaises(PreconditionError):
            build_review_report(request, evidence)


class DigestCannotBypassInvalidationTest(unittest.TestCase):
    def test_unchanged_digest_does_not_survive_a_new_head(self):
        # The attack this forecloses: keeping the digest identical so that a
        # moved HEAD looks like the same reviewed state.
        report = _build(support.candidate_dict())
        moved = support.candidate_dict(head_sha=support.OTHER_HEAD_SHA)
        self.assertEqual(report["diff_sha256"], moved["diff_sha256"])
        self.assertFalse(acceptance_still_valid(report, moved))

    def test_unchanged_digest_does_not_survive_a_new_base(self):
        report = _build(support.candidate_dict())
        moved = support.candidate_dict(base_sha="0" * 40)
        self.assertEqual(report["diff_sha256"], moved["diff_sha256"])
        self.assertFalse(acceptance_still_valid(report, moved))

    def test_digest_invalidates_in_one_direction_only(self):
        # A changed digest may additionally invalidate...
        report = _build(support.candidate_dict())
        self.assertFalse(acceptance_still_valid(report, support.candidate_dict(diff_sha256=ARBITRARY_DIGEST)))
        # ...but a matching digest never validates on its own.
        self.assertTrue(acceptance_still_valid(report, support.candidate_dict()))


if __name__ == "__main__":
    unittest.main()
