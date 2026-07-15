import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canonical  # noqa: E402
import evidence  # noqa: E402
import support  # noqa: E402
from model import EvidenceError  # noqa: E402


def bundle_with(scope=None, runner=None, attestation=None):
    return support.make_evidence_bundle(scope, runner, attestation)


class TestEvidence(unittest.TestCase):
    def test_valid_bundle_returns_bound_values(self):
        v = evidence.validate(bundle_with())
        self.assertEqual(v.issue_number, support.ISSUE)
        self.assertEqual(v.execution_id, support.EXEC)
        self.assertEqual(v.base_sha, support.BASE_SHA)
        self.assertEqual(v.head_sha, support.HEAD_SHA)
        self.assertEqual(v.branch, support.BRANCH)
        self.assertEqual(v.repository, "styx-secure/styx")
        self.assertEqual(
            v.hashes.runner_status_sha256, canonical.canonical_sha256(support.make_runner_status())
        )

    def test_wrong_scope_schema_const_fails(self):
        with self.assertRaises(EvidenceError):
            evidence.validate(bundle_with(scope=support.make_scope_report(schema="x")))

    def test_unknown_top_level_key_fails(self):
        bad = support.make_scope_report()
        bad["surprise"] = 1
        with self.assertRaises(EvidenceError):
            evidence.validate(bundle_with(scope=bad))

    def test_missing_top_level_key_fails(self):
        bad = support.make_scope_report()
        del bad["verdict"]
        with self.assertRaises(EvidenceError):
            evidence.validate(bundle_with(scope=bad))

    def test_issue_mismatch_fails(self):
        with self.assertRaises(EvidenceError):
            evidence.validate(bundle_with(scope=support.make_scope_report(issue_number=999)))

    def test_base_sha_mismatch_fails(self):
        with self.assertRaises(EvidenceError):
            evidence.validate(
                bundle_with(
                    runner=support.make_runner_status(
                        base={"branch": "main", "declared_sha": "0" * 40, "verified_sha": "0" * 40}
                    )
                )
            )

    def test_execution_id_mismatch_fails(self):
        with self.assertRaises(EvidenceError):
            evidence.validate(bundle_with(runner=support.make_runner_status(execution_id="other")))

    def test_status_report_hash_mismatch_fails(self):
        att = support.make_attestation(status_report_sha256="c" * 64)
        with self.assertRaises(EvidenceError):
            evidence.validate(bundle_with(attestation=att))

    def test_scope_report_hash_mismatch_fails(self):
        att = support.make_attestation(scope_report_sha256="d" * 64)
        with self.assertRaises(EvidenceError):
            evidence.validate(bundle_with(attestation=att))

    def test_non_pass_scope_fails(self):
        with self.assertRaises(EvidenceError):
            evidence.validate(bundle_with(scope=support.make_scope_report(verdict="FAIL")))

    def test_non_pass_test_evidence_fails(self):
        with self.assertRaises(EvidenceError):
            evidence.validate(bundle_with(runner=support.make_runner_status(tests=[{"state": "FAIL"}])))

    def test_non_final_attestation_fails(self):
        att = support.make_attestation(terminal_status="implementation")
        with self.assertRaises(EvidenceError):
            evidence.validate(bundle_with(attestation=att))

    def test_unverified_repository_fails(self):
        with self.assertRaises(EvidenceError):
            evidence.validate(
                bundle_with(
                    runner=support.make_runner_status(
                        repository={"expected": "styx-secure/styx", "verified": None, "source_root": "/w"}
                    )
                )
            )

    def test_branch_mismatch_between_runner_and_attestation_fails(self):
        att = support.make_attestation(branch="task/53-elsewhere")
        with self.assertRaises(EvidenceError):
            evidence.validate(bundle_with(attestation=att))


if __name__ == "__main__":
    unittest.main()
