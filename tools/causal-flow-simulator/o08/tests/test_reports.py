from __future__ import annotations

import copy
from hashlib import sha256
import json
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from canonical_report import ReportError, load_report, store_report
from envelope_model import candidate_identity, validate_candidate_set
from run_measurements import (
    REPORT_SCHEMA, _activation_outcome, _single, structural_evidence,
    validate_set,
)
from semantic_registry import CANDIDATES_PATH, canonical_bytes, load_json
from validate_envelope import validate_selection


class ReportTests(unittest.TestCase):
    def _selection_provider(self):
        candidates = validate_candidate_set(load_json(CANDIDATES_PATH))
        selection_head = "1" * 40
        object_id = "123456789"
        url = f"https://api.github.com/repos/styx-secure/styx/issues/comments/{object_id}"
        body = {
            "schema": "styx-o08-selection/v1", "status": "accepted",
            "operator": "maverde73", "base_sha": "ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3",
            "selection_head": selection_head,
            "candidate_set_sha256": sha256(CANDIDATES_PATH.read_bytes()).hexdigest(),
            "measurement_reports": [
                {
                    "candidate_id": candidate,
                    "capability_profile": profile,
                    "report_sha256": sha256(f"{candidate}/{profile}".encode()).hexdigest(),
                }
                for candidate in ("conservative", "balanced", "expansive")
                for profile in ("HOST_MINIMAL", "HOST_EXTENDED")
            ],
            "comparison_report_sha256": "2" * 64,
            "selected_candidate_id": "conservative",
            "selected_envelope_sha256": candidate_identity(candidates[0]),
        }
        provider = {
            "id": int(object_id), "url": url,
            "issue_url": "https://api.github.com/repos/styx-secure/styx/issues/250",
            "user": {"id": 141346846, "login": "maverde73"},
            "created_at": "2026-08-26T12:00:00Z",
            "updated_at": "2026-08-26T12:00:00Z",
            "body": json.dumps(body, sort_keys=True, separators=(",", ":")),
        }
        return provider, body, url, object_id, selection_head

    def test_canonical_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            report = {"schema": "example/v1", "value": "docs/protocol/root-authority.md", "verdict": "PASS"}
            store_report(path, report, "example/v1")
            self.assertEqual(load_report(path, "example/v1"), report)

    def test_runtime_provenance_and_measurement_are_rejected(self):
        bad = ("provenance=/tmp/styx", "path=C:\\review", "elapsed=1.2s", "2026-08-26T12:00")
        with tempfile.TemporaryDirectory() as temporary:
            for index, value in enumerate(bad):
                with self.assertRaises(ReportError):
                    store_report(Path(temporary) / f"{index}.json", {"schema": "x/v1", "value": value}, "x/v1")

    def test_structural_width_gate_precedes_dp_and_retains_reference_witness(self):
        import subprocess

        head = subprocess.run(
            ["git", "-C", str(ROOT.parents[2]), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        candidate = validate_candidate_set(load_json(CANDIDATES_PATH))[0]
        evidence = structural_evidence(ROOT.parents[2], candidate, head, "node")
        rows = {row["witness_id"]: row for row in evidence["rows"]}
        self.assertTrue(evidence["independent_oracle_agreement"])
        self.assertFalse(rows["BOUNDARY_PLUS_ONE"]["dp_invoked"])
        self.assertEqual(
            rows["BOUNDARY_PLUS_ONE"]["disposition"],
            "AUTHORITY_PROJECTION_UNAVAILABLE",
        )
        retained = rows["RETAINED_4033_STATE_WITNESS"]["reference_characterization"]
        self.assertEqual(
            (retained["reachable_states"], retained["transitions"]),
            (4_033, 14_556),
        )

    def test_report_set_rejects_self_hashed_but_fabricated_structural_evidence(self):
        import subprocess

        repo = ROOT.parents[2]
        head = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        payload = load_json(CANDIDATES_PATH)
        candidates = validate_candidate_set(payload)
        with tempfile.TemporaryDirectory() as temporary:
            paths = []
            for candidate in candidates:
                structural = structural_evidence(repo, candidate, head, "node")
                for profile_id, profile in payload["capability_profiles"].items():
                    retained, counters = _single(candidate, profile)
                    report = {
                        "schema": REPORT_SCHEMA,
                        "candidate_id": candidate["id"],
                        "candidate_digest": candidate_identity(candidate),
                        "candidate_set_sha256": sha256(CANDIDATES_PATH.read_bytes()).hexdigest(),
                        "selection_head": head,
                        "implementation_head": head,
                        "deterministic_structural_evidence": copy.deepcopy(structural),
                        "capability_profile": profile_id,
                        "repetitions": {"cold": 1, "warm": 1},
                        "cpu_ns": {"median": 1, "p95": 1, "maximum": 1},
                        "wall_ns": {"median": 1, "p95": 1, "maximum": 1},
                        "peak_rss_kib": 1,
                        "retained_output_octets": retained,
                        "transient_memory_counters": counters,
                        "semantic_outcome": _activation_outcome(candidate, profile),
                    }
                    path = Path(temporary) / f"{candidate['id']}-{profile_id}.json"
                    path.write_bytes(canonical_bytes(report))
                    paths.append(path)
            validate_set(repo, paths, head, CANDIDATES_PATH, "node")

            forged = json.loads(paths[0].read_bytes())
            forged_structural = forged["deterministic_structural_evidence"]
            forged_structural["rows"][0]["exact_width"] += 1
            unhashed = dict(forged_structural)
            unhashed.pop("structural_identity")
            forged_structural["structural_identity"] = sha256(
                canonical_bytes(unhashed)
            ).hexdigest()
            paths[0].write_bytes(canonical_bytes(forged))
            with self.assertRaises(ValueError):
                validate_set(repo, paths, head, CANDIDATES_PATH, "node")

    def test_selection_identity_and_digest_fail_closed(self):
        provider, body, url, object_id, selection_head = self._selection_provider()
        accepted = validate_selection(
            provider, url=url, object_id=object_id,
            base="ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3",
            selection_head=selection_head, candidate_set_path=CANDIDATES_PATH,
        )
        self.assertEqual(accepted["selected_candidate_id"], "conservative")
        mutations = []
        for field in ("candidate_set_sha256", "comparison_report_sha256", "selected_envelope_sha256"):
            hostile = copy.deepcopy(provider)
            value = copy.deepcopy(body); value[field] = "g" * 64
            hostile["body"] = json.dumps(value, sort_keys=True, separators=(",", ":"))
            mutations.append(hostile)
        wrong_tuple = copy.deepcopy(provider)
        value = copy.deepcopy(body); value["measurement_reports"][0]["capability_profile"] = "HOST_EXTENDED"
        wrong_tuple["body"] = json.dumps(value, sort_keys=True, separators=(",", ":"))
        mutations.append(wrong_tuple)
        wrong_head = copy.deepcopy(provider)
        value = copy.deepcopy(body); value["selection_head"] = "z" * 40
        wrong_head["body"] = json.dumps(value, sort_keys=True, separators=(",", ":"))
        mutations.append(wrong_head)
        stale = copy.deepcopy(provider); stale["updated_at"] = "2026-08-26T12:00:01Z"; mutations.append(stale)
        for hostile in mutations:
            with self.assertRaises(ValueError):
                validate_selection(
                    hostile, url=url, object_id=object_id,
                    base="ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3",
                    selection_head=selection_head, candidate_set_path=CANDIDATES_PATH,
                )

    def test_selection_rejects_candidate_set_package_substitution(self):
        provider, _, url, object_id, selection_head = self._selection_provider()
        with tempfile.TemporaryDirectory() as temporary:
            substituted = Path(temporary) / "resource-envelope.candidates.json"
            substituted.write_bytes(CANDIDATES_PATH.read_bytes() + b" ")
            with self.assertRaises(ValueError):
                validate_selection(
                    provider, url=url, object_id=object_id,
                    base="ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3",
                    selection_head=selection_head, candidate_set_path=substituted,
                )


if __name__ == "__main__":
    unittest.main()
