"""Source-backed O-14 invariants used by the mutation evidence gate."""

from __future__ import annotations

import copy
from pathlib import Path

from evidence_io import CanonicalJsonReport
from semantic_registry import Mutation


MODEL_PATH = Path("docs/protocol/review/styx-app-kernel-v0-review-model.json")
REPORT_PATH = Path(
    "docs/protocol/styx-app-kernel-v0-signature-suite-falsification-report.md"
)
EXPECTED_C03_DEPENDENCIES = {
    "C0.3_CORPUS_PATH_APPROVAL",
    "O-06c",
    "O-07",
    "O-08",
    "O-10",
    "O-14",
}
EXPECTED_EVIDENCE_SOURCES = {
    "decisions",
    "signature_suite_analysis",
    "signature_suite_report",
}


def _record(model: dict[str, object], identifier: str) -> dict[str, object]:
    blockers = model.get("blockers")
    if not isinstance(blockers, list):
        raise ValueError("review model blockers missing")
    matches = [item for item in blockers if item.get("id") == identifier]
    if len(matches) != 1:
        raise ValueError(f"review model blocker cardinality: {identifier}")
    return matches[0]


def evaluate_source_invariants(
    repo_root: Path, mutation: Mutation
) -> tuple[dict[str, object], ...]:
    """Mutate loaded source structures, then evaluate their real invariants."""

    model = CanonicalJsonReport.load(repo_root / MODEL_PATH)
    if not isinstance(model, dict):
        raise ValueError("review model root must be an object")
    candidate = copy.deepcopy(model)
    report_text = (repo_root / REPORT_PATH).read_text(encoding="utf-8")
    executed: list[str] = []

    o14 = _record(candidate, "O-14")
    c03 = _record(candidate, "C0.3")
    if mutation.identifier == "M_STATUS_WITHOUT_EVIDENCE":
        o14["citations"] = [
            item
            for item in o14.get("citations", [])
            if item.get("source_id") == "decisions"
        ]
        o14["reason"] = "DECIDED without linked falsification evidence"
        executed.append("mutant:status-without-evidence")
    elif mutation.identifier == "M_C03_DEPENDENCY_DRIFT":
        c03["depends_on"] = [
            item for item in c03.get("depends_on", []) if item != "O-14"
        ]
        executed.append("mutant:c03-dependency-drift")

    cited = {
        item.get("source_id")
        for item in o14.get("citations", [])
        if isinstance(item, dict)
    }
    decision_has_evidence = (
        o14.get("status") == "DECIDED"
        and str(o14.get("reason", "")).startswith("CONDITION-BEARING:")
        and cited == EXPECTED_EVIDENCE_SOURCES
        and "ALL_REQUIRED_MUTANTS_KILLED" in report_text
        and "O-14 may change from `OPEN` to condition-bearing" in report_text
    )
    dependency_fixed = (
        c03.get("status") == "NO_GO"
        and set(c03.get("depends_on", [])) == EXPECTED_C03_DEPENDENCIES
        and set(c03.get("blocks", []))
        == {"corpus", "demo", "implementation_alignment", "product", "sensitive_use"}
    )

    return (
        {
            "id": "decided-requires-evidence",
            "passed": decision_has_evidence,
            "expected_accept": True,
            "expected_code": "SOURCE_INVARIANT",
            "actual_accept": decision_has_evidence,
            "actual_code": "SOURCE_INVARIANT" if decision_has_evidence else "SOURCE_DRIFT",
            "verifier_invocations": 0,
            "ap_exposed": False,
            "executed_branches": list(executed),
        },
        {
            "id": "c03-dependency-set-fixed",
            "passed": dependency_fixed,
            "expected_accept": True,
            "expected_code": "SOURCE_INVARIANT",
            "actual_accept": dependency_fixed,
            "actual_code": "SOURCE_INVARIANT" if dependency_fixed else "SOURCE_DRIFT",
            "verifier_invocations": 0,
            "ap_exposed": False,
            "executed_branches": list(executed),
        },
    )
