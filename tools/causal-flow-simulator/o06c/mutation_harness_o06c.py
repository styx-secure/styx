#!/usr/bin/env python3
"""Closed exact-detector source mutation harness for O-06c."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

from common import sha256_hex, write_report
from combined_falsification_probe import WITNESS_ASSERTION_REGISTRY


SCHEMA = "styx-o06c-mutation-report/v1"


@dataclass(frozen=True)
class Mutant:
    identifier: str
    mutant_class: str
    path: str
    old: str
    new: str
    detector: str
    subject: str | None = None
    contractual_class_member: bool = True


MUTANTS = (
    Mutant("M01_TRANSCRIPT_DOMAIN_ROLE", "transcript domain/role", "protocol_model.py", 'transcript = DOMAINS["application"] + u32(len(body), "event body length") + body', 'transcript = _mutation_trace("M01_TRANSCRIPT_DOMAIN_ROLE", DOMAINS["commitment"]) + u32(len(body), "event body length") + body', "CROSS_LANGUAGE_TRANSCRIPT_MISMATCH"),
    Mutant("M02_TRANSCRIPT_LENGTH", "transcript length framing", "protocol_model.py", 'transcript = DOMAINS["application"] + u32(len(body), "event body length") + body', 'transcript = DOMAINS["application"] + _mutation_trace("M02_TRANSCRIPT_LENGTH", u32(len(body) + 1, "event body length")) + body', "TRANSCRIPT_LENGTH_REJECT"),
    Mutant("M03_CREDENTIAL_TAIL", "credential-control tail", "protocol_model.py", 'return prefix + u16(tail.grantee_suite_id, "grantee suite") + opaque_u32(', 'return prefix + _mutation_trace("M03_CREDENTIAL_TAIL", u16(tail.grantee_suite_id + 1, "grantee suite")) + opaque_u32(', "CREDENTIAL_TAIL_REJECT"),
    Mutant("M04_CONTEXT_84", "84-octet context", "protocol_model.py", 'u16(self.commitment_suite_id, "commitment suite"),', '_mutation_trace("M04_CONTEXT_84", u16(self.commitment_suite_id + 1, "commitment suite")),', "CTX84_SUITE_DRIFT"),
    Mutant("M05_CREDENTIAL_BINDING", "credential binding", "protocol_model.py", 'opaque32(self.credential_identifier, "credential identifier"),', '_mutation_trace("M05_CREDENTIAL_BINDING", bytes(32)),', "CREDENTIAL_BINDING_ALIAS"),
    Mutant("M06_AUTHOR_SEQUENCE_BINDING", "author-sequence binding", "protocol_model.py", 'u64(self.author_sequence, "author sequence"),', '_mutation_trace("M06_AUTHOR_SEQUENCE_BINDING", bytes(8)),', "SEQUENCE_BINDING_ALIAS"),
    Mutant("M07_LEAF_PREIMAGE", "leaf preimage", "protocol_model.py", 'u64(ordinal, "leaf ordinal"),', '_mutation_trace("M07_LEAF_PREIMAGE", bytes(8)),', "LEAF_ORDINAL_ALIAS"),
    Mutant("M08_NODE_PREIMAGE", "interior-node preimage", "protocol_model.py", '+ u64(len(digests), "subtree leaf count")', '+ _mutation_trace("M08_NODE_PREIMAGE", u64(2, "subtree leaf count"))', "NODE_COUNT_DRIFT"),
    Mutant("M09_COMMITMENT_OBJECT", "complete commitment object", "protocol_model.py", '            root,\n            randomizer,', '            _mutation_trace("M09_COMMITMENT_OBJECT", bytes(32)),\n            randomizer,', "COMMITMENT_ROOT_DRIFT"),
    Mutant("M10_PARSER_GEOMETRY", "parser/inverse geometry", "protocol_model.py", '    _validate_geometry(exact_length, shape, geometry, work)\n    return {', '    _mutation_trace("M10_PARSER_GEOMETRY", None)\n    return {', "INVALID_GEOMETRY_ACCEPTED"),
    Mutant("M11_AUTHORITY_MUST0", "authority Must0 expansion", "policy_guards.py", '    return len(bypass_observed) == 2 and not any(bypass_observed)', '    return _mutation_trace("M11_AUTHORITY_MUST0", True)', "MUST0_EXPANSION"),
    Mutant("M12_PENDING_RETENTION", "pending-authority retention", "policy_guards.py", '    return evidence', '    return _mutation_trace("M12_PENDING_RETENTION", ())', "K_EVIDENCE_FILTERED"),
    Mutant("M13_LINEAGE_FORK", "lineage-scoped fork effect", "policy_guards.py", '    return authority - forked_lineage', '    return _mutation_trace("M13_LINEAGE_FORK", frozenset())', "UNRELATED_AUTHORITY_LOST"),
    Mutant("M14_FROZEN_DIGEST", "frozen-section digest enforcement", "verify_frozen_sections.py", '    return "PASS" if actual == expected else "DIGEST_MISMATCH"', '    return _mutation_trace("M14_FROZEN_DIGEST", "PASS")', "FROZEN_DIGEST_BYPASS"),
    Mutant("M15_HISTORICAL_REGISTRY", "historical-registry enforcement", "historical_evidence_gate.py", '    if len(registry) != 7:', '    if _mutation_trace("M15_HISTORICAL_REGISTRY", False):', "EIGHTH_HISTORY_ACCEPTED"),
    Mutant("M16_C03_CAPABILITY", "C0.3 capability-gate retention", "policy_guards.py", '    return declared_blocks', '    return _mutation_trace("M16_C03_CAPABILITY", frozenset())', "C03_CAPABILITY_OPENED"),
    Mutant(
        "M17_REMOVAL_PROJECTION",
        "pending-authority retention",
        "policy_guards.py",
        '    matches = [record for record in ambient if record.reference == target_reference]',
        '    matches = _mutation_trace("M17_REMOVAL_PROJECTION", [])',
        "RETAINED_REMOVAL_NOT_APPLIED",
        subject="AP removal projection",
        contractual_class_member=False,
    ),
)

EXPECTED_MUTANT_CLASSES = frozenset(
    {
        "transcript domain/role",
        "transcript length framing",
        "credential-control tail",
        "84-octet context",
        "credential binding",
        "author-sequence binding",
        "leaf preimage",
        "interior-node preimage",
        "complete commitment object",
        "parser/inverse geometry",
        "authority Must0 expansion",
        "pending-authority retention",
        "lineage-scoped fork effect",
        "frozen-section digest enforcement",
        "historical-registry enforcement",
        "C0.3 capability-gate retention",
    }
)

# Witness coverage and source-mutation coverage are intentionally separate.
# A witness is an executed directed assertion; a mutant is killed only by the
# exact detector process below.  No unexecuted witness→mutant relation is
# reported.
WITNESS_COVERAGE = WITNESS_ASSERTION_REGISTRY

MUTANT_ONLY_COVERAGE = {
    "frozen-evidence": ("M14_FROZEN_DIGEST", "FROZEN_DIGEST_BYPASS"),
    "historical-evidence": (
        "M15_HISTORICAL_REGISTRY",
        "EIGHTH_HISTORY_ACCEPTED",
    ),
}


class HarnessError(ValueError):
    pass


INSTRUMENTATION = '''
_MUTATION_PATHS = set()

def _mutation_trace(label, value):
    _MUTATION_PATHS.add(label)
    return value
'''


def mutate_source(source: str, mutant: Mutant) -> str:
    if source.count(mutant.old) != 1:
        raise HarnessError(f"source selector count drift for {mutant.identifier}")
    marker = "from __future__ import annotations\n"
    if source.count(marker) != 1:
        raise HarnessError(f"future-import marker drift for {mutant.identifier}")
    instrumented = source.replace(marker, marker + INSTRUMENTATION, 1)
    return instrumented.replace(mutant.old, mutant.new, 1)


def execute_mutant(source_root: Path, mutant: Mutant, stage: Path) -> dict[str, object]:
    stage.mkdir()
    support = (
        "common.py",
        "protocol_model.py",
        "policy_guards.py",
        "verify_frozen_sections.py",
        "historical_evidence_gate.py",
        "mutation_detector.py",
    )
    for name in support:
        shutil.copyfile(source_root / name, stage / name)
    target = stage / mutant.path
    target.write_text(mutate_source(target.read_text(encoding="utf-8"), mutant), encoding="utf-8")
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
        "TZ": "UTC",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    completed = subprocess.run(
        [sys.executable, "-B", "mutation_detector.py", mutant.identifier],
        cwd=stage,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    try:
        observed = json.loads(completed.stdout) if completed.returncode == 0 else {}
    except ValueError:
        observed = {}
    observed_detectors = observed.get("detectors", [])
    declared = [mutant.detector]
    executed = observed.get("path_executed") is True
    exact = observed_detectors == declared
    missing = sorted(set(declared) - set(observed_detectors))
    extra = sorted(set(observed_detectors) - set(declared))
    status = "KILLED" if completed.returncode == 0 and executed and exact else "SURVIVED"
    if not executed:
        disposition = "NON_EXECUTED"
    elif extra:
        disposition = "UNDECLARED_DETECTOR"
    elif missing:
        disposition = "MISSING_DETECTOR"
    elif completed.returncode != 0:
        disposition = "DETECTOR_PROCESS_FAILURE"
    else:
        disposition = "EXACT_DECLARED_SET"
    return {
        "id": mutant.identifier,
        "class": mutant.mutant_class,
        "subject": mutant.subject or mutant.mutant_class,
        "contractual_class_member": mutant.contractual_class_member,
        "source_path": f"tools/causal-flow-simulator/o06c/{mutant.path}",
        "source_mutation_sha256": sha256_hex(target.read_bytes()),
        "declared_detectors": declared,
        "observed_detectors": observed_detectors,
        "missing_detectors": missing,
        "extra_detectors": extra,
        "mutated_path_executed": executed,
        "detector_exit": completed.returncode,
        "stdout_sha256": sha256_hex(completed.stdout.encode()),
        "stderr_sha256": sha256_hex(completed.stderr.encode()),
        "disposition": disposition,
        "status": status,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--frozen-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    source_root = Path(__file__).resolve().parent
    try:
        frozen_bytes = args.frozen_report.read_bytes()
        frozen = json.loads(frozen_bytes)
        if frozen.get("schema") != "styx-o06c-frozen-section-report/v1" or frozen.get("verdict") != "PASS":
            raise HarnessError("frozen-section report is not PASS")
        if len(MUTANTS) != 17 or len({item.identifier for item in MUTANTS}) != 17:
            raise HarnessError("closed mutant registry drift")
        mutant_ids = {item.identifier for item in MUTANTS}
        mutant_classes = {item.mutant_class for item in MUTANTS}
        if mutant_classes != EXPECTED_MUTANT_CLASSES:
            raise HarnessError("closed mutant-class registry drift")
        contractual_members = tuple(
            item for item in MUTANTS if item.contractual_class_member
        )
        if len(contractual_members) != len(EXPECTED_MUTANT_CLASSES):
            raise HarnessError("contractual mutant-class membership drift")
        if {
            item.mutant_class for item in contractual_members
        } != EXPECTED_MUTANT_CLASSES:
            raise HarnessError("contractual mutant-class coverage drift")
        if any(
            item.subject is None
            for item in MUTANTS
            if not item.contractual_class_member
        ):
            raise HarnessError("supplementary mutant subject missing")
        if any(not assertions for assertions in WITNESS_COVERAGE.values()):
            raise HarnessError("empty directed-assertion coverage")
        mutant_to_detectors = {
            item.identifier: [item.detector]
            for item in MUTANTS
        }
        if set(mutant_to_detectors) != mutant_ids:
            raise HarnessError("mutant/detector registry drift")
        for family, (mutant_id, detector) in MUTANT_ONLY_COVERAGE.items():
            if mutant_id not in mutant_ids:
                raise HarnessError(f"unknown mutant-only coverage ID: {family}")
            if mutant_to_detectors[mutant_id] != [detector]:
                raise HarnessError(f"mutant-only detector drift: {family}")
        with tempfile.TemporaryDirectory(prefix="styx-o06c-mutants-") as directory:
            root = Path(directory)
            records = [execute_mutant(source_root, mutant, root / mutant.identifier.lower()) for mutant in MUTANTS]
        killed = all(record["status"] == "KILLED" for record in records)
        report = {
            "schema": SCHEMA,
            "suite": "required",
            "frozen_report_sha256": sha256_hex(frozen_bytes),
            "registry_size": len(MUTANTS),
            "mutant_class_count": len(mutant_classes),
            "mutants": records,
            "witness_coverage": {
                family: {"directed_assertions": list(assertions)}
                for family, assertions in sorted(WITNESS_COVERAGE.items())
            },
            "mutant_only_coverage": {
                family: {
                    "mutant_id": mutant_id,
                    "directed_detector": detector,
                }
                for family, (mutant_id, detector) in sorted(
                    MUTANT_ONLY_COVERAGE.items()
                )
            },
            "mutant_to_detectors": mutant_to_detectors,
            "killed_count": sum(record["status"] == "KILLED" for record in records),
            "survived": [record["id"] for record in records if record["status"] != "KILLED"],
            "verdict": "ALL_REQUIRED_MUTANTS_KILLED" if killed else "MUTANTS_SURVIVED",
        }
        write_report(args.output, report)
    except (HarnessError, OSError, ValueError) as error:
        print(f"O-06c mutation harness failure: {error}", file=sys.stderr)
        return 2
    print(
        f"O-06c mutation verdict={report['verdict']} "
        f"killed={report['killed_count']}/{report['registry_size']}"
    )
    return 0 if killed else 1


if __name__ == "__main__":
    raise SystemExit(main())
