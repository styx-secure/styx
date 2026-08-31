#!/usr/bin/env python3
"""Generate the six deterministic, fully synthetic SS-0 corpus files."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any

from canonical_json import canonical_bytes, loads_unique, store_atomic


GENERATOR_PATH = "tools/causal-flow-simulator/ss0/corpus/generate_corpus.py"
GENERATOR_VERSION = "1"
CORPUS_PATHS = (
    "conformance/secure-session/ss0/manifest.json",
    "conformance/secure-session/ss0/valid-session-vectors.json",
    "conformance/secure-session/ss0/invalid-session-vectors.json",
    "conformance/secure-session/ss0/state-machine-scenarios.json",
    "conformance/secure-session/ss0/adversarial-mutations.json",
    "conformance/secure-session/ss0/expected-traces.json",
)
NORMATIVE_INPUTS = (
    ("docs/protocol/styx-secure-session-v0-decisions.md", "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07"),
    ("docs/protocol/styx-app-kernel-v0-responsibility-matrix.md", "3ea43a5b6c9b93a19b2b17ab6a54815583275ea7a544de7e5102b294b13f53db"),
    ("docs/security/STYX-THREAT-MODEL.md", "8863ce4b2ef697055e95da22e0a2fbb630172cdf3f5fd0c91b27ec02f9d2ba54"),
    ("docs/protocol/review/phase-exit/phase-exit-report.json", "b604ede7ab073cd101c6448975d9dac0f8760b214f28ca41d546703c458245af"),
    ("docs/protocol/review/styx-app-kernel-v0-review-model.schema.json", "9975d7ad63bb00ff3351bcf7e740f315a5cbac3acf9b13ac36901e421b46f846"),
    ("tools/protocol-review-model/validate.py", "e79caecde38c457ed79036d339c67b7aa7a394e37708ba76f0aa715ce0092f3b"),
)
REPRODUCTION_INPUTS = (
    ("tools/causal-flow-simulator/ss0/source-inventory.json", "9e793ac550cf5b42a5ebf6a61416c016aded7f248c6936f28fe70f5e6ea78f7c"),
    ("tools/causal-flow-simulator/ss0/source-mutants.json", "3591e3816b14d54107cc22d9f41ca327525401fefbc79719dbe2ce80ecece72b"),
    ("tools/causal-flow-simulator/ss0/phase-b-anchor.json", "4cbeedf3fed1c298739f9c3c00aa1232f1bfac27d1a2decbf2ae1fcd137a695c"),
    ("tools/causal-flow-simulator/ss0/public-candidate-projections.json", "c02160ed4249574edb85d548400c73d53342ac6a7d7dbc42d619499b1630aab1"),
    ("tools/causal-flow-simulator/ss0/oracle-reader-task.json", "7f8190bf3dae52a9140cdc25a24c967547ebb564c0db4d6f88ef3e4ef47ee599"),
    ("tools/causal-flow-simulator/ss0/model.py", "a6dbddf6ab166514268e7dc0c46c99b67743af0b88f862fe81223004aecd953f"),
    ("tools/causal-flow-simulator/ss0/node_adapter.mjs", "cf6461e6852a9180ecf83ad501f2be5e184cbc3b60d3201f891c170cad9056ca"),
    ("tools/causal-flow-simulator/ss0/inventory.py", "391149f9f67f8f444409588cdf0908b872e0efaba1f79afdef4dacb0d2fc4b2f"),
    ("tools/causal-flow-simulator/ss0/validate_inventory.py", "5d4a5432e09a1f9132c57bfeb713a66775ab7069f18a5b8ec03272083aea4861"),
    ("tools/causal-flow-simulator/ss0/canonical_report.py", "deaf4b06eb14243b15b06c5ab687b40dd846b35800a2c72ac24d809bb0fd314d"),
    ("tools/causal-flow-simulator/ss0/final_gate.py", "5967ad0eb0687579b8036e586c77275dd4f2d42a8c135a54e39c664275b07acf"),
    ("tools/causal-flow-simulator/ss0/scope_guard.py", "befc80557c35539964294f0389d9c02539400db842e96406f74dba8e21d77507"),
    ("tools/causal-flow-simulator/ss0/run_cross_runtime.py", "11b30444e9aebf5b887c414eeeb3c0782e9e69297a3470fea4fe309b1ba16468"),
    ("tools/causal-flow-simulator/ss0/run_mutations.py", "edcb7e54b5067d5953bd70b379fb2af811f04e5272e686a5cd3076be234df039"),
    ("tools/causal-flow-simulator/ss0/run_probe.py", "e70cc4c98e3070bda268296ad44abd104bef193215dd517b0eff86d2b844d1a6"),
    ("tools/causal-flow-simulator/ss0/verify_gate_a.py", "b638c0ee8a19d5bdbae5a332aa562bf6e8ca864ab8527bb22f2550f2e216858c"),
)
PROFILE = {
    "ciphersuite": "0x0001",
    "ciphersuite_registry": "IANA_MLS",
    "marmot": "4ad4ae21479c3f3fa9950c6fc4556a76941a62e1",
    "mdk": "9396adb6aa6b95b521a7979facd5ea7040c07288",
    "members": ["MDK_PIN_9396ADB", "STYX_B32A"],
    "openmls": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
    "retained_past_epochs": 5,
}
AUTHORITY = {
    "blocks": [
        "adapter", "demo", "deployment", "persistence", "product", "sdk",
        "sensitive_use", "transport",
    ],
    "corpusConstruction": "COMPLETE",
    "ss0Evidence": "BOUNDED_GO",
}
NON_CLAIMS = [
    "NO_ADAPTER_OR_SDK",
    "NO_CRYPTOGRAPHIC_PROOF_OR_GENERAL_MLS_CONFORMANCE",
    "NO_DELIVERY_FRESHNESS_FINALITY_OR_AVAILABILITY",
    "NO_PERSISTENCE_RECOVERY_OR_ROLLBACK_CLAIM",
    "NO_PRODUCT_DEMO_DEPLOYMENT_OR_SENSITIVE_USE",
    "NO_TRANSPORT_OR_WIRE_CLAIM",
]
STATE_OPERATIONS = {"convergence", "mutation", "replay", "restored_state", "welcome"}
VALID_DISPOSITIONS = {
    "ACCEPTED_EVIDENCE", "AP_AUTHORITY_REQUIRED", "NOT_CLAIMED_IN_PROFILE"
}
SUPPLEMENTAL_MUTANTS = {
    "M-X-CANDIDATE-NUMERIC-APP-WITNESS": "X-FLOAT-APP-WITNESS-CANDIDATE-FIELD",
    "M-X-CANDIDATE-NUMERIC-DEPTH": "X-FLOAT-DEPTH-CANDIDATE-FIELD",
    "M-X-TOP-LEVEL-UNKNOWN-FIELD": "X-UNKNOWN-CANDIDATE-FIELD",
}
EXPECTED_COUNTS = {
    "adversarialMutations": 44,
    "atomWitnessRelations": 104,
    "corpusDataMutations": 28,
    "corpusWitnessMutations": 41,
    "expectedTraces": 56,
    "frozenSupplementalMutations": 3,
    "invalidSessionVectors": 18,
    "owners": 20,
    "sourceAtoms": 60,
    "sourceWitnesses": 56,
    "stateMachineScenarios": 24,
    "validSessionVectors": 14,
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_pinned(repo: Path, relation: tuple[tuple[str, str], ...]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for name, expected in relation:
        path = repo / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"pinned input unavailable: {name}")
        actual = _sha256(path.read_bytes())
        if actual != expected:
            raise ValueError(f"pinned input digest mismatch: {name}")
        result.append({"path": name, "sha256": actual})
    return result


def _load_document(repo: Path, name: str) -> dict[str, Any]:
    value = loads_unique((repo / name).read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"input is not an object: {name}")
    return value


def build_files(repo: Path) -> dict[str, bytes]:
    repo = repo.resolve(strict=True)
    normative = _read_pinned(repo, NORMATIVE_INPUTS)
    reproduction = _read_pinned(repo, REPRODUCTION_INPUTS)
    inventory = _load_document(repo, "tools/causal-flow-simulator/ss0/source-inventory.json")
    mutants = _load_document(repo, "tools/causal-flow-simulator/ss0/source-mutants.json")
    if set(inventory) != {"atoms", "closed_dispositions", "owners", "schema", "witnesses"}:
        raise ValueError("source inventory shape mismatch")
    if inventory.get("schema") != "styx.ss0.inventory.v2":
        raise ValueError("source inventory schema mismatch")
    if set(mutants) != {"mutants", "schema"} or mutants.get("schema") != "styx.ss0.mutants.v2":
        raise ValueError("source mutant registry mismatch")

    valid: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    scenarios: list[dict[str, Any]] = []
    traces: list[dict[str, Any]] = []
    for witness in inventory["witnesses"]:
        identity = witness["id"]
        row = {"id": identity, "input": witness["input"], "sourceWitness": identity}
        operation = witness["input"].get("operation")
        disposition = witness["expected"].get("disposition")
        if operation in STATE_OPERATIONS:
            scenarios.append(row)
        elif disposition in VALID_DISPOSITIONS:
            valid.append(row)
        else:
            invalid.append(row)
        traces.append({"expected": witness["expected"], "id": identity})

    mutation_rows = []
    for mutant in mutants["mutants"]:
        identity = mutant["id"]
        expected_detector = SUPPLEMENTAL_MUTANTS.get(identity)
        if expected_detector is not None and mutant["detector"] != expected_detector:
            raise ValueError(f"supplemental detector mismatch: {identity}")
        mutation_rows.append(
            {
                "coverageClass": (
                    "FROZEN_SUPPLEMENTAL" if identity in SUPPLEMENTAL_MUTANTS
                    else "CORPUS_WITNESS"
                ),
                "detector": mutant["detector"],
                "id": identity,
                "requirement": mutant["requirement"],
                "sourceMutant": identity,
            }
        )

    documents: dict[str, dict[str, Any]] = {
        CORPUS_PATHS[1]: {"schema": "styx.ss0.corpus.valid-session-vectors.v1", "vectors": valid},
        CORPUS_PATHS[2]: {"schema": "styx.ss0.corpus.invalid-session-vectors.v1", "vectors": invalid},
        CORPUS_PATHS[3]: {"scenarios": scenarios, "schema": "styx.ss0.corpus.state-machine-scenarios.v1"},
        CORPUS_PATHS[4]: {"mutations": mutation_rows, "schema": "styx.ss0.corpus.adversarial-mutations.v1"},
        CORPUS_PATHS[5]: {"schema": "styx.ss0.corpus.expected-traces.v1", "traces": traces},
    }
    encoded = {name: canonical_bytes(value) for name, value in documents.items()}
    counts = {
        "adversarialMutations": len(mutation_rows),
        "atomWitnessRelations": sum(len(atom["witnesses"]) for atom in inventory["atoms"]),
        "corpusDataMutations": 28,
        "corpusWitnessMutations": len(mutation_rows) - len(SUPPLEMENTAL_MUTANTS),
        "expectedTraces": len(traces),
        "frozenSupplementalMutations": len(SUPPLEMENTAL_MUTANTS),
        "invalidSessionVectors": len(invalid),
        "owners": len(inventory["owners"]),
        "sourceAtoms": len(inventory["atoms"]),
        "sourceWitnesses": len(inventory["witnesses"]),
        "stateMachineScenarios": len(scenarios),
        "validSessionVectors": len(valid),
    }
    if counts != EXPECTED_COUNTS:
        raise ValueError(f"source-derived count mismatch: {counts}")
    manifest: dict[str, Any] = {
        "authority": AUTHORITY,
        "counts": counts,
        "generatedFiles": [
            {"path": name, "sha256": _sha256(encoded[name])} for name in CORPUS_PATHS[1:]
        ],
        "generator": {"path": GENERATOR_PATH, "version": GENERATOR_VERSION},
        "manifestPayloadSha256": "",
        "nonClaims": NON_CLAIMS,
        "normativeInputs": normative,
        "profile": PROFILE,
        "reproductionInputs": reproduction,
        "schema": "styx.ss0.corpus.manifest.v1",
        "synthetic": True,
        "upstreamBytes": "none",
    }
    payload = dict(manifest)
    del payload["manifestPayloadSha256"]
    manifest["manifestPayloadSha256"] = _sha256(canonical_bytes(payload))
    encoded[CORPUS_PATHS[0]] = canonical_bytes(manifest)
    return {name: encoded[name] for name in CORPUS_PATHS}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    repo = arguments.repo_root.resolve(strict=True)
    output = arguments.output_dir.resolve() if arguments.output_dir.is_absolute() else (repo / arguments.output_dir).resolve()
    expected_output = (repo / "conformance/secure-session/ss0").resolve()
    if output != expected_output:
        raise ValueError("output directory is outside the authorized corpus path")
    files = build_files(repo)
    for name, data in files.items():
        target = repo / name
        if arguments.write:
            store_atomic(target, data)
        elif not target.is_file() or target.is_symlink() or target.read_bytes() != data:
            raise ValueError(f"generated corpus drift: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
