#!/usr/bin/env python3
"""Provision exact O-14 runtime dependencies and compare their semantics."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request

sys.dont_write_bytecode = True

from evidence_io import CanonicalJsonReport
from signature_suite_probe import build_report as build_probe_report
from scenarios import EXPECTED_RUNTIME_VECTOR_COUNT


SCHEMA = "styx-o14-cross-runtime-report/v1"
NOBLE_VERSION = "2.3.0"
DART_CRYPTOGRAPHY_VERSION = "2.9.0"
DART_ARCHIVE_URL = "https://pub.dev/api/archives/cryptography-2.9.0.tar.gz"
DART_ARCHIVE_SHA256 = "3eda3029d34ec9095a27a198ac9785630fe525c0eb6a49f3d575272f8e792ef0"
ADAPTER_VECTOR_FIELDS = (
    "id",
    "message_hex",
    "public_key_hex",
    "signature_hex",
    "expected_selected",
)


class GateError(RuntimeError):
    pass


def adapter_vector(vector: dict[str, object]) -> dict[str, object]:
    """Project only protocol inputs and the expected decision into adapters."""

    return {field: vector[field] for field in ADAPTER_VECTOR_FIELDS}


def public_failure(error: BaseException) -> str:
    """Return bounded diagnostics without leaking temporary filesystem paths."""

    if isinstance(error, GateError):
        return str(error)
    if isinstance(error, subprocess.CalledProcessError):
        command = error.cmd if isinstance(error.cmd, (list, tuple)) else [error.cmd]
        executable = Path(str(command[0])).name
        return f"{executable} failed with exit status {error.returncode}"
    if isinstance(error, OSError):
        errno = error.errno if error.errno is not None else "unknown"
        return f"operating system error (errno={errno})"
    if isinstance(error, KeyError):
        return "runtime evidence omitted a required field"
    return "invalid structured runtime evidence"


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        executable = Path(command[0]).name
        raise GateError(
            f"{executable} failed with exit status {error.returncode}"
        ) from None
    return completed.stdout


def download(url: str, destination: Path) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    destination.write_bytes(data)
    return data


def noble_lock_identity(repo: Path) -> dict[str, str]:
    lock = CanonicalJsonReport.load(repo / "styx-js/package-lock.json")
    entry = lock["packages"]["node_modules/@noble/ed25519"]
    if entry["version"] != NOBLE_VERSION:
        raise GateError("unexpected @noble/ed25519 version")
    return {
        "version": entry["version"],
        "resolved": entry["resolved"],
        "integrity": entry["integrity"],
    }


def provision_noble(repo: Path, workspace: Path) -> tuple[Path, dict[str, str]]:
    identity = noble_lock_identity(repo)
    archive = workspace / "noble.tgz"
    data = download(identity["resolved"], archive)
    algorithm, encoded = identity["integrity"].split("-", 1)
    if algorithm != "sha512" or base64.b64encode(hashlib.sha512(data).digest()).decode() != encoded:
        raise GateError("@noble/ed25519 integrity mismatch")
    extract_root = workspace / "noble-extract"
    extract_root.mkdir()
    with tarfile.open(archive, "r:gz") as package:
        package.extractall(extract_root, filter="data")
    source = extract_root / "package"
    target = workspace / "node_modules/@noble/ed25519"
    target.parent.mkdir(parents=True)
    shutil.move(str(source), str(target))
    return target / "index.js", identity


def find_dart() -> str:
    candidates = [os.environ.get("STYX_O14_DART"), shutil.which("dart")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    raise GateError("required Dart SDK unavailable")


def provision_dart(repo: Path, workspace: Path) -> tuple[str, dict[str, str], Path]:
    dart = find_dart()
    archive = workspace / "cryptography-2.9.0.tar.gz"
    data = download(DART_ARCHIVE_URL, archive)
    digest = hashlib.sha256(data).hexdigest()
    if digest != DART_ARCHIVE_SHA256:
        raise GateError("Dart cryptography archive digest mismatch")
    project = workspace / "dart-project"
    project.mkdir()
    (project / "pubspec.yaml").write_text(
        "name: styx_o14_runtime_probe\n"
        "environment:\n  sdk: '>=3.3.0 <4.0.0'\n"
        "dependencies:\n  cryptography: 2.9.0\n",
        encoding="utf-8",
    )
    shutil.copy2(repo / "tools/causal-flow-simulator/o14/dart_adapter.dart", project / "dart_adapter.dart")
    pub_cache = workspace / "pub-cache"
    env = dict(os.environ)
    env["PUB_CACHE"] = str(pub_cache)
    run([dart, "pub", "get", "--no-precompile"], cwd=project, env=env)
    hosted_hash = pub_cache / "hosted-hashes/pub.dev/cryptography-2.9.0.sha256"
    if hosted_hash.read_text(encoding="utf-8").strip() != DART_ARCHIVE_SHA256:
        raise GateError("Dart hosted-cache identity mismatch")
    identity = {
        "version": DART_CRYPTOGRAPHY_VERSION,
        "resolved": DART_ARCHIVE_URL,
        "sha256": DART_ARCHIVE_SHA256,
    }
    return dart, identity, project


def results_by_id(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    return {str(item["id"]): item for item in payload["results"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    repo = args.repo_root.resolve()
    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True)

    probe, probe_ok = build_probe_report()
    if not probe_ok:
        raise GateError("semantic probe failed")
    vectors = probe["runtime_vectors"]
    if len(vectors) != EXPECTED_RUNTIME_VECTOR_COUNT:
        raise GateError("runtime-vector inventory drift")
    vectors_path = workspace / "vectors.json"
    adapter_vectors = [adapter_vector(vector) for vector in vectors]
    vectors_path.write_bytes(CanonicalJsonReport.encode(adapter_vectors))

    node = shutil.which("node")
    if not node:
        raise GateError("required Node.js runtime unavailable")
    noble_entry, noble_identity = provision_noble(repo, workspace)
    node_payload = json.loads(
        run(
            [node, str(repo / "tools/causal-flow-simulator/o14/node_adapter.mjs"), str(vectors_path), str(noble_entry)],
            cwd=workspace,
        )
    )

    dart, dart_identity, dart_project = provision_dart(repo, workspace)
    dart_version = subprocess.run(
        [dart, "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    ).stdout.strip()
    dart_env = dict(os.environ)
    dart_env["PUB_CACHE"] = str(workspace / "pub-cache")
    dart_payload = json.loads(
        run([dart, "run", "dart_adapter.dart", str(vectors_path)], cwd=dart_project, env=dart_env)
    )

    node_results = results_by_id(node_payload)
    dart_results = results_by_id(dart_payload)
    comparisons = []
    compliant = {"noble_prime_order_guarded": True, "node_webcrypto_prime_order_guarded": True}
    raw_divergences: dict[str, list[str]] = {
        "noble_default_zip215": [],
        "noble_zip215_false": [],
        "node_webcrypto_raw": [],
        "dart_cryptography_raw": [],
    }
    for vector in vectors:
        identifier = vector["id"]
        expected = bool(vector["expected_selected"])
        node_item = node_results[identifier]
        dart_item = dart_results[identifier]
        noble_guarded = bool(node_item["noble_prime_order_guarded"]["result"])
        webcrypto_guarded = bool(node_item["node_webcrypto_prime_order_guarded"]["result"])
        compliant["noble_prime_order_guarded"] &= noble_guarded == expected
        compliant["node_webcrypto_prime_order_guarded"] &= webcrypto_guarded == expected
        for key in ("noble_default_zip215", "noble_zip215_false", "node_webcrypto_raw"):
            if bool(node_item[key]["result"]) != expected:
                raw_divergences[key].append(identifier)
        if bool(dart_item["dart_cryptography_raw"]["result"]) != expected:
            raw_divergences["dart_cryptography_raw"].append(identifier)
        comparisons.append(
            {
                "id": identifier,
                "expected_selected": expected,
                "noble_default_zip215": node_item["noble_default_zip215"],
                "noble_zip215_false": node_item["noble_zip215_false"],
                "noble_prime_order_guarded": node_item["noble_prime_order_guarded"],
                "node_webcrypto_raw": node_item["node_webcrypto_raw"],
                "node_webcrypto_prime_order_guarded": node_item["node_webcrypto_prime_order_guarded"],
                "dart_cryptography_raw": dart_item["dart_cryptography_raw"],
            }
        )

    compliant_adapters = sorted(name for name, value in compliant.items() if value)
    passed = bool(compliant_adapters) and "noble_prime_order_guarded" in compliant_adapters
    report = {
        "schema": SCHEMA,
        "suite_id": 1,
        "sources": {
            "noble": noble_identity,
            "dart_cryptography": dart_identity,
            "rfc8032": "https://www.rfc-editor.org/rfc/rfc8032.txt#section-5.1.7",
            "webcrypto": "https://www.w3.org/TR/2025/WD-webcrypto-2-20250422/#ed25519-operations-verify",
            "zip215": "https://zips.z.cash/zip-0215",
        },
        "runtimes": {
            "node": node_payload["runtime"],
            "dart": {"sdk": dart_version, "provider": "cryptography DartEd25519"},
        },
        "adapter_construction": {
            "noble_prime_order_guarded": {
                "guard": "Point.fromBytes(bytes,false) + isSmallOrder() + isTorsionFree() for A and R; S<CURVE.n",
                "verifier": "verifyAsync(signature,message,key,{zip215:false}) exactly once",
            },
            "node_webcrypto_prime_order_guarded": {
                "guard": "@noble/ed25519 Point.fromBytes(bytes,false) + isSmallOrder() + isTorsionFree() for A and R; S<CURVE.n",
                "verifier": "webcrypto.subtle.verify({name:'Ed25519'},key,signature,message) exactly once",
            },
        },
        "compliant_adapters": compliant_adapters,
        "raw_divergences": raw_divergences,
        "comparisons": comparisons,
        "runtime_vector_count": len(comparisons),
        "verdict": "PASS" if passed else "NO_GO",
    }
    CanonicalJsonReport.store(args.output, report)
    print(f"O-14 RUNTIME verdict={report['verdict']} compliant={','.join(compliant_adapters)}")
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GateError, OSError, subprocess.CalledProcessError, KeyError, ValueError) as error:
        print(f"O-14 runtime gate failed: {public_failure(error)}", file=sys.stderr)
        raise SystemExit(2)
