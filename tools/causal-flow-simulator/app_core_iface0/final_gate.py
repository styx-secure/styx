#!/usr/bin/env python3
"""Exact two-checkout Phase-A gate and provider-bound Phase-B entry gate."""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from canonical_json import CanonicalJsonError, dumps, loads
from generate_seed_registry import REQUEST_SET_MANIFEST_SHA256
from inventory import (
    BASE_SHA,
    InventoryError,
    derive_acv049_relation_members,
)


RATIFIED_CARRIER_AUTHORITY_V3_SHA256 = (
    "19133d9a7734d054832b706b03c885ce6dc82b17902a9e9196e404a2ef109918"
)
POSITIVE_INVENTORY_RATIFICATION_KIND = (
    "APP_CORE_POSITIVE_CARRIER_INVENTORY_RATIFICATION_V1"
)
POSITIVE_INVENTORY_AUTHORITY_CHANGE_KIND = (
    "APP_CORE_POSITIVE_CARRIER_INVENTORY_AUTHORITY_CHANGE_V1"
)
ISSUE_URL = "https://api.github.com/repos/styx-secure/styx/issues/295"
ISSUE_COMMENTS_URL = ISSUE_URL + "/comments?per_page=100&page=1"
COMBINED_BRANCH_REF = "refs/heads/task/295-c03-h12-h3-combined-remediation"
COMBINED_BRANCH_URL = (
    "https://api.github.com/repos/styx-secure/styx/git/ref/heads/"
    "task/295-c03-h12-h3-combined-remediation"
)
OPERATOR_ID = 141346846
OPERATOR_LOGIN = "maverde73"
SEMANTIC_FIXTURE_SOURCE_PATH = (
    "tools/causal-flow-simulator/app_core_iface0/generate_seed_registry.py"
)
SEMANTIC_FIXTURE_SOURCE_OCTETS = 18424
SEMANTIC_FIXTURE_SOURCE_SHA256 = (
    "323c5227972b79a33bc8238390e8e6000cd6a339a65375155ebea21010b4c8d4"
)
SEMANTIC_FIXTURE_IDENTIFIER = b"_semantic_request_carriers"
HISTORICAL_EVIDENCE_HEAD = "fb42037934618dacbb8d4aac65f68b01bc9e7bbb"
DYNAMIC_NAMESPACE_MUTATORS = frozenset(
    {
        "__delattr__",
        "__import__",
        "__setattr__",
        "compile",
        "delattr",
        "eval",
        "exec",
        "globals",
        "locals",
        "setattr",
        "vars",
    }
)
RUNTIME_FIXTURE_MODULE = "styx_app_core_frozen_generator"
BANNED_PROVIDER_ENVIRONMENT = frozenset(
    {
        "GH_HOST",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GITHUB_API_URL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    }
)
ACV049_CONTROLLED_ENVIRONMENT = {
    "LC_CTYPE": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
}
ACV049_MUTANT_CHANNEL = "STYX_ACV049_MUTANT_CHANNEL"
ACV049_MUTANT_CHANNELS = (
    "ACV049-CONTROL-CHANNEL-ALPHA",
    "ACV049-CONTROL-CHANNEL-BRAVO",
)
ACV049_RELATION_COUNTS = {
    "ACV-049-E": 77,
    "ACV-049-L": 401,
    "ACV-049-N": 5,
    "ACV-049-P": 300,
    "ACV-049-S": 101,
}


class FinalGateError(ValueError):
    """A freeze identity, checkout, package, or provider authority failed."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise FinalGateError("required Git query failed")
    return completed.stdout


def _git_bytes(repo: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if completed.returncode != 0:
        raise FinalGateError("required Git object query failed")
    return completed.stdout


def _frozen_semantic_fixture_slice(source: bytes) -> bytes:
    """Extract and verify the exact V17 function from a selection-HEAD blob."""

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as error:
        raise FinalGateError("semantic-fixture source is not valid Python") from error
    definitions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_semantic_request_carriers"
    ]
    definition_lines = [
        line
        for line in source.splitlines()
        if line.startswith(b"def _semantic_request_carriers(")
    ]
    if (
        len(definitions) != 1
        or len(definition_lines) != 1
        or definitions[0] not in tree.body
        or definitions[0].decorator_list
    ):
        raise FinalGateError("semantic-fixture definition count drift")
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    fixture_loads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "_semantic_request_carriers"
        and isinstance(node.ctx, ast.Load)
    ]
    if len(fixture_loads) != 2 or any(
        not isinstance(parents.get(node), ast.Call)
        or parents[node].func is not node
        for node in fixture_loads
    ):
        raise FinalGateError("semantic-fixture call-site drift")
    forbidden_bindings = [
        node
        for node in ast.walk(tree)
        if (
            isinstance(node, ast.Name)
            and node.id == "_semantic_request_carriers"
            and isinstance(node.ctx, (ast.Store, ast.Del))
        )
        or (
            isinstance(node, (ast.Global, ast.Nonlocal))
            and "_semantic_request_carriers" in node.names
        )
        or (
            isinstance(node, ast.alias)
            and (
                node.asname == "_semantic_request_carriers"
                or (
                    node.asname is None
                    and node.name.rsplit(".", 1)[-1]
                    == "_semantic_request_carriers"
                )
            )
        )
        or (
            isinstance(node, ast.ClassDef)
            and node.name == "_semantic_request_carriers"
        )
        or (
            isinstance(node, ast.Attribute)
            and node.attr == "_semantic_request_carriers"
            and isinstance(node.ctx, (ast.Store, ast.Del))
        )
        or (
            isinstance(node, ast.Attribute)
            and node.attr == "__dict__"
        )
        or (
            isinstance(node, ast.Call)
            and (
                (
                    isinstance(node.func, ast.Name)
                    and node.func.id in DYNAMIC_NAMESPACE_MUTATORS
                )
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in DYNAMIC_NAMESPACE_MUTATORS
                )
            )
        )
        or (
            isinstance(node, ast.alias)
            and node.name.rsplit(".", 1)[-1] in DYNAMIC_NAMESPACE_MUTATORS
        )
        or (
            isinstance(node, ast.ImportFrom)
            and any(alias.name == "*" for alias in node.names)
        )
        or (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "modules"
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "sys"
        )
    ]
    if forbidden_bindings:
        raise FinalGateError("semantic-fixture identifier is rebound")
    node = definitions[0]
    if node.end_lineno is None:
        raise FinalGateError("semantic-fixture definition has no exact end")
    lines = source.splitlines(keepends=True)
    result = b"".join(lines[node.lineno - 1 : node.end_lineno])
    if (
        len(result) != SEMANTIC_FIXTURE_SOURCE_OCTETS
        or _sha256(result) != SEMANTIC_FIXTURE_SOURCE_SHA256
        or not result.endswith(b"\n")
    ):
        raise FinalGateError("ratified semantic-fixture source slice drift")
    if source.count(result) != 1:
        raise FinalGateError("semantic-fixture source occurrence drift")
    if source.count(SEMANTIC_FIXTURE_IDENTIFIER) != 3:
        raise FinalGateError("semantic-fixture identifier occurrence drift")
    offset = 0
    while True:
        offset = source.find(SEMANTIC_FIXTURE_IDENTIFIER, offset)
        if offset < 0:
            break
        following = offset + len(SEMANTIC_FIXTURE_IDENTIFIER)
        if source[following : following + 1] != b"(":
            raise FinalGateError("semantic-fixture identifier is rebound")
        offset = following
    return result


def _verify_runtime_semantic_fixture(
    repo: Path,
    selected_source: bytes,
) -> tuple[str, str, str]:
    """Prove the imported callable is the exact frozen top-level function."""

    source_path = repo.resolve() / SEMANTIC_FIXTURE_SOURCE_PATH
    if (
        not source_path.is_file()
        or source_path.is_symlink()
        or source_path.read_bytes() != selected_source
    ):
        raise FinalGateError("working semantic-fixture source differs from Git object")
    expected_source = _frozen_semantic_fixture_slice(selected_source)
    parsed = ast.parse(selected_source)
    definition = next(
        node
        for node in parsed.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_semantic_request_carriers"
    )
    inspector = r'''
import base64
import hashlib
import importlib.util
import inspect
import json
import pathlib
import sys
import types

sys.dont_write_bytecode = True
source_path = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(source_path.parent))
module_name = sys.argv[2]
spec = importlib.util.spec_from_file_location(module_name, source_path)
if spec is None or spec.loader is None:
    raise SystemExit("module specification unavailable")
module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
spec.loader.exec_module(module)
function = getattr(module, "_semantic_request_carriers", None)
if not inspect.isfunction(function):
    raise SystemExit("semantic fixture is not a function")

def normalize(value):
    if value is None:
        return ["none"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        return ["int", str(value)]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, bytes):
        return ["bytes", base64.b64encode(value).decode("ascii")]
    if isinstance(value, tuple):
        return ["tuple", [normalize(item) for item in value]]
    if isinstance(value, list):
        return ["list", [normalize(item) for item in value]]
    if isinstance(value, dict):
        rows = [[normalize(key), normalize(item)] for key, item in value.items()]
        rows.sort(key=lambda row: json.dumps(row[0], separators=(",", ":")))
        return ["dict", rows]
    if isinstance(value, types.CodeType):
        return [
            "code",
            {
                "argcount": value.co_argcount,
                "cellvars": list(value.co_cellvars),
                "code": base64.b64encode(value.co_code).decode("ascii"),
                "consts": [normalize(item) for item in value.co_consts],
                "flags": value.co_flags,
                "freevars": list(value.co_freevars),
                "kwonlyargcount": value.co_kwonlyargcount,
                "names": list(value.co_names),
                "posonlyargcount": value.co_posonlyargcount,
                "varnames": list(value.co_varnames),
            },
        ]
    raise TypeError(type(value).__name__)

from interface_model import ContractAuthority

authority = ContractAuthority.load(
    source_path.parents[3],
    source_path.parent / "contract",
)
fixture_rows = []
for case in function(authority):
    oracle = case.collision_oracle
    fixture_rows.append(
        [
            module.dumps(case.request).decode("utf-8"),
            None
            if oracle is None
            else [
                oracle.family,
                normalize(oracle.alternate_input),
                base64.b64encode(oracle.forced_digest).decode("ascii"),
            ],
        ]
    )
fixture_bytes = json.dumps(
    fixture_rows,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
code_bytes = json.dumps(
    normalize(function.__code__),
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
defaults_bytes = json.dumps(
    normalize([function.__defaults__, function.__kwdefaults__]),
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
payload = {
    "codeFilename": str(pathlib.Path(function.__code__.co_filename).resolve()),
    "codeSha256": hashlib.sha256(code_bytes).hexdigest(),
    "defaultsSha256": hashlib.sha256(defaults_bytes).hexdigest(),
    "firstLine": function.__code__.co_firstlineno,
    "fixtureSha256": hashlib.sha256(fixture_bytes).hexdigest(),
    "globalsOwned": function.__globals__ is module.__dict__,
    "hasWrapped": hasattr(function, "__wrapped__"),
    "module": function.__module__,
    "name": function.__name__,
    "qualname": function.__qualname__,
    "sourceBase64": base64.b64encode(
        inspect.getsource(function).encode("utf-8")
    ).decode("ascii"),
}
sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
'''
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            inspector,
            str(source_path),
            RUNTIME_FIXTURE_MODULE,
        ],
        cwd=repo.resolve(),
        env={"PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if completed.returncode != 0:
        raise FinalGateError("runtime semantic-fixture import failed")
    try:
        observed = json.loads(completed.stdout)
        runtime_source = base64.b64decode(
            observed.get("sourceBase64", ""), validate=True
        )
    except (json.JSONDecodeError, AttributeError, TypeError, ValueError) as error:
        raise FinalGateError("runtime semantic-fixture attestation is malformed") from error
    required = {
        "codeFilename": str(source_path),
        "codeSha256": observed.get("codeSha256"),
        "defaultsSha256": observed.get("defaultsSha256"),
        "firstLine": definition.lineno,
        "fixtureSha256": observed.get("fixtureSha256"),
        "globalsOwned": True,
        "hasWrapped": False,
        "module": RUNTIME_FIXTURE_MODULE,
        "name": "_semantic_request_carriers",
        "qualname": "_semantic_request_carriers",
        "sourceBase64": base64.b64encode(expected_source).decode("ascii"),
    }
    if (
        not isinstance(observed, dict)
        or set(observed) != set(required)
        or any(observed.get(key) != value for key, value in required.items())
        or runtime_source != expected_source
        or any(
            not isinstance(observed.get(key), str)
            or len(observed[key]) != 64
            or any(ch not in "0123456789abcdef" for ch in observed[key])
            for key in ("codeSha256", "defaultsSha256", "fixtureSha256")
        )
        or source_path.read_bytes() != selected_source
    ):
        raise FinalGateError("runtime semantic-fixture identity drift")
    return (
        observed["fixtureSha256"],
        observed["codeSha256"],
        observed["defaultsSha256"],
    )


def _historical_carrier_bytes(
    repo: Path,
    historical_source: bytes,
    selected_attestation: tuple[str, str, str],
    selection_head: str,
) -> dict[str, bytes]:
    """Generate the immutable historical carrier baseline once."""

    _verify_clean_checkout(repo, selection_head)
    with tempfile.TemporaryDirectory(
        prefix="styx-app-core-historical-fixture-"
    ) as temporary:
        historical_repo = Path(temporary) / "checkout"
        completed = subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--shared",
                "--no-checkout",
                str(repo.resolve()),
                str(historical_repo),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
        if completed.returncode != 0:
            raise FinalGateError("historical semantic-fixture clone failed")
        _git(historical_repo, "checkout", "--quiet", "--detach", HISTORICAL_EVIDENCE_HEAD)
        _verify_clean_checkout(historical_repo, HISTORICAL_EVIDENCE_HEAD)
        historical_path = historical_repo / SEMANTIC_FIXTURE_SOURCE_PATH
        if historical_path.read_bytes() != historical_source:
            raise FinalGateError("historical checkout source differs from Git object")
        historical_attestation = _verify_runtime_semantic_fixture(
            historical_repo,
            historical_source,
        )
        if historical_attestation != selected_attestation:
            raise FinalGateError("historical and selected fixture semantics differ")
        historical_evidence = Path(temporary) / "historical-evidence"
        _generate_phase_a_from_checkout(historical_repo, historical_evidence)
        historical_carriers = _tree(historical_evidence / "carriers")
    _verify_clean_checkout(repo, selection_head)
    return historical_carriers


def _carrier_subtree(evidence_tree: dict[str, bytes]) -> dict[str, bytes]:
    """Extract carrier files from the exact evidence tree under review."""

    prefix = "carriers/"
    return {
        name[len(prefix) :]: payload
        for name, payload in evidence_tree.items()
        if name.startswith(prefix)
    }


def _verify_exact_carrier_bytes(
    historical_carriers: dict[str, bytes],
    selected_carriers: dict[str, bytes],
) -> None:
    """Require the exact 77-request/19-response carrier relation."""

    request_count = sum(
        name.startswith("PCR-REQUEST-") for name in selected_carriers
    )
    response_count = sum(
        name.startswith("PCR-RESPONSE-") for name in selected_carriers
    )
    if (
        len(historical_carriers) != 96
        or len(selected_carriers) != 96
        or (request_count, response_count) != (77, 19)
        or historical_carriers != selected_carriers
    ):
        raise FinalGateError("historical and selected carrier bytes differ")


def _verify_actual_carriers_against_historical(
    repo: Path,
    sources: tuple[bytes, bytes],
    selection_head: str,
    actual_evidence_tree: dict[str, bytes],
) -> None:
    """Compare the real gate input with the immutable historical baseline."""

    historical_source, selected_source = sources
    selected_attestation = _verify_runtime_semantic_fixture(repo, selected_source)
    historical_carriers = _historical_carrier_bytes(
        repo,
        historical_source,
        selected_attestation,
        selection_head,
    )
    _verify_exact_carrier_bytes(
        historical_carriers,
        _carrier_subtree(actual_evidence_tree),
    )


def _local_source_blobs(repo: Path, selection_head: str) -> tuple[bytes, bytes]:
    historical = _git_bytes(
        repo,
        "show",
        f"{HISTORICAL_EVIDENCE_HEAD}:{SEMANTIC_FIXTURE_SOURCE_PATH}",
    )
    selected = _git_bytes(
        repo,
        "show",
        f"{selection_head}:{SEMANTIC_FIXTURE_SOURCE_PATH}",
    )
    if _frozen_semantic_fixture_slice(historical) != _frozen_semantic_fixture_slice(
        selected
    ):
        raise FinalGateError("historical and selected semantic-fixture slices differ")
    return historical, selected


def _verify_clean_checkout(repo: Path, selection_head: str) -> None:
    root = repo.resolve()
    if not root.is_dir() or root.is_symlink():
        raise FinalGateError("checkout root is invalid")
    if _git(root, "rev-parse", "HEAD").strip() != selection_head:
        raise FinalGateError("checkout HEAD does not equal selectionHead")
    _git(root, "merge-base", "--is-ancestor", BASE_SHA, selection_head)
    status = _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    )
    if status:
        raise FinalGateError("checkout is not clean, including ignored files")


def _tree(root: Path) -> dict[str, bytes]:
    if not root.is_dir() or root.is_symlink():
        raise FinalGateError("evidence root is invalid")
    result: dict[str, bytes] = {}
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            if path.is_dir() and not path.is_symlink():
                continue
            raise FinalGateError("evidence tree contains a non-regular entry")
        relative = path.relative_to(root).as_posix()
        result[relative] = path.read_bytes()
    return result


def _run_checkout_tool(
    repo: Path,
    relative_tool: str,
    arguments: list[str],
    *,
    environment: dict[str, str] | None = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess[bytes]:
    tool = repo.resolve() / relative_tool
    if not tool.is_file() or tool.is_symlink():
        raise FinalGateError("checkout evidence tool is absent or non-regular")
    process_environment = (
        dict(os.environ)
        if environment is None
        else dict(environment)
    )
    process_environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, str(tool), *arguments],
        cwd=repo.resolve(),
        env=process_environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise FinalGateError("checkout-owned evidence tool failed")
    return completed


def _controlled_acv049_environment(channel: str) -> dict[str, str]:
    try:
        encoded = channel.encode("ascii")
    except UnicodeEncodeError as error:
        raise FinalGateError("ACV-049 mutant channel is not canonical ASCII") from error
    if not encoded or b"\x00" in encoded or channel.strip() != channel:
        raise FinalGateError("ACV-049 mutant channel is not canonical ASCII")
    return {
        **ACV049_CONTROLLED_ENVIRONMENT,
        ACV049_MUTANT_CHANNEL: channel,
    }


def _verify_acv049_checkout_pair(
    repo_one: Path, repo_two: Path, candidate_head: str
) -> tuple[Path, Path]:
    if (
        len(candidate_head) != 40
        or any(ch not in "0123456789abcdef" for ch in candidate_head)
    ):
        raise FinalGateError("candidate HEAD is not a full lowercase Git identity")
    first_absolute = Path(os.path.abspath(repo_one))
    second_absolute = Path(os.path.abspath(repo_two))
    first = repo_one.resolve()
    second = repo_two.resolve()
    if first_absolute != first or second_absolute != second:
        raise FinalGateError("the ACV-049 checkout roots contain a symlink")
    if first == second:
        raise FinalGateError("the two checkout roots are not distinct")
    _verify_clean_checkout(first, candidate_head)
    _verify_clean_checkout(second, candidate_head)
    first_git = Path(
        _git(first, "rev-parse", "--absolute-git-dir").strip()
    ).resolve()
    second_git = Path(
        _git(second, "rev-parse", "--absolute-git-dir").strip()
    ).resolve()
    if first_git == second_git:
        raise FinalGateError("the two checkout Git metadata roots are not distinct")
    return first, second


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _validate_acv049_e_report(
    report: object, expected_sources: set[str]
) -> list[dict[str, Any]]:
    if not isinstance(report, dict):
        raise FinalGateError("ACV-049 semantic report is not an object")
    required = {
        "instance_count": 884,
        "pending_relation_counts": {"ACV-049-E": 77, "ACV-049-P": 300},
        "relation_counts": ACV049_RELATION_COUNTS,
        "schema": "styx.app-core-iface0.semantic-acv049-partial-execution.v3",
        "semantic_rule_id": "ACV-049",
        "status": "REMEDIATION_PARTIAL_EXECUTION",
        "verdict": "PARTIAL_EXECUTION_PASS",
    }
    if any(report.get(key) != value for key, value in required.items()):
        raise FinalGateError("ACV-049 semantic report identity drift")
    rows = report.get("rows")
    if not isinstance(rows, list) or len(rows) != 884:
        raise FinalGateError("ACV-049 semantic report row count drift")
    observed_counts = {
        relation_id: sum(
            isinstance(row, dict) and row.get("relationId") == relation_id
            for row in rows
        )
        for relation_id in ACV049_RELATION_COUNTS
    }
    if observed_counts != ACV049_RELATION_COUNTS:
        raise FinalGateError("ACV-049 semantic report relation count drift")
    e_rows = [
        row
        for row in rows
        if isinstance(row, dict) and row.get("relationId") == "ACV-049-E"
    ]
    e_fields = {
        "assertionId",
        "detectorId",
        "evidenceDisposition",
        "executionPhase",
        "faultContext",
        "instanceId",
        "observationId",
        "relationId",
        "requestOctets",
        "requestSha256",
        "responseCarrierCaseIds",
        "responseOctets",
        "responseSha256",
        "sourceIdentity",
    }
    if {row.get("sourceIdentity") for row in e_rows} != expected_sources:
        raise FinalGateError("ACV-049 E source relation drift")
    for row in e_rows:
        response_carriers = row.get("responseCarrierCaseIds")
        if (
            set(row) != e_fields
            or row.get("executionPhase") != "BLIND_INPUT_EXECUTION"
            or row.get("evidenceDisposition")
            != "LOCAL_BLIND_EXECUTION_PASS_TWO_ENVIRONMENT_PENDING"
            or row.get("faultContext")
            not in {"NONE", "FIXED_INTERNAL_COLLISION_ORACLE"}
            or not isinstance(row.get("requestOctets"), int)
            or row["requestOctets"] <= 0
            or not isinstance(row.get("responseOctets"), int)
            or row["responseOctets"] <= 0
            or not isinstance(row.get("requestSha256"), str)
            or len(row["requestSha256"]) != 64
            or any(ch not in "0123456789abcdef" for ch in row["requestSha256"])
            or not isinstance(row.get("responseSha256"), str)
            or len(row["responseSha256"]) != 64
            or any(ch not in "0123456789abcdef" for ch in row["responseSha256"])
            or not isinstance(response_carriers, list)
            or not response_carriers
            or any(
                not isinstance(value, str)
                or not value.startswith("PCR-RESPONSE-")
                for value in response_carriers
            )
        ):
            raise FinalGateError("ACV-049 E execution row drift")
    return e_rows


def run_acv049_e_baseline_gate(
    repo_one: Path,
    repo_two: Path,
    evidence_one: Path,
    evidence_two: Path,
    candidate_head: str,
    *,
    node: Path,
) -> dict[str, object]:
    """Prove E baseline equality; provenance monitors remain a separate gate."""

    first, second = _verify_acv049_checkout_pair(
        repo_one, repo_two, candidate_head
    )
    resolved_node = node.resolve()
    if not node.is_absolute() or not resolved_node.is_file():
        raise FinalGateError("ACV-049 Node runtime must be an absolute regular file")
    first_evidence_absolute = Path(os.path.abspath(evidence_one))
    second_evidence_absolute = Path(os.path.abspath(evidence_two))
    first_evidence = evidence_one.resolve()
    second_evidence = evidence_two.resolve()
    if (
        first_evidence_absolute != first_evidence
        or second_evidence_absolute != second_evidence
    ):
        raise FinalGateError("the ACV-049 evidence roots contain a symlink")
    first_git = Path(
        _git(first, "rev-parse", "--absolute-git-dir").strip()
    ).resolve()
    second_git = Path(
        _git(second, "rev-parse", "--absolute-git-dir").strip()
    ).resolve()
    if _paths_overlap(first_evidence, second_evidence):
        raise FinalGateError("the two ACV-049 evidence roots overlap")
    if any(
        _paths_overlap(evidence, protected)
        for evidence in (first_evidence, second_evidence)
        for protected in (first, second, first_git, second_git)
    ):
        raise FinalGateError("ACV-049 evidence overlaps checkout or Git metadata")
    first_validation = _validate_external_root(first, first_evidence)
    second_validation = _validate_external_root(second, second_evidence)
    if first_validation != second_validation:
        raise FinalGateError("the two Phase-A evidence roots disagree")
    if _tree(first_evidence) != _tree(second_evidence):
        raise FinalGateError("the two Phase-A evidence trees are not byte-identical")

    channels = ACV049_MUTANT_CHANNELS
    if channels[0] == channels[1]:
        raise FinalGateError("the two ACV-049 mutant channels are equal")
    environments = tuple(_controlled_acv049_environment(value) for value in channels)
    if (
        set(environments[0]) != set(environments[1])
        or any(
            environments[0][name] != environments[1][name]
            for name in environments[0]
            if name != ACV049_MUTANT_CHANNEL
        )
    ):
        raise FinalGateError("the controlled ACV-049 environments drift")

    contract_one = first / "tools/causal-flow-simulator/app_core_iface0/contract"
    contract_two = second / "tools/causal-flow-simulator/app_core_iface0/contract"
    expected_sources = set(
        derive_acv049_relation_members(contract_one)["ACV-049-E"]
    )
    with tempfile.TemporaryDirectory(prefix="styx-app-core-acv049-e-") as temporary:
        temporary_root = Path(temporary).resolve()
        if any(
            _paths_overlap(temporary_root, protected)
            for protected in (
                first,
                second,
                first_git,
                second_git,
                first_evidence,
                second_evidence,
            )
        ):
            raise FinalGateError("ACV-049 gate temporary root overlaps protected input")
        output_one = temporary_root / "environment-one" / "semantic-acv049.json"
        output_two = temporary_root / "environment-two" / "semantic-acv049.json"
        output_one.parent.mkdir()
        output_two.parent.mkdir()
        for repo, evidence, contract, output, environment in (
            (first, first_evidence, contract_one, output_one, environments[0]),
            (second, second_evidence, contract_two, output_two, environments[1]),
        ):
            _run_checkout_tool(
                repo,
                "tools/causal-flow-simulator/app_core_iface0/run_semantic_acv049.py",
                [
                    "--repo-root",
                    str(repo),
                    "--contract",
                    str(contract),
                    "--evidence-root",
                    str(evidence),
                    "--node",
                    str(resolved_node),
                    "--output",
                    str(output),
                ],
                environment=environment,
                timeout=600,
            )
        first_bytes = output_one.read_bytes()
        second_bytes = output_two.read_bytes()
        try:
            first_report = loads(first_bytes)
            second_report = loads(second_bytes)
        except (CanonicalJsonError, OSError) as error:
            raise FinalGateError("ACV-049 semantic report is invalid") from error
        first_e_rows = _validate_acv049_e_report(first_report, expected_sources)
        second_e_rows = _validate_acv049_e_report(second_report, expected_sources)
        if first_bytes != second_bytes or first_e_rows != second_e_rows:
            raise FinalGateError("ACV-049 E responses differ across environments")

    _verify_clean_checkout(first, candidate_head)
    _verify_clean_checkout(second, candidate_head)
    return {
        "channelSha256": [_sha256(value.encode("ascii")) for value in channels],
        "eRelationCount": 77,
        "provenanceControls": "PENDING",
        "semanticReportSha256": _sha256(first_bytes),
        "verdict": "TWO_ENVIRONMENT_BASELINE_IDENTITY_PASS",
    }


def _generate_phase_a_from_checkout(repo: Path, root: Path) -> None:
    contract = repo.resolve() / "tools/causal-flow-simulator/app_core_iface0/contract"
    _run_checkout_tool(
        repo,
        "tools/causal-flow-simulator/app_core_iface0/generate_seed_registry.py",
        [
            "--repo-root",
            str(repo.resolve()),
            "--contract",
            str(contract),
            "--generate-phase-a",
            "--evidence-root",
            str(root.resolve()),
        ],
    )


def _validate_external_root(repo: Path, root: Path) -> dict[str, object]:
    resolved_repo = repo.resolve()
    resolved = root.resolve()
    git_dir = Path(_git(resolved_repo, "rev-parse", "--absolute-git-dir").strip()).resolve()
    if (
        resolved == resolved_repo
        or resolved_repo in resolved.parents
        or resolved in resolved_repo.parents
        or resolved == git_dir
        or git_dir in resolved.parents
        or resolved in git_dir.parents
    ):
        raise FinalGateError("evidence root overlaps checkout or Git metadata")
    with tempfile.TemporaryDirectory(prefix="styx-app-core-validation-") as temporary:
        report_path = Path(temporary) / "report.json"
        contract = resolved_repo / "tools/causal-flow-simulator/app_core_iface0/contract"
        _run_checkout_tool(
            resolved_repo,
            "tools/causal-flow-simulator/app_core_iface0/validate_inventory.py",
            [
                "--repo-root",
                str(resolved_repo),
                "--contract",
                str(contract),
                "--phase-a-evidence-root",
                str(resolved),
                "--output",
                str(report_path),
            ],
        )
        try:
            report = loads(report_path.read_bytes())
        except (CanonicalJsonError, OSError) as error:
            raise FinalGateError("checkout validator report is invalid") from error
    required = {
        "case_count": 96,
        "schema": "styx.app-core-iface0.phase-a-validation.v1",
        "verdict": "PASS",
    }
    if (
        not isinstance(report, dict)
        or any(report.get(key) != value for key, value in required.items())
        or not isinstance(report.get("inventory_sha256"), str)
        or not isinstance(report.get("package_report_sha256"), str)
        or report.get("request_set_manifest_sha256")
        != REQUEST_SET_MANIFEST_SHA256
    ):
        raise FinalGateError("checkout validator report shape drift")
    return report


def run_phase_a_gate(
    repo_one: Path,
    repo_two: Path,
    evidence_one: Path,
    evidence_two: Path,
    selection_head: str,
) -> dict[str, object]:
    if len(selection_head) != 40 or any(ch not in "0123456789abcdef" for ch in selection_head):
        raise FinalGateError("selectionHead is not a full lowercase Git identity")
    first = repo_one.resolve()
    second = repo_two.resolve()
    if first == second:
        raise FinalGateError("the two checkout roots are not distinct")
    _verify_clean_checkout(first, selection_head)
    _verify_clean_checkout(second, selection_head)
    selected_one = _local_source_blobs(first, selection_head)
    selected_two = _local_source_blobs(second, selection_head)
    if selected_one != selected_two:
        raise FinalGateError("the two checkouts disagree on semantic-fixture source bytes")
    _verify_provider_source_slice(selection_head, selected_one)
    first_result = _validate_external_root(first, evidence_one)
    second_result = _validate_external_root(second, evidence_two)
    first_tree = _tree(evidence_one.resolve())
    second_tree = _tree(evidence_two.resolve())
    if first_tree != second_tree or first_result != second_result:
        raise FinalGateError("the two Phase-A evidence sets are not byte-identical")
    _verify_actual_carriers_against_historical(
        first,
        selected_one,
        selection_head,
        first_tree,
    )

    with tempfile.TemporaryDirectory(prefix="styx-app-core-phase-a-") as temporary:
        temporary_root = Path(temporary)
        regenerated_one = temporary_root / "checkout-one"
        regenerated_two = temporary_root / "checkout-two"
        _generate_phase_a_from_checkout(first, regenerated_one)
        _generate_phase_a_from_checkout(second, regenerated_two)
        if _tree(regenerated_one) != first_tree or _tree(regenerated_two) != first_tree:
            raise FinalGateError("independent final-gate regeneration differs")

    _verify_clean_checkout(first, selection_head)
    _verify_clean_checkout(second, selection_head)
    return {
        "verdict": "PASS",
        "caseCount": 96,
        "positiveCarrierInventorySha256": first_result["inventory_sha256"],
        "phaseAPackageReportSha256": first_result["package_report_sha256"],
        "requestSetManifestSha256": first_result[
            "request_set_manifest_sha256"
        ],
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise FinalGateError("provider redirect is forbidden")


def _fetch_json(url: str) -> tuple[Any, bytes, dict[str, str]]:
    if any(name in os.environ for name in BANNED_PROVIDER_ENVIRONMENT):
        raise FinalGateError("credential or provider override environment is present")
    tls_context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=tls_context),
        _NoRedirect,
    )
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "styx-app-core-final-gate-v1"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=30) as response:
            if response.status != 200 or response.geturl() != url:
                raise FinalGateError("provider response identity drift")
            raw = response.read()
            headers = {key.lower(): value for key, value in response.headers.items()}
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise FinalGateError("anonymous provider fetch failed") from error
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise FinalGateError("provider returned malformed JSON") from error
    return value, raw, headers


def _provider_source_blob(commit: str) -> bytes:
    url = (
        "https://api.github.com/repos/styx-secure/styx/contents/"
        f"{SEMANTIC_FIXTURE_SOURCE_PATH}?ref={commit}"
    )
    value, _raw, _headers = _fetch_json(url)
    if (
        not isinstance(value, dict)
        or value.get("type") != "file"
        or value.get("path") != SEMANTIC_FIXTURE_SOURCE_PATH
        or value.get("encoding") != "base64"
        or not isinstance(value.get("content"), str)
    ):
        raise FinalGateError("provider source object shape drift")
    encoded = "".join(value["content"].split())
    try:
        return base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise FinalGateError("provider source object is not strict base64") from error


def _verify_provider_source_slice(
    selection_head: str,
    local_sources: tuple[bytes, bytes],
) -> None:
    local_historical, local_selected = local_sources
    provider_historical = _provider_source_blob(HISTORICAL_EVIDENCE_HEAD)
    provider_selected = _provider_source_blob(selection_head)
    if (
        provider_historical != local_historical
        or provider_selected != local_selected
    ):
        raise FinalGateError("provider and local source blobs differ")
    if _frozen_semantic_fixture_slice(provider_historical) != (
        _frozen_semantic_fixture_slice(provider_selected)
    ):
        raise FinalGateError("provider historical and selected fixture slices differ")


def _next_link(headers: dict[str, str]) -> str | None:
    link = headers.get("link", "")
    for item in link.split(","):
        fields = item.strip().split(";")
        if len(fields) == 2 and fields[1].strip() == 'rel="next"':
            return fields[0].strip().removeprefix("<").removesuffix(">")
    return None


def _operator(row: dict[str, Any]) -> bool:
    user = row.get("user")
    return (
        isinstance(user, dict)
        and user.get("id") == OPERATOR_ID
        and user.get("login") == OPERATOR_LOGIN
    )


def _fetch_issue_comments() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    page_url: str | None = ISSUE_COMMENTS_URL
    seen_pages: set[str] = set()
    seen_ids: set[int] = set()
    previous_id = -1
    while page_url is not None:
        if page_url in seen_pages or not page_url.startswith(ISSUE_URL + "/comments?"):
            raise FinalGateError("provider pagination drift")
        seen_pages.add(page_url)
        page, _page_raw, page_headers = _fetch_json(page_url)
        if not isinstance(page, list):
            raise FinalGateError("provider comment page is malformed")
        for row in page:
            if not isinstance(row, dict) or not isinstance(row.get("id"), int):
                raise FinalGateError("provider comment row is malformed")
            row_id = row["id"]
            if row_id in seen_ids or row_id <= previous_id:
                raise FinalGateError("provider comment order or identity drift")
            seen_ids.add(row_id)
            previous_id = row_id
            result.append(row)
        page_url = _next_link(page_headers)
    return result


def _json_object(body: str) -> dict[str, Any] | None:
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _validate_ratification_target(
    target_id: str,
    target_body_sha256: str,
    selection_head: str,
) -> dict[str, Any]:
    if not target_id or not target_id.isdecimal():
        raise FinalGateError("authority change target comment ID is invalid")
    target_url = (
        "https://api.github.com/repos/styx-secure/styx/issues/comments/"
        + target_id
    )
    target, _target_raw, _headers = _fetch_json(target_url)
    if (
        not isinstance(target, dict)
        or target.get("id") != int(target_id)
        or target.get("url") != target_url
        or target.get("issue_url") != ISSUE_URL
        or not _operator(target)
        or target.get("created_at") != target.get("updated_at")
        or target.get("performed_via_github_app") is not None
        or not isinstance(target.get("body"), str)
    ):
        raise FinalGateError("authority change target provenance drift")
    target_body = target["body"].encode("utf-8")
    if _sha256(target_body) != target_body_sha256:
        raise FinalGateError("authority change target body digest drift")
    try:
        target_decision = loads(target_body)
    except CanonicalJsonError as error:
        raise FinalGateError("authority change target is not canonical") from error
    required = {
        "decision",
        "kind",
        "repository",
        "issue",
        "baseSha",
        "selectionHead",
        "closureAmendmentSha256",
        "candidateManifestSha256",
        "positiveCarrierInventorySha256",
        "phaseAPackageReportSha256",
        "caseCount",
        "requestCaseCount",
        "responseCaseCount",
    }
    if (
        not isinstance(target_decision, dict)
        or set(target_decision) != required
        or dumps(target_decision) != target_body
        or target_decision.get("decision") != "RATIFY"
        or target_decision.get("kind") != POSITIVE_INVENTORY_RATIFICATION_KIND
        or target_decision.get("repository") != "styx-secure/styx"
        or target_decision.get("issue") != 295
        or target_decision.get("baseSha") != BASE_SHA
        or target_decision.get("closureAmendmentSha256")
        != RATIFIED_CARRIER_AUTHORITY_V3_SHA256
        or target_decision.get("selectionHead") != selection_head
        or (
            target_decision.get("caseCount"),
            target_decision.get("requestCaseCount"),
            target_decision.get("responseCaseCount"),
        )
        != (96, 77, 19)
        or any(
            not isinstance(target_decision.get(name), str)
            or len(target_decision[name]) != 64
            or any(ch not in "0123456789abcdef" for ch in target_decision[name])
            for name in (
                "candidateManifestSha256",
                "positiveCarrierInventorySha256",
                "phaseAPackageReportSha256",
            )
        )
    ):
        raise FinalGateError("authority change target decision drift")
    return target


def _validate_authority_change(
    row: dict[str, Any],
    selected_comment: dict[str, Any],
) -> tuple[int, bytes, str]:
    row_id = row.get("id")
    selected_id = selected_comment.get("id")
    body = row.get("body")
    if (
        not isinstance(row_id, int)
        or not isinstance(selected_id, int)
        or not isinstance(body, str)
        or row_id <= selected_id
        or not isinstance(row.get("created_at"), str)
        or not isinstance(selected_comment.get("created_at"), str)
        or row["created_at"] <= selected_comment["created_at"]
    ):
        raise FinalGateError("authority change ordering drift")
    url = f"https://api.github.com/repos/styx-secure/styx/issues/comments/{row_id}"
    fetched, fetched_raw, _headers = _fetch_json(url)
    if fetched != row:
        raise FinalGateError("authority change collection/object drift")
    if (
        fetched.get("url") != url
        or fetched.get("issue_url") != ISSUE_URL
        or not _operator(fetched)
        or fetched.get("created_at") != fetched.get("updated_at")
        or fetched.get("performed_via_github_app") is not None
    ):
        raise FinalGateError("authority change provenance drift")
    body_bytes = body.encode("utf-8")
    try:
        change = loads(body_bytes)
    except CanonicalJsonError as error:
        raise FinalGateError("authority change is not canonical JSON") from error
    required = {
        "decision",
        "issue",
        "kind",
        "replacementCommentId",
        "repository",
        "selectionHead",
        "targetCommentBodySha256",
        "targetCommentId",
    }
    if not isinstance(change, dict) or set(change) != required or dumps(change) != body_bytes:
        raise FinalGateError("authority change body shape or final LF drift")
    decision = change["decision"]
    replacement_id = change["replacementCommentId"]
    if (
        decision not in {"WITHDRAW", "SUPERSEDE"}
        or change["kind"] != POSITIVE_INVENTORY_AUTHORITY_CHANGE_KIND
        or change["repository"] != "styx-secure/styx"
        or change["issue"] != 295
        or not isinstance(change["selectionHead"], str)
        or len(change["selectionHead"]) != 40
        or any(ch not in "0123456789abcdef" for ch in change["selectionHead"])
        or not isinstance(change["targetCommentBodySha256"], str)
        or len(change["targetCommentBodySha256"]) != 64
        or any(ch not in "0123456789abcdef" for ch in change["targetCommentBodySha256"])
        or not isinstance(change["targetCommentId"], str)
        or not change["targetCommentId"].isdecimal()
        or (decision == "WITHDRAW" and replacement_id is not None)
        or (
            decision == "SUPERSEDE"
            and (
                not isinstance(replacement_id, str)
                or not replacement_id
                or not replacement_id.isdecimal()
            )
        )
    ):
        raise FinalGateError("authority change value drift")
    target = _validate_ratification_target(
        change["targetCommentId"],
        change["targetCommentBodySha256"],
        change["selectionHead"],
    )
    if row_id <= target["id"] or row["created_at"] <= target["created_at"]:
        raise FinalGateError("authority change does not follow its target")
    return row_id, fetched_raw, change["targetCommentId"]


def _scan_provider_authority(
    decision: dict[str, Any],
    selected_comment: dict[str, Any],
    manifest_sha: str,
) -> tuple[tuple[int, bytes], ...]:
    selected_id = selected_comment.get("id")
    selected_created = selected_comment.get("created_at")
    if not isinstance(selected_id, int) or not isinstance(selected_created, str):
        raise FinalGateError("selected provider authority identity drift")
    matches = 0
    changes: list[tuple[int, bytes]] = []
    for row in _fetch_issue_comments():
        body = row.get("body")
        if not isinstance(body, str):
            continue
        parsed = _json_object(body)
        if (
            _operator(row)
            and isinstance(parsed, dict)
            and parsed.get("kind") == decision["kind"]
            and parsed.get("selectionHead") == decision["selectionHead"]
            and parsed.get("candidateManifestSha256") == manifest_sha
        ):
            matches += 1
            if row.get("id") != selected_id:
                raise FinalGateError("duplicate matching provider authority")

        if (
            _operator(row)
            and isinstance(row.get("id"), int)
            and row["id"] > selected_id
            and isinstance(row.get("created_at"), str)
            and row["created_at"] > selected_created
            and (
                POSITIVE_INVENTORY_AUTHORITY_CHANGE_KIND.encode("utf-8")
                in body.encode("utf-8")
                or (
                    isinstance(parsed, dict)
                    and parsed.get("kind") == POSITIVE_INVENTORY_AUTHORITY_CHANGE_KIND
                )
            )
        ):
            row_id, raw, target_id = _validate_authority_change(row, selected_comment)
            changes.append((row_id, raw))
            if target_id == str(selected_id):
                raise FinalGateError("provider authority was withdrawn or superseded")
    if matches != 1:
        raise FinalGateError("provider authority is absent or duplicated")
    return tuple(changes)


def _validate_provider_authority(comment_id: str, repo: Path) -> dict[str, Any]:
    if not comment_id.isdecimal() or not comment_id:
        raise FinalGateError("provider comment ID is not decimal")
    url = f"https://api.github.com/repos/styx-secure/styx/issues/comments/{comment_id}"
    comment, comment_raw, _headers = _fetch_json(url)
    if not isinstance(comment, dict):
        raise FinalGateError("provider comment is not a JSON object")
    comment_user = comment.get("user")
    if (
        comment.get("id") != int(comment_id)
        or comment.get("url") != url
        or comment.get("issue_url") != "https://api.github.com/repos/styx-secure/styx/issues/295"
        or not isinstance(comment_user, dict)
        or comment_user.get("id") != 141346846
        or comment_user.get("login") != "maverde73"
        or comment.get("created_at") != comment.get("updated_at")
        or comment.get("performed_via_github_app") is not None
    ):
        raise FinalGateError("provider comment provenance drift")
    body = comment.get("body")
    if not isinstance(body, str):
        raise FinalGateError("provider comment body is absent")
    body_bytes = body.encode("utf-8")
    try:
        decision = loads(body_bytes)
    except CanonicalJsonError as error:
        raise FinalGateError("provider decision is not canonical JSON") from error
    required = {
        "decision",
        "kind",
        "repository",
        "issue",
        "baseSha",
        "selectionHead",
        "closureAmendmentSha256",
        "candidateManifestSha256",
        "positiveCarrierInventorySha256",
        "phaseAPackageReportSha256",
        "caseCount",
        "requestCaseCount",
        "responseCaseCount",
    }
    if not isinstance(decision, dict) or set(decision) != required or dumps(decision) != body_bytes:
        raise FinalGateError("provider decision body shape or final LF drift")
    if (
        decision["decision"] != "RATIFY"
        or decision["kind"] != "APP_CORE_POSITIVE_CARRIER_INVENTORY_RATIFICATION_V1"
        or decision["repository"] != "styx-secure/styx"
        or decision["issue"] != 295
        or decision["baseSha"] != BASE_SHA
        or decision["closureAmendmentSha256"]
        != RATIFIED_CARRIER_AUTHORITY_V3_SHA256
        or (decision["caseCount"], decision["requestCaseCount"], decision["responseCaseCount"])
        != (96, 77, 19)
    ):
        raise FinalGateError("provider decision value drift")

    selection_head = decision["selectionHead"]
    _verify_clean_checkout(repo.resolve(), selection_head)
    manifest_sha = _sha256(
        (
            repo.resolve()
            / "tools/causal-flow-simulator/app_core_iface0/contract/APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json"
        ).read_bytes()
    )
    if decision["candidateManifestSha256"] != manifest_sha:
        raise FinalGateError("provider decision does not bind the candidate manifest")

    commit, _commit_raw, _ = _fetch_json(
        f"https://api.github.com/repos/styx-secure/styx/commits/{selection_head}"
    )
    branch, _branch_raw, _ = _fetch_json(COMBINED_BRANCH_URL)
    if not isinstance(commit, dict) or not isinstance(branch, dict):
        raise FinalGateError("provider commit or branch ref is not a JSON object")
    if commit.get("sha") != selection_head:
        raise FinalGateError("provider commit identity drift")
    branch_object = branch.get("object")
    if (
        branch.get("ref") != COMBINED_BRANCH_REF
        or not isinstance(branch_object, dict)
        or branch_object.get("type") != "commit"
        or branch_object.get("sha") != selection_head
    ):
        raise FinalGateError("provider combined branch identity drift")

    pre_regeneration_scan = _scan_provider_authority(
        decision,
        comment,
        manifest_sha,
    )

    selected = _local_source_blobs(repo.resolve(), selection_head)
    _verify_provider_source_slice(selection_head, selected)

    # Phase B never consumes the reviewed or caller-supplied Phase-A directory.
    # Only after provider authentication does the gate create a fresh private
    # root and independently regenerate the exact carrier population.
    with tempfile.TemporaryDirectory(prefix="styx-app-core-phase-b-entry-") as temporary:
        regenerated = Path(temporary) / "phase-a"
        _generate_phase_a_from_checkout(repo.resolve(), regenerated)
        _verify_actual_carriers_against_historical(
            repo.resolve(),
            selected,
            selection_head,
            _tree(regenerated),
        )
        result = _validate_external_root(repo.resolve(), regenerated)
        if (
            decision["positiveCarrierInventorySha256"]
            != result["inventory_sha256"]
            or decision["phaseAPackageReportSha256"]
            != result["package_report_sha256"]
            or result["request_set_manifest_sha256"]
            != REQUEST_SET_MANIFEST_SHA256
        ):
            raise FinalGateError("provider decision does not bind regenerated Phase A")

    # Refresh the exact object after regeneration. A modification or deletion
    # during the gate is a fail-closed authority change.
    refreshed, refreshed_raw, _refreshed_headers = _fetch_json(url)
    if refreshed_raw != comment_raw or refreshed != comment:
        raise FinalGateError("provider decision changed during Phase-B entry")
    post_regeneration_scan = _scan_provider_authority(
        decision,
        comment,
        manifest_sha,
    )
    if post_regeneration_scan != pre_regeneration_scan:
        raise FinalGateError("provider authority-change set drifted during Phase-B entry")
    _verify_clean_checkout(repo.resolve(), selection_head)
    return decision


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--phase-a", action="store_true")
    modes.add_argument("--phase-b-entry", action="store_true")
    modes.add_argument("--acv049-e-baseline", action="store_true")
    parser.add_argument("--repo-root-one", required=True, type=Path)
    parser.add_argument("--repo-root-two", type=Path)
    parser.add_argument("--evidence-root-one", type=Path)
    parser.add_argument("--evidence-root-two", type=Path)
    parser.add_argument("--selection-head")
    parser.add_argument("--provider-comment-id")
    parser.add_argument("--node", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.phase_a:
            if (
                args.repo_root_two is None
                or args.evidence_root_one is None
                or args.evidence_root_two is None
                or args.selection_head is None
            ):
                raise FinalGateError("Phase A requires two roots and selectionHead")
            result = run_phase_a_gate(
                args.repo_root_one,
                args.repo_root_two,
                args.evidence_root_one,
                args.evidence_root_two,
                args.selection_head,
            )
        elif args.acv049_e_baseline:
            if (
                args.repo_root_two is None
                or args.evidence_root_one is None
                or args.evidence_root_two is None
                or args.selection_head is None
                or args.node is None
            ):
                raise FinalGateError(
                    "ACV-049 E baseline requires two roots, evidence, candidate HEAD and Node"
                )
            result = run_acv049_e_baseline_gate(
                args.repo_root_one,
                args.repo_root_two,
                args.evidence_root_one,
                args.evidence_root_two,
                args.selection_head,
                node=args.node,
            )
        else:
            if args.provider_comment_id is None:
                raise FinalGateError("Phase B requires a provider comment ID")
            decision = _validate_provider_authority(
                args.provider_comment_id,
                args.repo_root_one,
            )
            result = {
                "verdict": "PASS",
                "selectionHead": decision["selectionHead"],
                "positiveCarrierInventorySha256": decision[
                    "positiveCarrierInventorySha256"
                ],
                "requestSetManifestSha256": REQUEST_SET_MANIFEST_SHA256,
            }
    except (
        FinalGateError,
        InventoryError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"APP-core final gate: FAIL: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
