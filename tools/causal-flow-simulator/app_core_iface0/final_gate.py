#!/usr/bin/env python3
"""Exact two-checkout Phase-A gate and provider-bound Phase-B entry gate."""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
import re
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
from generate_seed_registry import REQUEST_SET_MANIFEST_SHA256, TERMINAL_IMPLEMENTATION_FILES
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
ACV049_EVALUATOR_PYTHON_FILES = (
    "authority_projection.py",
    "canonical_json.py",
    "canonical_report.py",
    "generate_seed_registry.py",
    "generate_structural_witnesses.py",
    "interface_model.py",
    "inventory.py",
    "run_semantic_acv049.py",
    "validate_inventory.py",
)
ACV049_VALIDATOR_PYTHON_FILES = (
    "contract/derive_app_core_carrier_reachability.py",
    "contract/derive_app_core_native_dependencies.py",
    "contract/validate_app_core_contract_candidates.py",
    "derive_interface_maxima.py",
)
ACV049_BASE_PINNED_PYTHON_FILE = "tools/causal-flow-simulator/c03/corpus_model.py"
ACV049_DENIED_PYTHON_MODULES = frozenset(
    {"datetime", "getpass", "os", "platform", "random", "socket", "time"}
)
ACV049_SPAWN_SITE_COUNTS = {
    ("interface_model.py", "verify_native_authority"): 3,
    ("inventory.py", "run_ratified_package_validator"): 1,
    ("contract/derive_app_core_native_dependencies.py", "git"): 1,
    ("contract/validate_app_core_contract_candidates.py", "validate_native_dependencies"): 1,
    ("contract/validate_app_core_contract_candidates.py", "validate_schema_and_relations"): 1,
    ("contract/validate_app_core_contract_candidates.py", "main"): 3,
    (ACV049_BASE_PINNED_PYTHON_FILE, "BaseReader.read"): 1,
    (ACV049_BASE_PINNED_PYTHON_FILE, "validate_base_inputs"): 1,
}
ACV049_BACKEND_ENTRY_POINTS = frozenset(
    {
        "ed25519_sign",
        "ed25519_verify",
        "encode_commitment",
        "encode_event",
        "encode_genesis",
        "framed_hash",
    }
)
ACV049_RUNTIME_PROVENANCE_KINDS = (
    "ambient_file",
    "clock",
    "environment",
    "host_identity",
    "network",
    "process_identity",
    "process_spawn",
    "randomness",
    "user_identity",
)
ACV049_RUNTIME_TRACE = Path("/usr/bin/strace")


# This gate-owned bootstrap is passed with ``python -I -B -c``.  It is not a
# repository or protocol input.  It installs the monitor before loading any
# evaluator module and propagates itself across the one permitted validator
# process tree.  The evaluator only sees its original argv.
ACV049_PYTHON_RUNTIME_MONITOR = r'''import argparse as _argparse
import _colorize as _colorize
import base64 as _b64
import builtins as _builtins
import datetime as _datetime
import getpass as _getpass
import io as _io
import json as _json
import os as _os
import pathlib as _pathlib
import platform as _platform
import random as _random
import runpy as _runpy
import secrets as _secrets
import shutil as _shutil
import socket as _socket
import subprocess as _subprocess
import sys as _sys
import time as _time
from jsonschema.validators import Draft202012Validator as _PinnedDraft202012Validator

_POLICY = _json.loads(_b64.b64decode(_sys.argv[1]).decode("utf-8"))
_LOG_FD = int(_sys.argv[2])
_MODE = _sys.argv[3]
_TARGET = _sys.argv[4] if len(_sys.argv) > 4 else ""
_TARGET_ARGS = _sys.argv[5:]
_MONITORED = tuple(_POLICY["monitored_roots"])
_ALLOWED_READS = frozenset(_POLICY["allowed_reads"])
_ALLOWED_WRITES = frozenset(_POLICY["allowed_writes"])
_ALLOWED_METADATA = frozenset(_POLICY["allowed_metadata"])
_ENUMERABLE_DIRECTORIES = frozenset(_POLICY["enumerable_directories"])
_ORIGINAL_POPEN = _subprocess.Popen
_ORIGINAL_ENVIRON = _os.environ
_ORIGINAL_OS_WRITE = _os.write
_ORIGINAL_OPEN = _builtins.open
_FORCE = False
_argparse._ = lambda message: message
_colorize.can_colorize = lambda *args, **kwargs: False
_shutil.get_terminal_size = lambda fallback=(80, 24): _os.terminal_size((80, 24))

def _record(kind, disposition, justification, **detail):
    row = {"detail": detail, "disposition": disposition,
           "justification": justification, "kind": kind}
    raw = (_json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
    _ORIGINAL_OS_WRITE(_LOG_FD, raw)

def _frame():
    frame = _sys._getframe(2)
    while frame is not None:
        filename = frame.f_code.co_filename
        if any(filename == root or filename.startswith(root + _os.sep)
               for root in _MONITORED):
            return filename, frame.f_code.co_name
        frame = frame.f_back
    return None

def _active():
    return _FORCE or _frame() is not None

def _deny(kind, api):
    if _active():
        origin = _frame()
        stack = []
        current = _sys._getframe(1)
        while current is not None and len(stack) < 16:
            stack.append([current.f_code.co_filename, current.f_code.co_name])
            current = current.f_back
        _record(kind, "DENY", "host-runtime provenance is forbidden", api=api,
                origin=list(origin) if origin is not None else None, stack=stack)
        raise RuntimeError("ACV-049 runtime provenance violation: " + kind)

class _GuardedEnviron:
    def __getitem__(self, key):
        _deny("environment", "os.environ.__getitem__")
        return _ORIGINAL_ENVIRON[key]
    def get(self, key, default=None):
        _deny("environment", "os.environ.get")
        return _ORIGINAL_ENVIRON.get(key, default)
    def __contains__(self, key):
        _deny("environment", "os.environ.__contains__")
        return key in _ORIGINAL_ENVIRON
    def __iter__(self):
        _deny("environment", "os.environ.__iter__")
        return iter(_ORIGINAL_ENVIRON)
    def __len__(self):
        _deny("environment", "os.environ.__len__")
        return len(_ORIGINAL_ENVIRON)
    def __setitem__(self, key, value):
        _deny("environment", "os.environ.__setitem__")
        _ORIGINAL_ENVIRON[key] = value
    def __delitem__(self, key):
        _deny("environment", "os.environ.__delitem__")
        del _ORIGINAL_ENVIRON[key]
    def keys(self):
        _deny("environment", "os.environ.keys")
        return _ORIGINAL_ENVIRON.keys()
    def items(self):
        _deny("environment", "os.environ.items")
        return _ORIGINAL_ENVIRON.items()
    def values(self):
        _deny("environment", "os.environ.values")
        return _ORIGINAL_ENVIRON.values()
    def copy(self):
        _deny("environment", "os.environ.copy")
        return _ORIGINAL_ENVIRON.copy()

_os.environ = _GuardedEnviron()
_guarded_getenv_original = _os.getenv
def _guarded_getenv(key, default=None):
    _deny("environment", "os.getenv")
    return _guarded_getenv_original(key, default)
_os.getenv = _guarded_getenv

def _guard(module, name, kind):
    original = getattr(module, name, None)
    if original is None:
        return
    def guarded(*args, **kwargs):
        _deny(kind, module.__name__ + "." + name)
        return original(*args, **kwargs)
    setattr(module, name, guarded)

for _name in ("getpid", "getppid"):
    _guard(_os, _name, "process_identity")
for _name in ("getlogin", "getuid", "geteuid", "uname"):
    _guard(_os, _name, "user_identity")
_guard(_os, "getcwd", "host_identity")
_guard(_os, "urandom", "randomness")
_guard(_getpass, "getuser", "user_identity")
for _name in ("node", "platform", "processor", "release", "system", "uname"):
    _guard(_platform, _name, "host_identity")
for _name in ("getfqdn", "gethostbyaddr", "gethostbyname", "gethostname"):
    _guard(_socket, _name, "host_identity")
for _name in ("create_connection", "socketpair"):
    _guard(_socket, _name, "network")
_OriginalSocket = _socket.socket
class _GuardedSocket(_OriginalSocket):
    def __new__(cls, *args, **kwargs):
        _deny("network", "socket.socket")
        return _OriginalSocket.__new__(cls, *args, **kwargs)
_socket.socket = _GuardedSocket
for _name in ("monotonic", "monotonic_ns", "perf_counter", "perf_counter_ns",
              "process_time", "process_time_ns", "time", "time_ns"):
    _guard(_time, _name, "clock")
for _name in ("choice", "choices", "getrandbits", "randbytes", "randint",
              "random", "randrange", "sample", "shuffle", "uniform"):
    _guard(_random, _name, "randomness")
for _name in ("choice", "randbelow", "token_bytes", "token_hex", "token_urlsafe"):
    _guard(_secrets, _name, "randomness")

_OriginalDate = _datetime.date
_OriginalDateTime = _datetime.datetime
class _GuardedDate(_OriginalDate):
    @classmethod
    def today(cls):
        _deny("clock", "datetime.date.today")
        return _OriginalDate.today()
class _GuardedDateTime(_OriginalDateTime):
    @classmethod
    def now(cls, tz=None):
        _deny("clock", "datetime.datetime.now")
        return _OriginalDateTime.now(tz)
    @classmethod
    def utcnow(cls):
        _deny("clock", "datetime.datetime.utcnow")
        return _OriginalDateTime.utcnow()
    @classmethod
    def today(cls):
        _deny("clock", "datetime.datetime.today")
        return _OriginalDateTime.today()
_datetime.date = _GuardedDate
_datetime.datetime = _GuardedDateTime

def _import_loading():
    current = _sys._getframe(2)
    while current is not None:
        if "importlib" in current.f_code.co_filename:
            return True
        current = current.f_back
    return False

def _absolute_path(value):
    try:
        lexical = _os.fspath(value)
    except TypeError:
        return None
    if isinstance(lexical, bytes):
        lexical = _os.fsdecode(lexical)
    return _os.path.abspath(lexical)

for _metadata_name in ("access", "listdir", "lstat", "readlink", "scandir", "stat"):
    _metadata_original = getattr(_os, _metadata_name)
    def _metadata_guard(target=".", *args, __name=_metadata_name,
                        __original=_metadata_original, **kwargs):
        if _active():
            absolute = _absolute_path(target)
            if absolute is None:
                _record("ambient_file", "DENY", "non-path metadata target", api="os." + __name)
                raise RuntimeError("ACV-049 runtime provenance violation: ambient_file")
            enumerable = __name not in {"listdir", "scandir"} \
                or absolute in _ENUMERABLE_DIRECTORIES
            if enumerable and (absolute in _ALLOWED_METADATA or absolute in _ALLOWED_READS):
                _record("filesystem", "PERMIT", "bound path metadata",
                        api="os." + __name, path=absolute)
            elif _import_loading():
                _record("filesystem", "PERMIT", "interpreter module metadata",
                        api="os." + __name, path=absolute)
            else:
                _record("ambient_file", "DENY", "filesystem metadata is not bound",
                        api="os." + __name, path=absolute)
                raise RuntimeError("ACV-049 runtime provenance violation: ambient_file")
        return __original(target, *args, **kwargs)
    setattr(_os, _metadata_name, _metadata_guard)

def _audit(event, args):
    if event in {"sys._getframe", "object.__getattr__"}:
        return
    if not _active():
        return
    if event == "open":
        target = args[0]
        if isinstance(target, int):
            return
        absolute = _absolute_path(target)
        if absolute is None:
            _record("ambient_file", "DENY", "non-path filesystem target", api="open")
            raise RuntimeError("ACV-049 runtime provenance violation: ambient_file")
        mode = args[1]
        frame = _sys._getframe(1)
        if absolute == _os.devnull:
            current = frame
            while current is not None:
                if current.f_code.co_filename == _subprocess.__file__ \
                        and current.f_code.co_name == "_get_devnull":
                    _record("filesystem", "PERMIT", "permitted process plumbing",
                            mode=str(mode), path=absolute)
                    return
                current = current.f_back
        writing = isinstance(mode, str) and any(flag in mode for flag in "wax+")
        allowed = absolute in (_ALLOWED_WRITES if writing else _ALLOWED_READS)
        if allowed:
            _record("filesystem", "PERMIT",
                    "manifest-bound input" if not writing else "gate-owned output",
                    mode=str(mode), path=absolute)
            return
        # Imports are interpreter/code loading, not evaluator data access.  The
        # independent static closure fixes every first-party loaded module.
        while frame is not None:
            if "importlib" in frame.f_code.co_filename:
                _record("filesystem", "PERMIT", "interpreter module load",
                        mode=str(mode), path=absolute)
                return
            frame = frame.f_back
        _record("ambient_file", "DENY", "filesystem input is not manifest-bound",
                mode=str(mode), path=absolute)
        raise RuntimeError("ACV-049 runtime provenance violation: ambient_file")
    if event.startswith("socket."):
        _record("network", "DENY", "network access is forbidden", api=event)
        raise RuntimeError("ACV-049 runtime provenance violation: network")

_sys.addaudithook(_audit)

def _logical_python_target(argv):
    if not isinstance(argv, (list, tuple)) or not argv:
        return None
    rendered = [_os.fspath(value) for value in argv]
    executable = _os.path.basename(rendered[0])
    if executable not in {"python", "python3", _os.path.basename(_sys.executable)}:
        return None
    offset = 1
    if offset < len(rendered) and rendered[offset] == "-B":
        offset += 1
    if offset >= len(rendered) or rendered[offset].startswith("-"):
        return None
    return rendered, offset

def _classify_spawn(argv):
    caller = _frame()
    if caller is None or not isinstance(argv, (list, tuple)) or not argv:
        return None
    filename, function = caller
    rendered = [_os.fspath(value) for value in argv]
    base = _os.path.basename(filename)
    if base == "interface_model.py" and function == "verify_native_authority":
        if rendered[0] == "git" and len(rendered) > 1 and rendered[1] in {
            "cat-file", "hash-object", "ls-tree"}:
            return "pinned native-authority Git verification"
    if base == "inventory.py" and function == "run_ratified_package_validator":
        target = _logical_python_target(rendered)
        if target and _os.path.basename(target[0][target[1]]) == \
                "validate_app_core_contract_candidates.py":
            return "manifest-bound contract-package validator"
    if base == "validate_app_core_contract_candidates.py":
        if rendered[0] == "git" and "outcome-taxonomy.json" in " ".join(rendered):
            return "Base O-10 taxonomy Git read"
        target = _logical_python_target(rendered)
        if target and _os.path.basename(target[0][target[1]]) in {
            "derive_app_core_carrier_reachability.py",
            "derive_app_core_native_dependencies.py",
            "derive_interface_maxima.py",
        }:
            return "manifest-bound validator derivation"
    if base == "derive_app_core_native_dependencies.py" and function == "git":
        if rendered[0] == "git" and len(rendered) > 3 and rendered[1] == "-C" \
                and rendered[3] in {"cat-file", "hash-object", "ls-tree", "rev-parse"}:
            return "native-dependency Git derivation"
    return None

def _wrapped_python(argv):
    target = _logical_python_target(argv)
    if target is None:
        return None
    rendered, offset = target
    encoded_policy = _b64.b64encode(
        _json.dumps(_POLICY, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return [_sys.executable, "-I", "-B", "-c", _POLICY["bootstrap"],
            encoded_policy, str(_LOG_FD), "run",
            rendered[offset], *rendered[offset + 1:]]

def _guarded_popen(args, *positional, **keywords):
    if not _active():
        return _ORIGINAL_POPEN(args, *positional, **keywords)
    justification = _classify_spawn(args)
    if justification is None:
        _record("process_spawn", "DENY", "process spawn is outside the closed allowlist",
                argv=[str(value) for value in args] if isinstance(args, (list, tuple)) else str(args))
        raise RuntimeError("ACV-049 runtime provenance violation: process_spawn")
    rendered = [str(value) for value in args]
    _record("process_spawn", "PERMIT", justification, argv=rendered)
    wrapped = _wrapped_python(args)
    if wrapped is not None:
        inherited = tuple(keywords.get("pass_fds", ()))
        keywords["pass_fds"] = tuple(sorted({*inherited, _LOG_FD}))
        args = wrapped
    elif isinstance(args, (list, tuple)) and args and args[0] == "git":
        args = [_POLICY["git_executable"], *args[1:]]
    return _ORIGINAL_POPEN(args, *positional, **keywords)

_subprocess.Popen = _guarded_popen

if _MODE == "negative":
    _FORCE = True
    _kind = _TARGET
    try:
        if _kind.startswith("environment:"):
            _os.environ[_kind.split(":", 1)[1]]
        elif _kind == "host_identity":
            _socket.gethostname()
        elif _kind == "user_identity":
            _getpass.getuser()
        elif _kind == "process_identity":
            _os.getpid()
        elif _kind == "clock":
            _time.time()
        elif _kind == "randomness":
            _os.urandom(1)
        elif _kind == "network":
            _socket.socket()
        elif _kind == "ambient_file":
            _ORIGINAL_OPEN(_POLICY["negative_ambient_path"], "rb").close()
        elif _kind == "process_spawn":
            _subprocess.Popen(["unpermitted-acv049-process"])
        else:
            raise RuntimeError("unknown negative control")
    except RuntimeError as error:
        if str(error).startswith("ACV-049 runtime provenance violation:"):
            raise SystemExit(73)
        raise
    raise SystemExit(0)

if _MODE != "run" or not _TARGET:
    raise SystemExit("invalid ACV-049 monitor invocation")
_target = _os.path.abspath(_TARGET)
_sys.path.insert(0, _os.path.dirname(_target))
_sys.argv = [_target, *_TARGET_ARGS]
_record("monitor", "PERMIT", "runtime monitor installed before evaluator load",
        target=_target)
try:
    _runpy.run_path(_target, run_name="__main__")
except SystemExit as _error:
    if _error.code not in (None, 0):
        _record("monitor", "DENY", "monitored process terminated",
                error_type=type(_error).__name__, error_text=str(_error))
    raise
except BaseException as _error:
    _record("monitor", "DENY", "monitored process terminated",
            error_type=type(_error).__name__, error_text=str(_error))
    raise
'''


ACV049_NODE_RUNTIME_MONITOR = r'''"use strict";
const fs = require("node:fs");
const os = require("node:os");
const net = require("node:net");
const dns = require("node:dns");
const http = require("node:http");
const https = require("node:https");
const crypto = require("node:crypto");
const childProcess = require("node:child_process");
const policy = JSON.parse(Buffer.from("__POLICY_BASE64__", "base64").toString("utf8"));
const logFd = Number("__LOG_FD__");
const adapter = policy.node_adapter;
const allowedReads = new Set(policy.allowed_reads);
const allowedMetadata = new Set(policy.allowed_metadata);
const originalWriteSync = fs.writeSync.bind(fs);
function active() {
  return String(new Error().stack || "").includes(adapter);
}
function record(kind, disposition, justification, detail = {}) {
  originalWriteSync(logFd, JSON.stringify({detail, disposition, justification, kind}) + "\n");
}
function deny(kind, api) {
  if (active()) {
    record(kind, "DENY", "host-runtime provenance is forbidden", {api});
    throw new Error(`ACV-049 runtime provenance violation: ${kind}`);
  }
}
const originalEnv = process.env;
const guardedEnv = new Proxy(originalEnv, {
  get(target, property) { deny("environment", "process.env.get"); return Reflect.get(target, property); },
  has(target, property) { deny("environment", "process.env.has"); return Reflect.has(target, property); },
  ownKeys(target) { deny("environment", "process.env.keys"); return Reflect.ownKeys(target); },
});
Object.defineProperty(process, "env", {configurable: true, get() { deny("environment", "process.env"); return guardedEnv; }});
const originalPid = process.pid;
Object.defineProperty(process, "pid", {configurable: true, get() { deny("process_identity", "process.pid"); return originalPid; }});
const originalCwd = process.cwd.bind(process);
process.cwd = function() { deny("host_identity", "process.cwd"); return originalCwd(); };
for (const name of ["hostname", "userInfo", "networkInterfaces"]) {
  const original = os[name];
  os[name] = function(...args) { deny(name === "userInfo" ? "user_identity" : "host_identity", `os.${name}`); return original.apply(this, args); };
}
for (const [module, names] of [[net, ["connect", "createConnection", "createServer"]], [dns, ["lookup", "resolve"]], [http, ["get", "request"]], [https, ["get", "request"]]]) {
  for (const name of names) {
    const original = module[name];
    module[name] = function(...args) { deny("network", `${name}`); return original.apply(this, args); };
  }
}
for (const name of ["exec", "execFile", "fork", "spawn", "spawnSync"]) {
  const original = childProcess[name];
  childProcess[name] = function(...args) { deny("process_spawn", `child_process.${name}`); return original.apply(this, args); };
}
const OriginalDate = Date;
class GuardedDate extends OriginalDate {
  constructor(...args) { if (args.length === 0) deny("clock", "Date.constructor"); super(...args); }
  static now() { deny("clock", "Date.now"); return OriginalDate.now(); }
}
global.Date = GuardedDate;
if (global.performance) {
  const originalNow = global.performance.now.bind(global.performance);
  Object.defineProperty(global.performance, "now", {configurable: true, value() { deny("clock", "performance.now"); return originalNow(); }});
}
const originalRandom = Math.random;
Math.random = function() { deny("randomness", "Math.random"); return originalRandom(); };
for (const name of ["randomBytes", "randomFill", "randomFillSync", "randomInt", "randomUUID"]) {
  const original = crypto[name];
  if (typeof original === "function") crypto[name] = function(...args) { deny("randomness", `crypto.${name}`); return original.apply(this, args); };
}
function normalizePath(value) {
  if (typeof value !== "string" && !Buffer.isBuffer(value) && !(value instanceof URL)) return null;
  return fs.realpathSync.native(String(value));
}
for (const name of ["openSync", "readFileSync", "realpathSync", "statSync"]) {
  const original = fs[name];
  if (name === "realpathSync") continue;
  fs[name] = function(target, ...args) {
    if (active() && typeof target !== "number") {
      let resolved;
      try { resolved = fs.realpathSync.native(String(target)); } catch (_) { resolved = require("node:path").resolve(String(target)); }
      const allowed = name === "statSync"
        ? (allowedMetadata.has(resolved) || allowedReads.has(resolved))
        : allowedReads.has(resolved);
      if (!allowed) {
        record("ambient_file", "DENY", "filesystem input is not manifest-bound", {api: `fs.${name}`, path: resolved});
        throw new Error("ACV-049 runtime provenance violation: ambient_file");
      }
      record("filesystem", "PERMIT", name === "statSync" ? "bound path metadata" : "manifest-bound input", {api: `fs.${name}`, path: resolved});
    } else if (active() && target === 0) {
      record("filesystem", "PERMIT", "gate-owned standard input", {api: `fs.${name}`});
    }
    return original.call(this, target, ...args);
  };
}
const originalRealpathNative = fs.realpathSync.native.bind(fs.realpathSync);
fs.realpathSync.native = function(target, ...args) {
  const resolved = originalRealpathNative(target, ...args);
  if (active()) {
    if (!allowedReads.has(resolved) && !allowedMetadata.has(resolved)) {
      record("ambient_file", "DENY", "filesystem input is not manifest-bound", {api: "fs.realpathSync.native", path: resolved});
      throw new Error("ACV-049 runtime provenance violation: ambient_file");
    }
    record("filesystem", "PERMIT", "bound path metadata", {api: "fs.realpathSync.native", path: resolved});
  }
  return resolved;
};
record("monitor", "PERMIT", "runtime monitor installed before JavaScript reader load", {target: adapter});
'''


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
    input_bytes: bytes | None = None,
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
        input=input_bytes,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise FinalGateError("checkout-owned evidence tool failed")
    return completed


def _run_acv049_javascript_reader(
    repo: Path,
    node: Path,
    contract: Path,
    jobs_bytes: bytes,
    environment: dict[str, str],
) -> bytes:
    """Run the independent reader from the outer gate, never the evaluator."""

    try:
        value = loads(jobs_bytes)
    except CanonicalJsonError as error:
        raise FinalGateError("ACV-049 terminal jobs are not canonical") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"jobs"}
        or not isinstance(value["jobs"], list)
        or len(value["jobs"]) != 507
    ):
        raise FinalGateError("ACV-049 terminal job set drift")
    adapter = (
        repo.resolve()
        / "tools/causal-flow-simulator/app_core_iface0/node_adapter.mjs"
    )
    if not adapter.is_file() or adapter.is_symlink():
        raise FinalGateError("ACV-049 JavaScript reader is absent or non-regular")
    results: list[object] = []
    for offset in range(0, len(value["jobs"]), 64):
        batch = value["jobs"][offset:offset + 64]
        with tempfile.TemporaryFile() as input_file:
            input_file.write(dumps({"jobs": batch}))
            input_file.seek(0)
            completed = subprocess.run(
                [
                    str(node),
                    str(adapter),
                    "--self-test-terminal-schema",
                    "--contract",
                    str(contract),
                ],
                cwd=repo.resolve(),
                env=dict(environment),
                stdin=input_file,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=180,
            )
        if completed.returncode != 0:
            raise FinalGateError("ACV-049 JavaScript reader failed")
        try:
            result = json.loads(completed.stdout)
        except (UnicodeDecodeError, ValueError) as error:
            raise FinalGateError("ACV-049 JavaScript reader emitted invalid JSON") from error
        if (
            not isinstance(result, dict)
            or set(result) != {"results"}
            or not isinstance(result["results"], list)
            or len(result["results"]) != len(batch)
        ):
            raise FinalGateError("ACV-049 JavaScript reader result drift")
        results.extend(result["results"])
    if len(results) != 507:
        raise FinalGateError("ACV-049 JavaScript reader result count drift")
    return dumps({"results": results})


def _run_acv049_monitored_javascript_reader(
    repo: Path,
    node: Path,
    contract: Path,
    jobs_bytes: bytes,
    environment: dict[str, str],
    policy: dict[str, object],
) -> tuple[bytes, list[dict[str, object]], list[bytes]]:
    """Run each reader batch below a gate-owned Node provenance preloader."""

    try:
        value = loads(jobs_bytes)
    except CanonicalJsonError as error:
        raise FinalGateError("ACV-049 terminal jobs are not canonical") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"jobs"}
        or not isinstance(value["jobs"], list)
        or len(value["jobs"]) != 507
    ):
        raise FinalGateError("ACV-049 terminal job set drift")
    adapter = (
        repo.resolve()
        / "tools/causal-flow-simulator/app_core_iface0/node_adapter.mjs"
    ).resolve()
    if adapter != Path(str(policy.get("node_adapter", ""))) or not adapter.is_file():
        raise FinalGateError("ACV-049 monitored JavaScript reader identity drift")
    if not ACV049_RUNTIME_TRACE.is_file():
        raise FinalGateError("ACV-049 runtime process tracer is unavailable")
    results: list[object] = []
    traces: list[bytes] = []
    encoded_policy = base64.b64encode(dumps(policy)).decode("ascii")
    with tempfile.TemporaryDirectory(prefix="styx-acv049-runtime-node-") as raw:
        temporary = Path(raw)
        log_path = temporary / "monitor.jsonl"
        preloader = temporary / "monitor.cjs"
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            source = ACV049_NODE_RUNTIME_MONITOR.replace(
                "__POLICY_BASE64__", encoded_policy
            ).replace("__LOG_FD__", str(descriptor))
            preloader.write_text(source, encoding="utf-8")
            for offset in range(0, len(value["jobs"]), 64):
                batch = value["jobs"][offset:offset + 64]
                trace_path = temporary / f"exec-{offset:04d}.trace"
                with tempfile.TemporaryFile() as input_file:
                    input_file.write(dumps({"jobs": batch}))
                    input_file.seek(0)
                    completed = subprocess.run(
                        [
                            str(ACV049_RUNTIME_TRACE),
                            "-f",
                            "-qq",
                            "-e",
                            "trace=execve",
                            "-s",
                            "256",
                            "-o",
                            str(trace_path),
                            str(node),
                            "--require",
                            str(preloader),
                            str(adapter),
                            "--self-test-terminal-schema",
                            "--contract",
                            str(contract),
                        ],
                        cwd=repo.resolve(),
                        env=dict(environment),
                        stdin=input_file,
                        pass_fds=(descriptor,),
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=180,
                    )
                trace = trace_path.read_bytes()
                traces.append(trace)
                if completed.returncode != 0:
                    raise FinalGateError("ACV-049 monitored JavaScript reader failed")
                if _successful_exec_count(trace) != 1:
                    raise FinalGateError("ACV-049 JavaScript process trace escaped the monitor")
                for channel in ACV049_MUTANT_CHANNELS:
                    encoded = channel.encode("ascii")
                    if encoded in completed.stdout or encoded in completed.stderr:
                        raise FinalGateError("ACV-049 mutant channel leaked from JavaScript runtime")
                try:
                    result = json.loads(completed.stdout)
                except (UnicodeDecodeError, ValueError) as error:
                    raise FinalGateError(
                        "ACV-049 JavaScript reader emitted invalid JSON"
                    ) from error
                if (
                    not isinstance(result, dict)
                    or set(result) != {"results"}
                    or not isinstance(result["results"], list)
                    or len(result["results"]) != len(batch)
                ):
                    raise FinalGateError("ACV-049 JavaScript reader result drift")
                results.extend(result["results"])
        finally:
            os.close(descriptor)
        monitor_bytes = log_path.read_bytes()
    if len(results) != 507:
        raise FinalGateError("ACV-049 JavaScript reader result count drift")
    for channel in ACV049_MUTANT_CHANNELS:
        if channel.encode("ascii") in monitor_bytes:
            raise FinalGateError("ACV-049 mutant channel leaked into runtime evidence")
    rows = _decode_acv049_runtime_log(monitor_bytes)
    if sum(row["kind"] == "monitor" for row in rows) != 8:
        raise FinalGateError("ACV-049 JavaScript monitor batch count drift")
    return dumps({"results": results}), rows, traces


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


def _acv049_runtime_policy(
    repo: Path,
    contract: Path,
    evidence: Path,
    output: Path,
) -> dict[str, object]:
    """Derive the monitor policy only from already authenticated local bytes."""

    root = repo.resolve()
    contract_root = contract.resolve()
    evidence_root = evidence.resolve()
    output_path = output.resolve()
    manifest_path = contract_root / "APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json"
    try:
        manifest = json.loads(manifest_path.read_bytes())
    except (UnicodeError, ValueError, OSError) as error:
        raise FinalGateError("ACV-049 runtime contract manifest is invalid") from error
    rows = manifest.get("artifacts") if isinstance(manifest, dict) else None
    if not isinstance(rows, list) or len(rows) != 27:
        raise FinalGateError("ACV-049 runtime contract artifact relation drift")
    contract_files = {manifest_path.resolve()}
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("path"), str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", row["path"])
            or not isinstance(row.get("sha256"), str)
        ):
            raise FinalGateError("ACV-049 runtime contract artifact row drift")
        path = (contract_root / row["path"]).resolve()
        if (
            path.parent != contract_root
            or not path.is_file()
            or path.is_symlink()
            or _sha256(path.read_bytes()) != row["sha256"]
        ):
            raise FinalGateError("ACV-049 runtime contract artifact identity drift")
        contract_files.add(path)
    if {path.resolve() for path in contract_root.iterdir()} != contract_files:
        raise FinalGateError("ACV-049 runtime contract file set drift")

    native_path = contract_root / "APP-CORE-IFACE-0-NATIVE-DEPENDENCIES-CANDIDATE.json"
    try:
        native = json.loads(native_path.read_bytes())
    except (UnicodeError, ValueError, OSError) as error:
        raise FinalGateError("ACV-049 runtime native inventory is invalid") from error
    dependencies = native.get("dependencies") if isinstance(native, dict) else None
    if not isinstance(dependencies, list) or len(dependencies) != 65:
        raise FinalGateError("ACV-049 runtime native dependency relation drift")
    native_files: set[Path] = set()
    for row in dependencies:
        relative = row.get("path") if isinstance(row, dict) else None
        digest = row.get("sha256") if isinstance(row, dict) else None
        if (
            not isinstance(relative, str)
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or not isinstance(digest, str)
        ):
            raise FinalGateError("ACV-049 runtime native dependency row drift")
        path = (root / relative).resolve()
        if (
            root not in path.parents
            or not path.is_file()
            or path.is_symlink()
        ):
            raise FinalGateError("ACV-049 runtime native dependency path drift")
        # The exact-repin dependency intentionally binds candidate bytes in its
        # repin object; all others bind the Base bytes, which the validator has
        # already compared to this clean checkout.
        if row.get("mutationPolicy") == "RATIFIED_H12_H3_EXACT_REPIN":
            repin = row.get("repin")
            expected = repin.get("newSha256") if isinstance(repin, dict) else None
        else:
            expected = digest
        if not isinstance(expected, str) or _sha256(path.read_bytes()) != expected:
            raise FinalGateError("ACV-049 runtime native dependency digest drift")
        native_files.add(path)

    evidence_files = {
        (evidence_root / relative).resolve()
        for relative in _tree(evidence_root)
    }
    enumerable_directories = {contract_root, evidence_root}
    enumerable_directories.update(
        path.resolve()
        for path in evidence_root.rglob("*")
        if path.is_dir() and not path.is_symlink()
    )
    implementation = root / "tools/causal-flow-simulator/app_core_iface0"
    source_files = {
        (
            root / relative
            if relative.startswith("tools/")
            else implementation / relative
        ).resolve()
        for relative in (
            *ACV049_EVALUATOR_PYTHON_FILES,
            *ACV049_VALIDATOR_PYTHON_FILES,
            ACV049_BASE_PINNED_PYTHON_FILE,
        )
    }
    source_files.add((implementation / "node_adapter.mjs").resolve())
    source_files.update(
        (implementation / relative).resolve()
        for relative in TERMINAL_IMPLEMENTATION_FILES
    )
    git_executable = Path("/usr/bin/git").resolve()
    if not git_executable.is_file():
        raise FinalGateError("ACV-049 pinned Git executable is unavailable")
    allowed_reads = contract_files | native_files | evidence_files | source_files
    if any(not path.is_file() or path.is_symlink() for path in allowed_reads):
        raise FinalGateError("ACV-049 runtime permitted input is invalid")
    metadata_paths = {root, contract_root, evidence_root, output_path, output_path.parent}
    for anchor in tuple(metadata_paths):
        current = anchor
        while current != current.parent:
            metadata_paths.add(current)
            current = current.parent
        metadata_paths.add(current)
    for path in allowed_reads:
        current = path.parent
        while current != current.parent:
            metadata_paths.add(current)
            if current in {root, evidence_root}:
                break
            current = current.parent
    return {
        "allowed_metadata": sorted(str(path) for path in metadata_paths),
        "allowed_reads": sorted(str(path) for path in allowed_reads),
        "allowed_writes": [str(output_path)],
        "bootstrap": ACV049_PYTHON_RUNTIME_MONITOR,
        "enumerable_directories": sorted(
            str(path) for path in enumerable_directories
        ),
        "git_executable": str(git_executable),
        "monitored_roots": [
            str(implementation.resolve()),
            str((root / ACV049_BASE_PINNED_PYTHON_FILE).resolve()),
        ],
        "negative_ambient_path": str((root / ".git/config").resolve()),
        "node_adapter": str((implementation / "node_adapter.mjs").resolve()),
    }


def _decode_acv049_runtime_log(raw: bytes, *, allow_denial: bool = False) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise FinalGateError("ACV-049 runtime monitor log is not UTF-8") from error
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError as error:
            raise FinalGateError("ACV-049 runtime monitor emitted invalid JSON") from error
        if (
            not isinstance(row, dict)
            or set(row) != {"detail", "disposition", "justification", "kind"}
            or row["disposition"] not in {"DENY", "PERMIT"}
            or not isinstance(row["detail"], dict)
            or not isinstance(row["justification"], str)
            or not isinstance(row["kind"], str)
        ):
            raise FinalGateError("ACV-049 runtime monitor row drift")
        if row["disposition"] == "DENY" and not allow_denial:
            api = row["detail"].get("api")
            origin = row["detail"].get("origin")
            stack = row["detail"].get("stack")
            suffix = f" ({row['kind']}:{api}:{origin}:{stack})" if isinstance(api, str) else f" ({row['kind']})"
            raise FinalGateError("ACV-049 runtime provenance access was denied" + suffix)
        rows.append(row)
    if not rows:
        raise FinalGateError("ACV-049 runtime monitor emitted no evidence")
    return rows


def _successful_exec_count(trace: bytes) -> int:
    try:
        lines = trace.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as error:
        raise FinalGateError("ACV-049 process trace is not UTF-8") from error
    return sum("execve(" in line and re.search(r"=\s*0$", line) is not None for line in lines)


def _run_acv049_monitored_python(
    repo: Path,
    relative_tool: str,
    arguments: list[str],
    *,
    policy: dict[str, object],
    environment: dict[str, str],
    input_bytes: bytes | None = None,
    timeout: int = 600,
) -> tuple[subprocess.CompletedProcess[bytes], list[dict[str, object]], bytes]:
    if not ACV049_RUNTIME_TRACE.is_file():
        raise FinalGateError("ACV-049 runtime process tracer is unavailable")
    tool = (repo.resolve() / relative_tool).resolve()
    if not tool.is_file() or tool.is_symlink():
        raise FinalGateError("ACV-049 monitored Python tool is invalid")
    encoded_policy = base64.b64encode(dumps(policy)).decode("ascii")
    with tempfile.TemporaryDirectory(prefix="styx-acv049-runtime-python-") as raw:
        temporary = Path(raw)
        log_path = temporary / "monitor.jsonl"
        trace_path = temporary / "exec.trace"
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            completed = subprocess.run(
                [
                    str(ACV049_RUNTIME_TRACE),
                    "-f",
                    "-qq",
                    "-e",
                    "trace=execve",
                    "-s",
                    "256",
                    "-o",
                    str(trace_path),
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-B",
                    "-c",
                    ACV049_PYTHON_RUNTIME_MONITOR,
                    encoded_policy,
                    str(descriptor),
                    "run",
                    str(tool),
                    *arguments,
                ],
                cwd=repo.resolve(),
                env=dict(environment),
                input=input_bytes,
                pass_fds=(descriptor,),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
        finally:
            os.close(descriptor)
        monitor_bytes = log_path.read_bytes()
        trace_bytes = trace_path.read_bytes()
    if completed.returncode != 0:
        raise FinalGateError("ACV-049 monitored Python evaluator failed")
    rows = _decode_acv049_runtime_log(monitor_bytes)
    logical_spawns = sum(row["kind"] == "process_spawn" for row in rows)
    if _successful_exec_count(trace_bytes) != logical_spawns + 1:
        raise FinalGateError("ACV-049 Python process trace escaped the monitor")
    for channel in ACV049_MUTANT_CHANNELS:
        encoded = channel.encode("ascii")
        if encoded in completed.stdout or encoded in completed.stderr or encoded in monitor_bytes:
            raise FinalGateError("ACV-049 mutant channel leaked from Python runtime")
    return completed, rows, trace_bytes


def _run_acv049_runtime_negative_controls(
    repo: Path,
    policy: dict[str, object],
    environment: dict[str, str],
) -> list[dict[str, object]]:
    controls = [
        *(f"environment:{name}" for name in sorted(environment)),
        *ACV049_RUNTIME_PROVENANCE_KINDS,
    ]
    # Environment controls above cover the environment kind itself.
    controls = [value for value in controls if value != "environment"]
    result: list[dict[str, object]] = []
    encoded_policy = base64.b64encode(dumps(policy)).decode("ascii")
    for control in controls:
        with tempfile.TemporaryDirectory(prefix="styx-acv049-negative-") as raw:
            log_path = Path(raw) / "monitor.jsonl"
            descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                completed = subprocess.run(
                    [
                        str(Path(sys.executable).resolve()),
                        "-I",
                        "-B",
                        "-c",
                        ACV049_PYTHON_RUNTIME_MONITOR,
                        encoded_policy,
                        str(descriptor),
                        "negative",
                        control,
                    ],
                    cwd=repo.resolve(),
                    env=dict(environment),
                    pass_fds=(descriptor,),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30,
                )
            finally:
                os.close(descriptor)
            rows = _decode_acv049_runtime_log(log_path.read_bytes(), allow_denial=True)
        if completed.returncode != 73 or not any(row["disposition"] == "DENY" for row in rows):
            raise FinalGateError("ACV-049 runtime negative control survived")
        result.append({"control": control, "verdict": "DETECTED"})
    return result


def _run_acv049_node_runtime_negative_controls(
    repo: Path,
    node: Path,
    policy: dict[str, object],
    environment: dict[str, str],
) -> list[dict[str, object]]:
    snippets = {
        **{
            f"environment:{name}": f"void process.env[{json.dumps(name)}];"
            for name in sorted(environment)
        },
        "ambient_file": (
            "require('node:fs').readFileSync("
            + json.dumps(str(policy["negative_ambient_path"]))
            + ");"
        ),
        "clock:date": "void Date.now();",
        "clock:performance": "void performance.now();",
        "host_identity": "void require('node:os').hostname();",
        "network": "void require('node:net').createServer();",
        "process_identity": "void process.pid;",
        "process_spawn": "void require('node:child_process').spawnSync('/bin/true');",
        "randomness:crypto": "void require('node:crypto').randomBytes(1);",
        "randomness:math": "void Math.random();",
        "user_identity": "void require('node:os').userInfo();",
    }
    result: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="styx-acv049-node-negative-") as raw:
        temporary = Path(raw)
        for index, (control, snippet) in enumerate(sorted(snippets.items())):
            log_path = temporary / f"monitor-{index:02d}.jsonl"
            main_path = temporary / f"negative-{index:02d}.cjs"
            preloader = temporary / f"monitor-{index:02d}.cjs"
            control_policy = dict(policy)
            control_policy["node_adapter"] = str(main_path.resolve())
            encoded_policy = base64.b64encode(dumps(control_policy)).decode("ascii")
            descriptor = os.open(
                log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
            )
            try:
                source = ACV049_NODE_RUNTIME_MONITOR.replace(
                    "__POLICY_BASE64__", encoded_policy
                ).replace("__LOG_FD__", str(descriptor))
                preloader.write_text(source, encoding="utf-8")
                main_path.write_text('"use strict";\n' + snippet + "\n", encoding="utf-8")
                completed = subprocess.run(
                    [str(node), "--require", str(preloader), str(main_path)],
                    cwd=repo.resolve(),
                    env=dict(environment),
                    pass_fds=(descriptor,),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30,
                )
            finally:
                os.close(descriptor)
            rows = _decode_acv049_runtime_log(
                log_path.read_bytes(), allow_denial=True
            )
            if completed.returncode == 0 or not any(
                row["disposition"] == "DENY" for row in rows
            ):
                raise FinalGateError("ACV-049 Node runtime negative control survived")
            result.append({"control": control, "verdict": "DETECTED"})
    return result


def _aggregate_acv049_runtime_rows(
    rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    counts: dict[bytes, int] = {}
    values: dict[bytes, dict[str, object]] = {}
    for row in rows:
        encoded = dumps(row)
        counts[encoded] = counts.get(encoded, 0) + 1
        values[encoded] = row
    return [
        {"access": values[encoded], "count": counts[encoded]}
        for encoded in sorted(counts)
    ]


def _definition_name(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> str | None:
    names: list[str] = []
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(current.name)
        current = parents.get(current)
    if not names:
        return None
    return ".".join(reversed(names))


def _command_prefix(node: ast.AST) -> tuple[str, ...]:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return ()
    result: list[str] = []
    for item in node.elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            break
        result.append(item.value)
    return tuple(result)


def _has_ancestor_test(
    node: ast.AST, parents: dict[ast.AST, ast.AST], expected: str
) -> bool:
    current = parents.get(node)
    while current is not None:
        if isinstance(current, ast.If) and ast.unparse(current.test) == expected:
            return True
        current = parents.get(current)
    return False


def _validate_acv049_spawn_arguments(
    relative: str,
    function: str,
    calls: list[ast.Call],
    parents: dict[ast.AST, ast.AST],
    source: str,
) -> None:
    prefixes = [_command_prefix(call.args[0]) if call.args else () for call in calls]
    if relative == "interface_model.py":
        if sorted(prefix[:2] for prefix in prefixes) != sorted(
            [("git", "cat-file"), ("git", "hash-object"), ("git", "ls-tree")]
        ):
            raise FinalGateError("ACV-049 native-authority Git argv drift")
    elif relative == "inventory.py":
        if prefixes != [()] or not isinstance(calls[0].args[0], ast.Name):
            raise FinalGateError("ACV-049 contract-validator argv indirection drift")
        required = (
            "sys.executable",
            "'-B'",
            "'validate_app_core_contract_candidates.py'",
            "'--repository'",
            "'--base-ref'",
        )
        function_node = parents[calls[0]]
        while not isinstance(function_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_node = parents[function_node]
        rendered = ast.unparse(function_node)
        if any(value not in rendered for value in required):
            raise FinalGateError("ACV-049 contract-validator argv drift")
    elif relative == "contract/derive_app_core_native_dependencies.py":
        if prefixes != [("git", "-C")]:
            raise FinalGateError("ACV-049 validator Git wrapper argv drift")
        allowed_git_commands = {
            "cat-file", "hash-object", "ls-tree", "rev-parse"
        }
        tree = ast.parse(source)
        observed = {
            call.args[1].value
            for call in ast.walk(tree)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "git"
            and len(call.args) >= 2
            and isinstance(call.args[1], ast.Constant)
            and isinstance(call.args[1].value, str)
        }
        if observed != allowed_git_commands:
            raise FinalGateError("ACV-049 validator Git command set drift")
    elif relative == "contract/validate_app_core_contract_candidates.py":
        rendered = [ast.unparse(call) for call in calls]
        if function == "validate_native_dependencies":
            if (
                len(rendered) != 1
                or "derive_app_core_native_dependencies.py" not in rendered[0]
                or "'--check'" not in rendered[0]
            ):
                raise FinalGateError("ACV-049 native derivation argv drift")
        elif function == "validate_schema_and_relations":
            if (
                len(prefixes) != 1
                or prefixes[0][:4] != ("git", "-C")
                or "outcome-taxonomy.json" not in rendered[0]
                or "'show'" not in rendered[0]
            ):
                raise FinalGateError("ACV-049 Base O-10 taxonomy argv drift")
        else:
            scripts = {
                name: [call for call, text in zip(calls, rendered, strict=True) if name in text]
                for name in (
                    "derive_app_core_carrier_reachability.py",
                    "derive_interface_maxima.py",
                    "validate_app_core_provider_bindings.py",
                )
            }
            if any(len(found) != 1 for found in scripts.values()):
                raise FinalGateError("ACV-049 validator descendant argv drift")
            provider_call = scripts["validate_app_core_provider_bindings.py"][0]
            if not _has_ancestor_test(provider_call, parents, "args.verify_provider"):
                raise FinalGateError("ACV-049 provider-only descendant became reachable")
            if any(
                "'--check'" not in ast.unparse(found[0])
                for name, found in scripts.items()
                if name != "validate_app_core_provider_bindings.py"
            ):
                raise FinalGateError("ACV-049 validator check argv drift")
    elif relative == ACV049_BASE_PINNED_PYTHON_FILE:
        expected = {
            "BaseReader.read": [("git", "show")],
            "validate_base_inputs": [("git", "cat-file")],
        }[function]
        if [prefix[:2] for prefix in prefixes] != expected:
            raise FinalGateError("ACV-049 dormant Base spawn argv drift")
    else:
        raise FinalGateError("ACV-049 unclassified process-spawn site")


def _corpus_reachable_functions(tree: ast.Module) -> set[str]:
    definitions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    edges: dict[str, set[str]] = {name: set() for name in definitions}
    for name, definition in definitions.items():
        edges[name] = {
            call.func.id
            for call in ast.walk(definition)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id in definitions
        }
    reachable = set(ACV049_BACKEND_ENTRY_POINTS)
    pending = list(reachable)
    if not reachable <= set(definitions):
        raise FinalGateError("ACV-049 Base backend entry point drift")
    while pending:
        current = pending.pop()
        for callee in edges[current] - reachable:
            reachable.add(callee)
            pending.append(callee)
    return reachable


def _scan_acv049_python_source(
    relative: str, source_bytes: bytes
) -> tuple[ast.Module, list[tuple[str, ast.Call]], set[str]]:
    try:
        source = source_bytes.decode("utf-8")
        tree = ast.parse(source)
    except (UnicodeDecodeError, SyntaxError, ValueError) as error:
        raise FinalGateError("ACV-049 provenance source is not canonical Python") from error
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    subprocess_aliases: set[str] = set()
    subprocess_call_aliases: set[str] = set()
    local_imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in ACV049_DENIED_PYTHON_MODULES:
                    raise FinalGateError("ACV-049 denied Python import")
                if root == "subprocess":
                    subprocess_aliases.add(alias.asname or root)
                local_imports.add(root)
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".", 1)[0]
            if any(alias.name == "*" for alias in node.names):
                raise FinalGateError("ACV-049 wildcard import is not closed")
            if root in ACV049_DENIED_PYTHON_MODULES:
                raise FinalGateError("ACV-049 denied Python import")
            if root == "subprocess":
                for alias in node.names:
                    if alias.name in {"call", "check_call", "check_output", "Popen", "run"}:
                        subprocess_call_aliases.add(alias.asname or alias.name)
            local_imports.add(root)

    spawn_calls: list[tuple[str, ast.Call]] = []
    denied_direct_calls = {
        "getenv", "getpass", "gethostname", "getuser", "getpid", "urandom",
        "monotonic", "monotonic_ns", "perf_counter", "perf_counter_ns",
        "process_time", "process_time_ns", "randbytes",
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            if node.func.id == "__import__" or node.func.id in subprocess_call_aliases:
                if node.func.id == "__import__":
                    raise FinalGateError("ACV-049 dynamic Python import")
                function = _definition_name(node, parents)
                if function is None:
                    raise FinalGateError("ACV-049 module-level process spawn")
                spawn_calls.append((function, node))
            elif node.func.id in denied_direct_calls:
                raise FinalGateError("ACV-049 denied Python provenance call")
        elif isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
                and node.func.attr == "import_module"
            ):
                raise FinalGateError("ACV-049 dynamic Python import")
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id in subprocess_aliases
            ):
                if node.func.attr not in {
                    "call", "check_call", "check_output", "Popen", "run"
                }:
                    raise FinalGateError("ACV-049 unclassified subprocess call")
                function = _definition_name(node, parents)
                if function is None:
                    raise FinalGateError("ACV-049 module-level process spawn")
                spawn_calls.append((function, node))

    grouped: dict[str, list[ast.Call]] = {}
    for function, call in spawn_calls:
        grouped.setdefault(function, []).append(call)
    for function, calls in grouped.items():
        expected = ACV049_SPAWN_SITE_COUNTS.get((relative, function))
        if expected != len(calls):
            raise FinalGateError("ACV-049 process-spawn count drift")
        _validate_acv049_spawn_arguments(
            relative, function, calls, parents, source
        )
    expected_functions = {
        function
        for (path, function), _count in ACV049_SPAWN_SITE_COUNTS.items()
        if path == relative
    }
    if set(grouped) != expected_functions:
        raise FinalGateError("ACV-049 process-spawn site set drift")
    return tree, spawn_calls, local_imports


def _scan_acv049_javascript_source(source: str) -> None:
    denied_javascript = (
        r"\bprocess\s*(?:\.\s*env|\[\s*['\"]env['\"]\s*\])",
        r"\bprocess\s*(?:\.\s*pid|\[\s*['\"]pid['\"]\s*\])",
        r"\b(?:new\s+)?Date\b",
        r"\bperformance\b",
        r"\bcrypto\s*\.\s*random",
        r"\bMath\s*\.\s*random",
        r"\bfrom\s*['\"](?:node:)?os['\"]",
        r"\brequire\s*\(\s*['\"](?:node:)?os['\"]",
        r"\bimport\s*\(",
    )
    if any(re.search(pattern, source) for pattern in denied_javascript):
        raise FinalGateError("ACV-049 denied JavaScript provenance access")


def run_acv049_static_provenance_scan(repo: Path) -> dict[str, object]:
    """Fail closed over the exact evaluator, readers and validator descendants."""

    root = repo.resolve()
    implementation = root / "tools/causal-flow-simulator/app_core_iface0"
    module_by_name = {
        Path(relative).stem: relative for relative in ACV049_EVALUATOR_PYTHON_FILES
    }
    imports_by_module: dict[str, set[str]] = {}
    spawn_count = 0
    corpus_tree: ast.Module | None = None
    for relative in (
        *ACV049_EVALUATOR_PYTHON_FILES,
        *ACV049_VALIDATOR_PYTHON_FILES,
        ACV049_BASE_PINNED_PYTHON_FILE,
    ):
        path = root / relative if relative.startswith("tools/") else implementation / relative
        if not path.is_file() or path.is_symlink():
            raise FinalGateError("ACV-049 provenance source is absent or non-regular")
        tree, spawns, imports = _scan_acv049_python_source(relative, path.read_bytes())
        spawn_count += len(spawns)
        if relative in ACV049_EVALUATOR_PYTHON_FILES:
            imports_by_module[Path(relative).stem] = {
                module_by_name[name] for name in imports if name in module_by_name
            }
        if relative == ACV049_BASE_PINNED_PYTHON_FILE:
            corpus_tree = tree

    reachable_modules = {"run_semantic_acv049.py"}
    pending_modules = ["run_semantic_acv049"]
    while pending_modules:
        module = pending_modules.pop()
        for relative in imports_by_module.get(module, set()):
            if relative not in reachable_modules:
                reachable_modules.add(relative)
                pending_modules.append(Path(relative).stem)
    if reachable_modules != set(ACV049_EVALUATOR_PYTHON_FILES):
        raise FinalGateError("ACV-049 loaded first-party module closure drift")

    if corpus_tree is None:
        raise FinalGateError("ACV-049 Base backend was not scanned")
    reachable_corpus = _corpus_reachable_functions(corpus_tree)
    if {"validate_base_inputs", "validate_inventory", "validate_sources"} & reachable_corpus:
        raise FinalGateError("ACV-049 dormant Base provenance path became reachable")

    backend_calls: set[str] = set()
    for relative in ("generate_seed_registry.py", "interface_model.py"):
        tree = ast.parse((implementation / relative).read_bytes())
        backend_calls.update(
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "backend"
        )
    if backend_calls != ACV049_BACKEND_ENTRY_POINTS:
        raise FinalGateError("ACV-049 Base backend call set drift")

    javascript = implementation / "node_adapter.mjs"
    if not javascript.is_file() or javascript.is_symlink():
        raise FinalGateError("ACV-049 JavaScript reader is absent or non-regular")
    try:
        javascript_source = javascript.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise FinalGateError("ACV-049 JavaScript reader is not UTF-8") from error
    _scan_acv049_javascript_source(javascript_source)

    expected_spawn_count = sum(ACV049_SPAWN_SITE_COUNTS.values())
    if spawn_count != expected_spawn_count:
        raise FinalGateError("ACV-049 total process-spawn count drift")
    return {
        "basePinnedModuleCount": 1,
        "dormantBaseSpawnCount": 2,
        "evaluatorModuleCount": len(ACV049_EVALUATOR_PYTHON_FILES),
        "javascriptReaderCount": 1,
        "permittedSpawnSiteCount": expected_spawn_count - 2,
        "validatorDescendantModuleCount": len(ACV049_VALIDATOR_PYTHON_FILES),
        "verdict": "STATIC_PROVENANCE_PASS",
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
    """Prove E equality under conjunctive static and runtime provenance controls."""

    first, second = _verify_acv049_checkout_pair(
        repo_one, repo_two, candidate_head
    )
    first_static = run_acv049_static_provenance_scan(first)
    second_static = run_acv049_static_provenance_scan(second)
    if first_static != second_static:
        raise FinalGateError("the two ACV-049 static provenance scans disagree")
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
        runtime_evidence: list[dict[str, object]] = []
        for repo, evidence, contract, output, environment in (
            (first, first_evidence, contract_one, output_one, environments[0]),
            (second, second_evidence, contract_two, output_two, environments[1]),
        ):
            policy = _acv049_runtime_policy(repo, contract, evidence, output)
            negative_controls = {
                "javascript": _run_acv049_node_runtime_negative_controls(
                    repo, resolved_node, policy, environment
                ),
                "python": _run_acv049_runtime_negative_controls(
                    repo, policy, environment
                ),
            }
            emitter, emitter_rows, emitter_trace = _run_acv049_monitored_python(
                repo,
                "tools/causal-flow-simulator/app_core_iface0/run_semantic_acv049.py",
                [
                    "--repo-root",
                    str(repo),
                    "--contract",
                    str(contract),
                    "--evidence-root",
                    str(evidence),
                    "--emit-terminal-jobs",
                ],
                policy=policy,
                environment=environment,
                timeout=600,
            )
            terminal_jobs = emitter.stdout
            javascript_result, javascript_rows, javascript_traces = (
                _run_acv049_monitored_javascript_reader(
                repo,
                resolved_node,
                contract,
                terminal_jobs,
                environment,
                policy,
                )
            )
            _builder, builder_rows, builder_trace = _run_acv049_monitored_python(
                repo,
                "tools/causal-flow-simulator/app_core_iface0/run_semantic_acv049.py",
                [
                    "--repo-root",
                    str(repo),
                    "--contract",
                    str(contract),
                    "--evidence-root",
                    str(evidence),
                    "--javascript-results-stdin",
                    "--output",
                    str(output),
                ],
                policy=policy,
                environment=environment,
                input_bytes=javascript_result,
                timeout=600,
            )
            permitted = [
                row
                for row in (*emitter_rows, *javascript_rows, *builder_rows)
                if row["disposition"] == "PERMIT"
            ]
            runtime_evidence.append(
                {
                    "negativeControls": negative_controls,
                    "permittedAccesses": _aggregate_acv049_runtime_rows(permitted),
                    "processTraceSha256": [
                        _sha256(emitter_trace),
                        *(_sha256(trace) for trace in javascript_traces),
                        _sha256(builder_trace),
                    ],
                    "verdict": "RUNTIME_PROVENANCE_PASS",
                }
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
        "provenanceControls": "STATIC_AND_RUNTIME_PASS",
        "runtimeProvenance": runtime_evidence,
        "semanticReportSha256": _sha256(first_bytes),
        "staticProvenance": first_static,
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
