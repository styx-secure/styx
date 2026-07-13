# Styx task contract v1 and report-only scope guard

## Purpose

`tools/agent-enforcement/scope_guard.py` turns the path portion of a Styx atomic-task Issue contract into deterministic, machine-readable evidence. It is the first Phase 2A enforcement increment and is deliberately **report-only**:

- it reads an Issue body from a local UTF-8 file;
- it reads a local Git worktree and explicit base/head commits;
- it writes one canonical JSON report outside the tested repository;
- it performs no network request and no GitHub write;
- it never changes the index, worktree, refs, configuration, workflows or repository settings;
- it disables local bytecode-cache creation before importing its modules, so a self-hosted run does not create `__pycache__`.

A `PASS` report is evidence, not merge authority. Human gates from `AGENTS.md` and the Issue remain authoritative.

## Contract marker

A v1 contract contains exactly one marker:

```html
<!-- styx-task-contract:v1 -->
```

The marker must appear before the first required level-2 section. Unknown or duplicated markers fail closed.

## Required sections

Each heading below must occur exactly once as a Markdown level-2 heading:

```text
Observable outcome
Non-goals
Allowed paths
Forbidden paths
Native dependencies
Frozen shared interfaces
Acceptance criteria
Rollback
Residual risks
Executor and reviewers
Human gates
Base
```

Exactly one of these headings must occur:

```text
Required tests
Required verification
```

Additional headings are permitted. They cannot replace or duplicate required headings.

## Code blocks and structural text

Markers and headings are structural only outside code blocks. The parser
recognizes three line-oriented code-block forms:

- backtick fences: three or more backticks indented at most three spaces,
  with an info string that contains no backtick;
- tilde fences: three or more tildes indented at most three spaces;
- indented code: any line starting with at least four spaces or one tab.

A fence closes on a line with a run of the same character at least as long as
the opening run, indented at most three spaces, with nothing else but trailing
whitespace. Markers, headings and fence lookalikes inside any of these blocks
are ignored. An unterminated fence fails closed.

## Path declarations

`Allowed paths` and `Forbidden paths` each contain exactly one fenced code block. Every non-empty line is one POSIX repository-relative pattern.

Supported grammar:

- literal path characters;
- `*` matches zero or more characters inside one segment;
- `?` matches exactly one character inside one segment;
- `**` is valid only as an entire segment and matches zero or more complete path segments.

Examples:

```text
tools/agent-enforcement/**
docs/governance/task-contract-v1.md
docs/governance/schemas/*.schema.json
```

The parser rejects absolute paths, trailing or repeated slashes, backslashes, control characters, `.`/`..` segments, duplicate patterns, negation, brace expansion, character classes, extglob and embedded `**` tokens. Patterns that change after POSIX normalization are rejected.

Patterns and repository paths are limited to 255 segments. Longer inputs are
rejected deterministically with an `ERROR` verdict; pattern matching itself is
iterative, so adversarially deep paths cannot exhaust the interpreter stack.

Every changed path must match at least one allowed pattern and no forbidden pattern. **Forbidden patterns always override allowed patterns.**

## Git inventory semantics

The CLI accepts only lowercase full 40-hex commit SHAs. Symbolic refs such as `main`, `HEAD` or tags are rejected.

The repository must satisfy all of the following:

- `--repo` points to the worktree root;
- the repository is not shallow;
- both commit objects are locally available;
- base is an ancestor of head;
- worktree `HEAD` equals the declared head SHA;
- index and worktree are clean, including untracked files;
- the report output path is outside the tested repository.

Git subprocesses are invoked without a shell. Repository-redirecting Git environment variables are removed; `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` are pointed at the null device so global and system configuration cannot alter the run; command-line configuration injection (`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_*`/`GIT_CONFIG_VALUE_*`) is stripped; optional locks are disabled, and filesystem-monitor/untracked-cache refreshes are disabled for the read-only run. Per-file Git lookups use `:(literal)` pathspecs, so file names that begin with `:` or contain glob characters are handled literally. Changed entries are obtained using the equivalent of:

```shell
git -c core.quotepath=false diff-tree \
  -r --no-commit-id --name-status -z \
  -M -C --find-copies-harder \
  <base-sha> <head-sha>
```

Semantics:

- add: check the new path;
- modify: check the path;
- delete: check the old path;
- rename/copy: check both old and new paths;
- unsupported or ambiguous statuses fail closed.

When `--base-sha` and `--head-sha` name the same commit the diff is empty by
definition: there are no changed entries to evaluate, and the verdict is
`PASS` only if the contract parses and every repository-state check
(clean worktree, matching `HEAD`, non-shallow repository, valid inputs)
also succeeds. Any of those failures still produces `ERROR`.

For every relevant tree object, v1 rejects:

- symlinks (`120000`);
- gitlinks/submodules (`160000` or tree type `commit`);
- unsupported non-blob modes;
- blobs containing NUL bytes, treated conservatively as binary.

The binary rule is intentionally conservative but not a complete media-type detector. A later schema version may define stronger content classification; uncertainty must never silently become `PASS`.

## CLI

```shell
python3 tools/agent-enforcement/scope_guard.py \
  --issue-number 46 \
  --issue-body-file /absolute/path/issue-46.md \
  --base-sha 67eabffeec19a7446e8fc84b151ae9799fbe3869 \
  --head-sha <full-40-hex-head> \
  --execution-id issue-46-attempt-001 \
  --output /absolute/path/task-scope-report.json \
  --repo /absolute/path/to/styx
```

The output file must be outside `--repo` **and** outside the real worktree root that contains `--repo`: when `--repo` points at a subdirectory of a repository, the report is still refused anywhere inside that repository. The tool creates a unique temporary sibling file with exclusive creation and atomically replaces the requested output.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | `PASS`: contract parsed, Git inventory completed, every path is in scope, and no forbidden object/content condition was found. Also returned by `--help`. |
| `2` | `FAIL`: deterministic policy violation such as an out-of-scope path, forbidden path, symlink, gitlink or NUL-containing blob. |
| `3` | `ERROR`: invalid contract/input, unavailable Git object, dirty/mismatched repository, unsupported status, I/O failure, CLI usage error or tool failure. |

This table is complete: the guard never exits with any other status for an
anticipated condition. CLI usage errors (missing or malformed arguments)
print usage on stderr and exit `3` without writing a report.

The JSON report is written for `PASS`, `FAIL` and recoverable `ERROR` outcomes. If the destination itself cannot be written, or the output location is refused, the process returns `3` and reports the failure on stderr.

## Report format

The schema is:

```text
docs/governance/schemas/task-scope-report-v1.schema.json
```

Schema identifier:

```text
styx.task-scope-report/v1
```

The report records:

- tool and contract versions;
- issue number and immutable execution ID;
- base and head SHAs;
- SHA-256 of the exact Issue-body bytes;
- fields that echo CLI input (`issue_number`, `base_sha`, `head_sha`) are
  `null` when the corresponding argument failed validation, and
  `issue_body_sha256` is `null` when the Issue-body bytes were never read
  (for example an unreadable file) — a `null` hash is never conflated with
  the real hash of an existing empty body, and those runs end in `ERROR`;
- normalized allowed and forbidden patterns;
- ordered add/modify/delete/rename/copy entries;
- per-path allowed matches, forbidden matches and violations;
- stable diagnostics;
- final `PASS`, `FAIL` or `ERROR` verdict.

Canonical encoding is UTF-8 JSON with recursively sorted keys, compact separators and one trailing LF. Wall-clock timestamps are omitted. Equivalent inputs with the same execution ID produce byte-identical report bytes.

Diagnostics are stable machine-readable codes:

- `P_*`: policy failures that produce `FAIL`;
- `E_*`: invalid input, repository state or tool errors that produce `ERROR`.

## Local verification

```shell
python3 -m unittest discover -s tools/agent-enforcement/tests -p 'test_*.py'
python3 tools/agent-enforcement/scope_guard.py --help
python3 -m json.tool docs/governance/schemas/task-scope-report-v1.schema.json >/dev/null
git diff --check
```

The test suite creates isolated temporary Git repositories and does not need network access or third-party Python packages. The suite disables bytecode-cache writes for everything it imports, and a `.gitignore` strictly scoped to `tools/agent-enforcement/**` covers the caches the interpreter creates for the test modules themselves, so a test run leaves `git status` clean.

## Limitations

- Only contract version `v1` is accepted.
- Markdown parsing is intentionally strict and line-oriented.
- Rename/copy classification follows the exact Git invocation above and therefore Git's similarity scoring.
- NUL-byte inspection is a conservative binary heuristic.
- Report-only execution does not publish checks and does not block a merge.
- GitHub Actions integration, required-check registration, broker operations, persona isolation and Passaggio B are separate human-authorized tasks.

## Rollback

Remove:

```text
tools/agent-enforcement/**
docs/governance/task-contract-v1.md
docs/governance/schemas/task-scope-report-v1.schema.json
```

No workflow or administrative state is changed by this increment, so rollback has no product or repository-admission effect.
