# Non-blocking CI scope evidence

Status: Phase 2B observation mode. This control publishes evidence but is not a
required check and does not change branch protection, rulesets, CODEOWNERS,
Merge Queue, approval, or merge authority.

## Trust model

The workflow is `.github/workflows/agent-scope-evidence.yml` and runs on
`pull_request_target`. That event is security-sensitive, so the following
invariants are mandatory:

- execute only workflow and Python code from the immutable trusted tool SHA
  supplied by the base repository's `pull_request_target` run;
- never check out, import, source, or execute pull-request head files;
- treat the head commit only as Git object data used by diff and blob
  inspection;
- use the ephemeral `GITHUB_TOKEN` with explicit read-only permissions;
- never call a GitHub write endpoint or mutate Issue/PR state;
- pin every `uses:` action to a full immutable commit SHA.

Before any checkout, a repository-independent shell step validates the
runner-provided `GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` as lowercase full 40-hex
values and requires byte equality. The step uses no PR-controlled expression,
environment value, title, body, label, author, ref or repository file. A
failure aborts before checkout, produces no canonical report artifact, and is
still converted to the documented `ERROR = 3` job conclusion by the existing
`always()` summary/conclusion steps.

The checkout action receives immutable `${{ github.sha }}`, uses complete
history, and does not persist credentials. The adapter repeats the trusted-tool
and workflow-witness validation, requires checkout `HEAD` to equal that SHA,
and requires the event base to be its ancestor. It then fetches
`refs/pull/<number>/head` from the base repository with
`--no-write-fetch-head`, no destination ref, no checkout, and no worktree. The
expected event head object must then exist locally and the event base must be
its ancestor. The target base ref must be exactly `main`. A default-branch
force-push or history rewrite that disconnects an approved base therefore fails
closed instead of silently changing the task's trust root.

## PR-to-Issue linkage

A pull request must contain exactly one full line using this case-sensitive
syntax:

```text
Styx-Task: #48
```

Replace `48` with the local repository Issue number. The line may have spaces or
tabs after the colon and at the end, but no other text. Missing, duplicate,
malformed, or cross-repository references are `ERROR`.

The referenced item must be an open local Issue, not a pull request. The adapter
reads it from the GitHub Issues REST endpoint with the ephemeral read-only token.
Redirects are refused, response status/type/shape and size are checked, and the
body text is encoded directly as UTF-8 without Markdown rendering.

Current limits:

- event JSON: 1 MiB;
- Issue API response: 1 MiB;
- Issue body: 512 KiB;
- generated report: 4 MiB.

## Scope-guard invocation

The adapter invokes the trusted-tool CLI with three deliberately separate
identities: the event/contract base as `--base-sha`, the event candidate as
`--head-sha`, and the checked-out workflow/tool commit as `--worktree-sha`.
The exact Issue body, deterministic execution ID and output under `RUNNER_TEMP`
remain unchanged. The execution ID appends the full trusted tool SHA, providing
tool provenance without adding a report field or changing
`styx.task-scope-report/v1`.

Task-contract v1 requires the exact `Base` declaration and may include the
optional `Allowed binary artifacts` section documented in
`task-contract-v1.md`. The trusted-tool guard accepts only an A/M
regular blob whose candidate-HEAD bytes match the declared SHA-256 and byte
length exactly and whose path independently passes ordinary allowed/forbidden
scope evaluation. The authorization is read from the exact Issue body already
bound by `issue_body_sha256`; no extra report field or workflow-side exception
exists. Unlisted or mismatched binaries and every binary delete, rename, copy,
symlink, gitlink or unsupported mode remain fail-closed.

Task-contract v1 may also include the optional `Allowed copy sources` section.
It authorizes only an exact immutable text blob in the `old_path` role of a Git
copy record. The trusted-tool guard independently verifies its literal path,
base/HEAD regular-blob identity and mode, SHA-256, byte length, text
classification and absence from every other changed-entry role. One exact
source may serve multiple copies, but each destination still passes all ordinary
allow/forbid, object and content checks. Rename, source mutation/deletion,
binary/symlink/gitlink source, unused declaration and every destination-side
exception remain fail-closed.

The report schema and closed field set do not change. An authorized source keeps
its real forbidden matches and uses the documented synthetic
`![styx-copy-source sha256=<declared-64hex>]` item in `allowed_matches`. The
ordinary pattern grammar rejects that marker, and `issue_body_sha256` binds the
declaration. CI does not contain a separate exception or trust worktree bytes.

The scope guard supports an optional `--worktree-sha` argument. Its default
remains `--head-sha`, preserving local behavior. Observation CI passes the
trusted tool SHA so the worktree can run current base-repository enforcement
code while a task's approved historical base and candidate are inspected only
through Git objects. The guard still requires:

- full lowercase 40-hex base, head, and worktree SHAs;
- all commit objects to exist locally;
- base to be an ancestor of both the trusted tool and head commits (the adapter
  proves the first relationship and both adapter/guard preserve the second);
- worktree `HEAD` to equal the declared worktree SHA;
- a non-shallow, clean repository before and after execution.

Exit classes remain:

```text
PASS  = 0
FAIL  = 2
ERROR = 3
```

Unexpected exits, missing reports, inconsistent report metadata, API failures,
invalid events, object-fetch failures, and summary failures become `ERROR`; they
are never converted to `PASS`.

## Evidence

When a canonical report exists, the workflow attempts to upload it with the
pinned official `actions/upload-artifact` action. The artifact name is derived
only from immutable run data and contains the PR number, head SHA, run ID, and
run attempt. Retention is 14 days.

The job summary includes only:

- verdict;
- resolved Issue number;
- validated base/head SHAs;
- changed-entry and diagnostic counts;
- syntactically validated diagnostic codes.

Raw Issue text, paths, diagnostic messages, PR text, HTML, and Markdown are not
rendered in the summary. This prevents untrusted content from becoming active
Markdown or HTML.

A `FAIL` or `ERROR` makes the observation job red. It is nevertheless
non-blocking at repository-policy level because this task does not add the job
to the ruleset's required checks.

## Workflow triggers and concurrency

The workflow observes these `pull_request_target` actions:

```text
opened
reopened
synchronize
ready_for_review
converted_to_draft
edited
```

Only pull requests targeting `main` are observed. Runs are grouped by repository
and PR number, and stale runs are cancelled.

## Testing and review

Required local verification:

```shell
python3 -m unittest discover -s tools/agent-enforcement/tests -p 'test_*.py'
python3 tools/agent-enforcement/scope_guard.py --help
python3 tools/agent-enforcement/ci_adapter.py --help
python3 -m json.tool docs/governance/schemas/task-scope-report-v1.schema.json >/dev/null
git diff --check
```

The tests cover strict Issue reference parsing, fork metadata, API failures,
invalid or mismatched workflow identities, distinct trusted-tool/base object
inspection, exact contract-base binding, PASS/FAIL/ERROR preservation,
report-path containment, report absence, safe summary output, immutable action
pins, and absence of checkout/worktree/ref-update operations for the PR head.

Because `pull_request_target` loads its workflow definition from the base
repository, a change to this workflow cannot validate its own new definition
on its implementation PR. After merge, an older open PR needs a **new supported
PR event** (for example an `edited` event) to run the corrected definition.
`Re-run jobs` is not valid evidence because it reuses the workflow SHA from the
old run. The first corrected post-merge run is a human gate before any later
proposal to make the check required.

## Rollback

R0: revert or remove `.github/workflows/agent-scope-evidence.yml` to disable CI
observation immediately.

R1: remove `tools/agent-enforcement/ci_adapter.py`, its tests, and this document;
retain the local report-only guard from Issue #46. If no CI consumer needs
trusted-tool inspection, the optional `--worktree-sha` extension may also be
reverted.

Rollback does not alter product behavior or existing required checks.

## Residual risks

- A future edit that executes head content would turn `pull_request_target` into
  a privileged code-execution path and must be treated as blocking.
- GitHub API, Actions, or artifact outages can produce visible observation
  errors.
- The current trusted guard evaluates old open-task contracts. Future guard
  revisions must preserve backwards-safe semantics or fail closed, and their
  exact SHA remains visible in `execution_id`.
- A PR author can reference another open local Issue; human review must confirm
  that the referenced contract is the intended task until the restricted broker
  binds this relationship.
- Observation mode reports violations but does not itself prevent merge.
- Artifact retention limits long-term evidence unless a later approved system
  archives it.
