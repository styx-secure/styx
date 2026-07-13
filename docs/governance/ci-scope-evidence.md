# Non-blocking CI scope evidence

Status: Phase 2B observation mode. This control publishes evidence but is not a
required check and does not change branch protection, rulesets, CODEOWNERS,
Merge Queue, approval, or merge authority.

## Trust model

The workflow is `.github/workflows/agent-scope-evidence.yml` and runs on
`pull_request_target`. That event is security-sensitive, so the following
invariants are mandatory:

- execute only workflow and Python code from the pull request's trusted base
  SHA;
- never check out, import, source, or execute pull-request head files;
- treat the head commit only as Git object data used by diff and blob
  inspection;
- use the ephemeral `GITHUB_TOKEN` with explicit read-only permissions;
- never call a GitHub write endpoint or mutate Issue/PR state;
- pin every `uses:` action to a full immutable commit SHA.

The checkout action receives `github.event.pull_request.base.sha`, uses complete
history, and does not persist credentials. The adapter fetches
`refs/pull/<number>/head` from the base repository with
`--no-write-fetch-head`, no destination ref, no checkout, and no worktree. The
expected event head object must then exist locally and the event base must be
its ancestor.

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

The adapter invokes the trusted-base CLI with the event's full base and head
SHAs, the exact Issue body file, a deterministic execution ID, and an output
under `RUNNER_TEMP`.

The scope guard supports an optional `--worktree-sha` argument. Its default
remains `--head-sha`, preserving local behavior. Observation CI passes the
trusted base SHA so the worktree can remain on trusted code while the head is
inspected only through Git objects. The guard still requires:

- full lowercase 40-hex base, head, and worktree SHAs;
- all commit objects to exist locally;
- base to be an ancestor of head;
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

Runs are grouped by repository and PR number, and stale runs are cancelled.

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
invalid SHAs, trusted-base object inspection, PASS/FAIL/ERROR preservation,
report-path containment, report absence, safe summary output, immutable action
pins, and absence of checkout/worktree/ref-update operations for the PR head.

Because a newly added `pull_request_target` workflow is not present on the base
branch of its own implementation PR, its first GitHub-hosted observation occurs
only after merge. That first post-merge run is a human gate before any later
proposal to make the check required.

## Rollback

R0: revert or remove `.github/workflows/agent-scope-evidence.yml` to disable CI
observation immediately.

R1: remove `tools/agent-enforcement/ci_adapter.py`, its tests, and this document;
retain the local report-only guard from Issue #46. If no CI consumer needs
trusted-base inspection, the optional `--worktree-sha` extension may also be
reverted.

Rollback does not alter product behavior or existing required checks.

## Residual risks

- A future edit that executes head content would turn `pull_request_target` into
  a privileged code-execution path and must be treated as blocking.
- GitHub API, Actions, or artifact outages can produce visible observation
  errors.
- A PR author can reference another open local Issue; human review must confirm
  that the referenced contract is the intended task until the restricted broker
  binds this relationship.
- Observation mode reports violations but does not itself prevent merge.
- Artifact retention limits long-term evidence unless a later approved system
  archives it.
