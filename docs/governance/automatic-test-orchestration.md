# Automatic test orchestration

Normative description of the isolated automatic test planner and executor
introduced by Issue #54. The orchestrator evaluates an exact committed task
HEAD before review and emits canonical evidence:

```text
styx.test-plan/v1
styx.test-report/v1
styx.test-failure/v1
```

Published schemas:

- `docs/governance/schemas/test-plan-v1.schema.json`;
- `docs/governance/schemas/test-report-v1.schema.json`;
- `docs/governance/schemas/test-failure-v1.schema.json`.

Implementation: `tools/test-orchestrator/`. The tool is standard-library
Python, performs no GitHub operation, no model/API call and no network
activity of its own, and never writes evidence inside the tested repository.

## Trusted inputs

The planner derives the plan automatically. No human-authored plan exists.
Its only inputs are:

1. the Issue body containing `<!-- styx-task-contract:v1 -->`, parsed for
   allowed/forbidden patterns by the trusted parser in
   `tools/agent-enforcement/contract.py` and for the Base and Required
   tests sections with the same fence-aware rules;
2. the `styx.task-scope-report/v1` evidence produced by the existing scope
   guard, consumed as canonical bytes and bound by SHA-256;
3. the committed tree at the candidate HEAD, read through read-only git
   commands.

Untrusted generated-test proposals may be supplied as a JSON array. Each
proposal is accepted only when it satisfies the offline command policy and
the resource-policy bounds; every other proposal is recorded in
`rejected_proposals` with a redacted, bounded reason.

## Plan derivation

Every check records trusted origin, purpose, the exact HEAD, execution
class, timeout/output policy and a deterministic identifier (the SHA-256 of
its canonical content, which includes the exact HEAD). The plan is
closed-shape canonical JSON; two runs over identical inputs are
byte-identical.

| Class | Origin | Content |
| --- | --- | --- |
| `MANDATORY` | `issue-contract` | Every command in the Issue's Required tests section, automatically included. |
| `REGRESSION` | `regression-discovery` | Every `tools/*/tests/test_*.py` unittest suite tracked at HEAD. |
| `GENERATED` | `generated-proposal` | Accepted proposals only; always archive-isolated. |
| `ADVERSARIAL` | `planner-builtin` | `git diff --check` between base and HEAD plus one byte-immutability probe per forbidden pattern. |
| `STATIC` | `planner-builtin` | JSON well-formedness of every tracked governance schema and compilation of changed python files. |
| `ROLLBACK` | `planner-builtin` | The declared base exists and is an ancestor of HEAD, so reverting to base is well-defined. |

Planning fails closed when the declared base drifts from the Issue
contract, when the scope report binds a different base/head or Issue body,
when the scope report verdict is not `PASS` (a non-`PASS` scope can never
produce an executable plan), or when a required test violates the command
policy.

## Command policy

Commands are argv vectors executed without a shell. The policy allows only:

- `python3 -m {unittest, json.tool, py_compile, compileall}` (never `-c`,
  never script paths). Path material is restricted: absolute paths,
  home-relative paths and any `..` component are rejected, including
  inside combined `--option=value` tokens, at planning time and again by
  the executor immediately before execution;
- read-only git subcommands (`diff`, `status`, `rev-parse`, `ls-files`,
  `ls-tree`, `cat-file`, `merge-base`) with a positive per-subcommand
  option allowlist (for `diff` only `--check` and `--quiet`). Every other
  option token is rejected, so write-capable or helper-executing options
  (`--output`, `--ext-diff`, `--textconv`, `-G`, `-S`, `--find-object`,
  prefix rewriting, `-c`, `--git-dir`, `--exec-path`, …) never execute.

Shell control tokens, network-capable tools (`curl`, `wget`, `ssh`, `gh`,
`pip`, `npm`, …) and any other executable are rejected. The single accepted
redirection is a trailing `>/dev/null`, normalised into the boolean
`discard_stdout` field.

The active policy is described by a deterministic descriptor whose SHA-256
is recorded in the plan and echoed by the report as
`command_policy_sha256`. The executor recomputes the hash before running
anything: a plan produced under a different policy is invalidated and can
only yield an `ERROR` report.

## Execution

The executor re-validates everything before running anything: strict JSON
with duplicate-key rejection, canonical-bytes equality, closed shape with
unknown fields rejected, identifier integrity, command policy and resource
bounds. A structurally invalid plan produces no report and exits `3`.

A structurally valid plan is then bound to reality: Issue body hash, scope
report hash and `PASS` verdict, command policy hash, base/head binding,
exact repository HEAD and a clean worktree. Any drift — a new commit, a
dirty worktree, a changed Issue, scope report, base, diff or policy —
invalidates the plan: the report is written with verdict `ERROR`, a
`PLAN`-category `styx.test-failure/v1` entry (`plan_invalidated`) and
every class verdict `NOT_RUN`.

Network denial is fail-closed. The executor resolves bubblewrap to an
absolute path (fixed system locations first, then `PATH`) and, before any
check runs, probes that the binary actually starts and can establish the
`--unshare-net` namespace; a missing binary, a probe that does not start
or a probe that exits non-zero stops execution before the first check,
producing an `ERROR` report with a `sandbox_unavailable` entry and every
class verdict `NOT_RUN`. There is no unsandboxed fallback path for any
command. Defending against a local administrator who replaces the
bubblewrap binary (same-host compromise) is explicitly out of scope for
the declared threat model. Real namespace isolation is exercised by an
integration test that runs the actual bubblewrap binary where the host
supports it; the deterministic sandbox stub used by the unit suite is
wiring-level only and is not evidence of isolation.

Preparation failures fail closed as well: any error while materialising
the pristine `git archive` copy for `GENERATED` checks (archive, tar
extraction, timeout, I/O), while resolving path containment, or while
creating the scratch environment produces a structured, sanitized
`styx.test-failure/v1` entry with observed class `preparation_error` and
an `ERROR` report; once preparation has failed, no further
archive-isolated check is attempted.

Checks run with:

- a scratch `HOME` and `TMPDIR`, masking `~/.ssh`, `~/.netrc`,
  `~/.git-credentials` and `~/.config/gh`;
- an environment built from scratch (only `PATH` is inherited), so no
  credential variable can leak;
- mandatory `bwrap --unshare-net` network denial with the repository
  mounted read-only;
- runtime hardening of executed `git diff` commands: the executor forces
  `--no-ext-diff` and `--no-textconv`, sets `GIT_EXTERNAL_DIFF` to the
  empty string and explicitly neutralizes a repository-local
  `diff.external` (`-c diff.external=`), while global and system
  configuration and the pager are already disabled. The plan itself may
  only carry `--check`/`--quiet`;
- a runtime path-containment check for python arguments: every existing
  path is resolved (following symlinks) and must stay inside the execution
  root, so a committed symlink cannot reach the primary worktree;
- a per-check timeout and per-stream output caps enforced during
  execution: stdout/stderr are read incrementally into bounded buffers and
  never accumulate beyond `max_output_bytes` per stream. Exceeding a cap
  or the deadline kills the whole process group (checks run in their own
  session; bubblewrap adds `--die-with-parent` for its children);
- for `GENERATED` checks, a pristine `git archive` copy of HEAD, so
  generated tests can never touch the primary worktree.

## Classification

Per check: exit `0` is `PASS`; a non-zero exit is `FAIL`
(`nonzero_exit`); timeout, output overflow, missing tool, rejected
command, unavailable sandbox, preparation failures and internal faults
are `ERROR`. Per class:
`ERROR` beats `FAIL` beats `PASS`; a class with no checks is `NOT_RUN`.
Overall: any `ERROR` class gives `ERROR`, any `FAIL` class gives `FAIL`,
and `PASS` additionally requires `mandatory_verdict == PASS`. `FAIL` and
`ERROR` can never become `PASS`.

The admitted verdict combinations are frozen and exhaustive; documents
violating them are rejected wherever evidence is consumed:

- `PASS` ⇔ no failure entries, `mandatory_verdict == PASS`, and every
  class verdict (generated and every other optional class included) in
  {`PASS`, `NOT_RUN`};
- `FAIL` ⇔ at least one class verdict `FAIL`, no class verdict `ERROR`,
  `mandatory_verdict` in {`PASS`, `FAIL`}, no plan-level entry;
- `ERROR` ⇔ at least one class verdict `ERROR`, or a `PLAN`-category
  failure entry, or an unexecuted mandatory class.

Per class: `PASS`/`NOT_RUN` admit no failure entries of that class;
`FAIL` requires at least one `FAIL` entry and admits only `FAIL`
entries; `ERROR` requires at least one `ERROR` entry. Plan-level entries
are `ERROR`-only and admit no executed class.

Every non-`PASS` check yields a `styx.test-failure/v1` entry with the
stable test identifier, category, expected outcome, observed class, a safe
reproduction reference (plan hash, check identifier, argv) and bounded
SHA-256 stdout/stderr hashes computed over exactly the captured — possibly
truncated — content. The reproduction argv is sanitized before it enters
the report with explicit, shape-specific patterns only: `key=value`
assignments and `--name=value`/`--name value` forms whose name contains
`token`, `password`, `passwd`, `secret`, `api_key`, `access_key`,
`client_secret`, `private_key`, `authorization`, `credential` or
`bearer` (a `Bearer`/`Token`/`Basic` scheme word between the name and the
secret is preserved while the secret itself is fully redacted, e.g.
`--authorization Bearer [REDACTED]`); `Authorization: Bearer/Token`
headers; GitHub token shapes
(`ghp_…`, `github_pat_…`); AWS key IDs (`AKIA…`/`ASIA…`); Slack tokens
(`xoxa/xoxb/xoxp/xoxs-…`); JWTs; URLs with embedded credentials; and
known credential file paths. No generic entropy heuristic is applied, so
commit SHAs, digests and other legitimate identifiers are never
obscured. Raw output never enters the evidence, so secrets cannot leak
through reports.

## Review eligibility

```text
review_eligible =
  test_report.verdict == PASS
  AND test_report.head_sha == candidate_head_sha
  AND scope_report.verdict == PASS
  AND scope_report.head_sha == candidate_head_sha
```

The `eligibility` subcommand applies exactly this rule (exit `0` eligible,
`2` not eligible) — but only after strictly validating both evidence
documents at runtime, without a general JSON Schema engine: canonical
JSON with duplicate keys rejected, closed shape with every required field
present and no extra fields, exact field types (a boolean is never
accepted where an integer is required), schema identifiers, verdict
enums, per-entry failure validation and the frozen verdict-combination
rules above. The scope report is validated against its own frozen
interface with the same rigour, including the complete
`changed_entries`/`diagnostics` structure. The evidence pair is then
cross-bound: the scope report bytes must hash to the test report's
`scope_report_sha256`, the report's `command_policy_sha256` must match
the active policy, and both documents must bind the same issue, base,
HEAD and Issue body (`issue_body_sha256` equality is mandatory).
Minimal, tampered, non-canonical or inconsistent documents are rejected
with exit `3`, never treated as eligible or silently ineligible.
Because both reports bind the exact HEAD and the plan binds Issue body,
scope evidence and base, a new commit or any changed input invalidates
the previous evidence and review eligibility with it.

## Usage

```bash
python3 tools/test-orchestrator/orchestrator.py plan \
  --issue-number 54 --issue-body-file /outside/issue.md \
  --scope-report /outside/scope-report.json \
  --base-sha <base> --head-sha <head> \
  --execution-id <id> --repo <worktree> --output /outside/test-plan.json

python3 tools/test-orchestrator/orchestrator.py execute \
  --plan /outside/test-plan.json --issue-body-file /outside/issue.md \
  --scope-report /outside/scope-report.json \
  --repo <worktree> --output /outside/test-report.json

python3 tools/test-orchestrator/orchestrator.py eligibility \
  --test-report /outside/test-report.json \
  --scope-report /outside/scope-report.json --head-sha <candidate>
```

Exit codes follow the repository convention: `0` PASS, `2` FAIL, `3`
ERROR. Evidence outputs must live outside the tested repository; the tool
refuses anything else.

## Rollback

- R0 — remove `tools/test-orchestrator/`, this document and the three
  schemas. The existing runner and CI evidence flow are untouched: nothing
  else imports the orchestrator.
- R1 — retain the schemas and test fixtures while disabling the
  planner/executor entrypoints (remove or guard `orchestrator.py`).

## Residual risks

- Generated tests may be incomplete or overfit; review must assess plan
  adequacy rather than assume coverage.
- Language-specific and expensive integration suites (Dart, JS, Go) need
  later execution plugins and resource policies; today they surface only
  through the Issue's Required tests.
- A production model-backed planner requires a separate credential,
  privacy and deployment gate.
- Bubblewrap is a hard operational dependency: hosts without a working
  `bwrap` cannot execute plans (every run is an `ERROR` with
  `sandbox_unavailable`); runner integration and evidence publication
  remain separate tasks.
- Same-host compromise is out of scope by declared threat model: a local
  administrator who can replace the bubblewrap binary, the git binary or
  the orchestrator itself defeats any in-process guarantee; the defence
  for that layer is host integrity, not this tool.
