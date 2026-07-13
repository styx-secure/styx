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
or when a required test violates the command policy.

## Command policy

Commands are argv vectors executed without a shell. The policy allows only:

- `python3 -m {unittest, json.tool, py_compile, compileall}` (never `-c`,
  never script paths, never absolute paths);
- read-only git subcommands (`diff`, `status`, `rev-parse`, `ls-files`,
  `ls-tree`, `cat-file`, `merge-base`) with configuration and path
  overrides (`-c`, `--git-dir`, `--exec-path`, …) rejected.

Shell control tokens, network-capable tools (`curl`, `wget`, `ssh`, `gh`,
`pip`, `npm`, …) and any other executable are rejected. The single accepted
redirection is a trailing `>/dev/null`, normalised into the boolean
`discard_stdout` field.

## Execution

The executor re-validates everything before running anything: strict JSON
with duplicate-key rejection, canonical-bytes equality, closed shape with
unknown fields rejected, identifier integrity, command policy and resource
bounds. A structurally invalid plan produces no report and exits `3`.

A structurally valid plan is then bound to reality: Issue body hash, scope
report hash, base/head binding, exact repository HEAD and a clean worktree.
Any drift — a new commit, a dirty worktree, a changed Issue, scope report,
base, diff or policy — invalidates the plan: the report is written with
verdict `ERROR`, a `PLAN`-category `styx.test-failure/v1` entry
(`plan_invalidated`) and every class verdict `NOT_RUN`.

Checks run with:

- a scratch `HOME` and `TMPDIR`, masking `~/.ssh`, `~/.netrc`,
  `~/.git-credentials` and `~/.config/gh`;
- an environment built from scratch (only `PATH` is inherited), so no
  credential variable can leak;
- `bwrap --unshare-net` network denial with the repository mounted
  read-only whenever bubblewrap is available; the command allowlist keeps
  execution offline-only even without it;
- per-check timeout and output byte limits;
- for `GENERATED` checks, a pristine `git archive` copy of HEAD, so
  generated tests can never touch the primary worktree.

## Classification

Per check: exit `0` is `PASS`; a non-zero exit is `FAIL`
(`nonzero_exit`); timeout, output overflow, missing tool, rejected command
and internal faults are `ERROR`. Per class: `ERROR` beats `FAIL` beats
`PASS`; a class with no checks is `NOT_RUN`. Overall: any `ERROR` class
gives `ERROR`, any `FAIL` class gives `FAIL`, and `PASS` additionally
requires `mandatory_verdict == PASS`. `FAIL` and `ERROR` can never become
`PASS`.

Every non-`PASS` check yields a `styx.test-failure/v1` entry with the
stable test identifier, category, expected outcome, observed class, a safe
reproduction reference (plan hash, check identifier, argv) and bounded
SHA-256 stdout/stderr hashes. Raw output never enters the evidence, so
secrets cannot leak through reports.

## Review eligibility

```text
review_eligible =
  test_report.verdict == PASS
  AND test_report.head_sha == candidate_head_sha
  AND scope_report.verdict == PASS
  AND scope_report.head_sha == candidate_head_sha
```

The `eligibility` subcommand applies exactly this rule (exit `0` eligible,
`2` not eligible). Because both reports bind the exact HEAD and the plan
binds Issue body, scope evidence and base, a new commit or any changed
input invalidates the previous evidence and review eligibility with it.

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
- Without bubblewrap the network-denial guarantee degrades to the command
  allowlist; runner integration and evidence publication remain separate
  tasks.
