# Review gate and structured remediation loop

Isolated, versioned, fail-closed review gate for Styx task branches. It turns
green technical evidence plus an independent reviewer decision into a canonical
review report, and turns a change-requesting review into a canonical, actionable
remediation request. It never executes tests, never runs git, never touches the
network or credentials, never calls GitHub and never writes inside the reviewed
repository.

This document is normative for the tool under `tools/review-gate/` and the two
schemas it owns:

- `docs/governance/schemas/review-report-v1.schema.json` (`styx.review-report/v1`)
- `docs/governance/schemas/remediation-request-v1.schema.json` (`styx.remediation-request/v1`)

The test schemas (`styx.test-plan/v1`, `styx.test-report/v1`,
`styx.test-failure/v1`) and the scope schema (`styx.task-scope-report/v1`) are
owned elsewhere and are consumed here strictly read-only.

## Pipeline position

```text
scope guard        →  styx.task-scope-report/v1  (verdict PASS)
test orchestrator  →  styx.test-report/v1        (verdict PASS)
review gate        →  styx.review-report/v1      (this tool)
review gate        →  styx.remediation-request/v1 (when changes are requested)
```

A review may only start once both the scope report and the test report are
present, valid and `PASS`, and every binding below matches. Any new
implementation commit invalidates all prior scope, test and review evidence and
requires a fresh `scope → test → review` cycle.

## Commands

```bash
# Emit a review report from evidence and a reviewer request.
python3 tools/review-gate/review_gate.py review \
  --review-request  review-request.json \
  --scope-report    scope-report.json \
  --test-report     test-report.json \
  --output          /path/outside/repo/review-report.json
# optional: --issue-body-file issue-body.txt  --repo-root /path/to/checkout

# Turn a change-requesting review report into a remediation request.
python3 tools/review-gate/review_gate.py remediate \
  --review-report   review-report.json \
  --round           1 \
  --output          /path/outside/repo/remediation-request.json
```

Exit codes: `0` accepting review (`GO`/`GO_WITH_CONDITIONS`) or successful
remediation; `2` a review that requests changes or blocks
(`CHANGES_REQUESTED`/`BLOCKED`); `3` any fail-closed error, in which case **no**
output is written. Every unexpected condition maps to `3`; the entrypoint never
propagates an unhandled exception.

## Review request (input)

The reviewer authors a closed-shape JSON request. Unknown or duplicate keys are
rejected. Shape:

```json
{
  "candidate": {
    "repository": "styx-secure/styx",
    "issue_number": 55,
    "issue_body_sha256": "<64-hex>",
    "base_sha": "<40-hex>",
    "head_sha": "<40-hex>",
    "diff_sha256": "<64-hex>",
    "implementer_execution_id": "<string>",
    "implementer_context_id": "<string>"
  },
  "reviewer": {
    "reviewer_class": "HUMAN | DELEGATED_AGENT",
    "execution_id": "<string>",
    "context_id": "<string>",
    "identity_ref": "<string>"
  },
  "verdict": "GO | GO_WITH_CONDITIONS | CHANGES_REQUESTED | BLOCKED",
  "findings": [
    {
      "severity": "BLOCKER | HIGH | MEDIUM | LOW | INFO",
      "component_path": "repo/relative/path",
      "problem": "<what is wrong>",
      "required_behavior": "<what must hold instead>",
      "required_test": "<required or missing test>",
      "acceptance_criterion": "<how the fix is judged done>",
      "lifecycle": "OPEN | ADDRESSED_PENDING_REVERIFY | RESOLVED | WAIVED_BY_HUMAN",
      "required_fix": true
    }
  ]
}
```

The candidate is the reviewer's declared identity of what is under review,
established from a **separate read-only checkout**. The gate itself performs no
git operation: it binds the declared candidate to the evidence and fails closed
on any divergence.

## Review precondition

A review starts only when every one of these holds; otherwise the gate exits `3`
and writes nothing:

- scope report present, valid, `verdict == PASS`;
- test report present, valid, `verdict == PASS`;
- test report is cross-linked to the exact scope report
  (`test.scope_report_sha256 == sha256(scope bytes)`);
- scope and test reports agree on Issue, base, HEAD and Issue-body hash;
- the declared candidate agrees with the evidence on Issue, base, HEAD and
  Issue-body hash (exact-HEAD binding);
- optional `--issue-body-file` hashes to the candidate `issue_body_sha256`;
- the reviewer is independent (see below).

Any missing, ambiguous, duplicated, malformed, stale or cross-linked field fails
closed. "Stale" is any evidence whose HEAD differs from the candidate HEAD.

## Reviewer independence

Exactly two reviewer classes are supported: `HUMAN` and `DELEGATED_AGENT`. For
both, the review fails closed unless:

- `reviewer.execution_id != candidate.implementer_execution_id` (no self-review,
  no reused implementer identity);
- `reviewer.context_id != candidate.implementer_context_id` (no reused
  implementer context).

A `DELEGATED_AGENT` additionally carries an explicit `identity_ref` and can never
waive a finding: any `WAIVED_BY_HUMAN` finding requires `reviewer_class == HUMAN`,
which in particular denies delegated waivers of `BLOCKER` and `HIGH` findings.

## Verdicts and findings

Verdicts: `GO`, `GO_WITH_CONDITIONS`, `CHANGES_REQUESTED`, `BLOCKED`.

An open finding is one whose lifecycle is `OPEN` or `ADDRESSED_PENDING_REVERIFY`.
A severe-or-required open finding is an open finding with severity `BLOCKER` or
`HIGH`, or with `required_fix == true`.

- `GO` and `GO_WITH_CONDITIONS` are **invalid** while any severe-or-required open
  finding exists. The contract fixes this rule for `GO`; the gate applies it to
  `GO_WITH_CONDITIONS` as well, fail-closed, because an acceptance cannot coexist
  with an open blocker. Lower-severity open findings are the "conditions".
- `CHANGES_REQUESTED` and `BLOCKED` require at least one open finding.
- `remediation_required` is `true` exactly for `CHANGES_REQUESTED`.

Finding severities: `BLOCKER`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Finding lifecycle:
`OPEN`, `ADDRESSED_PENDING_REVERIFY`, `RESOLVED`, `WAIVED_BY_HUMAN`.

Each finding receives a **stable canonical identifier**:
`sha256` over the canonical JSON of `{component_path, problem, required_behavior,
severity}`. Identical semantics hash identically across remediation rounds,
independent of lifecycle or acceptance-criterion edits, so a finding can be
tracked to resolution. Two findings that collapse to the same identifier are
rejected.

## Review report (output)

`styx.review-report/v1` is canonical (RFC8259, sorted keys, UTF-8, LF, no
timestamp), closed-shape and exact-HEAD-bound. It records the repository, Issue,
base, HEAD, Issue-body hash, diff hash, the scope- and test-report hashes, both
technical verdicts (`PASS`), the reviewer class and identity, the implementer
identity, the independence flag, the verdict, the findings and whether
remediation is required. Its own hash (`sha256` of the canonical bytes) binds any
remediation derived from it.

## Remediation request (output)

`styx.remediation-request/v1` is produced from a review report whose verdict is
not an acceptance and which carries at least one open finding. Each item records
the finding identifier, severity, normalized component/path, problem, required
behavior, required or missing test, acceptance criterion, the originating
review-report hash and the remediation-round identifier. The request also carries
the exact-HEAD binding (repository, Issue, base, HEAD, Issue-body hash, diff
hash) so a remediation verified against an old commit can never be reused after a
new candidate HEAD.

Rounds are explicit positive integers. Re-running with a higher `--round` over
the same review report reproduces the same finding identifiers under a new round.

## Invalidation

A prior acceptance still applies only if the repository, Issue, base, HEAD,
Issue-body hash and diff hash are all unchanged (`acceptance_still_valid`). A new
candidate HEAD or diff invalidates any prior scope evidence, test evidence,
review report, `GO` verdict and remediation verified on the old HEAD. After any
implementation change a completely fresh `scope → test → review` cycle is
required.

## Security and determinism properties

- JSON closed-shape with unknown-field and duplicate-key rejection.
- Canonical serialization and deterministic hashing; timestamps omitted.
- Atomic writes to a single caller-chosen output path outside the repository.
- Symlink and path-replacement rejection on every input and on the output path.
- Component-path normalization rejects absolute, home-relative, traversal and
  backslash paths.
- Secret redaction on every free-text and identity field; commit SHAs and
  digests are never redacted.
- Fail-closed exception mapping; the entrypoint raises nothing uncaught.
- No network, no credentials, no GitHub call, no test execution, and no write
  inside the reviewed repository (hence no implementation-branch modification).

## Independent review and human gate

This tool records review evidence; it does not replace independent human review
or the human merge gate. Producing a `GO` review report is necessary but not
sufficient for integration: a separate clean-context security review and explicit
human authorization remain required before any Draft PR, GitHub publication,
Ready, approval or merge.

## Rollback

- **R0** — remove `tools/review-gate/`, this document and the two schemas without
  touching the runner, broker, test orchestrator or any GitHub state.
- **R1** — retain the schemas and fixtures while disabling the `review` and
  `remediate` entrypoints.
