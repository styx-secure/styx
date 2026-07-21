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
  --repo-root       /path/to/reviewed/checkout \
  --output          /path/outside/repo/review-report.json
# optional: --issue-body-file issue-body.txt

# Turn a change-requesting review report into a remediation request.
python3 tools/review-gate/review_gate.py remediate \
  --review-report   review-report.json \
  --round           1 \
  --repo-root       /path/to/reviewed/checkout \
  --output          /path/outside/repo/remediation-request.json
```

`--repo-root` is **required** by both writing subcommands: see
[Output containment](#output-containment).

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

### What the declared candidate is trusted for

The review request is reviewer-authored input, so it is trusted only where it is
checked against evidence. Three levels apply:

| Field | Status | Basis |
| --- | --- | --- |
| `base_sha`, `head_sha` | **Authoritative** | Stated independently by the scope and test reports; must match exactly. |
| `implementer_execution_id` | **Evidence-derived** | Must exactly restate the evidence `execution_id`; never believed on its own. |
| `issue_number`, `issue_body_sha256` | **Authoritative** | Must match the evidence. |
| `diff_sha256` | **Advisory** | Unauthenticated; see [Advisory fields](#advisory-fields). |
| `implementer_context_id` | **Advisory** | Unanchored; defence in depth only. |

## Review precondition

A review starts only when every one of these holds; otherwise the gate exits `3`
and writes nothing:

- scope report present, valid, `verdict == PASS`;
- test report present, valid, `verdict == PASS`;
- test report is cross-linked to the exact scope report
  (`test.scope_report_sha256 == sha256(scope bytes)`);
- scope and test reports agree on Issue, base, HEAD, Issue-body hash and
  `execution_id`;
- the declared candidate agrees with the evidence on Issue, base, HEAD and
  Issue-body hash (exact-HEAD binding);
- the declared `implementer_execution_id` exactly restates the evidence
  `execution_id` (see [Implementer identity binding](#implementer-identity-binding));
- optional `--issue-body-file` hashes to the candidate `issue_body_sha256`;
- the reviewer is independent (see below).

Any missing, ambiguous, duplicated, malformed, stale or cross-linked field fails
closed. "Stale" is any evidence whose HEAD differs from the candidate HEAD.

## Implementer identity binding

An independence check is only as trustworthy as the implementer identity it
compares against, so that identity is **derived from the evidence, never from the
review request**. Before any independence rule is applied:

1. the authoritative implementer identity is the `execution_id` carried by the
   evidence. `load_evidence` requires
   `scope_report.execution_id == test_report.execution_id`: a pair that
   disagrees about who produced the candidate describes no single execution and
   yields no identity at all;
2. `candidate.implementer_execution_id` must **exactly** equal that value. It is
   accepted only as a restatement, never as a source;
3. any mismatch fails closed with `E_IDENTITY` before independence is evaluated;
4. the emitted report records the evidence-derived value.

Without step 2 a self-reviewing implementer could declare a decoy
`implementer_execution_id`, differ from it trivially, and obtain `GO` on its own
work — the independence check would be comparing the reviewer against a value the
reviewer itself chose. `execution_id` is consumed from the authoritative
`styx.task-scope-report/v1` shape declared on the base; this task neither
redefines nor extends it.

### Canonical identifiers

Every execution and context identifier — in the evidence, the candidate and the
reviewer — must match:

```text
^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$
```

An ASCII alphanumeric first character, then ASCII alphanumerics and `-`, `_`,
`.`, up to 128 characters. Anything else fails closed: empty values, leading or
trailing whitespace, embedded whitespace, control bytes, and **all** non-ASCII
text — which is what excludes Unicode confusables such as a Cyrillic `е`
(U+0435) dressed as an ASCII `e`.

Rejecting is deliberate, and normalization is deliberately avoided: a folding
rule (NFKC, confusable folding) could map two genuinely different agents onto
one identity, which is a worse failure than refusing an odd-looking one.
Restricting the alphabet achieves the same protection without ever merging
distinct parties.

Case is handled asymmetrically, and in both directions the effect is to reject
more rather than accept more:

- **Bindings are exact.** `Issue-55-Implementer-01` does not restate evidence
  reading `issue-55-implementer-01`; it fails closed.
- **Distinctness checks fold ASCII case.** A reviewer cannot escape self-review
  detection by re-typing the implementer's id in different case. Both operands
  are pure ASCII by the rule above, so the fold is unambiguous.

## Reviewer independence

Exactly two reviewer classes are supported: `HUMAN` and `DELEGATED_AGENT`. For
both, the review fails closed unless:

- `reviewer.execution_id` does not conflict with the **evidence-derived**
  implementer execution id (no self-review, no reused implementer identity);
- `reviewer.context_id` does not conflict with
  `candidate.implementer_context_id` (no reused implementer context).

The context check is defence in depth only: the frozen evidence interface
carries no context id, so unlike the execution id it has no evidence anchor, and
no acceptance rests on it alone. No weak substitute is invented for it.

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

### Severe findings may not be self-cleared by a delegated agent

A bare `RESOLVED` lifecycle is an assertion, not evidence. Because `RESOLVED`
findings are excluded from the open/severe evaluation above, a delegated agent
could otherwise record a `BLOCKER`, mark it `RESOLVED`, and take `GO` on the very
same HEAD — no fix, no new evidence, no re-verification — which is the waiver
denial defeated in all but name.

Therefore, for `reviewer_class == DELEGATED_AGENT`, `GO` and `GO_WITH_CONDITIONS`
fail closed whenever **any** finding with severity `BLOCKER` or `HIGH`, or with
`required_fix == true`, carries lifecycle `RESOLVED`. In this version:

- final resolution of a severe or required-fix finding is **reserved to a
  `HUMAN`** reviewer;
- `OPEN` and `ADDRESSED_PENDING_REVERIFY` continue to block acceptance for every
  reviewer class;
- `WAIVED_BY_HUMAN` remains impossible for a delegated agent;
- `required_fix == true` blocks acceptance until the finding is resolved by a
  party entitled to resolve it;
- a delegated agent may still **record** a severe `RESOLVED` finding under a
  non-accepting verdict (`CHANGES_REQUESTED`, `BLOCKED`): keeping history is
  fine, accepting on it is not.

This is stricter than the eventual goal, on purpose. Proving a genuine
cross-round re-verification would require binding a resolution to a prior
review-report hash, a strictly newer candidate HEAD and fresh evidence of the
fix. The v1 shapes carry none of those fields, and inventing a weak binding that
merely *looked* like proof would be worse than admitting the gap. When the
schemas can express a verifiable re-verification, this rule can be relaxed to
accept it; until then it fails closed.

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

## Output containment

The gate's only side effect is one atomic write of one canonical document. The
"never writes inside the reviewed repository" property is contractual, so it is
enforced fail-closed and cannot be opted out of:

- `--repo-root` is **required** by every writing subcommand (`review`,
  `remediate`). Omitting it is a usage error: parsing fails with exit `3` and
  **nothing** is created — no output, no parent directory, no temporary file. It
  is not optional, because a protection a caller can disable by leaving out a
  flag is not a protection.
- The root must be an absolute, existing directory. A non-existent root is
  refused: believing one would let a caller re-enable the write by naming a
  directory at random.
- Root and output are compared **fully resolved**, so containment cannot be
  evaded through a symlink in either direction. Output equal to the root, or
  anywhere beneath it, is refused.
- Relative paths and paths containing `..` are refused rather than guessed at:
  their meaning depends on the caller's working directory.
- A symlinked output, or any symlinked ancestor of it, is refused (checked on
  the literal path, since resolution would follow the link silently).
- Independently of the declared root, an output inside **any** detected git
  working tree is refused. This closes the residual case of a caller that
  declares one root while writing into a different checkout — a required flag
  alone cannot stop a caller from lying about it. Detection inspects the
  filesystem for a `.git` directory or file among the output's ancestors; the
  gate still never runs git and never reads repository contents.

A consequence worth stating: if `TMPDIR` itself lies inside a git working tree,
the gate refuses to write there. That is the intended answer, not a defect.

## Advisory fields

Two fields are recorded but are **not** evidence, and no security decision may
rest on either.

`diff_sha256` is unauthenticated reviewer input. The consumed frozen evidence
interface carries no diff digest, so there is no bound source to verify it
against; deriving a trustworthy one would require a diff hash inside the
evidence, which this task does not own. The authoritative binding of the code
state is `base_sha` + `head_sha`, each stated independently by the scope and test
reports and matched exactly against the candidate; the diff itself is derivable
from `base..head`. Concretely, the digest:

- cannot make invalid or stale evidence valid;
- cannot substitute for, or alter the outcome of, the base/HEAD binding;
- cannot rescue an acceptance whose HEAD has moved;
- participates in invalidation in one direction only — a *changed* digest may
  additionally invalidate a prior acceptance, but a matching one never validates
  anything on its own.

It may be used for correlation, or to invalidate, only when it comes from the
same authoritative context that produced the base/HEAD binding.

`implementer_context_id` is likewise unanchored: the evidence carries no context
id. It is kept as defence in depth (a reviewer reusing the implementer's context
id is rejected) but, unlike the execution id, nothing rests on it alone.

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
- Atomic writes to a single caller-chosen output path outside the repository,
  with a mandatory `--repo-root` and git-working-tree detection
  ([Output containment](#output-containment)); a failed write leaves no
  temporary or partial file behind.
- Reviewer independence decided against an evidence-derived implementer
  identity, over a restricted ASCII identifier alphabet
  ([Implementer identity binding](#implementer-identity-binding)).
- Severe findings cannot be self-cleared to `RESOLVED` by a delegated agent.
- Symlink and path-replacement rejection on every input and on the output path.
- Component-path normalization rejects absolute, home-relative, traversal and
  backslash paths.
- Secret redaction on every free-text and identity field; commit SHAs and
  digests are never redacted.
- Fail-closed exception mapping; the entrypoint raises nothing uncaught.
- No network, no credentials, no GitHub call, no test execution, and no write
  inside the reviewed repository (hence no implementation-branch modification).

## Known limits

Stated explicitly so they are not mistaken for guarantees:

- **No cross-round re-verification.** The v1 shapes cannot express "this finding
  was re-verified against review report X at HEAD Y with fresh evidence". Until
  they can, a delegated agent cannot finally resolve a severe finding at all;
  such resolutions require a `HUMAN`.
- **Identity is asserted, not authenticated.** The gate binds the implementer
  identity to the evidence, which prevents a reviewer from inventing one; it
  does not prove that the party behind an `execution_id` is who it claims to be.
  Production identity binding is separately authorized work.
- **`diff_sha256` and `implementer_context_id` are advisory**
  ([Advisory fields](#advisory-fields)).
- **Reviewer quality is out of scope.** Schema validation cannot judge whether a
  review was any good; persona and delegation controls remain necessary.
- **Evidence trust is inherited.** The gate consumes the scope and test reports
  as given. It re-validates their shape and cross-binding, but their integrity
  is the producing tool's responsibility.

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
