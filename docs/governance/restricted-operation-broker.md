# Restricted-Operation Broker v1

Status: implementation of Issue #53 (`area:governance`, `risk:high`,
`gate:human-required`, `gate:security-review`). Base
`main @ f5b6e0c70b08b23b3bd299228dd669090546e0e6`.

The broker is an isolated, versioned, **deny-by-default** core that validates
trusted task evidence and exposes exactly two **simulated** operations. It
performs no runner integration, no live GitHub operation, no credential handling
and no network access. It is the agent-facing authority boundary: even when a
future production credential holds broader scopes, this allowlist stays the
outer limit of what an agent may request.

## Operations (frozen)

```text
push_task_branch
open_draft_pr
```

Every other operation identifier fails closed with `DENIED_POLICY`. The request
carries `operation` as a plain string; only `broker.py` dispatches it, so an
unknown value is a policy denial (not a request-shape error).

## Documents (frozen, closed-shape)

| Identifier | Schema file |
|---|---|
| `styx.restricted-broker-request/v1` | `docs/governance/schemas/restricted-broker-request-v1.schema.json` |
| `styx.restricted-broker-response/v1` | `docs/governance/schemas/restricted-broker-response-v1.schema.json` |
| `styx.restricted-broker-audit/v1` | `docs/governance/schemas/restricted-broker-audit-v1.schema.json` |

Result classes: `SUCCESS`, `DENIED_POLICY`, `DENIED_EVIDENCE`,
`CONFLICT_IDEMPOTENT`, `AUTH_UNAVAILABLE`, `REMOTE_FAILURE`, `INTERNAL_ERROR`.

The request is minimal: `operation`, `issue_number`, `execution_id`,
`idempotency_key`, and the three evidence documents. Repository, owner, target
ref, base, force, tag and PR mode are **derived** from validated evidence and
fixed policy — never accepted from the request.

## Consumed evidence shapes

The broker re-implements strict closed-shape binders (it never imports runtime
code from forbidden paths). Each document must carry exactly its real top-level
key set; fields the broker binds are deeply type-checked. Deep validation of
fields the broker does not consume (for example runner `environment.tools`) is
out of scope for v1.

- **`styx.task-scope-report/v1`** — consumed: `schema`, `issue_number`,
  `execution_id`, `base_sha`, `head_sha`, `issue_body_sha256`, `verdict` (must
  be `PASS`). (Schema file exists at base.)
- **`styx.agent-runner-status/v1`** — consumed: `schema`, `execution_id`,
  `repository.{expected,verified}`, `issue.{number,body_sha256}`,
  `base.declared_sha`, `worktree.branch`, `tests[].state` (all `PASS`),
  `scope_guard.verdict` (`PASS`), `terminal_status`
  (`BLOCKED_BROKER_UNAVAILABLE`). (Schema file exists at base.)
- **`styx.agent-hook-attestation/v1`** — no schema file exists at the base. The
  exact field set is the *final* snapshot emitted by
  `.claude/hooks/styx_guard.py::_snapshot`: `schema`, `issue_number`,
  `terminal_status`, `active_state_sha256`, `status_report`,
  `status_report_sha256`, `worktree`, `branch`, `base_sha`, `head_sha`,
  `scope_report`, `scope_report_sha256`, `changed_paths`. The broker binds to
  this real shape without adding a new schema file (outside the allowlist).

### Cross-binding (all required)

`issue_number` across request/scope/runner/attestation; `execution_id` across
request/scope/runner; `base_sha` across scope/runner/attestation; `head_sha`
across scope/attestation; `branch` across runner/attestation; issue-body hash
across scope/runner; and the attestation's `status_report_sha256` /
`scope_report_sha256` must equal the sha256 of the canonical runner-status /
scope-report bytes. Any mismatch, non-PASS evidence, non-final attestation,
unknown/missing top-level key, or duplicate JSON key fails closed with
`DENIED_EVIDENCE`.

## Policy derivation

`repository = styx-secure/styx`; `branch` must match `^task/{issue}-[a-z0-9-]+$`
and equal the runner/attestation branch; `base_sha`/`head_sha` from evidence;
`force = false`, `draft = true`, `tag = null` are constants. PR title and body
are a fixed deterministic template derived only from `issue_number` and
`branch`; no free text is accepted from the request.

## Pipeline

```text
parse (reject dup keys / non-object)
→ build request (reject unknown fields; operation stays a string)
→ explicit dispatch (unknown → DENIED_POLICY)
→ validate evidence (closed-shape + cross-binding + doc hashes)
→ bind request issue_number/execution_id to evidence
→ derive policy target
→ atomic idempotency begin()
    · CONFLICT → CONFLICT_IDEMPOTENT (same key, different request)
    · PENDING  → CONFLICT_IDEMPOTENT (same key, concurrent/incomplete reservation)
    · REPLAY   → recorded terminal outcome (no fake call), new audit record + new audit_id
→ fresh evidence revalidation (re-parsed from canonical bytes)
→ fresh local repository-state revalidation
    · any pre-call failure → abort() the reservation (key stays retryable)
→ fake client call (non-force publish / Draft-only PR)
→ idempotency complete() → terminal recorded outcome (success OR client failure)
→ audit append (one record per attempt) → response
```

The revalidation before the side effect re-parses the evidence from immutable
canonical bytes and, additionally, checks the **real** local repository state:
repository, worktree, branch, HEAD, declared **base SHA** (bound to the target
base, not a context-free ancestry boolean), base ancestry, clean checkout,
changed paths, and symlink/path replacement. A historical attestation is never
accepted as a substitute for this fresh check. Evidence closed-shape validation
covers both the document top level and the consumed runner-status sub-objects
(`issue`, `repository`, `base`, `worktree`, `scope_guard`); unknown fields there
fail closed.

## Injected boundaries (no persisted format decided)

`AuditSink` and `IdempotencyStore` are abstract interfaces. v1 ships only
deterministic in-memory reference implementations, which are the authoritative
reference semantics. The idempotency store is an explicit state machine —
`begin` reserves, `abort` releases a reservation whose attempt never reached the
client call (so the key stays retryable), and `complete` records a terminal
outcome once the client has been invoked (success or a client-produced failure
alike). A replay of a terminal key returns the recorded outcome without
re-invoking the client; a concurrent/incomplete reservation is denied. Append-only
audit records are deep-copied and sanitized on ingress and handed out as
independent copies, so they cannot be mutated retroactively. No on-disk format,
directory, locking, fsync, retention, recovery, multi-process concurrency or
production storage is decided here; that is a separately authorized task. The
`RepositoryInspector` is likewise injected; a real `git`-based inspector is
deferred to runner integration.

If the primary `AuditSink` raises, a broker-owned, non-configurable in-memory
emergency sink records an `INTERNAL_ERROR` / `audit_sink_failure` marker
(sanitized, no raw exception) and supplies the response `audit_id`; no exception
escapes `execute`, and because the idempotency key is already terminal on a
success path an audit failure cannot enable a second side effect.

The audit record is canonical and deterministic (no timestamp, no randomness).
`request_sha256` is always present; identifiers not yet validated (execution id,
issue number, operation, idempotency key, evidence hashes, derived target) are
`null` in early-denial records — unvalidated input is never used as a trusted
audit identifier. Known token, authorization, bearer and userinfo-URL patterns
are redacted from any text.

## Fake GitHub client

`GitHubTransport` exposes exactly `publish_task_branch` and `create_draft_pr`.
There is no generic `request`/`api`/`execute`/`graphql`/`merge`/`review`/
`approve`/`label`/`comment`/`project`/administration method, and no network or
credential path. A test proves only these two methods exist and that execution
performs no socket call.

## Tests

```bash
python3 -m unittest discover -s tools/restricted-broker/tests -p 'test_*.py'
python3 -m json.tool docs/governance/schemas/restricted-broker-request-v1.schema.json  >/dev/null
python3 -m json.tool docs/governance/schemas/restricted-broker-response-v1.schema.json >/dev/null
python3 -m json.tool docs/governance/schemas/restricted-broker-audit-v1.schema.json    >/dev/null
git diff --check
```

## Rollback

- **R0** — remove the broker implementation, this document and the three
  schemas. The runner keeps stopping at `BLOCKED_BROKER_UNAVAILABLE`.
- **R1** — retain schemas and fixtures while disabling broker-core entrypoints.

## Residual risks

A later production credential may hold broader scopes; integration must preserve
this allowlist as the agent-facing authority boundary. Same-host compromise and
production credential security are deferred. Remote race behavior requires a
separately authorized harmless live pilot. Runner integration, automatic
testing, review/remediation and discovery/claim remain separate tasks.

## Human gates

Local implementation, local commits and local tests from the exact base are
authorized. Separate explicit authorization remains required before push, Draft
PR creation, runner integration, any real credential or live GitHub operation,
deployment, allowlist expansion, marking Ready, merging, or changing workflows,
rulesets, required checks, Merge Queue or CODEOWNERS.
