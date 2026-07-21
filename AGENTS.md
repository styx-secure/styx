# AGENTS.md

Canonical, tool-neutral policy for every human or automated agent working in
`styx-secure/styx`. Tool-specific files may add operating hints but must not
weaken this document.

## Authority

Use this order: approved GitHub Issue and native dependencies; `AGENTS.md`;
normative specs, ADRs and active plans; tool adapters such as `CLAUDE.md`; chat
or local notes. GitHub is the operational source of truth.

A **contract task** is executable only when its Issue contains:

```html
<!-- styx-task-contract:v1 -->
```

and defines outcome, non-goals, allowed and forbidden paths, native dependencies,
frozen interfaces, acceptance criteria, exact tests, rollback, residual risks,
executor/persona, independent reviewers, human gates, base branch and base SHA.
Missing or ambiguous data blocks execution. MUCC stories have their own
executability condition, defined under "Execution lanes" below.

## Execution lanes

Since ADR-0006 the repository runs two execution lanes:

- **Styx contract tasks** — branch `task/<issue>-<slug>`. The Issue carries the
  v1 contract above; the `Agent scope evidence (observation)` required status
  check enforces its allowed and forbidden paths server-side.
- **MUCC stories** — branch `task/US-<id>`. Spec content is owned by
  `specs/03-user-stories.md` and `specs/05-sprint-plan.md`; the story Issue
  bodies are generated projections and are never edited by hand. A story is
  executable when it exists in the sprint plan, is claimed through the MUCC
  coordinator (claim = assignee) and carries its `us-id:*` label. The Styx
  scope check intentionally skips this namespace; the gate is mandatory human
  review of the pull request. Story commits and pull requests reference the
  story and its Issue; story PRs report changed paths, exact tests and
  results, and rollback.

Namespace discipline is load-bearing: a contract task must never use a
`task/US-*` branch name, or it would silently skip its scope check.

Every other rule in this document — permissions, human-gate areas, isolation,
PR lifecycle, independent review and fail-closed behaviour — applies to both
lanes unchanged. Lane references:
`docs/governance/adr/ADR-0006-adopt-mucc-multidev.md`,
`docs/governance/mucc-migration/migration-plan.md`,
`docs/governance/mucc-migration/ruleset-proposal.md`.

## Permissions

No agent may:

- push directly to `main`;
- merge, enable auto-merge or enter the Merge Queue;
- approve its own work or satisfy a human gate;
- change rulesets, protection, secrets, CODEOWNERS or Project configuration;
- broaden its own scope or start with unresolved dependencies;
- decide cryptography, persisted formats, migrations or vault architecture
  outside their approved technical process.

Agents must not receive generic persistent GitHub credentials. Any broker or App
must expose minimum operations and must never expose merge or approval actions.

## Scope and parallel work

- Paths are repository-root relative.
- Every added, modified, renamed or deleted file must match an allowed pattern.
- Both sides of a rename must be allowed.
- Forbidden paths always win.
- Symlinks, submodules, binary files and lockfiles are forbidden unless explicit.
- Scope expansion requires an Issue update and human approval before continuing.
- Concurrent tasks must have disjoint file sets unless an approved exception
  names one integration owner.

These areas always require a human gate: `.github/workflows/**`, CODEOWNERS,
repository governance, runtime manifests/lockfiles, cryptographic code or test
vectors, persisted formats/migrations, vault architecture, and vendored WASM.

## Isolation and commits

Each execution uses one dedicated worktree and branch created from a recorded
base SHA — the contract's base SHA for contract tasks, the `main` head at
branch creation (reported in the pull request) for MUCC stories:

```text
task/<issue>-<slug>
task/US-<story>
agent/<issue>-<slug>
review/<pr>-<persona>
```

`task/US-<story>` is reserved for the MUCC story lane (see "Execution lanes").

Do not mix cleanup or unrelated work. Commits must be small, coherent and
reversible; messages are English and should include `Refs #<issue>`.

## Pull requests

Open a Draft PR after the first useful commit. It normally implements one atomic
Issue and must report the Issue/base SHA, outcome, non-goals, changed paths,
tests/results, rollback, residual risks, reviewer independence and human gates.

A PR may leave Draft only when dependencies are closed, the diff is in scope,
mandatory tests pass, rollback is documented and no blocking finding remains.
Only an authorized human may approve the final gate or enter the Merge Queue.

## Independent review

Implementer and reviewer must be different identities and execution contexts.
The reviewer starts from the Issue, diff and normative repository documents,
uses a clean read-only context, never modifies the reviewed branch, and reports
severity, evidence, path and required action. Fixes are re-verified. Agent review
is evidence, never a replacement for human approval.

## Fail closed

Stop and report `Blocked` when the contract is invalid, base/dependencies drift,
required work is outside scope, tasks overlap, a test cannot run, CI/change
detection is failed/cancelled/unexpectedly skipped/absent, a sensitive decision
is underspecified, independence is unprovable, or human approval is missing.
Timeouts, silence and empty outputs are failures, not green skips.

## Repository commands and boundaries

Dart reference stack:

```bash
melos bootstrap
melos run analyze
melos run format:check
melos run test:all
melos run coverage:check
```

`packages/themis_survey` is Flutter and, when touched, is tested from its own
directory with `flutter test`.

JavaScript/PWA:

```bash
cd styx-js && npm ci
cd styx-js && npm test -- --testTimeout=20000
cd styx-js/apps/chat && npm ci && npm run build
```

The React app has its own lifecycle. Relay tests need their documented Docker
infrastructure; browser tests need Playwright.

`styx-js/vendor/openmls-wasm/` and `styx-js/vendor/styx-kdf-wasm/` are pinned,
reproducible-build security boundaries. Use only their documented verification
scripts and never rebuild them as an unrelated side effect.

Legacy Go service:

```bash
cd push_bridge_server && go test ./...
```

Current PR gates cover the Dart stack, `styx-js` tests/build, applicable WASM
integrity and CodeQL for JavaScript/TypeScript. Path-aware jobs may green-skip
only after successful change detection.

## Repository landmines

- Dart and JavaScript are separate and intentionally not crypto-interoperable.
- `styx-js/apps/chat/` is not part of the root Jest invocation.
- Dual-language API docs (`docs/API_REFERENCE.md` and `_IT.md`) stay synchronized.
- `docs/archive/tasks/TASK_*.md` is historical, not a current plan.
- Design docs are primarily Italian; code, commits and comments are English.
- The product remains experimental while documented H1/H2 blockers are open.

This governance policy does not authorize PR-3 or any product change.
