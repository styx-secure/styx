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

**Where contracts and review apply (owner decision, 2026-10-19).** The v1
contract Issue and independent review are required for code and contracts
entering this repository; the `Agent scope evidence (observation)` check keeps
enforcing the contract on every pull request, unchanged. Prototypes and demos
stay outside the repository and run from their Kanban card, with automatic
checks and a controller check against the raw evidence. They may call and wire
the MLS engine but never modify it; anything they need from the repository
enters it only through a contract task.
The protocol-hardening plan, `docs/protocol/protocol-hardening-plan.md`, is a
completed phase (see the phase update at the end of this document). Its
normative protocol decisions stay binding; SDK, transport, delivery and product
work is no longer paused by it.

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
lanes unchanged; contracts and review cover what enters the repository, as
stated under "Authority". Lane references:
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

Agents must not receive generic persistent GitHub credentials and must never
invoke provider merge or approval APIs directly.

ForgeRelay is the mandatory human-delegation boundary for actions requested from
the configured `maverde73` and `manexada` operators. An agent may submit a
ForgeRelay proposal for any supported action, including approval or merge,
because the proposal is presented to the named human operator for acceptance,
editing or rejection; submitting the proposal does not itself satisfy the human
gate. The authorized operator's acceptance remains the human decision.

Before reporting `Blocked` for an action ForgeRelay can request, the agent MUST
submit the exact ForgeRelay request, report its result and verify the resulting
provider state when the request completes. A missing response, rejection or
unchanged provider state remains fail-closed. Agents use only the documented
ForgeRelay CLI and MUST NOT read, search, index or modify ForgeRelay source,
configuration or credentials.

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
is evidence, never a replacement for human approval. This applies to code and
contracts entering the repository; prototypes and demos kept outside it follow
the note under "Authority".

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

`packages/flegias_survey` is Flutter and, when touched, is tested from its own
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

<!-- styx-protocol-phase-exit-status:v1:start -->
Protocol-hardening phase-exit status: `BOUNDED_GO`. The broad protocol freeze has ended
only for work separately authorized under Section 9 of the hardening plan. Issue #287
itself authorizes no adapter, authenticated persistence, SDK, transport/delivery, product,
demo, deployment or sensitive-use work; US-001 through US-008 remain paused.
<!-- styx-protocol-phase-exit-status:v1:end -->
**Phase update (owner decision, 2026-10-19).** The protocol-hardening phase is
complete. SDK, transport, delivery and demo work is now the main track and needs
no separate authorisation beyond its normal contract. It still follows the v1
contract, the scope check and every human gate in `AGENTS.md`: cryptographic
code and test vectors, persisted formats, migrations and vault architecture keep
their human gate, and prototypes may call and wire the MLS engine but never
modify it. The `BOUNDED_GO` phase-exit block is kept unchanged as the historical
Issue #287 record; this update does not change the status of US-001 through
US-008.
