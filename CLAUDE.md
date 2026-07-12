# CLAUDE.md

Claude Code adapter for `styx-secure/styx`.

## Canonical policy

Read `AGENTS.md` before planning or changing anything. It is the tool-neutral,
canonical policy. This file only adds Claude Code operating guidance and cannot
override the approved GitHub Issue, native dependencies, `AGENTS.md`, normative
specifications or active plans.

Do not infer authorization from chat history. Work only from a complete Issue
containing `<!-- styx-task-contract:v1 -->`.

## Claude Code modes

### Implementer

- Use the dedicated worktree and branch named by the task.
- Verify the Issue's base SHA and dependencies before editing.
- Modify only declared allowed paths; forbidden paths win.
- Open or maintain a Draft PR and report exact tests and results.
- Stop on ambiguity or scope expansion; do not silently solve adjacent problems.

### Reviewer

- Use a clean context and a separate read-only checkout.
- Read the Issue, normative documents and PR diff independently.
- Do not modify the branch or reuse the implementer's private context.
- Report findings with severity, evidence, path and required remediation.
- Re-run relevant checks and actively verify claimed fixes.

Claude Code must never merge, enable auto-merge, enter the Merge Queue, approve
its own work, satisfy a human gate or change repository administration.

## Project overview

The repository contains two intentionally separate codebases:

1. `packages/`: Dart/Flutter sovereign-ledger reference stack.
2. `styx-js/`: active JavaScript/PWA E2EE chat using MLS via vendored
   OpenMLS/WASM, Nostr transport, a React PWA and the Node `push_bridge/`.

They are not cryptographically interoperable. Primary design documentation is
Italian. `docs/archive/` is historical and non-normative.

Read before product planning:

- `docs/security/2026-07-11-fattibilita-piano-utente.md`;
- `docs/security/2026-07-10-styx-chat-security-report.md`;
- active specs and plans under `docs/superpowers/`.

The product remains experimental while H1/H2 are open. Do not introduce
"serverless", "zero-knowledge" or equivalent claims.

## Commands

Dart reference stack:

```bash
melos bootstrap
melos run analyze
melos run format:check
melos run test:all
melos run coverage:check
```

JavaScript/PWA:

```bash
cd styx-js && npm ci
cd styx-js && npm test -- --testTimeout=20000
cd styx-js/apps/chat && npm ci && npm run build
```

Run targeted Jest tests from `styx-js/` with native ESM. Relay integration needs
its documented Docker relay. Browser suites need Playwright.

WASM artifacts are security boundaries. Use their pinned build, verification
and audit scripts only when the Issue explicitly includes those paths.

Legacy Go service:

```bash
cd push_bridge_server && go test ./...
```

## CI reality

Pull requests to `main` have stable gates for the Dart reference stack,
`styx-js` tests/build, applicable WASM integrity/reproducibility, and CodeQL for
JavaScript/TypeScript. A successful path detector may green-skip irrelevant
heavy jobs; detector failure is never a green skip.

CI coverage does not replace the exact tests named by the task contract.
`packages/themis_survey` is Flutter and must be tested separately when touched.

## Current governance boundary

Governance work does not authorize product changes. Do not start PR-3 or decide
cryptography, persisted formats, migrations or vault architecture unless a
separate approved technical Issue explicitly authorizes that work.
