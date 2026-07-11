# GitHub security baseline — `styx-secure/styx`

Date: 2026-07-12 · Repo: `styx-secure/styx` · Visibility: **public** · Plan: GitHub Free (org)

This records the GitHub-side security posture after the repository was made public, which
unlocked the free-for-public-repos protections (rulesets/branch protection, secret scanning,
push protection, code scanning, private vulnerability reporting) that returned `403`/`404`
while the repository was private on the Free plan.

## Status by category

### Active now (enabled this session)

| Feature | State | How |
|---|---|---|
| Dependabot alerts | ✅ enabled | `PUT /repos/…/vulnerability-alerts` |
| Dependabot security updates | ✅ enabled | `PUT /repos/…/automated-security-fixes` |
| Dependabot version updates | ✅ configured | `.github/dependabot.yml` (github-actions, npm ×3, pub, gomod) |
| Dependency graph | ✅ on | default for public repos |
| Secret scanning | ✅ enabled | `security_and_analysis.secret_scanning` |
| Secret scanning — push protection | ✅ enabled | `security_and_analysis.secret_scanning_push_protection` |
| Private vulnerability reporting | ✅ enabled | `PUT /repos/…/private-vulnerability-reporting` |
| CodeQL (JavaScript/TypeScript) | ✅ workflow added | `.github/workflows/codeql.yml`, `security-extended` |
| `GITHUB_TOKEN` default permissions | ✅ read-only | `default_workflow_permissions: read` (already set) |
| Actions must be pinned to full SHA | ✅ required | `actions/permissions.sha_pinning_required: true` |
| Merge strategy | ✅ squash-only | merge-commit + rebase disabled; `allow_update_branch` on; auto-delete off (deferred) |

### Branch protection / ruleset on `main`

Applied as a repository **ruleset** (see `docs/architecture/decisions` / gate report for the
exact JSON). Enforces: PR required before merge; **0 required approvals** (single maintainer);
conversation resolution; required status checks; linear history; no force-push; no branch
deletion; require branch up to date. Not yet required (deliberately): a second human review,
CODEOWNERS review, signed commits (pending Dependabot/automation compatibility).

Required status checks (only stable, always-present gate checks): `Dart reference stack / Gate`,
`styx-js web / Gate`, `WASM integrity / Gate`, `CodeQL`.

### Not available on the current plan (GitHub Advanced Security only)

| Feature | Why |
|---|---|
| Secret scanning — non-provider (generic/custom) patterns | GHAS-only, even on public repos |
| Secret scanning — validity checks | GHAS-only |

These stay disabled; the base secret-scanning provider patterns + push protection are active.

### Deferred (by decision, not blocked)

- **Auto-delete branch on merge** — enable only after the historical migration branches are
  pruned (`feature/pwa-push-bridge`, `review/block-2`).
- **Signed-commit requirement** — after verifying Dependabot/automation compatibility.
- **CodeQL for Go** (`push_bridge_server`, legacy) — add once the js/ts setup is stable.
- **Second-reviewer / CODEOWNERS review** — while there is a single maintainer.

### Pre-release blockers (must clear before recommending for real use)

These are product-security, not GitHub settings, and remain open (see the audit and
feasibility docs): **H1** local data not yet fully encrypted at rest; **H2** transport
metadata still visible to relays; the Block 3 vault and pre-audit metadata protection are not
implemented. The public README/profile/site must carry the EXPERIMENTAL / NOT-AUDITED /
NOT-FOR-SENSITIVE-USE warnings, and the licensing status is temporary (ADR-0004 Proposed).

## GitHub Actions workflow audit

Scope: `.github/workflows/*` after the hardening PRs.

| Check | Result |
|---|---|
| Explicit least-privilege `permissions` | ✅ every workflow sets `contents: read`; CodeQL adds only `security-events: write` |
| `pull_request_target` used | ✅ none |
| Secrets exposed to workflows | ✅ none referenced (`secrets.*` absent); PR triggers are `pull_request` (no fork-secret exposure) |
| Third-party actions pinned to full SHA | ✅ after hardening: `actions/checkout`, `dart-lang/setup-dart`, `actions/setup-node`, `actions/upload-artifact`, `github/codeql-action` all pinned + tag-annotated |
| Sensitive data in artifacts | ✅ only `wasm-verify-hashes` (sha256 digests), retention 14 days |
| Dangerous events | ✅ none (`workflow_dispatch` used only for the manual hermetic WASM rebuild) |

Note: the pre-hardening `ci.yml`/`styx-js-web.yml` used tag refs (`@v4`, `@v1`); enabling
`sha_pinning_required` made those runs fail until the hardening PRs (SHA-pinned) merged. This
is expected and is the mechanism working as intended.

## Dependabot triage (2026-07-12)

Enabling Dependabot opened 13 update PRs. Triaged against the frozen pre-Block-3 baseline;
crypto, MLS, the WASM crate, the OpenMLS pin, the ciphersuite, the MLS storage format and the
pinned Rust/toolchain were **not** touched.

**Merged (safe security fixes, one at a time, all required checks green):**

| PR | Update | Sev | Rationale |
|---|---|---|---|
| #15 | `ws` 8.19.0→8.21.0 (styx-js runtime) | **High** | Memory-exhaustion DoS; minor bump, WebSocket transport tested by the web gate |
| #16 | `serialize-javascript` 7.0.4→7.0.7 | Medium | CPU-DoS; patch, build/tooling, tested |
| #9 | `qs` 6.15.0→6.15.3 | Medium | DoS; patch, tested |

**Deferred (annotated on each PR):**

- **Crypto — do not auto-update** (policy §3): `@noble/curves`, `@noble/hashes`, `@noble/ciphers`,
  `@noble/ed25519` major bumps in `push_bridge` (#5) and `styx-js` (#12/#20). Require a dedicated
  crypto review, split from tooling; never bulk-merged.
- **Unplanned major migration**: React 18→19 + Vite 5→8 in `apps/chat` (#10/#11/#21). The one
  **remaining High** (`vite` GHSA-fx2h-pf6j-xcff, `server.fs.deny` bypass) is a **dev-server-only**
  advisory on a `devDependency` — Vite is not in the shipped static bundle (runtime deps are only
  react/react-dom/@zxing/qrcode), so it is **not reachable in production**. A controlled Vite/React
  upgrade is tracked separately; not merged as a major jump.
- **Frozen Dart reference stack** (#13, `dart_code_linter` 3→4): major, no security benefit.
- **Legacy Go `push_bridge_server`** (#4/#6/#7): no advisories, non-canonical component.
- **Test-framework major** (#14, jest 29→30) and transitive dev patches (#19 picomatch): low
  priority; revisit with targeted bumps.

**Residual alerts after triage:** 1 High (vite, dev-only, risk-accepted/deferred), 7 medium, 1 low
— all in build/dev tooling, none reachable in the shipped runtime. No Critical.

## Supplementary scanners (CodeQL is not sufficient alone)

CodeQL covers JavaScript/TypeScript only. It does **not** replace, and must be complemented by:

- **Dart** — `dart analyze --fatal-infos` (Dart reference-stack workflow).
- **Rust / WASM** — reproducible-build + adversarial-parser gate (`WASM integrity` workflow,
  `docs/architecture/wasm-ci-strategy.md`); `cargo audit` / `cargo deny` are **recommended
  follow-ups** for the vendored crate's dependency graph.
- **npm** — Dependabot alerts/updates; `npm audit` in CI is a follow-up.
- **Go** — CodeQL Go coverage is a deferred follow-up.

## Verification commands (read-only)

```bash
gh api repos/styx-secure/styx --jq '.visibility, .security_and_analysis'
gh api repos/styx-secure/styx/actions/permissions --jq '{allowed_actions, sha_pinning_required}'
gh api repos/styx-secure/styx/actions/permissions/workflow --jq '.default_workflow_permissions'
gh api repos/styx-secure/styx/private-vulnerability-reporting
gh api repos/styx-secure/styx/rulesets
```
