# AGENTS.md

## Landmines

- **Go module not in melos:** `push_bridge_server/` is a standalone Go module. `melos run test:all` only tests Dart packages. Test Go separately: `cd push_bridge_server && go test ./...`
- **CI skips Go:** The GitHub Actions workflow (`.github/workflows/ci.yml`) only runs Dart analysis, tests, and coverage. Go tests must be run manually.
- **Coverage 95% for crypto_core is policy, not tooling:** `tool/check_coverage.sh` enforces a single threshold (default 90%). The 95% requirement for `crypto_core` stated in `CLAUDE.md` is not enforced automatically — verify manually after touching crypto code.
- **`styx-js/` is experimental:** Untracked JS port, not in CI, not in the Dart workspace. Do not treat it as authoritative or assume parity with the Dart implementation.

## Task-specific constraints

- **Dual-language API docs must stay in sync:** `docs/API_REFERENCE.md` (EN) and `docs/API_REFERENCE_IT.md` (IT) are parallel documents. Any structural or content change to one must be mirrored in the other.
- **Task implementation order is strict:** `docs/tasks/TASK_*.md` define a bottom-up build order. Each task must pass all previous task tests before it is considered complete.
- **Primary documentation language is Italian:** Design specs in `docs/` are written in Italian. Code, commit messages, and comments are in English.
