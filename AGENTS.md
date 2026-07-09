# AGENTS.md

## Landmines

- **CI covers only the Dart pub-workspace packages.** The GitHub Actions workflow (`.github/workflows/ci.yml`) runs `melos` analyze/test/coverage over the packages listed in the root `pubspec.yaml` `workspace:` field. Everything below is outside CI and must be tested manually.
- **`push_bridge_server/` is a standalone Go module,** not in melos or the workspace. Test with `cd push_bridge_server && go test ./...`.
- **`styx-js/` is a separate JavaScript port** with its own npm/jest suite (`cd styx-js && npm test`; relay tests need Docker, WebRTC tests need Playwright). It is tracked in git but has no guaranteed parity with the Dart implementation — do not treat it as authoritative for Dart behavior.
- **`styx-js/vendor/openmls-wasm/` is a vendored Rust→WASM binary** (OpenMLS, MIT), not built by npm. Regenerate with its own `build.sh` (needs Docker; no host Rust toolchain required) — see the dir's `README.md` for provenance/commit. The MLS layer intentionally **breaks crypto interop with the Dart port** (the 22 interop tests); the chat app is web-only.
- **`styx-js/apps/chat/` is a separate Vite React app** with its own `package.json` — NOT part of the styx-js jest suite, the Dart workspace, or CI. Build/run it on its own: `cd styx-js/apps/chat && npm install && npm run dev`. It consumes the `StyxChat` contract and falls back to an in-memory mock when the real lib is absent.
- **`packages/themis_survey` is a Flutter package,** not pure Dart. It is tracked and matched by the melos `packages/*` glob, but it is **not** in the root `pubspec.yaml` `workspace:` list and has no `resolution: workspace`. `melos run test:all` execs `dart test`, which cannot run a Flutter package — run its tests with `flutter test` from the package dir.
- **Some styx-js suites are slow and time out under load.** `test/facade/sovereign-ledger.test.js` and `test/integration/e2e.test.js` do real crypto + transport retry backoffs (individual tests approach the 5s Jest default). When the full suite runs alongside the strfry Docker relay, they can spuriously fail on timeout — re-run with `--testTimeout=20000` (they pass). Not a regression signal.
- **Coverage 95% for `crypto_core` is policy, not tooling.** `tool/check_coverage.sh` enforces a single global threshold (default 90%). The 95% requirement for `crypto_core` stated in `CLAUDE.md` is not enforced automatically — verify manually after touching crypto code.

## Task-specific constraints

- **Dual-language API docs must stay in sync:** `docs/API_REFERENCE.md` (EN) and `docs/API_REFERENCE_IT.md` (IT) are parallel documents. Any structural or content change to one must be mirrored in the other.
- **Task implementation order is strict:** `docs/tasks/TASK_*.md` define a bottom-up build order. Each task must pass all previous task tests before it is considered complete.
- **Primary documentation language is Italian:** Design specs in `docs/` are written in Italian. Code, commit messages, and comments are in English.
