# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Styx started as a Dart/Flutter library for sovereign, peer-to-peer cryptographic ledgers (two peers — Affidante and Custode — sharing a tamper-evident event chain, no server). It now contains **two codebases**, and most active work is in the second:

1. **`packages/` — the Dart ledger library.** Implemented and tested (Melos monorepo, ~107 production files, ~60 test files). This is what the "Architecture" section below describes, and the only thing CI covers.
2. **`styx-js/` — the JavaScript/PWA E2EE chat.** A separate port whose messaging layer is **MLS (RFC 9420)** via a vendored OpenMLS→WASM crate (`styx-js/vendor/openmls-wasm/`), with a Nostr transport, a React PWA under `styx-js/apps/chat/`, and a Node push bridge in `push_bridge/`. It has its own npm/jest suite and **no crypto interop with the Dart port**. It is outside CI.

The primary documentation is in Italian (see `docs/`).

**Current direction — read before planning any work:**
- `docs/security/2026-07-11-fattibilita-piano-utente.md` — the normative roadmap: five blocks, executed one at a time with an architectural review between them. The vendored Rust/WASM crate is the critical path.
- `docs/security/2026-07-10-styx-chat-security-report.md` — audit; H1 (plaintext at-rest storage) and H2 (metadata exposed to relays) are still open.
- `docs/superpowers/plans/` — active implementation plans. `docs/archive/` is historical and non-normative.

**Security posture:** the chat is not yet fit for sensitive use. Do not add "serverless"/"zero-knowledge" claims to UI or docs; the relays see transport metadata.

## Build & Test Commands

Dart library (`packages/`):

```bash
melos bootstrap                # Initialize all packages in the monorepo
melos run test:all             # Run all tests across all packages
melos run analyze              # Static analysis
melos run format:check         # Check formatting
melos run ci                   # Full CI pipeline locally
melos run coverage:check       # Verify 90% coverage threshold
dart test                      # Run tests in a single package (from package dir)
dart test test/some_test.dart  # Run a single test file
```

JavaScript chat (`styx-js/`) — separate toolchain, not in CI:

```bash
cd styx-js && npm test                        # jest (native ESM, no Babel)
cd styx-js && npx jest test/path/to/file.test.js
cd styx-js/vendor/openmls-wasm && ./build.sh  # rebuild the WASM artifact (needs Docker)
cd styx-js/apps/chat && npm run dev           # the React PWA (its own package.json)
```

**CI pipeline** (Dart only): `analyze → format check → test:all → coverage gate → build Android → build iOS`

Coverage gates: 90% global minimum, 95% for crypto modules. Uses lcov.

Linting: `very_good_analysis` baseline + `dart_code_linter`. Dart SDK ≥ 3.6.0 required.

## Architecture

### Repository layout

```
styx/
├── packages/                  # Dart ledger library (Melos 7.x + Pub Workspaces) — see below
│   ├── crypto_core/           # Identity layer: Ed25519/X25519 keys, SPAKE2, BIP-39, Shamir SSS
│   ├── storage/               # Encrypted DB: Drift + SQLCipher (AES-256)
│   ├── ledger_engine/         # Event sourcing, SHA-256 hash chain, vector clocks, merge, pruning
│   ├── transport/             # Nostr (primary), Email/IMAP (fallback), Tor overlay, failover engine
│   ├── push_bridge_client/    # Flutter FCM/APNs client with privacy profiles
│   └── styx/                  # Public façade (Styx entry point) + pairing protocols
├── styx-js/                   # JavaScript E2EE chat (MLS) — the active line of work
│   ├── src/{crypto,chat,transport,storage,pairing,push,ledger,facade}/
│   ├── apps/chat/             # React PWA (own package.json, own Vite build)
│   └── vendor/openmls-wasm/   # Vendored OpenMLS → WASM (Rust patch + built artifact)
├── push_bridge/               # Node push bridge for the JS chat (wake-up only, no content)
├── push_bridge_server/        # Go microservice — push bridge for the Dart client
└── test_integration/          # Cross-package Dart integration tests
```

The sections below describe the **Dart** library.

### Layered Architecture (bottom-up dependency order)

1. **Identity Layer** (`crypto_core`) — Ed25519 keypairs, digital signatures, X25519 key exchange, SPAKE2 password-authenticated key exchange, BIP-39 mnemonics, Shamir's Secret Sharing for backup. Keys stored in hardware enclaves (Android Keystore / iOS Keychain) via `flutter_secure_storage`.

2. **Integrity Layer** (`storage` + `ledger_engine`) — Append-only event store with SHA-256 hash chain. Each event includes: previous hash, vector clock (2-element for the 2-peer system), HLC timestamp, payload, sender pubkey, and Ed25519 signature. Deterministic merge for concurrent events (order by VC sum, then lexicographic pubkey). GDPR-compliant pruning removes payloads while preserving hashes.

3. **Transport Layer** (`transport`) — Failover hierarchy: Nostr relay pool (3 retries, 5s timeout) → Email IMAP/SMTP (2 retries, 30s timeout). Tor as optional overlay via SOCKS5 proxy. Local outbox queue respects causal ordering via vector clocks.

4. **Reliability Layer** (`push_bridge_client` + `push_bridge_server`) — Stateless Go microservice subscribes to Nostr relays, sends data-only push via FCM/APNs. Three privacy profiles: Balanced (no dummies), Private (Poisson-distributed dummy pushes, no network on dummy wake), Paranoid (dummy pushes with real relay connections).

5. **Trust Layer** (`styx` façade) — QR pairing (direct pubkey exchange), remote pairing (BIP-39 mnemonic → SPAKE2 → Double Check 6-digit verification), device re-keying protocol (REKEY blessing event).

### Key Design Decisions

- **SPAKE2:** Pure-Dart implementation on P-256 recommended (portable, no FFI). FFI to libspake2 as fallback if performance is insufficient.
- **Vector Clock vs HLC:** For the 2-peer system, VectorClock wraps HLC with N=2 specific logic.
- **Merge strategy:** MERGE event linearizes forks (not a persistent DAG). Ordering: sum of VC components, then lexicographic pubkey.
- **iOS push:** Requires a native Swift Notification Service Extension outside Flutter.

### Development Philosophy

Bottom-up with parallel spike on Push Bridge. Each task must pass ALL previous task tests before completion. No task is complete unless `melos run test:all` passes 100%. Property-based testing with `glados` for cryptographic invariants.

## Key Dependencies

- **Crypto:** `cryptography` ^2.9.0, `cryptography_flutter` ^2.3.4, `crypto` ^3.0.7
- **Storage:** `drift` ^2.30.1, `sqlcipher_flutter_libs` ^0.6.8
- **Transport:** `ndk` ^0.6.0, `enough_mail` ^2.1.7, `tor` ^0.1.1
- **Push:** `firebase_messaging` ^16.1.1 (client), `firebase-admin-go` + `sideshow/apns2` (server)
- **Testing:** `glados` (property-based), lcov (coverage)
