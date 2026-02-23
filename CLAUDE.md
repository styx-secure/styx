# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Styx is a Dart/Flutter library for building sovereign, peer-to-peer cryptographic ledgers. Zero-server architecture where two peers (Affidante and Custode) maintain a shared cryptographic event chain. The primary documentation is in Italian (see `docs/`).

**Current status:** Specification/planning phase — only documentation exists in `docs/`. No code has been implemented yet.

## Build & Test Commands

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

**CI pipeline:** `analyze → format check → test:all → coverage gate → build Android → build iOS`

Coverage gates: 90% global minimum, 95% for crypto modules. Uses lcov.

Linting: `very_good_analysis` baseline + `dart_code_linter`. Dart SDK ≥ 3.6.0 required.

## Architecture

The project is a Dart monorepo managed with Melos 7.x + Pub Workspaces.

### Package Structure

```
styx/
├── packages/
│   ├── crypto_core/           # Identity layer: Ed25519/X25519 keys, SPAKE2, BIP-39, Shamir SSS
│   ├── storage/               # Encrypted DB: Drift + SQLCipher (AES-256)
│   ├── ledger_engine/         # Event sourcing, SHA-256 hash chain, vector clocks, merge, pruning
│   ├── transport/             # Nostr (primary), Email/IMAP (fallback), Tor overlay, failover engine
│   ├── push_bridge_client/    # Flutter FCM/APNs client with privacy profiles
│   └── styx/                  # Public façade (Styx entry point) + pairing protocols
├── push_bridge_server/        # Go microservice — stateless push notification bridge
└── test_integration/          # Cross-package integration tests
```

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
