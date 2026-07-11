# 🏛️ Styx

**Oaths sealed in code. Trust forged in math.**

> ⚠️ **EXPERIMENTAL SOFTWARE** — Styx is under active development and has **not** completed an
> independent security audit. Do not use current builds for sensitive, high-risk, or life-critical
> communications. See `docs/PANORAMICA-PROGETTO.md` for the real project state.

Styx is a project for sovereign, end-to-end encrypted, metadata-minimizing communication. It contains
two codebases: a mature **Dart** ledger library (`packages/`) and the active **JavaScript/MLS chat**
(`styx-js/`, an E2EE PWA over federated Nostr relays). Messages are end-to-end encrypted; relays route
them but cannot read the content, though they observe some transport metadata.

> *In Greek mythology, the River Styx was the boundary between the mortal world and the underworld. The gods swore their most sacred oaths upon its waters — oaths that could never be broken. Styx brings that same inviolable trust to digital agreements.*

## Quick Start

```dart
import 'dart:convert';
import 'package:styx/styx.dart';

// 1. Create the ledger
final styx = SovereignLedger(
  identity: identity,
  config: const LedgerConfig(
    relayUrls: ['wss://relay.damus.io'],
  ),
  ledgerStore: ledgerStore,
  transport: transport,
  trustStore: trustStore,
  qrPairing: qrPairing,
  remotePairing: remotePairing,
  reKeyProtocol: reKeyProtocol,
  migrationService: migrationService,
  backupService: backupService,
  retentionManager: retentionManager,
  pruneProtocol: pruneProtocol,
  keyPair: keyPair,
);

// 2. Initialize
await styx.initialize();

// 3. Pair via QR
final qr = styx.generatePairingQr();
// ... show QR to peer, scan theirs ...

// 4. Send a transaction
await styx.sendTransaction(
  Uint8List.fromList(utf8.encode('{"amount": 42.50, "desc": "Cena"}')),
);

// 5. Read history
final history = await styx.getHistory();

// 6. GDPR pruning
await styx.requestPrune(targetEventId: history.last.eventId);

// 7. Backup identity (Shamir 2-of-3)
final shares = styx.createIdentityBackup();

// 8. Shutdown
await styx.shutdown();
```

## Architecture

Styx is structured as a monorepo of composable packages, layered bottom-up:

```
┌─────────────────────────────────────────────────────────┐
│                    styx (façade)                        │
│  SovereignLedger · Pairing · Migration · Backup         │
├──────────────┬──────────────┬───────────────────────────┤
│  transport   │ push_bridge  │      ledger_engine        │
│  Nostr·Email │ FCM/APNs     │  Hash chain · HLC · Merge │
│  Tor·Outbox  │ Privacy      │  Pruning · VectorClock    │
├──────────────┴──────────────┴───────────────────────────┤
│                     storage                             │
│              Drift + SQLCipher (AES-256)                │
├─────────────────────────────────────────────────────────┤
│                    crypto_core                          │
│  Ed25519 · X25519 · SPAKE2 · SHA-256 · BIP-39 · Shamir│
└─────────────────────────────────────────────────────────┘
```

| Package | Description | Tests |
|---------|-------------|-------|
| `styx` | Public façade — single entry point with `SovereignLedger` | 76 |
| `crypto_core` | Ed25519/X25519 keys, SPAKE2, SHA-256, BIP-39, Shamir SSS | 135 |
| `storage` | Drift + SQLCipher encrypted database engine | 37 |
| `ledger_engine` | Append-only hash chain, HLC, vector clocks, merge, pruning | 69 |
| `transport` | Nostr (primary), Email/IMAP (fallback), Tor (overlay), failover engine | 61 |
| `push_bridge_client` | FCM/APNs wake-up with 3 privacy profiles | 11 |
| `push_bridge_server` | Stateless Go microservice for push notification bridging | — |

**389 tests** across 6 Dart packages.

## Features

### Pairing
- **QR Pairing** — Direct public key exchange with anti-replay nonces
- **Remote Pairing** — BIP-39 mnemonic → SPAKE2 key exchange → 6-digit Double Check code for MITM detection

### Transactions
- Append-only event chain with SHA-256 hashes and Ed25519 signatures
- Event types: `transaction`, `message`, `config`, `sos`, `rekey`, `merge`, `pruneRequest`, `pruneAck`
- Hybrid Logical Clocks (HLC) for causal ordering across peers

### Offline & Sync
- Full offline operation — events queue in the outbox
- Deterministic merge on reconnect (order by vector clock sum, then lexicographic pubkey)
- Failover transport: Nostr → Email/IMAP → optional Tor overlay

### Privacy & GDPR
- Three push notification profiles: **Balanced** (no dummies), **Private** (Poisson-distributed dummy pushes), **Paranoid** (dummy pushes with real relay connections)
- Bilateral pruning protocol: `PRUNE_REQUEST` → `PRUNE_ACK` → payload removed, hash preserved
- Unilateral pruning for GDPR Article 17 (right to erasure)
- Configurable retention policies with automatic expiration

### Device Migration
- **Re-keying** via Blessing Events (old device signs the new device's public key)
- **Shamir backup** (2-of-3 by default) for identity recovery without re-keying

## Principles

- **Zero-Server** — No data ever touches a central server
- **Cryptographic Trust** — Every event is signed, hashed, and chained
- **Sovereign Identity** — Keys generated locally, stored in hardware enclaves
- **GDPR by Design** — Bilateral pruning with hash persistence
- **Offline-First** — Full operation without connectivity, deterministic sync on reconnect

## Development

### Prerequisites

- Dart SDK ≥ 3.6.0
- Melos (`dart pub global activate melos`)
- Go 1.21+ (for `push_bridge_server` only)

### Setup

```bash
git clone https://github.com/maverde73/styx.git
cd styx
melos bootstrap
```

### Commands

```bash
melos run test:all        # Run all tests across all packages
melos run analyze         # Static analysis
melos run format:check    # Check formatting
melos run ci              # Full CI pipeline locally
melos run coverage:check  # Verify 90% coverage threshold

# Single package
cd packages/styx && dart test                    # All tests in one package
cd packages/styx && dart test test/some_test.dart # Single test file
```

### Project Structure

```
styx/
├── packages/
│   ├── crypto_core/           # Identity & cryptography primitives
│   ├── storage/               # Encrypted persistence (Drift + SQLCipher)
│   ├── ledger_engine/         # Event chain, clocks, merge, pruning
│   ├── transport/             # Nostr, Email, Tor, failover, outbox
│   ├── push_bridge_client/    # Flutter push notification client
│   └── styx/                  # Public façade (SovereignLedger)
├── push_bridge_server/        # Go microservice for push bridging
├── test_integration/          # Cross-package integration tests
└── docs/                      # Specification (Italian)
```

## Licensing status

The source code is publicly visible, but the project-wide open-source license is still being
finalized (see [`docs/architecture/decisions/ADR-0004-licensing-strategy.md`](docs/architecture/decisions/ADR-0004-licensing-strategy.md)).
No additional permissions are granted beyond those provided by applicable law and GitHub's
Terms of Service. External contributions are temporarily paused until the licensing and
contributor terms are finalized.

This is a **public-source experimental project**, not (yet) a licensed open-source release.
