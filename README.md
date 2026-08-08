# 🏛️ Styx

**Secure infrastructure for sensitive work.**

> ⚠️ **EXPERIMENTAL SOFTWARE** — Styx is under active development and has **not** completed an
> independent security audit. Do not use current builds for sensitive, high-risk, or life-critical
> use. The browser profile is also weaker against an adversary that controls the web origin. See
> the [approved vision](specs/01-vision.md) and the
> [Phase A capability report](docs/architecture/spikes/2026-08-08-marmot-openmls-phase-a.md).

## Mission

Styx is an open-source, platform-neutral secure application substrate for sensitive workflows over
infrastructure that must not be trusted with plaintext. It combines self-custodied identity,
end-to-end-encrypted collaboration, verifiable state transitions, offline operation, and redundant
delivery. It is not a general-purpose messenger or a replacement for Signal.

It is intended for human-rights and civil-society teams, journalists, safeguarding organizations,
trusted intermediaries, and developers building casework, evidence, coordination, or other
sensitive applications.

The first product vertical is **Themis**: a planned case-management application intended to let a
person open and continue a confidential case without providing an email address, phone number, or
ordinary account. This can support abuse, harassment, discrimination, whistleblowing, safeguarding,
and other sensitive casework, but the software cannot replace trained handlers, legal and privacy
review, safeguarding procedures, or emergency channels.

## Where the project stands

- **Built and tested foundations:** an independent Dart ledger and an active JavaScript browser
  stack with a reference MLS chat, Nostr transport, encrypted IndexedDB vault, crypto-worker
  lifecycle, pinned WASM artifacts, and fail-closed storage work.
- **Not yet a complete product:** the language-neutral application protocol, interoperability
  proof, reliable delivery SDK, metadata-minimizing case routing, anonymous return capability,
  organizational workflow, distribution assurance, complete-product audit, and controlled pilot
  remain to be completed.
- **Current technical direction:** Marmot is the preferred compatibility target for the
  MLS-over-Nostr session profile, but current Styx builds are not Marmot-compatible. The chat is a
  minimal reference application and interoperability harness, not the product roadmap.

The proposed funded programme takes these tested foundations through a conformance-backed Styx
protocol, a bounded secure-session interoperability decision, a reusable SDK and reliable delivery,
a text-first Themis alpha, stronger distribution assurance, independent audit and remediation, and
a controlled organizational pilot. See the [project brief](docs/PROJECT_BRIEF.md) for the mission,
evidence, milestones, measurable outcomes, and explicit non-claims. The
[public identity guide](docs/BRAND_IDENTITY.md) defines naming and claim boundaries; the
[dependency-free landing-page source](website/README.md) turns that identity into a reviewable
public surface without deploying it.

Current transports expose routing, timing, size, and relationship metadata. E2EE also does not
protect a compromised endpoint, a malicious recipient, or a browser build supplied by an origin
controlled by the adversary. No current build offers a universal anonymity guarantee.

> *In Greek mythology, the River Styx marked a boundary and the gods swore solemn oaths upon its waters. The project uses that image to represent explicit trust boundaries in digital systems—not a promise of invulnerability.*

## Dart reference quick start

The following example exercises the Dart reference implementation. New application-layer work
targets the language-neutral protocol and conformance corpus before either implementation is
extended.

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

## Dart reference architecture

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

## Dart reference capabilities

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

- **No central server of record** — peers hold the authoritative event chain; messages are
  E2E-encrypted and routed by federated relays that cannot read content but do observe some
  transport metadata (not a zero-metadata or "serverless" system)
- **Cryptographic Trust** — Every event is signed, hashed, and chained
- **Sovereign Identity** — Keys are generated locally; storage protections depend on the selected runtime profile
- **GDPR by Design** — Bilateral pruning with hash persistence
- **Offline-First** — Full operation without connectivity, deterministic sync on reconnect

## Development

### Prerequisites

- Dart SDK ≥ 3.10.0 (the locked dependency graph requires it; see `pubspec.yaml`)
- Melos (`dart pub global activate melos`)
- Go 1.21+ (for `push_bridge_server` only)

### Setup

```bash
git clone https://github.com/styx-secure/styx.git
cd styx
melos bootstrap
```

### Commands

```bash
melos run test:all        # Run all tests across all packages
melos run analyze         # Static analysis
melos run format:check    # Check formatting
melos run ci              # Full CI pipeline locally
melos run coverage:check  # Enforce the per-package coverage baseline (90% is a target, not yet met everywhere)

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
└── docs/                      # Architecture, security, API, and historical records
```

## License

Styx is **open source**. The licensing model, approved in
[ADR-0004](docs/architecture/decisions/ADR-0004-licensing-strategy.md) and mapped exactly in
[`LICENSING.md`](LICENSING.md) and [`REUSE.toml`](REUSE.toml), is:

- **Original Styx software and documentation:** [`AGPL-3.0-or-later`](LICENSE).
- **Six exact interoperability vector files** (five `vault-crypto-v1` known-answer vectors and
  `kdf-kat-vectors.js`, listed exactly in `LICENSING.md`): `Apache-2.0`, so independent
  implementations can reuse them freely.
- **Third-party and vendored material** keeps its upstream licenses and attribution — notably the
  OpenMLS-derived material in `styx-js/vendor/openmls-wasm/` (MIT; that directory also contains
  Styx-authored AGPL scripts and a Styx-modified MIT derivative, classified path by path). See
  [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
- **Trademarks are separate:** the Styx and Styx Secure names and logos are not granted by the
  software licenses ([`TRADEMARKS.md`](TRADEMARKS.md)).
- **External code contributions remain paused** until separate contributor terms are approved
  ([`CONTRIBUTING.md`](CONTRIBUTING.md)); issues and feedback are welcome.
- Separate commercial terms may be available from the copyright holder; the public AGPL edition
  stays in place regardless.
