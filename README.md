# 🏛️ Styx

**Oaths sealed in code. Trust forged in math.**

Styx is a Dart/Flutter library for building sovereign, peer-to-peer cryptographic ledgers. No servers, no accounts, no trust assumptions — just two peers and an unbreakable chain of signed events.

> *In Greek mythology, the River Styx was the boundary between the mortal world and the underworld. The gods swore their most sacred oaths upon its waters — oaths that could never be broken. Styx brings that same inviolable trust to digital agreements.*

## Architecture

Styx is structured as a monorepo of composable packages:

| Package | Description |
|---------|-------------|
| `styx` | Public façade — single entry point for the full library |
| `crypto_core` | Ed25519/X25519 keys, SPAKE2, SHA-256, BIP-39, Shamir SSS |
| `storage` | Drift + SQLCipher encrypted database engine |
| `ledger_engine` | Append-only hash chain, HLC, vector clocks, merge, pruning |
| `transport` | Nostr (primary), Email (fallback), Tor (overlay) |
| `push_bridge_client` | FCM/APNs wake-up with privacy profiles |

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
```

## License

TBD
