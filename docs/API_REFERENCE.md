# Styx API Reference

Complete API documentation for the Styx library — sovereign, peer-to-peer cryptographic ledgers designed to minimize server trust. Relays observe transport metadata; this is not a zero-metadata or "serverless" system.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Quick Start](#2-quick-start)
3. [Use Cases](#3-use-cases)
4. [API Reference — styx (facade)](#4-api-reference--styx-facade)
5. [API Reference — crypto_core](#5-api-reference--crypto_core)
6. [API Reference — ledger_engine](#6-api-reference--ledger_engine)
7. [API Reference — transport](#7-api-reference--transport)
8. [API Reference — push_bridge_client](#8-api-reference--push_bridge_client)
9. [API Reference — push_bridge_server (REST)](#9-api-reference--push_bridge_server-rest)
10. [Glossary](#10-glossary)

---

## 1. Introduction

### What is Styx

Styx is a Dart/Flutter library for building sovereign, peer-to-peer cryptographic ledgers. Two peers — called **Affidante** and **Custode** — maintain a shared, tamper-evident event chain without any central server. Every event is signed with Ed25519, hash-chained with SHA-256, and causally ordered via vector clocks.

### Layered Architecture

```
┌─────────────────────────────────────────────┐
│  5. Trust Layer (styx facade)               │  Pairing, re-keying, backup
├─────────────────────────────────────────────┤
│  4. Reliability Layer (push_bridge_client)   │  FCM/APNs, privacy profiles
├─────────────────────────────────────────────┤
│  3. Transport Layer (transport)              │  Nostr, Email/IMAP, Tor, failover
├─────────────────────────────────────────────┤
│  2. Integrity Layer (ledger_engine + storage)│  Event chain, vector clocks, pruning
├─────────────────────────────────────────────┤
│  1. Identity Layer (crypto_core)             │  Ed25519, SPAKE2, Shamir, BIP-39
└─────────────────────────────────────────────┘
```

### Typical Flow

1. **Generate identity** — Ed25519 keypair via `IdentityManager`.
2. **Pair** — Exchange public keys via QR code (local) or BIP-39 mnemonic (remote).
3. **Exchange events** — Append signed events to the hash chain, sync via Nostr relays.
4. **Resolve forks** — Deterministic merge when peers produce concurrent events.
5. **Prune** — GDPR-compliant bilateral or unilateral payload deletion.

---

## 2. Quick Start

### Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  styx:
    path: packages/styx
```

All transitive dependencies (`crypto_core`, `ledger_engine`, `transport`, `push_bridge_client`) are resolved automatically via the Melos monorepo.

### Minimal Initialization

```dart
import 'package:styx/styx.dart';

Future<void> main() async {
  final ledger = SovereignLedger(
    config: LedgerConfig(
      relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
    ),
    ledgerStore: MyLedgerStore(),       // your persistence implementation
  );

  await ledger.initialize();
  // State is now StyxState.unpaired
}
```

### First Event

```dart
// After pairing is complete (state == StyxState.ready):
await ledger.sendTransaction(
  payload: utf8.encode('Hello from Styx!'),
);

// Read history
final events = await ledger.getHistory();
for (final event in events) {
  print('${event.eventType}: ${utf8.decode(event.payload!)}');
}
```

---

## 3. Use Cases

### 3.1 QR Pairing Between Two Devices

**Scenario:** Two users are physically co-located. Device A displays a QR code; Device B scans it.

**Prerequisites:** Both devices have initialized `SovereignLedger` in `unpaired` state.

```dart
// === Device A (displays QR) ===
final qrData = await ledgerA.generatePairingQr();
// Display qrData.toQrPayload() as a QR code on screen.
// qrData contains: public key + 16-byte nonce + optional relay hints.

// === Device B (scans QR) ===
final scannedPayload = '...'; // raw string from QR scanner
final result = await ledgerB.processPairingQr(scannedPayload);

if (result.isValid) {
  await ledgerB.confirmPairing(peerAlias: 'Alice');
  // State transitions: unpaired → pairing → ready
}
```

**Notes:**
- The QR payload is approximately 80–120 bytes (Base64-encoded public key + nonce + relay hints).
- Nonces expire after 5 minutes. A maximum of 100 recent nonces are tracked for anti-replay.
- After pairing, peer role assignment (`A` or `B`) is determined by lexicographic ordering of public keys.

### 3.2 Remote Pairing via Mnemonic

**Scenario:** Two users are not physically co-located. They share a BIP-39 mnemonic out-of-band (e.g., by phone) and complete SPAKE2 key exchange with Double Check verification.

**Prerequisites:** Both devices have initialized `SovereignLedger` in `unpaired` state.

```dart
// === Device A (initiator) ===
final mnemonic = await ledgerA.startRemotePairing();
// Share this mnemonic with Device B via phone call, SMS, etc.
// Example: "abandon ability able about above absent"

// === Device B (responder) ===
// User enters the mnemonic received from Device A
await ledgerB.startRemotePairing(existingMnemonic: mnemonic);

// Both devices derive SPAKE2 session from the mnemonic.
// After SPAKE2 completes, both get a 6-digit Double Check code.

// === Both devices ===
final code = await ledger.getDoubleCheckCode();
// Display: "483 291" — users compare codes verbally.

// If codes match:
await ledger.confirmPairing(peerAlias: 'Bob');
// State: ready
```

**Notes:**
- Default mnemonic length is 6 words (from BIP-39 English wordlist).
- SPAKE2 uses NIST P-256 curve (pure Dart, no FFI).
- The Double Check code is derived from the SPAKE2 session key via SHA-256 truncation to 6 decimal digits.
- States flow: `idle → mnemonicGenerated → waitingForPeer → spake2InProgress → doubleCheckPending → completed`.

### 3.3 Sending and Receiving Transactions

**Scenario:** Two paired peers exchange signed events over the shared ledger.

**Prerequisites:** Both devices are paired (`StyxState.ready`).

```dart
// Send a transaction
await ledger.sendTransaction(
  payload: utf8.encode(jsonEncode({'amount': 100, 'note': 'Dinner'})),
);

// Send a text message
await ledger.sendMessage(
  payload: utf8.encode('Thanks for dinner!'),
);

// Send a config event
await ledger.sendConfig(
  payload: utf8.encode(jsonEncode({'theme': 'dark'})),
);

// Listen for incoming events
final stream = ledger.eventStream;
stream.remoteEvents.listen((event) {
  print('Received ${event.eventType} from peer');
});

// Filter by type
stream.eventsByType(EventType.transaction).listen((event) {
  final data = jsonDecode(utf8.decode(event.payload!));
  print('Transaction: ${data['amount']}');
});
```

**Notes:**
- Each event includes: previous hash, vector clock, HLC timestamp, payload, sender pubkey, and Ed25519 signature.
- Events are delivered in causal order via the outbox queue.

### 3.4 SOS Handling

**Scenario:** A user sends an emergency signal to their peer.

**Prerequisites:** Paired state.

```dart
// Send SOS
await ledger.sendSOS(
  payload: utf8.encode(jsonEncode({
    'type': 'emergency',
    'location': {'lat': 45.464, 'lng': 9.190},
    'timestamp': DateTime.now().toIso8601String(),
  })),
);

// Listen for SOS events
ledger.eventStream.eventsByType(EventType.sos).listen((event) {
  final data = jsonDecode(utf8.decode(event.payload!));
  showEmergencyAlert(data);
});
```

### 3.5 GDPR Pruning (Bilateral and Unilateral)

**Scenario:** A user wants to delete a specific event's payload from the ledger while preserving the hash chain integrity.

**Prerequisites:** Paired state with existing events.

```dart
// Get event history
final events = await ledger.getHistory();
final targetEvent = events.first;

// Request bilateral prune (asks peer to also delete)
await ledger.requestPrune(
  targetEventId: targetEvent.eventId,
  reason: PruneReason.userRequest,
);
// Flow: PRUNE_REQUEST → peer sends PRUNE_ACK → payload nullified on both sides

// GDPR Article 17 — unilateral prune (no peer ACK needed)
await ledger.requestPrune(
  targetEventId: targetEvent.eventId,
  reason: PruneReason.gdprArticle17,
);
// Payload is immediately nullified locally. The hash chain remains intact.
```

**Notes:**
- Pruning nullifies the `payload` field but preserves the event hash, maintaining chain integrity.
- Bilateral pruning requires both `PRUNE_REQUEST` and `PRUNE_ACK` events before execution.
- Unilateral pruning (GDPR Art. 17) executes immediately without peer acknowledgment.

### 3.6 Automatic Retention Policy

**Scenario:** Automatically identify events that exceed a time-based retention period.

```dart
final ledger = SovereignLedger(
  config: LedgerConfig(
    retentionPeriod: Duration(days: 365),
    retentionTypes: [EventType.transaction, EventType.message],
  ),
  ledgerStore: myStore,
);

await ledger.initialize();

// Identify expired events
final expired = await ledger.getExpiredEvents();
for (final event in expired) {
  await ledger.requestPrune(
    targetEventId: event.eventId,
    reason: PruneReason.retentionExpired,
  );
}
```

**Notes:**
- Only events of types listed in `retentionTypes` are evaluated.
- Already-pruned events are excluded from the results.

### 3.7 Re-Keying (Device Change)

**Scenario:** A user gets a new phone and needs to migrate their identity.

**Prerequisites:** Access to the old device (or Shamir backup shares).

```dart
// === Old device ===
await ledgerOld.blessNewDevice(newPublicKey: newDevicePublicKey);
// Creates a REKEY event signed by the old key, endorsing the new key.

// === New device ===
final status = await ledgerNew.checkMigrationStatus();
// MigrationState: idle → newKeyGenerated → blessingCreated → blessingSent
//                → waitingPeerAck → syncingHistory → completed

// === Peer device ===
// Automatically processes REKEY event:
// - Verifies old key signature on the blessing
// - Extracts new public key from the event payload
// - Updates the trust store to recognize the new key
```

**Notes:**
- The REKEY event is signed by the old private key and contains the new public key in its payload.
- The peer must verify the blessing signature before accepting the new key.
- States: `idle → newKeyGenerated → blessingCreated → blessingSent → waitingPeerAck → syncingHistory → completed`.

### 3.8 Identity Backup and Restore (Shamir)

**Scenario:** A user creates a backup of their private key using Shamir's Secret Sharing, splitting it into multiple shares that can be distributed to trusted parties.

```dart
// Create backup (split private key into 3 shares, 2 needed to restore)
final shares = await ledger.createIdentityBackup(
  threshold: 2,
  totalShares: 3,
);
// shares is a List<String> — distribute to trusted parties
// share[0] → stored on paper
// share[1] → given to a trusted friend
// share[2] → stored in a bank vault

// Restore identity on a new device
final restoredLedger = SovereignLedger(
  config: LedgerConfig(),
  ledgerStore: myStore,
);
await restoredLedger.initialize();
await restoredLedger.restoreIdentity(
  shares: [shares[0], shares[2]], // any 2 of 3
);
```

**Notes:**
- Shamir splitting uses GF(256) arithmetic (Galois Field).
- Shares are serialized as Base64 strings with embedded index metadata.
- The threshold is the minimum number of shares needed for reconstruction.
- After restore, the `ShamirBackupService` verifies the reconstructed key by re-deriving the public key and checking it matches.

### 3.9 Privacy Profiles for Push Notifications

**Scenario:** Configure push notification behavior to balance between battery life and metadata privacy.

```dart
// Set privacy profile
await ledger.setPrivacyProfile(PrivacyProfile.private);

// Three profiles available:
// - balanced:  Real pushes only. Zero extra battery. Push provider sees timing.
// - private:   Poisson-distributed dummy pushes (~4-6/day). App wakes but
//              does zero network I/O for dummies.
// - paranoid:  Dummy pushes with real relay connections. Traffic patterns
//              fully masked. Higher battery cost.

// The push handler automatically routes:
// - Real push   → wake up, download events, process outbox
// - Dummy push  → (balanced) ignore
//                  (private) wake and drop silently
//                  (paranoid) wake and connect to relay
```

**Notes:**
- Dummy notifications contain `{"d": "1"}` in the data payload.
- The `DummyDetector` class inspects this field.
- Profile changes take effect on the next push bridge registration.

### 3.10 Offline Sync and Merge

**Scenario:** Both peers create events while offline. When they reconnect, the fork must be resolved deterministically.

```dart
// Both peers work offline...
// Peer A creates events: E1a, E2a (VC: {a:3, b:1}, {a:4, b:1})
// Peer B creates events: E1b, E2b (VC: {a:2, b:2}, {a:2, b:3})

// When they reconnect, the ledger engine detects the fork:
// - ForkDetector finds events sharing the same previousHash
// - DeterministicMerge orders concurrent events:
//   1. Sort by vector clock total (ascending)
//   2. Tiebreak by sender pubkey (lexicographic)
// - A MERGE event is appended to linearize the chain

// This happens automatically during sync. To manually validate:
final error = await ledger.validateChain();
if (error != null) {
  print('Chain error: ${error.errorType} at ${error.eventId}');
} else {
  print('Chain is valid');
}
```

**Notes:**
- Both peers apply the same deterministic ordering rule, guaranteeing convergence without additional communication.
- The MERGE event payload contains the hashes of both branch tips and the common ancestor.

### 3.11 Chain Validation

**Scenario:** Verify the integrity of the entire event chain.

```dart
final error = await ledger.validateChain();

if (error == null) {
  print('Chain integrity verified');
} else {
  switch (error.errorType) {
    case ChainErrorType.hashMismatch:
      print('Hash mismatch at event ${error.eventId}');
    case ChainErrorType.signatureInvalid:
      print('Invalid signature at event ${error.eventId}');
    case ChainErrorType.previousHashMissing:
      print('Broken chain link at event ${error.eventId}');
    case ChainErrorType.hlcViolation:
      print('HLC not monotonic at event ${error.eventId}');
    case ChainErrorType.genesisViolation:
      print('Invalid genesis event at ${error.eventId}');
  }
}

// Validate a time range
final rangeEvents = await ledger.getHistoryRange(
  from: DateTime(2026, 1, 1),
  to: DateTime(2026, 2, 1),
);
```

---

## 4. API Reference — styx (facade)

Package: `package:styx/styx.dart`

### `SovereignLedger`

> Main entry point for the Styx library. Manages the lifecycle of identity, pairing, event exchange, privacy, and device migration.

#### Constructor

```dart
SovereignLedger({
  required LedgerConfig config,
  required LedgerStore ledgerStore,
  PushBridgeRegistrar? pushBridgeRegistrar,
})
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| config | `LedgerConfig` | Yes | — | Ledger configuration (relays, privacy, retention) |
| ledgerStore | `LedgerStore` | Yes | — | Persistence layer for the event chain |
| pushBridgeRegistrar | `PushBridgeRegistrar?` | No | `null` | Optional push notification bridge |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| state | `StyxState` | Current state of the ledger |
| identity | `StyxIdentity?` | Local identity (available after initialization) |
| eventStream | `LedgerEventStream` | Reactive stream of local and remote events |

#### Methods

##### `initialize()`

> Initializes the ledger: generates or loads identity, sets up crypto, connects transport.

```dart
Future<void> initialize()
```

**Returns:** Completes when initialization is done. State transitions to `unpaired` or `ready`.

##### `shutdown()`

> Gracefully shuts down all subsystems.

```dart
Future<void> shutdown()
```

##### `generatePairingQr()`

> Generates QR pairing data containing the local public key, a fresh nonce, and optional relay hints.

```dart
Future<QrPairingData> generatePairingQr()
```

**Returns:** `QrPairingData` — encode via `toQrPayload()` for display.

##### `processPairingQr(String qrPayload)`

> Processes a scanned QR payload, validates format and anti-replay nonce.

```dart
Future<PairingResult> processPairingQr(String qrPayload)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| qrPayload | `String` | Yes | Raw string from QR scanner |

**Returns:** `PairingResult` with `isValid`, `peerPublicKey`, `relayHints`, `errorMessage`.

##### `startRemotePairing({String? existingMnemonic})`

> Starts remote pairing. If no mnemonic is provided, generates one (initiator role). If a mnemonic is provided, joins as responder.

```dart
Future<String> startRemotePairing({String? existingMnemonic})
```

**Returns:** The BIP-39 mnemonic (new or existing).

##### `getDoubleCheckCode()`

> Returns the 6-digit Double Check verification code after SPAKE2 completes.

```dart
Future<String> getDoubleCheckCode()
```

**Returns:** Formatted code string, e.g. `"483 291"`.

##### `confirmPairing({String? peerAlias})`

> Confirms pairing after QR scan or Double Check verification.

```dart
Future<void> confirmPairing({String? peerAlias})
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| peerAlias | `String?` | No | Human-readable alias for the peer |

##### `getPeer()`

> Returns the currently paired peer, or `null` if unpaired.

```dart
Future<TrustedPeer?> getPeer()
```

##### `sendTransaction({required Uint8List payload})`

> Appends a `transaction` event to the chain.

```dart
Future<void> sendTransaction({required Uint8List payload})
```

##### `sendMessage({required Uint8List payload})`

> Appends a `message` event to the chain.

```dart
Future<void> sendMessage({required Uint8List payload})
```

##### `sendSOS({required Uint8List payload})`

> Appends an `sos` event to the chain.

```dart
Future<void> sendSOS({required Uint8List payload})
```

##### `sendConfig({required Uint8List payload})`

> Appends a `config` event to the chain.

```dart
Future<void> sendConfig({required Uint8List payload})
```

##### `getHistory()`

> Returns all events in the chain, ordered by HLC.

```dart
Future<List<LedgerEvent>> getHistory()
```

##### `getHistoryRange({required DateTime from, required DateTime to})`

> Returns events within a time range.

```dart
Future<List<LedgerEvent>> getHistoryRange({
  required DateTime from,
  required DateTime to,
})
```

##### `validateChain()`

> Validates the integrity of the full event chain.

```dart
Future<ChainValidationError?> validateChain()
```

**Returns:** `null` if valid, or the first `ChainValidationError` found.

##### `setPrivacyProfile(PrivacyProfile profile)`

> Updates the push notification privacy profile.

```dart
Future<void> setPrivacyProfile(PrivacyProfile profile)
```

##### `requestPrune({required String targetEventId, required PruneReason reason})`

> Requests pruning of a specific event. Bilateral for `userRequest`/`retentionExpired`, unilateral for `gdprArticle17`.

```dart
Future<void> requestPrune({
  required String targetEventId,
  required PruneReason reason,
})
```

##### `setRetentionPolicy({required Duration period, required List<EventType> types})`

> Configures automatic retention policy.

```dart
Future<void> setRetentionPolicy({
  required Duration period,
  required List<EventType> types,
})
```

##### `getExpiredEvents()`

> Returns events that exceed the configured retention period.

```dart
Future<List<LedgerEvent>> getExpiredEvents()
```

##### `createIdentityBackup({int threshold = 2, int totalShares = 3})`

> Creates Shamir backup shares of the private key.

```dart
Future<List<String>> createIdentityBackup({
  int threshold = 2,
  int totalShares = 3,
})
```

**Returns:** List of serialized share strings.

##### `restoreIdentity({required List<String> shares})`

> Restores identity from Shamir backup shares.

```dart
Future<void> restoreIdentity({required List<String> shares})
```

##### `blessNewDevice({required StyxPublicKey newPublicKey})`

> Creates a REKEY blessing event endorsing a new device's public key.

```dart
Future<void> blessNewDevice({required StyxPublicKey newPublicKey})
```

##### `checkMigrationStatus()`

> Returns the current state of any in-progress device migration.

```dart
Future<MigrationState> checkMigrationStatus()
```

---

### `LedgerStore`

> Abstract interface for ledger persistence. Implement this to provide storage for the event chain.

```dart
abstract class LedgerStore
```

Applications must provide their own implementation backed by `styx_storage` (Drift + SQLCipher) or any other persistence layer.

---

### `PushBridgeRegistrar`

> Abstract interface for registering/unregistering with the push bridge server.

```dart
abstract class PushBridgeRegistrar
```

Implement this to wire up `PushBridgeClient` with your Firebase/APNs token management.

---

### `LedgerConfig`

> Immutable configuration for the Styx ledger.

#### Constructor

```dart
LedgerConfig({
  String? databasePath,
  List<String> relayUrls = const ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.snort.social'],
  EmailConfig? emailConfig,
  String? pushBridgeUrl,
  PrivacyProfile privacyProfile = PrivacyProfile.balanced,
  Duration? retentionPeriod,
  List<EventType> retentionTypes = const [],
  bool enableTor = false,
  Duration torTimeout = const Duration(seconds: 120),
  LogLevel logLevel = LogLevel.info,
})
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| databasePath | `String?` | No | `null` | Path to the encrypted SQLCipher database |
| relayUrls | `List<String>` | No | 3 default relays | Nostr relay WebSocket URLs |
| emailConfig | `EmailConfig?` | No | `null` | Email fallback transport config |
| pushBridgeUrl | `String?` | No | `null` | Push bridge server URL |
| privacyProfile | `PrivacyProfile` | No | `balanced` | Push notification privacy profile |
| retentionPeriod | `Duration?` | No | `null` | Auto-pruning retention period |
| retentionTypes | `List<EventType>` | No | `[]` | Event types subject to retention |
| enableTor | `bool` | No | `false` | Route transport through Tor |
| torTimeout | `Duration` | No | 120s | Tor bootstrap timeout |
| logLevel | `LogLevel` | No | `info` | Logging verbosity |

---

### `LogLevel`

> Logging verbosity level.

```dart
enum LogLevel { none, error, warning, info, debug }
```

---

### `StyxIdentity`

> Immutable representation of the local peer's identity.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| publicKey | `StyxPublicKey` | Ed25519 public key |
| nodeId | `String` | First 8 hex characters of the public key |
| peerRole | `String` | `'A'` or `'B'`, determined at pairing by lexicographic pubkey order |

---

### `StyxState`

> Lifecycle state of the Styx library.

```dart
enum StyxState {
  uninitialized,
  initializing,
  unpaired,
  ready,
  degraded,
  pairing,
  migrating,
  error,
  shuttingDown,
}
```

| Value | Description |
|-------|-------------|
| `uninitialized` | Library not yet initialized |
| `initializing` | Initialization in progress |
| `unpaired` | Identity ready, no peer paired |
| `ready` | Fully operational, peer paired |
| `degraded` | Operational with reduced transport (e.g., relay down) |
| `pairing` | Pairing protocol in progress |
| `migrating` | Device migration in progress |
| `error` | Unrecoverable error |
| `shuttingDown` | Shutdown in progress |

---

### `LedgerEventStream`

> Reactive event stream that merges local and remote event sources.

#### Constructor

```dart
LedgerEventStream({
  required Stream<LedgerEvent> localEventSource,
  required Stream<LedgerEvent> remoteEventSource,
})
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| localEventSource | `Stream<LedgerEvent>` | Yes | Stream of locally created events |
| remoteEventSource | `Stream<LedgerEvent>` | Yes | Stream of events received from the peer |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| allEvents | `Stream<LedgerEvent>` | Merged stream of all events |
| localEvents | `Stream<LedgerEvent>` | Only locally created events |
| remoteEvents | `Stream<LedgerEvent>` | Only events from the peer |

#### Methods

##### `eventsByType(EventType type)`

> Filters the merged stream by event type.

```dart
Stream<LedgerEvent> eventsByType(EventType type)
```

##### `eventsAfter(DateTime timestamp)`

> Filters the merged stream to events after a given timestamp.

```dart
Stream<LedgerEvent> eventsAfter(DateTime timestamp)
```

##### `dispose()`

> Closes all internal stream controllers.

```dart
void dispose()
```

---

### `QrPairingData`

> Immutable container for QR code pairing data.

#### Constructor

```dart
QrPairingData({
  required StyxPublicKey publicKey,
  required Uint8List nonce,
  List<String>? relayHints,
})
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| publicKey | `StyxPublicKey` | Yes | Local Ed25519 public key |
| nonce | `Uint8List` | Yes | 16-byte anti-replay nonce |
| relayHints | `List<String>?` | No | Suggested Nostr relay URLs |

#### Factory Constructors

##### `QrPairingData.fromQrPayload(String payload)`

> Deserializes from a QR-scanned string (Base64).

#### Properties

| Name | Type | Description |
|------|------|-------------|
| estimatedBytes | `int` | Estimated size in bytes of the QR payload |

#### Methods

##### `toQrPayload()`

> Serializes to a compact Base64 string for QR encoding.

```dart
String toQrPayload()
```

---

### `QrPairingService`

> Handles QR-based pairing protocol with nonce anti-replay protection.

#### Constructor

```dart
QrPairingService({
  required TrustStoreManager trustStore,
  Random? random,
})
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| trustStore | `TrustStoreManager` | Yes | Trust store for persisting paired peers |
| random | `Random?` | No | Random source (defaults to `Random.secure()`) |

#### Methods

##### `generateQrData(StyxPublicKey localPublicKey, {List<String>? relayHints})`

> Generates QR data with a fresh 16-byte nonce.

```dart
QrPairingData generateQrData(
  StyxPublicKey localPublicKey, {
  List<String>? relayHints,
})
```

##### `processScannedQr(String qrPayload, StyxPublicKey localPublicKey)`

> Validates a scanned QR payload. Checks format, prevents self-pairing, and verifies nonce anti-replay.

```dart
PairingResult processScannedQr(
  String qrPayload,
  StyxPublicKey localPublicKey,
)
```

**Returns:** `PairingResult` with validity status.

##### `completePairing(StyxPublicKey peerPublicKey, {String? peerAlias})`

> Persists the peer in the trust store.

```dart
Future<void> completePairing(
  StyxPublicKey peerPublicKey, {
  String? peerAlias,
})
```

---

### `PairingResult`

> Immutable result of a QR pairing attempt.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| peerPublicKey | `StyxPublicKey` | The peer's public key |
| relayHints | `List<String>` | Suggested relay URLs from the peer |
| isValid | `bool` | Whether the pairing data is valid |
| errorMessage | `String?` | Error description if `isValid` is false |

---

### `DoubleCheckVerifier`

> Generates and validates 6-digit Double Check verification codes.

#### Constructor

```dart
DoubleCheckVerifier({required SessionVerifier sessionVerifier})
```

#### Methods

##### `generateCode(Uint8List sessionKey)`

> Generates a 6-digit code from a SPAKE2 session key.

```dart
String generateCode(Uint8List sessionKey)
```

**Returns:** 6-digit string, e.g. `"483291"`.

##### `formatForDisplay(String code)`

> Formats the code with a space for readability.

```dart
String formatForDisplay(String code)
```

**Returns:** e.g. `"483 291"`.

##### `isValidFormat(String input)`

> Checks if input is exactly 6 digits (ignoring spaces/dashes).

```dart
bool isValidFormat(String input)
```

##### `normalize(String input)`

> Removes spaces and dashes from input.

```dart
String normalize(String input)
```

---

### `RemotePairingService`

> Manages the full remote pairing flow: mnemonic → SPAKE2 → Double Check → trust store.

#### Constructor

```dart
RemotePairingService({
  required Spake2Protocol spake2Protocol,
  required MnemonicGenerator mnemonicGenerator,
  required DoubleCheckVerifier doubleCheckVerifier,
  required TrustStoreManager trustStore,
  Duration? timeout,
})
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| spake2Protocol | `Spake2Protocol` | Yes | SPAKE2 session factory |
| mnemonicGenerator | `MnemonicGenerator` | Yes | BIP-39 mnemonic generator |
| doubleCheckVerifier | `DoubleCheckVerifier` | Yes | 6-digit code verifier |
| trustStore | `TrustStoreManager` | Yes | Trust store manager |
| timeout | `Duration?` | No | Optional timeout for the pairing process |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| state | `RemotePairingState` | Current pairing state |
| stateStream | `Stream<RemotePairingState>` | Reactive state changes |
| peerPublicKey | `StyxPublicKey?` | Peer's public key (available after SPAKE2) |

#### Methods

##### `generateMnemonic({int? wordCount})`

> Generates a BIP-39 mnemonic for out-of-band sharing.

```dart
String generateMnemonic({int? wordCount})
```

##### `startAsInitiator(String mnemonic, StyxPublicKey localPublicKey)`

> Starts SPAKE2 as the initiator.

```dart
Future<Uint8List> startAsInitiator(String mnemonic, StyxPublicKey localPublicKey)
```

**Returns:** SPAKE2 message bytes to send to the peer.

##### `startAsResponder(String mnemonic, StyxPublicKey localPublicKey)`

> Starts SPAKE2 as the responder.

```dart
Future<Uint8List> startAsResponder(String mnemonic, StyxPublicKey localPublicKey)
```

**Returns:** SPAKE2 message bytes to send to the peer.

##### `processPeerMessage(Uint8List peerMessage)`

> Processes the peer's SPAKE2 message and derives the shared session key.

```dart
Future<void> processPeerMessage(Uint8List peerMessage)
```

##### `getDoubleCheckCode()`

> Returns the 6-digit verification code for verbal comparison.

```dart
String getDoubleCheckCode()
```

##### `confirmDoubleCheck(bool codeMatches, {String? peerAlias})`

> Completes or fails the pairing based on code comparison.

```dart
Future<void> confirmDoubleCheck(bool codeMatches, {String? peerAlias})
```

##### `cancel()`

> Cancels the pairing process.

```dart
void cancel()
```

##### `dispose()`

> Releases resources.

```dart
void dispose()
```

##### `deriveSharedTag(String mnemonic)` (static)

> Derives a discovery tag from the mnemonic for peer discovery.

```dart
static String deriveSharedTag(String mnemonic)
```

---

### `RemotePairingState`

> State machine for remote pairing.

```dart
enum RemotePairingState {
  idle,
  mnemonicGenerated,
  waitingForPeer,
  spake2InProgress,
  doubleCheckPending,
  completed,
  failed,
}
```

---

### `TrustStoreManager`

> Manages the trust store of paired peers with re-keying history.

#### Constructor

```dart
TrustStoreManager({required PeerStore peerStore})
```

#### Methods

##### `addTrustedPeer(StyxPublicKey peerPublicKey, {String? alias})`

> Adds a peer to the trust store.

```dart
Future<void> addTrustedPeer(StyxPublicKey peerPublicKey, {String? alias})
```

##### `revokePeer(StyxPublicKey peerPublicKey)`

> Deactivates a peer (marks as untrusted).

```dart
Future<void> revokePeer(StyxPublicKey peerPublicKey)
```

##### `isTrusted(StyxPublicKey publicKey)`

> Checks whether a public key belongs to an active trusted peer.

```dart
Future<bool> isTrusted(StyxPublicKey publicKey)
```

##### `getActivePeer()`

> Returns the currently active trusted peer, or `null`.

```dart
Future<TrustedPeer?> getActivePeer()
```

##### `updatePeerKey(StyxPublicKey oldKey, StyxPublicKey newKey)`

> Updates a peer's key after a re-key event and records the change.

```dart
Future<void> updatePeerKey(StyxPublicKey oldKey, StyxPublicKey newKey)
```

##### `getRekeyHistory(StyxPublicKey currentKey)`

> Returns the re-key history for a peer.

```dart
Future<List<RekeyRecord>> getRekeyHistory(StyxPublicKey currentKey)
```

---

### `TrustedPeer`

> Immutable representation of a trusted peer.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| publicKey | `StyxPublicKey` | Peer's current Ed25519 public key |
| alias | `String?` | Human-readable alias |
| pairedAt | `DateTime` | When the pairing was established |
| isActive | `bool` | Whether the peer is currently trusted |

---

### `RekeyRecord`

> Immutable record of a key change.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| oldKey | `String` | Hex-encoded old public key |
| newKey | `String` | Hex-encoded new public key |
| timestamp | `DateTime` | When the re-key occurred |

---

### `PeerStore`

> Abstract interface for peer persistence.

```dart
abstract class PeerStore {
  Future<void> addPeer({
    required String pubkeyHex,
    String? alias,
    required DateTime pairedAt,
  });
  Future<TrustedPeer?> getPeerByPubkey(String pubkeyHex);
  Future<List<TrustedPeer>> getActivePeers();
  Future<void> deactivatePeer(String pubkeyHex);
  Future<void> updatePeerKey({
    required String oldPubkeyHex,
    required String newPubkeyHex,
  });
  Future<void> addRekeyEntry({
    required String oldKeyHex,
    required String newKeyHex,
    required DateTime timestamp,
  });
  Future<List<RekeyRecord>> getRekeyHistory(String currentKeyHex);
}
```

---

### `InMemoryPeerStore`

> In-memory implementation of `PeerStore` for testing.

```dart
class InMemoryPeerStore implements PeerStore
```

Stores peers and re-key records in memory. Not suitable for production.

---

### `ReKeyProtocol`

> Manages the re-keying protocol for device migration.

#### Constructor

```dart
ReKeyProtocol({
  required EventFactory eventFactory,
  required TrustStoreManager trustStoreManager,
  required Verifier verifier,
})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| state | `ReKeyState` | Current re-key protocol state |

#### Methods

##### `createBlessingEvent(...)`

> Creates a REKEY blessing event signed by the old key.

```dart
Future<LedgerEvent> createBlessingEvent({
  required StyxPrivateKey oldPrivateKey,
  required StyxPublicKey oldPublicKey,
  required StyxPublicKey newPublicKey,
  required LedgerEvent? previousEvent,
  required VectorClock currentVectorClock,
  required String localPeerRole,
})
```

**Returns:** A `LedgerEvent` of type `rekey` containing the new public key in the payload.

##### `processReKeyEvent(LedgerEvent rekeyEvent)`

> Processes a received REKEY event: verifies signature, extracts new key, updates trust store.

```dart
Future<ReKeyResult> processReKeyEvent(LedgerEvent rekeyEvent)
```

**Returns:** `ReKeyResult` indicating success or failure.

##### `isReKeyAcknowledged(StyxPublicKey newKey)`

> Checks if the peer has accepted the new key.

```dart
Future<bool> isReKeyAcknowledged(StyxPublicKey newKey)
```

---

### `ReKeyState`

```dart
enum ReKeyState { idle, blessingCreated, blessingSent, peerUpdated, completed }
```

---

### `ReKeyResult`

> Immutable result of processing a re-key event.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| success | `bool` | Whether the re-key was accepted |
| oldKey | `StyxPublicKey` | The previous public key |
| newKey | `StyxPublicKey` | The new public key |
| errorMessage | `String?` | Error description if `success` is false |

---

### `KeyMigrationService`

> Orchestrates the full device migration flow across old device, new device, and peer.

#### Constructor

```dart
KeyMigrationService({
  required IdentityManager identityManager,
  required ReKeyProtocol reKeyProtocol,
  required KeyBackup keyBackup,
})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| state | `MigrationState` | Current migration state |
| stateStream | `Stream<MigrationState>` | Reactive state changes |

#### Methods

##### `generateNewIdentity()`

> Step 1: Generates a new Ed25519 keypair on the new device.

```dart
Future<StyxKeyPair> generateNewIdentity()
```

##### `blessNewDevice()`

> Step 2: Creates a blessing event on the old device.

```dart
Future<LedgerEvent> blessNewDevice()
```

##### `checkPeerAcknowledgment(StyxPublicKey newPublicKey)`

> Step 3: Checks if the peer has acknowledged the re-key.

```dart
Future<bool> checkPeerAcknowledgment(StyxPublicKey newPublicKey)
```

##### `restoreFromBackup(List<ShamirShare> shares)`

> Restores identity from Shamir shares (alternative to old-device blessing).

```dart
Future<StyxKeyPair> restoreFromBackup(List<ShamirShare> shares)
```

##### `dispose()`

```dart
void dispose()
```

---

### `MigrationState`

```dart
enum MigrationState {
  idle,
  newKeyGenerated,
  blessingCreated,
  blessingSent,
  waitingPeerAck,
  syncingHistory,
  completed,
  failed,
}
```

---

### `MigrationLedger`

> Abstract interface for ledger operations during migration.

```dart
abstract class MigrationLedger {
  Future<void> appendEvent(LedgerEvent event);
  Future<LedgerEvent?> getLatestEvent();
  Future<VectorClock> getCurrentVectorClock();
  Future<List<LedgerEvent>> getHistory();
}
```

---

### `ShamirBackupService`

> High-level service for creating and restoring Shamir secret sharing backups.

#### Constructor

```dart
ShamirBackupService({
  required KeyBackup keyBackup,
  required SecureKeyStore secureKeyStore,
})
```

#### Methods

##### `createBackup(StyxPrivateKey privateKey, {int threshold = 2, int totalShares = 3})`

> Splits the private key into Shamir shares.

```dart
List<String> createBackup(
  StyxPrivateKey privateKey, {
  int threshold = 2,
  int totalShares = 3,
})
```

**Returns:** List of serialized share strings (Base64 with embedded index).

##### `restoreFromBackup(List<String> serializedShares, String keyId)`

> Reconstructs the keypair from shares and saves to the secure store.

```dart
Future<StyxKeyPair> restoreFromBackup(
  List<String> serializedShares,
  String keyId,
)
```

##### `verifyShares(List<String> serializedShares)`

> Verifies that shares can reconstruct a valid keypair without persisting.

```dart
Future<bool> verifyShares(List<String> serializedShares)
```

---

## 5. API Reference — crypto_core

Package: `package:styx_crypto_core/styx_crypto_core.dart`

### `StyxPublicKey`

> Immutable Ed25519 public key (32 bytes).

#### Constructor

```dart
StyxPublicKey(Uint8List bytes)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| bytes | `Uint8List` | Yes | Raw 32-byte public key |

#### Factory Constructors

##### `StyxPublicKey.fromHex(String hex)`

> Creates from hex-encoded string.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| bytes | `Uint8List` | Raw public key bytes |

#### Methods

##### `toHex()`

> Returns hex-encoded string representation.

```dart
String toHex()
```

**Equality:** Two `StyxPublicKey` instances are equal if their bytes are identical (constant-time comparison).

---

### `StyxPrivateKey`

> Ed25519 private key with secure destruction support.

#### Constructor

```dart
StyxPrivateKey(Uint8List bytes)
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| bytes | `Uint8List` | Raw private key bytes (throws if destroyed) |
| isDestroyed | `bool` | Whether the key has been zeroed out |

#### Methods

##### `destroy()`

> Zeroes out the key material. Subsequent access to `bytes` throws `StateError`.

```dart
void destroy()
```

---

### `StyxKeyPair`

> Container for an Ed25519 public/private key pair.

#### Constructor

```dart
const StyxKeyPair({
  required StyxPublicKey publicKey,
  required StyxPrivateKey privateKey,
})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| publicKey | `StyxPublicKey` | Public key |
| privateKey | `StyxPrivateKey` | Private key |

---

### `IdentityManager`

> Generates and imports Ed25519 key pairs.

#### Methods

##### `generate()`

> Generates a new Ed25519 keypair.

```dart
Future<StyxKeyPair> generate()
```

##### `exportPublicKey(StyxPublicKey publicKey)`

> Exports a public key as raw bytes.

```dart
Uint8List exportPublicKey(StyxPublicKey publicKey)
```

##### `importPublicKey(Uint8List bytes)`

> Imports a public key from raw bytes.

```dart
StyxPublicKey importPublicKey(Uint8List bytes)
```

##### `exportPrivateKey(StyxPrivateKey privateKey)`

> Exports a private key as raw bytes.

```dart
Uint8List exportPrivateKey(StyxPrivateKey privateKey)
```

##### `importPrivateKey(Uint8List bytes)`

> Reconstructs a full keypair from raw private key bytes.

```dart
Future<StyxKeyPair> importPrivateKey(Uint8List bytes)
```

---

### `Signer`

> Signs data with Ed25519 private keys.

#### Methods

##### `sign(Uint8List payload, StyxPrivateKey privateKey)`

> Creates an Ed25519 signature.

```dart
Future<Uint8List> sign(Uint8List payload, StyxPrivateKey privateKey)
```

**Returns:** Signature bytes (64 bytes).

---

### `Verifier`

> Verifies Ed25519 signatures.

#### Methods

##### `verify({required Uint8List payload, required Uint8List signatureBytes, required StyxPublicKey publicKey})`

> Verifies an Ed25519 signature.

```dart
Future<bool> verify({
  required Uint8List payload,
  required Uint8List signatureBytes,
  required StyxPublicKey publicKey,
})
```

---

### `Hasher`

> SHA-256 hashing utilities.

#### Methods

##### `hash(Uint8List data)`

> Computes SHA-256 hash.

```dart
Uint8List hash(Uint8List data)
```

##### `chainHash({required Uint8List? previousHash, required Uint8List payload})`

> Computes hash for chain linkage: `SHA-256(previousHash || payload)`.

```dart
Uint8List chainHash({
  required Uint8List? previousHash,
  required Uint8List payload,
})
```

##### `compositeHash(List<Uint8List> segments)`

> Computes `SHA-256(segment[0] || segment[1] || ... || segment[n])`.

```dart
Uint8List compositeHash(List<Uint8List> segments)
```

---

### `Spake2Protocol`

> Factory for creating SPAKE2 sessions on NIST P-256.

#### Methods

##### `createInitiatorSession(Uint8List password)`

> Creates an initiator-side SPAKE2 session.

```dart
Spake2Session createInitiatorSession(Uint8List password)
```

##### `createResponderSession(Uint8List password)`

> Creates a responder-side SPAKE2 session.

```dart
Spake2Session createResponderSession(Uint8List password)
```

##### `mnemonicToPassword(String mnemonic)`

> Converts a BIP-39 mnemonic to a password suitable for SPAKE2.

```dart
Uint8List mnemonicToPassword(String mnemonic)
```

---

### `Spake2Session`

> A SPAKE2 session that progresses through `init → messageSent → completed`.

#### Constructor

```dart
Spake2Session({
  required Spake2Role role,
  required Uint8List password,
})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| role | `Spake2Role` | `initiator` or `responder` |
| state | `Spake2State` | Current session state |

#### Methods

##### `generateMessage()`

> Generates the SPAKE2 message to send to the peer.

```dart
Uint8List generateMessage()
```

##### `processMessage(Uint8List peerMessage)`

> Processes the peer's SPAKE2 message. Returns `true` if the session key was derived.

```dart
bool processMessage(Uint8List peerMessage)
```

##### `getSessionKey()`

> Returns the derived shared session key.

```dart
Uint8List getSessionKey()
```

**Throws:** `StateError` if called before `processMessage` completes.

##### `getConfirmation()`

> Returns the HMAC confirmation value for the session.

```dart
Uint8List getConfirmation()
```

##### `verifyConfirmation(Uint8List peerConfirmation)`

> Verifies the peer's HMAC confirmation.

```dart
bool verifyConfirmation(Uint8List peerConfirmation)
```

##### `destroy()`

> Zeroes out all session secrets.

```dart
void destroy()
```

---

### `Spake2Role`

```dart
enum Spake2Role { initiator, responder }
```

### `Spake2State`

```dart
enum Spake2State { init, messageSent, completed, failed }
```

---

### `MnemonicGenerator`

> Generates and validates BIP-39 mnemonics from the English wordlist (2048 words).

#### Methods

##### `generate({int wordCount = 6})`

> Generates a random mnemonic.

```dart
String generate({int wordCount = 6})
```

**Returns:** Space-separated words, e.g. `"abandon ability able about above absent"`.

##### `validate(String mnemonic)`

> Validates that all words exist in the BIP-39 wordlist.

```dart
bool validate(String mnemonic)
```

##### `mnemonicToSeed(String mnemonic)`

> Derives a 32-byte seed from the mnemonic via PBKDF2.

```dart
Future<Uint8List> mnemonicToSeed(String mnemonic)
```

##### `supportedLanguages`

> Returns the list of supported languages (currently `['english']`).

```dart
List<String> get supportedLanguages
```

---

### `SessionVerifier`

> Derives 6-digit verification codes from SPAKE2 session keys.

#### Methods

##### `generateDoubleCheckCode(Uint8List sessionKey)`

> Computes `SHA-256(sessionKey || suffix)`, truncates to 6 decimal digits.

```dart
String generateDoubleCheckCode(Uint8List sessionKey)
```

---

### `KeyBackup`

> Creates and restores Shamir secret sharing backups of private keys.

#### Constructor

```dart
KeyBackup({
  required ShamirSplitter splitter,
  required ShamirReconstructor reconstructor,
})
```

#### Methods

##### `backupPrivateKey({required StyxPrivateKey privateKey, int threshold = 2, int totalShares = 3})`

> Splits a private key into Shamir shares.

```dart
List<ShamirShare> backupPrivateKey({
  required StyxPrivateKey privateKey,
  int threshold = 2,
  int totalShares = 3,
})
```

##### `restoreFromShares(List<ShamirShare> shares)`

> Reconstructs a full keypair from Shamir shares.

```dart
Future<StyxKeyPair> restoreFromShares(List<ShamirShare> shares)
```

---

### `ShamirSplitter`

> Splits secrets using Shamir's Secret Sharing over GF(256).

#### Methods

##### `split({required Uint8List secret, int threshold = 2, int totalShares = 3})`

> Splits a secret into shares.

```dart
List<ShamirShare> split({
  required Uint8List secret,
  int threshold = 2,
  int totalShares = 3,
})
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| secret | `Uint8List` | Yes | — | The secret to split |
| threshold | `int` | No | `2` | Minimum shares to reconstruct |
| totalShares | `int` | No | `3` | Total shares to create |

**Constraints:** `2 ≤ threshold ≤ totalShares ≤ 255`.

---

### `ShamirReconstructor`

> Reconstructs secrets from Shamir shares using Lagrange interpolation.

#### Methods

##### `reconstruct(List<ShamirShare> shares)`

> Reconstructs the original secret from shares.

```dart
Uint8List reconstruct(List<ShamirShare> shares)
```

**Throws:**
- `InsufficientSharesException` if fewer than 2 shares are provided.
- `InvalidShareException` if shares have inconsistent lengths.

---

### `ShamirShare`

> Immutable Shamir secret share.

#### Constructor

```dart
const ShamirShare({required int index, required Uint8List data})
```

#### Factory Constructors

##### `ShamirShare.deserialize(String encoded)`

> Deserializes from a string (as produced by `serialize()`).

#### Properties

| Name | Type | Description |
|------|------|-------------|
| index | `int` | Share index (1-based, used in Lagrange interpolation) |
| data | `Uint8List` | Share data bytes |

#### Methods

##### `serialize()`

> Serializes to a string for storage/transmission.

```dart
String serialize()
```

---

### `InsufficientSharesException`

> Thrown when not enough shares are provided for reconstruction.

```dart
class InsufficientSharesException implements Exception {
  const InsufficientSharesException(String message);
  final String message;
}
```

### `InvalidShareException`

> Thrown when shares are malformed or inconsistent.

```dart
class InvalidShareException implements Exception {
  const InvalidShareException(String message);
  final String message;
}
```

---

### `SecureKeyStore`

> Abstract interface for secure key storage (hardware enclave backed in production).

```dart
abstract class SecureKeyStore {
  Future<void> storeKeyPair({required String keyId, required StyxKeyPair keyPair});
  Future<StyxKeyPair?> retrieveKeyPair(String keyId);
  Future<void> deleteKeyPair(String keyId);
  Future<bool> hasKeyPair(String keyId);
  Future<void> storeSecret({required String key, required Uint8List value});
  Future<Uint8List?> retrieveSecret(String key);
  Future<void> deleteSecret(String key);
  Future<void> deleteAll();
}
```

---

### `InMemoryKeyStore`

> In-memory implementation of `SecureKeyStore` for testing.

```dart
class InMemoryKeyStore implements SecureKeyStore
```

---

### `KeyConverter`

> Converts Ed25519 keys to X25519 format for Diffie-Hellman key exchange.

#### Methods

##### `ed25519PublicToX25519(StyxPublicKey publicKey)`

```dart
Uint8List ed25519PublicToX25519(StyxPublicKey publicKey)
```

##### `ed25519PrivateToX25519(StyxPrivateKey privateKey)`

```dart
Uint8List ed25519PrivateToX25519(StyxPrivateKey privateKey)
```

---

### `DiffieHellman`

> X25519 Diffie-Hellman key exchange.

#### Methods

##### `generateEphemeralKeyPair()`

```dart
Future<X25519KeyPair> generateEphemeralKeyPair()
```

##### `computeSharedSecret({required Uint8List localPrivateKey, required Uint8List remotePublicKey})`

```dart
Future<Uint8List> computeSharedSecret({
  required Uint8List localPrivateKey,
  required Uint8List remotePublicKey,
})
```

---

### `X25519KeyPair`

> Ephemeral X25519 key pair with secure destruction.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| publicKey | `Uint8List` | X25519 public key |
| privateKey | `Uint8List` | X25519 private key (throws if destroyed) |
| isDestroyed | `bool` | Whether key material has been zeroed |

#### Methods

##### `destroy()`

```dart
void destroy()
```

---

### `KeyDerivation`

> HKDF-based key derivation.

#### Methods

##### `deriveKey({required Uint8List sharedSecret, required Uint8List info, Uint8List? salt, int outputLength = 32})`

```dart
Future<Uint8List> deriveKey({
  required Uint8List sharedSecret,
  required Uint8List info,
  Uint8List? salt,
  int outputLength = 32,
})
```

##### `deriveDirectionalKeys({required Uint8List sharedSecret, required Uint8List localPubKey, required Uint8List remotePubKey})`

> Derives send/receive keys based on lexicographic public key order.

```dart
Future<DirectionalKeys> deriveDirectionalKeys({
  required Uint8List sharedSecret,
  required Uint8List localPubKey,
  required Uint8List remotePubKey,
})
```

---

### `DirectionalKeys`

> Send and receive key pair with secure destruction.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| sendKey | `Uint8List` | Key for encrypting outgoing messages |
| receiveKey | `Uint8List` | Key for decrypting incoming messages |
| isDestroyed | `bool` | Whether key material has been zeroed |

#### Methods

##### `destroy()`

```dart
void destroy()
```

---

## 6. API Reference — ledger_engine

Package: `package:styx_ledger_engine/styx_ledger_engine.dart`

### `LedgerEvent`

> Immutable representation of a ledger event in the hash chain.

#### Constructor

```dart
LedgerEvent({
  required String eventId,
  required EventType eventType,
  Uint8List? payload,
  String? previousHash,
  required String eventHash,
  required HybridLogicalClock hlc,
  required VectorClock vectorClock,
  required String senderPubkey,
  required Uint8List signature,
  required DateTime createdAt,
  bool isPruned = false,
})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| eventId | `String` | UUID v4 identifier |
| eventType | `EventType` | Type of event |
| payload | `Uint8List?` | Event data (null after pruning) |
| previousHash | `String?` | Hash of the preceding event (null for genesis) |
| eventHash | `String` | SHA-256 hash of this event |
| hlc | `HybridLogicalClock` | Hybrid logical clock timestamp |
| vectorClock | `VectorClock` | 2-element vector clock |
| senderPubkey | `String` | Hex-encoded sender public key |
| signature | `Uint8List` | Ed25519 signature over the event hash |
| createdAt | `DateTime` | Wall-clock creation time (UTC) |
| isPruned | `bool` | Whether the payload has been pruned |

---

### `EventType`

> Types of events in the ledger.

```dart
enum EventType {
  transaction,
  message,
  sos,
  config,
  rekey,
  merge,
  pruneRequest,
  pruneAck,
}
```

| Value | Description |
|-------|-------------|
| `transaction` | Financial or data transaction |
| `message` | Text message |
| `sos` | Emergency signal |
| `config` | Configuration change (also used for genesis) |
| `rekey` | Device re-keying (blessing) event |
| `merge` | Fork resolution event |
| `pruneRequest` | Request to prune an event (bilateral) |
| `pruneAck` | Acknowledgment of a prune request |

---

### `EventFactory`

> Creates signed, hashed events for the ledger chain.

#### Constructor

```dart
EventFactory({required Signer signer, required Hasher hasher})
```

#### Methods

##### `createEvent({...})`

> Creates a new event appended to the chain. Generates UUID, computes HLC, increments vector clock, computes SHA-256 hash, signs with Ed25519.

```dart
Future<LedgerEvent> createEvent({
  required EventType type,
  required Uint8List payload,
  required StyxPrivateKey privateKey,
  required StyxPublicKey publicKey,
  required LedgerEvent? previousEvent,
  required VectorClock currentVectorClock,
  required String localPeerRole,
})
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| type | `EventType` | Yes | Event type |
| payload | `Uint8List` | Yes | Event data |
| privateKey | `StyxPrivateKey` | Yes | Signing key |
| publicKey | `StyxPublicKey` | Yes | Sender public key |
| previousEvent | `LedgerEvent?` | Yes | Previous event (null for genesis) |
| currentVectorClock | `VectorClock` | Yes | Current vector clock state |
| localPeerRole | `String` | Yes | `'A'` or `'B'` |

##### `createGenesisEvent({...})`

> Creates the first event in the chain.

```dart
Future<LedgerEvent> createGenesisEvent({
  required StyxPrivateKey privateKey,
  required StyxPublicKey publicKey,
  required String nodeId,
})
```

##### `computeHashBytes({...})`

> Computes `SHA-256(previousHash || eventType || payload || hlcBytes)`.

```dart
Uint8List computeHashBytes({
  required String? previousHash,
  required EventType eventType,
  required Uint8List? payload,
  required Uint8List hlcBytes,
})
```

---

### `ChainValidator`

> Validates the integrity of the ledger chain.

#### Constructor

```dart
ChainValidator({required Hasher hasher, required Verifier verifier})
```

#### Methods

##### `validateFullChain(List<LedgerEvent> events)`

> Validates every event in sequence. Checks genesis validity, hash linkage, hash integrity, Ed25519 signatures, and HLC monotonicity.

```dart
Future<ChainValidationError?> validateFullChain(List<LedgerEvent> events)
```

**Returns:** `null` if valid, or the first error found.

##### `validateEvent({...})`

> Validates a single event against its predecessor.

```dart
Future<ChainValidationError?> validateEvent({
  required LedgerEvent event,
  required LedgerEvent? previousEvent,
  required StyxPublicKey senderPublicKey,
})
```

##### `verifyEventHash(LedgerEvent event, String? previousHash)`

> Verifies that the event's stored hash matches the computed hash.

```dart
Future<bool> verifyEventHash(LedgerEvent event, String? previousHash)
```

##### `verifyEventSignature(LedgerEvent event, StyxPublicKey publicKey)`

> Verifies the Ed25519 signature on the event.

```dart
Future<bool> verifyEventSignature(LedgerEvent event, StyxPublicKey publicKey)
```

---

### `ChainValidationError`

> Describes a chain validation error.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| eventId | `String` | ID of the event with the error |
| errorType | `ChainErrorType` | Category of error |
| message | `String` | Human-readable description |

---

### `ChainErrorType`

```dart
enum ChainErrorType {
  hashMismatch,
  signatureInvalid,
  previousHashMissing,
  hlcViolation,
  genesisViolation,
}
```

| Value | Description |
|-------|-------------|
| `hashMismatch` | Computed hash differs from stored hash |
| `signatureInvalid` | Ed25519 signature verification failed |
| `previousHashMissing` | `previousHash` does not match preceding event's hash |
| `hlcViolation` | HLC is not monotonically increasing |
| `genesisViolation` | First event has a non-null `previousHash` |

---

### `VectorClock`

> 2-element vector clock for the Styx 2-peer system.

#### Constructors

```dart
const VectorClock({required int a, required int b})
const VectorClock.zero()  // a: 0, b: 0
factory VectorClock.fromJson(Map<String, dynamic> json)
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| a | `int` | Counter for peer A |
| b | `int` | Counter for peer B |
| total | `int` | Sum `a + b` (used for deterministic merge ordering) |

#### Methods

##### `increment(String localPeerRole)`

> Returns a new `VectorClock` with the counter for the given role incremented.

```dart
VectorClock increment(String localPeerRole)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| localPeerRole | `String` | `'A'` or `'B'` |

**Throws:** `ArgumentError` if role is not `'A'` or `'B'`.

##### `merge(VectorClock other)`

> Returns a new `VectorClock` with component-wise maximum.

```dart
VectorClock merge(VectorClock other)
```

##### `causalRelation(VectorClock other)`

> Compares the causal relationship.

```dart
CausalRelation causalRelation(VectorClock other)
```

##### `toJson()`

```dart
Map<String, int> toJson()
```

##### `toBytes()`

> Serializes to 8 bytes (4 for A, 4 for B, big-endian).

```dart
Uint8List toBytes()
```

---

### `CausalRelation`

```dart
enum CausalRelation { before, after, concurrent, equal }
```

| Value | Description |
|-------|-------------|
| `before` | This clock is causally before the other |
| `after` | This clock is causally after the other |
| `concurrent` | No causal relationship (fork) |
| `equal` | Identical clocks |

---

### `HybridLogicalClock`

> Hybrid Logical Clock combining wall-clock time, logical counter, and node ID.

#### Constructor

```dart
HybridLogicalClock({
  required DateTime timestamp,
  required int counter,
  required String nodeId,
})
```

#### Factory Constructors

##### `HybridLogicalClock.now({HybridLogicalClock? previous, required String nodeId})`

> Creates an HLC for the current instant, ensuring monotonicity with `previous`.

##### `HybridLogicalClock.fromCanonical(String s)`

> Parses from canonical format: `2026-02-24T12:00:00.000Z-0042-a1b2c3d4`.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| timestamp | `DateTime` | UTC wall-clock time |
| counter | `int` | Logical counter (tiebreaker within same millisecond) |
| nodeId | `String` | Node identifier (first 8 hex chars of pubkey) |

#### Methods

##### `toCanonical()`

> Returns canonical string: `2026-02-24T12:00:00.000Z-0042-a1b2c3d4`.

```dart
String toCanonical()
```

##### `toBytes()`

> Serializes to bytes for hash computation.

```dart
Uint8List toBytes()
```

##### `compareTo(HybridLogicalClock other)`

> Compares by timestamp, then counter, then nodeId.

```dart
int compareTo(HybridLogicalClock other)
```

---

### `PruneProtocol`

> Bilateral pruning protocol for GDPR compliance.

#### Constructor

```dart
PruneProtocol({required EventFactory eventFactory})
```

#### Methods

##### `requestPrune({...})`

> Creates a `PRUNE_REQUEST` event.

```dart
Future<LedgerEvent> requestPrune({
  required String targetEventId,
  required String targetEventHash,
  required PruneReason reason,
  required StyxPrivateKey privateKey,
  required StyxPublicKey publicKey,
  required LedgerEvent? previousEvent,
  required VectorClock currentVectorClock,
  required String localPeerRole,
})
```

##### `acknowledgePrune({...})`

> Creates a `PRUNE_ACK` event in response to a request.

```dart
Future<LedgerEvent> acknowledgePrune({
  required LedgerEvent pruneRequest,
  required StyxPrivateKey privateKey,
  required StyxPublicKey publicKey,
  required LedgerEvent? previousEvent,
  required VectorClock currentVectorClock,
  required String localPeerRole,
})
```

##### `executeBilateralPrune({required String targetEventId, required EventDao eventDao})`

> Nullifies the payload after both `REQUEST` and `ACK`.

```dart
Future<void> executeBilateralPrune({
  required String targetEventId,
  required EventDao eventDao,
})
```

##### `executeUnilateralPrune({required String targetEventId, required EventDao eventDao})`

> Immediately nullifies the payload (GDPR Art. 17, no ACK needed).

```dart
Future<void> executeUnilateralPrune({
  required String targetEventId,
  required EventDao eventDao,
})
```

---

### `PruneState`

```dart
enum PruneState { idle, requestSent, waitingAck, pruned, unilateralPruned }
```

### `PruneReason`

```dart
enum PruneReason { retentionExpired, userRequest, gdprArticle17 }
```

---

### `RetentionManager`

> Evaluates retention policies to identify expired events.

#### Methods

##### `getExpiredEvents({...})`

> Returns events that exceed the retention period.

```dart
List<LedgerEvent> getExpiredEvents({
  required List<LedgerEvent> events,
  required Duration retentionPeriod,
  required List<EventType> applicableTypes,
})
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| events | `List<LedgerEvent>` | Yes | All events to evaluate |
| retentionPeriod | `Duration` | Yes | Maximum age before expiry |
| applicableTypes | `List<EventType>` | Yes | Event types subject to retention |

Already-pruned events are excluded.

---

### `LedgerService`

> High-level facade for ledger operations with persistent storage.

#### Constructor

```dart
LedgerService({
  required EventFactory eventFactory,
  required ChainValidator chainValidator,
  required EventDao eventDao,
  required String localPeerRole,
})
```

#### Methods

##### `appendEvent({...})`

> Appends a new event to the local chain.

```dart
Future<LedgerEvent> appendEvent({
  required EventType type,
  required Uint8List payload,
  required StyxPrivateKey privateKey,
  required StyxPublicKey publicKey,
})
```

##### `getHistory()`

> Returns all events ordered by HLC.

```dart
Future<List<LedgerEvent>> getHistory()
```

##### `validateChain()`

> Validates the full chain.

```dart
Future<ChainValidationError?> validateChain()
```

##### `getLatestEvent()`

> Returns the latest event, or `null` for empty chains.

```dart
Future<LedgerEvent?> getLatestEvent()
```

##### `watchNewEvents()`

> Reactive stream emitting new events as they are appended.

```dart
Stream<LedgerEvent> watchNewEvents()
```

---

### `ForkDetector`

> Detects forks in the event chain by finding events that share the same `previousHash`.

#### Constructor

```dart
ForkDetector({CausalityChecker? causalityChecker})
```

#### Methods

##### `detectForks(List<LedgerEvent> events)`

> Scans all events for forks.

```dart
List<Fork> detectForks(List<LedgerEvent> events)
```

##### `detectForkOnReceive({required LedgerEvent remoteEvent, required LedgerEvent localHead})`

> Detects if a received remote event creates a fork with the local head.

```dart
Fork? detectForkOnReceive({
  required LedgerEvent remoteEvent,
  required LedgerEvent localHead,
})
```

---

### `Fork`

> Represents a fork where two branches diverge from a common ancestor.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| commonAncestorHash | `String` | Hash of the last common event |
| branchA | `List<LedgerEvent>` | Events on branch A (typically local) |
| branchB | `List<LedgerEvent>` | Events on branch B (typically remote) |

---

### `DeterministicMerge`

> Performs deterministic merge of forked branches. Both peers apply the same ordering rule, guaranteeing convergence.

#### Methods

##### `orderConcurrentEvents(List<LedgerEvent> events)`

> Orders concurrent events: (1) by vector clock total ascending, (2) by sender pubkey lexicographic.

```dart
List<LedgerEvent> orderConcurrentEvents(List<LedgerEvent> events)
```

##### `merge({required Fork fork, required String localPeerRole})`

> Merges a fork into a linear sequence.

```dart
MergeResult merge({required Fork fork, required String localPeerRole})
```

---

### `MergeResult`

> Result of a deterministic merge operation.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| orderedEvents | `List<LedgerEvent>` | Deterministically ordered event sequence |
| mergeEventNeeded | `bool` | Whether a MERGE event should be appended |

---

### `MergeEventFactory`

> Creates MERGE events that reference both tips of a fork.

#### Constructor

```dart
MergeEventFactory({required EventFactory eventFactory})
```

#### Methods

##### `createMergeEvent({...})`

```dart
Future<LedgerEvent> createMergeEvent({
  required String branchAHeadHash,
  required String branchBHeadHash,
  required String ancestorHash,
  required LedgerEvent newPreviousEvent,
  required StyxPrivateKey privateKey,
  required StyxPublicKey publicKey,
  required VectorClock mergedVectorClock,
  required String localPeerRole,
})
```

The payload is JSON: `{"type": "merge", "branch_a_head": "...", "branch_b_head": "...", "ancestor": "..."}`.

---

### `CausalityChecker`

> Determines causal relationships between vector clocks.

#### Methods

##### `compare(VectorClock a, VectorClock b)`

```dart
CausalRelation compare(VectorClock a, VectorClock b)
```

##### `isAfter(VectorClock event, VectorClock reference)`

```dart
bool isAfter(VectorClock event, VectorClock reference)
```

##### `isConcurrent(VectorClock a, VectorClock b)`

```dart
bool isConcurrent(VectorClock a, VectorClock b)
```

---

## 7. API Reference — transport

Package: `package:styx_transport/styx_transport.dart`

### `TransportInterface`

> Abstract interface for all transport implementations.

```dart
abstract class TransportInterface {
  TransportState get currentState;
  Stream<TransportState> get stateChanges;
  Stream<TransportMessage> get messages;
  bool get isAvailable;
  Future<void> connect();
  Future<void> disconnect();
  Future<void> send(TransportMessage message);
}
```

---

### `TransportState`

```dart
enum TransportState { disconnected, connecting, connected }
```

---

### `TransportMessage`

> A message exchanged between peers over the transport layer.

#### Constructor

```dart
TransportMessage({
  required String id,
  required String senderPubkey,
  required String recipientPubkey,
  required Uint8List payload,
  required DateTime timestamp,
})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| id | `String` | Unique message identifier |
| senderPubkey | `String` | Hex-encoded sender public key |
| recipientPubkey | `String` | Hex-encoded recipient public key |
| payload | `Uint8List` | Encrypted message payload |
| timestamp | `DateTime` | Message creation time (UTC) |

#### Methods

##### `toJson()`

```dart
Map<String, dynamic> toJson()
```

##### `TransportMessage.fromJson(Map<String, dynamic> json)` (factory)

```dart
factory TransportMessage.fromJson(Map<String, dynamic> json)
```

---

### `TransportFailover`

> Multi-transport failover engine. Tries transports in priority order with retry + exponential backoff.

#### Constructor

```dart
TransportFailover({required List<TransportPriority> transports})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| transports | `List<TransportPriority>` | Configured transport priorities |
| anyAvailable | `bool` | Whether at least one transport is available |

#### Methods

Implements `TransportInterface` plus:

##### `dispose()`

```dart
Future<void> dispose()
```

**Backoff strategy:** `min(100ms * 2^attempt, 5000ms)`.

**Exception:** Throws `TransportFailoverException` if all transports fail.

---

### `TransportPriority`

> Associates a transport with its retry and timeout policy.

#### Constructor

```dart
const TransportPriority({
  required TransportInterface transport,
  required int maxRetries,
  required Duration timeout,
})
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| transport | `TransportInterface` | Yes | Transport implementation |
| maxRetries | `int` | Yes | Max retries before falling through |
| timeout | `Duration` | Yes | Timeout per send attempt |

---

### `TransportFailoverException`

```dart
class TransportFailoverException implements Exception {
  const TransportFailoverException(String message);
  final String message;
}
```

---

### `TransportSelector`

> Factory that builds a `TransportFailover` chain based on configuration.

#### Methods

##### `createFailoverChain({...})`

```dart
TransportFailover createFailoverChain({
  required TransportInterface nostr,
  TransportInterface? email,
  TorManager? torManager,
  bool useTor = false,
})
```

Default hierarchy:
1. Nostr (3 retries, 5s timeout)
2. Email (2 retries, 30s timeout) — if provided

When `useTor` is true, transports are wrapped with `TorTransportDecorator`.

---

### `EmailConfig`

> Configuration for email-based transport.

#### Constructor

```dart
const EmailConfig({
  required String imapHost,
  required int imapPort,
  required String smtpHost,
  required int smtpPort,
  required String username,
  required String password,
  required String recipientAddress,
  bool useSsl = true,
  String? senderAddress,
})
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| imapHost | `String` | Yes | — | IMAP server hostname |
| imapPort | `int` | Yes | — | IMAP port (typically 993) |
| smtpHost | `String` | Yes | — | SMTP server hostname |
| smtpPort | `int` | Yes | — | SMTP port (typically 465 or 587) |
| username | `String` | Yes | — | Login username |
| password | `String` | Yes | — | Login password or OAuth2 token |
| recipientAddress | `String` | Yes | — | Recipient email address |
| useSsl | `bool` | No | `true` | Use SSL/TLS |
| senderAddress | `String?` | No | `username` | Sender address |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| sender | `String` | Effective sender address (`senderAddress ?? username`) |

---

### `NostrTransport`

> Nostr relay-based transport implementing `TransportInterface`.

#### Constructor

```dart
NostrTransport({
  required RelayPool relayPool,
  required NostrEncryptor encryptor,
  required String localPubkey,
  required String peerPubkey,
})
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| relayPool | `RelayPool` | Yes | Pool of Nostr relay connections |
| encryptor | `NostrEncryptor` | Yes | NIP-44 compatible encryption |
| localPubkey | `String` | Yes | Hex-encoded local public key |
| peerPubkey | `String` | Yes | Hex-encoded peer public key |

Implements `TransportInterface`. Also provides:

##### `dispose()`

```dart
Future<void> dispose()
```

---

### `NostrEncryptor`

> Handles NIP-44 compatible encryption for Nostr messages.

#### Constructor

```dart
NostrEncryptor({
  required Uint8List sendKey,
  required Uint8List receiveKey,
})
```

#### Methods

##### `encrypt(Uint8List plaintext)`

```dart
Future<Uint8List> encrypt(Uint8List plaintext)
```

##### `decrypt(Uint8List ciphertext)`

```dart
Future<Uint8List> decrypt(Uint8List ciphertext)
```

---

### `RelayPool`

> Manages connections to multiple Nostr relays.

#### Constructor

```dart
RelayPool({
  required List<String> relayUrls,
  required RelayConnectionFactory factory,
})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| relayUrls | `List<String>` | Currently configured relay URLs (unmodifiable) |
| messages | `Stream<String>` | Incoming messages from all relays |
| connectedCount | `int` | Number of currently open connections |

#### Methods

##### `connectAll()`

> Connects to all relays. Returns count of successful connections.

```dart
Future<int> connectAll()
```

##### `disconnectAll()`

```dart
Future<void> disconnectAll()
```

##### `publish(Map<String, dynamic> event)`

> Publishes a JSON event to all connected relays. Returns count of relays reached.

```dart
int publish(Map<String, dynamic> event)
```

##### `subscribe(String subscriptionId, Map<String, dynamic> filter)`

> Subscribes to events on all connected relays.

```dart
void subscribe(String subscriptionId, Map<String, dynamic> filter)
```

##### `healthCheck()`

> Returns health status of all relays.

```dart
List<RelayHealth> healthCheck()
```

##### `addRelay(String url)`

> Adds a relay URL (does not auto-connect).

```dart
void addRelay(String url)
```

##### `removeRelay(String url)`

> Removes and disconnects a relay.

```dart
Future<void> removeRelay(String url)
```

##### `dispose()`

```dart
Future<void> dispose()
```

---

### `RelayHealth`

> Health status of a single relay.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| url | `String` | Relay WebSocket URL |
| isConnected | `bool` | Whether the relay is currently connected |

---

### `TorManager`

> Manages the Tor SOCKS5 proxy lifecycle.

#### Constructor

```dart
TorManager({required TorEngine engine})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| state | `TorState` | Current Tor state |
| stateStream | `Stream<TorState>` | Reactive state changes |
| socksPort | `int` | SOCKS5 port (valid only when `ready`) |
| bootstrapProgress | `int` | Bootstrap progress 0–100 |

#### Methods

##### `start({Duration timeout = const Duration(seconds: 120)})`

```dart
Future<void> start({Duration timeout = const Duration(seconds: 120)})
```

##### `stop()`

```dart
Future<void> stop()
```

##### `dispose()`

```dart
Future<void> dispose()
```

---

### `TorState`

```dart
enum TorState { stopped, bootstrapping, ready, error }
```

---

### `TorTransportDecorator`

> Decorator that routes any `TransportInterface` through Tor SOCKS5 proxy. Ensures Tor is bootstrapped before the inner transport connects.

#### Constructor

```dart
TorTransportDecorator({
  required TransportInterface inner,
  required TorManager torManager,
})
```

Implements `TransportInterface`. The `isAvailable` getter requires both Tor readiness and inner transport availability.

---

### `OutboxWorker`

> Processes the outbox queue in causal (HLC) order.

#### Constructor

```dart
OutboxWorker({
  required OutboxStore outboxStore,
  required EventStore eventStore,
  required TransportFailover transport,
  required NostrEncryptor encryptor,
  required String localPubkey,
  required String peerPubkey,
})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| isRunning | `bool` | Whether the worker loop is active |
| sentCount | `int` | Total events sent since creation |
| failedCount | `int` | Total failed sends since creation |
| pendingCount | `Future<int>` | Current pending count |

#### Methods

##### `start()`

> Starts the worker loop, processing batches until stopped or empty.

```dart
Future<void> start()
```

##### `stop()`

> Stops the worker after the current batch.

```dart
void stop()
```

##### `processNow()`

> Forces immediate processing of one batch.

```dart
Future<int> processNow()
```

##### `processBatch()`

> Processes one batch of ready-to-send events in HLC order.

```dart
Future<int> processBatch()
```

---

### `OutboxStore`

> Abstract interface for outbox persistence.

```dart
abstract class OutboxStore {
  Future<List<OutboxEntry>> getReadyToSend();
  Future<void> markSent({required String eventId, required String transport});
  Future<void> markFailed({required String eventId});
  Future<int> pendingCount();
}
```

---

### `OutboxEntry`

> An outbox entry ready to be sent.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| eventId | `String` | Event ID to send |
| status | `String` | `pending`, `failed`, `sent`, or `abandoned` |
| retryCount | `int` | Number of retries so far |
| createdAt | `DateTime` | When the entry was created |
| nextRetryAt | `DateTime?` | When to retry next (for failed entries) |

---

### `EventStore`

> Abstract interface for event retrieval by ID.

```dart
abstract class EventStore {
  Future<StoredEvent?> getEvent(String eventId);
  Future<List<StoredEvent>> getEventsByIds(List<String> eventIds);
}
```

---

### `StoredEvent`

> Pre-serialized event data from the store.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| eventId | `String` | Event ID |
| senderPubkey | `String` | Hex-encoded sender public key |
| serializedBytes | `Uint8List` | Pre-serialized event data |
| hlcTimestamp | `String` | HLC timestamp for causal ordering |
| hlcCounter | `int` | HLC counter for causal ordering |

---

### `EmailTransport`

> Email-based transport using SMTP for sending and IMAP for receiving. Fallback when Nostr relays are unavailable.

#### Constructor

```dart
EmailTransport({
  required EmailConfig config,
  required EmailEncoder encoder,
  required ImapWatcher watcher,
  required SmtpSender smtpSender,
})
```

Implements `TransportInterface`. Also provides:

##### `checkAvailability()`

```dart
Future<bool> checkAvailability()
```

##### `dispose()`

```dart
Future<void> dispose()
```

---

### `EmailEncoder`

> Encodes `TransportMessage` as MIME email with binary attachment and decodes back.

#### Static Methods

##### `subjectPattern(String pubkeyShort)`

> Returns the Styx email subject pattern: `[STYX:v1:a1b2c3d4]`.

```dart
static String subjectPattern(String pubkeyShort)
```

#### Methods

##### `encode({...})`

```dart
MimeMessage encode({
  required TransportMessage message,
  required String senderEmail,
  required String recipientEmail,
})
```

##### `decode(MimeMessage email)`

```dart
TransportMessage? decode(MimeMessage email)
```

**Returns:** `null` if the email is not a valid Styx message.

---

### `ImapWatcher`

> Monitors an inbox for incoming Styx messages via IMAP IDLE or polling.

#### Constructor

```dart
ImapWatcher({
  required ImapClientAdapter client,
  required String subjectFilter,
  Duration pollingInterval = const Duration(seconds: 60),
})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| messages | `Stream<MimeMessage>` | Incoming Styx messages |
| isConnected | `bool` | Whether the watcher is connected |

#### Methods

##### `connect()`

```dart
Future<void> connect()
```

##### `disconnect()`

```dart
Future<void> disconnect()
```

##### `fetchUnreadStyxMessages()`

```dart
Future<List<MimeMessage>> fetchUnreadStyxMessages()
```

##### `markAsRead(MimeMessage message)`

```dart
Future<void> markAsRead(MimeMessage message)
```

##### `dispose()`

```dart
Future<void> dispose()
```

---

### `MessageSerializer`

> Serializes and deserializes `TransportMessage` to/from bytes.

#### Methods

##### `serialize(TransportMessage message)`

```dart
Uint8List serialize(TransportMessage message)
```

##### `deserialize(Uint8List bytes)`

```dart
TransportMessage deserialize(Uint8List bytes)
```

---

## 8. API Reference — push_bridge_client

Package: `package:styx_push_bridge_client/styx_push_bridge_client.dart`

### `PrivacyProfile`

> Privacy profile for push notification behavior.

```dart
enum PrivacyProfile { balanced, private, paranoid }
```

| Value | Description | Battery | Privacy |
|-------|-------------|---------|---------|
| `balanced` | Real pushes only | Zero extra | Low (timing visible to provider) |
| `private` | Poisson-distributed dummies (~4-6/day), no network on dummy wake | Minimal | Medium (temporal patterns masked) |
| `paranoid` | Dummies with real relay connections | Measurable | High (traffic patterns fully masked) |

#### Static Methods

##### `PrivacyProfile.fromString(String value)`

> Parses from name string, defaults to `balanced`.

```dart
static PrivacyProfile fromString(String value)
```

---

### `PushBridgeClient`

> HTTP client for registering/unregistering with the Push Bridge server.

#### Constructor

```dart
PushBridgeClient({
  required String bridgeUrl,
  required BridgeHttpClient httpClient,
})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| bridgeUrl | `String` | Configured bridge server URL |

#### Methods

##### `register({...})`

> Registers the device with the push bridge.

```dart
Future<void> register({
  required String fcmToken,
  required String nostrPubkey,
  required PrivacyProfile profile,
  String platform = 'android',
})
```

##### `unregister({required String fcmToken})`

> Unregisters the device.

```dart
Future<void> unregister({required String fcmToken})
```

##### `updateProfile({...})`

> Updates the privacy profile (re-registers with new profile).

```dart
Future<void> updateProfile({
  required String fcmToken,
  required String nostrPubkey,
  required PrivacyProfile profile,
  String platform = 'android',
})
```

---

### `BridgeHttpClient`

> Abstract HTTP client for push bridge communication.

```dart
abstract class BridgeHttpClient {
  Future<int> post(String path, Map<String, dynamic> body);
  Future<String> get(String path);
}
```

---

### `PushHandler`

> Handles incoming push notifications according to the configured privacy profile.

#### Constructor

```dart
PushHandler({
  required PrivacyProfile profile,
  required WakeUpCallback onWakeUp,
  required WakeUpCallback onConnectRelay,
  TokenRefreshCallback? onTokenRefresh,
  DummyDetector? detector,
})
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| profile | `PrivacyProfile` | Yes | Active privacy profile |
| onWakeUp | `WakeUpCallback` | Yes | Called for real pushes |
| onConnectRelay | `WakeUpCallback` | Yes | Called for paranoid dummy pushes |
| onTokenRefresh | `TokenRefreshCallback?` | No | Called on FCM/APNs token refresh |
| detector | `DummyDetector?` | No | Dummy detector (defaults to `const DummyDetector()`) |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| profile | `PrivacyProfile` | Active profile |
| realCount | `int` | Real wake-ups processed |
| dummyCount | `int` | Dummy notifications detected |
| connectCount | `int` | Total relay connections (real + paranoid dummy) |

#### Methods

##### `handleMessage(Map<String, dynamic> data)`

> Routes a push notification based on profile. Balanced: ignore dummies. Private: drop dummies silently. Paranoid: connect to relay even for dummies.

```dart
Future<void> handleMessage(Map<String, dynamic> data)
```

##### `handleTokenRefresh(String newToken)`

```dart
Future<void> handleTokenRefresh(String newToken)
```

---

### `DummyDetector`

> Detects dummy push notifications by checking for `{"d": "1"}` in the data payload.

#### Constructor

```dart
const DummyDetector()
```

#### Methods

##### `isDummy(Map<String, dynamic> data)`

```dart
bool isDummy(Map<String, dynamic> data)
```

**Returns:** `true` if `data['d'] == '1'`.

---

### `WakeUpOrchestrator`

> Orchestrates the full wake-up flow: connect → download → insert → outbox → disconnect.

#### Constructor

```dart
WakeUpOrchestrator({
  required TransportInterface transport,
  required LedgerOperations ledger,
  required OutboxProcessor outbox,
  Duration downloadTimeout = const Duration(seconds: 10),
})
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| isRunning | `bool` | Whether a wake-up is in progress |
| lastDownloadCount | `int` | Events downloaded in the last wake-up |
| lastOutboxCount | `int` | Outbox events sent in the last wake-up |

#### Methods

##### `handleWakeUp()`

> Executes the full wake-up sequence. Returns total events processed.

```dart
Future<int> handleWakeUp()
```

---

### `LedgerOperations`

> Abstract interface for ledger operations during wake-up.

```dart
abstract class LedgerOperations {
  Future<int> insertEvents(List<TransportMessage> events);
  Future<String?> lastKnownTimestamp();
}
```

---

### `OutboxProcessor`

> Abstract interface for outbox processing during wake-up.

```dart
abstract class OutboxProcessor {
  Future<int> processPending();
  Future<int> pendingCount();
}
```

---

### `PushMessagingService`

> Abstract interface for push messaging (wraps Firebase Messaging in production).

```dart
abstract class PushMessagingService {
  Future<String?> getToken();
  Stream<String> get onTokenRefresh;
}
```

---

### Callback Types

```dart
typedef WakeUpCallback = Future<void> Function();
typedef TokenRefreshCallback = Future<void> Function(String newToken);
```

---

## 9. API Reference — push_bridge_server (REST)

The **Push Bridge Server** is the only HTTP component in the Styx architecture. It is a stateless Go microservice that sits in the **Reliability Layer** — it subscribes to Nostr relays for events matching registered public keys and sends data-only push notifications via FCM/APNs to wake the client application.

### Overview

- **Language:** Go
- **Storage:** In-memory only (all registrations are lost on restart)
- **Authentication:** None (designed for trusted network deployment)
- **Router:** `gorilla/mux`
- **Graceful shutdown:** Listens for `SIGINT` / `SIGTERM`, cancels background goroutines, then calls `http.Server.Shutdown`

### Configuration

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `BRIDGE_ADDR` | `:8080` | Address and port the HTTP server binds to |

| Server Parameter | Value |
|------------------|-------|
| `ReadTimeout` | 5 s |
| `WriteTimeout` | 10 s |

### Endpoints

#### `POST /register`

Registers (or updates) a device for push notifications. Idempotent — if a registration with the same `fcm_token` already exists, it is overwritten (upsert). After registration, the server subscribes to the device's `nostr_pubkey` on the Nostr relay pool.

**Request body** (`Content-Type: application/json`):

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `fcm_token` | `string` | Yes | — | FCM/APNs device token |
| `nostr_pubkey` | `string` | Yes | — | Hex-encoded Nostr public key to subscribe to |
| `platform` | `string` | No | `"android"` | `"android"` or `"ios"` |
| `privacy_profile` | `string` | No | `"balanced"` | `"balanced"`, `"private"`, or `"paranoid"` |

**Privacy profiles and dummy push behavior:**

| Profile | Poisson Lambda | Approx. Frequency | Behavior |
|---------|----------------|-------------------|----------|
| `balanced` | 0 | No dummies | Real pushes only |
| `private` | 1/150 (~0.0067) | ~4–6 per day | Poisson-distributed dummy pushes; no network activity on dummy wake |
| `paranoid` | 1/30 (~0.033) | ~48 per day | Poisson-distributed dummy pushes; real relay connections on dummy wake |

**Response `200 OK`** (`Content-Type: application/json`):

```json
{"status": "ok"}
```

**Response `400 Bad Request`** (`Content-Type: text/plain; charset=utf-8`):

Returned when the request body is not valid JSON or when required fields are missing.

```
{"error":"invalid json"}
```

```
{"error":"fcm_token and nostr_pubkey required"}
```

> **Note:** Error responses use `http.Error()` in Go, which sets `Content-Type: text/plain; charset=utf-8` even though the body is JSON-formatted. Clients should not rely on `Content-Type` to distinguish success from error — use the HTTP status code instead.

**Example:**

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "fcm_token": "dGVzdF90b2tlbg==",
    "nostr_pubkey": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "platform": "android",
    "privacy_profile": "private"
  }'
```

---

#### `POST /unregister`

Removes a device registration by FCM token. If the token is not found, the operation is a silent no-op (still returns `200 OK`).

**Request body** (`Content-Type: application/json`):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fcm_token` | `string` | Yes | FCM/APNs device token to unregister |

**Response `200 OK`** (`Content-Type: application/json`):

```json
{"status": "ok"}
```

**Response `400 Bad Request`** (`Content-Type: text/plain; charset=utf-8`):

```
{"error":"invalid json"}
```

```
{"error":"fcm_token required"}
```

> **Note:** Same `Content-Type` caveat as `/register` — error bodies are JSON-formatted but served as `text/plain`.

**Example:**

```bash
curl -X POST http://localhost:8080/unregister \
  -H "Content-Type: application/json" \
  -d '{"fcm_token": "dGVzdF90b2tlbg=="}'
```

---

#### `GET /health`

Returns server health status and the current number of in-memory registrations.

**Response `200 OK`** (`Content-Type: application/json`):

```json
{"status": "ok", "registrations": 42}
```

**Example:**

```bash
curl http://localhost:8080/health
```

### Data Types

#### Registration

| Field | JSON Key | Type | Enum Values | Default |
|-------|----------|------|-------------|---------|
| `FCMToken` | `fcm_token` | `string` | — | — |
| `NostrPubkey` | `nostr_pubkey` | `string` | — | — |
| `Platform` | `platform` | `string` | `"android"`, `"ios"` | `"android"` |
| `PrivacyProfile` | `privacy_profile` | `string` | `"balanced"`, `"private"`, `"paranoid"` | `"balanced"` |

#### SuccessResponse

```json
{"status": "ok"}
```

Returned by `POST /register`, `POST /unregister`.

#### HealthResponse

```json
{"status": "ok", "registrations": <int>}
```

Returned by `GET /health`. The `registrations` field reflects the current size of the in-memory store.

#### ErrorResponse

```
{"error": "<message>"}
```

Returned with HTTP `400`. Body is JSON-formatted but `Content-Type` is `text/plain; charset=utf-8` (Go `http.Error()` behavior).

### Push Notification Payload

The server sends **data-only** push notifications (no visible alert). The payload schema is strictly validated — only the keys listed below are allowed.

#### PushPayload

| Key | Type | Present | Description |
|-----|------|---------|-------------|
| `styx` | `string` | Always | Fixed value `"wake"` — signals the client to sync |
| `ts` | `string` | Always | Unix timestamp (seconds) as a string |
| `d` | `string` | Dummy only | `"1"` if this is a dummy push; absent for real pushes |

**Real push example:**

```json
{"styx": "wake", "ts": "1711036800"}
```

**Dummy push example:**

```json
{"styx": "wake", "ts": "1711036800", "d": "1"}
```

**Payload validation:** The `ValidatePayload` function rejects any payload containing keys other than `styx`, `ts`, and `d`. This ensures no sensitive data is ever transmitted via push notifications.

### Background Services

#### NostrSubscriber

Runs as a background goroutine. Subscribes to Nostr relays and listens for events where the `p` tag matches a registered public key. When a matching event is received, it triggers a wake-up push notification to all devices registered for that public key.

#### DummyScheduler

Runs as a background goroutine with a **1-second ticker**. On each tick, it iterates over all registrations and, for each registration with a non-zero privacy profile lambda, generates a Poisson-distributed random delay. If the delay is less than 1 second, a dummy push notification is sent.

| Profile | Lambda | Mean Interval |
|---------|--------|---------------|
| `balanced` | 0 | No dummies sent |
| `private` | 1/150 | ~150 seconds (~2.5 minutes) |
| `paranoid` | 1/30 | ~30 seconds |

---

## 10. Glossary

| Term | Definition |
|------|-----------|
| **Affidante** | One of the two peers in a Styx ledger (Italian for "entrustor") |
| **Custode** | The other peer in a Styx ledger (Italian for "custodian") |
| **BIP-39** | Bitcoin Improvement Proposal 39 — mnemonic code for generating deterministic keys |
| **Blessing** | A REKEY event where the old key endorses a new key for device migration |
| **Chain hash** | `SHA-256(previousHash \|\| eventType \|\| payload \|\| hlcBytes)` |
| **Double Check** | 6-digit verification code derived from SPAKE2 session key, compared verbally |
| **Ed25519** | Elliptic curve digital signature algorithm used for all Styx signatures |
| **Fork** | When two peers create events concurrently from the same ancestor |
| **GF(256)** | Galois Field used in Shamir's Secret Sharing arithmetic |
| **Genesis** | The first event in a chain (null `previousHash`, type `config`) |
| **HLC** | Hybrid Logical Clock — combines wall-clock time with logical counter |
| **MERGE event** | Event that linearizes a fork, referencing both branch tips |
| **Nonce** | 16-byte random value in QR pairing for anti-replay protection |
| **NIP-44** | Nostr protocol for encrypted direct messages |
| **Node ID** | First 8 hex characters of a peer's public key |
| **Nostr** | Primary transport protocol using WebSocket relay connections |
| **Peer role** | `'A'` or `'B'`, assigned by lexicographic ordering of public keys at pairing |
| **Pruning** | Nullifying event payload while preserving the hash chain integrity |
| **Push Bridge** | Stateless Go microservice that subscribes to Nostr relays and sends FCM/APNs push notifications |
| **Retention policy** | Time-based rule for automatic pruning of specific event types |
| **SPAKE2** | Password-Authenticated Key Exchange on P-256, used in remote pairing |
| **Shamir SSS** | Shamir's Secret Sharing — splits a secret into N shares, any K reconstruct |
| **SOCKS5** | Proxy protocol used by Tor for transport routing |
| **Vector clock** | 2-element counter `(a, b)` tracking causal ordering between peers |
| **X25519** | Elliptic curve Diffie-Hellman used for key exchange and message encryption |
