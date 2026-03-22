# Styx.js API Reference

Complete API documentation for the Styx.js library -- sovereign, peer-to-peer cryptographic ledgers for the browser. JavaScript port of the Dart Styx library with full cross-platform interoperability.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Quick Start](#2-quick-start)
3. [Use Cases](#3-use-cases)
4. [API Reference -- facade](#4-api-reference--facade)
5. [API Reference -- crypto](#5-api-reference--crypto)
6. [API Reference -- ledger](#6-api-reference--ledger)
7. [API Reference -- storage](#7-api-reference--storage)
8. [API Reference -- transport](#8-api-reference--transport)
9. [API Reference -- pairing](#9-api-reference--pairing)
10. [Dart <-> JS Interoperability](#10-dart--js-interoperability)
11. [Glossary](#11-glossary)

---

## 1. Introduction

### What is Styx.js

Styx.js is a browser-native JavaScript library for building sovereign, peer-to-peer cryptographic ledgers. Two peers -- called **Affidante** and **Custode** -- maintain a shared, tamper-evident event chain without any central server. Every event is signed with Ed25519, hash-chained with SHA-256, and causally ordered via 2-element vector clocks. All communication is end-to-end encrypted with ChaCha20-Poly1305.

Styx.js is a faithful port of the Dart/Flutter Styx library, designed to run in modern browsers (Chrome, Firefox, Safari, Edge). It uses the `@noble` family of cryptographic libraries and supports two transport backends: **Nostr relays** (WebSocket-based) and **WebRTC DataChannels** (direct peer-to-peer).

### Layered Architecture

```
+---------------------------------------------+
|  5. Trust Layer (facade)                     |  Pairing, re-keying, backup
+---------------------------------------------+
|  4. Transport Layer (transport)              |  Nostr, WebRTC, failover, outbox
+---------------------------------------------+
|  3. Integrity Layer (ledger + storage)       |  Event chain, vector clocks, pruning
+---------------------------------------------+
|  2. Encryption Layer (crypto)                |  ChaCha20-Poly1305, HKDF, X25519 DH
+---------------------------------------------+
|  1. Identity Layer (crypto)                  |  Ed25519, SPAKE2, Shamir, BIP-39
+---------------------------------------------+
```

### Privacy Model

| Property | Nostr Transport | WebRTC Transport |
|----------|-----------------|------------------|
| Relay/Server sees metadata | Encrypted pubkeys in tags | No server after ICE |
| Relay/Server sees payload | No (ChaCha20-Poly1305) | No (direct P2P) |
| IP visible to relay | Yes | No (after connection) |
| Requires signaling | No | Yes (via WebSocket) |
| Works offline (outbox) | Yes | No |
| NAT traversal | N/A | STUN/TURN required |

### Typical Flow

1. **Generate identity** -- Ed25519 keypair via `IdentityManager`.
2. **Pair** -- Exchange public keys via QR code (local) or BIP-39 mnemonic (remote).
3. **Exchange events** -- Append signed events to the hash chain, sync via Nostr relays or WebRTC.
4. **Resolve forks** -- Deterministic merge when peers produce concurrent events.
5. **Prune** -- GDPR-compliant bilateral or unilateral payload deletion.

---

## 2. Quick Start

### Installation

```bash
npm install styx-js
```

### Minimal Initialization

```js
import {
  SovereignLedger, LedgerConfig,
  MemoryLedgerStore, MemoryPeerStore, MemoryOutboxStore, MemoryKeyStore,
  setBip39Wordlist,
} from 'styx-js';

// Load the BIP-39 English wordlist (2048 words)
import { wordlist } from 'styx-js/wordlist';
setBip39Wordlist(wordlist);

const ledger = new SovereignLedger({
  config: new LedgerConfig({
    relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
  }),
  ledgerStore: new MemoryLedgerStore(),
  peerStore: new MemoryPeerStore(),
  keyStore: new MemoryKeyStore(),
  outboxStore: new MemoryOutboxStore(),
});

await ledger.initialize();
// State is now 'unpaired'
```

### First Event After Pairing

```js
// After pairing is complete (state === 'ready'):
const encoder = new TextEncoder();

await ledger.sendTransaction({
  payload: encoder.encode('Hello from Styx.js!'),
});

// Read history
const events = await ledger.getHistory();
const decoder = new TextDecoder();
for (const event of events) {
  if (event.payload) {
    console.log(`${event.eventType}: ${decoder.decode(event.payload)}`);
  }
}
```

---

## 3. Use Cases

### 3.1 QR Pairing Between Two Devices

**Scenario:** Two users are physically co-located. Device A displays a QR code; Device B scans it.

**Prerequisites:** Both devices have initialized `SovereignLedger` in `unpaired` state.

```js
// === Device A (displays QR) ===
const qrData = await ledgerA.generatePairingQr();
const qrPayload = qrData.toQrPayload();
// Display qrPayload as a QR code on screen.
// Contains: public key + 16-byte nonce + optional relay hints.

// === Device B (scans QR) ===
const scannedPayload = '...'; // raw string from QR scanner
const result = await ledgerB.processPairingQr(scannedPayload);

if (result.isValid) {
  await ledgerB.confirmPairing({
    peerPublicKey: result.peerPublicKey,
    peerAlias: 'Alice',
  });
  // State transitions: unpaired -> pairing -> ready
}
```

**Notes:**
- The QR payload is approximately 80-120 bytes (JSON with hex public key + Base64 nonce + relay hints).
- Nonces expire after 5 minutes. A maximum of 100 recent nonces are tracked for anti-replay.
- After pairing, peer role assignment (`A` or `B`) is determined by lexicographic ordering of public keys.

### 3.2 Remote Pairing via Mnemonic

**Scenario:** Two users are not physically co-located. They share a BIP-39 mnemonic out-of-band (e.g., by phone) and complete SPAKE2 key exchange with Double Check verification.

```js
// === Device A (initiator) ===
const mnemonic = await ledgerA.startRemotePairing();
// Share this mnemonic with Device B via phone call, SMS, etc.
// Example: "abandon ability able about above absent"

// === Device B (responder) ===
await ledgerB.startRemotePairing(mnemonic);

// Both devices derive SPAKE2 session from the mnemonic.
// After SPAKE2 completes, both get a 6-digit Double Check code.

// === Both devices ===
const code = await ledger.getDoubleCheckCode();
// Display: "483 291" -- users compare codes verbally.

// If codes match:
await ledger.confirmPairing({
  peerPublicKey: peerPubKey,
  peerAlias: 'Bob',
});
// State: ready
```

**Notes:**
- Default mnemonic length is 6 words (from BIP-39 English wordlist).
- SPAKE2 uses NIST P-256 curve (pure JavaScript via `@noble/curves`).
- The Double Check code is derived from the SPAKE2 session key via SHA-256 truncation to 6 decimal digits.
- States flow: `idle -> mnemonicGenerated -> waitingForPeer -> spake2InProgress -> doubleCheckPending -> completed`.

### 3.3 Sending and Receiving Events

**Scenario:** Two paired peers exchange signed events over the shared ledger.

**Prerequisites:** Both devices are paired (`state === 'ready'`).

```js
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Send a transaction
await ledger.sendTransaction({
  payload: encoder.encode(JSON.stringify({ amount: 100, note: 'Dinner' })),
});

// Send a text message
await ledger.sendMessage({
  payload: encoder.encode('Thanks for dinner!'),
});

// Send a config event
await ledger.sendConfig({
  payload: encoder.encode(JSON.stringify({ theme: 'dark' })),
});

// Listen for incoming events
ledger.eventStream.onRemoteEvents((event) => {
  console.log(`Received ${event.eventType} from peer`);
});

// Filter by type
import { EventType } from 'styx-js';

ledger.eventStream.onEventsByType(EventType.TRANSACTION, (event) => {
  const data = JSON.parse(decoder.decode(event.payload));
  console.log(`Transaction: ${data.amount}`);
});
```

**Notes:**
- Each event includes: previous hash, vector clock, HLC timestamp, payload, sender pubkey, and Ed25519 signature.
- Events are delivered in causal order via the outbox queue.

### 3.4 SOS Handling

**Scenario:** A user sends an emergency signal to their peer.

```js
import { EventType } from 'styx-js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Send SOS
await ledger.sendSOS({
  payload: encoder.encode(JSON.stringify({
    type: 'emergency',
    location: { lat: 45.464, lng: 9.190 },
    timestamp: new Date().toISOString(),
  })),
});

// Listen for SOS events
ledger.eventStream.onEventsByType(EventType.SOS, (event) => {
  const data = JSON.parse(decoder.decode(event.payload));
  showEmergencyAlert(data);
});
```

### 3.5 GDPR Pruning (Bilateral and Unilateral)

**Scenario:** A user wants to delete a specific event's payload from the ledger while preserving the hash chain integrity.

```js
import { PruneReason } from 'styx-js';

// Get event history
const events = await ledger.getHistory();
const targetEvent = events[0];

// Request bilateral prune (asks peer to also delete)
await ledger.requestPrune({
  targetEventId: targetEvent.eventId,
  reason: PruneReason.USER_REQUEST,
});
// Flow: PRUNE_REQUEST -> peer sends PRUNE_ACK -> payload nullified on both sides

// GDPR Article 17 -- unilateral prune (no peer ACK needed)
await ledger.requestPrune({
  targetEventId: targetEvent.eventId,
  reason: PruneReason.GDPR_ARTICLE_17,
});
// Payload is immediately nullified locally. The hash chain remains intact.
```

**Notes:**
- Pruning nullifies the `payload` field but preserves the event hash, maintaining chain integrity.
- Bilateral pruning requires both `PRUNE_REQUEST` and `PRUNE_ACK` events before execution.
- Unilateral pruning (GDPR Art. 17) executes immediately without peer acknowledgment.

### 3.6 Retention Policies

**Scenario:** Automatically identify events that exceed a time-based retention period.

```js
import { EventType, LedgerConfig } from 'styx-js';

const ledger = new SovereignLedger({
  config: new LedgerConfig({
    retentionPeriodMs: 365 * 24 * 60 * 60 * 1000, // 1 year
    retentionTypes: [EventType.TRANSACTION, EventType.MESSAGE],
  }),
  ledgerStore: myStore,
  peerStore: myPeerStore,
  keyStore: myKeyStore,
  outboxStore: myOutboxStore,
});

await ledger.initialize();

// Identify expired events
const expired = await ledger.getExpiredEvents();
for (const event of expired) {
  await ledger.requestPrune({
    targetEventId: event.eventId,
    reason: PruneReason.RETENTION_EXPIRED,
  });
}
```

**Notes:**
- Only events of types listed in `retentionTypes` are evaluated.
- Already-pruned events are excluded from the results.

### 3.7 Re-Keying (Device Change)

**Scenario:** A user gets a new device and needs to migrate their identity.

```js
// === Old device ===
import { StyxPublicKey } from 'styx-js';

const newDevicePubKey = StyxPublicKey.fromHex('abcd...');
await ledgerOld.blessNewDevice({ newPublicKey: newDevicePubKey });
// Creates a REKEY event signed by the old key, endorsing the new key.

// === Peer device ===
// Automatically processes REKEY event:
// - Verifies old key signature on the blessing
// - Extracts new public key from the event payload
// - Updates the trust store to recognize the new key
```

**Notes:**
- The REKEY event is signed by the old private key and contains the new public key in its payload.
- The peer must verify the blessing signature before accepting the new key.

### 3.8 Shamir Backup and Restore

**Scenario:** A user creates a backup of their private key using Shamir's Secret Sharing.

```js
// Create backup (split private key into 3 shares, 2 needed to restore)
const shares = await ledger.createIdentityBackup({
  threshold: 2,
  totalShares: 3,
});
// shares is a string[] -- distribute to trusted parties
// shares[0] -> stored on paper
// shares[1] -> given to a trusted friend
// shares[2] -> stored in a bank vault

// Restore identity on a new device
const restoredLedger = new SovereignLedger({
  config: new LedgerConfig(),
  ledgerStore: myStore,
  peerStore: myPeerStore,
  keyStore: myKeyStore,
  outboxStore: myOutboxStore,
});
await restoredLedger.initialize();
await restoredLedger.restoreIdentity({
  shares: [shares[0], shares[2]], // any 2 of 3
});
```

**Notes:**
- Shamir splitting uses GF(256) arithmetic (Galois Field).
- Shares are serialized as `styx-share-v1:{index}:{base64_data}`.
- The threshold is the minimum number of shares needed for reconstruction.
- After restore, the `KeyBackup` service verifies the reconstructed key by re-deriving the public key and checking it matches.

### 3.9 Chain Validation

**Scenario:** Verify the integrity of the entire event chain.

```js
const error = await ledger.validateChain();

if (error === null) {
  console.log('Chain integrity verified');
} else {
  switch (error.errorType) {
    case 'hashMismatch':
      console.log(`Hash mismatch at event ${error.eventId}`);
      break;
    case 'signatureInvalid':
      console.log(`Invalid signature at event ${error.eventId}`);
      break;
    case 'previousHashMissing':
      console.log(`Broken chain link at event ${error.eventId}`);
      break;
    case 'hlcViolation':
      console.log(`HLC not monotonic at event ${error.eventId}`);
      break;
    case 'genesisViolation':
      console.log(`Invalid genesis event at ${error.eventId}`);
      break;
  }
}

// Validate a time range
const rangeEvents = await ledger.getHistoryRange({
  from: new Date('2026-01-01'),
  to: new Date('2026-02-01'),
});
```

### 3.10 E2E Encrypted Chat via Nostr

**Scenario:** Two paired peers exchange encrypted messages via Nostr relays. Relays see only opaque ciphertext.

```js
import {
  SovereignLedger, LedgerConfig,
  MemoryLedgerStore, MemoryPeerStore, MemoryOutboxStore, MemoryKeyStore,
  EventType,
} from 'styx-js';

// --- Peer A ---
const ledgerA = new SovereignLedger({
  config: new LedgerConfig({
    relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
  }),
  ledgerStore: new MemoryLedgerStore(),
  peerStore: new MemoryPeerStore(),
  keyStore: new MemoryKeyStore(),
  outboxStore: new MemoryOutboxStore(),
});

await ledgerA.initialize();

// After QR or remote pairing completes...
// The SovereignLedger automatically:
// 1. Derives X25519 shared secret from Ed25519 keys
// 2. Derives directional ChaCha20-Poly1305 send/receive keys via HKDF
// 3. Connects to Nostr relays and subscribes to p-tagged events
// 4. Signs Nostr events with a derived secp256k1 key (NIP-01 compliant)

// Send encrypted message
const encoder = new TextEncoder();
await ledgerA.sendMessage({
  payload: encoder.encode('This is end-to-end encrypted!'),
});

// --- Peer B ---
// Incoming messages are automatically decrypted and emitted
const decoder = new TextDecoder();
ledgerB.eventStream.onEventsByType(EventType.MESSAGE, (event) => {
  console.log('Received:', decoder.decode(event.payload));
  // Output: "Received: This is end-to-end encrypted!"
});

// The relay only sees:
// {
//   kind: 30078,
//   pubkey: "<derived secp256k1 pubkey>",
//   content: "<base64(nonce || ciphertext || tag)>",
//   tags: [["p", "<peer ed25519 hex pubkey>"]],
//   ...
// }
```

---

## 4. API Reference -- facade

Module: `styx-js` (main entry point)

### `SovereignLedger`

> Main entry point for the Styx library. Manages the lifecycle of identity, pairing, event exchange, privacy, and device migration.

#### Constructor

```js
new SovereignLedger({ config, ledgerStore, peerStore, keyStore, outboxStore })
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| config | `LedgerConfig` | No | `new LedgerConfig()` | Ledger configuration (relays, privacy, retention) |
| ledgerStore | `LedgerStore` | Yes | -- | Persistence layer for the event chain |
| peerStore | `PeerStore` | Yes | -- | Persistence layer for peer trust data |
| keyStore | `SecureKeyStore` | Yes | -- | Secure storage for private keys |
| outboxStore | `OutboxStore` | Yes | -- | Persistence for the outbound message queue |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| state | `string` | Current `StyxState` value |
| identity | `object\|null` | Local identity `{ publicKey, nodeId, peerRole }` after initialization |
| eventStream | `object` | Reactive stream interface with `onAllEvents`, `onRemoteEvents`, `onEventsByType` |

#### Methods

##### `initialize()`

> Initializes the ledger: generates or loads identity, sets up crypto, connects transport.

```js
await ledger.initialize(): Promise<void>
```

**Returns:** Completes when initialization is done. State transitions to `unpaired` (no peer) or `ready` (peer found).

**Throws:** `Error` if initialization fails (state transitions to `error`).

##### `shutdown()`

> Gracefully shuts down all subsystems: stops outbox worker, disposes transport, clears listeners.

```js
await ledger.shutdown(): Promise<void>
```

##### `generatePairingQr()`

> Generates QR pairing data containing the local public key, a fresh 16-byte nonce, and optional relay hints.

```js
await ledger.generatePairingQr(): Promise<QrPairingData>
```

**Returns:** `QrPairingData` -- encode via `toQrPayload()` for display.

**Throws:** `Error` if state is not `unpaired`.

##### `processPairingQr(qrPayload)`

> Processes a scanned QR payload, validates format and prevents self-pairing.

```js
await ledger.processPairingQr(qrPayload): Promise<object>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| qrPayload | `string` | Yes | Raw string from QR scanner |

**Returns:** `{ isValid, peerPublicKey, relayHints, errorMessage }`.

##### `startRemotePairing(existingMnemonic)`

> Starts remote pairing. If no mnemonic is provided, generates one (initiator role). If a mnemonic is provided, joins as responder.

```js
await ledger.startRemotePairing(existingMnemonic?): Promise<string>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| existingMnemonic | `string` | No | BIP-39 mnemonic from the initiator |

**Returns:** The BIP-39 mnemonic (new or existing).

##### `getDoubleCheckCode()`

> Returns the 6-digit Double Check verification code after SPAKE2 completes.

```js
await ledger.getDoubleCheckCode(): Promise<string>
```

**Returns:** Formatted code string, e.g. `"483 291"`.

**Throws:** `Error` if no remote pairing is in progress.

##### `confirmPairing({ peerPublicKey, peerAlias })`

> Confirms pairing after QR scan or Double Check verification.

```js
await ledger.confirmPairing({ peerPublicKey, peerAlias }): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| peerPublicKey | `StyxPublicKey\|string` | Yes | Peer's public key (object or hex string) |
| peerAlias | `string` | No | Human-readable alias for the peer |

##### `getPeer()`

> Returns the currently paired peer, or `null` if unpaired.

```js
await ledger.getPeer(): Promise<object|null>
```

**Returns:** Peer object `{ publicKey, alias, pairedAt, isActive }` or `null`.

##### `sendTransaction({ payload })`

> Appends a `transaction` event to the chain.

```js
await ledger.sendTransaction({ payload }): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| payload | `Uint8Array` | Yes | Event data bytes |

**Returns:** The created `LedgerEvent`.

##### `sendMessage({ payload })`

> Appends a `message` event to the chain.

```js
await ledger.sendMessage({ payload }): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| payload | `Uint8Array` | Yes | Event data bytes |

##### `sendSOS({ payload })`

> Appends an `sos` event to the chain.

```js
await ledger.sendSOS({ payload }): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| payload | `Uint8Array` | Yes | Event data bytes |

##### `sendConfig({ payload })`

> Appends a `config` event to the chain.

```js
await ledger.sendConfig({ payload }): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| payload | `Uint8Array` | Yes | Event data bytes |

##### `getHistory()`

> Returns all events in the chain, ordered by HLC.

```js
await ledger.getHistory(): Promise<LedgerEvent[]>
```

##### `getHistoryRange({ from, to })`

> Returns events within a time range.

```js
await ledger.getHistoryRange({ from, to }): Promise<LedgerEvent[]>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| from | `Date` | Yes | Start of range (inclusive) |
| to | `Date` | Yes | End of range (inclusive) |

##### `validateChain()`

> Validates the integrity of the full event chain: hash linkage, signatures, HLC monotonicity.

```js
await ledger.validateChain(): Promise<ChainValidationError|null>
```

**Returns:** `null` if valid, or the first `ChainValidationError` found.

##### `requestPrune({ targetEventId, reason })`

> Requests pruning of a specific event. Bilateral for `userRequest`/`retentionExpired`, unilateral for `gdprArticle17`.

```js
await ledger.requestPrune({ targetEventId, reason }): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| targetEventId | `string` | Yes | UUID of the event to prune |
| reason | `string` | Yes | `PruneReason` value |

**Throws:** `Error` if state is not `ready` or `degraded`.

##### `setRetentionPolicy({ periodMs, types })`

> Configures automatic retention policy.

```js
await ledger.setRetentionPolicy({ periodMs, types }): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| periodMs | `number` | Yes | Retention period in milliseconds |
| types | `string[]` | Yes | `EventType` values to evaluate |

##### `getExpiredEvents()`

> Returns events that exceed the configured retention period.

```js
await ledger.getExpiredEvents(): Promise<LedgerEvent[]>
```

##### `createIdentityBackup({ threshold, totalShares })`

> Creates Shamir backup shares of the private key.

```js
await ledger.createIdentityBackup({ threshold, totalShares }): Promise<string[]>
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| threshold | `number` | No | `2` | Minimum shares to reconstruct |
| totalShares | `number` | No | `3` | Total shares to create |

**Returns:** Array of serialized share strings (format: `styx-share-v1:{index}:{base64}`).

##### `restoreIdentity({ shares })`

> Restores identity from Shamir backup shares.

```js
await ledger.restoreIdentity({ shares }): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| shares | `string[]` | Yes | Serialized share strings (minimum `threshold` count) |

##### `blessNewDevice({ newPublicKey })`

> Creates a REKEY blessing event endorsing a new device's public key.

```js
await ledger.blessNewDevice({ newPublicKey }): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| newPublicKey | `StyxPublicKey` | Yes | The new device's Ed25519 public key |

**Throws:** `Error` if state is not `ready`.

##### `onStateChange(callback)`

> Subscribes to state change events.

```js
const unsubscribe = ledger.onStateChange(callback): () => void
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| callback | `function(string): void` | Yes | Called with the new `StyxState` value |

**Returns:** Unsubscribe function.

---

### `LedgerConfig`

> Configuration for the Styx ledger. Immutable after construction.

#### Constructor

```js
new LedgerConfig({
  relayUrls,
  privacyProfile,
  retentionPeriodMs,
  retentionTypes,
  logLevel,
  persistence,
  dbName,
  signalingUrl,
  iceServers,
})
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| relayUrls | `string[]` | No | `['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.snort.social']` | Nostr relay WebSocket URLs |
| privacyProfile | `string` | No | `'balanced'` | Push privacy profile (`'balanced'`, `'private'`, `'paranoid'`) |
| retentionPeriodMs | `number\|null` | No | `null` | Retention period in milliseconds |
| retentionTypes | `string[]` | No | `[]` | Event types subject to retention |
| logLevel | `string` | No | `'info'` | `LogLevel` value |
| persistence | `string` | No | `'memory'` | `'memory'` or `'indexeddb'` |
| dbName | `string` | No | `'styx-ledger'` | IndexedDB database name |
| signalingUrl | `string\|null` | No | `null` | WebSocket URL for WebRTC signaling |
| iceServers | `RTCIceServer[]\|null` | No | `null` | Custom ICE configuration for WebRTC |

---

### `StyxState`

> Enum of possible ledger states.

```js
import { StyxState } from 'styx-js';
```

| Value | Description |
|-------|-------------|
| `StyxState.UNINITIALIZED` | Not yet initialized |
| `StyxState.INITIALIZING` | Initialization in progress |
| `StyxState.UNPAIRED` | Initialized but no peer paired |
| `StyxState.READY` | Paired and transport connected |
| `StyxState.DEGRADED` | Paired but transport connection failed |
| `StyxState.PAIRING` | Pairing in progress |
| `StyxState.MIGRATING` | Device migration in progress |
| `StyxState.ERROR` | Unrecoverable error |
| `StyxState.SHUTTING_DOWN` | Shutdown in progress |

---

### `LogLevel`

> Enum of log levels.

```js
import { LogLevel } from 'styx-js';
```

| Value | Description |
|-------|-------------|
| `LogLevel.NONE` | No logging |
| `LogLevel.ERROR` | Errors only |
| `LogLevel.WARNING` | Errors and warnings |
| `LogLevel.INFO` | Errors, warnings, and info |
| `LogLevel.DEBUG` | All messages including debug |

---

## 5. API Reference -- crypto

Module: `styx-js/crypto`

### `StyxPublicKey`

> Immutable Ed25519 public key (32 bytes).

#### Constructor

```js
new StyxPublicKey(bytes)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| bytes | `Uint8Array` | Yes | Raw 32-byte Ed25519 public key |

**Throws:** `Error` if bytes is not exactly 32 bytes.

#### Static Methods

##### `StyxPublicKey.fromHex(hex)`

> Create a StyxPublicKey from a hex-encoded string.

```js
StyxPublicKey.fromHex(hex): StyxPublicKey
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| hex | `string` | Yes | 64-character hex string |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| bytes | `Uint8Array` | Copy of the raw 32-byte public key |
| nodeId | `string` | First 8 hex characters of the public key (used as node identifier) |

#### Methods

##### `toHex()`

> Returns the hex-encoded public key string (64 characters).

```js
publicKey.toHex(): string
```

##### `equals(other)`

> Constant-time equality comparison with another `StyxPublicKey`.

```js
publicKey.equals(other): boolean
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| other | `StyxPublicKey` | Yes | Key to compare against |

##### `toString()`

> Returns the hex representation. Alias for `toHex()`.

```js
publicKey.toString(): string
```

##### `toJSON()`

> Returns the hex representation for JSON serialization.

```js
publicKey.toJSON(): string
```

---

### `StyxPrivateKey`

> Ed25519 private key with secure destruction support.

#### Constructor

```js
new StyxPrivateKey(bytes)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| bytes | `Uint8Array` | Yes | Raw private key bytes |

**Throws:** `Error` if bytes is not a `Uint8Array`.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| bytes | `Uint8Array` | Copy of the raw private key bytes. Throws if destroyed. |
| isDestroyed | `boolean` | Whether `destroy()` has been called |

#### Methods

##### `destroy()`

> Securely zeros the key material. After calling, `bytes` will throw.

```js
privateKey.destroy(): void
```

---

### `StyxKeyPair`

> Container for an Ed25519 public/private key pair.

#### Constructor

```js
new StyxKeyPair(publicKey, privateKey)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| publicKey | `StyxPublicKey` | Yes | The public key |
| privateKey | `StyxPrivateKey` | Yes | The private key |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| publicKey | `StyxPublicKey` | The Ed25519 public key |
| privateKey | `StyxPrivateKey` | The Ed25519 private key |

---

### `IdentityManager`

> Generates and imports Ed25519 key pairs.

#### Constructor

```js
new IdentityManager()
```

No parameters.

#### Methods

##### `generate()`

> Generate a new random Ed25519 keypair.

```js
await identityManager.generate(): Promise<StyxKeyPair>
```

**Returns:** A new `StyxKeyPair` with freshly generated keys.

##### `exportPublicKey(publicKey)`

> Export a public key as raw bytes.

```js
identityManager.exportPublicKey(publicKey): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| publicKey | `StyxPublicKey` | Yes | Key to export |

##### `importPublicKey(bytes)`

> Import a public key from raw bytes.

```js
identityManager.importPublicKey(bytes): StyxPublicKey
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| bytes | `Uint8Array` | Yes | 32-byte raw public key |

##### `exportPrivateKey(privateKey)`

> Export a private key as raw bytes.

```js
identityManager.exportPrivateKey(privateKey): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| privateKey | `StyxPrivateKey` | Yes | Key to export |

##### `importPrivateKey(bytes)`

> Reconstruct a full keypair from raw private key bytes.

```js
await identityManager.importPrivateKey(bytes): Promise<StyxKeyPair>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| bytes | `Uint8Array` | Yes | Raw private key bytes |

**Returns:** A `StyxKeyPair` with the derived public key.

---

### `Hasher`

> SHA-256 hashing utilities for chain linkage and composite hashes.

#### Constructor

```js
new Hasher()
```

No parameters.

#### Methods

##### `hash(data)`

> Compute SHA-256 hash.

```js
hasher.hash(data): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| data | `Uint8Array` | Yes | Data to hash |

**Returns:** 32-byte SHA-256 hash.

##### `chainHash(previousHash, payload)`

> Compute chain hash: `SHA-256(previousHash || payload)`. For genesis events, `previousHash` is `null` (only payload is hashed).

```js
hasher.chainHash(previousHash, payload): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| previousHash | `Uint8Array\|null` | Yes | Hash of the preceding event, or `null` for genesis |
| payload | `Uint8Array` | Yes | Event payload |

##### `compositeHash(segments)`

> Compute composite hash: `SHA-256(segment[0] || segment[1] || ... || segment[n])`. Used for event hash computation.

```js
hasher.compositeHash(segments): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| segments | `Uint8Array[]` | Yes | Array of byte segments to concatenate and hash |

---

### `Signer`

> Signs data with Ed25519 private keys.

#### Constructor

```js
new Signer()
```

No parameters.

#### Methods

##### `sign(payload, privateKey)`

> Create an Ed25519 signature (64 bytes).

```js
await signer.sign(payload, privateKey): Promise<Uint8Array>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| payload | `Uint8Array` | Yes | Data to sign |
| privateKey | `StyxPrivateKey` | Yes | Ed25519 private key |

**Returns:** 64-byte Ed25519 signature.

---

### `Verifier`

> Verifies Ed25519 signatures.

#### Constructor

```js
new Verifier()
```

No parameters.

#### Methods

##### `verify(payload, signatureBytes, publicKey)`

> Verify an Ed25519 signature.

```js
await verifier.verify(payload, signatureBytes, publicKey): Promise<boolean>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| payload | `Uint8Array` | Yes | Original data |
| signatureBytes | `Uint8Array` | Yes | 64-byte signature |
| publicKey | `StyxPublicKey` | Yes | Signer's public key |

**Returns:** `true` if the signature is valid, `false` otherwise. Never throws.

---

### `KeyConverter`

> Converts Ed25519 keys to X25519 format for Diffie-Hellman key exchange.

#### Constructor

```js
new KeyConverter()
```

No parameters.

#### Methods

##### `ed25519PublicToX25519(publicKey)`

> Convert an Ed25519 public key to X25519 format.

```js
keyConverter.ed25519PublicToX25519(publicKey): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| publicKey | `StyxPublicKey` | Yes | Ed25519 public key |

**Returns:** 32-byte X25519 public key.

##### `ed25519PrivateToX25519(privateKey)`

> Convert an Ed25519 private key to X25519 format.

```js
keyConverter.ed25519PrivateToX25519(privateKey): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| privateKey | `StyxPrivateKey` | Yes | Ed25519 private key |

**Returns:** 32-byte X25519 private key.

---

### `X25519KeyPair`

> Ephemeral X25519 key pair with secure destruction.

#### Constructor

```js
new X25519KeyPair(publicKey, privateKey)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| publicKey | `Uint8Array` | Yes | 32-byte X25519 public key |
| privateKey | `Uint8Array` | Yes | 32-byte X25519 private key |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| publicKey | `Uint8Array` | X25519 public key |
| privateKey | `Uint8Array` | X25519 private key. Throws if destroyed. |
| isDestroyed | `boolean` | Whether `destroy()` has been called |

#### Methods

##### `destroy()`

> Securely zeros the private key material.

```js
keyPair.destroy(): void
```

---

### `DiffieHellman`

> X25519 Diffie-Hellman key exchange.

#### Constructor

```js
new DiffieHellman()
```

No parameters.

#### Methods

##### `generateEphemeralKeyPair()`

> Generate a random ephemeral X25519 key pair.

```js
dh.generateEphemeralKeyPair(): X25519KeyPair
```

**Returns:** A new `X25519KeyPair`.

##### `computeSharedSecret(localPrivateKey, remotePublicKey)`

> Compute the X25519 shared secret.

```js
dh.computeSharedSecret(localPrivateKey, remotePublicKey): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| localPrivateKey | `Uint8Array` | Yes | Local X25519 private key (32 bytes) |
| remotePublicKey | `Uint8Array` | Yes | Remote X25519 public key (32 bytes) |

**Returns:** 32-byte shared secret.

---

### `DirectionalKeys`

> Send and receive key pair with secure destruction. Derived via HKDF from a shared secret.

#### Constructor

```js
new DirectionalKeys(sendKey, receiveKey)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| sendKey | `Uint8Array` | Yes | 32-byte key for outgoing messages |
| receiveKey | `Uint8Array` | Yes | 32-byte key for incoming messages |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| sendKey | `Uint8Array` | Key for outgoing encryption. Throws if destroyed. |
| receiveKey | `Uint8Array` | Key for incoming decryption. Throws if destroyed. |
| isDestroyed | `boolean` | Whether `destroy()` has been called |

#### Methods

##### `destroy()`

> Securely zeros both key materials.

```js
directionalKeys.destroy(): void
```

---

### `KeyDerivation`

> HKDF-based key derivation with directional send/receive keys.

#### Constructor

```js
new KeyDerivation()
```

No parameters.

#### Methods

##### `deriveKey(sharedSecret, info, salt, outputLength)`

> Derive a key using HKDF-SHA256.

```js
keyDerivation.deriveKey(sharedSecret, info, salt?, outputLength?): Uint8Array
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| sharedSecret | `Uint8Array` | Yes | -- | Input key material |
| info | `Uint8Array` | Yes | -- | Context/application info |
| salt | `Uint8Array` | No | `new Uint8Array(0)` | Optional salt |
| outputLength | `number` | No | `32` | Output key length in bytes |

##### `deriveDirectionalKeys(sharedSecret, localPubKey, remotePubKey)`

> Derive directional send/receive keys based on lexicographic pubkey order. The peer with the lexicographically smaller pubkey gets `keyA` as `sendKey`.

```js
keyDerivation.deriveDirectionalKeys(sharedSecret, localPubKey, remotePubKey): DirectionalKeys
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| sharedSecret | `Uint8Array` | Yes | X25519 shared secret |
| localPubKey | `Uint8Array` | Yes | Local Ed25519 public key bytes |
| remotePubKey | `Uint8Array` | Yes | Remote Ed25519 public key bytes |

**Returns:** `DirectionalKeys` with send and receive keys.

---

### `StyxEncryptor`

> Encrypts/decrypts messages using ChaCha20-Poly1305. Wire format: `nonce(12) || ciphertext || tag(16)`. Compatible with the Dart `cryptography` package.

#### Constructor

```js
new StyxEncryptor(sendKey, receiveKey)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| sendKey | `Uint8Array` | Yes | 32-byte key for outgoing messages |
| receiveKey | `Uint8Array` | Yes | 32-byte key for incoming messages |

#### Methods

##### `encrypt(plaintext)`

> Encrypt plaintext with the send key.

```js
encryptor.encrypt(plaintext): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| plaintext | `Uint8Array` | Yes | Data to encrypt |

**Returns:** `nonce(12) || ciphertext || tag(16)`.

##### `decrypt(data)`

> Decrypt ciphertext with the receive key.

```js
encryptor.decrypt(data): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| data | `Uint8Array` | Yes | Encrypted data: `nonce(12) \|\| ciphertext \|\| tag(16)` |

**Returns:** Decrypted plaintext.

**Throws:** `Error` if authentication fails or data is too short.

---

### `Spake2Session`

> A SPAKE2 session on NIST P-256 that progresses through `init -> messageSent -> completed`. Compatible with the Dart implementation.

#### Constructor

```js
new Spake2Session(role, password)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| role | `string` | Yes | `Spake2Role.INITIATOR` or `Spake2Role.RESPONDER` |
| password | `Uint8Array` | Yes | Password bytes (UTF-8 encoded mnemonic) |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| role | `string` | `Spake2Role` value |
| state | `string` | Current `Spake2State` value |

#### Methods

##### `generateMessage()`

> Generate the SPAKE2 message to send to the peer. Returns uncompressed P-256 point bytes (65 bytes: `04 || x || y`).

```js
session.generateMessage(): Uint8Array
```

**Returns:** 65-byte uncompressed point.

**Throws:** `Error` if state is not `init`.

##### `processMessage(peerMessage)`

> Process the peer's SPAKE2 message and derive the shared session key.

```js
session.processMessage(peerMessage): boolean
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| peerMessage | `Uint8Array` | Yes | Peer's uncompressed point bytes (65 bytes) |

**Returns:** `true` if session key was derived, `false` on failure.

##### `getSessionKey()`

> Get the derived 32-byte shared session key.

```js
session.getSessionKey(): Uint8Array
```

**Throws:** `Error` if SPAKE2 is not completed.

##### `getConfirmation()`

> Get HMAC confirmation value for the session: `HMAC(confirmationKey, roleByte || ourMessage || peerMessage)`.

```js
session.getConfirmation(): Uint8Array
```

**Throws:** `Error` if SPAKE2 is not completed.

##### `verifyConfirmation(peerConfirmation)`

> Verify peer's HMAC confirmation using constant-time comparison.

```js
session.verifyConfirmation(peerConfirmation): boolean
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| peerConfirmation | `Uint8Array` | Yes | Peer's confirmation HMAC |

**Returns:** `true` if confirmation is valid.

##### `destroy()`

> Securely destroy all session secrets (scalar, session key, confirmation key).

```js
session.destroy(): void
```

---

### `Spake2Protocol`

> Factory for creating SPAKE2 sessions.

#### Constructor

```js
new Spake2Protocol()
```

No parameters.

#### Methods

##### `createInitiatorSession(password)`

> Create a SPAKE2 session in the initiator role.

```js
spake2.createInitiatorSession(password): Spake2Session
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| password | `Uint8Array` | Yes | Password bytes |

##### `createResponderSession(password)`

> Create a SPAKE2 session in the responder role.

```js
spake2.createResponderSession(password): Spake2Session
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| password | `Uint8Array` | Yes | Password bytes |

##### `mnemonicToPassword(mnemonic)`

> Convert a BIP-39 mnemonic to password bytes for SPAKE2. Compatible with Dart: `utf8(mnemonic.trim().toLowerCase())`.

```js
spake2.mnemonicToPassword(mnemonic): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| mnemonic | `string` | Yes | Space-separated BIP-39 mnemonic |

---

### `Spake2Role`

> Enum of SPAKE2 roles.

| Value | Description |
|-------|-------------|
| `Spake2Role.INITIATOR` | The peer that generates the mnemonic |
| `Spake2Role.RESPONDER` | The peer that receives the mnemonic |

---

### `Spake2State`

> Enum of SPAKE2 session states.

| Value | Description |
|-------|-------------|
| `Spake2State.INIT` | Session created, not yet started |
| `Spake2State.MESSAGE_SENT` | Local message generated |
| `Spake2State.COMPLETED` | Session key derived successfully |
| `Spake2State.FAILED` | Protocol failed or was cancelled |

---

### `ShamirShare`

> Immutable Shamir secret share with serialization.

#### Constructor

```js
new ShamirShare(index, data)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| index | `number` | Yes | Share index (1-255, 1-based) |
| data | `Uint8Array` | Yes | Share data bytes |

**Throws:** `Error` if index is not in range 1-255.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| index | `number` | Share index (1-based) |
| data | `Uint8Array` | Share data bytes |

#### Methods

##### `serialize()`

> Serialize to string for storage/transmission.

```js
share.serialize(): string
```

**Returns:** Format: `styx-share-v1:{index}:{base64_data}`.

##### `ShamirShare.deserialize(encoded)` (static)

> Deserialize from string.

```js
ShamirShare.deserialize(encoded): ShamirShare
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| encoded | `string` | Yes | Serialized share string |

**Throws:** `InvalidShareException` if format is invalid.

---

### `ShamirSplitter`

> Splits secrets using Shamir's Secret Sharing over GF(256).

#### Constructor

```js
new ShamirSplitter()
```

No parameters.

#### Methods

##### `split(secret, threshold, totalShares)`

> Split a secret into shares.

```js
splitter.split(secret, threshold?, totalShares?): ShamirShare[]
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| secret | `Uint8Array` | Yes | -- | The secret to split |
| threshold | `number` | No | `2` | Minimum shares to reconstruct |
| totalShares | `number` | No | `3` | Total shares to create |

**Throws:** `Error` if threshold < 2, totalShares < threshold, or totalShares > 255.

---

### `ShamirReconstructor`

> Reconstructs secrets from Shamir shares using Lagrange interpolation over GF(256).

#### Constructor

```js
new ShamirReconstructor()
```

No parameters.

#### Methods

##### `reconstruct(shares)`

> Reconstruct the original secret from shares.

```js
reconstructor.reconstruct(shares): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| shares | `ShamirShare[]` | Yes | At least `threshold` shares |

**Throws:** `InsufficientSharesException` if fewer than 2 shares. `InvalidShareException` if shares have different lengths.

---

### `KeyBackup`

> High-level service for creating and restoring Shamir backups of private keys.

#### Constructor

```js
new KeyBackup()
```

No parameters. Internally creates a `ShamirSplitter` and `ShamirReconstructor`.

#### Methods

##### `backupPrivateKey(privateKey, threshold, totalShares)`

> Split a private key into Shamir shares.

```js
keyBackup.backupPrivateKey(privateKey, threshold?, totalShares?): ShamirShare[]
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| privateKey | `StyxPrivateKey` | Yes | -- | Private key to back up |
| threshold | `number` | No | `2` | Minimum shares to reconstruct |
| totalShares | `number` | No | `3` | Total shares to create |

##### `restoreFromShares(shares, identityManager)`

> Reconstruct a keypair from Shamir shares.

```js
await keyBackup.restoreFromShares(shares, identityManager): Promise<StyxKeyPair>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| shares | `ShamirShare[]` | Yes | At least `threshold` shares |
| identityManager | `IdentityManager` | Yes | Used to derive the public key from the reconstructed private key |

##### `verifyShares(shares, identityManager)`

> Verify that shares can reconstruct a valid keypair.

```js
await keyBackup.verifyShares(shares, identityManager): Promise<boolean>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| shares | `ShamirShare[]` | Yes | Shares to verify |
| identityManager | `IdentityManager` | Yes | Used to derive and validate the public key |

---

### `InsufficientSharesException`

> Error thrown when fewer than 2 shares are provided for reconstruction.

```js
class InsufficientSharesException extends Error
```

### `InvalidShareException`

> Error thrown when share data is malformed or inconsistent.

```js
class InvalidShareException extends Error
```

---

### `MnemonicGenerator`

> Generates and validates BIP-39 mnemonics.

#### Constructor

```js
new MnemonicGenerator()
```

No parameters.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| supportedLanguages | `string[]` | Always `['english']` |

#### Methods

##### `generate(wordCount)`

> Generate a random mnemonic from the BIP-39 wordlist.

```js
mnemonicGenerator.generate(wordCount?): string
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| wordCount | `number` | No | `6` | Number of words to generate |

**Returns:** Space-separated mnemonic string.

**Throws:** `Error` if the BIP-39 wordlist has not been loaded via `setBip39Wordlist()`.

##### `validate(mnemonic)`

> Validate that all words exist in the BIP-39 wordlist.

```js
mnemonicGenerator.validate(mnemonic): boolean
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| mnemonic | `string` | Yes | Space-separated mnemonic |

##### `mnemonicToSeed(mnemonic)`

> Derive a 64-byte seed from the mnemonic via PBKDF2-SHA512 (2048 iterations).

```js
await mnemonicGenerator.mnemonicToSeed(mnemonic): Promise<Uint8Array>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| mnemonic | `string` | Yes | Space-separated mnemonic |

**Returns:** 64-byte seed.

---

### `SessionVerifier`

> Derives 6-digit Double Check verification codes from SPAKE2 session keys.

#### Constructor

```js
new SessionVerifier()
```

No parameters.

#### Methods

##### `generateDoubleCheckCode(sessionKey)`

> Generate a 6-digit code from a session key via `SHA-256(sessionKey || "styx-double-check-v1")`, truncated to 24 bits modulo 1,000,000.

```js
sessionVerifier.generateDoubleCheckCode(sessionKey): string
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| sessionKey | `Uint8Array` | Yes | 32-byte SPAKE2 session key |

**Returns:** 6-digit zero-padded string, e.g. `"483291"`.

---

### `DoubleCheckVerifier`

> Double Check code verifier with formatting utilities.

#### Constructor

```js
new DoubleCheckVerifier()
```

No parameters.

#### Methods

##### `generateCode(sessionKey)`

> Generate a 6-digit code from a session key.

```js
doubleCheck.generateCode(sessionKey): string
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| sessionKey | `Uint8Array` | Yes | 32-byte SPAKE2 session key |

##### `formatForDisplay(code)`

> Format code for user display.

```js
doubleCheck.formatForDisplay(code): string
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| code | `string` | Yes | 6-digit code |

**Returns:** Formatted string, e.g. `"483291"` becomes `"483 291"`.

##### `isValidFormat(input)`

> Check if input is exactly 6 digits (ignoring spaces and dashes).

```js
doubleCheck.isValidFormat(input): boolean
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| input | `string` | Yes | User input to validate |

##### `normalize(input)`

> Remove spaces and dashes from input.

```js
doubleCheck.normalize(input): string
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| input | `string` | Yes | Input to normalize |

---

### `setBip39Wordlist(wordlist)`

> Set the BIP-39 wordlist. Must be called before using `MnemonicGenerator`.

```js
setBip39Wordlist(wordlist): void
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| wordlist | `string[]` | Yes | Array of exactly 2048 words |

**Throws:** `Error` if wordlist does not have exactly 2048 entries.

---

### `getBip39Wordlist()`

> Get the currently loaded BIP-39 wordlist.

```js
getBip39Wordlist(): string[]
```

**Throws:** `Error` if wordlist has not been loaded.

---

## 6. API Reference -- ledger

Module: `styx-js/ledger`

### `LedgerEvent`

> Immutable representation of a ledger event in the hash chain. Frozen after construction.

#### Constructor

```js
new LedgerEvent({
  eventId,
  eventType,
  payload,
  previousHash,
  eventHash,
  hlc,
  vectorClock,
  senderPubkey,
  signature,
  createdAt,
  isPruned,
})
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| eventId | `string` | Yes | -- | UUID v4 identifier |
| eventType | `string` | Yes | -- | `EventType` value |
| payload | `Uint8Array\|null` | Yes | -- | Event data (null after pruning) |
| previousHash | `string\|null` | Yes | -- | Hash of the preceding event (null for genesis) |
| eventHash | `string` | Yes | -- | SHA-256 hash of this event (hex) |
| hlc | `HybridLogicalClock` | Yes | -- | Hybrid Logical Clock timestamp |
| vectorClock | `VectorClock` | Yes | -- | 2-element vector clock |
| senderPubkey | `string` | Yes | -- | Hex-encoded sender public key |
| signature | `Uint8Array` | Yes | -- | Ed25519 signature (64 bytes) |
| createdAt | `Date` | Yes | -- | Wall-clock creation time (UTC) |
| isPruned | `boolean` | No | `false` | Whether payload has been pruned |

#### Properties

All constructor parameters are available as read-only properties (the object is `Object.freeze`d).

#### Methods

##### `toPruned()`

> Create a pruned copy with payload nullified.

```js
event.toPruned(): LedgerEvent
```

**Returns:** A new `LedgerEvent` with `payload: null` and `isPruned: true`.

##### `toJSON()`

> Serialize to a JSON-compatible object. Converts `Uint8Array` fields to arrays, HLC to canonical string, VectorClock to `{ a, b }`.

```js
event.toJSON(): object
```

##### `LedgerEvent.fromJSON(json, HLC, VC)` (static)

> Deserialize from a JSON object.

```js
LedgerEvent.fromJSON(json, HybridLogicalClock, VectorClock): LedgerEvent
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| json | `object` | Yes | Serialized event data |
| HLC | `typeof HybridLogicalClock` | Yes | The HLC class (for `fromCanonical`) |
| VC | `typeof VectorClock` | Yes | The VectorClock class (for `fromJSON`) |

---

### `EventType`

> Enum of event types.

```js
import { EventType } from 'styx-js';
```

| Value | Description |
|-------|-------------|
| `EventType.TRANSACTION` | `'transaction'` -- Financial or data transaction |
| `EventType.MESSAGE` | `'message'` -- Text message |
| `EventType.SOS` | `'sos'` -- Emergency signal |
| `EventType.CONFIG` | `'config'` -- Configuration event (also used for genesis) |
| `EventType.REKEY` | `'rekey'` -- Device migration / key rotation |
| `EventType.MERGE` | `'merge'` -- Fork merge event |
| `EventType.PRUNE_REQUEST` | `'pruneRequest'` -- Request to prune an event |
| `EventType.PRUNE_ACK` | `'pruneAck'` -- Acknowledgment of a prune request |

---

### `PruneReason`

> Enum of pruning reasons.

| Value | Description |
|-------|-------------|
| `PruneReason.RETENTION_EXPIRED` | `'retentionExpired'` -- Event exceeded retention policy |
| `PruneReason.USER_REQUEST` | `'userRequest'` -- User-initiated deletion |
| `PruneReason.GDPR_ARTICLE_17` | `'gdprArticle17'` -- GDPR right to erasure (unilateral) |

---

### `ChainErrorType`

> Enum of chain validation error types.

| Value | Description |
|-------|-------------|
| `ChainErrorType.HASH_MISMATCH` | Computed hash differs from stored hash |
| `ChainErrorType.SIGNATURE_INVALID` | Ed25519 signature verification failed |
| `ChainErrorType.PREVIOUS_HASH_MISSING` | previousHash does not match preceding event |
| `ChainErrorType.HLC_VIOLATION` | HLC is not monotonically increasing |
| `ChainErrorType.GENESIS_VIOLATION` | Invalid genesis event (non-null previousHash) |

---

### `ChainValidationError`

> Describes a chain validation error.

#### Constructor

```js
new ChainValidationError(eventId, errorType, message)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| eventId | `string` | Yes | UUID of the problematic event |
| errorType | `string` | Yes | `ChainErrorType` value |
| message | `string` | Yes | Human-readable error description |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| eventId | `string` | UUID of the problematic event |
| errorType | `string` | `ChainErrorType` value |
| message | `string` | Human-readable error description |

---

### `VectorClock`

> 2-element vector clock for the Styx 2-peer system. Immutable -- all mutations return a new VectorClock.

#### Constructor

```js
new VectorClock(a, b)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| a | `number` | Yes | Counter for peer A |
| b | `number` | Yes | Counter for peer B |

#### Static Methods

##### `VectorClock.zero()`

> Create a zero vector clock `VC(0, 0)`.

```js
VectorClock.zero(): VectorClock
```

##### `VectorClock.fromJSON(json)`

> Create from a JSON object `{ a, b }`.

```js
VectorClock.fromJSON(json): VectorClock
```

##### `VectorClock.fromBytes(bytes)`

> Create from 8-byte big-endian buffer (4 bytes for A, 4 bytes for B).

```js
VectorClock.fromBytes(bytes): VectorClock
```

#### Properties

| Name | Type | Description |
|------|------|-------------|
| a | `number` | Counter for peer A |
| b | `number` | Counter for peer B |
| total | `number` | Sum `a + b` (used for deterministic merge ordering) |

#### Methods

##### `increment(localPeerRole)`

> Return a new VectorClock with the counter for the given role incremented by 1.

```js
vc.increment(localPeerRole): VectorClock
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| localPeerRole | `string` | Yes | `'A'` or `'B'` |

**Throws:** `Error` if role is not `'A'` or `'B'`.

##### `merge(other)`

> Component-wise maximum (merge). Used when merging forks.

```js
vc.merge(other): VectorClock
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| other | `VectorClock` | Yes | Vector clock to merge with |

**Returns:** New VectorClock with `max(a1, a2)` and `max(b1, b2)`.

##### `causalRelation(other)`

> Determine the causal relationship with another vector clock.

```js
vc.causalRelation(other): string
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| other | `VectorClock` | Yes | Vector clock to compare against |

**Returns:** `CausalRelation` value: `'before'`, `'after'`, `'concurrent'`, or `'equal'`.

##### `toJSON()`

> Serialize to `{ a, b }`.

```js
vc.toJSON(): { a: number, b: number }
```

##### `toBytes()`

> Serialize to 8 bytes (4 for A, 4 for B, big-endian).

```js
vc.toBytes(): Uint8Array
```

##### `equals(other)`

> Check equality.

```js
vc.equals(other): boolean
```

##### `toString()`

> Returns `"VC(a, b)"`.

```js
vc.toString(): string
```

---

### `CausalRelation`

> Enum of causal relationships between vector clocks.

| Value | Description |
|-------|-------------|
| `CausalRelation.BEFORE` | This event happened before the other |
| `CausalRelation.AFTER` | This event happened after the other |
| `CausalRelation.CONCURRENT` | Events are concurrent (fork) |
| `CausalRelation.EQUAL` | Identical vector clocks |

---

### `CausalityChecker`

> Determines causal relationships between vector clocks.

#### Constructor

```js
new CausalityChecker()
```

No parameters.

#### Methods

##### `compare(a, b)`

> Compare two vector clocks.

```js
checker.compare(a, b): string
```

**Returns:** `CausalRelation` value.

##### `isAfter(event, reference)`

> Check if `event` happened after `reference`.

```js
checker.isAfter(event, reference): boolean
```

##### `isConcurrent(a, b)`

> Check if two vector clocks are concurrent.

```js
checker.isConcurrent(a, b): boolean
```

---

### `HybridLogicalClock`

> Hybrid Logical Clock combining wall-clock time, logical counter, and node ID. Immutable.

#### Constructor

```js
new HybridLogicalClock(timestamp, counter, nodeId)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| timestamp | `Date` | Yes | UTC wall-clock time |
| counter | `number` | Yes | Logical counter (tiebreaker within same millisecond) |
| nodeId | `string` | Yes | Node identifier (first 8 hex chars of pubkey) |

#### Static Methods

##### `HybridLogicalClock.now(previous, nodeId)`

> Create an HLC for the current instant, ensuring monotonicity with the previous HLC.

```js
HybridLogicalClock.now(previous, nodeId): HybridLogicalClock
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| previous | `HybridLogicalClock\|null` | Yes | Previous HLC, or `null` for the first event |
| nodeId | `string` | Yes | Local node identifier |

##### `HybridLogicalClock.fromCanonical(s)`

> Parse from canonical format: `"2026-02-24T12:00:00.000Z-0042-a1b2c3d4"`.

```js
HybridLogicalClock.fromCanonical(s): HybridLogicalClock
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| s | `string` | Yes | Canonical HLC string |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| timestamp | `Date` | UTC wall-clock time |
| counter | `number` | Logical counter |
| nodeId | `string` | Node identifier |

#### Methods

##### `toCanonical()`

> Canonical string representation.

```js
hlc.toCanonical(): string
```

**Returns:** Format: `"2026-02-24T12:00:00.000Z-0042-a1b2c3d4"`.

**Note:** The counter is serialized as a decimal integer (not hex), zero-padded to 4 characters. This is compatible with the Dart implementation.

##### `toBytes()`

> Serialize to UTF-8 bytes of the canonical string (for hash computation).

```js
hlc.toBytes(): Uint8Array
```

##### `compareTo(other)`

> Compare by timestamp, then counter, then nodeId.

```js
hlc.compareTo(other): number
```

**Returns:** `-1`, `0`, or `1`.

##### `toString()`

> Alias for `toCanonical()`.

```js
hlc.toString(): string
```

---

### `EventFactory`

> Creates signed, hashed events for the ledger chain.

#### Constructor

```js
new EventFactory(signer, hasher)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| signer | `Signer` | Yes | Ed25519 signer |
| hasher | `Hasher` | Yes | SHA-256 hasher |

#### Methods

##### `createEvent({ type, payload, privateKey, publicKey, previousEvent, currentVectorClock, localPeerRole })`

> Create a new event appended to the chain. Generates UUID, computes HLC, increments vector clock, computes SHA-256 hash, signs with Ed25519.

```js
await eventFactory.createEvent({
  type,
  payload,
  privateKey,
  publicKey,
  previousEvent,
  currentVectorClock,
  localPeerRole,
}): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| type | `string` | Yes | `EventType` value |
| payload | `Uint8Array` | Yes | Event data bytes |
| privateKey | `StyxPrivateKey` | Yes | Signing key |
| publicKey | `StyxPublicKey` | Yes | Sender's public key |
| previousEvent | `LedgerEvent\|null` | Yes | Last event in the chain, or `null` |
| currentVectorClock | `VectorClock` | Yes | Current vector clock state |
| localPeerRole | `string` | Yes | `'A'` or `'B'` |

##### `createGenesisEvent({ privateKey, publicKey, nodeId })`

> Create the first event in the chain (genesis). Uses `EventType.CONFIG` with zero vector clock.

```js
await eventFactory.createGenesisEvent({ privateKey, publicKey, nodeId }): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| privateKey | `StyxPrivateKey` | Yes | Signing key |
| publicKey | `StyxPublicKey` | Yes | Sender's public key |
| nodeId | `string` | Yes | Node identifier for HLC |

##### `computeHashBytes({ previousHash, eventType, payload, hlcBytes })`

> Compute `SHA-256(previousHash || eventType || payload || hlcBytes)`.

```js
eventFactory.computeHashBytes({ previousHash, eventType, payload, hlcBytes }): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| previousHash | `string\|null` | Yes | Hex hash of preceding event |
| eventType | `string` | Yes | Event type string |
| payload | `Uint8Array\|null` | Yes | Event payload |
| hlcBytes | `Uint8Array` | Yes | HLC serialized to bytes |

---

### `ChainValidator`

> Validates the integrity of the ledger chain: hash linkage, signatures, HLC monotonicity.

#### Constructor

```js
new ChainValidator(hasher, verifier)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| hasher | `Hasher` | Yes | SHA-256 hasher |
| verifier | `Verifier` | Yes | Ed25519 verifier |

#### Methods

##### `validateFullChain(events)`

> Validate every event in sequence.

```js
await chainValidator.validateFullChain(events): Promise<ChainValidationError|null>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| events | `LedgerEvent[]` | Yes | Events ordered by HLC |

**Returns:** `null` if valid, or the first `ChainValidationError` found.

##### `validateEvent(event, previousEvent, senderPublicKey)`

> Validate a single event against its predecessor.

```js
await chainValidator.validateEvent(event, previousEvent, senderPublicKey): Promise<ChainValidationError|null>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event | `LedgerEvent` | Yes | Event to validate |
| previousEvent | `LedgerEvent\|null` | Yes | Preceding event, or `null` for genesis |
| senderPublicKey | `StyxPublicKey` | Yes | Expected signer's public key |

##### `verifyEventHash(event, previousHash)`

> Verify that the stored event hash matches the computed hash.

```js
await chainValidator.verifyEventHash(event, previousHash): Promise<boolean>
```

##### `verifyEventSignature(event, publicKey)`

> Verify the Ed25519 signature on the event.

```js
await chainValidator.verifyEventSignature(event, publicKey): Promise<boolean>
```

---

### `Fork`

> Represents a fork where two branches diverge from a common ancestor.

#### Constructor

```js
new Fork(commonAncestorHash, branchA, branchB)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| commonAncestorHash | `string` | Yes | Hash of the common ancestor event |
| branchA | `LedgerEvent[]` | Yes | Local branch events |
| branchB | `LedgerEvent[]` | Yes | Remote branch events |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| commonAncestorHash | `string` | Hash of the common ancestor |
| branchA | `LedgerEvent[]` | Local branch |
| branchB | `LedgerEvent[]` | Remote branch |

---

### `ForkDetector`

> Detects forks in the event chain.

#### Constructor

```js
new ForkDetector(causalityChecker?)
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| causalityChecker | `CausalityChecker` | No | `new CausalityChecker()` | Causality comparison helper |

#### Methods

##### `detectForks(events)`

> Scan all events for forks (events sharing the same previousHash).

```js
forkDetector.detectForks(events): Fork[]
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| events | `LedgerEvent[]` | Yes | All events in the chain |

##### `detectForkOnReceive(remoteEvent, localHead)`

> Detect if a received remote event creates a fork with the local head.

```js
forkDetector.detectForkOnReceive(remoteEvent, localHead): Fork|null
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| remoteEvent | `LedgerEvent` | Yes | Incoming remote event |
| localHead | `LedgerEvent` | Yes | Current local chain head |

**Returns:** `Fork` if a fork is detected, `null` otherwise.

---

### `MergeResult`

> Result of a deterministic merge operation.

#### Constructor

```js
new MergeResult(orderedEvents, mergeEventNeeded)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| orderedEvents | `LedgerEvent[]` | Yes | Events in deterministic order |
| mergeEventNeeded | `boolean` | Yes | Whether a MERGE event should be appended |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| orderedEvents | `LedgerEvent[]` | Events in deterministic order |
| mergeEventNeeded | `boolean` | Whether a MERGE event should be appended |

---

### `DeterministicMerge`

> Deterministic merge of forked branches. Both peers apply the same ordering rule, guaranteeing convergence.

#### Constructor

```js
new DeterministicMerge()
```

No parameters.

#### Methods

##### `orderConcurrentEvents(events)`

> Order concurrent events deterministically: (1) by vector clock total ascending, (2) tiebreak by sender pubkey lexicographic.

```js
merge.orderConcurrentEvents(events): LedgerEvent[]
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| events | `LedgerEvent[]` | Yes | Concurrent events to order |

**Returns:** New array sorted deterministically.

##### `merge(fork, localPeerRole)`

> Merge a fork into a linear sequence.

```js
merge.merge(fork, localPeerRole): MergeResult
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| fork | `Fork` | Yes | Fork to merge |
| localPeerRole | `string` | Yes | `'A'` or `'B'` |

---

### `MergeEventFactory`

> Creates MERGE events that reference both tips of a fork.

#### Constructor

```js
new MergeEventFactory(eventFactory)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| eventFactory | `EventFactory` | Yes | Factory for creating signed events |

#### Methods

##### `createMergeEvent({ branchAHeadHash, branchBHeadHash, ancestorHash, newPreviousEvent, privateKey, publicKey, mergedVectorClock, localPeerRole })`

> Create a MERGE event with a payload containing the branch tip hashes and ancestor hash.

```js
await mergeEventFactory.createMergeEvent({
  branchAHeadHash,
  branchBHeadHash,
  ancestorHash,
  newPreviousEvent,
  privateKey,
  publicKey,
  mergedVectorClock,
  localPeerRole,
}): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| branchAHeadHash | `string` | Yes | Hash of local branch tip |
| branchBHeadHash | `string` | Yes | Hash of remote branch tip |
| ancestorHash | `string` | Yes | Hash of common ancestor |
| newPreviousEvent | `LedgerEvent` | Yes | Event to link as predecessor |
| privateKey | `StyxPrivateKey` | Yes | Signing key |
| publicKey | `StyxPublicKey` | Yes | Sender's public key |
| mergedVectorClock | `VectorClock` | Yes | Merged vector clock (component-wise max) |
| localPeerRole | `string` | Yes | `'A'` or `'B'` |

---

### `PruneState`

> Enum of pruning states.

| Value | Description |
|-------|-------------|
| `PruneState.IDLE` | No pruning in progress |
| `PruneState.REQUEST_SENT` | PRUNE_REQUEST event sent |
| `PruneState.WAITING_ACK` | Waiting for peer's PRUNE_ACK |
| `PruneState.PRUNED` | Bilateral prune completed |
| `PruneState.UNILATERAL_PRUNED` | Unilateral prune completed |

---

### `PruneProtocol`

> Bilateral pruning protocol for GDPR compliance.

#### Constructor

```js
new PruneProtocol(eventFactory)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| eventFactory | `EventFactory` | Yes | Factory for creating signed events |

#### Methods

##### `requestPrune({ targetEventId, targetEventHash, reason, privateKey, publicKey, previousEvent, currentVectorClock, localPeerRole })`

> Create a PRUNE_REQUEST event.

```js
await pruneProtocol.requestPrune({
  targetEventId,
  targetEventHash,
  reason,
  privateKey,
  publicKey,
  previousEvent,
  currentVectorClock,
  localPeerRole,
}): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| targetEventId | `string` | Yes | UUID of the event to prune |
| targetEventHash | `string` | Yes | Hash of the event to prune |
| reason | `string` | Yes | `PruneReason` value |
| privateKey | `StyxPrivateKey` | Yes | Signing key |
| publicKey | `StyxPublicKey` | Yes | Sender's public key |
| previousEvent | `LedgerEvent` | Yes | Last event in the chain |
| currentVectorClock | `VectorClock` | Yes | Current vector clock |
| localPeerRole | `string` | Yes | `'A'` or `'B'` |

##### `acknowledgePrune({ pruneRequest, privateKey, publicKey, previousEvent, currentVectorClock, localPeerRole })`

> Create a PRUNE_ACK event in response to a request.

```js
await pruneProtocol.acknowledgePrune({
  pruneRequest,
  privateKey,
  publicKey,
  previousEvent,
  currentVectorClock,
  localPeerRole,
}): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| pruneRequest | `LedgerEvent` | Yes | The received PRUNE_REQUEST event |
| privateKey | `StyxPrivateKey` | Yes | Signing key |
| publicKey | `StyxPublicKey` | Yes | Sender's public key |
| previousEvent | `LedgerEvent` | Yes | Last event in the chain |
| currentVectorClock | `VectorClock` | Yes | Current vector clock |
| localPeerRole | `string` | Yes | `'A'` or `'B'` |

##### `executeBilateralPrune(targetEventId, store)`

> Nullify payload after both REQUEST and ACK.

```js
await pruneProtocol.executeBilateralPrune(targetEventId, store): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| targetEventId | `string` | Yes | UUID of the event to prune |
| store | `LedgerStore` | Yes | Store to perform pruning on |

##### `executeUnilateralPrune(targetEventId, store)`

> Immediately nullify payload -- GDPR Art. 17, no ACK needed.

```js
await pruneProtocol.executeUnilateralPrune(targetEventId, store): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| targetEventId | `string` | Yes | UUID of the event to prune |
| store | `LedgerStore` | Yes | Store to perform pruning on |

---

### `RetentionManager`

> Evaluates retention policies to identify expired events.

#### Constructor

```js
new RetentionManager()
```

No parameters.

#### Methods

##### `getExpiredEvents(events, retentionMs, applicableTypes)`

> Return events that exceed the retention period. Already-pruned events are excluded.

```js
retentionManager.getExpiredEvents(events, retentionMs, applicableTypes): LedgerEvent[]
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| events | `LedgerEvent[]` | Yes | All events to evaluate |
| retentionMs | `number` | Yes | Retention period in milliseconds |
| applicableTypes | `string[]` | Yes | `EventType` values to evaluate |

---

### `LedgerService`

> High-level facade for ledger operations with persistent storage.

#### Constructor

```js
new LedgerService(eventFactory, chainValidator, store, localPeerRole)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| eventFactory | `EventFactory` | Yes | Factory for creating signed events |
| chainValidator | `ChainValidator` | Yes | Chain validation service |
| store | `LedgerStore` | Yes | Ledger persistence layer |
| localPeerRole | `string` | Yes | `'A'` or `'B'` |

#### Methods

##### `appendEvent({ type, payload, privateKey, publicKey })`

> Append a new event to the local chain. Automatically retrieves the latest event and vector clock from the store.

```js
await ledgerService.appendEvent({ type, payload, privateKey, publicKey }): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| type | `string` | Yes | `EventType` value |
| payload | `Uint8Array` | Yes | Event data |
| privateKey | `StyxPrivateKey` | Yes | Signing key |
| publicKey | `StyxPublicKey` | Yes | Sender's public key |

##### `receiveRemoteEvent(event)`

> Receive and store a remote event. Emits both `remoteEvent` and `newEvent` events.

```js
await ledgerService.receiveRemoteEvent(event): Promise<LedgerEvent>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event | `LedgerEvent` | Yes | Remote event to store |

##### `getHistory()`

> Returns all events ordered by HLC.

```js
await ledgerService.getHistory(): Promise<LedgerEvent[]>
```

##### `getHistoryRange(from, to)`

> Returns events within a time range.

```js
await ledgerService.getHistoryRange(from, to): Promise<LedgerEvent[]>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| from | `Date` | Yes | Start of range |
| to | `Date` | Yes | End of range |

##### `validateChain()`

> Validate the full chain integrity.

```js
await ledgerService.validateChain(): Promise<ChainValidationError|null>
```

##### `getLatestEvent()`

> Get the latest event or `null`.

```js
await ledgerService.getLatestEvent(): Promise<LedgerEvent|null>
```

##### `onNewEvent(callback)`

> Subscribe to all new events (local and remote).

```js
const unsubscribe = ledgerService.onNewEvent(callback): () => void
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| callback | `function(LedgerEvent): void` | Yes | Called for each new event |

**Returns:** Unsubscribe function.

##### `onRemoteEvent(callback)`

> Subscribe to remote events only.

```js
const unsubscribe = ledgerService.onRemoteEvent(callback): () => void
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| callback | `function(LedgerEvent): void` | Yes | Called for each remote event |

**Returns:** Unsubscribe function.

---

## 7. API Reference -- storage

Module: `styx-js/storage`

### `LedgerStore` (abstract)

> Abstract interface for ledger persistence. Extend this class to provide storage backed by IndexedDB, SQLite, or any other backend.

#### Methods

All methods are `async` and throw `Error('Not implemented')` by default.

| Method | Signature | Description |
|--------|-----------|-------------|
| `appendEvent(event)` | `Promise<void>` | Append an event to the store |
| `getAllEvents()` | `Promise<LedgerEvent[]>` | Get all events ordered by HLC |
| `getLatestEvent()` | `Promise<LedgerEvent\|null>` | Get the most recent event |
| `getEventById(eventId)` | `Promise<LedgerEvent\|null>` | Get an event by UUID |
| `getEventsByType(eventType)` | `Promise<LedgerEvent[]>` | Get events by type |
| `getCurrentVectorClock()` | `Promise<VectorClock>` | Get the current vector clock state |
| `pruneEvent(eventId)` | `Promise<void>` | Nullify an event's payload |
| `clear()` | `Promise<void>` | Clear all events |
| `count()` | `Promise<number>` | Get event count |

---

### `PeerStore` (abstract)

> Abstract interface for peer persistence.

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `addPeer({ pubkeyHex, alias, pairedAt })` | `Promise<void>` | Add a trusted peer |
| `getPeerByPubkey(pubkeyHex)` | `Promise<object\|null>` | Get peer by public key hex |
| `getActivePeers()` | `Promise<object[]>` | Get all active peers |
| `deactivatePeer(pubkeyHex)` | `Promise<void>` | Deactivate (revoke) a peer |
| `updatePeerKey({ oldPubkeyHex, newPubkeyHex })` | `Promise<void>` | Update peer key (re-keying) |
| `addRekeyEntry({ oldKeyHex, newKeyHex, timestamp })` | `Promise<void>` | Record re-key history |
| `getRekeyHistory(currentKeyHex)` | `Promise<object[]>` | Get re-key history for a key |

---

### `OutboxStore` (abstract)

> Abstract interface for outbox persistence.

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `addEntry(eventId)` | `Promise<void>` | Add an event to the outbox |
| `getReadyToSend()` | `Promise<object[]>` | Get entries ready for transmission |
| `markSent({ eventId, transport })` | `Promise<void>` | Mark an entry as sent |
| `markFailed({ eventId })` | `Promise<void>` | Mark an entry as failed (increments retry) |
| `pendingCount()` | `Promise<number>` | Count pending/failed entries |

---

### `SecureKeyStore` (abstract)

> Abstract interface for secure key storage.

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `storeKeyPair({ keyId, keyPair })` | `Promise<void>` | Store a key pair |
| `retrieveKeyPair(keyId)` | `Promise<StyxKeyPair\|null>` | Retrieve a key pair |
| `deleteKeyPair(keyId)` | `Promise<void>` | Delete a key pair |
| `hasKeyPair(keyId)` | `Promise<boolean>` | Check if a key pair exists |
| `storeSecret({ key, value })` | `Promise<void>` | Store a secret byte array |
| `retrieveSecret(key)` | `Promise<Uint8Array\|null>` | Retrieve a secret |
| `deleteSecret(key)` | `Promise<void>` | Delete a secret |
| `deleteAll()` | `Promise<void>` | Delete all stored keys and secrets |

---

### `MemoryLedgerStore`

> In-memory ledger store -- data is lost when the page/tab closes. Extends `LedgerStore`.

#### Constructor

```js
new MemoryLedgerStore()
```

No parameters. Initializes with an empty event list and zero vector clock.

#### Methods

Implements all `LedgerStore` methods. Events are kept sorted by HLC on every `appendEvent`. Vector clock is updated to component-wise max on each append.

---

### `MemoryPeerStore`

> In-memory peer store. Extends `PeerStore`.

#### Constructor

```js
new MemoryPeerStore()
```

No parameters.

#### Methods

Implements all `PeerStore` methods using an internal `Map`.

---

### `MemoryOutboxStore`

> In-memory outbox store with exponential backoff on failures. Extends `OutboxStore`.

#### Constructor

```js
new MemoryOutboxStore()
```

No parameters.

#### Methods

Implements all `OutboxStore` methods. On `markFailed`, applies exponential backoff: `min(100ms * 2^attempt, 5000ms)`.

---

### `MemoryKeyStore`

> In-memory secure key store. Extends `SecureKeyStore`.

#### Constructor

```js
new MemoryKeyStore()
```

No parameters.

#### Methods

Implements all `SecureKeyStore` methods using internal `Map`s for key pairs and secrets.

---

### `IndexedDBLedgerStore`

> IndexedDB-backed ledger store for persistent mode. Extends `LedgerStore`. Creates object stores with HLC and type indexes.

#### Constructor

```js
new IndexedDBLedgerStore(dbName?)
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| dbName | `string` | No | `'styx-ledger'` | Custom IndexedDB database name |

#### Methods

Implements all `LedgerStore` methods using IndexedDB transactions. Additionally:

##### `close()`

> Close the IndexedDB database connection.

```js
ledgerStore.close(): void
```

---

### `IndexedDBPeerStore`

> IndexedDB-backed peer store. Extends `PeerStore`.

#### Constructor

```js
new IndexedDBPeerStore(dbName?)
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| dbName | `string` | No | `'styx-ledger'` | Custom IndexedDB database name |

#### Methods

Implements all `PeerStore` methods. Re-key history is stored inline within the peer record.

---

### `IndexedDBKeyStore`

> IndexedDB-backed secure key store. Extends `SecureKeyStore`.

#### Constructor

```js
new IndexedDBKeyStore(dbName?)
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| dbName | `string` | No | `'styx-ledger'` | Custom IndexedDB database name |

#### Methods

Implements all `SecureKeyStore` methods. Key pairs are stored with `kp:` prefix, secrets with `sec:` prefix.

**Security note:** In production, key material stored in IndexedDB should be encrypted with the Web Crypto API (e.g., AES-GCM with a key derived from a user password).

---

## 8. API Reference -- transport

Module: `styx-js/transport`

### `TransportState`

> Enum of transport connection states.

| Value | Description |
|-------|-------------|
| `TransportState.DISCONNECTED` | Not connected |
| `TransportState.CONNECTING` | Connection in progress |
| `TransportState.CONNECTED` | Connected and ready to send/receive |

---

### `TransportMessage`

> A message exchanged between peers over the transport layer. Immutable.

#### Constructor

```js
new TransportMessage({ id, senderPubkey, recipientPubkey, payload, timestamp })
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| id | `string` | Yes | -- | Message identifier |
| senderPubkey | `string` | Yes | -- | Hex-encoded sender pubkey |
| recipientPubkey | `string` | Yes | -- | Hex-encoded recipient pubkey |
| payload | `Uint8Array` | Yes | -- | Message payload (encrypted) |
| timestamp | `Date` | No | `new Date()` | Message timestamp |

#### Properties

All constructor parameters are available as read-only properties.

#### Methods

##### `toJSON()`

> Serialize to JSON-compatible object.

```js
message.toJSON(): object
```

##### `TransportMessage.fromJSON(json)` (static)

> Deserialize from JSON object.

```js
TransportMessage.fromJSON(json): TransportMessage
```

---

### `TransportInterface` (abstract)

> Abstract interface for all transport implementations.

#### Properties

| Name | Type | Description |
|------|------|-------------|
| currentState | `string` | `TransportState` value (default: `DISCONNECTED`) |
| isAvailable | `boolean` | Whether this transport can be used in the current environment |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `onStateChange(callback)` | `() => void` | Subscribe to state changes; returns unsubscribe |
| `onMessage(callback)` | `() => void` | Subscribe to incoming messages; returns unsubscribe |
| `connect()` | `Promise<void>` | Establish connection |
| `disconnect()` | `Promise<void>` | Close connection |
| `send(message)` | `Promise<void>` | Send a `TransportMessage` |

---

### `RelayPool`

> Manages connections to multiple Nostr relays via WebSocket.

#### Constructor

```js
new RelayPool(relayUrls)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| relayUrls | `string[]` | Yes | WebSocket relay URLs (e.g., `['wss://relay.damus.io']`) |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| relayUrls | `string[]` | Copy of configured relay URLs |
| connectedCount | `number` | Number of currently connected relays |
| messages | `EventEmitter` | Internal event emitter for relay messages |

#### Methods

##### `connectAll()`

> Connect to all relays. Returns count of successful connections.

```js
await relayPool.connectAll(): Promise<number>
```

##### `disconnectAll()`

> Disconnect from all relays.

```js
await relayPool.disconnectAll(): Promise<void>
```

##### `publish(event)`

> Publish a Nostr event to all connected relays.

```js
relayPool.publish(event): number
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event | `object` | Yes | NIP-01 Nostr event object |

**Returns:** Count of relays reached.

##### `subscribe(subscriptionId, filter)`

> Subscribe to events on all connected relays.

```js
relayPool.subscribe(subscriptionId, filter): void
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| subscriptionId | `string` | Yes | Unique subscription identifier |
| filter | `object` | Yes | Nostr subscription filter (kinds, #p, etc.) |

##### `healthCheck()`

> Check connectivity status of all relays.

```js
relayPool.healthCheck(): Array<{ url: string, isConnected: boolean }>
```

##### `addRelay(url)`

> Add a relay URL to the pool. Does not connect automatically.

```js
relayPool.addRelay(url): void
```

##### `removeRelay(url)`

> Remove and disconnect a relay.

```js
await relayPool.removeRelay(url): Promise<void>
```

##### `dispose()`

> Disconnect all relays and clean up listeners.

```js
await relayPool.dispose(): Promise<void>
```

---

### `NostrTransport`

> Nostr relay transport implementing `TransportInterface`. Messages are encrypted with the provided encryptor before being sent as Nostr events (kind 30078), making them opaque to relays. Nostr event signing uses schnorr (secp256k1) per NIP-01.

#### Constructor

```js
new NostrTransport(relayPool, encryptor, localPubkey, peerPubkey, nostrSecretKey?, subscriptionTag?)
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| relayPool | `RelayPool` | Yes | -- | Pool of Nostr relays |
| encryptor | `StyxEncryptor` | Yes | -- | ChaCha20-Poly1305 encryptor |
| localPubkey | `string` | Yes | -- | Hex pubkey for the Nostr event `pubkey` field (secp256k1) |
| peerPubkey | `string` | Yes | -- | Hex pubkey for outgoing p-tags (Ed25519) |
| nostrSecretKey | `Uint8Array` | No | `null` | 32-byte secp256k1 private key for NIP-01 schnorr signing |
| subscriptionTag | `string` | No | `localPubkey` | Hex tag for incoming p-tag subscription filter (Ed25519) |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| currentState | `string` | `TransportState` value |
| isAvailable | `boolean` | `true` if `WebSocket` is available |

#### Methods

##### `connect()`

> Connect to relays and subscribe to p-tagged events with kind 30078.

```js
await nostrTransport.connect(): Promise<void>
```

**Throws:** `Error` if no relay could be reached.

##### `disconnect()`

> Unsubscribe and disconnect.

```js
await nostrTransport.disconnect(): Promise<void>
```

##### `send(message)`

> Encrypt and publish a TransportMessage as a Nostr event. The payload is encrypted with ChaCha20-Poly1305, Base64-encoded into the `content` field, and signed with schnorr.

```js
await nostrTransport.send(message): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| message | `TransportMessage` | Yes | Message to send |

**Throws:** `Error` if not connected.

##### `dispose()`

> Disconnect and clean up all listeners.

```js
await nostrTransport.dispose(): Promise<void>
```

##### `onStateChange(callback)`

> Subscribe to state change events.

```js
const unsubscribe = nostrTransport.onStateChange(callback): () => void
```

##### `onMessage(callback)`

> Subscribe to incoming decrypted messages.

```js
const unsubscribe = nostrTransport.onMessage(callback): () => void
```

---

### `WebRTCTransport`

> WebRTC DataChannel transport for direct P2P communication. Requires a signaling channel to exchange SDP offers/answers and ICE candidates. After the DataChannel is established, all data flows directly peer-to-peer.

#### Constructor

```js
new WebRTCTransport({ sendSignal, iceConfig?, localPubkey, peerPubkey })
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| sendSignal | `function(object): void` | Yes | -- | Callback to send signaling data to peer |
| iceConfig | `RTCConfiguration` | No | Google STUN servers | Custom ICE configuration |
| localPubkey | `string` | Yes | -- | Local hex pubkey |
| peerPubkey | `string` | Yes | -- | Peer hex pubkey |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| currentState | `string` | `TransportState` value |
| isAvailable | `boolean` | `true` if `RTCPeerConnection` is available |

#### Methods

##### `connect()`

> Initiate a WebRTC connection (caller/offerer role). Creates a DataChannel named `"styx"` with the `"styx-v1"` protocol, generates an SDP offer, and sends it via `sendSignal`.

```js
await webrtcTransport.connect(): Promise<void>
```

**Throws:** `Error` if WebRTC is not available.

##### `handleSignal(signal)`

> Process incoming signaling data from the peer. Handles offers (creates answer), answers (sets remote description), and ICE candidates.

```js
await webrtcTransport.handleSignal(signal): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| signal | `object` | Yes | `{ type: 'offer'\|'answer'\|'candidate', sdp?, candidate? }` |

##### `disconnect()`

> Close the DataChannel and PeerConnection.

```js
await webrtcTransport.disconnect(): Promise<void>
```

##### `send(message)`

> Send a TransportMessage over the DataChannel as JSON.

```js
await webrtcTransport.send(message): Promise<void>
```

**Throws:** `Error` if DataChannel is not connected.

##### `onStateChange(callback)`

> Subscribe to state change events.

```js
const unsubscribe = webrtcTransport.onStateChange(callback): () => void
```

##### `onMessage(callback)`

> Subscribe to incoming messages.

```js
const unsubscribe = webrtcTransport.onMessage(callback): () => void
```

---

### `TransportPriority`

> Associates a transport with its retry and timeout policy.

#### Constructor

```js
new TransportPriority(transport, maxRetries, timeoutMs)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| transport | `TransportInterface` | Yes | Transport implementation |
| maxRetries | `number` | Yes | Maximum retry attempts per send |
| timeoutMs | `number` | Yes | Timeout per send attempt in milliseconds |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| transport | `TransportInterface` | Transport implementation |
| maxRetries | `number` | Maximum retry attempts |
| timeoutMs | `number` | Timeout per attempt |

---

### `TransportFailover`

> Multi-transport failover engine. Tries transports in priority order with retry and exponential backoff. Extends `TransportInterface`.

#### Constructor

```js
new TransportFailover(transports)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| transports | `TransportPriority[]` | Yes | Transports ordered by priority (highest first) |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| currentState | `string` | `TransportState` value |
| isAvailable | `boolean` | `true` if any transport is available |
| anyAvailable | `boolean` | Alias for `isAvailable` |
| activeTransportName | `string\|null` | Constructor name of the active transport, or `null` |

#### Methods

##### `connect()`

> Connect using the highest-priority available transport. If it fails, tries the next one.

```js
await failover.connect(): Promise<void>
```

**Throws:** `TransportFailoverException` if all transports fail.

##### `disconnect()`

> Disconnect all transports and clean up handlers.

```js
await failover.disconnect(): Promise<void>
```

##### `send(message)`

> Send with retry across transports. Applies exponential backoff between retries: `min(100ms * 2^attempt, 5000ms)`.

```js
await failover.send(message): Promise<void>
```

**Throws:** `TransportFailoverException` if all transports fail to send.

##### `dispose()`

> Disconnect and clean up all listeners.

```js
await failover.dispose(): Promise<void>
```

##### `onStateChange(callback)`

> Subscribe to state change events.

```js
const unsubscribe = failover.onStateChange(callback): () => void
```

##### `onMessage(callback)`

> Subscribe to incoming messages from the active transport.

```js
const unsubscribe = failover.onMessage(callback): () => void
```

---

### `TransportFailoverException`

> Error thrown when all transports fail.

```js
class TransportFailoverException extends Error
```

---

### `OutboxWorker`

> Processes the outbox queue in causal (HLC) order, sending events through the failover transport.

#### Constructor

```js
new OutboxWorker({ outboxStore, ledgerStore, transport, encryptor, localPubkey, peerPubkey })
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| outboxStore | `OutboxStore` | Yes | Outbox persistence |
| ledgerStore | `LedgerStore` | Yes | Ledger persistence (to look up events) |
| transport | `TransportFailover` | Yes | Transport for sending |
| encryptor | `StyxEncryptor` | Yes | Encryptor (unused directly; transport handles encryption) |
| localPubkey | `string` | Yes | Local hex pubkey |
| peerPubkey | `string` | Yes | Peer hex pubkey |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| isRunning | `boolean` | Whether the worker loop is active |
| sentCount | `number` | Total events successfully sent |
| failedCount | `number` | Total send failures |
| pendingCount | `Promise<number>` | Number of pending/failed entries |

#### Methods

##### `start()`

> Start the worker loop. Continuously processes batches, sleeping 1 second when idle.

```js
await outboxWorker.start(): Promise<void>
```

**Note:** This runs indefinitely until `stop()` is called.

##### `stop()`

> Stop the worker loop.

```js
outboxWorker.stop(): void
```

##### `processNow()`

> Force immediate processing of one batch.

```js
await outboxWorker.processNow(): Promise<number>
```

**Returns:** Number of events processed.

##### `processBatch()`

> Process one batch of ready-to-send events.

```js
await outboxWorker.processBatch(): Promise<number>
```

**Returns:** Number of events processed.

---

## 9. API Reference -- pairing

Module: `styx-js` (exported from `pairing/trust-store.js`)

### `TrustStoreManager`

> Manages the trust store of paired peers with re-keying history.

#### Constructor

```js
new TrustStoreManager(peerStore)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| peerStore | `PeerStore` | Yes | Peer persistence layer |

#### Methods

##### `addTrustedPeer(peerPublicKey, alias)`

> Add a peer to the trust store.

```js
await trustStore.addTrustedPeer(peerPublicKey, alias): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| peerPublicKey | `StyxPublicKey` | Yes | Peer's Ed25519 public key |
| alias | `string` | Yes | Human-readable alias |

##### `revokePeer(peerPublicKey)`

> Deactivate a trusted peer.

```js
await trustStore.revokePeer(peerPublicKey): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| peerPublicKey | `StyxPublicKey` | Yes | Peer's public key |

##### `isTrusted(publicKey)`

> Check if a public key belongs to an active trusted peer.

```js
await trustStore.isTrusted(publicKey): Promise<boolean>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| publicKey | `StyxPublicKey` | Yes | Public key to check |

##### `getActivePeer()`

> Get the first active trusted peer, or `null`.

```js
await trustStore.getActivePeer(): Promise<object|null>
```

##### `updatePeerKey(oldKey, newKey)`

> Update a peer's public key during re-keying. Records re-key history.

```js
await trustStore.updatePeerKey(oldKey, newKey): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| oldKey | `StyxPublicKey` | Yes | Previous public key |
| newKey | `StyxPublicKey` | Yes | New public key |

##### `getRekeyHistory(currentKey)`

> Get the re-key history for a public key.

```js
await trustStore.getRekeyHistory(currentKey): Promise<object[]>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| currentKey | `StyxPublicKey` | Yes | Current public key |

---

### `QrPairingData`

> QR pairing data container.

#### Constructor

```js
new QrPairingData(publicKey, nonce, relayHints?)
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| publicKey | `StyxPublicKey` | Yes | -- | Local Ed25519 public key |
| nonce | `Uint8Array` | Yes | -- | 16-byte anti-replay nonce |
| relayHints | `string[]` | No | `[]` | Relay URL hints for the peer |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| publicKey | `StyxPublicKey` | Local public key |
| nonce | `Uint8Array` | 16-byte nonce |
| relayHints | `string[]` | Relay URL hints |
| estimatedBytes | `number` | Approximate payload size in bytes |

#### Methods

##### `toQrPayload()`

> Serialize to JSON string for QR encoding. Compatible with Dart implementation.

```js
qrData.toQrPayload(): string
```

**Returns:** JSON string: `{"pk":"<hex>","n":"<base64>","r":["wss://..."]}`.

##### `QrPairingData.fromQrPayload(payload)` (static)

> Deserialize from a JSON QR payload.

```js
QrPairingData.fromQrPayload(payload): QrPairingData
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| payload | `string` | Yes | JSON string from QR scanner |

**Throws:** `Error` if payload is missing `pk` or `n` fields.

---

### `QrPairingService`

> QR-based pairing protocol with nonce anti-replay.

#### Constructor

```js
new QrPairingService(trustStore)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| trustStore | `TrustStoreManager` | Yes | Trust store for persisting peers |

#### Methods

##### `generateQrData(localPublicKey, relayHints)`

> Generate QR data with a fresh 16-byte nonce.

```js
qrService.generateQrData(localPublicKey, relayHints): QrPairingData
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| localPublicKey | `StyxPublicKey` | Yes | Local Ed25519 public key |
| relayHints | `string[]` | Yes | Relay URLs to include as hints |

##### `processScannedQr(qrPayload, localPublicKey)`

> Validate a scanned QR payload. Prevents self-pairing.

```js
qrService.processScannedQr(qrPayload, localPublicKey): object
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| qrPayload | `string` | Yes | Raw JSON string from QR scanner |
| localPublicKey | `StyxPublicKey` | Yes | Local public key (for self-pairing check) |

**Returns:** `{ isValid, peerPublicKey, relayHints, errorMessage }`.

##### `completePairing(peerPublicKey, peerAlias)`

> Complete the pairing by persisting the peer in the trust store.

```js
await qrService.completePairing(peerPublicKey, peerAlias): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| peerPublicKey | `StyxPublicKey` | Yes | Peer's public key |
| peerAlias | `string` | Yes | Human-readable alias |

---

### `RemotePairingState`

> Enum of remote pairing states.

| Value | Description |
|-------|-------------|
| `RemotePairingState.IDLE` | Not started |
| `RemotePairingState.MNEMONIC_GENERATED` | Mnemonic created |
| `RemotePairingState.WAITING_FOR_PEER` | SPAKE2 message sent, waiting for peer |
| `RemotePairingState.SPAKE2_IN_PROGRESS` | Processing peer's SPAKE2 message |
| `RemotePairingState.DOUBLE_CHECK_PENDING` | Session key derived, awaiting user verification |
| `RemotePairingState.COMPLETED` | Pairing completed successfully |
| `RemotePairingState.FAILED` | Pairing failed |

---

### `RemotePairingService`

> Remote pairing service: mnemonic -> SPAKE2 -> Double Check -> trust store.

#### Constructor

```js
new RemotePairingService({ spake2Protocol, mnemonicGenerator, doubleCheckVerifier, trustStore, timeoutMs? })
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| spake2Protocol | `Spake2Protocol` | Yes | -- | SPAKE2 session factory |
| mnemonicGenerator | `MnemonicGenerator` | Yes | -- | Mnemonic generator |
| doubleCheckVerifier | `DoubleCheckVerifier` | Yes | -- | Double Check code verifier |
| trustStore | `TrustStoreManager` | Yes | -- | Trust store for persisting peers |
| timeoutMs | `number` | No | `undefined` | Optional timeout for the protocol |

#### Properties

| Name | Type | Description |
|------|------|-------------|
| state | `string` | Current `RemotePairingState` value |
| stateStream | `EventEmitter` | Emits `'stateChange'` events |
| peerPublicKey | `StyxPublicKey\|null` | Peer's public key after completion |

#### Methods

##### `generateMnemonic(wordCount)`

> Generate a BIP-39 mnemonic for out-of-band sharing.

```js
remotePairing.generateMnemonic(wordCount?): string
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| wordCount | `number` | No | `6` | Number of words |

##### `startAsInitiator(mnemonic, localPublicKey)`

> Start SPAKE2 as the initiator. Returns the SPAKE2 message to send to the peer.

```js
remotePairing.startAsInitiator(mnemonic, localPublicKey): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| mnemonic | `string` | Yes | BIP-39 mnemonic |
| localPublicKey | `StyxPublicKey` | Yes | Local public key |

**Returns:** 65-byte uncompressed P-256 point (SPAKE2 message).

##### `startAsResponder(mnemonic, localPublicKey)`

> Start SPAKE2 as the responder. Returns the SPAKE2 message to send to the peer.

```js
remotePairing.startAsResponder(mnemonic, localPublicKey): Uint8Array
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| mnemonic | `string` | Yes | BIP-39 mnemonic |
| localPublicKey | `StyxPublicKey` | Yes | Local public key |

##### `processPeerMessage(peerMessage)`

> Process the peer's SPAKE2 message. On success, transitions to `doubleCheckPending`.

```js
remotePairing.processPeerMessage(peerMessage): boolean
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| peerMessage | `Uint8Array` | Yes | 65-byte SPAKE2 message from the peer |

**Returns:** `true` on success, `false` on failure (state transitions to `failed`).

##### `getDoubleCheckCode()`

> Get the formatted 6-digit Double Check code (e.g., `"483 291"`).

```js
remotePairing.getDoubleCheckCode(): string
```

##### `confirmDoubleCheck(codeMatches, peerPublicKey, peerAlias)`

> Confirm or reject pairing based on Double Check code comparison.

```js
await remotePairing.confirmDoubleCheck(codeMatches, peerPublicKey, peerAlias): Promise<void>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| codeMatches | `boolean` | Yes | Whether codes matched |
| peerPublicKey | `StyxPublicKey` | Yes | Peer's public key |
| peerAlias | `string` | Yes | Human-readable alias |

##### `RemotePairingService.deriveSharedTag(mnemonic)` (static)

> Derive a 16-character hex discovery tag from the mnemonic. Used for peer discovery on relays.

```js
RemotePairingService.deriveSharedTag(mnemonic): string
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| mnemonic | `string` | Yes | BIP-39 mnemonic |

**Returns:** 16-character hex string derived via `SHA-256("styx-pairing-tag:" + normalized_mnemonic)`.

##### `cancel()`

> Cancel the pairing and destroy the SPAKE2 session.

```js
remotePairing.cancel(): void
```

##### `dispose()`

> Destroy the SPAKE2 session and clean up listeners.

```js
remotePairing.dispose(): void
```

---

## 10. Dart <-> JS Interoperability

Styx.js is designed to be wire-compatible with the Dart Styx library. Two peers can communicate across platforms (e.g., a Flutter mobile app paired with a browser-based web app) as long as the following parameters are aligned.

### Compatibility Matrix

| Area | Dart | JS | Compatible |
|------|------|----|------------|
| Ed25519 key format | 32-byte raw | 32-byte raw | Yes |
| Ed25519 signatures | 64-byte raw | 64-byte raw | Yes |
| SHA-256 hashing | `package:crypto` | `@noble/hashes` | Yes |
| ChaCha20-Poly1305 nonce | 12 bytes | 12 bytes | Yes |
| ChaCha20-Poly1305 wire format | `nonce(12) \|\| ciphertext \|\| tag(16)` | `nonce(12) \|\| ciphertext \|\| tag(16)` | Yes |
| HKDF info strings | `styx-send-`, `styx-recv-` | `styx-send-`, `styx-recv-` | Yes |
| Directional key derivation | Lexicographic pubkey comparison | Lexicographic pubkey comparison | Yes |
| SPAKE2 curve | P-256 | P-256 | Yes |
| SPAKE2 point format | Uncompressed (65 bytes) | Uncompressed (65 bytes) | Yes |
| SPAKE2 M point | RFC 9382 | RFC 9382 | Yes |
| SPAKE2 N point | RFC 9382 | RFC 9382 | Yes |
| SPAKE2 transcript | `SHA-256(pA \|\| pB \|\| K)` | `SHA-256(pA \|\| pB \|\| K)` | Yes |
| Double Check derivation | `SHA-256(key \|\| "styx-double-check-v1")` | `SHA-256(key \|\| "styx-double-check-v1")` | Yes |
| Double Check format | 6-digit, `num % 1000000` | 6-digit, `num % 1000000` | Yes |
| Shamir GF(256) polynomial | `x^8 + x^4 + x^3 + x + 1` (0x11B) | `x^8 + x^4 + x^3 + x + 1` (0x11B) | Yes |
| Shamir share format | `styx-share-v1:{idx}:{b64}` | `styx-share-v1:{idx}:{b64}` | Yes |
| HLC canonical format | `ISO8601Z-{counter}-{nodeId}` | `ISO8601Z-{counter}-{nodeId}` | Yes |
| HLC counter encoding | Decimal, zero-padded to 4 | Decimal, zero-padded to 4 | Yes |
| Vector clock JSON | `{ "a": N, "b": N }` | `{ "a": N, "b": N }` | Yes |
| Vector clock bytes | 8 bytes big-endian | 8 bytes big-endian | Yes |
| Event hash | `SHA-256(prevHash \|\| type \|\| payload \|\| hlcBytes)` | `SHA-256(prevHash \|\| type \|\| payload \|\| hlcBytes)` | Yes |
| QR payload format | `{"pk":"hex","n":"b64","r":[...]}` | `{"pk":"hex","n":"b64","r":[...]}` | Yes |
| Merge ordering | VC total, then pubkey lexicographic | VC total, then pubkey lexicographic | Yes |
| BIP-39 wordlist | English 2048 | English 2048 | Yes |
| Nostr event kind | 30078 | 30078 | Yes |

### Key Alignment Parameters

These parameters MUST match exactly between Dart and JS for cross-platform operation:

1. **ChaCha20-Poly1305 nonce**: Always 12 bytes. The wire format is `nonce(12) || ciphertext || tag(16)`.

2. **SPAKE2 uncompressed points**: Both implementations use uncompressed P-256 points (65 bytes: `04 || x || y`). Compressed points will cause protocol failure.

3. **Shamir share format**: `styx-share-v1:{1-based index}:{standard base64 data}`. The index is always 1-based (1-255).

4. **HLC counter encoding**: The counter is a decimal integer (NOT hex), zero-padded to 4 characters. Example: `2026-03-21T10:30:00.000Z-0042-a1b2c3d4`.

5. **HKDF info strings**: The directional key derivation uses `styx-send-` and `styx-recv-` prefixed to the concatenated sorted pubkeys. The pubkey comparison is byte-by-byte lexicographic.

6. **SPAKE2 confirmation**: The confirmation key is `SHA-256(sessionKey || "styx-spake2-confirm")`, and the confirmation HMAC is over `roleByte || ourMessage || peerMessage`.

### Generating Cross-Platform Test Vectors

To verify interoperability, generate test vectors from one platform and verify on the other:

```js
import {
  IdentityManager, Hasher, Signer, Verifier,
  KeyConverter, DiffieHellman, KeyDerivation,
  StyxEncryptor, bytesToHex, hexToBytes,
} from 'styx-js';

// 1. Generate a keypair and export as hex
const im = new IdentityManager();
const kp = await im.generate();
console.log('Private:', bytesToHex(kp.privateKey.bytes));
console.log('Public:', kp.publicKey.toHex());

// 2. Sign and verify
const signer = new Signer();
const payload = new TextEncoder().encode('test payload');
const sig = await signer.sign(payload, kp.privateKey);
console.log('Signature:', bytesToHex(sig));

// 3. Hash
const hasher = new Hasher();
const hash = hasher.hash(payload);
console.log('SHA-256:', bytesToHex(hash));

// 4. DH + encryption round-trip
const kc = new KeyConverter();
const dh = new DiffieHellman();
const kd = new KeyDerivation();

const kp2 = await im.generate();
const priv1x = kc.ed25519PrivateToX25519(kp.privateKey);
const pub2x = kc.ed25519PublicToX25519(kp2.publicKey);
const shared = dh.computeSharedSecret(priv1x, pub2x);

const keys = kd.deriveDirectionalKeys(shared, kp.publicKey.bytes, kp2.publicKey.bytes);
console.log('Send key:', bytesToHex(keys.sendKey));
console.log('Recv key:', bytesToHex(keys.receiveKey));

const enc = new StyxEncryptor(keys.sendKey, keys.receiveKey);
const ciphertext = enc.encrypt(payload);
console.log('Ciphertext:', bytesToHex(ciphertext));
// Share ciphertext hex with Dart side for decryption verification

// 5. Shamir round-trip
import { KeyBackup, ShamirShare } from 'styx-js';
const kb = new KeyBackup();
const shares = kb.backupPrivateKey(kp.privateKey, 2, 3);
console.log('Shares:', shares.map(s => s.serialize()));
// Share serialized strings with Dart side for reconstruction verification
```

---

## 11. Glossary

| Term | Definition |
|------|------------|
| **Affidante** | One of the two peers in a Styx ledger pair. The term is Italian for "trustor" -- the person who entrusts data to the other. |
| **Custode** | The other peer in a Styx ledger pair. Italian for "guardian" -- the person who safeguards the shared data. |
| **BIP-39** | Bitcoin Improvement Proposal 39. A standard for generating mnemonic phrases from a wordlist of 2048 English words. Styx uses 6-word mnemonics for remote pairing. |
| **ChaCha20-Poly1305** | An AEAD (Authenticated Encryption with Associated Data) cipher. ChaCha20 provides confidentiality; Poly1305 provides integrity. 12-byte nonce, 16-byte authentication tag. |
| **Double Check** | A 6-digit verification code derived from the SPAKE2 session key. Users compare codes verbally to confirm they completed SPAKE2 with the correct peer. |
| **Ed25519** | An elliptic curve digital signature algorithm using the Edwards curve Curve25519. Produces 32-byte public keys and 64-byte signatures. |
| **EventType** | Category of a ledger event: `transaction`, `message`, `sos`, `config`, `rekey`, `merge`, `pruneRequest`, `pruneAck`. |
| **Fork** | When two peers create events concurrently from the same chain head, producing divergent branches. Resolved by deterministic merge. |
| **GF(256)** | Galois Field with 256 elements. The finite field used by Shamir's Secret Sharing for byte-level polynomial arithmetic. |
| **Genesis Event** | The first event in the hash chain. Has `previousHash: null` and `VectorClock(0, 0)`. Type is `config`. |
| **HKDF** | HMAC-based Key Derivation Function (RFC 5869). Extracts and expands key material from a shared secret. |
| **HLC** | Hybrid Logical Clock. Combines wall-clock time with a logical counter and node ID to provide monotonic, globally-unique timestamps. |
| **Merge Event** | A special event (`type: 'merge'`) appended to linearize forked branches. Contains hashes of both branch tips and the common ancestor. |
| **Mnemonic** | A sequence of BIP-39 words used for remote pairing. Default length is 6 words. Converted to SPAKE2 password via UTF-8 encoding. |
| **NIP-01** | Nostr Implementation Possibility 01. The basic protocol for Nostr events: id (SHA-256), pubkey, created_at, kind, tags, content, sig (schnorr). |
| **Node ID** | First 8 hex characters of a peer's Ed25519 public key. Used as the HLC node identifier. |
| **Nostr** | "Notes and Other Stuff Transmitted by Relays." A decentralized relay-based protocol. Styx uses Nostr relays as a transport layer with kind 30078 events. |
| **P-256** | NIST P-256 elliptic curve (also called secp256r1 or prime256v1). Used for SPAKE2 in Styx. |
| **Peer Role** | `A` or `B`, determined by lexicographic ordering of Ed25519 public keys. The peer with the smaller key is `A`. Affects vector clock increment and directional key assignment. |
| **Pruning** | GDPR-compliant deletion of event payloads. Bilateral (requires peer ACK) or unilateral (GDPR Art. 17, immediate). Preserves hash chain integrity. |
| **REKEY** | The process of migrating identity to a new device. The old device signs a "blessing" event containing the new public key. |
| **schnorr** | Schnorr signature scheme over secp256k1. Used for NIP-01 Nostr event signing (distinct from Ed25519 used for Styx events). |
| **secp256k1** | The elliptic curve used by Bitcoin and Nostr. Styx derives a secp256k1 keypair from Ed25519 keys via HKDF for Nostr compatibility. |
| **Shamir's Secret Sharing** | A (t, n) threshold secret sharing scheme. A secret is split into n shares such that any t shares can reconstruct it, but t-1 shares reveal nothing. |
| **SPAKE2** | Simple Password-Authenticated Key Exchange. Allows two parties sharing a password to establish a session key, resistant to offline dictionary attacks. |
| **Vector Clock** | A mechanism for tracking causality in distributed systems. Styx uses a 2-element clock `(a, b)` for its 2-peer system. |
| **WebRTC** | Web Real-Time Communication. Enables direct browser-to-browser data transfer via DataChannels after ICE/STUN/TURN negotiation. |
| **X25519** | Diffie-Hellman key agreement using Curve25519 in Montgomery form. Styx converts Ed25519 keys to X25519 for shared secret derivation. |

---

*Generated from styx-js v1.0.0 source code. Last updated: 2026-03-21.*
