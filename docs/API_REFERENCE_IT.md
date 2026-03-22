# Styx — Riferimento API

Documentazione API completa per la libreria Styx — ledger crittografici sovrani, peer-to-peer, con architettura zero-server.

---

## Indice

1. [Introduzione](#1-introduzione)
2. [Guida Rapida](#2-guida-rapida)
3. [Casi d'Uso](#3-casi-duso)
4. [Riferimento API — styx (facciata)](#4-riferimento-api--styx-facciata)
5. [Riferimento API — crypto_core](#5-riferimento-api--crypto_core)
6. [Riferimento API — ledger_engine](#6-riferimento-api--ledger_engine)
7. [Riferimento API — transport](#7-riferimento-api--transport)
8. [Riferimento API — push_bridge_client](#8-riferimento-api--push_bridge_client)
9. [Riferimento API — push_bridge_server (REST)](#9-riferimento-api--push_bridge_server-rest)
10. [Glossario](#10-glossario)

---

## 1. Introduzione

### Cos'è Styx

Styx è una libreria Dart/Flutter per costruire ledger crittografici sovrani, peer-to-peer. Due peer — chiamati **Affidante** e **Custode** — mantengono una catena di eventi condivisa e a prova di manomissione senza alcun server centrale. Ogni evento è firmato con Ed25519, concatenato tramite hash con SHA-256 e ordinato causalmente tramite vector clock.

### Architettura a Livelli

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

### Flusso Tipico

1. **Generare identità** — coppia di chiavi Ed25519 tramite `IdentityManager`.
2. **Pairing** — Scambio di chiavi pubbliche tramite codice QR (locale) o mnemonica BIP-39 (remoto).
3. **Scambio eventi** — Aggiungere eventi firmati alla catena di hash, sincronizzazione tramite relay Nostr.
4. **Risolvere fork** — Merge deterministico quando i peer producono eventi concorrenti.
5. **Pruning** — Cancellazione del payload bilaterale o unilaterale conforme al GDPR.

---

## 2. Guida Rapida

### Installazione

Aggiungere al proprio `pubspec.yaml`:

```yaml
dependencies:
  styx:
    path: packages/styx
```

Tutte le dipendenze transitive (`crypto_core`, `ledger_engine`, `transport`, `push_bridge_client`) vengono risolte automaticamente tramite il monorepo Melos.

### Inizializzazione Minima

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

### Primo Evento

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

## 3. Casi d'Uso

### 3.1 Pairing QR tra Due Dispositivi

**Scenario:** Due utenti si trovano fisicamente nello stesso luogo. Il dispositivo A mostra un codice QR; il dispositivo B lo scansiona.

**Prerequisiti:** Entrambi i dispositivi hanno inizializzato `SovereignLedger` nello stato `unpaired`.

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

**Note:**
- Il payload QR è di circa 80–120 byte (chiave pubblica codificata in Base64 + nonce + suggerimenti relay).
- I nonce scadono dopo 5 minuti. Vengono tracciati al massimo 100 nonce recenti per la protezione anti-replay.
- Dopo il pairing, l'assegnazione del ruolo del peer (`A` o `B`) è determinata dall'ordinamento lessicografico delle chiavi pubbliche.

### 3.2 Pairing Remoto tramite Mnemonica

**Scenario:** Due utenti non si trovano fisicamente nello stesso luogo. Condividono una mnemonica BIP-39 fuori banda (ad es. per telefono) e completano lo scambio di chiavi SPAKE2 con verifica Double Check.

**Prerequisiti:** Entrambi i dispositivi hanno inizializzato `SovereignLedger` nello stato `unpaired`.

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

**Note:**
- La lunghezza predefinita della mnemonica è di 6 parole (dalla wordlist inglese BIP-39).
- SPAKE2 utilizza la curva NIST P-256 (Dart puro, nessun FFI).
- Il codice Double Check è derivato dalla chiave di sessione SPAKE2 tramite troncamento SHA-256 a 6 cifre decimali.
- Flusso degli stati: `idle → mnemonicGenerated → waitingForPeer → spake2InProgress → doubleCheckPending → completed`.

### 3.3 Invio e Ricezione di Transazioni

**Scenario:** Due peer accoppiati scambiano eventi firmati sul ledger condiviso.

**Prerequisiti:** Entrambi i dispositivi sono accoppiati (`StyxState.ready`).

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

**Note:**
- Ogni evento include: hash precedente, vector clock, timestamp HLC, payload, chiave pubblica del mittente e firma Ed25519.
- Gli eventi vengono consegnati in ordine causale tramite la coda outbox.

### 3.4 Gestione SOS

**Scenario:** Un utente invia un segnale di emergenza al proprio peer.

**Prerequisiti:** Stato accoppiato.

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

### 3.5 Pruning GDPR (Bilaterale e Unilaterale)

**Scenario:** Un utente desidera eliminare il payload di uno specifico evento dal ledger preservando l'integrità della catena di hash.

**Prerequisiti:** Stato accoppiato con eventi esistenti.

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

**Note:**
- Il pruning annulla il campo `payload` ma preserva l'hash dell'evento, mantenendo l'integrità della catena.
- Il pruning bilaterale richiede sia l'evento `PRUNE_REQUEST` che `PRUNE_ACK` prima dell'esecuzione.
- Il pruning unilaterale (GDPR Art. 17) viene eseguito immediatamente senza conferma del peer.

### 3.6 Policy di Retention Automatica

**Scenario:** Identificare automaticamente gli eventi che superano un periodo di retention temporale.

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

**Note:**
- Solo gli eventi dei tipi elencati in `retentionTypes` vengono valutati.
- Gli eventi già sottoposti a pruning sono esclusi dai risultati.

### 3.7 Re-Keying (Cambio Dispositivo)

**Scenario:** Un utente cambia telefono e deve migrare la propria identità.

**Prerequisiti:** Accesso al vecchio dispositivo (o share di backup Shamir).

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

**Note:**
- L'evento REKEY è firmato dalla vecchia chiave privata e contiene la nuova chiave pubblica nel suo payload.
- Il peer deve verificare la firma del blessing prima di accettare la nuova chiave.
- Stati: `idle → newKeyGenerated → blessingCreated → blessingSent → waitingPeerAck → syncingHistory → completed`.

### 3.8 Backup e Ripristino dell'Identità (Shamir)

**Scenario:** Un utente crea un backup della propria chiave privata utilizzando lo schema di condivisione del segreto di Shamir, suddividendola in più share che possono essere distribuite a parti fidate.

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

**Note:**
- La suddivisione Shamir utilizza l'aritmetica GF(256) (Campo di Galois).
- Le share sono serializzate come stringhe Base64 con metadati dell'indice incorporati.
- La soglia è il numero minimo di share necessarie per la ricostruzione.
- Dopo il ripristino, il `ShamirBackupService` verifica la chiave ricostruita riderivando la chiave pubblica e controllando la corrispondenza.

### 3.9 Profili di Privacy per le Notifiche Push

**Scenario:** Configurare il comportamento delle notifiche push per bilanciare tra durata della batteria e privacy dei metadati.

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

**Note:**
- Le notifiche dummy contengono `{"d": "1"}` nel payload dei dati.
- La classe `DummyDetector` ispeziona questo campo.
- Le modifiche al profilo hanno effetto alla successiva registrazione al push bridge.

### 3.10 Sincronizzazione Offline e Merge

**Scenario:** Entrambi i peer creano eventi mentre sono offline. Quando si riconnettono, il fork deve essere risolto in modo deterministico.

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

**Note:**
- Entrambi i peer applicano la stessa regola di ordinamento deterministico, garantendo la convergenza senza comunicazione aggiuntiva.
- Il payload dell'evento MERGE contiene gli hash di entrambi i tip dei rami e l'antenato comune.

### 3.11 Validazione della Catena

**Scenario:** Verificare l'integrità dell'intera catena di eventi.

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

## 4. Riferimento API — styx (facciata)

Package: `package:styx/styx.dart`

### `SovereignLedger`

> Punto di accesso principale della libreria Styx. Gestisce il ciclo di vita di identità, pairing, scambio eventi, privacy e migrazione dispositivo.

#### Costruttore

```dart
SovereignLedger({
  required LedgerConfig config,
  required LedgerStore ledgerStore,
  PushBridgeRegistrar? pushBridgeRegistrar,
})
```

| Parametro | Tipo | Obbligatorio | Default | Descrizione |
|-----------|------|--------------|---------|-------------|
| config | `LedgerConfig` | Sì | — | Configurazione del ledger (relay, privacy, retention) |
| ledgerStore | `LedgerStore` | Sì | — | Livello di persistenza per la catena di eventi |
| pushBridgeRegistrar | `PushBridgeRegistrar?` | No | `null` | Bridge opzionale per notifiche push |

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| state | `StyxState` | Stato corrente del ledger |
| identity | `StyxIdentity?` | Identità locale (disponibile dopo l'inizializzazione) |
| eventStream | `LedgerEventStream` | Stream reattivo di eventi locali e remoti |

#### Metodi

##### `initialize()`

> Inizializza il ledger: genera o carica l'identità, configura la crittografia, connette il trasporto.

```dart
Future<void> initialize()
```

**Ritorna:** Completa quando l'inizializzazione è terminata. Lo stato transisce a `unpaired` o `ready`.

##### `shutdown()`

> Arresta in modo controllato tutti i sottosistemi.

```dart
Future<void> shutdown()
```

##### `generatePairingQr()`

> Genera i dati di pairing QR contenenti la chiave pubblica locale, un nonce fresco e suggerimenti relay opzionali.

```dart
Future<QrPairingData> generatePairingQr()
```

**Ritorna:** `QrPairingData` — codificare tramite `toQrPayload()` per la visualizzazione.

##### `processPairingQr(String qrPayload)`

> Elabora un payload QR scansionato, valida il formato e il nonce anti-replay.

```dart
Future<PairingResult> processPairingQr(String qrPayload)
```

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| qrPayload | `String` | Sì | Stringa grezza dallo scanner QR |

**Ritorna:** `PairingResult` con `isValid`, `peerPublicKey`, `relayHints`, `errorMessage`.

##### `startRemotePairing({String? existingMnemonic})`

> Avvia il pairing remoto. Se non viene fornita una mnemonica, ne genera una (ruolo iniziatore). Se viene fornita una mnemonica, si unisce come risponditore.

```dart
Future<String> startRemotePairing({String? existingMnemonic})
```

**Ritorna:** La mnemonica BIP-39 (nuova o esistente).

##### `getDoubleCheckCode()`

> Restituisce il codice di verifica Double Check a 6 cifre dopo il completamento di SPAKE2.

```dart
Future<String> getDoubleCheckCode()
```

**Ritorna:** Stringa di codice formattata, ad es. `"483 291"`.

##### `confirmPairing({String? peerAlias})`

> Conferma il pairing dopo la scansione QR o la verifica Double Check.

```dart
Future<void> confirmPairing({String? peerAlias})
```

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| peerAlias | `String?` | No | Alias leggibile per il peer |

##### `getPeer()`

> Restituisce il peer attualmente accoppiato, o `null` se non accoppiato.

```dart
Future<TrustedPeer?> getPeer()
```

##### `sendTransaction({required Uint8List payload})`

> Aggiunge un evento `transaction` alla catena.

```dart
Future<void> sendTransaction({required Uint8List payload})
```

##### `sendMessage({required Uint8List payload})`

> Aggiunge un evento `message` alla catena.

```dart
Future<void> sendMessage({required Uint8List payload})
```

##### `sendSOS({required Uint8List payload})`

> Aggiunge un evento `sos` alla catena.

```dart
Future<void> sendSOS({required Uint8List payload})
```

##### `sendConfig({required Uint8List payload})`

> Aggiunge un evento `config` alla catena.

```dart
Future<void> sendConfig({required Uint8List payload})
```

##### `getHistory()`

> Restituisce tutti gli eventi nella catena, ordinati per HLC.

```dart
Future<List<LedgerEvent>> getHistory()
```

##### `getHistoryRange({required DateTime from, required DateTime to})`

> Restituisce gli eventi all'interno di un intervallo temporale.

```dart
Future<List<LedgerEvent>> getHistoryRange({
  required DateTime from,
  required DateTime to,
})
```

##### `validateChain()`

> Valida l'integrità dell'intera catena di eventi.

```dart
Future<ChainValidationError?> validateChain()
```

**Ritorna:** `null` se valida, oppure il primo `ChainValidationError` trovato.

##### `setPrivacyProfile(PrivacyProfile profile)`

> Aggiorna il profilo di privacy delle notifiche push.

```dart
Future<void> setPrivacyProfile(PrivacyProfile profile)
```

##### `requestPrune({required String targetEventId, required PruneReason reason})`

> Richiede il pruning di uno specifico evento. Bilaterale per `userRequest`/`retentionExpired`, unilaterale per `gdprArticle17`.

```dart
Future<void> requestPrune({
  required String targetEventId,
  required PruneReason reason,
})
```

##### `setRetentionPolicy({required Duration period, required List<EventType> types})`

> Configura la policy di retention automatica.

```dart
Future<void> setRetentionPolicy({
  required Duration period,
  required List<EventType> types,
})
```

##### `getExpiredEvents()`

> Restituisce gli eventi che superano il periodo di retention configurato.

```dart
Future<List<LedgerEvent>> getExpiredEvents()
```

##### `createIdentityBackup({int threshold = 2, int totalShares = 3})`

> Crea share di backup Shamir della chiave privata.

```dart
Future<List<String>> createIdentityBackup({
  int threshold = 2,
  int totalShares = 3,
})
```

**Ritorna:** Lista di stringhe di share serializzate.

##### `restoreIdentity({required List<String> shares})`

> Ripristina l'identità dalle share di backup Shamir.

```dart
Future<void> restoreIdentity({required List<String> shares})
```

##### `blessNewDevice({required StyxPublicKey newPublicKey})`

> Crea un evento di blessing REKEY che approva la chiave pubblica di un nuovo dispositivo.

```dart
Future<void> blessNewDevice({required StyxPublicKey newPublicKey})
```

##### `checkMigrationStatus()`

> Restituisce lo stato corrente di qualsiasi migrazione dispositivo in corso.

```dart
Future<MigrationState> checkMigrationStatus()
```

---

### `LedgerStore`

> Interfaccia astratta per la persistenza del ledger. Implementare questa classe per fornire l'archiviazione della catena di eventi.

```dart
abstract class LedgerStore
```

Le applicazioni devono fornire la propria implementazione supportata da `styx_storage` (Drift + SQLCipher) o qualsiasi altro livello di persistenza.

---

### `PushBridgeRegistrar`

> Interfaccia astratta per la registrazione/cancellazione presso il server push bridge.

```dart
abstract class PushBridgeRegistrar
```

Implementare questa classe per collegare `PushBridgeClient` alla gestione dei token Firebase/APNs.

---

### `LedgerConfig`

> Configurazione immutabile per il ledger Styx.

#### Costruttore

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

| Parametro | Tipo | Obbligatorio | Default | Descrizione |
|-----------|------|--------------|---------|-------------|
| databasePath | `String?` | No | `null` | Percorso del database SQLCipher crittografato |
| relayUrls | `List<String>` | No | 3 relay predefiniti | URL WebSocket dei relay Nostr |
| emailConfig | `EmailConfig?` | No | `null` | Configurazione trasporto email di fallback |
| pushBridgeUrl | `String?` | No | `null` | URL del server push bridge |
| privacyProfile | `PrivacyProfile` | No | `balanced` | Profilo di privacy per le notifiche push |
| retentionPeriod | `Duration?` | No | `null` | Periodo di retention per l'auto-pruning |
| retentionTypes | `List<EventType>` | No | `[]` | Tipi di evento soggetti a retention |
| enableTor | `bool` | No | `false` | Instrada il trasporto attraverso Tor |
| torTimeout | `Duration` | No | 120s | Timeout di bootstrap Tor |
| logLevel | `LogLevel` | No | `info` | Livello di verbosità del logging |

---

### `LogLevel`

> Livello di verbosità del logging.

```dart
enum LogLevel { none, error, warning, info, debug }
```

---

### `StyxIdentity`

> Rappresentazione immutabile dell'identità del peer locale.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| publicKey | `StyxPublicKey` | Chiave pubblica Ed25519 |
| nodeId | `String` | Primi 8 caratteri esadecimali della chiave pubblica |
| peerRole | `String` | `'A'` o `'B'`, determinato al pairing dall'ordinamento lessicografico delle chiavi pubbliche |

---

### `StyxState`

> Stato del ciclo di vita della libreria Styx.

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

| Valore | Descrizione |
|--------|-------------|
| `uninitialized` | Libreria non ancora inizializzata |
| `initializing` | Inizializzazione in corso |
| `unpaired` | Identità pronta, nessun peer accoppiato |
| `ready` | Pienamente operativo, peer accoppiato |
| `degraded` | Operativo con trasporto ridotto (ad es. relay non raggiungibile) |
| `pairing` | Protocollo di pairing in corso |
| `migrating` | Migrazione dispositivo in corso |
| `error` | Errore non recuperabile |
| `shuttingDown` | Arresto in corso |

---

### `LedgerEventStream`

> Stream di eventi reattivo che unisce le sorgenti di eventi locali e remoti.

#### Costruttore

```dart
LedgerEventStream({
  required Stream<LedgerEvent> localEventSource,
  required Stream<LedgerEvent> remoteEventSource,
})
```

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| localEventSource | `Stream<LedgerEvent>` | Sì | Stream di eventi creati localmente |
| remoteEventSource | `Stream<LedgerEvent>` | Sì | Stream di eventi ricevuti dal peer |

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| allEvents | `Stream<LedgerEvent>` | Stream unificato di tutti gli eventi |
| localEvents | `Stream<LedgerEvent>` | Solo eventi creati localmente |
| remoteEvents | `Stream<LedgerEvent>` | Solo eventi dal peer |

#### Metodi

##### `eventsByType(EventType type)`

> Filtra lo stream unificato per tipo di evento.

```dart
Stream<LedgerEvent> eventsByType(EventType type)
```

##### `eventsAfter(DateTime timestamp)`

> Filtra lo stream unificato per gli eventi successivi a un dato timestamp.

```dart
Stream<LedgerEvent> eventsAfter(DateTime timestamp)
```

##### `dispose()`

> Chiude tutti i controller di stream interni.

```dart
void dispose()
```

---

### `QrPairingData`

> Contenitore immutabile per i dati di pairing QR.

#### Costruttore

```dart
QrPairingData({
  required StyxPublicKey publicKey,
  required Uint8List nonce,
  List<String>? relayHints,
})
```

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| publicKey | `StyxPublicKey` | Sì | Chiave pubblica locale Ed25519 |
| nonce | `Uint8List` | Sì | Nonce anti-replay di 16 byte |
| relayHints | `List<String>?` | No | URL dei relay Nostr suggeriti |

#### Costruttori Factory

##### `QrPairingData.fromQrPayload(String payload)`

> Deserializza da una stringa scansionata da QR (Base64).

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| estimatedBytes | `int` | Dimensione stimata in byte del payload QR |

#### Metodi

##### `toQrPayload()`

> Serializza in una stringa Base64 compatta per la codifica QR.

```dart
String toQrPayload()
```

---

### `QrPairingService`

> Gestisce il protocollo di pairing basato su QR con protezione anti-replay tramite nonce.

#### Costruttore

```dart
QrPairingService({
  required TrustStoreManager trustStore,
  Random? random,
})
```

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| trustStore | `TrustStoreManager` | Sì | Trust store per la persistenza dei peer accoppiati |
| random | `Random?` | No | Sorgente casuale (default: `Random.secure()`) |

#### Metodi

##### `generateQrData(StyxPublicKey localPublicKey, {List<String>? relayHints})`

> Genera i dati QR con un nonce fresco di 16 byte.

```dart
QrPairingData generateQrData(
  StyxPublicKey localPublicKey, {
  List<String>? relayHints,
})
```

##### `processScannedQr(String qrPayload, StyxPublicKey localPublicKey)`

> Valida un payload QR scansionato. Controlla il formato, previene l'auto-pairing e verifica il nonce anti-replay.

```dart
PairingResult processScannedQr(
  String qrPayload,
  StyxPublicKey localPublicKey,
)
```

**Ritorna:** `PairingResult` con lo stato di validità.

##### `completePairing(StyxPublicKey peerPublicKey, {String? peerAlias})`

> Persiste il peer nel trust store.

```dart
Future<void> completePairing(
  StyxPublicKey peerPublicKey, {
  String? peerAlias,
})
```

---

### `PairingResult`

> Risultato immutabile di un tentativo di pairing QR.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| peerPublicKey | `StyxPublicKey` | Chiave pubblica del peer |
| relayHints | `List<String>` | URL relay suggeriti dal peer |
| isValid | `bool` | Se i dati di pairing sono validi |
| errorMessage | `String?` | Descrizione dell'errore se `isValid` è false |

---

### `DoubleCheckVerifier`

> Genera e valida codici di verifica Double Check a 6 cifre.

#### Costruttore

```dart
DoubleCheckVerifier({required SessionVerifier sessionVerifier})
```

#### Metodi

##### `generateCode(Uint8List sessionKey)`

> Genera un codice a 6 cifre da una chiave di sessione SPAKE2.

```dart
String generateCode(Uint8List sessionKey)
```

**Ritorna:** Stringa a 6 cifre, ad es. `"483291"`.

##### `formatForDisplay(String code)`

> Formatta il codice con uno spazio per la leggibilità.

```dart
String formatForDisplay(String code)
```

**Ritorna:** ad es. `"483 291"`.

##### `isValidFormat(String input)`

> Verifica se l'input è esattamente di 6 cifre (ignorando spazi/trattini).

```dart
bool isValidFormat(String input)
```

##### `normalize(String input)`

> Rimuove spazi e trattini dall'input.

```dart
String normalize(String input)
```

---

### `RemotePairingService`

> Gestisce il flusso completo di pairing remoto: mnemonica → SPAKE2 → Double Check → trust store.

#### Costruttore

```dart
RemotePairingService({
  required Spake2Protocol spake2Protocol,
  required MnemonicGenerator mnemonicGenerator,
  required DoubleCheckVerifier doubleCheckVerifier,
  required TrustStoreManager trustStore,
  Duration? timeout,
})
```

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| spake2Protocol | `Spake2Protocol` | Sì | Factory di sessioni SPAKE2 |
| mnemonicGenerator | `MnemonicGenerator` | Sì | Generatore di mnemoniche BIP-39 |
| doubleCheckVerifier | `DoubleCheckVerifier` | Sì | Verificatore del codice a 6 cifre |
| trustStore | `TrustStoreManager` | Sì | Gestore del trust store |
| timeout | `Duration?` | No | Timeout opzionale per il processo di pairing |

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| state | `RemotePairingState` | Stato corrente del pairing |
| stateStream | `Stream<RemotePairingState>` | Cambiamenti di stato reattivi |
| peerPublicKey | `StyxPublicKey?` | Chiave pubblica del peer (disponibile dopo SPAKE2) |

#### Metodi

##### `generateMnemonic({int? wordCount})`

> Genera una mnemonica BIP-39 per la condivisione fuori banda.

```dart
String generateMnemonic({int? wordCount})
```

##### `startAsInitiator(String mnemonic, StyxPublicKey localPublicKey)`

> Avvia SPAKE2 come iniziatore.

```dart
Future<Uint8List> startAsInitiator(String mnemonic, StyxPublicKey localPublicKey)
```

**Ritorna:** Byte del messaggio SPAKE2 da inviare al peer.

##### `startAsResponder(String mnemonic, StyxPublicKey localPublicKey)`

> Avvia SPAKE2 come risponditore.

```dart
Future<Uint8List> startAsResponder(String mnemonic, StyxPublicKey localPublicKey)
```

**Ritorna:** Byte del messaggio SPAKE2 da inviare al peer.

##### `processPeerMessage(Uint8List peerMessage)`

> Elabora il messaggio SPAKE2 del peer e deriva la chiave di sessione condivisa.

```dart
Future<void> processPeerMessage(Uint8List peerMessage)
```

##### `getDoubleCheckCode()`

> Restituisce il codice di verifica a 6 cifre per il confronto verbale.

```dart
String getDoubleCheckCode()
```

##### `confirmDoubleCheck(bool codeMatches, {String? peerAlias})`

> Completa o fallisce il pairing in base al confronto dei codici.

```dart
Future<void> confirmDoubleCheck(bool codeMatches, {String? peerAlias})
```

##### `cancel()`

> Annulla il processo di pairing.

```dart
void cancel()
```

##### `dispose()`

> Rilascia le risorse.

```dart
void dispose()
```

##### `deriveSharedTag(String mnemonic)` (statico)

> Deriva un tag di scoperta dalla mnemonica per la scoperta del peer.

```dart
static String deriveSharedTag(String mnemonic)
```

---

### `RemotePairingState`

> Macchina a stati per il pairing remoto.

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

> Gestisce il trust store dei peer accoppiati con cronologia di re-keying.

#### Costruttore

```dart
TrustStoreManager({required PeerStore peerStore})
```

#### Metodi

##### `addTrustedPeer(StyxPublicKey peerPublicKey, {String? alias})`

> Aggiunge un peer al trust store.

```dart
Future<void> addTrustedPeer(StyxPublicKey peerPublicKey, {String? alias})
```

##### `revokePeer(StyxPublicKey peerPublicKey)`

> Disattiva un peer (lo segna come non fidato).

```dart
Future<void> revokePeer(StyxPublicKey peerPublicKey)
```

##### `isTrusted(StyxPublicKey publicKey)`

> Verifica se una chiave pubblica appartiene a un peer fidato attivo.

```dart
Future<bool> isTrusted(StyxPublicKey publicKey)
```

##### `getActivePeer()`

> Restituisce il peer fidato attualmente attivo, o `null`.

```dart
Future<TrustedPeer?> getActivePeer()
```

##### `updatePeerKey(StyxPublicKey oldKey, StyxPublicKey newKey)`

> Aggiorna la chiave di un peer dopo un evento di re-key e registra la modifica.

```dart
Future<void> updatePeerKey(StyxPublicKey oldKey, StyxPublicKey newKey)
```

##### `getRekeyHistory(StyxPublicKey currentKey)`

> Restituisce la cronologia dei re-key per un peer.

```dart
Future<List<RekeyRecord>> getRekeyHistory(StyxPublicKey currentKey)
```

---

### `TrustedPeer`

> Rappresentazione immutabile di un peer fidato.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| publicKey | `StyxPublicKey` | Chiave pubblica Ed25519 attuale del peer |
| alias | `String?` | Alias leggibile |
| pairedAt | `DateTime` | Quando è stato stabilito il pairing |
| isActive | `bool` | Se il peer è attualmente fidato |

---

### `RekeyRecord`

> Record immutabile di un cambio chiave.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| oldKey | `String` | Vecchia chiave pubblica codificata in esadecimale |
| newKey | `String` | Nuova chiave pubblica codificata in esadecimale |
| timestamp | `DateTime` | Quando è avvenuto il re-key |

---

### `PeerStore`

> Interfaccia astratta per la persistenza dei peer.

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

> Implementazione in memoria di `PeerStore` per i test.

```dart
class InMemoryPeerStore implements PeerStore
```

Memorizza i peer e i record di re-key in memoria. Non adatto alla produzione.

---

### `ReKeyProtocol`

> Gestisce il protocollo di re-keying per la migrazione del dispositivo.

#### Costruttore

```dart
ReKeyProtocol({
  required EventFactory eventFactory,
  required TrustStoreManager trustStoreManager,
  required Verifier verifier,
})
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| state | `ReKeyState` | Stato corrente del protocollo di re-key |

#### Metodi

##### `createBlessingEvent(...)`

> Crea un evento di blessing REKEY firmato dalla vecchia chiave.

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

**Ritorna:** Un `LedgerEvent` di tipo `rekey` contenente la nuova chiave pubblica nel payload.

##### `processReKeyEvent(LedgerEvent rekeyEvent)`

> Elabora un evento REKEY ricevuto: verifica la firma, estrae la nuova chiave, aggiorna il trust store.

```dart
Future<ReKeyResult> processReKeyEvent(LedgerEvent rekeyEvent)
```

**Ritorna:** `ReKeyResult` che indica successo o fallimento.

##### `isReKeyAcknowledged(StyxPublicKey newKey)`

> Verifica se il peer ha accettato la nuova chiave.

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

> Risultato immutabile dell'elaborazione di un evento di re-key.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| success | `bool` | Se il re-key è stato accettato |
| oldKey | `StyxPublicKey` | La chiave pubblica precedente |
| newKey | `StyxPublicKey` | La nuova chiave pubblica |
| errorMessage | `String?` | Descrizione dell'errore se `success` è false |

---

### `KeyMigrationService`

> Orchestratore del flusso completo di migrazione dispositivo tra vecchio dispositivo, nuovo dispositivo e peer.

#### Costruttore

```dart
KeyMigrationService({
  required IdentityManager identityManager,
  required ReKeyProtocol reKeyProtocol,
  required KeyBackup keyBackup,
})
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| state | `MigrationState` | Stato corrente della migrazione |
| stateStream | `Stream<MigrationState>` | Cambiamenti di stato reattivi |

#### Metodi

##### `generateNewIdentity()`

> Passo 1: Genera una nuova coppia di chiavi Ed25519 sul nuovo dispositivo.

```dart
Future<StyxKeyPair> generateNewIdentity()
```

##### `blessNewDevice()`

> Passo 2: Crea un evento di blessing sul vecchio dispositivo.

```dart
Future<LedgerEvent> blessNewDevice()
```

##### `checkPeerAcknowledgment(StyxPublicKey newPublicKey)`

> Passo 3: Verifica se il peer ha confermato il re-key.

```dart
Future<bool> checkPeerAcknowledgment(StyxPublicKey newPublicKey)
```

##### `restoreFromBackup(List<ShamirShare> shares)`

> Ripristina l'identità dalle share Shamir (alternativa al blessing dal vecchio dispositivo).

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

> Interfaccia astratta per le operazioni del ledger durante la migrazione.

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

> Servizio di alto livello per la creazione e il ripristino di backup tramite schema di condivisione del segreto di Shamir.

#### Costruttore

```dart
ShamirBackupService({
  required KeyBackup keyBackup,
  required SecureKeyStore secureKeyStore,
})
```

#### Metodi

##### `createBackup(StyxPrivateKey privateKey, {int threshold = 2, int totalShares = 3})`

> Suddivide la chiave privata in share Shamir.

```dart
List<String> createBackup(
  StyxPrivateKey privateKey, {
  int threshold = 2,
  int totalShares = 3,
})
```

**Ritorna:** Lista di stringhe di share serializzate (Base64 con indice incorporato).

##### `restoreFromBackup(List<String> serializedShares, String keyId)`

> Ricostruisce la coppia di chiavi dalle share e la salva nello store sicuro.

```dart
Future<StyxKeyPair> restoreFromBackup(
  List<String> serializedShares,
  String keyId,
)
```

##### `verifyShares(List<String> serializedShares)`

> Verifica che le share possano ricostruire una coppia di chiavi valida senza persistere.

```dart
Future<bool> verifyShares(List<String> serializedShares)
```

---

## 5. Riferimento API — crypto_core

Package: `package:styx_crypto_core/styx_crypto_core.dart`

### `StyxPublicKey`

> Chiave pubblica Ed25519 immutabile (32 byte).

#### Costruttore

```dart
StyxPublicKey(Uint8List bytes)
```

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| bytes | `Uint8List` | Sì | Chiave pubblica grezza di 32 byte |

#### Costruttori Factory

##### `StyxPublicKey.fromHex(String hex)`

> Crea da una stringa codificata in esadecimale.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| bytes | `Uint8List` | Byte grezzi della chiave pubblica |

#### Metodi

##### `toHex()`

> Restituisce la rappresentazione in stringa codificata in esadecimale.

```dart
String toHex()
```

**Uguaglianza:** Due istanze di `StyxPublicKey` sono uguali se i loro byte sono identici (confronto a tempo costante).

---

### `StyxPrivateKey`

> Chiave privata Ed25519 con supporto alla distruzione sicura.

#### Costruttore

```dart
StyxPrivateKey(Uint8List bytes)
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| bytes | `Uint8List` | Byte grezzi della chiave privata (lancia eccezione se distrutta) |
| isDestroyed | `bool` | Se la chiave è stata azzerata |

#### Metodi

##### `destroy()`

> Azzera il materiale della chiave. L'accesso successivo a `bytes` lancia `StateError`.

```dart
void destroy()
```

---

### `StyxKeyPair`

> Contenitore per una coppia di chiavi pubblica/privata Ed25519.

#### Costruttore

```dart
const StyxKeyPair({
  required StyxPublicKey publicKey,
  required StyxPrivateKey privateKey,
})
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| publicKey | `StyxPublicKey` | Chiave pubblica |
| privateKey | `StyxPrivateKey` | Chiave privata |

---

### `IdentityManager`

> Genera e importa coppie di chiavi Ed25519.

#### Metodi

##### `generate()`

> Genera una nuova coppia di chiavi Ed25519.

```dart
Future<StyxKeyPair> generate()
```

##### `exportPublicKey(StyxPublicKey publicKey)`

> Esporta una chiave pubblica come byte grezzi.

```dart
Uint8List exportPublicKey(StyxPublicKey publicKey)
```

##### `importPublicKey(Uint8List bytes)`

> Importa una chiave pubblica da byte grezzi.

```dart
StyxPublicKey importPublicKey(Uint8List bytes)
```

##### `exportPrivateKey(StyxPrivateKey privateKey)`

> Esporta una chiave privata come byte grezzi.

```dart
Uint8List exportPrivateKey(StyxPrivateKey privateKey)
```

##### `importPrivateKey(Uint8List bytes)`

> Ricostruisce una coppia di chiavi completa da byte grezzi della chiave privata.

```dart
Future<StyxKeyPair> importPrivateKey(Uint8List bytes)
```

---

### `Signer`

> Firma i dati con chiavi private Ed25519.

#### Metodi

##### `sign(Uint8List payload, StyxPrivateKey privateKey)`

> Crea una firma Ed25519.

```dart
Future<Uint8List> sign(Uint8List payload, StyxPrivateKey privateKey)
```

**Ritorna:** Byte della firma (64 byte).

---

### `Verifier`

> Verifica le firme Ed25519.

#### Metodi

##### `verify({required Uint8List payload, required Uint8List signatureBytes, required StyxPublicKey publicKey})`

> Verifica una firma Ed25519.

```dart
Future<bool> verify({
  required Uint8List payload,
  required Uint8List signatureBytes,
  required StyxPublicKey publicKey,
})
```

---

### `Hasher`

> Utilità di hashing SHA-256.

#### Metodi

##### `hash(Uint8List data)`

> Calcola l'hash SHA-256.

```dart
Uint8List hash(Uint8List data)
```

##### `chainHash({required Uint8List? previousHash, required Uint8List payload})`

> Calcola l'hash per il collegamento della catena: `SHA-256(previousHash || payload)`.

```dart
Uint8List chainHash({
  required Uint8List? previousHash,
  required Uint8List payload,
})
```

##### `compositeHash(List<Uint8List> segments)`

> Calcola `SHA-256(segment[0] || segment[1] || ... || segment[n])`.

```dart
Uint8List compositeHash(List<Uint8List> segments)
```

---

### `Spake2Protocol`

> Factory per la creazione di sessioni SPAKE2 su NIST P-256.

#### Metodi

##### `createInitiatorSession(Uint8List password)`

> Crea una sessione SPAKE2 lato iniziatore.

```dart
Spake2Session createInitiatorSession(Uint8List password)
```

##### `createResponderSession(Uint8List password)`

> Crea una sessione SPAKE2 lato risponditore.

```dart
Spake2Session createResponderSession(Uint8List password)
```

##### `mnemonicToPassword(String mnemonic)`

> Converte una mnemonica BIP-39 in una password adatta per SPAKE2.

```dart
Uint8List mnemonicToPassword(String mnemonic)
```

---

### `Spake2Session`

> Una sessione SPAKE2 che progredisce attraverso `init → messageSent → completed`.

#### Costruttore

```dart
Spake2Session({
  required Spake2Role role,
  required Uint8List password,
})
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| role | `Spake2Role` | `initiator` o `responder` |
| state | `Spake2State` | Stato corrente della sessione |

#### Metodi

##### `generateMessage()`

> Genera il messaggio SPAKE2 da inviare al peer.

```dart
Uint8List generateMessage()
```

##### `processMessage(Uint8List peerMessage)`

> Elabora il messaggio SPAKE2 del peer. Restituisce `true` se la chiave di sessione è stata derivata.

```dart
bool processMessage(Uint8List peerMessage)
```

##### `getSessionKey()`

> Restituisce la chiave di sessione condivisa derivata.

```dart
Uint8List getSessionKey()
```

**Lancia:** `StateError` se chiamato prima del completamento di `processMessage`.

##### `getConfirmation()`

> Restituisce il valore di conferma HMAC per la sessione.

```dart
Uint8List getConfirmation()
```

##### `verifyConfirmation(Uint8List peerConfirmation)`

> Verifica la conferma HMAC del peer.

```dart
bool verifyConfirmation(Uint8List peerConfirmation)
```

##### `destroy()`

> Azzera tutti i segreti della sessione.

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

> Genera e valida mnemoniche BIP-39 dalla wordlist inglese (2048 parole).

#### Metodi

##### `generate({int wordCount = 6})`

> Genera una mnemonica casuale.

```dart
String generate({int wordCount = 6})
```

**Ritorna:** Parole separate da spazi, ad es. `"abandon ability able about above absent"`.

##### `validate(String mnemonic)`

> Valida che tutte le parole esistano nella wordlist BIP-39.

```dart
bool validate(String mnemonic)
```

##### `mnemonicToSeed(String mnemonic)`

> Deriva un seed di 32 byte dalla mnemonica tramite PBKDF2.

```dart
Future<Uint8List> mnemonicToSeed(String mnemonic)
```

##### `supportedLanguages`

> Restituisce la lista delle lingue supportate (attualmente `['english']`).

```dart
List<String> get supportedLanguages
```

---

### `SessionVerifier`

> Deriva codici di verifica a 6 cifre dalle chiavi di sessione SPAKE2.

#### Metodi

##### `generateDoubleCheckCode(Uint8List sessionKey)`

> Calcola `SHA-256(sessionKey || suffix)`, tronca a 6 cifre decimali.

```dart
String generateDoubleCheckCode(Uint8List sessionKey)
```

---

### `KeyBackup`

> Crea e ripristina backup tramite schema di condivisione del segreto di Shamir per le chiavi private.

#### Costruttore

```dart
KeyBackup({
  required ShamirSplitter splitter,
  required ShamirReconstructor reconstructor,
})
```

#### Metodi

##### `backupPrivateKey({required StyxPrivateKey privateKey, int threshold = 2, int totalShares = 3})`

> Suddivide una chiave privata in share Shamir.

```dart
List<ShamirShare> backupPrivateKey({
  required StyxPrivateKey privateKey,
  int threshold = 2,
  int totalShares = 3,
})
```

##### `restoreFromShares(List<ShamirShare> shares)`

> Ricostruisce una coppia di chiavi completa dalle share Shamir.

```dart
Future<StyxKeyPair> restoreFromShares(List<ShamirShare> shares)
```

---

### `ShamirSplitter`

> Suddivide segreti utilizzando lo schema di condivisione del segreto di Shamir su GF(256).

#### Metodi

##### `split({required Uint8List secret, int threshold = 2, int totalShares = 3})`

> Suddivide un segreto in share.

```dart
List<ShamirShare> split({
  required Uint8List secret,
  int threshold = 2,
  int totalShares = 3,
})
```

| Parametro | Tipo | Obbligatorio | Default | Descrizione |
|-----------|------|--------------|---------|-------------|
| secret | `Uint8List` | Sì | — | Il segreto da suddividere |
| threshold | `int` | No | `2` | Share minime per la ricostruzione |
| totalShares | `int` | No | `3` | Share totali da creare |

**Vincoli:** `2 ≤ threshold ≤ totalShares ≤ 255`.

---

### `ShamirReconstructor`

> Ricostruisce segreti dalle share Shamir utilizzando l'interpolazione di Lagrange.

#### Metodi

##### `reconstruct(List<ShamirShare> shares)`

> Ricostruisce il segreto originale dalle share.

```dart
Uint8List reconstruct(List<ShamirShare> shares)
```

**Lancia:**
- `InsufficientSharesException` se vengono fornite meno di 2 share.
- `InvalidShareException` se le share hanno lunghezze inconsistenti.

---

### `ShamirShare`

> Share immutabile del segreto di Shamir.

#### Costruttore

```dart
const ShamirShare({required int index, required Uint8List data})
```

#### Costruttori Factory

##### `ShamirShare.deserialize(String encoded)`

> Deserializza da una stringa (come prodotta da `serialize()`).

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| index | `int` | Indice della share (1-based, usato nell'interpolazione di Lagrange) |
| data | `Uint8List` | Byte dei dati della share |

#### Metodi

##### `serialize()`

> Serializza in una stringa per archiviazione/trasmissione.

```dart
String serialize()
```

---

### `InsufficientSharesException`

> Lanciata quando non vengono fornite abbastanza share per la ricostruzione.

```dart
class InsufficientSharesException implements Exception {
  const InsufficientSharesException(String message);
  final String message;
}
```

### `InvalidShareException`

> Lanciata quando le share sono malformate o inconsistenti.

```dart
class InvalidShareException implements Exception {
  const InvalidShareException(String message);
  final String message;
}
```

---

### `SecureKeyStore`

> Interfaccia astratta per l'archiviazione sicura delle chiavi (supportata da enclave hardware in produzione).

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

> Implementazione in memoria di `SecureKeyStore` per i test.

```dart
class InMemoryKeyStore implements SecureKeyStore
```

---

### `KeyConverter`

> Converte le chiavi Ed25519 nel formato X25519 per lo scambio di chiavi Diffie-Hellman.

#### Metodi

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

> Scambio di chiavi X25519 Diffie-Hellman.

#### Metodi

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

> Coppia di chiavi X25519 effimera con distruzione sicura.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| publicKey | `Uint8List` | Chiave pubblica X25519 |
| privateKey | `Uint8List` | Chiave privata X25519 (lancia eccezione se distrutta) |
| isDestroyed | `bool` | Se il materiale della chiave è stato azzerato |

#### Metodi

##### `destroy()`

```dart
void destroy()
```

---

### `KeyDerivation`

> Derivazione di chiavi basata su HKDF.

#### Metodi

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

> Deriva chiavi di invio/ricezione basate sull'ordine lessicografico delle chiavi pubbliche.

```dart
Future<DirectionalKeys> deriveDirectionalKeys({
  required Uint8List sharedSecret,
  required Uint8List localPubKey,
  required Uint8List remotePubKey,
})
```

---

### `DirectionalKeys`

> Coppia di chiavi di invio e ricezione con distruzione sicura.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| sendKey | `Uint8List` | Chiave per crittografare i messaggi in uscita |
| receiveKey | `Uint8List` | Chiave per decrittografare i messaggi in arrivo |
| isDestroyed | `bool` | Se il materiale della chiave è stato azzerato |

#### Metodi

##### `destroy()`

```dart
void destroy()
```

---

## 6. Riferimento API — ledger_engine

Package: `package:styx_ledger_engine/styx_ledger_engine.dart`

### `LedgerEvent`

> Rappresentazione immutabile di un evento del ledger nella catena di hash.

#### Costruttore

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

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| eventId | `String` | Identificatore UUID v4 |
| eventType | `EventType` | Tipo di evento |
| payload | `Uint8List?` | Dati dell'evento (null dopo il pruning) |
| previousHash | `String?` | Hash dell'evento precedente (null per il genesis) |
| eventHash | `String` | Hash SHA-256 di questo evento |
| hlc | `HybridLogicalClock` | Timestamp Hybrid Logical Clock |
| vectorClock | `VectorClock` | Vector clock a 2 elementi |
| senderPubkey | `String` | Chiave pubblica del mittente codificata in esadecimale |
| signature | `Uint8List` | Firma Ed25519 sull'hash dell'evento |
| createdAt | `DateTime` | Orario di creazione wall-clock (UTC) |
| isPruned | `bool` | Se il payload è stato sottoposto a pruning |

---

### `EventType`

> Tipi di eventi nel ledger.

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

| Valore | Descrizione |
|--------|-------------|
| `transaction` | Transazione finanziaria o di dati |
| `message` | Messaggio di testo |
| `sos` | Segnale di emergenza |
| `config` | Modifica di configurazione (usato anche per il genesis) |
| `rekey` | Evento di re-keying (blessing) del dispositivo |
| `merge` | Evento di risoluzione fork |
| `pruneRequest` | Richiesta di pruning di un evento (bilaterale) |
| `pruneAck` | Conferma di una richiesta di pruning |

---

### `EventFactory`

> Crea eventi firmati e con hash per la catena del ledger.

#### Costruttore

```dart
EventFactory({required Signer signer, required Hasher hasher})
```

#### Metodi

##### `createEvent({...})`

> Crea un nuovo evento aggiunto alla catena. Genera UUID, calcola HLC, incrementa il vector clock, calcola l'hash SHA-256, firma con Ed25519.

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

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| type | `EventType` | Sì | Tipo di evento |
| payload | `Uint8List` | Sì | Dati dell'evento |
| privateKey | `StyxPrivateKey` | Sì | Chiave di firma |
| publicKey | `StyxPublicKey` | Sì | Chiave pubblica del mittente |
| previousEvent | `LedgerEvent?` | Sì | Evento precedente (null per il genesis) |
| currentVectorClock | `VectorClock` | Sì | Stato corrente del vector clock |
| localPeerRole | `String` | Sì | `'A'` o `'B'` |

##### `createGenesisEvent({...})`

> Crea il primo evento della catena.

```dart
Future<LedgerEvent> createGenesisEvent({
  required StyxPrivateKey privateKey,
  required StyxPublicKey publicKey,
  required String nodeId,
})
```

##### `computeHashBytes({...})`

> Calcola `SHA-256(previousHash || eventType || payload || hlcBytes)`.

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

> Valida l'integrità della catena del ledger.

#### Costruttore

```dart
ChainValidator({required Hasher hasher, required Verifier verifier})
```

#### Metodi

##### `validateFullChain(List<LedgerEvent> events)`

> Valida ogni evento in sequenza. Controlla la validità del genesis, il collegamento degli hash, l'integrità degli hash, le firme Ed25519 e la monotonicità dell'HLC.

```dart
Future<ChainValidationError?> validateFullChain(List<LedgerEvent> events)
```

**Ritorna:** `null` se valida, oppure il primo errore trovato.

##### `validateEvent({...})`

> Valida un singolo evento rispetto al suo predecessore.

```dart
Future<ChainValidationError?> validateEvent({
  required LedgerEvent event,
  required LedgerEvent? previousEvent,
  required StyxPublicKey senderPublicKey,
})
```

##### `verifyEventHash(LedgerEvent event, String? previousHash)`

> Verifica che l'hash memorizzato dell'evento corrisponda all'hash calcolato.

```dart
Future<bool> verifyEventHash(LedgerEvent event, String? previousHash)
```

##### `verifyEventSignature(LedgerEvent event, StyxPublicKey publicKey)`

> Verifica la firma Ed25519 sull'evento.

```dart
Future<bool> verifyEventSignature(LedgerEvent event, StyxPublicKey publicKey)
```

---

### `ChainValidationError`

> Descrive un errore di validazione della catena.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| eventId | `String` | ID dell'evento con l'errore |
| errorType | `ChainErrorType` | Categoria dell'errore |
| message | `String` | Descrizione leggibile |

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

| Valore | Descrizione |
|--------|-------------|
| `hashMismatch` | L'hash calcolato differisce dall'hash memorizzato |
| `signatureInvalid` | La verifica della firma Ed25519 è fallita |
| `previousHashMissing` | `previousHash` non corrisponde all'hash dell'evento precedente |
| `hlcViolation` | L'HLC non è monotonicamente crescente |
| `genesisViolation` | Il primo evento ha un `previousHash` non nullo |

---

### `VectorClock`

> Vector clock a 2 elementi per il sistema Styx a 2 peer.

#### Costruttori

```dart
const VectorClock({required int a, required int b})
const VectorClock.zero()  // a: 0, b: 0
factory VectorClock.fromJson(Map<String, dynamic> json)
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| a | `int` | Contatore per il peer A |
| b | `int` | Contatore per il peer B |
| total | `int` | Somma `a + b` (usata per l'ordinamento deterministico del merge) |

#### Metodi

##### `increment(String localPeerRole)`

> Restituisce un nuovo `VectorClock` con il contatore per il ruolo dato incrementato.

```dart
VectorClock increment(String localPeerRole)
```

| Parametro | Tipo | Descrizione |
|-----------|------|-------------|
| localPeerRole | `String` | `'A'` o `'B'` |

**Lancia:** `ArgumentError` se il ruolo non è `'A'` o `'B'`.

##### `merge(VectorClock other)`

> Restituisce un nuovo `VectorClock` con il massimo componente per componente.

```dart
VectorClock merge(VectorClock other)
```

##### `causalRelation(VectorClock other)`

> Confronta la relazione causale.

```dart
CausalRelation causalRelation(VectorClock other)
```

##### `toJson()`

```dart
Map<String, int> toJson()
```

##### `toBytes()`

> Serializza in 8 byte (4 per A, 4 per B, big-endian).

```dart
Uint8List toBytes()
```

---

### `CausalRelation`

```dart
enum CausalRelation { before, after, concurrent, equal }
```

| Valore | Descrizione |
|--------|-------------|
| `before` | Questo clock è causalmente prima dell'altro |
| `after` | Questo clock è causalmente dopo l'altro |
| `concurrent` | Nessuna relazione causale (fork) |
| `equal` | Clock identici |

---

### `HybridLogicalClock`

> Hybrid Logical Clock che combina tempo wall-clock, contatore logico e ID del nodo.

#### Costruttore

```dart
HybridLogicalClock({
  required DateTime timestamp,
  required int counter,
  required String nodeId,
})
```

#### Costruttori Factory

##### `HybridLogicalClock.now({HybridLogicalClock? previous, required String nodeId})`

> Crea un HLC per l'istante corrente, garantendo la monotonicità rispetto a `previous`.

##### `HybridLogicalClock.fromCanonical(String s)`

> Analizza dal formato canonico: `2026-02-24T12:00:00.000Z-0042-a1b2c3d4`.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| timestamp | `DateTime` | Tempo wall-clock UTC |
| counter | `int` | Contatore logico (spareggio nello stesso millisecondo) |
| nodeId | `String` | Identificatore del nodo (primi 8 caratteri esadecimali della chiave pubblica) |

#### Metodi

##### `toCanonical()`

> Restituisce la stringa canonica: `2026-02-24T12:00:00.000Z-0042-a1b2c3d4`.

```dart
String toCanonical()
```

##### `toBytes()`

> Serializza in byte per il calcolo dell'hash.

```dart
Uint8List toBytes()
```

##### `compareTo(HybridLogicalClock other)`

> Confronta per timestamp, poi contatore, poi nodeId.

```dart
int compareTo(HybridLogicalClock other)
```

---

### `PruneProtocol`

> Protocollo di pruning bilaterale per la conformità GDPR.

#### Costruttore

```dart
PruneProtocol({required EventFactory eventFactory})
```

#### Metodi

##### `requestPrune({...})`

> Crea un evento `PRUNE_REQUEST`.

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

> Crea un evento `PRUNE_ACK` in risposta a una richiesta.

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

> Annulla il payload dopo entrambi `REQUEST` e `ACK`.

```dart
Future<void> executeBilateralPrune({
  required String targetEventId,
  required EventDao eventDao,
})
```

##### `executeUnilateralPrune({required String targetEventId, required EventDao eventDao})`

> Annulla immediatamente il payload (GDPR Art. 17, nessun ACK necessario).

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

> Valuta le policy di retention per identificare gli eventi scaduti.

#### Metodi

##### `getExpiredEvents({...})`

> Restituisce gli eventi che superano il periodo di retention.

```dart
List<LedgerEvent> getExpiredEvents({
  required List<LedgerEvent> events,
  required Duration retentionPeriod,
  required List<EventType> applicableTypes,
})
```

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| events | `List<LedgerEvent>` | Sì | Tutti gli eventi da valutare |
| retentionPeriod | `Duration` | Sì | Età massima prima della scadenza |
| applicableTypes | `List<EventType>` | Sì | Tipi di evento soggetti a retention |

Gli eventi già sottoposti a pruning sono esclusi.

---

### `LedgerService`

> Facciata di alto livello per le operazioni del ledger con archiviazione persistente.

#### Costruttore

```dart
LedgerService({
  required EventFactory eventFactory,
  required ChainValidator chainValidator,
  required EventDao eventDao,
  required String localPeerRole,
})
```

#### Metodi

##### `appendEvent({...})`

> Aggiunge un nuovo evento alla catena locale.

```dart
Future<LedgerEvent> appendEvent({
  required EventType type,
  required Uint8List payload,
  required StyxPrivateKey privateKey,
  required StyxPublicKey publicKey,
})
```

##### `getHistory()`

> Restituisce tutti gli eventi ordinati per HLC.

```dart
Future<List<LedgerEvent>> getHistory()
```

##### `validateChain()`

> Valida l'intera catena.

```dart
Future<ChainValidationError?> validateChain()
```

##### `getLatestEvent()`

> Restituisce l'ultimo evento, o `null` per catene vuote.

```dart
Future<LedgerEvent?> getLatestEvent()
```

##### `watchNewEvents()`

> Stream reattivo che emette nuovi eventi man mano che vengono aggiunti.

```dart
Stream<LedgerEvent> watchNewEvents()
```

---

### `ForkDetector`

> Rileva i fork nella catena di eventi trovando eventi che condividono lo stesso `previousHash`.

#### Costruttore

```dart
ForkDetector({CausalityChecker? causalityChecker})
```

#### Metodi

##### `detectForks(List<LedgerEvent> events)`

> Scansiona tutti gli eventi alla ricerca di fork.

```dart
List<Fork> detectForks(List<LedgerEvent> events)
```

##### `detectForkOnReceive({required LedgerEvent remoteEvent, required LedgerEvent localHead})`

> Rileva se un evento remoto ricevuto crea un fork con la testa locale.

```dart
Fork? detectForkOnReceive({
  required LedgerEvent remoteEvent,
  required LedgerEvent localHead,
})
```

---

### `Fork`

> Rappresenta un fork dove due rami divergono da un antenato comune.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| commonAncestorHash | `String` | Hash dell'ultimo evento comune |
| branchA | `List<LedgerEvent>` | Eventi sul ramo A (tipicamente locale) |
| branchB | `List<LedgerEvent>` | Eventi sul ramo B (tipicamente remoto) |

---

### `DeterministicMerge`

> Esegue il merge deterministico dei rami biforcati. Entrambi i peer applicano la stessa regola di ordinamento, garantendo la convergenza.

#### Metodi

##### `orderConcurrentEvents(List<LedgerEvent> events)`

> Ordina gli eventi concorrenti: (1) per totale del vector clock in ordine crescente, (2) per chiave pubblica del mittente in ordine lessicografico.

```dart
List<LedgerEvent> orderConcurrentEvents(List<LedgerEvent> events)
```

##### `merge({required Fork fork, required String localPeerRole})`

> Unisce un fork in una sequenza lineare.

```dart
MergeResult merge({required Fork fork, required String localPeerRole})
```

---

### `MergeResult`

> Risultato di un'operazione di merge deterministico.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| orderedEvents | `List<LedgerEvent>` | Sequenza di eventi ordinata deterministicamente |
| mergeEventNeeded | `bool` | Se è necessario aggiungere un evento MERGE |

---

### `MergeEventFactory`

> Crea eventi MERGE che fanno riferimento a entrambi i tip di un fork.

#### Costruttore

```dart
MergeEventFactory({required EventFactory eventFactory})
```

#### Metodi

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

Il payload è JSON: `{"type": "merge", "branch_a_head": "...", "branch_b_head": "...", "ancestor": "..."}`.

---

### `CausalityChecker`

> Determina le relazioni causali tra vector clock.

#### Metodi

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

## 7. Riferimento API — transport

Package: `package:styx_transport/styx_transport.dart`

### `TransportInterface`

> Interfaccia astratta per tutte le implementazioni di trasporto.

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

> Un messaggio scambiato tra peer attraverso il livello di trasporto.

#### Costruttore

```dart
TransportMessage({
  required String id,
  required String senderPubkey,
  required String recipientPubkey,
  required Uint8List payload,
  required DateTime timestamp,
})
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| id | `String` | Identificatore univoco del messaggio |
| senderPubkey | `String` | Chiave pubblica del mittente codificata in esadecimale |
| recipientPubkey | `String` | Chiave pubblica del destinatario codificata in esadecimale |
| payload | `Uint8List` | Payload del messaggio crittografato |
| timestamp | `DateTime` | Orario di creazione del messaggio (UTC) |

#### Metodi

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

> Motore di failover multi-trasporto. Tenta i trasporti in ordine di priorità con retry + backoff esponenziale.

#### Costruttore

```dart
TransportFailover({required List<TransportPriority> transports})
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| transports | `List<TransportPriority>` | Priorità di trasporto configurate |
| anyAvailable | `bool` | Se almeno un trasporto è disponibile |

#### Metodi

Implementa `TransportInterface` più:

##### `dispose()`

```dart
Future<void> dispose()
```

**Strategia di backoff:** `min(100ms * 2^tentativo, 5000ms)`.

**Eccezione:** Lancia `TransportFailoverException` se tutti i trasporti falliscono.

---

### `TransportPriority`

> Associa un trasporto alla sua politica di retry e timeout.

#### Costruttore

```dart
const TransportPriority({
  required TransportInterface transport,
  required int maxRetries,
  required Duration timeout,
})
```

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| transport | `TransportInterface` | Sì | Implementazione del trasporto |
| maxRetries | `int` | Sì | Numero massimo di retry prima del passaggio al successivo |
| timeout | `Duration` | Sì | Timeout per tentativo di invio |

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

> Factory che costruisce una catena `TransportFailover` basata sulla configurazione.

#### Metodi

##### `createFailoverChain({...})`

```dart
TransportFailover createFailoverChain({
  required TransportInterface nostr,
  TransportInterface? email,
  TorManager? torManager,
  bool useTor = false,
})
```

Gerarchia predefinita:
1. Nostr (3 retry, timeout 5s)
2. Email (2 retry, timeout 30s) — se fornito

Quando `useTor` è true, i trasporti vengono avvolti con `TorTransportDecorator`.

---

### `EmailConfig`

> Configurazione per il trasporto basato su email.

#### Costruttore

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

| Parametro | Tipo | Obbligatorio | Default | Descrizione |
|-----------|------|--------------|---------|-------------|
| imapHost | `String` | Sì | — | Hostname del server IMAP |
| imapPort | `int` | Sì | — | Porta IMAP (tipicamente 993) |
| smtpHost | `String` | Sì | — | Hostname del server SMTP |
| smtpPort | `int` | Sì | — | Porta SMTP (tipicamente 465 o 587) |
| username | `String` | Sì | — | Nome utente di login |
| password | `String` | Sì | — | Password di login o token OAuth2 |
| recipientAddress | `String` | Sì | — | Indirizzo email del destinatario |
| useSsl | `bool` | No | `true` | Utilizza SSL/TLS |
| senderAddress | `String?` | No | `username` | Indirizzo del mittente |

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| sender | `String` | Indirizzo del mittente effettivo (`senderAddress ?? username`) |

---

### `NostrTransport`

> Trasporto basato su relay Nostr che implementa `TransportInterface`.

#### Costruttore

```dart
NostrTransport({
  required RelayPool relayPool,
  required NostrEncryptor encryptor,
  required String localPubkey,
  required String peerPubkey,
})
```

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| relayPool | `RelayPool` | Sì | Pool di connessioni ai relay Nostr |
| encryptor | `NostrEncryptor` | Sì | Crittografia compatibile NIP-44 |
| localPubkey | `String` | Sì | Chiave pubblica locale codificata in esadecimale |
| peerPubkey | `String` | Sì | Chiave pubblica del peer codificata in esadecimale |

Implementa `TransportInterface`. Fornisce anche:

##### `dispose()`

```dart
Future<void> dispose()
```

---

### `NostrEncryptor`

> Gestisce la crittografia compatibile NIP-44 per i messaggi Nostr.

#### Costruttore

```dart
NostrEncryptor({
  required Uint8List sendKey,
  required Uint8List receiveKey,
})
```

#### Metodi

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

> Gestisce le connessioni a più relay Nostr.

#### Costruttore

```dart
RelayPool({
  required List<String> relayUrls,
  required RelayConnectionFactory factory,
})
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| relayUrls | `List<String>` | URL dei relay attualmente configurati (non modificabile) |
| messages | `Stream<String>` | Messaggi in arrivo da tutti i relay |
| connectedCount | `int` | Numero di connessioni attualmente aperte |

#### Metodi

##### `connectAll()`

> Si connette a tutti i relay. Restituisce il numero di connessioni riuscite.

```dart
Future<int> connectAll()
```

##### `disconnectAll()`

```dart
Future<void> disconnectAll()
```

##### `publish(Map<String, dynamic> event)`

> Pubblica un evento JSON su tutti i relay connessi. Restituisce il numero di relay raggiunti.

```dart
int publish(Map<String, dynamic> event)
```

##### `subscribe(String subscriptionId, Map<String, dynamic> filter)`

> Si iscrive agli eventi su tutti i relay connessi.

```dart
void subscribe(String subscriptionId, Map<String, dynamic> filter)
```

##### `healthCheck()`

> Restituisce lo stato di salute di tutti i relay.

```dart
List<RelayHealth> healthCheck()
```

##### `addRelay(String url)`

> Aggiunge un URL relay (non si connette automaticamente).

```dart
void addRelay(String url)
```

##### `removeRelay(String url)`

> Rimuove e disconnette un relay.

```dart
Future<void> removeRelay(String url)
```

##### `dispose()`

```dart
Future<void> dispose()
```

---

### `RelayHealth`

> Stato di salute di un singolo relay.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| url | `String` | URL WebSocket del relay |
| isConnected | `bool` | Se il relay è attualmente connesso |

---

### `TorManager`

> Gestisce il ciclo di vita del proxy SOCKS5 Tor.

#### Costruttore

```dart
TorManager({required TorEngine engine})
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| state | `TorState` | Stato corrente di Tor |
| stateStream | `Stream<TorState>` | Cambiamenti di stato reattivi |
| socksPort | `int` | Porta SOCKS5 (valida solo quando `ready`) |
| bootstrapProgress | `int` | Progresso del bootstrap 0–100 |

#### Metodi

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

> Decorator che instrada qualsiasi `TransportInterface` attraverso il proxy SOCKS5 Tor. Assicura che Tor sia avviato prima che il trasporto interno si connetta.

#### Costruttore

```dart
TorTransportDecorator({
  required TransportInterface inner,
  required TorManager torManager,
})
```

Implementa `TransportInterface`. Il getter `isAvailable` richiede sia la disponibilità di Tor che quella del trasporto interno.

---

### `OutboxWorker`

> Elabora la coda outbox in ordine causale (HLC).

#### Costruttore

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

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| isRunning | `bool` | Se il ciclo di lavoro è attivo |
| sentCount | `int` | Totale eventi inviati dalla creazione |
| failedCount | `int` | Totale invii falliti dalla creazione |
| pendingCount | `Future<int>` | Conteggio pendente corrente |

#### Metodi

##### `start()`

> Avvia il ciclo di lavoro, elaborando batch fino all'arresto o al vuoto.

```dart
Future<void> start()
```

##### `stop()`

> Ferma il worker dopo il batch corrente.

```dart
void stop()
```

##### `processNow()`

> Forza l'elaborazione immediata di un batch.

```dart
Future<int> processNow()
```

##### `processBatch()`

> Elabora un batch di eventi pronti per l'invio in ordine HLC.

```dart
Future<int> processBatch()
```

---

### `OutboxStore`

> Interfaccia astratta per la persistenza dell'outbox.

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

> Una voce dell'outbox pronta per essere inviata.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| eventId | `String` | ID dell'evento da inviare |
| status | `String` | `pending`, `failed`, `sent` o `abandoned` |
| retryCount | `int` | Numero di retry effettuati finora |
| createdAt | `DateTime` | Quando la voce è stata creata |
| nextRetryAt | `DateTime?` | Quando effettuare il prossimo retry (per le voci fallite) |

---

### `EventStore`

> Interfaccia astratta per il recupero degli eventi per ID.

```dart
abstract class EventStore {
  Future<StoredEvent?> getEvent(String eventId);
  Future<List<StoredEvent>> getEventsByIds(List<String> eventIds);
}
```

---

### `StoredEvent`

> Dati dell'evento pre-serializzati dallo store.

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| eventId | `String` | ID dell'evento |
| senderPubkey | `String` | Chiave pubblica del mittente codificata in esadecimale |
| serializedBytes | `Uint8List` | Dati dell'evento pre-serializzati |
| hlcTimestamp | `String` | Timestamp HLC per l'ordinamento causale |
| hlcCounter | `int` | Contatore HLC per l'ordinamento causale |

---

### `EmailTransport`

> Trasporto basato su email che utilizza SMTP per l'invio e IMAP per la ricezione. Fallback quando i relay Nostr non sono disponibili.

#### Costruttore

```dart
EmailTransport({
  required EmailConfig config,
  required EmailEncoder encoder,
  required ImapWatcher watcher,
  required SmtpSender smtpSender,
})
```

Implementa `TransportInterface`. Fornisce anche:

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

> Codifica `TransportMessage` come email MIME con allegato binario e decodifica il risultato.

#### Metodi Statici

##### `subjectPattern(String pubkeyShort)`

> Restituisce il pattern dell'oggetto email Styx: `[STYX:v1:a1b2c3d4]`.

```dart
static String subjectPattern(String pubkeyShort)
```

#### Metodi

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

**Ritorna:** `null` se l'email non è un messaggio Styx valido.

---

### `ImapWatcher`

> Monitora una casella di posta per i messaggi Styx in arrivo tramite IMAP IDLE o polling.

#### Costruttore

```dart
ImapWatcher({
  required ImapClientAdapter client,
  required String subjectFilter,
  Duration pollingInterval = const Duration(seconds: 60),
})
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| messages | `Stream<MimeMessage>` | Messaggi Styx in arrivo |
| isConnected | `bool` | Se il watcher è connesso |

#### Metodi

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

> Serializza e deserializza `TransportMessage` da/verso byte.

#### Metodi

##### `serialize(TransportMessage message)`

```dart
Uint8List serialize(TransportMessage message)
```

##### `deserialize(Uint8List bytes)`

```dart
TransportMessage deserialize(Uint8List bytes)
```

---

## 8. Riferimento API — push_bridge_client

Package: `package:styx_push_bridge_client/styx_push_bridge_client.dart`

### `PrivacyProfile`

> Profilo di privacy per il comportamento delle notifiche push.

```dart
enum PrivacyProfile { balanced, private, paranoid }
```

| Valore | Descrizione | Batteria | Privacy |
|--------|-------------|----------|---------|
| `balanced` | Solo push reali | Zero extra | Bassa (timing visibile al provider) |
| `private` | Dummy con distribuzione di Poisson (~4-6/giorno), nessuna rete al risveglio per i dummy | Minima | Media (pattern temporali mascherati) |
| `paranoid` | Dummy con connessioni reali ai relay | Misurabile | Alta (pattern di traffico completamente mascherati) |

#### Metodi Statici

##### `PrivacyProfile.fromString(String value)`

> Analizza dalla stringa del nome, default `balanced`.

```dart
static PrivacyProfile fromString(String value)
```

---

### `PushBridgeClient`

> Client HTTP per la registrazione/cancellazione presso il server Push Bridge.

#### Costruttore

```dart
PushBridgeClient({
  required String bridgeUrl,
  required BridgeHttpClient httpClient,
})
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| bridgeUrl | `String` | URL del server bridge configurato |

#### Metodi

##### `register({...})`

> Registra il dispositivo presso il push bridge.

```dart
Future<void> register({
  required String fcmToken,
  required String nostrPubkey,
  required PrivacyProfile profile,
  String platform = 'android',
})
```

##### `unregister({required String fcmToken})`

> Cancella la registrazione del dispositivo.

```dart
Future<void> unregister({required String fcmToken})
```

##### `updateProfile({...})`

> Aggiorna il profilo di privacy (ri-registra con il nuovo profilo).

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

> Client HTTP astratto per la comunicazione con il push bridge.

```dart
abstract class BridgeHttpClient {
  Future<int> post(String path, Map<String, dynamic> body);
  Future<String> get(String path);
}
```

---

### `PushHandler`

> Gestisce le notifiche push in arrivo in base al profilo di privacy configurato.

#### Costruttore

```dart
PushHandler({
  required PrivacyProfile profile,
  required WakeUpCallback onWakeUp,
  required WakeUpCallback onConnectRelay,
  TokenRefreshCallback? onTokenRefresh,
  DummyDetector? detector,
})
```

| Parametro | Tipo | Obbligatorio | Descrizione |
|-----------|------|--------------|-------------|
| profile | `PrivacyProfile` | Sì | Profilo di privacy attivo |
| onWakeUp | `WakeUpCallback` | Sì | Invocato per le push reali |
| onConnectRelay | `WakeUpCallback` | Sì | Invocato per le push dummy in modalità paranoid |
| onTokenRefresh | `TokenRefreshCallback?` | No | Invocato al rinnovo del token FCM/APNs |
| detector | `DummyDetector?` | No | Rilevatore di dummy (default: `const DummyDetector()`) |

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| profile | `PrivacyProfile` | Profilo attivo |
| realCount | `int` | Risvegli reali elaborati |
| dummyCount | `int` | Notifiche dummy rilevate |
| connectCount | `int` | Connessioni totali ai relay (reali + dummy paranoid) |

#### Metodi

##### `handleMessage(Map<String, dynamic> data)`

> Instrada una notifica push in base al profilo. Balanced: ignora i dummy. Private: scarta i dummy silenziosamente. Paranoid: si connette al relay anche per i dummy.

```dart
Future<void> handleMessage(Map<String, dynamic> data)
```

##### `handleTokenRefresh(String newToken)`

```dart
Future<void> handleTokenRefresh(String newToken)
```

---

### `DummyDetector`

> Rileva le notifiche push dummy controllando la presenza di `{"d": "1"}` nel payload dei dati.

#### Costruttore

```dart
const DummyDetector()
```

#### Metodi

##### `isDummy(Map<String, dynamic> data)`

```dart
bool isDummy(Map<String, dynamic> data)
```

**Ritorna:** `true` se `data['d'] == '1'`.

---

### `WakeUpOrchestrator`

> Orchestratore del flusso completo di risveglio: connetti → scarica → inserisci → outbox → disconnetti.

#### Costruttore

```dart
WakeUpOrchestrator({
  required TransportInterface transport,
  required LedgerOperations ledger,
  required OutboxProcessor outbox,
  Duration downloadTimeout = const Duration(seconds: 10),
})
```

#### Proprietà

| Nome | Tipo | Descrizione |
|------|------|-------------|
| isRunning | `bool` | Se un risveglio è in corso |
| lastDownloadCount | `int` | Eventi scaricati nell'ultimo risveglio |
| lastOutboxCount | `int` | Eventi outbox inviati nell'ultimo risveglio |

#### Metodi

##### `handleWakeUp()`

> Esegue la sequenza completa di risveglio. Restituisce il totale degli eventi elaborati.

```dart
Future<int> handleWakeUp()
```

---

### `LedgerOperations`

> Interfaccia astratta per le operazioni del ledger durante il risveglio.

```dart
abstract class LedgerOperations {
  Future<int> insertEvents(List<TransportMessage> events);
  Future<String?> lastKnownTimestamp();
}
```

---

### `OutboxProcessor`

> Interfaccia astratta per l'elaborazione dell'outbox durante il risveglio.

```dart
abstract class OutboxProcessor {
  Future<int> processPending();
  Future<int> pendingCount();
}
```

---

### `PushMessagingService`

> Interfaccia astratta per il servizio di messaggistica push (avvolge Firebase Messaging in produzione).

```dart
abstract class PushMessagingService {
  Future<String?> getToken();
  Stream<String> get onTokenRefresh;
}
```

---

### Tipi di Callback

```dart
typedef WakeUpCallback = Future<void> Function();
typedef TokenRefreshCallback = Future<void> Function(String newToken);
```

---

## 9. Riferimento API — push_bridge_server (REST)

Il **Push Bridge Server** è l'unico componente HTTP nell'architettura Styx. È un microservizio Go stateless che si colloca nel **Reliability Layer** — si iscrive ai relay Nostr per gli eventi corrispondenti alle chiavi pubbliche registrate e invia notifiche push data-only tramite FCM/APNs per risvegliare l'applicazione client.

### Panoramica

- **Linguaggio:** Go
- **Storage:** Solo in memoria (tutte le registrazioni vengono perse al riavvio)
- **Autenticazione:** Nessuna (progettato per il deployment in rete trusted)
- **Router:** `gorilla/mux`
- **Shutdown graceful:** Ascolta `SIGINT` / `SIGTERM`, cancella le goroutine in background, quindi chiama `http.Server.Shutdown`

### Configurazione

| Variabile d'ambiente | Default | Descrizione |
|----------------------|---------|-------------|
| `BRIDGE_ADDR` | `:8080` | Indirizzo e porta su cui il server HTTP si mette in ascolto |

| Parametro del server | Valore |
|----------------------|--------|
| `ReadTimeout` | 5 s |
| `WriteTimeout` | 10 s |

### Endpoint

#### `POST /register`

Registra (o aggiorna) un dispositivo per le notifiche push. Idempotente — se esiste già una registrazione con lo stesso `fcm_token`, viene sovrascritta (upsert). Dopo la registrazione, il server si iscrive al `nostr_pubkey` del dispositivo sul pool di relay Nostr.

**Corpo della richiesta** (`Content-Type: application/json`):

| Campo | Tipo | Obbligatorio | Default | Descrizione |
|-------|------|--------------|---------|-------------|
| `fcm_token` | `string` | Sì | — | Token dispositivo FCM/APNs |
| `nostr_pubkey` | `string` | Sì | — | Chiave pubblica Nostr in formato esadecimale a cui iscriversi |
| `platform` | `string` | No | `"android"` | `"android"` o `"ios"` |
| `privacy_profile` | `string` | No | `"balanced"` | `"balanced"`, `"private"` o `"paranoid"` |

**Profili di privacy e comportamento dei push dummy:**

| Profilo | Lambda Poisson | Frequenza approx. | Comportamento |
|---------|----------------|-------------------|---------------|
| `balanced` | 0 | Nessun dummy | Solo push reali |
| `private` | 1/150 (~0.0067) | ~4–6 al giorno | Push dummy con distribuzione di Poisson; nessuna attività di rete al risveglio dummy |
| `paranoid` | 1/30 (~0.033) | ~48 al giorno | Push dummy con distribuzione di Poisson; connessioni reali ai relay al risveglio dummy |

**Risposta `200 OK`** (`Content-Type: application/json`):

```json
{"status": "ok"}
```

**Risposta `400 Bad Request`** (`Content-Type: text/plain; charset=utf-8`):

Restituita quando il corpo della richiesta non è JSON valido o quando mancano i campi obbligatori.

```
{"error":"invalid json"}
```

```
{"error":"fcm_token and nostr_pubkey required"}
```

> **Nota:** Le risposte di errore utilizzano `http.Error()` in Go, che imposta `Content-Type: text/plain; charset=utf-8` anche se il corpo è in formato JSON. I client non devono basarsi sul `Content-Type` per distinguere successo da errore — utilizzare il codice di stato HTTP.

**Esempio:**

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

Rimuove la registrazione di un dispositivo tramite token FCM. Se il token non viene trovato, l'operazione è un no-op silenzioso (restituisce comunque `200 OK`).

**Corpo della richiesta** (`Content-Type: application/json`):

| Campo | Tipo | Obbligatorio | Descrizione |
|-------|------|--------------|-------------|
| `fcm_token` | `string` | Sì | Token dispositivo FCM/APNs da deregistrare |

**Risposta `200 OK`** (`Content-Type: application/json`):

```json
{"status": "ok"}
```

**Risposta `400 Bad Request`** (`Content-Type: text/plain; charset=utf-8`):

```
{"error":"invalid json"}
```

```
{"error":"fcm_token required"}
```

> **Nota:** Stessa particolarità del `Content-Type` di `/register` — i corpi degli errori sono in formato JSON ma serviti come `text/plain`.

**Esempio:**

```bash
curl -X POST http://localhost:8080/unregister \
  -H "Content-Type: application/json" \
  -d '{"fcm_token": "dGVzdF90b2tlbg=="}'
```

---

#### `GET /health`

Restituisce lo stato di salute del server e il numero attuale di registrazioni in memoria.

**Risposta `200 OK`** (`Content-Type: application/json`):

```json
{"status": "ok", "registrations": 42}
```

**Esempio:**

```bash
curl http://localhost:8080/health
```

### Tipi di Dati

#### Registration

| Campo | Chiave JSON | Tipo | Valori Enum | Default |
|-------|-------------|------|-------------|---------|
| `FCMToken` | `fcm_token` | `string` | — | — |
| `NostrPubkey` | `nostr_pubkey` | `string` | — | — |
| `Platform` | `platform` | `string` | `"android"`, `"ios"` | `"android"` |
| `PrivacyProfile` | `privacy_profile` | `string` | `"balanced"`, `"private"`, `"paranoid"` | `"balanced"` |

#### SuccessResponse

```json
{"status": "ok"}
```

Restituita da `POST /register`, `POST /unregister`.

#### HealthResponse

```json
{"status": "ok", "registrations": <int>}
```

Restituita da `GET /health`. Il campo `registrations` riflette la dimensione attuale dello store in memoria.

#### ErrorResponse

```
{"error": "<messaggio>"}
```

Restituita con HTTP `400`. Il corpo è in formato JSON ma il `Content-Type` è `text/plain; charset=utf-8` (comportamento di `http.Error()` in Go).

### Payload delle Notifiche Push

Il server invia notifiche push **data-only** (nessun avviso visibile). Lo schema del payload è rigorosamente validato — sono ammesse solo le chiavi elencate di seguito.

#### PushPayload

| Chiave | Tipo | Presente | Descrizione |
|--------|------|----------|-------------|
| `styx` | `string` | Sempre | Valore fisso `"wake"` — segnala al client di sincronizzarsi |
| `ts` | `string` | Sempre | Timestamp Unix (secondi) come stringa |
| `d` | `string` | Solo dummy | `"1"` se è un push dummy; assente per i push reali |

**Esempio di push reale:**

```json
{"styx": "wake", "ts": "1711036800"}
```

**Esempio di push dummy:**

```json
{"styx": "wake", "ts": "1711036800", "d": "1"}
```

**Validazione del payload:** La funzione `ValidatePayload` rifiuta qualsiasi payload contenente chiavi diverse da `styx`, `ts` e `d`. Questo garantisce che nessun dato sensibile venga mai trasmesso tramite notifiche push.

### Servizi in Background

#### NostrSubscriber

Eseguito come goroutine in background. Si iscrive ai relay Nostr e ascolta gli eventi in cui il tag `p` corrisponde a una chiave pubblica registrata. Quando viene ricevuto un evento corrispondente, invia una notifica push di risveglio a tutti i dispositivi registrati per quella chiave pubblica.

#### DummyScheduler

Eseguito come goroutine in background con un **ticker di 1 secondo**. Ad ogni tick, itera su tutte le registrazioni e, per ogni registrazione con un lambda del profilo di privacy diverso da zero, genera un ritardo casuale con distribuzione di Poisson. Se il ritardo è inferiore a 1 secondo, viene inviata una notifica push dummy.

| Profilo | Lambda | Intervallo Medio |
|---------|--------|-----------------|
| `balanced` | 0 | Nessun dummy inviato |
| `private` | 1/150 | ~150 secondi (~2,5 minuti) |
| `paranoid` | 1/30 | ~30 secondi |

---

## 10. Glossario

| Termine | Definizione |
|---------|------------|
| **Affidante** | Uno dei due peer in un ledger Styx (dall'italiano "colui che affida") |
| **Custode** | L'altro peer in un ledger Styx (dall'italiano "colui che custodisce") |
| **BIP-39** | Bitcoin Improvement Proposal 39 — codice mnemonico per la generazione deterministica di chiavi |
| **Blessing** | Un evento REKEY in cui la vecchia chiave approva una nuova chiave per la migrazione del dispositivo |
| **Chain hash** | `SHA-256(previousHash \|\| eventType \|\| payload \|\| hlcBytes)` |
| **Double Check** | Codice di verifica a 6 cifre derivato dalla chiave di sessione SPAKE2, confrontato verbalmente |
| **Ed25519** | Algoritmo di firma digitale a curva ellittica utilizzato per tutte le firme Styx |
| **Fork** | Quando due peer creano eventi concorrenti dallo stesso antenato |
| **GF(256)** | Campo di Galois utilizzato nell'aritmetica dello schema di condivisione del segreto di Shamir |
| **Genesis** | Il primo evento in una catena (`previousHash` nullo, tipo `config`) |
| **HLC** | Hybrid Logical Clock — combina tempo wall-clock con contatore logico |
| **Evento MERGE** | Evento che linearizza un fork, facendo riferimento a entrambi i tip dei rami |
| **Nonce** | Valore casuale di 16 byte nel pairing QR per la protezione anti-replay |
| **NIP-44** | Protocollo Nostr per i messaggi diretti crittografati |
| **Node ID** | Primi 8 caratteri esadecimali della chiave pubblica di un peer |
| **Nostr** | Protocollo di trasporto primario che utilizza connessioni WebSocket ai relay |
| **Ruolo del peer** | `'A'` o `'B'`, assegnato tramite ordinamento lessicografico delle chiavi pubbliche al pairing |
| **Pruning** | Annullamento del payload dell'evento preservando l'integrità della catena di hash |
| **Push Bridge** | Microservizio Go stateless che si iscrive ai relay Nostr e invia notifiche push FCM/APNs |
| **Policy di retention** | Regola temporale per il pruning automatico di specifici tipi di evento |
| **SPAKE2** | Scambio di chiavi autenticato tramite password su P-256, usato nel pairing remoto |
| **Shamir SSS** | Schema di condivisione del segreto di Shamir — suddivide un segreto in N share, qualsiasi K lo ricostruisce |
| **SOCKS5** | Protocollo proxy utilizzato da Tor per l'instradamento del trasporto |
| **Vector clock** | Contatore a 2 elementi `(a, b)` che traccia l'ordinamento causale tra i peer |
| **X25519** | Curva ellittica Diffie-Hellman utilizzata per lo scambio di chiavi e la crittografia dei messaggi |
