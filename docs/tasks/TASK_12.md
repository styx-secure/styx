# Task 12 — Façade Pubblica + Integration Test End-to-End

**Stato:** Da iniziare
**Durata stimata:** 3-5 giorni
**Dipendenze:** Tutti i task precedenti (0-11)
**Package:** `packages/styx/` (completamento), `test_integration/`
**Coverage target:** ≥ 90% globale

---

## Obiettivo

Creare l'API pubblica unificata della libreria Styx (singolo entry point per le app consumer), completare la documentazione dartdoc, e implementare la suite completa di test end-to-end che valida ogni scenario reale: pairing, transazioni, offline sync, pruning, SOS, re-keying, e stress testing.

---

## Dipendenze Interne

```yaml
# packages/styx/pubspec.yaml
dependencies:
  styx_crypto_core: {path: ../crypto_core}
  styx_storage: {path: ../storage}
  styx_ledger_engine: {path: ../ledger_engine}
  styx_transport: {path: ../transport}
  styx_push_bridge_client: {path: ../push_bridge_client}
  meta: ^1.16.0
  flutter:
    sdk: flutter
```

---

## PARTE A: Façade Pubblica

### 1. `SovereignLedger` — `lib/src/sovereign_ledger.dart`

Entry point unico della libreria. Espone tutte le operazioni ad alto livello.

```dart
class SovereignLedger {
  SovereignLedger._({
    required this.identity,
    required this.config,
    required LedgerService ledgerService,
    required TransportFailover transport,
    required OutboxWorker outboxWorker,
    required TrustStoreManager trustStore,
    required PushBridgeClient pushBridge,
    required QrPairingService qrPairing,
    required RemotePairingService remotePairing,
    required ReKeyProtocol reKeyProtocol,
    required KeyMigrationService migrationService,
    required ShamirBackupService backupService,
    required RetentionManager retentionManager,
  });

  /// Identità corrente (pubkey + ruolo)
  final StyxIdentity identity;

  /// Configurazione corrente
  final LedgerConfig config;

  // ─── LIFECYCLE ──────────────────────────────────────────────────

  /// Inizializza la libreria Styx
  ///
  /// 1. Apre (o crea) il database cifrato
  /// 2. Carica (o genera) l'identità dal SecureKeyStore
  /// 3. Valida l'integrità della catena
  /// 4. Connette ai relay Nostr (se configurati)
  /// 5. Registra al Push Bridge (se configurato)
  /// 6. Avvia l'OutboxWorker
  ///
  /// Questa è l'unica operazione necessaria per avviare Styx.
  static Future<SovereignLedger> init({
    required LedgerConfig config,
    StyxKeyPair? existingKeyPair,
  });

  /// Arresta Styx in modo pulito
  /// Disconnette dai relay, ferma l'outbox worker, chiude il database
  Future<void> shutdown();

  /// Stato corrente della libreria
  StyxState get state;
  Stream<StyxState> get stateStream;

  // ─── PAIRING ────────────────────────────────────────────────────

  /// Genera QR code data per pairing fisico
  Future<QrPairingData> generatePairingQr({List<String>? relayHints});

  /// Processa un QR code scansionato dal peer
  Future<PairingResult> processPairingQr(String qrPayload);

  /// Avvia pairing remoto come initiator (genera mnemonic)
  Future<String> startRemotePairing({int wordCount = 6});

  /// Avvia pairing remoto come responder (inserisci mnemonic ricevuto)
  Future<void> joinRemotePairing(String mnemonic);

  /// Ottieni il Double Check code per verifica MITM
  String? getDoubleCheckCode();

  /// Conferma il Double Check e completa il pairing
  Future<void> confirmPairing({
    required bool codeMatches,
    String? peerAlias,
  });

  /// Stato del peer abbinato (null se non ancora paired)
  Future<TrustedPeer?> getPeer();

  // ─── TRANSAZIONI ────────────────────────────────────────────────

  /// Registra una transazione finanziaria
  ///
  /// [payload] — dati della transazione (importo, descrizione, foto scontrino...)
  /// cifrati automaticamente prima della persistenza
  Future<LedgerEvent> sendTransaction(Uint8List payload);

  /// Invia un messaggio generico al peer
  Future<LedgerEvent> sendMessage(Uint8List payload);

  /// Invia un segnale SOS (priorità alta)
  Future<LedgerEvent> sendSOS(Uint8List payload);

  /// Modifica configurazione condivisa
  Future<LedgerEvent> sendConfig(Uint8List payload);

  // ─── HISTORY ────────────────────────────────────────────────────

  /// Recupera la storia completa degli eventi
  Future<List<LedgerEvent>> getHistory();

  /// Recupera gli eventi in un range temporale
  Future<List<LedgerEvent>> getHistoryRange({
    required DateTime from,
    required DateTime to,
  });

  /// Stream reattivo di nuovi eventi (locali + ricevuti)
  Stream<LedgerEvent> get eventStream;

  /// Valida l'integrità dell'intera catena
  /// Restituisce null se tutto OK, altrimenti il primo errore trovato
  Future<ChainValidationError?> validateChain();

  // ─── PRIVACY & GDPR ────────────────────────────────────────────

  /// Imposta il profilo privacy per le notifiche push
  Future<void> setPrivacyProfile(PrivacyProfile profile);

  /// Profilo privacy corrente
  PrivacyProfile get privacyProfile;

  /// Richiede la cancellazione di un evento (GDPR Art. 17)
  /// Avvia il protocollo bilaterale PRUNE_REQUEST → PRUNE_ACK
  Future<LedgerEvent> requestPrune({
    required String targetEventId,
    PruneReason reason = PruneReason.userRequest,
  });

  /// Imposta la retention policy per cancellazione automatica
  Future<void> setRetentionPolicy({
    required Duration retentionPeriod,
    required List<EventType> applicableTypes,
  });

  // ─── DEVICE MIGRATION ──────────────────────────────────────────

  /// Crea un backup dell'identità come share Shamir
  Future<List<String>> createIdentityBackup({
    int threshold = 2,
    int totalShares = 3,
  });

  /// Ripristina l'identità da share Shamir
  /// Usare con `init(existingKeyPair: restored)` dopo il restore
  static Future<StyxKeyPair> restoreIdentity(List<String> shares);

  /// Avvia la migrazione a un nuovo device (lato vecchio device)
  /// [newDevicePublicKey] — la pubkey del nuovo device (ricevuta via QR)
  Future<void> blessNewDevice(StyxPublicKey newDevicePublicKey);

  /// Completa la migrazione (lato nuovo device)
  Future<void> completeMigration();
}
```

### 2. `LedgerConfig` — `lib/src/config/ledger_config.dart`

```dart
@immutable
class LedgerConfig {
  const LedgerConfig({
    this.databasePath,
    this.relayUrls = const ['wss://relay.damus.io', 'wss://nos.lol'],
    this.emailConfig,
    this.pushBridgeUrl,
    this.privacyProfile = PrivacyProfile.balanced,
    this.retentionPeriod,
    this.retentionTypes = const [EventType.transaction],
    this.enableTor = false,
    this.torTimeout = const Duration(seconds: 120),
    this.logLevel = LogLevel.warning,
  });

  /// Percorso del database SQLCipher (null = default platform path)
  final String? databasePath;

  /// URL dei relay Nostr
  final List<String> relayUrls;

  /// Configurazione email per fallback transport (opzionale)
  final EmailConfig? emailConfig;

  /// URL del Push Bridge server (opzionale)
  final String? pushBridgeUrl;

  /// Profilo privacy per notifiche push
  final PrivacyProfile privacyProfile;

  /// Periodo di retention per auto-pruning (null = disabilitato)
  final Duration? retentionPeriod;

  /// Tipi di evento soggetti a retention
  final List<EventType> retentionTypes;

  /// Abilita routing via Tor
  final bool enableTor;

  /// Timeout bootstrap Tor
  final Duration torTimeout;

  /// Livello di logging
  final LogLevel logLevel;
}

enum LogLevel { none, error, warning, info, debug }
```

### 3. `StyxIdentity` — `lib/src/config/styx_identity.dart`

```dart
@immutable
class StyxIdentity {
  const StyxIdentity({
    required this.publicKey,
    required this.nodeId,
    required this.peerRole,
  });

  /// Chiave pubblica Ed25519
  final StyxPublicKey publicKey;

  /// Node ID per HLC (primi 8 char hex della pubkey)
  final String nodeId;

  /// Ruolo del peer (A o B, determinato al pairing)
  final String peerRole;
}
```

### 4. `StyxState` — `lib/src/config/styx_state.dart`

```dart
enum StyxState {
  /// Non ancora inizializzato
  uninitialized,

  /// Inizializzazione in corso
  initializing,

  /// Pronto ma senza peer abbinato
  unpaired,

  /// Pronto con peer abbinato, connesso
  ready,

  /// Connesso ma con problemi di trasporto
  degraded,

  /// Pairing in corso
  pairing,

  /// Migrazione device in corso
  migrating,

  /// Errore critico (database corrotto, chiave persa)
  error,

  /// Shutdown in corso
  shuttingDown,
}
```

### 5. `LedgerEventStream` — `lib/src/streams/ledger_event_stream.dart`

```dart
class LedgerEventStream {
  LedgerEventStream({
    required EventDao eventDao,
    required TransportInterface transport,
  });

  /// Stream unificato: eventi locali + eventi ricevuti dal peer
  Stream<LedgerEvent> get allEvents;

  /// Solo eventi creati localmente
  Stream<LedgerEvent> get localEvents;

  /// Solo eventi ricevuti dal peer
  Stream<LedgerEvent> get remoteEvents;

  /// Solo eventi di un tipo specifico
  Stream<LedgerEvent> eventsByType(EventType type);

  /// Filtro per data
  Stream<LedgerEvent> eventsAfter(DateTime after);
}
```

### 6. Barrel Export Completo — `lib/styx.dart`

```dart
/// Styx — Sovereign P2P cryptographic ledger.
///
/// Oaths sealed in code. Trust forged in math.
library styx;

// Façade
export 'src/sovereign_ledger.dart';
export 'src/config/ledger_config.dart';
export 'src/config/styx_identity.dart';
export 'src/config/styx_state.dart';
export 'src/streams/ledger_event_stream.dart';

// Re-export tipi necessari per l'API pubblica
export 'package:styx_crypto_core/styx_crypto_core.dart'
    show StyxPublicKey, StyxKeyPair, ShamirShare;
export 'package:styx_ledger_engine/styx_ledger_engine.dart'
    show LedgerEvent, EventType, ChainValidationError;
export 'package:styx_transport/styx_transport.dart'
    show EmailConfig;
export 'package:styx_push_bridge_client/styx_push_bridge_client.dart'
    show PrivacyProfile;

// Pairing
export 'src/pairing/qr_pairing_data.dart';
export 'src/pairing/qr_pairing_service.dart' show PairingResult;
export 'src/pairing/remote_pairing_service.dart' show RemotePairingState;
export 'src/trust/trust_store_manager.dart' show TrustedPeer;

// Pruning
export 'package:styx_ledger_engine/styx_ledger_engine.dart'
    show PruneReason;
```

---

## PARTE B: Integration Test End-to-End

Tutti i test di integrazione risiedono in `test_integration/` e simulano scenari reali con due peer.

### Infrastruttura di Test

```dart
/// Crea due istanze SovereignLedger con database in-memory
/// connesse tramite un transport mock bidirezionale
class StyxTestHarness {
  late SovereignLedger peerA;
  late SovereignLedger peerB;
  late MockBidirectionalTransport transport;

  Future<void> setup();
  Future<void> teardown();

  /// Simula il pairing tra i due peer
  Future<void> performQrPairing();

  /// Simula disconnessione di un peer
  Future<void> disconnectPeer(String peer);

  /// Simula riconnessione
  Future<void> reconnectPeer(String peer);

  /// Forza il processing outbox (simula push wake-up)
  Future<void> triggerSync();
}
```

### Scenario Test: `test_integration/e2e_transaction_test.dart`

| # | Test | Scenario | Aspettativa |
|---|------|----------|-------------|
| E2E.1 | Happy path completo | Init → QR pair → A invia 100 transazioni → B le riceve | B vede tutte 100, chain valida su entrambi |
| E2E.2 | Bidirezionale | A invia 50, B invia 50 | Entrambi vedono 100 eventi nello stesso ordine |
| E2E.3 | Tipi misti | 30 TRANSACTION + 10 MESSAGE + 5 CONFIG + 1 SOS | Tutti gli eventi presenti, tipi corretti |

### Scenario Test: `test_integration/e2e_offline_test.dart`

| # | Test | Scenario | Aspettativa |
|---|------|----------|-------------|
| E2E.4 | Offline unilaterale | A crea 10 eventi offline → reconnect → sync | B riceve tutti 10 |
| E2E.5 | Offline bilaterale (fork) | A crea 10 offline, B crea 10 offline → reconnect | Merge deterministico, entrambi vedono 20 nello stesso ordine |
| E2E.6 | Offline bilaterale asimmetrico | A crea 3 offline, B crea 50 offline → reconnect | Merge corretto, 53 eventi |
| E2E.7 | Offline prolungato | A crea 1000 eventi offline → reconnect | Sync completo < 10 secondi |
| E2E.8 | Multipli fork/merge | 5 cicli di disconnect → eventi → reconnect → merge | Chain valida dopo ogni ciclo |

### Scenario Test: `test_integration/e2e_pruning_test.dart`

| # | Test | Scenario | Aspettativa |
|---|------|----------|-------------|
| E2E.9 | Pruning bilaterale | A invia foto scontrino → A richiede prune → B conferma | Payload rimosso su entrambi, hash preservato, chain valida |
| E2E.10 | Pruning unilaterale (Art. 17) | A richiede prune → B non risponde → A prune locale | Payload A rimosso, B ha ancora il payload, chain valida su entrambi |
| E2E.11 | Retention automatica | Retention 1 giorno, eventi di 2 giorni fa | Auto-prune request inviato |
| E2E.12 | Pruning + merge | Fork → merge → prune evento nel branch → validate | Chain valida |

### Scenario Test: `test_integration/e2e_sos_test.dart`

| # | Test | Scenario | Aspettativa |
|---|------|----------|-------------|
| E2E.13 | SOS delivery | A invia SOS | B lo riceve, evento tipo SOS |
| E2E.14 | SOS durante offline | A invia SOS, B offline → reconnect | B riceve SOS al sync |

### Scenario Test: `test_integration/e2e_rekey_test.dart`

| # | Test | Scenario | Aspettativa |
|---|------|----------|-------------|
| E2E.15 | Re-key completo | Pair → 10 eventi → re-key A → 10 eventi con nuova chiave | Chain valida, 20 eventi + REKEY, nuova chiave trusted |
| E2E.16 | Re-key + merge | A re-key offline, B crea eventi offline → merge | Chain valida con REKEY nel branch |
| E2E.17 | Doppio re-key | A re-key → 5 eventi → A re-key di nuovo → 5 eventi | Chain valida, trust store aggiornato 2 volte |

### Scenario Test: `test_integration/e2e_backup_test.dart`

| # | Test | Scenario | Aspettativa |
|---|------|----------|-------------|
| E2E.18 | Backup + restore | Pair → 20 eventi → backup → delete identity → restore → resume | Chain continua, nuovi eventi firmati con stessa chiave |
| E2E.19 | Backup share insufficienti | Tentativo restore con 1 share su threshold 2 | Errore gestito |

### Scenario Test: `test_integration/e2e_pairing_test.dart`

| # | Test | Scenario | Aspettativa |
|---|------|----------|-------------|
| E2E.20 | QR pairing completo | A genera QR → B scansiona → B genera QR → A scansiona | Entrambi paired |
| E2E.21 | Remote pairing completo | A genera mnemonic → B inserisce → SPAKE2 → Double Check → OK | Entrambi paired |
| E2E.22 | Remote pairing MITM | Attaccante intercetta → Double Check diversi | Pairing rifiutato |

### Scenario Test: `test_integration/e2e_transport_test.dart`

| # | Test | Scenario | Aspettativa |
|---|------|----------|-------------|
| E2E.23 | Failover Nostr → Email | Nostr down → invio via email → ricezione | Evento ricevuto via email |
| E2E.24 | Tutto via Tor | Tor abilitato → tutti gli scenari | Funzionamento identico ma via Tor |
| E2E.25 | Transport recovery | Nostr down → Email down → eventi in outbox → Nostr up → sync | Outbox svuotato |

### Stress Test: `test_integration/e2e_stress_test.dart`

| # | Test | Scenario | Aspettativa |
|---|------|----------|-------------|
| E2E.26 | 10.000 eventi | A invia 10.000 transazioni | Chain valida, validateChain < 2 secondi |
| E2E.27 | 10.000 eventi bidirezionali | A e B inviano 5.000 ciascuno | 10.000 eventi, merge corretto |
| E2E.28 | Bulk sync | A ha 10.000 eventi, B è nuovo → sync | B riceve tutti in < 30 secondi |

### Fuzzing Test: `test_integration/e2e_fuzzing_test.dart`

| # | Test | Scenario | Aspettativa |
|---|------|----------|-------------|
| E2E.29 | Payload random | 1000 payload random (0 - 100KB) | Tutti processati, chain valida |
| E2E.30 | Timestamp futuri | Evento con timestamp +1 anno | Gestito da HLC (clock drift), nessun crash |
| E2E.31 | Firma corrotta ricevuta | Evento con firma random | Rifiutato, chain non alterata |
| E2E.32 | Hash chain corrotta ricevuta | Evento con previousHash sbagliato | Rifiutato |
| E2E.33 | EventType sconosciuto | Tipo non nell'enum | Errore gestito, nessun crash |
| E2E.34 | Database corrotto al boot | Flip random byte nel DB file | Errore rilevato al init, stato → error |

---

## PARTE C: Documentazione

### Dartdoc

Ogni classe, metodo e proprietà dell'API pubblica (`SovereignLedger`, `LedgerConfig`, `StyxState`, etc.) deve avere documentazione dartdoc completa con:
- Descrizione del comportamento
- Parametri documentati
- Valori di ritorno documentati
- Eccezioni possibili documentate
- Esempio d'uso per i metodi principali

### Esempio d'uso nel README

```dart
import 'package:styx/styx.dart';

// Inizializza
final styx = await SovereignLedger.init(
  config: LedgerConfig(
    relayUrls: ['wss://relay.damus.io'],
    privacyProfile: PrivacyProfile.private,
  ),
);

// Pairing
final qr = await styx.generatePairingQr();
// ... mostra QR al peer ...

// Transazione
await styx.sendTransaction(utf8.encode('{"amount": 42.50, "desc": "Cena"}'));

// Storia
final history = await styx.getHistory();

// Pruning GDPR
await styx.requestPrune(targetEventId: history.last.eventId);

// Shutdown
await styx.shutdown();
```

### CHANGELOG.md

Creare il CHANGELOG con tutte le feature implementate per la v0.1.0.

---

## Test Specification — Façade Unit Test

### Unit Test: `test/sovereign_ledger_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T12.1 | Init con config minima | Solo relayUrls | Stato → unpaired |
| T12.2 | Init con keypair esistente | existingKeyPair fornito | Identità caricata, non generata |
| T12.3 | Init + chain validation | DB con eventi validi | Stato → ready (se paired) o unpaired |
| T12.4 | Init con DB corrotto | DB con hash chain rotta | Stato → error, errore specifico |
| T12.5 | Shutdown | Styx attivo | Stato → shuttingDown → risorse rilasciate |
| T12.6 | SendTransaction senza peer | Unpaired | Eccezione (deve prima fare pairing) |
| T12.7 | SendTransaction con peer | Paired | Evento creato, in outbox |
| T12.8 | GetHistory vuoto | Nessun evento | Lista vuota |
| T12.9 | GetHistory con eventi | 10 eventi | 10 eventi ordinati per HLC |
| T12.10 | EventStream | 5 eventi inseriti | Stream emette 5 eventi |
| T12.11 | SetPrivacyProfile | Cambio a Paranoid | Profilo aggiornato, push bridge ri-registrato |
| T12.12 | SetRetentionPolicy | 30 giorni, solo TRANSACTION | Config salvata |
| T12.13 | CreateIdentityBackup | threshold=2, total=3 | 3 share serializzati |
| T12.14 | RestoreIdentity | 2 share validi | Keypair ricostruito |
| T12.15 | State stream | Init → pair → ready | Stati emessi nell'ordine corretto |

---

## Criteri di Completamento

- [ ] TUTTI i test di TUTTI i task (T0.x → T12.x) passano
- [ ] TUTTI i test E2E (E2E.1 → E2E.34) passano
- [ ] Coverage globale ≥ 90% su ogni package
- [ ] `melos run test:all` green
- [ ] `melos run analyze` zero warning
- [ ] API documentata al 100% (dartdoc)
- [ ] README.md aggiornato con esempio d'uso
- [ ] CHANGELOG.md per v0.1.0
- [ ] Nessun `TODO` o `FIXME` residuo nel codice
- [ ] Nessuna dipendenza con vulnerabilità note (`dart pub audit`)
