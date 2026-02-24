# Task 5 — Ledger Engine: Event Sourcing + Hash Chain

**Stato:** Da iniziare
**Durata stimata:** 3-4 giorni
**Dipendenze:** Task 1, Task 4
**Package:** `packages/ledger_engine/`
**Coverage target:** ≥ 95%

---

## Obiettivo

Implementare il motore di event sourcing: creazione, firma, hashing e validazione di eventi nella catena crittografica append-only. Implementare l'Hybrid Logical Clock per l'ordinamento causale.

---

## Dipendenze

```yaml
dependencies:
  styx_crypto_core: {path: ../crypto_core}
  styx_storage: {path: ../storage}
  crdt: ^5.4.0    # Reference per HLC (o implementazione standalone)
  meta: ^1.16.0
```

---

## Componenti da Implementare

### 1. `EventType` — `lib/src/event_type.dart`

```dart
enum EventType {
  transaction,  // Transazione finanziaria
  sos,          // Segnale di emergenza
  config,       // Modifica configurazione
  rekey,        // Migrazione device
  merge,        // Risoluzione fork
  pruneRequest, // Richiesta cancellazione GDPR
  pruneAck,     // Conferma cancellazione
  message,      // Messaggio generico
}
```

### 2. `LedgerEvent` — `lib/src/ledger_event.dart`

Modello di dominio immutabile per un evento nella catena.

```dart
@immutable
class LedgerEvent {
  const LedgerEvent({
    required this.eventId,
    required this.eventType,
    required this.payload,
    required this.previousHash,
    required this.eventHash,
    required this.hlc,
    required this.vectorClock,
    required this.senderPubkey,
    required this.signature,
    required this.createdAt,
    this.isPruned = false,
  });

  final String eventId;           // UUID v4
  final EventType eventType;
  final Uint8List? payload;       // Null se pruned
  final String? previousHash;     // Null solo per genesis
  final String eventHash;         // SHA-256 hex
  final HybridLogicalClock hlc;
  final VectorClock vectorClock;
  final String senderPubkey;      // Ed25519 pubkey hex
  final Uint8List signature;      // 64 bytes Ed25519
  final DateTime createdAt;
  final bool isPruned;
}
```

### 3. `HybridLogicalClock` — `lib/src/hlc.dart`

Implementazione HLC per ordinamento causale.

```dart
@immutable
class HybridLogicalClock implements Comparable<HybridLogicalClock> {
  const HybridLogicalClock({
    required this.timestamp,
    required this.counter,
    required this.nodeId,
  });

  final DateTime timestamp;   // Wall-clock time
  final int counter;           // Tiebreaker per eventi allo stesso timestamp
  final String nodeId;         // Pubkey del nodo (primi 8 char hex)

  /// Crea un nuovo HLC per un evento locale
  /// Se il wall-clock è avanzato, counter = 0
  /// Se il wall-clock è uguale o precedente, counter++
  factory HybridLogicalClock.now({
    required HybridLogicalClock? previous,
    required String nodeId,
  });

  /// Aggiorna l'HLC alla ricezione di un evento remoto
  /// max(local.ts, remote.ts, now) — gestione clock drift
  factory HybridLogicalClock.receive({
    required HybridLogicalClock local,
    required HybridLogicalClock remote,
    required String nodeId,
  });

  /// Serializzazione ISO 8601 estesa: "2026-02-24T12:00:00.000Z-0042-a1b2c3d4"
  String toCanonical();
  factory HybridLogicalClock.fromCanonical(String s);

  @override
  int compareTo(HybridLogicalClock other);

  /// Serializzazione come bytes per inclusione nell'hash
  Uint8List toBytes();
}
```

**Note:** HLC è equivalente a un Vector Clock per il caso N=2 peer, ma con dimensione costante. Il campo `counter` garantisce l'ordinamento causale senza crescita lineare.

### 4. `VectorClock` — `lib/src/vector_clock.dart`

Vector Clock a 2 elementi come descritto nel manifesto.

```dart
@immutable
class VectorClock {
  const VectorClock({required this.a, required this.b});

  final int a;  // Counter del peer A
  final int b;  // Counter del peer B

  /// Incrementa il contatore del peer specificato
  VectorClock increment(String localPeerRole); // 'A' o 'B'

  /// Merge di due vector clock: max(component-wise)
  VectorClock merge(VectorClock other);

  /// Somma totale dei contatori (usata per ordinamento)
  int get total => a + b;

  /// Relazione causale
  CausalRelation compareTo(VectorClock other);

  /// Serializzazione
  Map<String, int> toJson();
  factory VectorClock.fromJson(Map<String, int> json);
  Uint8List toBytes();
}

enum CausalRelation { before, after, concurrent, equal }
```

### 5. `EventFactory` — `lib/src/event_factory.dart`

Costruzione di eventi firmati e hashati.

```dart
class EventFactory {
  EventFactory({
    required Signer signer,
    required Hasher hasher,
  });

  /// Crea un nuovo evento per la catena locale
  ///
  /// 1. Genera eventId (UUID v4)
  /// 2. Calcola HLC da previousEvent
  /// 3. Incrementa VectorClock
  /// 4. Calcola eventHash = SHA-256(previousHash || eventType || payload || hlc.toBytes())
  /// 5. Firma con chiave privata
  Future<LedgerEvent> createEvent({
    required EventType type,
    required Uint8List payload,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
    required LedgerEvent? previousEvent,
    required VectorClock currentVectorClock,
    required String localPeerRole,
  });

  /// Crea il genesis event (primo evento della catena)
  Future<LedgerEvent> createGenesisEvent({
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
    required String nodeId,
  });
}
```

### 6. `ChainValidator` — `lib/src/chain_validator.dart`

Verifica dell'integrità della catena.

```dart
class ChainValidator {
  ChainValidator({
    required Hasher hasher,
    required Verifier verifier,
  });

  /// Verifica l'intera catena dall'inizio alla fine
  /// Restituisce il primo errore trovato, o null se tutto OK
  Future<ChainValidationError?> validateFullChain(List<LedgerEvent> events);

  /// Verifica un singolo evento rispetto al precedente
  Future<ChainValidationError?> validateEvent({
    required LedgerEvent event,
    required LedgerEvent? previousEvent,
    required StyxPublicKey senderPublicKey,
  });

  /// Verifica che l'hash dell'evento sia corretto
  Future<bool> verifyEventHash(LedgerEvent event, String? previousHash);

  /// Verifica che la firma dell'evento sia valida
  Future<bool> verifyEventSignature(LedgerEvent event, StyxPublicKey publicKey);
}

@immutable
class ChainValidationError {
  const ChainValidationError({
    required this.eventId,
    required this.errorType,
    required this.message,
  });

  final String eventId;
  final ChainErrorType errorType;
  final String message;
}

enum ChainErrorType {
  hashMismatch,        // L'hash calcolato non corrisponde
  signatureInvalid,    // La firma non è valida
  previousHashMissing, // L'evento referenzia un hash precedente che non esiste
  hlcViolation,        // L'HLC non è monotonicamente crescente
  genesisViolation,    // Il primo evento non è un genesis valido
}
```

### 7. `LedgerService` — `lib/src/ledger_service.dart`

Façade per le operazioni sul ledger.

```dart
class LedgerService {
  LedgerService({
    required EventFactory eventFactory,
    required ChainValidator chainValidator,
    required EventDao eventDao,
  });

  /// Aggiunge un nuovo evento alla catena locale
  Future<LedgerEvent> appendEvent({
    required EventType type,
    required Uint8List payload,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
  });

  /// Recupera la storia completa degli eventi
  Future<List<LedgerEvent>> getHistory();

  /// Valida l'intera catena
  Future<ChainValidationError?> validateChain();

  /// Recupera l'ultimo evento
  Future<LedgerEvent?> getLatestEvent();

  /// Stream reattivo di nuovi eventi
  Stream<LedgerEvent> watchNewEvents();
}
```

---

## Test Specification

### Unit Test: `test/hlc_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T5.1 | HLC.now senza precedente | `previous = null` | `counter = 0`, `timestamp ≈ now` |
| T5.2 | HLC.now con precedente stesso ts | Same millisecond | `counter = previous.counter + 1` |
| T5.3 | HLC.now con precedente ts passato | Old timestamp | `counter = 0`, `timestamp = now` |
| T5.4 | HLC.receive clock drift | Remote.ts > local.ts + 5min | `timestamp = remote.ts`, gestito senza errore |
| T5.5 | HLC.receive local ahead | Local.ts > remote.ts | `timestamp = local.ts` |
| T5.6 | HLC ordinamento totale | 1000 HLC random | `compareTo` produce ordinamento totale (no pareggi) |
| T5.7 | HLC serialization round-trip | HLC qualsiasi | `fromCanonical(hlc.toCanonical()) == hlc` |

### Unit Test: `test/vector_clock_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T5.8 | VC increment A | `{A:0, B:0}` | `{A:1, B:0}` |
| T5.9 | VC merge | `{A:2, B:1}` merge `{A:1, B:3}` | `{A:2, B:3}` |
| T5.10 | Causal BEFORE | `{A:1, B:1}` vs `{A:2, B:1}` | `before` |
| T5.11 | Causal CONCURRENT | `{A:2, B:1}` vs `{A:1, B:2}` | `concurrent` |
| T5.12 | Causal EQUAL | `{A:1, B:1}` vs `{A:1, B:1}` | `equal` |
| T5.13 | VC total | `{A:3, B:5}` | `8` |

### Unit Test: `test/event_factory_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T5.14 | Create genesis event | — | `previousHash = null`, hash e firma validi |
| T5.15 | Create normal event | Previous event | `previousHash = previous.eventHash` |
| T5.16 | Hash deterministico | Stesso input × 2 | Stesso `eventHash` |
| T5.17 | Hash diverso per payload diverso | Payload A vs B | `eventHash` diversi |
| T5.18 | Firma verificabile | Evento creato | `verifier.verify() == true` |
| T5.19 | EventId unicità | 1000 eventi | Tutti `eventId` diversi (UUID v4) |
| T5.20 | HLC monotono | 100 eventi sequenziali | Ogni HLC > precedente |

### Unit Test: `test/chain_validator_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T5.21 | Catena valida 10 eventi | 10 eventi corretti | `null` (nessun errore) |
| T5.22 | Catena valida 1000 eventi | 1000 eventi | `null` |
| T5.23 | Hash alterato | Flip 1 byte nel payload di evento #5 | `ChainErrorType.hashMismatch` su evento #5 |
| T5.24 | Firma alterata | Flip 1 byte nella firma di evento #3 | `ChainErrorType.signatureInvalid` su evento #3 |
| T5.25 | Hash precedente sbagliato | Modifica previousHash evento #7 | `ChainErrorType.previousHashMissing` |
| T5.26 | Genesis non in prima posizione | Evento genesis in posizione 2 | Errore |
| T5.27 | Catena vuota | Lista vuota | `null` (valida per definizione) |
| T5.28 | Singolo evento (genesis) | 1 evento genesis | `null` |

### Property-Based Test: `test/property_ledger_test.dart`

| # | Test | Proprietà |
|---|------|-----------|
| T5.29 | Chain integrity universale | `∀ sequenza di N eventi (1-500): validateChain() == null` |
| T5.30 | Tamper detection universale | `∀ catena valida, ∀ alterazione singolo byte: validateChain() ≠ null` |
| T5.31 | HLC monotonia | `∀ sequenza: events[i].hlc < events[i+1].hlc` |

---

## Criteri di Completamento

- [ ] Tutti i test T5.1–T5.31 passano
- [ ] Coverage ≥ 95%
- [ ] `melos run test:all` include Task 0-5, tutto green
- [ ] Chain validation di 10.000 eventi < 2 secondi
- [ ] HLC ordinamento totale verificato (nessun pareggio possibile grazie a nodeId)
