# Task 4 — Storage: Database Cifrato con Drift + SQLCipher

**Stato:** Da iniziare
**Durata stimata:** 3-4 giorni
**Dipendenze:** Task 1, Task 3
**Package:** `packages/storage/`
**Coverage target:** ≥ 90%

---

## Obiettivo

Creare il database locale cifrato con AES-256 (SQLCipher), schema per eventi append-only, trust store dei peer, outbox per invio offline, e tabella configurazione. ORM type-safe via Drift con supporto migration e isolate.

---

## Dipendenze Esterne

```yaml
dependencies:
  styx_crypto_core:
    path: ../crypto_core
  drift: ^2.30.1
  sqlcipher_flutter_libs: ^0.6.8
  sqlite3: ^2.7.0
  meta: ^1.16.0

dev_dependencies:
  drift_dev: ^2.25.0
  build_runner: ^2.4.0
  test: ^1.25.0
  mocktail: ^1.0.4
  very_good_analysis: ^7.0.0
```

---

## Componenti da Implementare

### 1. `StyxDatabase` — `lib/src/styx_database.dart`

Factory e configurazione del database cifrato.

```dart
@DriftDatabase(tables: [Events, Peers, Outbox, Config], daos: [EventDao, PeerDao, OutboxDao, ConfigDao])
class StyxDatabase extends _$StyxDatabase {
  StyxDatabase(super.e);

  /// Crea un database cifrato con SQLCipher in un background isolate
  factory StyxDatabase.encrypted({
    required String path,
    required String passphrase,
  }) {
    return StyxDatabase(
      NativeDatabase.createInBackground(
        File(path),
        setup: (db) {
          db.execute("PRAGMA key = '$passphrase'");
          db.execute('PRAGMA journal_mode = WAL');
          db.execute('PRAGMA foreign_keys = ON');
          db.execute('PRAGMA auto_vacuum = INCREMENTAL');
        },
      ),
    );
  }

  /// Factory per test in-memory (non cifrato)
  factory StyxDatabase.inMemory();

  @override
  int get schemaVersion => 1;

  @override
  MigrationStrategy get migration => MigrationStrategy(
    onCreate: (m) => m.createAll(),
    onUpgrade: (m, from, to) async {
      // Migrazioni incrementali qui
    },
  );
}
```

### 2. Schema Tabelle

#### `Events` — `lib/src/tables/events.dart`

```dart
class Events extends Table {
  IntColumn get id => integer().autoIncrement()();
  TextColumn get eventId => text().unique()();
  TextColumn get eventType => text()();                    // TRANSACTION, SOS, CONFIG, REKEY, MERGE, PRUNE_REQUEST, PRUNE_ACK, MESSAGE
  BlobColumn get payloadEncrypted => blob().nullable()();  // Nullable per eventi pruned
  TextColumn get previousHash => text().nullable()();      // Null solo per genesis
  TextColumn get eventHash => text()();
  TextColumn get hlcTimestamp => text()();                  // ISO 8601 con counter
  TextColumn get hlcNodeId => text()();
  IntColumn get hlcCounter => integer()();
  IntColumn get vectorClockA => integer().withDefault(const Constant(0))();
  IntColumn get vectorClockB => integer().withDefault(const Constant(0))();
  TextColumn get senderPubkey => text()();                 // Hex della pubkey del mittente
  BlobColumn get signature => blob()();                    // Firma Ed25519 (64 bytes)
  DateTimeColumn get createdAt => dateTime()();
  BoolColumn get isPruned => boolean().withDefault(const Constant(false))();

  @override
  List<Set<Column>> get uniqueKeys => [{eventId}, {eventHash}];
}
```

#### `Peers` — `lib/src/tables/peers.dart`

```dart
class Peers extends Table {
  IntColumn get id => integer().autoIncrement()();
  TextColumn get pubkey => text().unique()();            // Hex della pubkey Ed25519
  TextColumn get alias => text().nullable()();           // Nome utente opzionale
  DateTimeColumn get pairedAt => dateTime()();
  BoolColumn get isActive => boolean().withDefault(const Constant(true))();
  TextColumn get rekeyHistory => text().withDefault(const Constant('[]'))(); // JSON array di {oldKey, newKey, timestamp}
}
```

#### `Outbox` — `lib/src/tables/outbox.dart`

```dart
class Outbox extends Table {
  IntColumn get id => integer().autoIncrement()();
  TextColumn get eventId => text().references(Events, #eventId)();
  TextColumn get status => text().withDefault(const Constant('pending'))(); // pending, sending, sent, failed
  TextColumn get transportUsed => text().nullable()();   // nostr, email, null se non ancora inviato
  IntColumn get retryCount => integer().withDefault(const Constant(0))();
  DateTimeColumn get nextRetryAt => dateTime().nullable()();
  DateTimeColumn get createdAt => dateTime()();
  DateTimeColumn get sentAt => dateTime().nullable()();
}
```

#### `Config` — `lib/src/tables/config.dart`

```dart
class Config extends Table {
  TextColumn get key => text()();
  TextColumn get value => text()();

  @override
  Set<Column> get primaryKey => {key};
}
```

### 3. `EventDao` — `lib/src/dao/event_dao.dart`

```dart
@DriftAccessor(tables: [Events])
class EventDao extends DatabaseAccessor<StyxDatabase> with _$EventDaoMixin {
  EventDao(super.db);

  /// Inserisce un evento nella catena (append-only)
  Future<int> insertEvent(EventsCompanion event);

  /// Recupera un evento per eventId
  Future<Event?> getByEventId(String eventId);

  /// Recupera un evento per hash
  Future<Event?> getByHash(String eventHash);

  /// Recupera l'ultimo evento della catena
  Future<Event?> getLatestEvent();

  /// Recupera tutti gli eventi ordinati per HLC
  Future<List<Event>> getAllEventsOrdered();

  /// Recupera eventi in un range HLC
  Future<List<Event>> getEventsInRange({
    required String fromHlc,
    required String toHlc,
  });

  /// Recupera eventi non ancora confermati dal peer
  Future<List<Event>> getUnconfirmedEvents();

  /// Marca un evento come pruned (rimuove payload, conserva hash)
  Future<void> pruneEvent(String eventId);

  /// Verifica l'integrità della catena hash
  /// Restituisce l'eventId del primo evento corrotto, o null se la catena è integra
  Future<String?> verifyChainIntegrity();

  /// Conta gli eventi totali
  Future<int> countEvents();

  /// Stream reattivo di nuovi eventi
  Stream<List<Event>> watchEvents();
}
```

**Enforcement append-only:** Drift non supporta trigger nativamente, ma si può:
1. Non esporre metodi `update` o `delete` per Events nel DAO
2. Aggiungere un trigger SQL via `customStatement` nella migration:
   ```sql
   CREATE TRIGGER events_no_update BEFORE UPDATE ON events
   BEGIN SELECT RAISE(ABORT, 'Events table is append-only'); END;

   CREATE TRIGGER events_no_delete BEFORE DELETE ON events
   BEGIN SELECT RAISE(ABORT, 'Events table is append-only. Use pruning.'); END;
   ```
3. L'unica modifica permessa è il pruning (update di `payload_encrypted` a NULL + `is_pruned` a true)

### 4. `OutboxDao` — `lib/src/dao/outbox_dao.dart`

```dart
@DriftAccessor(tables: [Outbox, Events])
class OutboxDao extends DatabaseAccessor<StyxDatabase> with _$OutboxDaoMixin {
  OutboxDao(super.db);

  /// Accoda un evento per l'invio
  Future<void> enqueue(String eventId);

  /// Recupera il prossimo evento da inviare (FIFO, rispettando HLC order)
  Future<OutboxEntry?> dequeueNext();

  /// Recupera tutti gli eventi pending o failed con retry scaduto
  Future<List<OutboxEntry>> getReadyToSend();

  /// Marca come inviato
  Future<void> markSent({required String eventId, required String transport});

  /// Marca come fallito con backoff esponenziale
  Future<void> markFailed({required String eventId});

  /// Rimuove un entry dalla outbox (dopo conferma dal peer)
  Future<void> remove(String eventId);

  /// Conta messaggi in coda
  Future<int> pendingCount();
}
```

**Backoff strategy:** `nextRetryAt = now + min(baseDelay * 2^retryCount, maxDelay)`
- `baseDelay`: 5 secondi
- `maxDelay`: 5 minuti
- `maxRetries`: 20 (poi passa a stato `abandoned`)

### 5. `PeerDao` — `lib/src/dao/peer_dao.dart`

```dart
@DriftAccessor(tables: [Peers])
class PeerDao extends DatabaseAccessor<StyxDatabase> with _$PeerDaoMixin {
  PeerDao(super.db);

  Future<void> addPeer(PeersCompanion peer);
  Future<Peer?> getPeerByPubkey(String pubkey);
  Future<List<Peer>> getActivePeers();
  Future<void> deactivatePeer(String pubkey);
  Future<void> updatePeerKey({required String oldPubkey, required String newPubkey});
  Future<void> addRekeyEntry({required String pubkey, required String oldKey, required String newKey});
}
```

### 6. `ConfigDao` — `lib/src/dao/config_dao.dart`

```dart
@DriftAccessor(tables: [Config])
class ConfigDao extends DatabaseAccessor<StyxDatabase> with _$ConfigDaoMixin {
  ConfigDao(super.db);

  Future<void> set(String key, String value);
  Future<String?> get(String key);
  Future<void> delete(String key);
  Future<Map<String, String>> getAll();
}
```

---

## Test Specification

### Unit Test: `test/styx_database_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T4.1 | Open/close in-memory | — | Nessun errore |
| T4.2 | Open cifrato + riapertura stessa passphrase | DB + passphrase | Dati preservati |
| T4.3 | Open cifrato + passphrase sbagliata | DB + passphrase errata | `SqliteException` (non crash) |
| T4.4 | Schema version | — | `schemaVersion == 1` |

### Unit Test: `test/event_dao_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T4.5 | Insert + getByEventId | Evento valido | Match completo |
| T4.6 | Insert duplicato eventId | Stesso eventId | `SqliteException` (unique violation) |
| T4.7 | GetLatestEvent su DB vuoto | — | `null` |
| T4.8 | GetLatestEvent dopo 10 insert | 10 eventi | L'ultimo inserito |
| T4.9 | GetAllEventsOrdered | 100 eventi con HLC random | Ordinati per HLC crescente |
| T4.10 | GetEventsInRange | 100 eventi | Solo quelli nel range specificato |
| T4.11 | PruneEvent | Evento con payload | `isPruned = true`, `payloadEncrypted = null`, `eventHash` preservato |
| T4.12 | VerifyChainIntegrity OK | 100 eventi con hash chain valida | `null` (nessun errore) |
| T4.13 | VerifyChainIntegrity FAIL | Alterare 1 byte nel payload DB raw | EventId dell'evento corrotto |
| T4.14 | Append-only enforcement | Tentativo UPDATE via SQL raw | `RAISE(ABORT)` se trigger attivo |
| T4.15 | CountEvents | 42 eventi | `42` |
| T4.16 | WatchEvents stream | Insert 5 eventi | Stream emette 5 aggiornamenti |

### Unit Test: `test/outbox_dao_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T4.17 | Enqueue + dequeueNext | 1 evento | Stesso eventId |
| T4.18 | FIFO order | Enqueue A, B, C | DequeueNext → A, B, C |
| T4.19 | MarkSent | Enqueue → markSent | Status = `sent`, `sentAt` populated |
| T4.20 | MarkFailed backoff | Enqueue → markFailed × 3 | `nextRetryAt` cresce esponenzialmente |
| T4.21 | GetReadyToSend | 3 pending, 2 failed con retry scaduto | 5 risultati |
| T4.22 | GetReadyToSend esclude non-scaduti | 1 failed con nextRetryAt in futuro | 0 risultati |
| T4.23 | PendingCount | 7 pending | `7` |

### Unit Test: `test/peer_dao_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T4.24 | AddPeer + getPeerByPubkey | Peer valido | Match |
| T4.25 | GetActivePeers | 3 active, 2 deactivated | 3 risultati |
| T4.26 | DeactivatePeer | Peer attivo | `isActive = false` |
| T4.27 | UpdatePeerKey (rekey) | oldPubkey → newPubkey | Peer trovabile con newPubkey |
| T4.28 | Peer duplicato pubkey | Stessa pubkey | `SqliteException` |

### Performance Test: `test/performance_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T4.29 | Bulk insert 10.000 eventi | Batch insert | Completamento < 5 secondi |
| T4.30 | Chain verification 10.000 eventi | DB con 10K eventi | Completamento < 3 secondi |
| T4.31 | Concurrent read/write | Write in isolate + read in main | Nessun deadlock, WAL mode OK |

---

## Note di Implementazione

### WAL Mode

`PRAGMA journal_mode = WAL` è essenziale per:
- Read/write concorrente (la OutboxWorker legge mentre l'app inserisce)
- Crash recovery (WAL è più resiliente di DELETE mode)
- Performance su mobile (meno fsync)

### Generazione Passphrase

La passphrase SQLCipher deve essere derivata dalla chiave hardware, non scelta dall'utente:
1. Al primo avvio, genera 32 bytes random via CSPRNG
2. Salva in `SecureKeyStore` come `"styx:db:passphrase"`
3. All'apertura del DB, recupera dalla SecureKeyStore
4. Converti in hex string per `PRAGMA key`

### Indici

```sql
CREATE INDEX idx_events_hlc ON events (hlc_timestamp, hlc_counter);
CREATE INDEX idx_events_previous_hash ON events (previous_hash);
CREATE INDEX idx_events_sender ON events (sender_pubkey);
CREATE INDEX idx_events_type ON events (event_type);
CREATE INDEX idx_outbox_status ON outbox (status, next_retry_at);
```

---

## Criteri di Completamento

- [ ] Tutti i test T4.1–T4.31 passano
- [ ] Coverage ≥ 90% (drift genera boilerplate)
- [ ] `melos run test:all` include Task 0-4, tutto green
- [ ] DB funziona su Android e iOS con SQLCipher
- [ ] Trigger append-only attivo
- [ ] WAL mode verificato
- [ ] Passphrase derivata da SecureKeyStore
