# Task 7 — Transport: Nostr Client

**Stato:** Da iniziare
**Durata stimata:** 4-5 giorni
**Dipendenze:** Task 1, Task 5
**Package:** `packages/transport/`
**Coverage target:** ≥ 90%

---

## Obiettivo

Implementare il canale di trasporto primario via protocollo Nostr: connessione a relay pool, invio/ricezione di messaggi cifrati end-to-end, gestione connessioni WebSocket, health check relay, e interfaccia astratta `TransportInterface` riutilizzabile per i fallback.

---

## Dipendenze Esterne

```yaml
dependencies:
  styx_crypto_core: {path: ../crypto_core}
  styx_ledger_engine: {path: ../ledger_engine}
  ndk: ^0.6.0                   # Nostr Development Kit
  web_socket_client: ^0.2.1     # Auto-reconnect WebSocket
  meta: ^1.16.0
```

---

## Componenti da Implementare

### 1. `TransportMessage` — `lib/src/transport_message.dart`

Envelope per messaggi in transito tra peer.

```dart
@immutable
class TransportMessage {
  const TransportMessage({
    required this.encryptedPayload,
    required this.senderPubkey,
    required this.recipientPubkey,
    required this.nonce,
    required this.timestamp,
    required this.messageId,
  });

  final Uint8List encryptedPayload;  // LedgerEvent serializzato + cifrato
  final String senderPubkey;          // Hex Ed25519 pubkey
  final String recipientPubkey;       // Hex Ed25519 pubkey destinatario
  final Uint8List nonce;              // Nonce per ChaCha20-Poly1305
  final DateTime timestamp;
  final String messageId;             // UUID v4 per deduplicazione

  /// Serializza per il trasporto (JSON-encodable)
  Map<String, dynamic> toJson();
  factory TransportMessage.fromJson(Map<String, dynamic> json);

  /// Dimensione totale in bytes
  int get sizeBytes;
}
```

### 2. `TransportInterface` — `lib/src/transport_interface.dart`

Interfaccia astratta che tutti i canali implementano.

```dart
enum TransportState { disconnected, connecting, connected, error }

abstract class TransportInterface {
  /// Nome del trasporto (per logging e failover)
  String get name;

  /// Stato corrente della connessione
  TransportState get state;

  /// Stream dello stato di connessione
  Stream<TransportState> get stateStream;

  /// Connetti al canale di trasporto
  Future<void> connect();

  /// Disconnetti
  Future<void> disconnect();

  /// Invia un messaggio al peer
  /// Restituisce true se l'invio è andato a buon fine
  Future<bool> send(TransportMessage message);

  /// Stream di messaggi ricevuti
  Stream<TransportMessage> get messageStream;

  /// Verifica se il trasporto è disponibile (health check)
  Future<bool> isAvailable();
}
```

### 3. `NostrEncryptor` — `lib/src/nostr/nostr_encryptor.dart`

Cifratura E2E dei payload per Nostr.

```dart
class NostrEncryptor {
  NostrEncryptor({
    required DiffieHellman diffieHellman,
    required KeyDerivation keyDerivation,
  });

  /// Cifra un LedgerEvent serializzato per il peer destinatario
  /// Usa X25519 DH → HKDF → ChaCha20-Poly1305
  Future<TransportMessage> encrypt({
    required Uint8List plaintext,
    required StyxPrivateKey senderPrivateKey,
    required StyxPublicKey senderPublicKey,
    required StyxPublicKey recipientPublicKey,
  });

  /// Decifra un messaggio ricevuto dal peer
  Future<Uint8List> decrypt({
    required TransportMessage message,
    required StyxPrivateKey recipientPrivateKey,
  });
}
```

**Nota:** Non usare NIP-04 (deprecato, usa AES-CBC senza autenticazione). Usare NIP-44 (versioned, con padding) o cifratura custom ChaCha20-Poly1305 inviata come NIP-59 Gift Wrap per nascondere anche i metadati.

### 4. `RelayPool` — `lib/src/nostr/relay_pool.dart`

Gestione connessioni multiple a relay Nostr.

```dart
class RelayPool {
  RelayPool({required List<String> relayUrls});

  /// Connetti a tutti i relay configurati
  Future<void> connectAll();

  /// Disconnetti da tutti
  Future<void> disconnectAll();

  /// Pubblica un evento su tutti i relay connessi
  /// Restituisce il numero di relay che hanno accettato
  Future<int> publish(String eventJson);

  /// Sottoscrivi a eventi filtrati (per la nostra pubkey)
  Stream<String> subscribe({required Map<String, dynamic> filter});

  /// Lista relay attualmente connessi
  List<String> get connectedRelays;

  /// Numero di relay connessi
  int get connectedCount;

  /// Health check: verifica quali relay rispondono
  Future<Map<String, bool>> healthCheck();

  /// Aggiungi/rimuovi relay a runtime
  Future<void> addRelay(String url);
  Future<void> removeRelay(String url);
}
```

### 5. `NostrTransport` — `lib/src/nostr/nostr_transport.dart`

Implementazione concreta di `TransportInterface` per Nostr.

```dart
class NostrTransport implements TransportInterface {
  NostrTransport({
    required RelayPool relayPool,
    required NostrEncryptor encryptor,
    required StyxPublicKey localPublicKey,
  });

  @override
  String get name => 'nostr';

  @override
  Future<void> connect() async {
    await relayPool.connectAll();
    _subscribeToIncomingEvents();
  }

  @override
  Future<bool> send(TransportMessage message) async {
    final nostrEvent = _wrapInNostrEvent(message);
    final relaysOk = await relayPool.publish(nostrEvent);
    return relaysOk > 0;
  }

  @override
  Stream<TransportMessage> get messageStream;

  @override
  Future<bool> isAvailable() async {
    final health = await relayPool.healthCheck();
    return health.values.any((ok) => ok);
  }
}
```

### 6. `MessageSerializer` — `lib/src/message_serializer.dart`

Serializzazione/deserializzazione degli eventi ledger per il trasporto.

```dart
class MessageSerializer {
  /// Serializza un LedgerEvent in bytes per la cifratura
  Uint8List serializeEvent(LedgerEvent event);

  /// Deserializza bytes in LedgerEvent
  LedgerEvent deserializeEvent(Uint8List data);

  /// Serializza un batch di eventi (per sync iniziale)
  Uint8List serializeBatch(List<LedgerEvent> events);

  /// Deserializza un batch
  List<LedgerEvent> deserializeBatch(Uint8List data);
}
```

---

## Test Specification

### Unit Test: `test/nostr_encryptor_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T7.1 | Encrypt → decrypt round-trip | Plaintext 1KB | Decrypted == plaintext |
| T7.2 | Chiave sbagliata | Decrypt con altra private key | Errore di autenticazione |
| T7.3 | Payload alterato in transito | Flip 1 byte nel ciphertext | Errore di autenticazione |
| T7.4 | Nonce unicità | 1000 encrypt dello stesso plaintext | 1000 nonce diversi |
| T7.5 | Payload vuoto | 0 bytes | Encrypt/decrypt OK |
| T7.6 | Payload grande | 100 KB | Encrypt/decrypt OK, nessun OOM |

### Unit Test: `test/relay_pool_test.dart` (con mock WebSocket)

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T7.7 | Connect a 3 relay | 3 URL mock | `connectedCount == 3` |
| T7.8 | 1 relay down | 2 OK + 1 timeout | `connectedCount == 2`, nessun crash |
| T7.9 | Publish su multi-relay | Evento JSON | Pubblicato su tutti i connessi |
| T7.10 | Subscribe filtra correttamente | Filtro per pubkey | Solo eventi matching |
| T7.11 | Reconnect automatico | Disconnect forzato di 1 relay | Reconnect entro 5 secondi |
| T7.12 | Health check | 2 OK + 1 down | Map corretta |
| T7.13 | Add/remove relay a runtime | — | Pool aggiornato senza disconnect degli altri |

### Integration Test: `test/nostr_transport_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T7.14 | Send + receive tra 2 peer simulati | 2 NostrTransport + mock relay | Peer B riceve il messaggio di A |
| T7.15 | 100 messaggi sequenziali | A invia 100 msg | B riceve tutti 100 nell'ordine |
| T7.16 | Messaggio per pubkey sbagliata | Encrypt per C, B prova decrypt | Errore, messaggio scartato |
| T7.17 | Deduplicazione | Stesso messageId inviato 3 volte | B lo processa solo 1 volta |
| T7.18 | IsAvailable true | Almeno 1 relay UP | `true` |
| T7.19 | IsAvailable false | Tutti i relay down | `false` |
| T7.20 | State stream | Connect → disconnect | Stream emette: connecting → connected → disconnected |

### Unit Test: `test/message_serializer_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T7.21 | Serialize/deserialize event | LedgerEvent completo | Round-trip perfetto |
| T7.22 | Serialize/deserialize batch | 50 eventi | Round-trip perfetto |
| T7.23 | Evento pruned (payload null) | Evento con payload null | Serializzazione/deserializzazione OK |
| T7.24 | Evento con tutti i tipi | Ogni EventType | Tutti serializzabili |

---

## Note di Implementazione

### ndk vs Custom

Il package `ndk` fornisce relay management, signer, e cifratura. Valutare:
- **Usare ndk completamente:** Pro: relay pool gestito, NIP-59 gift wrap integrato. Contro: API opinionate, possibili breaking changes.
- **Usare ndk parzialmente:** Usare solo relay connection e event publish/subscribe. Cifratura custom con ChaCha20-Poly1305 di `cryptography`.
- **Non usare ndk:** Implementare direttamente su WebSocket con protocollo Nostr raw. Pro: controllo totale. Contro: reimplementare relay management.

**Raccomandazione:** Usare ndk per relay management e event handling. Cifratura gestita internamente dal crypto_core per non dipendere dall'implementazione di ndk.

### Deduplicazione

I relay Nostr possono inviare lo stesso evento più volte (da relay diversi nel pool). Implementare una cache in-memory (LRU) degli ultimi 1000 `messageId` ricevuti per scartare duplicati.

### Nostr Event Structure

```json
{
  "kind": 4,
  "pubkey": "<sender nostr pubkey>",
  "tags": [["p", "<recipient nostr pubkey>"]],
  "content": "<encrypted TransportMessage JSON>",
  "created_at": 1234567890
}
```

**Nota:** La pubkey Nostr (secp256k1) è diversa dalla pubkey Styx (Ed25519). Occorre una mappatura. Opzioni:
1. Generare una keypair Nostr separata per ogni identità Styx e salvarla nel SecureKeyStore
2. Usare la pubkey Styx direttamente come tag nell'evento Nostr (non come autore Nostr)

---

## Criteri di Completamento

- [ ] Tutti i test T7.1–T7.24 passano
- [ ] Coverage ≥ 90%
- [ ] `melos run test:all` include Task 0-7, tutto green
- [ ] Cifratura E2E verificata (relay non vede plaintext)
- [ ] Reconnect automatico funzionante
- [ ] Deduplicazione messaggi attiva
