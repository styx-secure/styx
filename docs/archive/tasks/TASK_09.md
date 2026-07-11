# Task 9 — Transport: Tor Overlay + Failover Engine

**Stato:** Da iniziare
**Durata stimata:** 3-4 giorni
**Dipendenze:** Task 7, Task 8
**Package:** `packages/transport/` (estensione)
**Coverage target:** ≥ 85%

---

## Obiettivo

Routing opzionale del traffico via Tor per anonimato di rete, e motore di failover multi-transport che gestisce il passaggio automatico da Nostr a Email con retry e backoff esponenziale. Implementare l'OutboxWorker che processa la coda di invio rispettando l'ordine causale.

---

## Dipendenze Esterne Aggiuntive

```yaml
dependencies:
  tor: ^0.1.1               # Arti-based Tor client
  socks5_proxy: ^2.1.1      # SOCKS5 proxy routing
  retry: ^3.1.2             # Exponential backoff (Google)
```

---

## Componenti da Implementare

### 1. `TorManager` — `lib/src/tor/tor_manager.dart`

```dart
enum TorState { stopped, bootstrapping, ready, error }

class TorManager {
  /// Stato corrente del bootstrap Tor
  TorState get state;

  /// Stream dello stato
  Stream<TorState> get stateStream;

  /// Avvia il bootstrap Tor
  /// Timeout dopo [timeout] secondi (default: 120)
  Future<void> start({Duration timeout = const Duration(seconds: 120)});

  /// Arresta Tor
  Future<void> stop();

  /// Porta SOCKS5 locale (disponibile dopo bootstrap)
  int get socksPort;

  /// Crea un HttpClient configurato per routare via Tor
  HttpClient createTorHttpClient();

  /// Percentuale di bootstrap (0-100)
  int get bootstrapProgress;
}
```

**Note implementative:**
```dart
// Esempio di utilizzo con il package tor
await Tor.init();
await Tor.instance.start();
final port = Tor.instance.port; // SOCKS5 port

final client = HttpClient();
SocksTCPClient.assignToHttpClient(client, [
  ProxySettings(InternetAddress.loopbackIPv4, port),
]);
```

### 2. `TorTransportDecorator` — `lib/src/tor/tor_transport_decorator.dart`

Decorator pattern: wrappa qualsiasi `TransportInterface` per routare via Tor.

```dart
class TorTransportDecorator implements TransportInterface {
  TorTransportDecorator({
    required TransportInterface inner,
    required TorManager torManager,
  });

  @override
  String get name => '${inner.name}+tor';

  @override
  Future<void> connect() async {
    if (torManager.state != TorState.ready) {
      await torManager.start();
    }
    // Configura inner transport per usare Tor SOCKS proxy
    await inner.connect();
  }

  @override
  Future<bool> send(TransportMessage message) => inner.send(message);

  @override
  Stream<TransportMessage> get messageStream => inner.messageStream;

  @override
  Future<bool> isAvailable() async {
    return torManager.state == TorState.ready && await inner.isAvailable();
  }
}
```

### 3. `TransportFailover` — `lib/src/failover/transport_failover.dart`

```dart
class TransportFailover implements TransportInterface {
  TransportFailover({
    required List<TransportPriority> transports,
  });

  @override
  String get name => 'failover';

  /// Invia un messaggio usando la gerarchia di trasporto
  /// Nostr (3 tentativi, 5s timeout) → Email (2 tentativi, 30s timeout)
  @override
  Future<bool> send(TransportMessage message) async {
    for (final transport in transports) {
      for (var attempt = 0; attempt < transport.maxRetries; attempt++) {
        try {
          final success = await transport.transport
            .send(message)
            .timeout(transport.timeout);
          if (success) return true;
        } catch (_) {
          await _backoff(attempt);
        }
      }
    }
    return false; // Tutti i transport hanno fallito
  }

  /// Stream aggregato di tutti i transport
  @override
  Stream<TransportMessage> get messageStream;

  /// Connetti tutti i transport disponibili
  @override
  Future<void> connect();

  /// Il failover è disponibile se almeno un transport lo è
  @override
  Future<bool> isAvailable() async {
    for (final t in transports) {
      if (await t.transport.isAvailable()) return true;
    }
    return false;
  }
}

@immutable
class TransportPriority {
  const TransportPriority({
    required this.transport,
    required this.maxRetries,
    required this.timeout,
  });

  final TransportInterface transport;
  final int maxRetries;
  final Duration timeout;
}
```

### 4. `TransportSelector` — `lib/src/failover/transport_selector.dart`

```dart
class TransportSelector {
  /// Crea la configurazione di failover in base alle preferenze utente
  TransportFailover createFailoverChain({
    required NostrTransport nostr,
    required EmailTransport? email,
    required TorManager? torManager,
    required bool useTor,
  });
}
```

### 5. `OutboxWorker` — `lib/src/failover/outbox_worker.dart`

```dart
class OutboxWorker {
  OutboxWorker({
    required OutboxDao outboxDao,
    required EventDao eventDao,
    required TransportFailover transport,
    required MessageSerializer serializer,
    required NostrEncryptor encryptor,
    required StyxPrivateKey localPrivateKey,
    required StyxPublicKey localPublicKey,
    required StyxPublicKey peerPublicKey,
  });

  /// Avvia il worker che processa la outbox
  /// Rispetta l'ordine causale HLC — non invia evento N+1 prima di N
  Future<void> start();

  /// Ferma il worker
  Future<void> stop();

  /// Forza il processing immediato (dopo wake-up da push)
  Future<void> processNow();

  /// Processing di un singolo ciclo
  /// 1. Recupera eventi ready_to_send dalla outbox
  /// 2. Per ogni evento (in ordine HLC):
  ///    a. Serializza il LedgerEvent
  ///    b. Cifra per il peer
  ///    c. Invia via TransportFailover
  ///    d. Se OK → markSent; se FAIL → markFailed con backoff
  Future<int> processBatch();

  /// Stato corrente
  bool get isRunning;

  /// Statistiche
  int get pendingCount;
  int get sentCount;
  int get failedCount;
}
```

---

## Test Specification

### Unit Test: `test/tor_manager_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T9.1 | Start → state ready | — | `state == TorState.ready` entro 120s |
| T9.2 | SocksPort valido | Dopo start | Porta > 0 e < 65536 |
| T9.3 | Stop | Dopo start → stop | `state == TorState.stopped` |
| T9.4 | Bootstrap timeout | Timeout 1ms (impossibile) | `state == TorState.error` |
| T9.5 | Double start | Start × 2 | Nessun errore, idempotente |

### Unit Test: `test/transport_failover_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T9.6 | Nostr OK al primo tentativo | Mock Nostr che restituisce true | Messaggio inviato, email non tentata |
| T9.7 | Nostr fail → Email OK | Mock Nostr fail, Mock Email OK | Messaggio inviato via email |
| T9.8 | Tutto fail | Tutti i mock falliscono | `send() == false`, nessun crash |
| T9.9 | Retry con backoff | Nostr fail × 3 | 3 tentativi con delay crescente |
| T9.10 | Timeout respected | Mock Nostr che non risponde | Timeout scatta, passa a email |
| T9.11 | IsAvailable almeno uno | Nostr down, email up | `true` |
| T9.12 | IsAvailable nessuno | Tutto down | `false` |
| T9.13 | MessageStream aggregato | 3 msg da Nostr + 2 da Email | Stream emette tutti 5 |

### Unit Test: `test/outbox_worker_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T9.14 | ProcessBatch 5 eventi | 5 pending in outbox | 5 inviati, outbox vuota |
| T9.15 | Ordine causale | 5 eventi con HLC diversi | Inviati in ordine HLC crescente |
| T9.16 | Partial failure | 3 OK + 2 fail | 3 markSent + 2 markFailed |
| T9.17 | Backoff su failure | 1 evento che fallisce × 3 | `retryCount` incrementa, `nextRetryAt` cresce |
| T9.18 | ProcessNow | Worker fermo → processNow | Batch processato immediatamente |
| T9.19 | Start/stop lifecycle | Start → process → stop | Worker si ferma pulito |
| T9.20 | Outbox vuota | Nessun evento pending | `processBatch() == 0`, nessun errore |

### Integration Test: `test/tor_integration_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T9.21 | HTTP via Tor | Fetch `https://check.torproject.org` | Risposta indica Tor attivo |
| T9.22 | WebSocket via Tor | Connect a relay Nostr via Tor | Connessione stabilita |

**Nota:** T9.1, T9.21, T9.22 richiedono una connessione di rete e il bootstrap Tor reale (~20-40 secondi). Taggare come `@Tags(['slow', 'integration'])` e escludere dal CI veloce.

---

## Note di Implementazione

### Tor + WebSocket

Il package `tor` espone un proxy SOCKS5. Per routare WebSocket attraverso Tor, occorre un `HttpClient` custom che usa il proxy SOCKS5:

```dart
final torClient = torManager.createTorHttpClient();
// web_socket_channel non accetta HttpClient custom
// Occorre usare dart:io WebSocket.connect con HttpClient:
final ws = await WebSocket.connect(relayUrl, customClient: torClient);
```

Se `web_socket_channel` non supporta proxy, usare `dart:io` `WebSocket` direttamente e wrappare in un `IOWebSocketChannel`.

### Failover State Machine

```
START → try NOSTR
  NOSTR OK → DONE
  NOSTR FAIL × maxRetries → try EMAIL
    EMAIL OK → DONE
    EMAIL FAIL × maxRetries → FAIL (evento resta in outbox)
```

### OutboxWorker e Background Execution

L'OutboxWorker viene invocato:
1. All'avvio dell'app (processa coda accumulata)
2. Al wake-up da push notification
3. Al ripristino della connettività (connectivity_plus listener)

Non è un servizio background permanente — si attiva, processa, si ferma.

---

## Criteri di Completamento

- [ ] Tutti i test T9.1–T9.22 passano (T9.21-T9.22 opzionali in CI)
- [ ] Coverage ≥ 85% (Tor bootstrap non completamente controllabile)
- [ ] `melos run test:all` include Task 0-9, tutto green
- [ ] Failover Nostr → Email end-to-end
- [ ] OutboxWorker rispetta ordine causale
- [ ] Tor bootstrap < 60 secondi su rete stabile
