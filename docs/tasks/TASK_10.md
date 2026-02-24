# Task 10 — Push Bridge: Server + Client

**Stato:** Da iniziare
**Durata stimata:** 5-7 giorni
**Dipendenze:** Task 7, Task 4
**Package server:** `push_bridge_server/` (Go)
**Package client:** `packages/push_bridge_client/`
**Coverage target:** ≥ 90% (client), ≥ 85% (server)

---

## Obiettivo

Implementare il microservizio stateless Push Bridge e il client Flutter. Il bridge sottoscrive relay Nostr per conto dei device e invia push data-only per svegliare l'app. Nessun dato sensibile transita attraverso il bridge. Tre profili privacy con dummy notifications Poisson-distribuite.

---

## PARTE A: Push Bridge Server (Go)

### Dipendenze Go

```go
// go.mod
require (
    firebase.google.com/go/v4
    github.com/sideshow/apns2
    github.com/nbd-wtf/go-nostr
    github.com/gorilla/mux
)
```

### Componenti Server

#### `main.go` — Entry point

```go
func main() {
    // Load FCM/APNs credentials from environment
    // Start Nostr subscriber
    // Start HTTP API
    // Start dummy scheduler (per profilo)
}
```

#### `api.go` — HTTP Endpoints

| Endpoint | Method | Body | Descrizione |
|----------|--------|------|-------------|
| `/register` | POST | `{fcm_token, nostr_pubkey, platform, privacy_profile}` | Registra device |
| `/unregister` | POST | `{fcm_token}` | Deregistra device |
| `/health` | GET | — | Health check |

**Nessun endpoint per l'invio di dati.** Il bridge non riceve mai contenuti dall'app.

```go
type Registration struct {
    FCMToken       string `json:"fcm_token"`
    NostrPubkey    string `json:"nostr_pubkey"`
    Platform       string `json:"platform"`     // "android" | "ios"
    PrivacyProfile string `json:"privacy_profile"` // "balanced" | "private" | "paranoid"
}
```

#### `subscriber.go` — Nostr Relay Subscriber

```go
type NostrSubscriber struct {
    relayURLs    []string
    registrations map[string]Registration  // nostrPubkey → Registration
}

// Subscribe to all registered pubkeys
// When an event for a registered pubkey is detected → trigger push
func (s *NostrSubscriber) Start(ctx context.Context)
func (s *NostrSubscriber) AddPubkey(pubkey string, reg Registration)
func (s *NostrSubscriber) RemovePubkey(pubkey string)
```

#### `dispatcher.go` — Push Notification Dispatcher

```go
type PushDispatcher struct {
    fcmClient  *messaging.Client
    apnsClient *apns2.Client
}

// Invia push data-only (nessun payload sensibile)
// FCM: data message con {"styx": "wake"}
// APNs: background notification con content-available: 1
func (d *PushDispatcher) SendWakeUp(reg Registration) error
```

**FCM payload:**
```json
{
  "message": {
    "token": "<fcm_token>",
    "data": {
      "styx": "wake",
      "ts": "1234567890"
    },
    "android": {
      "priority": "high"
    },
    "apns": {
      "headers": {
        "apns-priority": "10",
        "apns-push-type": "background"
      },
      "payload": {
        "aps": {
          "content-available": 1
        }
      }
    }
  }
}
```

#### `dummy.go` — Dummy Notification Scheduler

```go
type DummyScheduler struct {
    registrations map[string]Registration
    dispatcher    *PushDispatcher
}

// Genera dummy push con distribuzione di Poisson
// λ dipende dal profilo:
//   balanced: λ = 0 (nessuna dummy)
//   private:  λ = 1/(150 sec) ≈ 4-6/giorno
//   paranoid: λ = 1/(30 sec) ≈ high frequency
func (ds *DummyScheduler) Start(ctx context.Context)
```

**Poisson timing:**
```go
nextDelay := -math.Log(rand.Float64()) / lambda
time.Sleep(time.Duration(nextDelay * float64(time.Second)))
```

#### Stateless Enforcement

- **Zero database:** Registrations in-memory (`sync.Map`)
- **Zero log di contenuti:** Solo log strutturati di eventi operativi (register/unregister/errors)
- **Zero chiavi private:** Il bridge non possiede né accede a chiavi crittografiche
- **Restart = clean slate:** Alla ripartenza, i device si ri-registrano al primo wake-up dell'app

---

## PARTE B: Push Bridge Client (Flutter)

### Dipendenze Flutter

```yaml
dependencies:
  firebase_messaging: ^16.1.1
  flutter_local_notifications: ^20.0.0
  styx_crypto_core: {path: ../crypto_core}
  styx_transport: {path: ../transport}
```

### Componenti Client

#### `PushBridgeClient` — `lib/src/push_bridge_client.dart`

```dart
class PushBridgeClient {
  PushBridgeClient({required String bridgeUrl});

  /// Registra il device presso il Push Bridge
  Future<void> register({
    required String fcmToken,
    required String nostrPubkey,
    required PrivacyProfile profile,
  });

  /// Deregistra il device
  Future<void> unregister({required String fcmToken});

  /// Aggiorna il profilo privacy
  Future<void> updateProfile({
    required String fcmToken,
    required PrivacyProfile profile,
  });
}
```

#### `PushHandler` — `lib/src/push_handler.dart`

```dart
class PushHandler {
  /// Top-level callback per firebase_messaging background handler
  /// DEVE essere una funzione top-level (non un metodo di classe)
  static Future<void> onBackgroundMessage(RemoteMessage message);

  /// Handler per messaggi ricevuti in foreground
  static void onForegroundMessage(RemoteMessage message);

  /// Configura il handler
  static Future<void> initialize({
    required Future<void> Function() onWakeUp,
  });
}
```

**Callback top-level (obbligatorio per firebase_messaging):**
```dart
@pragma('vm:entry-point')
Future<void> _firebaseMessagingBackgroundHandler(RemoteMessage message) async {
  // 1. Controlla se è dummy
  // 2. Se dummy → return (torna a dormire, zero I/O di rete)
  // 3. Se reale → connetti a relay → download eventi → processa
}
```

#### `DummyDetector` — `lib/src/dummy_detector.dart`

```dart
class DummyDetector {
  /// Determina se una push notification è una dummy o un wake reale
  ///
  /// Strategia: la push contiene un campo "styx_nonce" cifrato con la chiave
  /// condivisa bridge-client. Se il decrypt rivela un pattern "dummy", scartare.
  ///
  /// Alternativa più semplice: dummy push hanno un campo "d": "1",
  /// ma questo rivela al provider push che è dummy (metadata leakage minimo)
  bool isDummy(RemoteMessage message);
}
```

**Decisione di design:** Per il profilo Balanced (nessuna dummy), il campo `d` non serve. Per Private e Paranoid, il bridge inserisce `"d": "1"` nelle dummy. L'app controlla il campo prima di connettersi alla rete.

In realtà per massima privacy (Paranoid), anche le dummy dovrebbero sembrare reali al device OS level. Quindi nel profilo Paranoid, il client si connette SEMPRE al relay (sia per push reali che dummy), rendendo i pattern di traffico indistinguibili.

#### `PrivacyProfile` — `lib/src/privacy_profile.dart`

```dart
enum PrivacyProfile {
  /// Nessuna dummy. Push solo per eventi reali.
  /// Pro: zero consumo batteria extra
  /// Contro: provider push conosce i tempi di comunicazione
  balanced,

  /// Dummy a intervalli Poisson (~4-6/giorno)
  /// L'app si sveglia, controlla flag dummy, torna a dormire (zero rete)
  /// Pro: pattern temporali mascherati
  /// Contro: wake-up CPU minimi
  private,

  /// Dummy ad alta frequenza con connessione reale al relay
  /// L'app si connette al relay ad ogni push (anche dummy)
  /// Pro: pattern di traffico completamente mascherati
  /// Contro: consumo batteria misurabile
  paranoid,
}
```

#### `WakeUpOrchestrator` — `lib/src/wake_up_orchestrator.dart`

```dart
class WakeUpOrchestrator {
  WakeUpOrchestrator({
    required OutboxWorker outboxWorker,
    required TransportInterface transport,
    required LedgerService ledgerService,
  });

  /// Gestisce il wake-up da push notification
  /// 1. Connetti al relay Nostr
  /// 2. Download eventi nuovi (filtro per pubkey + ultimo HLC noto)
  /// 3. Verifica firme e hash chain
  /// 4. Inserisci nel ledger locale
  /// 5. Processa outbox (invia eventi pending)
  /// 6. Disconnetti
  Future<int> handleWakeUp();
}
```

---

## Test Specification

### Server Test (Go): `push_bridge_server/*_test.go`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T10.1 | Register + memory check | POST /register | Registration in memory map |
| T10.2 | Unregister | POST /unregister | Registration rimossa |
| T10.3 | Health check | GET /health | 200 OK |
| T10.4 | Nostr event → push FCM | Evento Nostr mock | FCM mock chiamato con data-only payload |
| T10.5 | Push payload no sensitive data | — | Solo `{"styx": "wake"}`, nessun contenuto |
| T10.6 | Dummy Poisson distribution | 10.000 campioni, λ=1/150 | Chi-square test: distribuzione Poisson |
| T10.7 | Server restart | Kill → restart | Memory vuota, health OK |
| T10.8 | Register duplicato | Stesso token × 2 | Aggiornamento, non duplicazione |

### Client Test (Dart): `test/push_handler_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T10.9 | DummyDetector con flag "d":"1" | Push con d=1 | `isDummy == true` |
| T10.10 | DummyDetector senza flag | Push senza d | `isDummy == false` |
| T10.11 | Profilo Balanced: no dummy | Push reale | WakeUp → connect → download |
| T10.12 | Profilo Private: dummy push | Push dummy | WakeUp → check dummy → sleep (zero rete) |
| T10.13 | Profilo Paranoid: dummy push | Push dummy | WakeUp → connect relay → sleep |
| T10.14 | WakeUpOrchestrator flow | Push reale | Connect → download 5 eventi → validate → insert → disconnect |
| T10.15 | FCM token refresh | Token cambiato | Auto re-register al bridge |

### Integration Test (device reale):

| # | Test | Platform | Aspettativa |
|---|------|----------|-------------|
| T10.16 | Push background Android | Android device | App si sveglia, processa |
| T10.17 | Push background iOS | iOS device | App si sveglia (se non force-killed) |
| T10.18 | Push iOS force-killed | iOS, app force-killed | Push NON consegnata (limitazione Apple) |

---

## Note di Implementazione

### iOS Notification Service Extension

Per push affidabili su iOS (anche con app terminata), serve una **Notification Service Extension** nativa in Swift:

```swift
// NotificationServiceExtension/NotificationService.swift
class NotificationService: UNNotificationServiceExtension {
    override func didReceive(_ request: UNNotificationRequest,
                            withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        // Questa extension può:
        // 1. Scaricare eventi dal relay
        // 2. Decifrare
        // 3. Mostrare una notifica con contenuto
        // Oppure semplicemente svegliare l'app principale
    }
}
```

**Limitazione:** La Notification Service Extension riceve solo push con `mutable-content: 1` e contenuto visibile. Una push completamente silent (`content-available: 1` sola) non la attiva se l'app è terminata.

**Strategia ibrida:** Inviare push con `alert: { title: "New activity", body: "" }` + `mutable-content: 1` + `content-available: 1`. L'extension modifica il contenuto, l'app background handler processa i dati.

### Deployment del Bridge

Il bridge è un singolo binario Go. Opzioni di deployment:
- **Docker container:** `FROM gcr.io/distroless/static-debian12`
- **fly.io:** Free tier sufficiente per uso personale
- **VPS minimale:** 128 MB RAM sufficienti
- **Self-hosted:** L'utente può eseguirlo sulla propria infrastruttura

### Poisson Timing — Verifica Statistica

Per verificare che le dummy seguano una distribuzione di Poisson, usare il test del chi-quadrato:
1. Generare 10.000 intervalli con λ = 1/150 sec
2. Dividere in bucket (0-30s, 30-60s, 60-120s, 120-300s, 300+s)
3. Confrontare le frequenze osservate con quelle attese dalla CDF esponenziale
4. Chi-square < valore critico (p > 0.05) → distribuzione corretta

---

## Criteri di Completamento

- [ ] Tutti i test T10.1–T10.15 passano
- [ ] Coverage ≥ 90% (client), ≥ 85% (server)
- [ ] `melos run test:all` include Task 0-10, tutto green
- [ ] Push funziona su device Android reale
- [ ] Push funziona su device iOS reale
- [ ] Bridge stateless verificato (restart → clean state)
- [ ] Dummy Poisson distribution statisticamente verificata
- [ ] Template Swift per Notification Service Extension incluso
