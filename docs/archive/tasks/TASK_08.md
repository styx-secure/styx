# Task 8 — Transport: Email Fallback

**Stato:** Da iniziare
**Durata stimata:** 3-4 giorni
**Dipendenze:** Task 7 (per `TransportInterface`)
**Package:** `packages/transport/` (estensione)
**Coverage target:** ≥ 90%

---

## Obiettivo

Implementare il canale di trasporto fallback via IMAP/SMTP usando account email esistenti. I messaggi cifrati vengono inviati come allegati binari. IMAP IDLE fornisce notifiche quasi-realtime. Questo garantisce interoperabilità massima per utenti senza relay Nostr.

---

## Dipendenze Esterne Aggiuntive

```yaml
dependencies:
  enough_mail: ^2.1.7    # IMAP, POP3, SMTP client
```

---

## Componenti da Implementare

### 1. `EmailConfig` — `lib/src/email/email_config.dart`

```dart
@immutable
class EmailConfig {
  const EmailConfig({
    required this.imapHost,
    required this.imapPort,
    required this.smtpHost,
    required this.smtpPort,
    required this.username,
    required this.password,
    this.useSsl = true,
    this.senderAddress,
    required this.recipientAddress,
  });

  final String imapHost;
  final int imapPort;           // Tipicamente 993 (SSL)
  final String smtpHost;
  final int smtpPort;           // Tipicamente 465 (SSL) o 587 (STARTTLS)
  final String username;
  final String password;        // O OAuth2 token
  final bool useSsl;
  final String? senderAddress;  // Se diverso da username
  final String recipientAddress;

  /// Sender effettivo
  String get sender => senderAddress ?? username;
}
```

### 2. `EmailEncoder` — `lib/src/email/email_encoder.dart`

```dart
class EmailEncoder {
  /// Codifica un TransportMessage come email MIME con allegato binario
  /// Subject: "[STYX:v1:{recipientPubkeyShort}]" per filtraggio
  /// Body: vuoto o messaggio placeholder
  /// Attachment: TransportMessage serializzato come application/octet-stream
  MimeMessage encode(TransportMessage message);

  /// Decodifica un'email ricevuta in un TransportMessage
  /// Restituisce null se l'email non è un messaggio Styx valido
  TransportMessage? decode(MimeMessage email);

  /// Pattern del subject per filtraggio IMAP
  static String subjectPattern(String recipientPubkeyShort);
}
```

**Formato subject:** `[STYX:v1:a1b2c3d4]` dove `a1b2c3d4` sono i primi 8 caratteri hex della pubkey destinatario. Questo permette al filtro IMAP di selezionare solo i messaggi Styx senza esporre la pubkey completa.

**Formato allegato:**
- Filename: `styx_msg_{messageId}.bin`
- Content-Type: `application/octet-stream`
- Content: `TransportMessage.toJson()` encoded come UTF-8 bytes

### 3. `ImapWatcher` — `lib/src/email/imap_watcher.dart`

```dart
class ImapWatcher {
  ImapWatcher({required EmailConfig config});

  /// Inizia il monitoraggio IMAP IDLE per nuovi messaggi Styx
  /// Restituisce uno stream di email ricevute che matchano il pattern
  Stream<MimeMessage> watchInbox();

  /// Fallback polling per provider che non supportano IDLE
  /// [interval] — intervallo di polling (default: 60 secondi)
  Stream<MimeMessage> pollInbox({Duration interval = const Duration(seconds: 60)});

  /// Connetti al server IMAP
  Future<void> connect();

  /// Disconnetti
  Future<void> disconnect();

  /// Marca un messaggio come letto dopo il processing
  Future<void> markAsRead(MimeMessage message);

  /// Cerca messaggi Styx non letti
  Future<List<MimeMessage>> fetchUnreadStyxMessages();
}
```

### 4. `EmailTransport` — `lib/src/email/email_transport.dart`

```dart
class EmailTransport implements TransportInterface {
  EmailTransport({
    required EmailConfig config,
    required EmailEncoder encoder,
    required ImapWatcher watcher,
  });

  @override
  String get name => 'email';

  @override
  Future<void> connect() async {
    await _smtpClient.connect();
    await watcher.connect();
    _subscription = watcher.watchInbox().listen(_handleIncomingEmail);
  }

  @override
  Future<bool> send(TransportMessage message) async {
    final mimeMessage = encoder.encode(message);
    try {
      await _smtpClient.sendMessage(mimeMessage);
      return true;
    } catch (e) {
      return false;
    }
  }

  @override
  Stream<TransportMessage> get messageStream;

  @override
  Future<bool> isAvailable() async {
    try {
      await _testSmtpConnection();
      return true;
    } catch (_) {
      return false;
    }
  }
}
```

---

## Test Specification

### Unit Test: `test/email_encoder_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T8.1 | Encode/decode round-trip | TransportMessage completo | Decode produce lo stesso message |
| T8.2 | Subject pattern corretto | PubkeyShort "a1b2c3d4" | `[STYX:v1:a1b2c3d4]` |
| T8.3 | Allegato binario presente | Messaggio codificato | Attachment con tipo `application/octet-stream` |
| T8.4 | Decode email non-Styx | Email normale senza pattern | `null` |
| T8.5 | Decode email con subject matching ma allegato corrotto | Subject OK + dati random | `null` o eccezione gestita |
| T8.6 | Payload grande | 500 KB messaggio cifrato | Encode/decode OK |

### Mock Test: `test/email_transport_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T8.7 | Send con SMTP mock | Messaggio valido | `true`, email inviata al mock |
| T8.8 | Send con SMTP down | SMTP unreachable | `false`, nessun crash |
| T8.9 | Receive via IMAP mock | Email Styx nel mock | `messageStream` emette il TransportMessage |
| T8.10 | Filtra email non-Styx | Email con subject diverso | Non emessa nel stream |
| T8.11 | Credenziali errate | Username/password sbagliati | Errore gestito, state → error |
| T8.12 | IsAvailable true | SMTP mock raggiungibile | `true` |
| T8.13 | IsAvailable false | SMTP mock down | `false` |
| T8.14 | IDLE reconnect | Disconnessione IMAP forzata | Reconnect automatico |
| T8.15 | Polling fallback | IDLE non supportato | Polling attivo, messaggi ricevuti |

### Integration Test (opzionale): `test/email_integration_test.dart`

| # | Test | Provider | Aspettativa |
|---|------|---------|-------------|
| T8.16 | Round-trip Gmail | Account test Gmail | Invio → ricezione < 30 secondi |
| T8.17 | Round-trip provider generico | IMAP/SMTP generico | Invio → ricezione funzionante |

**Nota:** I test di integrazione con provider reali richiedono credenziali e sono opzionali in CI. Eseguirli manualmente durante lo sviluppo.

---

## Note di Implementazione

### IMAP IDLE vs Polling

`enough_mail` supporta IMAP IDLE nativamente:
```dart
final client = MailClient(account);
await client.startPolling(idleDuration: const Duration(minutes: 29));
client.eventBus.on<MailLoadEvent>().listen((event) { ... });
```

L'IDLE ha un timeout di 29 minuti (RFC 2177). Il client deve re-emettere IDLE prima del timeout. `enough_mail` gestisce questo internamente.

Se il server non supporta IDLE (raro), fallback a polling ogni 60 secondi.

### OAuth2 per Gmail

Gmail richiede OAuth2 per app di terze parti. `enough_mail` supporta OAuth2:
```dart
final token = OauthToken(accessToken: '...', refreshToken: '...');
final auth = OauthAuthentication(userName: email, oauthToken: token);
```

La gestione del token refresh è responsabilità dell'app chiamante, non della libreria Styx.

### Pulizia Inbox

Dopo il processing, i messaggi Styx dovrebbero essere:
1. Marcati come letti (`markAsRead`)
2. Opzionalmente spostati in una cartella dedicata (`STYX_PROCESSED`)
3. Non eliminati (l'utente potrebbe volerli conservare)

### Rate Limiting

Provider email hanno limiti di invio:
- Gmail: 500 email/giorno (account consumer)
- Outlook: 300 email/giorno
- Provider self-hosted: nessun limite tipicamente

Per il use case Styx (2 peer), i volumi sono minimi. Non serve rate limiting dedicato.

---

## Criteri di Completamento

- [ ] Tutti i test T8.1–T8.15 passano
- [ ] Coverage ≥ 90%
- [ ] `melos run test:all` include Task 0-8, tutto green
- [ ] Email round-trip verificato con almeno 1 provider reale (manuale)
- [ ] IMAP IDLE funzionante
- [ ] Email non-Styx correttamente filtrate
