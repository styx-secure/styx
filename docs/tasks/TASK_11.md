# Task 11 — Pairing Protocol + Device Migration

**Stato:** Da iniziare
**Durata stimata:** 4-5 giorni
**Dipendenze:** Task 2 (SPAKE2, DH, SessionVerifier), Task 3 (SecureKeyStore, BIP-39, Shamir), Task 7 (TransportInterface, NostrEncryptor)
**Package:** `packages/styx/` (façade)
**Coverage target:** ≥ 90%

---

## Obiettivo

Implementare i tre flussi di pairing (QR fisico, remoto via SPAKE2+mnemonic, Double Check anti-MITM), il protocollo di device migration (re-keying con Blessing Event), e il backup/restore dell'identità via Shamir's Secret Sharing. Questo task unifica crypto_core e transport in flussi utente completi.

---

## Dipendenze Interne

```yaml
dependencies:
  styx_crypto_core: {path: ../crypto_core}
  styx_storage: {path: ../storage}
  styx_ledger_engine: {path: ../ledger_engine}
  styx_transport: {path: ../transport}
  meta: ^1.16.0
```

---

## Componenti da Implementare

### 1. `QrPairingData` — `lib/src/pairing/qr_pairing_data.dart`

Struttura dati per il payload del QR code.

```dart
@immutable
class QrPairingData {
  const QrPairingData({
    required this.publicKey,
    required this.nonce,
    this.relayHints,
  });

  /// Chiave pubblica Ed25519 del peer (hex)
  final StyxPublicKey publicKey;

  /// Nonce monouso (16 bytes) per prevenire replay
  final Uint8List nonce;

  /// URL dei relay Nostr suggeriti (opzionale)
  final List<String>? relayHints;

  /// Serializza come JSON compatto per QR code
  /// Formato: {"pk":"<hex>","n":"<base64>","r":["wss://..."]}
  String toQrPayload();

  /// Deserializza dal payload QR
  factory QrPairingData.fromQrPayload(String payload);

  /// Dimensione stimata del QR (per scegliere la versione QR)
  int get estimatedBytes;
}
```

### 2. `QrPairingService` — `lib/src/pairing/qr_pairing_service.dart`

```dart
class QrPairingService {
  QrPairingService({
    required IdentityManager identityManager,
    required PeerDao peerDao,
  });

  /// Genera i dati per il QR code da mostrare
  /// Include la propria pubkey + un nonce fresh
  Future<QrPairingData> generateQrData({
    required StyxPublicKey localPublicKey,
    List<String>? relayHints,
  });

  /// Processa i dati ricevuti dalla scansione QR del peer
  /// 1. Valida il formato
  /// 2. Verifica che il nonce non sia stato già usato (anti-replay)
  /// 3. Salva il peer nel trust store
  /// 4. Restituisce la pubkey del peer
  Future<PairingResult> processScannedQr({
    required String qrPayload,
    required StyxPublicKey localPublicKey,
  });

  /// Completa il pairing bidirezionale
  /// Dopo che entrambi i peer hanno scansionato il QR dell'altro
  Future<void> completePairing({
    required StyxPublicKey peerPublicKey,
    required String? peerAlias,
  });
}

@immutable
class PairingResult {
  const PairingResult({
    required this.peerPublicKey,
    required this.relayHints,
    required this.isValid,
    this.errorMessage,
  });

  final StyxPublicKey peerPublicKey;
  final List<String> relayHints;
  final bool isValid;
  final String? errorMessage;
}
```

### 3. `RemotePairingService` — `lib/src/pairing/remote_pairing_service.dart`

Pairing remoto completo: mnemonic → SPAKE2 → scambio chiavi → Double Check.

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

class RemotePairingService {
  RemotePairingService({
    required Spake2Protocol spake2Protocol,
    required MnemonicGenerator mnemonicGenerator,
    required SessionVerifier sessionVerifier,
    required DiffieHellman diffieHellman,
    required KeyDerivation keyDerivation,
    required TransportInterface transport,
    required PeerDao peerDao,
  });

  /// Stato corrente del pairing
  RemotePairingState get state;
  Stream<RemotePairingState> get stateStream;

  /// === FLUSSO INITIATOR ===

  /// Step 1: Genera il codice mnemonico da comunicare fuori banda
  Future<String> generateMnemonic({int wordCount = 6});

  /// Step 2: Avvia il pairing come initiator
  /// Pubblica un "pairing beacon" cifrato sul relay con il SPAKE2 message
  /// Attende la risposta del responder
  Future<void> startAsInitiator({
    required String mnemonic,
    required StyxPublicKey localPublicKey,
    required StyxPrivateKey localPrivateKey,
  });

  /// === FLUSSO RESPONDER ===

  /// Step 1: Avvia il pairing come responder con il mnemonic ricevuto fuori banda
  /// Cerca il "pairing beacon" dell'initiator sul relay
  /// Risponde con il proprio SPAKE2 message
  Future<void> startAsResponder({
    required String mnemonic,
    required StyxPublicKey localPublicKey,
    required StyxPrivateKey localPrivateKey,
  });

  /// === COMMON ===

  /// Step 3: Ottieni il codice Double Check da verificare con il peer
  /// Disponibile solo dopo che SPAKE2 è completato
  String getDoubleCheckCode();

  /// Step 4: Conferma che il Double Check code corrisponde
  /// Se confermato → salva il peer nel trust store e completa il pairing
  Future<void> confirmDoubleCheck({
    required bool codeMatches,
    required String? peerAlias,
  });

  /// Annulla il pairing in corso
  Future<void> cancel();

  /// Timeout configurabile (default 5 minuti)
  Duration get timeout;
}
```

**Protocollo di scambio chiavi via relay:**

```
Initiator                         Relay                          Responder
    |                               |                               |
    |  1. genera mnemonic           |                               |
    |  2. comunica mnemonic fuori banda ─────────────────────────>  |
    |                               |                               |
    |  3. SPAKE2 msg + ephemeral DH pubkey                         |
    |  ──── publish kind:4 ──────>  |                               |
    |                               |  <──── subscribe ────────     |
    |                               |  ────── deliver ──────────>   |
    |                               |                               |
    |                               |  4. SPAKE2 msg + DH pubkey   |
    |                               |  <──── publish kind:4 ──────  |
    |  <──── deliver ───────────    |                               |
    |                               |                               |
    |  5. Entrambi calcolano:       |                   5. Idem     |
    |     - SPAKE2 session key      |                               |
    |     - DH shared secret        |                               |
    |     - Double Check code       |                               |
    |                               |                               |
    |  6. Verifica Double Check fuori banda ─────────────────────>  |
    |  <───────────────────────────────────────────── conferma      |
    |                               |                               |
    |  7. Scambio Ed25519 pubkey cifrate con session key            |
    |  ──── publish cifrato ─────>  |  ────── deliver ──────────>   |
    |  <──── deliver ───────────    |  <──── publish cifrato ──────  |
    |                               |                               |
    |  8. Entrambi salvano peer nel trust store                     |
```

### 4. `DoubleCheckVerifier` — `lib/src/pairing/double_check_verifier.dart`

```dart
class DoubleCheckVerifier {
  DoubleCheckVerifier({required SessionVerifier sessionVerifier});

  /// Genera il codice di verifica a 6 cifre
  /// Wrapper semantico attorno a SessionVerifier.generateDoubleCheckCode
  String generateCode(Uint8List sessionKey);

  /// Formatta il codice per il display (es. "483 291" con spazio centrale)
  String formatForDisplay(String code);

  /// Valida il formato di un codice inserito dall'utente
  bool isValidFormat(String input);

  /// Normalizza l'input utente (rimuove spazi, trattini)
  String normalize(String input);
}
```

### 5. `TrustStoreManager` — `lib/src/trust/trust_store_manager.dart`

```dart
class TrustStoreManager {
  TrustStoreManager({required PeerDao peerDao});

  /// Aggiunge un peer al trust store dopo pairing completato
  Future<void> addTrustedPeer({
    required StyxPublicKey peerPublicKey,
    required String? alias,
  });

  /// Rimuove un peer dal trust store (revoca fiducia)
  Future<void> revokePeer(StyxPublicKey peerPublicKey);

  /// Verifica se una pubkey è trusted
  Future<bool> isTrusted(StyxPublicKey publicKey);

  /// Recupera il peer attivo (nel sistema a 2 peer, ce n'è al massimo 1)
  Future<TrustedPeer?> getActivePeer();

  /// Aggiorna la pubkey del peer dopo re-keying
  Future<void> updatePeerKey({
    required StyxPublicKey oldKey,
    required StyxPublicKey newKey,
  });

  /// Recupera la storia dei re-key per un peer
  Future<List<RekeyRecord>> getRekeyHistory(StyxPublicKey currentKey);
}

@immutable
class TrustedPeer {
  const TrustedPeer({
    required this.publicKey,
    required this.alias,
    required this.pairedAt,
    required this.isActive,
  });

  final StyxPublicKey publicKey;
  final String? alias;
  final DateTime pairedAt;
  final bool isActive;
}

@immutable
class RekeyRecord {
  const RekeyRecord({
    required this.oldKey,
    required this.newKey,
    required this.timestamp,
  });

  final String oldKey;
  final String newKey;
  final DateTime timestamp;
}
```

### 6. `ReKeyProtocol` — `lib/src/migration/rekey_protocol.dart`

```dart
enum ReKeyState { idle, blessingCreated, blessingSent, peerUpdated, completed }

class ReKeyProtocol {
  ReKeyProtocol({
    required EventFactory eventFactory,
    required TrustStoreManager trustStoreManager,
    required LedgerService ledgerService,
  });

  /// === LATO VECCHIO DEVICE ===

  /// Crea il Blessing Event: il vecchio device firma la nuova pubkey
  /// L'evento REKEY viene inserito nella catena come qualsiasi altro
  /// Payload: {"old_key": "<hex>", "new_key": "<hex>", "device_info": "..."}
  Future<LedgerEvent> createBlessingEvent({
    required StyxPrivateKey oldPrivateKey,
    required StyxPublicKey oldPublicKey,
    required StyxPublicKey newPublicKey,
    required LedgerEvent? previousEvent,
    required VectorClock currentVectorClock,
    required String localPeerRole,
  });

  /// === LATO PEER RICEVENTE ===

  /// Processa un REKEY event ricevuto dal peer
  /// 1. Verifica la firma con la vecchia chiave pubblica (quella nel trust store)
  /// 2. Estrae la nuova chiave pubblica dal payload
  /// 3. Aggiorna il trust store
  /// 4. Da ora in poi, eventi firmati con la nuova chiave sono accettati
  Future<ReKeyResult> processReKeyEvent({
    required LedgerEvent rekeyEvent,
  });

  /// === LATO NUOVO DEVICE ===

  /// Verifica che il re-keying sia stato processato dal peer
  /// Controlla che il peer abbia ricevuto e processato il REKEY event
  Future<bool> isReKeyAcknowledged();
}

@immutable
class ReKeyResult {
  const ReKeyResult({
    required this.success,
    required this.oldKey,
    required this.newKey,
    this.errorMessage,
  });

  final bool success;
  final StyxPublicKey oldKey;
  final StyxPublicKey newKey;
  final String? errorMessage;
}
```

### 7. `KeyMigrationService` — `lib/src/migration/key_migration_service.dart`

Orchestrazione completa della migrazione device.

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

class KeyMigrationService {
  KeyMigrationService({
    required IdentityManager identityManager,
    required ReKeyProtocol reKeyProtocol,
    required SecureKeyStore secureKeyStore,
    required LedgerService ledgerService,
    required TransportInterface transport,
  });

  /// Stato corrente della migrazione
  MigrationState get state;
  Stream<MigrationState> get stateStream;

  /// === MIGRAZIONE CON VECCHIO DEVICE DISPONIBILE ===

  /// Step 1 (nuovo device): Genera nuova identità
  Future<StyxKeyPair> generateNewIdentity();

  /// Step 2 (vecchio device): Crea e invia il Blessing Event
  /// La nuova pubkey viene passata via QR code dal nuovo device
  Future<void> blessNewDevice({
    required StyxPrivateKey oldPrivateKey,
    required StyxPublicKey oldPublicKey,
    required StyxPublicKey newPublicKey,
  });

  /// Step 3 (nuovo device): Attende che il peer processi il REKEY
  /// e poi sincronizza la storia del ledger
  Future<void> completeOnNewDevice({
    required StyxPrivateKey newPrivateKey,
    required StyxPublicKey newPublicKey,
  });

  /// === MIGRAZIONE DA BACKUP SHAMIR (vecchio device non disponibile) ===

  /// Ripristina identità da share Shamir
  /// Non serve re-keying: la chiave originale viene ricostruita
  Future<StyxKeyPair> restoreFromBackup(List<ShamirShare> shares);
}
```

### 8. `ShamirBackupService` — `lib/src/backup/shamir_backup_service.dart`

```dart
class ShamirBackupService {
  ShamirBackupService({
    required KeyBackup keyBackup,
    required SecureKeyStore secureKeyStore,
  });

  /// Crea un backup della chiave privata corrente
  /// Restituisce gli share serializzati (pronti per QR o testo)
  Future<List<String>> createBackup({
    required StyxPrivateKey privateKey,
    int threshold = 2,
    int totalShares = 3,
  });

  /// Ripristina la chiave privata da share serializzati
  /// Salva automaticamente nel SecureKeyStore
  Future<StyxKeyPair> restoreFromBackup({
    required List<String> serializedShares,
    required String keyId,
  });

  /// Verifica che un set di share sia valido
  /// (deserializza + tenta ricostruzione senza salvare)
  Future<bool> verifyShares(List<String> serializedShares);
}
```

---

## Test Specification

### Unit Test: `test/qr_pairing_service_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T11.1 | GenerateQrData formato | Pubkey + relay hints | QR payload JSON valido, contiene pk, n, r |
| T11.2 | QrPairingData round-trip | Genera → serialize → deserialize | Dati identici |
| T11.3 | ProcessScannedQr valido | QR payload corretto | `isValid == true`, pubkey estratta |
| T11.4 | ProcessScannedQr invalido | JSON malformato | `isValid == false`, errorMessage presente |
| T11.5 | ProcessScannedQr replay | Stesso nonce × 2 | Secondo tentativo rifiutato |
| T11.6 | CompletePairing | Pubkey valida | Peer salvato in trust store |

### Unit Test: `test/remote_pairing_service_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T11.7 | Mnemonic generato | wordCount: 6 | 6 parole BIP-39 valide |
| T11.8 | Full remote pairing (happy path) | Initiator + Responder mock | Entrambi ottengono la pubkey dell'altro |
| T11.9 | SPAKE2 password mismatch | Mnemonic diverso su responder | Stato → failed |
| T11.10 | Double Check code match | Stessa session key | Stesso codice su entrambi |
| T11.11 | Double Check code mismatch (MITM) | Session key diverse | Codici diversi → utente rileva |
| T11.12 | Confirm Double Check true | codeMatches: true | Peer salvato, stato → completed |
| T11.13 | Confirm Double Check false | codeMatches: false | Pairing annullato, stato → failed |
| T11.14 | Timeout pairing | Nessuna risposta entro timeout | Stato → failed |
| T11.15 | Cancel pairing | Cancel durante waitingForPeer | Stato → idle, risorse rilasciate |
| T11.16 | State stream | Full flow | Stati emessi nell'ordine corretto |

### Unit Test: `test/trust_store_manager_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T11.17 | AddTrustedPeer + isTrusted | Pubkey valida | `isTrusted == true` |
| T11.18 | RevokePeer | Peer attivo | `isTrusted == false`, `isActive == false` |
| T11.19 | GetActivePeer | 1 peer attivo | Peer restituito |
| T11.20 | GetActivePeer nessun peer | Nessun pairing | `null` |
| T11.21 | UpdatePeerKey | oldKey → newKey | `isTrusted(newKey) == true`, `isTrusted(oldKey) == false` |
| T11.22 | RekeyHistory | 2 re-key successivi | Lista con 2 record in ordine cronologico |

### Unit Test: `test/rekey_protocol_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T11.23 | CreateBlessingEvent | Old key + new key | Evento REKEY con payload corretto, firmato con old key |
| T11.24 | ProcessReKeyEvent valido | REKEY firmato con chiave trusted | Trust store aggiornato, `success == true` |
| T11.25 | ProcessReKeyEvent firma invalida | REKEY con firma sbagliata | `success == false`, trust store invariato |
| T11.26 | ProcessReKeyEvent chiave non trusted | REKEY da chiave sconosciuta | `success == false` |
| T11.27 | Post-rekey: eventi con nuova chiave accettati | Evento firmato con new key | Validazione OK |
| T11.28 | Post-rekey: eventi con vecchia chiave rifiutati | Evento firmato con old key | Validazione FAIL |

### Unit Test: `test/key_migration_service_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T11.29 | Full migration (vecchio device disponibile) | Old device + new device mock | Blessing → peer update → sync → completed |
| T11.30 | Migration state stream | Full flow | Stati emessi nell'ordine corretto |
| T11.31 | Restore da Shamir backup | 2-of-3 share validi | Keypair originale ricostruito |
| T11.32 | Restore con share insufficienti | 1 share su threshold 2 | Eccezione |

### Unit Test: `test/shamir_backup_service_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T11.33 | CreateBackup produce N share | threshold=2, total=3 | 3 stringhe serializzate |
| T11.34 | RestoreFromBackup round-trip | Create → restore | Keypair identico |
| T11.35 | VerifyShares valido | 2 share corretti | `true` |
| T11.36 | VerifyShares invalido | 1 share corrotto | `false` |

### Integration Test: `test/pairing_integration_test.dart`

| # | Test | Input | Aspettativa |
|---|------|-------|-------------|
| T11.37 | Full QR pairing → 10 eventi → validate | 2 peer simulati | Chain valida su entrambi |
| T11.38 | Full remote pairing → 10 eventi → validate | 2 peer con SPAKE2 | Chain valida su entrambi |
| T11.39 | Pairing → 10 eventi → re-key → 10 eventi → validate | Migrazione device | Chain valida, 20 eventi, REKEY incluso |
| T11.40 | Backup → delete identity → restore → resume | Shamir 2-of-3 | Chain continua senza interruzione |

---

## Note di Implementazione

### Pairing Beacon su Nostr

Per il pairing remoto, l'initiator pubblica un "beacon" sul relay:
- Nostr kind: `4` (encrypted DM) o kind custom
- Il contenuto è cifrato con la session key SPAKE2 (non con DH, perché le pubkey non sono ancora scambiate)
- Tag: `["t", "styx-pairing-v1"]` per filtraggio
- Il responder sottoscrive lo stesso tag e cerca beacon con lo stesso SPAKE2 exchange

**Problema:** Prima del pairing, i peer non conoscono la pubkey Nostr dell'altro. Soluzioni:
1. **Derivazione da mnemonic:** Entrambi derivano una pubkey Nostr temporanea dalla stessa password SPAKE2 tramite HKDF. Questa pubkey effimera viene usata solo per il pairing.
2. **Tag condiviso:** Entrambi calcolano `tag = SHA-256(mnemonic)[0:8]` e sottoscrivono/pubblicano con quel tag.

**Raccomandazione:** Opzione 2 (tag condiviso) è più semplice e non richiede gestione di keypair Nostr effimere.

### Anti-Replay per QR

Mantenere un set in-memory (e/o persistente) degli ultimi 100 nonce QR visti. Un nonce visto due volte indica un tentativo di replay. I nonce scadono dopo 5 minuti (il QR è valido solo per la sessione corrente).

### Pruning del REKEY Event

Come specificato nel manifesto (Sezione 2A): dopo che entrambi i peer hanno processato il REKEY, il payload può essere eliminato tramite Secure Pruning (conservando solo l'hash). Questo perché il payload contiene una correlazione tra due identità crittografiche dello stesso utente, che è dato personale ai fini GDPR.

### Sequence Diagram: Re-Keying

```
Old Device              Peer               New Device
    |                    |                    |
    |  1. New device genera keypair           |
    |  <───── nuova pubkey via QR ────────    |
    |                    |                    |
    |  2. Crea REKEY event                    |
    |     (firma con old key,                 |
    |      payload contiene new key)          |
    |  ──── invia via relay ──>  |            |
    |                    |                    |
    |                    |  3. Verifica firma  |
    |                    |     con old key     |
    |                    |  4. Aggiorna trust  |
    |                    |     store           |
    |                    |                    |
    |                    |  5. Sync storia ──> |
    |                    |                    |
    |  6. (opzionale) wipe old device         |
```

---

## Criteri di Completamento

- [ ] Tutti i test T11.1–T11.40 passano
- [ ] Coverage ≥ 90%
- [ ] `melos run test:all` include Task 0-11, tutto green
- [ ] Pairing QR round-trip funzionante con dati mock
- [ ] Pairing remoto SPAKE2 funzionante end-to-end (mock transport)
- [ ] Double Check rileva MITM simulato
- [ ] Re-keying preserva integrità catena
- [ ] Restore da Shamir ricostruisce identità completa
- [ ] Nessun segreto SPAKE2 residuo in memoria dopo destroy()
