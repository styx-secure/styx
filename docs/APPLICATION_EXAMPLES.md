# Esempi di Applicazioni con Styx

Styx è una libreria Dart/Flutter per costruire ledger crittografici sovrani e peer-to-peer. Due peer — **Affidante** e **Custode** — mantengono una catena di eventi condivisa, a prova di manomissione, senza alcun server centrale. Ogni evento è firmato con Ed25519, concatenato con SHA-256 e ordinato causalmente tramite vector clock.

Questo documento presenta 10 esempi concreti di applicazioni reali che possono essere costruite con Styx, mostrando come le API si adattano a scenari diversi.

---

## 1. Messaggistica P2P Privata

**Descrizione:** Un'app di messaggistica uno-a-uno dove ogni messaggio è un evento firmato crittograficamente e sincronizzato tramite relay Nostr. Nessun server centrale conserva i messaggi: solo i due peer possiedono la cronologia. Messaggi offline vengono recapitati automaticamente al riconnessione grazie al merge deterministico.

**Perché Styx:**
- Zero server: i messaggi transitano solo sui relay Nostr come blob opachi e vivono permanentemente solo sui dispositivi dei due peer
- Ogni messaggio è firmato Ed25519 — impossibile falsificare il mittente o alterare il testo
- Il profilo privacy `paranoid` con Tor maschera completamente i pattern di comunicazione
- La coda outbox garantisce la consegna anche con connettività intermittente
- Il pruning bilaterale consente di cancellare consensualmente messaggi specifici

**Tipi di evento usati:** `message`, `config`

**Esempio di integrazione:**

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:styx/styx.dart';

class PrivateMessenger {
  late final SovereignLedger _ledger;

  Future<void> initialize({required PrivacyProfile privacy}) async {
    _ledger = SovereignLedger(
      config: LedgerConfig(
        relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
        privacyProfile: privacy,
        enableTor: privacy == PrivacyProfile.paranoid,
        pushBridgeUrl: 'https://push.mymessenger.example',
      ),
      ledgerStore: MyLedgerStore(),
    );
    await _ledger.initialize();
  }

  /// Pairing QR di persona.
  Future<String> generateInviteQr() async {
    final qr = await _ledger.generatePairingQr();
    return qr.toQrPayload();
  }

  Future<bool> acceptInvite(String qrPayload, String alias) async {
    final result = await _ledger.processPairingQr(qrPayload);
    if (result.isValid) {
      await _ledger.confirmPairing(peerAlias: alias);
      return true;
    }
    return false;
  }

  /// Pairing remoto via mnemonic condiviso a voce.
  Future<String> startRemoteInvite({String? mnemonic}) async {
    return await _ledger.startRemotePairing(existingMnemonic: mnemonic);
  }

  Future<String> getVerificationCode() async {
    return await _ledger.getDoubleCheckCode();
  }

  Future<void> confirmRemoteInvite(String alias) async {
    await _ledger.confirmPairing(peerAlias: alias);
  }

  /// Invia un messaggio di testo.
  Future<void> sendText(String text) async {
    await _ledger.sendMessage(
      payload: utf8.encode(jsonEncode({
        'type': 'text',
        'text': text,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Invia un messaggio con allegato (solo hash + metadati, non il file).
  Future<void> sendAttachment({
    required String fileHash,
    required String fileName,
    required int sizeBytes,
    String? caption,
  }) async {
    await _ledger.sendMessage(
      payload: utf8.encode(jsonEncode({
        'type': 'attachment',
        'fileHash': fileHash,
        'fileName': fileName,
        'sizeBytes': sizeBytes,
        'caption': caption,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Ascolta i messaggi in arrivo dal peer.
  void onMessageReceived(void Function(Map<String, dynamic>) callback) {
    _ledger.eventStream.remoteEvents.listen((event) {
      if (event.eventType == EventType.message && !event.isPruned) {
        callback(jsonDecode(utf8.decode(event.payload!)));
      }
    });
  }

  /// Carica lo storico messaggi.
  Future<List<Map<String, dynamic>>> loadHistory({
    DateTime? from,
    DateTime? to,
  }) async {
    final events = (from != null && to != null)
        ? await _ledger.getHistoryRange(from: from, to: to)
        : await _ledger.getHistory();

    return events
        .where((e) => e.eventType == EventType.message && !e.isPruned)
        .map((e) => {
              'sender': e.senderPublicKey.toString(),
              'isMe': e.senderPublicKey == _ledger.identity!.publicKey,
              ...jsonDecode(utf8.decode(e.payload!)),
            })
        .toList();
  }

  /// Cancella un messaggio (richiede consenso del peer).
  Future<void> deleteMessage(String eventId) async {
    await _ledger.requestPrune(
      targetEventId: eventId,
      reason: PruneReason.userRequest,
    );
  }

  /// Cancellazione unilaterale GDPR.
  Future<void> gdprDeleteMessage(String eventId) async {
    await _ledger.requestPrune(
      targetEventId: eventId,
      reason: PruneReason.gdprArticle17,
    );
  }

  /// Cambia profilo privacy.
  Future<void> setPrivacy(PrivacyProfile profile) async {
    await _ledger.setPrivacyProfile(profile);
  }
}
```

**Scenari chiave:**
- **Conversazione sensibile:** Due giornalisti comunicano con Tor attivo e profilo `paranoid`. I relay Nostr vedono solo blob cifrati e le push dummy mascherano i pattern temporali.
- **Messaggi offline:** Entrambi scrivono messaggi in aereo. All'atterraggio, il merge deterministico linearizza la conversazione senza perdere nessun messaggio.
- **Diritto all'oblio:** Un utente invoca il GDPR Art. 17 per cancellare unilateralmente il contenuto di un messaggio. L'hash nella catena rimane intatto, ma il payload viene nullificato.
- **Cambio telefono:** Il protocollo di re-keying (`blessNewDevice`) consente di migrare l'identità crittografica al nuovo dispositivo senza perdere la cronologia.

---

## 2. Segnalazioni Anonime su Condizioni Lavorative

**Descrizione:** Un'app che collega un lavoratore (segnalante) con un rappresentante sindacale, un avvocato del lavoro o un ente di tutela. Il lavoratore può segnalare violazioni (sicurezza, straordinari non pagati, mobbing) in modo crittograficamente sicuro. Il ledger crea un registro incontestabile delle segnalazioni, protetto da Tor e push dummy.

**Perché Styx:**
- Tor + profilo `paranoid` proteggono l'identità del segnalante: nessun osservatore di rete può collegare l'app alla segnalazione
- Le firme Ed25519 provano che le segnalazioni provengono dal segnalante originale (utile in sede legale), ma la chiave pubblica non è collegata all'identità anagrafica
- L'SOS integrato consente segnalazioni di emergenza (es. pericolo immediato sul luogo di lavoro)
- Il pruning GDPR consente al lavoratore di cancellare unilateralmente i propri dati dopo la risoluzione del caso
- Il pairing remoto con mnemonic evita qualsiasi incontro fisico tra segnalante e ricevente

**Tipi di evento usati:** `transaction`, `sos`, `message`, `config`

**Esempio di integrazione:**

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:styx/styx.dart';

class WhistleblowerApp {
  late final SovereignLedger _ledger;

  Future<void> initialize() async {
    _ledger = SovereignLedger(
      config: LedgerConfig(
        relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
        privacyProfile: PrivacyProfile.paranoid,
        enableTor: true,
        pushBridgeUrl: 'https://push.workerprotect.example',
      ),
      ledgerStore: MyLedgerStore(),
    );
    await _ledger.initialize();
  }

  /// Pairing remoto: il sindacalista genera un mnemonic e lo comunica
  /// al lavoratore tramite canale sicuro (telefono, di persona).
  Future<String> initiatePairing() async {
    return await _ledger.startRemotePairing();
  }

  Future<void> joinWithMnemonic(String mnemonic) async {
    await _ledger.startRemotePairing(existingMnemonic: mnemonic);
  }

  Future<String> getVerificationCode() async {
    return await _ledger.getDoubleCheckCode();
  }

  Future<void> confirmConnection(String alias) async {
    await _ledger.confirmPairing(peerAlias: alias);
  }

  /// Il lavoratore invia una segnalazione dettagliata.
  Future<void> submitReport({
    required String category,
    required String description,
    required String severity,
    String? location,
    String? evidenceHash,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'report',
        'category': category, // 'safety', 'unpaid_overtime', 'harassment', ...
        'description': description,
        'severity': severity, // 'low', 'medium', 'high', 'critical'
        'location': location,
        'evidenceHash': evidenceHash,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Segnalazione SOS: pericolo immediato sul posto di lavoro.
  Future<void> sendUrgentAlert({
    required String description,
    required double lat,
    required double lng,
  }) async {
    await _ledger.sendSOS(
      payload: utf8.encode(jsonEncode({
        'type': 'workplace_danger',
        'description': description,
        'location': {'lat': lat, 'lng': lng},
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Il sindacalista/avvocato risponde con un aggiornamento.
  Future<void> sendUpdate({
    required String reportRef,
    required String status,
    required String notes,
  }) async {
    await _ledger.sendMessage(
      payload: utf8.encode(jsonEncode({
        'type': 'case_update',
        'reportRef': reportRef,
        'status': status, // 'received', 'investigating', 'resolved'
        'notes': notes,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Il lavoratore allega prove (solo hash, non il file in sé).
  Future<void> attachEvidence({
    required String reportRef,
    required String fileHash,
    required String fileName,
    required String description,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'evidence',
        'reportRef': reportRef,
        'fileHash': fileHash,
        'fileName': fileName,
        'description': description,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Il lavoratore esercita il diritto GDPR alla cancellazione dopo la risoluzione.
  Future<void> deleteMyReports() async {
    final events = await _ledger.getHistory();
    final myKey = _ledger.identity!.publicKey.toString();

    for (final event in events) {
      if (event.senderPublicKey.toString() == myKey && !event.isPruned) {
        await _ledger.requestPrune(
          targetEventId: event.eventId,
          reason: PruneReason.gdprArticle17,
        );
      }
    }
  }

  /// Esporta la catena validata per uso legale.
  Future<bool> exportForLegalUse() async {
    final error = await _ledger.validateChain();
    return error == null;
    // Se la catena è valida, ogni segnalazione è firmata e timestampata:
    // prova crittografica ammissibile in procedimenti legali.
  }
}
```

**Scenari chiave:**
- **Segnalazione di straordinari non pagati:** Il lavoratore documenta le violazioni nel tempo. Ogni segnalazione è firmata e timestampata — il datore di lavoro non può sostenere che le prove siano state fabbricate retroattivamente.
- **Pericolo immediato:** Un lavoratore scopre una violazione grave della sicurezza (es. cavi scoperti, assenza di DPI). L'SOS con geolocalizzazione raggiunge immediatamente il rappresentante sindacale.
- **Anonimato di rete:** Con Tor attivo e profilo `paranoid`, nemmeno l'amministratore IT dell'azienda può rilevare che il lavoratore usa l'app. Le push dummy mascherano i pattern temporali.
- **Caso risolto:** Dopo la chiusura del procedimento, il lavoratore cancella unilateralmente tutti i suoi dati personali (GDPR Art. 17), mantenendo l'integrità della catena hash.

---

## 3. Diario Clinico Paziente-Medico

**Descrizione:** Un'app in cui medico e paziente co-gestiscono un diario clinico privato. Il medico registra visite, prescrizioni, parametri vitali; il paziente registra sintomi, aderenza terapeutica, effetti collaterali. Il ledger crea un fascicolo sanitario bilaterale incontestabile, senza dipendere da piattaforme cloud sanitarie.

**Perché Styx:**
- I dati sanitari non transitano mai su server centrali — conformità massima con la privacy del paziente
- Ogni annotazione è firmata dal suo autore (medico o paziente): attribuzione certa e immutabile
- Il profilo `private` protegge i metadati sanitari nelle push notification
- Il backup Shamir consente al paziente di distribuire l'accesso alla propria identità tra familiari di fiducia
- La retention policy gestisce automaticamente la scadenza dei dati clinici

**Tipi di evento usati:** `transaction`, `message`, `config`

**Esempio di integrazione:**

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:styx/styx.dart';

class ClinicalDiaryApp {
  late final SovereignLedger _ledger;

  Future<void> initialize() async {
    _ledger = SovereignLedger(
      config: LedgerConfig(
        relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
        privacyProfile: PrivacyProfile.private,
        retentionPeriod: Duration(days: 365 * 10),
        retentionTypes: [EventType.message],
      ),
      ledgerStore: MyLedgerStore(),
    );
    await _ledger.initialize();
  }

  /// Il medico registra una visita con diagnosi e prescrizioni.
  Future<void> logVisit({
    required String diagnosis,
    required List<String> prescriptions,
    required Map<String, dynamic> vitals,
    String? notes,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'visit',
        'diagnosis': diagnosis,
        'prescriptions': prescriptions,
        'vitals': vitals,
        'notes': notes,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Il paziente registra un sintomo o effetto collaterale.
  Future<void> logSymptom({
    required String symptom,
    required int severity,
    String? relatedMedication,
    String? notes,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'symptom',
        'symptom': symptom,
        'severity': severity, // 1-10
        'relatedMedication': relatedMedication,
        'notes': notes,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Il paziente conferma l'assunzione di un farmaco.
  Future<void> confirmMedicationTaken({
    required String medication,
    required String dosage,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'medication_taken',
        'medication': medication,
        'dosage': dosage,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Messaggi liberi tra medico e paziente.
  Future<void> sendNote(String text) async {
    await _ledger.sendMessage(
      payload: utf8.encode(jsonEncode({
        'text': text,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Backup dell'identità del paziente distribuito tra familiari.
  Future<List<String>> backupPatientIdentity() async {
    return await _ledger.createIdentityBackup(
      threshold: 2,
      totalShares: 3,
    );
  }

  /// Storico clinico in un intervallo temporale.
  Future<List<Map<String, dynamic>>> getClinicalHistory({
    required DateTime from,
    required DateTime to,
  }) async {
    final events = await _ledger.getHistoryRange(from: from, to: to);
    return events
        .where((e) => e.eventType == EventType.transaction && !e.isPruned)
        .map((e) => {
              'author': e.senderPublicKey.toString(),
              ...jsonDecode(utf8.decode(e.payload!)),
            })
        .toList();
  }

  /// Paziente esercita il diritto GDPR alla cancellazione dei propri dati.
  Future<void> patientGdprDeletion(String eventId) async {
    await _ledger.requestPrune(
      targetEventId: eventId,
      reason: PruneReason.gdprArticle17,
    );
  }
}
```

**Scenari chiave:**
- **Aderenza terapeutica:** Il medico verifica che il paziente assume regolarmente i farmaci. Ogni conferma è firmata dal paziente — log di aderenza verificabile.
- **Secondo parere:** Il paziente mostra il diario clinico a un altro medico. La catena è validabile con `validateChain()`: il secondo medico può verificare che nessun dato è stato alterato.
- **Paziente incapacitato:** Due familiari combinano le loro share Shamir (soglia 2/3) per accedere al diario clinico e informare il medico curante.
- **Cambio medico:** Il paziente crea un nuovo ledger con il nuovo medico; il vecchio diario resta intatto e verificabile come archivio storico.

---

## 4. Notarizzazione Prove Digitali (Due Testimoni)

**Descrizione:** Un'app in cui due parti fungono da "testimoni digitali" reciproci per notarizzare l'esistenza di documenti, foto, video o altri file digitali. L'hash SHA-256 del file viene registrato sul ledger condiviso, creando una prova crittografica di esistenza a una data certa. Nessuna blockchain pubblica, nessun costo di transazione.

**Perché Styx:**
- La catena hash SHA-256 crea una timeline verificabile di notarizzazioni
- Entrambi i peer possiedono una copia del ledger — nessun singolo punto di fallimento
- Le firme Ed25519 identificano chi ha presentato ogni documento
- Il vector clock fornisce ordinamento causale preciso anche senza server di timestamp centralizzato
- Nessun costo per notarizzazione (a differenza delle soluzioni blockchain)

**Tipi di evento usati:** `transaction`, `message`

**Esempio di integrazione:**

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:styx/styx.dart';

class DigitalNotaryApp {
  late final SovereignLedger _ledger;

  Future<void> initialize() async {
    _ledger = SovereignLedger(
      config: LedgerConfig(
        relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
      ),
      ledgerStore: MyLedgerStore(),
    );
    await _ledger.initialize();
  }

  /// Notarizza un file calcolandone l'hash e registrandolo sul ledger.
  Future<void> notarizeDocument({
    required Uint8List fileBytes,
    required String fileName,
    required String mimeType,
    String? description,
  }) async {
    final fileHash = sha256.convert(fileBytes).toString();

    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'notarization',
        'fileHash': fileHash,
        'fileName': fileName,
        'mimeType': mimeType,
        'fileSizeBytes': fileBytes.length,
        'description': description,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Verifica se un file corrisponde a una notarizzazione esistente.
  Future<Map<String, dynamic>?> verifyDocument(Uint8List fileBytes) async {
    final fileHash = sha256.convert(fileBytes).toString();
    final events = await _ledger.getHistory();

    for (final event in events) {
      if (event.eventType != EventType.transaction || event.isPruned) continue;
      final data = jsonDecode(utf8.decode(event.payload!));
      if (data['type'] == 'notarization' && data['fileHash'] == fileHash) {
        return {
          'found': true,
          'notarizedAt': data['timestamp'],
          'notarizedBy': event.senderPublicKey.toString(),
          'eventId': event.eventId,
        };
      }
    }
    return null;
  }

  /// Aggiunge un commento o annotazione a una notarizzazione.
  Future<void> annotateNotarization({
    required String notarizationEventId,
    required String annotation,
  }) async {
    await _ledger.sendMessage(
      payload: utf8.encode(jsonEncode({
        'type': 'annotation',
        'notarizationRef': notarizationEventId,
        'annotation': annotation,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Verifica l'integrità dell'intera catena di notarizzazioni.
  Future<bool> verifyChainIntegrity() async {
    final error = await _ledger.validateChain();
    return error == null;
  }

  /// Elenco di tutte le notarizzazioni con metadati.
  Future<List<Map<String, dynamic>>> listNotarizations() async {
    final events = await _ledger.getHistory();
    return events
        .where((e) => e.eventType == EventType.transaction && !e.isPruned)
        .map((e) => {
              'eventId': e.eventId,
              'author': e.senderPublicKey.toString(),
              ...jsonDecode(utf8.decode(e.payload!)),
            })
        .where((data) => data['type'] == 'notarization')
        .toList();
  }
}
```

**Scenari chiave:**
- **Proprietà intellettuale:** Un inventore notarizza i bozzetti del suo brevetto. Il partner (avvocato, socio) funge da secondo testimone. L'hash e il timestamp sono prove crittografiche di anteriorità.
- **Documentazione immobiliare:** Proprietario e inquilino fotografano lo stato dell'immobile prima dell'affitto. Le foto vengono notarizzate su Styx: nessuno può contestare lo stato originale alla riconsegna.
- **Verifica indipendente:** Un perito può validare con `validateChain()` che nessun evento è stato inserito, rimosso o alterato retroattivamente nella catena di notarizzazioni.

---

## 5. Custodia Condivisa Figli

**Descrizione:** Un'app per genitori separati che gestiscono la custodia condivisa dei figli. Registra scambi di custodia, spese per i figli, comunicazioni importanti e accordi. Ogni azione è firmata e verificabile — utile anche in contesti legali.

**Perché Styx:**
- Il ledger firmato crea un registro legalmente rilevante degli scambi di custodia
- I messaggi firmati sono prove crittografiche di comunicazioni avvenute
- Il pruning unilaterale (GDPR Art. 17) consente a un genitore di rimuovere dati personali specifici
- L'architettura senza server impedisce a terze parti di accedere a dati familiari sensibili
- Con Tor + profilo `paranoid`, nemmeno i relay Nostr possono correlare i pattern di comunicazione

**Tipi di evento usati:** `transaction`, `message`, `config`

**Esempio di integrazione:**

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:styx/styx.dart';

class CustodyApp {
  late final SovereignLedger _ledger;

  Future<void> initialize() async {
    _ledger = SovereignLedger(
      config: LedgerConfig(
        relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
        privacyProfile: PrivacyProfile.paranoid,
        enableTor: true,
      ),
      ledgerStore: MyLedgerStore(),
    );
    await _ledger.initialize();
  }

  /// Registra uno scambio di custodia.
  Future<void> logCustodyExchange({
    required String childName,
    required String fromParent,
    required String toParent,
    required String location,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'custody_exchange',
        'child': childName,
        'from': fromParent,
        'to': toParent,
        'location': location,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Registra una spesa per il figlio.
  Future<void> logChildExpense({
    required double amount,
    required String category,
    required String description,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'child_expense',
        'amount': amount,
        'category': category,
        'description': description,
        'currency': 'EUR',
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Invia una comunicazione formale all'altro genitore.
  Future<void> sendFormalMessage(String text) async {
    await _ledger.sendMessage(
      payload: utf8.encode(jsonEncode({
        'text': text,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Calcola il totale delle spese per categoria in un periodo.
  Future<Map<String, double>> expenseSummary({
    required DateTime from,
    required DateTime to,
  }) async {
    final events = await _ledger.getHistoryRange(from: from, to: to);
    final summary = <String, double>{};

    for (final event in events) {
      if (event.eventType != EventType.transaction || event.isPruned) continue;
      final data = jsonDecode(utf8.decode(event.payload!));
      if (data['type'] == 'child_expense') {
        final cat = data['category'] as String;
        summary[cat] = (summary[cat] ?? 0) + (data['amount'] as num).toDouble();
      }
    }
    return summary;
  }

  /// Esercita il diritto GDPR alla cancellazione di un evento specifico.
  Future<void> gdprDelete(String eventId) async {
    await _ledger.requestPrune(
      targetEventId: eventId,
      reason: PruneReason.gdprArticle17,
    );
  }

  /// Esporta lo storico per uso legale (la catena è verificabile indipendentemente).
  Future<bool> verifyForLegal() async {
    final error = await _ledger.validateChain();
    return error == null;
    // Se true, l'intero storico è integro e ogni evento
    // porta la firma Ed25519 del genitore che l'ha creato.
  }
}
```

**Scenari chiave:**
- **Contestazione in tribunale:** Un genitore nega uno scambio di custodia. Il ledger contiene l'evento firmato con la sua chiave privata — prova crittografica inconfutabile.
- **Privacy massima:** Con Tor attivo e profilo `paranoid`, nemmeno i relay Nostr possono correlare i pattern di comunicazione tra i genitori.
- **Diritto all'oblio:** Un genitore esercita il GDPR Art. 17 per cancellare unilateralmente il contenuto di messaggi specifici, mantenendo la struttura della catena intatta.

---

## 6. Contratti Freelancer-Cliente

**Descrizione:** Un'app per freelancer e clienti che formalizza accordi, milestone e pagamenti su un ledger P2P. Ogni proposta, accettazione, consegna e conferma di pagamento è un evento firmato. La catena hash impedisce modifiche retroattive — nessuna delle due parti può alterare i termini dopo l'accordo.

**Perché Styx:**
- La doppia firma (entrambi i peer firmano i propri eventi) crea un registro bilaterale di impegni
- Il merge deterministico garantisce che anche accordi creati simultaneamente convergano
- La retention policy automatica gestisce la scadenza della documentazione contrattuale
- L'assenza di server elimina il rischio di data breach su piattaforme terze

**Tipi di evento usati:** `transaction`, `message`, `config`

**Esempio di integrazione:**

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:styx/styx.dart';

class FreelanceContractApp {
  late final SovereignLedger _ledger;

  Future<void> initialize() async {
    _ledger = SovereignLedger(
      config: LedgerConfig(
        relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
        retentionPeriod: Duration(days: 365 * 5),
        retentionTypes: [EventType.message],
      ),
      ledgerStore: MyLedgerStore(),
    );
    await _ledger.initialize();
  }

  /// Propone un nuovo accordo/milestone.
  Future<void> proposeAgreement({
    required String title,
    required String terms,
    required double amount,
    required DateTime deadline,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'proposal',
        'title': title,
        'terms': terms,
        'amount': amount,
        'currency': 'EUR',
        'deadline': deadline.toIso8601String(),
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Accetta un accordo proposto dal peer.
  Future<void> acceptAgreement({required String proposalEventId}) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'acceptance',
        'proposalRef': proposalEventId,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Il freelancer segna una milestone come completata, allegando l'hash del deliverable.
  Future<void> completeMilestone({
    required String milestoneId,
    required String deliverableHash,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'milestone_complete',
        'milestoneRef': milestoneId,
        'deliverableHash': deliverableHash,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Il cliente conferma il pagamento.
  Future<void> confirmPayment({
    required String milestoneId,
    required double amount,
    required String paymentRef,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'payment',
        'milestoneRef': milestoneId,
        'amount': amount,
        'paymentRef': paymentRef,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Comunicazioni informali legate al progetto.
  Future<void> sendProjectMessage(String text) async {
    await _ledger.sendMessage(
      payload: utf8.encode(jsonEncode({
        'text': text,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Verifica lo stato di tutti gli accordi.
  Future<List<Map<String, dynamic>>> getAgreementStatus() async {
    final events = await _ledger.getHistory();
    return events
        .where((e) => e.eventType == EventType.transaction && !e.isPruned)
        .map((e) => {
              'eventId': e.eventId,
              'author': e.senderPublicKey.toString(),
              ...jsonDecode(utf8.decode(e.payload!)),
            })
        .toList();
  }
}
```

**Scenari chiave:**
- **Disputa su una milestone:** Il freelancer dichiara di aver completato il lavoro. L'evento con `deliverableHash` è firmato e timestampato — il cliente non può negare di aver ricevuto il deliverable.
- **Pagamento contestato:** Ogni conferma di pagamento è un evento firmato dal cliente. La catena hash impedisce di rimuoverlo o modificarlo retroattivamente.
- **Scadenza documentale:** Dopo 5 anni, la retention policy identifica le comunicazioni informali scadute per il pruning, mantenendo intatti gli eventi transazionali (proposte, accettazioni, pagamenti).

---

## 7. App di Accountability (Sobrietà, Fitness, Studio)

**Descrizione:** Un'app in cui due persone si supportano reciprocamente nel raggiungere un obiettivo personale: sobrietà, fitness, studio, o qualsiasi abitudine. Ogni check-in giornaliero è un evento firmato, e il partner di accountability vede i progressi in tempo reale. L'integrità crittografica impedisce di falsificare i check-in — la matematica ti tiene onesto.

**Perché Styx:**
- I check-in firmati sono prove crittografiche di impegno — impossibile falsificare o retrodatare i progressi
- La privacy P2P protegge dati personali sensibili (stato di sobrietà, peso, etc.) da server terzi
- La sincronizzazione offline consente check-in in qualsiasi momento e luogo
- Il pruning bilaterale permette di rimuovere consensualmente i dati dettagliati dopo il raggiungimento dell'obiettivo

**Tipi di evento usati:** `transaction`, `message`, `config`

**Esempio di integrazione:**

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:styx/styx.dart';

class AccountabilityApp {
  late final SovereignLedger _ledger;

  Future<void> initialize() async {
    _ledger = SovereignLedger(
      config: LedgerConfig(
        relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
        privacyProfile: PrivacyProfile.private,
        pushBridgeUrl: 'https://push.accountability.example',
      ),
      ledgerStore: MyLedgerStore(),
    );
    await _ledger.initialize();
  }

  /// Configura l'obiettivo condiviso.
  Future<void> setGoal({
    required String goalType,
    required String description,
    required int targetDays,
  }) async {
    await _ledger.sendConfig(
      payload: utf8.encode(jsonEncode({
        'type': 'goal_setup',
        'goalType': goalType,
        'description': description,
        'targetDays': targetDays,
        'startDate': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Registra un check-in giornaliero con metriche.
  Future<void> dailyCheckIn({
    required bool success,
    required Map<String, dynamic> metrics,
    String? note,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'daily_checkin',
        'success': success,
        'metrics': metrics, // es. {'weight': 78.5, 'steps': 8200}
        'note': note,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Invia un messaggio di supporto al partner.
  Future<void> sendEncouragement(String text) async {
    await _ledger.sendMessage(
      payload: utf8.encode(jsonEncode({
        'text': text,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Calcola la streak corrente (giorni consecutivi di successo).
  Future<int> getCurrentStreak() async {
    final events = await _ledger.getHistory();
    int streak = 0;
    final myKey = _ledger.identity!.publicKey.toString();

    for (final event in events.reversed) {
      if (event.eventType != EventType.transaction || event.isPruned) continue;
      if (event.senderPublicKey.toString() != myKey) continue;

      final data = jsonDecode(utf8.decode(event.payload!));
      if (data['type'] != 'daily_checkin') continue;

      if (data['success'] == true) {
        streak++;
      } else {
        break;
      }
    }
    return streak;
  }

  /// Pulizia consensuale dopo il raggiungimento dell'obiettivo.
  Future<void> cleanupAfterGoalReached() async {
    final events = await _ledger.getHistory();
    for (final event in events) {
      if (event.eventType == EventType.transaction && !event.isPruned) {
        await _ledger.requestPrune(
          targetEventId: event.eventId,
          reason: PruneReason.userRequest,
        );
      }
    }
  }
}
```

**Scenari chiave:**
- **Check-in falsificato:** Impossibile. Ogni check-in è firmato con la chiave Ed25519 dell'utente e timestampato con HLC. Non si può retrodatare o modificare un evento già nella catena.
- **Privacy dei dati sensibili:** I dati di sobrietà o peso non passano mai per un server cloud. Il profilo `private` aggiunge push dummy per mascherare i pattern temporali.
- **Obiettivo raggiunto:** Entrambi i partner concordano di rimuovere i dati dettagliati tramite pruning bilaterale, mantenendo solo la struttura della catena come prova dell'impegno completato.

---

## 8. Dead Man's Switch / Eredità Digitale

**Descrizione:** Un'app per la pianificazione dell'eredità digitale tra un titolare e un fiduciario (coniuge, figlio, avvocato). Il titolare registra beni digitali, credenziali, istruzioni da seguire in caso di incapacità o decesso. Il backup Shamir garantisce che l'accesso sia possibile anche quando il titolare non è più disponibile. Un meccanismo di "dead man's switch" richiede un check-in periodico: se il titolare non risponde entro un intervallo configurabile, il fiduciario viene allertato.

**Perché Styx:**
- Il backup Shamir divide la chiave privata tra più eredi con soglia configurabile
- Il ledger firmato crea un inventario patrimoniale verificabile e immutabile
- Il re-keying consente il trasferimento formale dell'identità a un erede
- Tor + privacy `private` proteggono i dati patrimoniali da occhi indiscreti
- Nessuna retention policy: i dati patrimoniali devono persistere indefinitamente

**Tipi di evento usati:** `transaction`, `message`, `config`

**Esempio di integrazione:**

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:styx/styx.dart';

class DigitalEstateApp {
  late final SovereignLedger _ledger;

  Future<void> initialize() async {
    _ledger = SovereignLedger(
      config: LedgerConfig(
        relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
        privacyProfile: PrivacyProfile.private,
        enableTor: true,
        // Nessuna retention policy: i dati patrimoniali sono permanenti.
      ),
      ledgerStore: MyLedgerStore(),
    );
    await _ledger.initialize();
  }

  /// Configura l'intervallo del dead man's switch.
  Future<void> configureDeadManSwitch({required int checkInDays}) async {
    await _ledger.sendConfig(
      payload: utf8.encode(jsonEncode({
        'type': 'dead_man_switch_config',
        'checkInIntervalDays': checkInDays,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Il titolare esegue il check-in periodico ("sono ancora qui").
  Future<void> checkIn() async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'alive_checkin',
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Registra un bene nell'inventario patrimoniale.
  Future<void> registerAsset({
    required String assetType,
    required String description,
    required Map<String, dynamic> details,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'asset_registration',
        'assetType': assetType, // 'crypto_wallet', 'bank_account', 'property', ...
        'description': description,
        'details': details,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Registra istruzioni da seguire in caso di incapacità.
  Future<void> recordDirective({
    required String directiveType,
    required String instructions,
  }) async {
    await _ledger.sendMessage(
      payload: utf8.encode(jsonEncode({
        'type': 'directive',
        'directiveType': directiveType, // 'medical', 'financial', 'digital_assets'
        'instructions': instructions,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Prepara il backup Shamir per gli eredi.
  Future<Map<String, String>> prepareInheritanceBackup({
    required List<String> heirNames,
    required int threshold,
  }) async {
    final shares = await _ledger.createIdentityBackup(
      threshold: threshold,
      totalShares: heirNames.length,
    );
    return Map.fromIterables(heirNames, shares);
    // Esempio: {'Figlio Marco': share1, 'Figlia Anna': share2, 'Avv. Rossi': share3}
    // Servono almeno `threshold` share per ricostruire la chiave.
  }

  /// Il fiduciario verifica se il titolare ha mancato il check-in.
  Future<bool> isCheckInOverdue({required int maxDays}) async {
    final events = await _ledger.getHistory();
    final now = DateTime.now();

    for (final event in events.reversed) {
      if (event.eventType != EventType.transaction || event.isPruned) continue;
      final data = jsonDecode(utf8.decode(event.payload!));
      if (data['type'] == 'alive_checkin') {
        final checkinTime = DateTime.parse(data['timestamp'] as String);
        return now.difference(checkinTime).inDays > maxDays;
      }
    }
    return true; // nessun check-in trovato
  }

  /// L'erede ricostruisce l'identità del titolare dalle share Shamir.
  Future<void> restoreFromInheritance(List<String> collectedShares) async {
    final restoredLedger = SovereignLedger(
      config: LedgerConfig(
        relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
      ),
      ledgerStore: MyLedgerStore(),
    );
    await restoredLedger.initialize();
    await restoredLedger.restoreIdentity(shares: collectedShares);
  }
}
```

**Scenari chiave:**
- **Decesso del titolare:** Il fiduciario nota che il check-in è scaduto. Due dei tre eredi uniscono le loro share Shamir (soglia 2/3) per ricostruire la chiave privata e accedere all'inventario completo.
- **Falso allarme:** Il titolare era semplicemente in vacanza. Esegue il check-in al ritorno e la catena registra la continuità di presenza.
- **Cambio fiduciario:** Il titolare usa il re-keying (`blessNewDevice`) per trasferire formalmente la gestione a un nuovo fiduciario, con blessing dal dispositivo originale.

---

## 9. Tracciamento Consegne Peer-to-Peer

**Descrizione:** Un'app per il tracciamento di consegne dirette tra un mittente e un corriere (o tra privati). Ogni passaggio di mano, checkpoint e conferma di ricezione è un evento firmato. Ideale per consegne di valore, documenti legali o farmaci dove serve una catena di custodia verificabile.

**Perché Styx:**
- Ogni passaggio di mano è un evento firmato da chi lo effettua — catena di custodia crittografica
- Il pairing QR consente di collegare mittente e corriere al momento del ritiro
- La geolocalizzazione nel payload crea un tracciamento verificabile del percorso
- La sincronizzazione offline gestisce consegne in aree con copertura intermittente

**Tipi di evento usati:** `transaction`, `message`, `config`

**Esempio di integrazione:**

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:styx/styx.dart';

class DeliveryTrackingApp {
  late final SovereignLedger _ledger;

  Future<void> initialize() async {
    _ledger = SovereignLedger(
      config: LedgerConfig(
        relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
        pushBridgeUrl: 'https://push.deliverytrack.example',
        privacyProfile: PrivacyProfile.balanced,
        retentionPeriod: Duration(days: 90),
        retentionTypes: [EventType.message],
      ),
      ledgerStore: MyLedgerStore(),
    );
    await _ledger.initialize();
  }

  /// Pairing QR al momento del ritiro del pacco.
  Future<String> generatePickupQr() async {
    final qr = await _ledger.generatePairingQr();
    return qr.toQrPayload();
  }

  Future<bool> scanPickupQr(String qrPayload) async {
    final result = await _ledger.processPairingQr(qrPayload);
    if (result.isValid) {
      await _ledger.confirmPairing(peerAlias: 'Corriere');
      return true;
    }
    return false;
  }

  /// Registra il ritiro del pacco.
  Future<void> logPickup({
    required String packageId,
    required String description,
    required double lat,
    required double lng,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'pickup',
        'packageId': packageId,
        'description': description,
        'location': {'lat': lat, 'lng': lng},
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Registra un checkpoint durante il trasporto.
  Future<void> logCheckpoint({
    required String packageId,
    required double lat,
    required double lng,
    String? note,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'checkpoint',
        'packageId': packageId,
        'location': {'lat': lat, 'lng': lng},
        'note': note,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Conferma la consegna con firma del destinatario.
  Future<void> confirmDelivery({
    required String packageId,
    required double lat,
    required double lng,
    required String recipientNote,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'delivery_confirmed',
        'packageId': packageId,
        'location': {'lat': lat, 'lng': lng},
        'recipientNote': recipientNote,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Segnala un problema con la consegna.
  Future<void> reportIssue({
    required String packageId,
    required String issue,
  }) async {
    await _ledger.sendMessage(
      payload: utf8.encode(jsonEncode({
        'type': 'delivery_issue',
        'packageId': packageId,
        'issue': issue,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Traccia lo stato attuale di un pacco.
  Future<String> getPackageStatus(String packageId) async {
    final events = await _ledger.getHistory();
    String lastStatus = 'unknown';

    for (final event in events) {
      if (event.eventType != EventType.transaction || event.isPruned) continue;
      final data = jsonDecode(utf8.decode(event.payload!));
      if (data['packageId'] == packageId) {
        lastStatus = data['type'] as String;
      }
    }
    return lastStatus;
  }
}
```

**Scenari chiave:**
- **Pacco di valore:** Il mittente e il corriere si collegano via QR al ritiro. Ogni checkpoint è firmato dal corriere — prova incontestabile del percorso effettuato.
- **Consegna contestata:** Il destinatario nega di aver ricevuto il pacco. L'evento `delivery_confirmed` firmato è la prova crittografica della consegna avvenuta.
- **Zone senza copertura:** Il corriere attraversa aree senza rete. Gli eventi vengono accodati nell'outbox locale e sincronizzati al rientro della copertura.

---

## 10. Caregiver / Assistenza Anziani con SOS

**Descrizione:** Un'app che collega un caregiver (familiare o professionista) con un assistito anziano. Registra visite, somministrazione farmaci, parametri vitali e segnalazioni di emergenza. Il ledger crittografico crea un registro incontestabile delle cure prestate, e l'SOS integrato fornisce un canale di emergenza immediato.

**Perché Styx:**
- L'SOS integrato permette all'anziano di inviare un segnale di emergenza con geolocalizzazione
- Ogni azione del caregiver è firmata e timestampata — accountability totale sulle cure prestate
- Il profilo privacy `private` protegge i metadati sanitari nelle push notification
- Il backup Shamir permette all'anziano di distribuire l'accesso alla propria identità tra familiari fidati
- La catena hash rende il registro delle cure verificabile da terzi (familiari, ispettori)

**Tipi di evento usati:** `transaction`, `sos`, `message`, `config`

**Esempio di integrazione:**

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:styx/styx.dart';

class CaregiverApp {
  late final SovereignLedger _ledger;

  Future<void> initialize() async {
    _ledger = SovereignLedger(
      config: LedgerConfig(
        relayUrls: ['wss://relay.damus.io', 'wss://nos.lol'],
        privacyProfile: PrivacyProfile.private,
        pushBridgeUrl: 'https://push.caregiver.example',
      ),
      ledgerStore: MyLedgerStore(),
    );
    await _ledger.initialize();
  }

  /// Il caregiver registra la somministrazione di un farmaco.
  Future<void> logMedication({
    required String medication,
    required String dosage,
    String? notes,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'medication',
        'medication': medication,
        'dosage': dosage,
        'notes': notes,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Il caregiver registra i parametri vitali dell'assistito.
  Future<void> logVitals({
    required Map<String, dynamic> vitals,
    String? notes,
  }) async {
    await _ledger.sendTransaction(
      payload: utf8.encode(jsonEncode({
        'type': 'vitals',
        'vitals': vitals, // es. {'pressure': '120/80', 'heartRate': 72, 'temp': 36.5}
        'notes': notes,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// L'anziano invia un segnale SOS con posizione.
  Future<void> sendEmergency({
    required double lat,
    required double lng,
    required String description,
  }) async {
    await _ledger.sendSOS(
      payload: utf8.encode(jsonEncode({
        'type': 'emergency',
        'location': {'lat': lat, 'lng': lng},
        'description': description,
        'timestamp': DateTime.now().toIso8601String(),
      })),
    );
  }

  /// Il caregiver ascolta gli SOS in tempo reale.
  void onEmergency(void Function(Map<String, dynamic>) callback) {
    _ledger.eventStream.eventsByType(EventType.sos).listen((event) {
      callback(jsonDecode(utf8.decode(event.payload!)));
    });
  }

  /// Crea backup dell'identità dell'anziano distribuito tra familiari.
  Future<List<String>> backupElderlyIdentity() async {
    return await _ledger.createIdentityBackup(
      threshold: 2,
      totalShares: 3,
    );
    // share[0] → figlio/a
    // share[1] → altro familiare
    // share[2] → cassetta di sicurezza
  }

  /// Storico delle cure prestate in un intervallo.
  Future<List<Map<String, dynamic>>> getCareLog({
    required DateTime from,
    required DateTime to,
  }) async {
    final events = await _ledger.getHistoryRange(from: from, to: to);
    return events
        .where((e) => e.eventType == EventType.transaction && !e.isPruned)
        .map((e) => {
              'author': e.senderPublicKey.toString(),
              ...jsonDecode(utf8.decode(e.payload!)),
            })
        .toList();
  }

  /// Verifica che il registro non sia stato alterato.
  Future<bool> verifyCareLog() async {
    final error = await _ledger.validateChain();
    return error == null;
  }
}
```

**Scenari chiave:**
- **Caduta dell'anziano:** L'app rileva una caduta e invia un SOS con geolocalizzazione. Il caregiver riceve una push notification privata (senza esporre dati sanitari al provider push).
- **Verifica delle cure:** Un familiare può validare l'intera catena con `validateChain()` per verificare che il registro delle cure non sia stato alterato dal caregiver.
- **Cambio telefono dell'anziano:** Il protocollo di re-keying consente la migrazione dell'identità al nuovo dispositivo tramite blessing dal vecchio.
- **Anziano incapacitato:** Due familiari combinano le loro share Shamir per accedere al registro clinico e informare il medico curante.

---

## Riepilogo delle Feature Styx per Caso d'Uso

| Applicazione | Hash Chain | Firme Ed25519 | SOS | Pruning GDPR | Shamir Backup | Tor | Push Privacy | Pairing QR | Pairing Remoto | Retention Policy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Messaggistica P2P | ✓ | ✓ | | ✓ | | ✓ | ✓ | ✓ | ✓ | |
| Segnalazioni lavorative | ✓ | ✓ | ✓ | ✓ | | ✓ | ✓ | | ✓ | |
| Diario clinico | ✓ | ✓ | | ✓ | ✓ | | ✓ | ✓ | | ✓ |
| Notarizzazione | ✓ | ✓ | | | | | | ✓ | ✓ | |
| Custodia figli | ✓ | ✓ | | ✓ | | ✓ | ✓ | | ✓ | |
| Contratti freelancer | ✓ | ✓ | | | | | | ✓ | ✓ | ✓ |
| Accountability | ✓ | ✓ | | ✓ | | | ✓ | ✓ | ✓ | |
| Eredità digitale | ✓ | ✓ | | | ✓ | ✓ | ✓ | ✓ | | |
| Consegne P2P | ✓ | ✓ | | | | | ✓ | ✓ | | ✓ |
| Caregiver con SOS | ✓ | ✓ | ✓ | | ✓ | | ✓ | ✓ | | |
