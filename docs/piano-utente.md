# Obiettivo realistico

Può diventare una **PWA di messaggistica E2EE seriamente sicura**, ma non esiste una condizione “sicura al 100%”. Il target dovrebbe essere:

* conformità almeno **OWASP ASVS livello 2**, con controlli selezionati del livello 3;
* rispetto delle aree OWASP MASVS relative a storage, crittografia, autenticazione e rete;
* protocollo documentato;
* test avversariali;
* audit indipendente prima dell’uso per comunicazioni sensibili. ([owasp.org][1])

C’è inoltre una limitazione intrinseca: quando la chat è sbloccata, il JavaScript deve vedere i messaggi per mostrarli. Una XSS, un aggiornamento compromesso o un’estensione malevola potrebbero quindi leggere il contenuto in memoria. CSP, Trusted Types, SRI e una pipeline sicura riducono enormemente il rischio, ma per un livello di garanzia molto elevato conviene affiancare alla PWA un’app nativa firmata che esegua codice installato localmente. ([W3C][2])

---

# Architettura finale consigliata

```text
┌─────────────────────────────┐
│             UI              │
│ Nessun accesso diretto alle │
│ chiavi crittografiche       │
└──────────────┬──────────────┘
               │ protocollo tipizzato
┌──────────────▼──────────────┐
│ Crypto Worker dedicato      │
│ OpenMLS + firme + vault     │
│ chiavi mantenute in memoria │
└───────┬─────────────┬───────┘
        │             │
┌───────▼──────┐ ┌────▼────────────────┐
│ IndexedDB    │ │ Outbox persistente   │
│ tutto cifrato│ │ ciphertext firmati  │
│ transazionale│ │ retry e relay ACK    │
└──────────────┘ └────┬────────────────┘
                      │
            ┌─────────▼──────────┐
            │ Relay Nostr        │
            │ + WebRTC opzionale │
            └─────────┬──────────┘
                      │
            ┌─────────▼──────────┐
            │ Push bridge        │
            │ solo “wake-up”     │
            │ nessun messaggio   │
            └────────────────────┘
```

Una sola scheda o Worker deve poter modificare lo stato MLS. Le altre schede funzionano come client passivi tramite `BroadcastChannel`.

---

# Fase 0 — Bloccare subito i rischi maggiori

Questi interventi devono precedere qualsiasi distribuzione reale.

## 0.1 Eliminare il fallback mock

Attualmente, se il bundle reale non si carica, l’app importa automaticamente `MockStyxChat`. 

Correzione:

```typescript
const StyxChat = await import("./styx-real");

if (!StyxChat?.StyxChat) {
  throw new FatalSecurityError("Modulo crittografico non disponibile");
}
```

Il mock deve:

* stare in un progetto o entry point separato;
* essere incluso solo con `mode === "demo"`;
* usare un dominio separato, per esempio `demo.example.com`;
* non essere importabile dalla build production;
* far fallire la CI se nel bundle production compaiono stringhe come `MockStyxChat`, `seedDemo` o i nomi dei contatti dimostrativi.

**Criterio di completamento:** la mancanza del WASM blocca l’app con errore esplicito; non viene mai mostrata una chat simulata.

## 0.2 Disabilitare le funzioni incomplete

Nascondere temporaneamente:

* pairing remoto;
* WebRTC se non completamente autenticato;
* backup;
* funzioni ledger non integrate;
* presenza online non affidabile.

Non devono esistere pulsanti che terminano con `not implemented`.

## 0.3 Correggere immediatamente la comunicazione

Sostituire:

> “serverless”
> “nessun server conserva i dati”
> “tutto peer-to-peer”

con:

> “Messaggi cifrati end-to-end distribuiti tramite relay federati. I relay non possono leggere il contenuto, ma possono osservare parte dei metadati di trasporto.”

Il protocollo Nostr espone normalmente tag indicizzabili come `p`, e il progetto Nostr stesso riconosce che l’architettura a relay rende difficili la protezione dei metadati, la forward secrecy e la post-compromise security se non si aggiungono livelli ulteriori. ([GitHub][3])

## 0.4 Verificare la versione OpenMLS

La versione inclusa nel WASM deve essere identificata esattamente, insieme a:

* versione OpenMLS;
* provider crittografico;
* versione Rust;
* dipendenze HPKE, AEAD e firme;
* feature flag abilitate.

Nel 2026 OpenMLS ha pubblicato i risultati di un audit che aveva trovato otto problemi, incluso uno ad alta gravità. Il progetto indica versioni corrette nelle linee 0.8.x e 0.7.x e ha inoltre pubblicato aggiornamenti per dipendenze crittografiche vulnerabili. Va quindi utilizzata una versione supportata che includa tutte le correzioni, ricontrollando le release immediatamente prima della distribuzione. ([OpenMLS][4])

---

# Fase 1 — Definire threat model e protocollo

Prima di modificare la crittografia serve un documento formale.

## Avversari da considerare

1. Relay curioso o malevolo.
2. Push bridge compromesso.
3. Server web o CDN compromessi.
4. Attaccante di rete.
5. Furto del dispositivo spento o bloccato.
6. Accesso al profilo browser.
7. XSS.
8. Scheda concorrente che corrompe MLS.
9. Peer malevolo.
10. Replay, riordinamento o duplicazione di eventi.
11. Rollback di un vecchio database.
12. Dipendenza npm/Rust compromessa.

## Garanzie dichiarate

* contenuto dei messaggi illeggibile da relay e bridge;
* autenticità del mittente;
* forward secrecy e post-compromise security secondo MLS;
* protezione locale quando il vault è bloccato;
* rilevamento del cambio delle chiavi;
* consegna affidabile o errore esplicito;
* nessun fallback silenzioso.

MLS è progettato per fornire forward secrecy e post-compromise security, ma il protocollo lascia all’applicazione responsabilità importanti come autenticazione delle identità, servizio di consegna, persistenza e gestione degli stati. ([RFC Editor][5])

## Fuori dal threat model

Devono essere dichiarati esplicitamente:

* sistema operativo già compromesso;
* browser compromesso;
* estensione con accesso completo alla pagina;
* dispositivo sbloccato sotto controllo dell’attaccante;
* screenshot o fotografia dello schermo;
* destinatario che copia volontariamente un messaggio.

---

# Fase 2 — Vault locale realmente cifrato

Il problema più grave è che il backend predefinito è basato su `localStorage`, mentre messaggi e stato MLS vengono serializzati nel backend.

## 2.1 Passare a IndexedDB

Creare questi object store:

```text
meta
key_wrappers
identity
devices
contacts
conversations
messages
mls_state
mls_keys
outbox
inbox_dedupe
push_subscriptions
migrations
```

IndexedDB offre transazioni atomiche: o vengono salvati insieme tutti gli aggiornamenti, oppure l’intera transazione viene annullata. Questo è essenziale per aggiornare nello stesso commit messaggio, stato MLS e outbox. ([W3C][6])

Usare `durability: "strict"` almeno per:

* stato MLS;
* chiavi;
* outbox;
* revoche dei dispositivi.

Richiedere inoltre storage persistente tramite `navigator.storage.persist()`, pur gestendo il caso in cui il browser lo rifiuti. ([MDN Web Docs][7])

## 2.2 Gerarchia delle chiavi

Non cifrare direttamente tutto con la password.

```text
Password
   │
Argon2id(password, salt)
   │
Password KEK
   │ unwrap
Root Storage Key casuale da 256 bit
   ├── Identity Storage Key
   ├── MLS Storage Key
   ├── Message Storage Key
   ├── Backup Key
   └── chiavi per conversazione
```

Procedura:

1. Generare una Root Storage Key casuale da 32 byte.
2. Derivare una KEK dalla password con Argon2id.
3. Usare la KEK solo per cifrare la Root Storage Key.
4. Derivare le altre chiavi tramite HKDF con domain separation.
5. Non salvare mai la Root Storage Key in chiaro.

Argon2id è una funzione memory-hard progettata per rendere più costosi gli attacchi offline alle password. I parametri devono essere calibrati sul dispositivo e salvati insieme al salt, invece di fissare per sempre un numero di iterazioni PBKDF2. ([RFC Editor][8])

Compatibilità:

* modalità preferita: Argon2id tramite WASM verificato;
* fallback: PBKDF2-SHA-256 calibrato;
* mai FNV, SHA semplice o password usata direttamente come chiave.

## 2.3 Cifratura dei record

Per ciascun record:

* AES-256-GCM;
* nonce casuale o contatore univoco da 96 bit;
* mai riutilizzare un nonce con la stessa chiave;
* AAD contenente:

```text
schemaVersion
recordType
recordId
conversationId
keyVersion
```

La Web Crypto API supporta AES-GCM, ma è un’API di basso livello e richiede un uso rigoroso. ([MDN Web Docs][9])

Devono essere cifrati anche:

* alias;
* anteprime;
* timestamp;
* ricevute;
* contatti;
* stato “verificato”;
* gruppi;
* configurazione dei relay;
* token di pairing.

## 2.4 Cancellazione crittografica

OpenMLS elimina materiale chiave obsoleto per garantire forward secrecy e richiede che il backend non conservi copie recuperabili. ([book.openmls.tech][10])

IndexedDB e il filesystem del browser non garantiscono una cancellazione fisica sicura. La soluzione è la **cryptographic erasure**:

* cifrare gli stati sensibili con chiavi di breve durata;
* conservare solo le chiavi ancora necessarie;
* quando un’epoca MLS viene eliminata, distruggere la relativa chiave di wrapping;
* eventuali vecchi blocchi rimasti sul disco diventano inutilizzabili.

## 2.5 Migrazione

Flusso atomico:

1. Bloccare tutte le altre schede.
2. Leggere il vecchio `localStorage`.
3. Creare il nuovo vault.
4. Migrare e cifrare ogni record.
5. Verificare conteggi e checksum.
6. Completare la transazione IndexedDB.
7. Eliminare le vecchie chiavi da `localStorage`.
8. Registrare `migrationVersion`.
9. Rifiutare il downgrade verso vecchie versioni.

---

# Fase 3 — Correggere l’integrazione MLS

## 3.1 StorageProvider nativo

Implementare un `StorageProvider` OpenMLS direttamente sopra il vault cifrato, invece di serializzare l’intero motore come blob Base64.

Vantaggi:

* scritture più piccole;
* cancellazione selettiva delle chiavi obsolete;
* transazioni coerenti;
* migrazioni versionate;
* minore rischio di sovrascrivere uno stato recente.

OpenMLS dispone specificamente di uno `StorageProvider` per chiavi, gruppi, ratchet tree, epoch secrets e altri stati sensibili. ([book.openmls.tech][10])

## 3.2 Separare identità utente e dispositivi

Non usare una singola chiave clonata su più dispositivi.

Struttura:

```text
User Identity Key
   ├── firma Device A
   ├── firma Device B
   └── firma Device C

Ogni dispositivo:
- propria chiave transport
- propria chiave MLS
- propria leaf MLS
- proprio stato locale
```

Aggiungere un dispositivo significa aggiungere una nuova leaf MLS. Revocarlo significa rimuovere quella leaf con un commit.

Non bisogna copiare lo stesso stato MLS su due dispositivi: genererebbe race, riutilizzo di stato e possibili fork.

## 3.3 Commit MLS e conferme

Un commit locale non deve essere definitivamente integrato finché il servizio di consegna non lo ha accettato. La documentazione OpenMLS indica esplicitamente che il client deve attendere l’acknowledgement del Delivery Service prima di fondere il nuovo stato e scartare il precedente. ([book.openmls.tech][11])

Procedura:

1. Preparare il commit.
2. Salvarlo come `pending`.
3. Pubblicarlo.
4. Attendere `OK=true` dai relay previsti.
5. Solo allora eseguire `merge_pending_commit`.
6. Se viene rifiutato, eseguire `clear_pending_commit`.
7. Conservare il vecchio stato fino alla conferma.

## 3.4 Fork detection

Registrare per ogni gruppo:

* epoch;
* hash del ratchet tree;
* hash del transcript;
* ultimo commit accettato;
* versione locale monotona.

Se due stati divergono:

* bloccare l’invio;
* mostrare errore;
* tentare `readd` o `reboot` del gruppo;
* non continuare silenziosamente.

OpenMLS documenta meccanismi specifici di fork resolution. ([book.openmls.tech][12])

---

# Fase 4 — Trasporto affidabile

Il codice attuale chiama `publish()` senza attendere né interpretare la risposta `OK` del relay. 

NIP-01 prevede che il relay risponda obbligatoriamente:

```json
["OK", "<event-id>", true, ""]
```

oppure con un rifiuto e una motivazione. ([GitHub][13])

## 4.1 Macchina a stati

```text
draft
  ↓
queued
  ↓
encrypting
  ↓
publishing
  ↓
accepted_by_relay
  ↓
delivered
  ↓
read
```

Stati di errore:

```text
retry_wait
expired
rejected
failed
```

“Sent” deve significare almeno un `OK=true`, non semplicemente `WebSocket.send()`.

## 4.2 Outbox persistente

Ogni elemento deve contenere:

```typescript
interface OutboxItem {
  messageId: string;
  conversationId: string;
  encryptedEvent: Uint8Array;
  eventId: string;
  createdAt: number;
  expiresAt: number;
  attempts: number;
  nextAttemptAt: number;
  acceptedRelays: string[];
  status: OutboxStatus;
}
```

L’evento deve essere già:

* cifrato;
* firmato;
* serializzato;
* idempotente.

In questo modo anche il service worker può ritentare l’invio senza possedere la chiave privata.

## 4.3 Politica relay

Configurare almeno:

* relay primario;
* relay secondario;
* relay scelto dall’utente;
* relay self-hosted opzionale.

Per messaggi normali:

* “sent” dopo almeno un relay;
* “ridondante” dopo due relay.

Per commit MLS:

* politica più rigorosa;
* set di relay stabilito per conversazione;
* commit definitivo solo dopo il quorum configurato.

## 4.4 Retry

* exponential backoff;
* jitter casuale;
* limite massimo;
* scadenza del messaggio;
* pulsante di retry manuale;
* nessun loop infinito;
* gestione `NOTICE`, `CLOSED`, timeout e disconnessione.

## 4.5 Ricevute

Le ricevute devono essere messaggi MLS cifrati:

```json
{
  "type": "receipt",
  "messageId": "...",
  "status": "delivered"
}
```

Non devono essere eventi Nostr leggibili dal relay.

---

# Fase 5 — Protezione dei metadati

La cifratura del contenuto non nasconde automaticamente:

* mittente;
* destinatario;
* orario;
* dimensione;
* frequenza;
* IP;
* presenza;
* ricevute.

## 5.1 Mailbox key per conversazione

Non usare direttamente la chiave identitaria Nostr nei tag `p`.

Per ogni relazione:

```text
Identity key        → autenticazione
MLS key             → contenuto
Transport mailbox   → instradamento
Ephemeral event key → firma esterna
```

La mailbox key deve:

* essere casuale;
* essere scambiata dentro MLS;
* ruotare periodicamente;
* non essere pubblicamente collegata all’identità.

## 5.2 Gift wrapping

È possibile inserire il ciphertext MLS dentro un wrapper simile a NIP-59:

* chiave esterna usa-e-getta;
* timestamp leggermente modificato;
* payload interno cifrato;
* firma identitaria non visibile al relay.

NIP-59 usa precisamente chiavi casuali esterne e gift wrapping per ridurre l’esposizione del mittente, pur non eliminando completamente i metadati del destinatario. ([GitHub][14])

## 5.3 Modalità privacy elevata

Aggiungere una modalità che:

* disabilita “sta scrivendo”;
* disabilita “letto”;
* disabilita presenza;
* usa padding a dimensioni standard;
* applica batching;
* ritarda leggermente eventi non urgenti;
* usa relay differenti per invio e ricezione.

---

# Fase 6 — Funzionamento offline reale

Lo sblocco locale non deve dipendere dai relay.

## Avvio corretto

```typescript
await vault.open(password);
await loadContacts();
await loadMessages();
renderApplication();

transport.connect().catch(() => {
  showOfflineMode();
});
```

Non:

```typescript
await vault.open(password);
await transport.connect(); // non deve bloccare l'intera app
renderApplication();
```

## Funzioni offline

Devono funzionare:

* apertura dell’app;
* sblocco;
* lettura dei messaggi;
* ricerca locale;
* composizione;
* accodamento;
* modifica delle impostazioni locali;
* backup.

## Background Sync

Usarlo come miglioramento opzionale, non come requisito. La Background Sync API non è disponibile in tutti i browser. Il fallback deve utilizzare:

* evento `online`;
* riconnessione all’apertura;
* retry periodico mentre la pagina è attiva;
* push per risvegliare il service worker quando disponibile. ([MDN Web Docs][15])

---

# Fase 7 — Gestire correttamente più schede

## Soluzione principale

```typescript
await navigator.locks.request(
  `styx-mls:${profileId}`,
  { mode: "exclusive" },
  async () => {
    await runMlsLeader();
  }
);
```

Web Locks impedisce che due contesti dello stesso origin acquisiscano contemporaneamente lo stesso lock esclusivo. ([W3C][16])

## Modello leader/follower

Il leader:

* apre i WebSocket;
* modifica MLS;
* scrive nell’outbox;
* esegue migrazioni;
* gestisce pairing.

Le altre schede:

* inviano comandi tramite `BroadcastChannel`;
* ricevono snapshot;
* non possiedono il motore MLS scrivibile.

Fallback per browser senza Web Locks:

* lease in IndexedDB;
* heartbeat;
* fencing token incrementale;
* compare-and-swap sulla versione dello stato.

Ogni scrittura MLS deve verificare:

```text
expectedStateVersion === currentStateVersion
```

altrimenti viene rifiutata.

---

# Fase 8 — Push notification sicuro

Le notifiche web richiedono necessariamente:

* browser;
* servizio push;
* application server o bridge.

Non sono realmente serverless. La Push API associa a ogni sottoscrizione un endpoint e chiavi dedicate; Web Push cifra il payload tra application server e browser, ma il bridge rimane parte dell’architettura. ([W3C][17])

## Architettura privacy-preserving

Il bridge deve conoscere soltanto:

```text
randomPushHandle → PushSubscription
```

Non:

```text
pubkey utente → PushSubscription
```

Il `randomPushHandle` viene condiviso con i contatti dentro MLS.

Quando arriva un messaggio:

```json
{
  "handle": "random-256-bit-value"
}
```

il bridge invia solo:

```json
{
  "type": "wake"
}
```

La notifica deve mostrare:

> “Hai un nuovo messaggio”

e non:

* mittente;
* contenuto;
* gruppo;
* anteprima.

## Funzioni necessarie

* registrazione firmata;
* deregistrazione;
* refresh automatico della subscription;
* scadenza;
* rotazione dei token;
* rate limit;
* protezione dagli abusi;
* invalidazione alla revoca del dispositivo;
* eliminazione durante il reset.

Le anteprime nella notifica possono essere un’opzione esplicita, spiegando che riducono la sicurezza locale.

---

# Fase 9 — Pairing sicuro

## 9.1 QR pairing

Il QR dovrebbe contenere:

```json
{
  "version": 1,
  "inviteId": "...",
  "identityKey": "...",
  "deviceCredential": "...",
  "mlsKeyPackage": "...",
  "transportMailbox": "...",
  "relayHints": ["..."],
  "expiresAt": 1234567890,
  "nonce": "...",
  "capabilities": ["mls", "push"],
  "signature": "..."
}
```

Proprietà:

* monouso;
* scadenza breve;
* nonce da almeno 128 bit;
* firma;
* protezione replay;
* cancellazione dopo l’utilizzo;
* conferma visiva del contatto.

## 9.2 Pairing remoto

Non inventare un protocollo basato su dodici parole.

Usare:

* SPAKE2+;
* oppure OPAQUE;
* libreria verificata;
* transcript binding;
* codice SAS finale;
* limite ai tentativi;
* scadenza;
* cancellazione immediata dei segreti temporanei.

SPAKE2+ e OPAQUE sono protocolli PAKE standardizzati per derivare una chiave condivisa senza esporre direttamente la password al canale. ([RFC Editor][18])

## 9.3 Safety number

Derivarlo da:

```text
protocolVersion
identityKeyA
identityKeyB
deviceCredentialA
deviceCredentialB
conversationId
```

con ordine canonico e domain separation.

Supportare:

* confronto numerico;
* QR reciproco;
* stato verificato;
* data di verifica;
* avviso bloccante al cambio chiave;
* cronologia delle variazioni.

---

# Fase 10 — Password, biometria, backup e reset

## Cambio password

Non ricifrare tutti i messaggi.

1. Verificare la vecchia password.
2. Derivare la vecchia KEK.
3. Sbloccare la Root Storage Key.
4. Creare nuovo salt.
5. Derivare nuova KEK.
6. Ricifrare solo la Root Storage Key.
7. Salvare atomicamente.
8. Eliminare il vecchio wrapper.

## Sblocco biometrico

WebAuthn può essere usato come secondo metodo di sblocco, preferibilmente tramite estensione PRF quando supportata, senza sostituire il recovery code. WebAuthn fornisce credenziali a chiave pubblica vincolate all’origin e richiede il consenso dell’utente. ([W3C][19])

Prevedere:

* password;
* passkey/biometria;
* entrambe;
* recovery code.

## Backup

Offrire due tipi distinti.

### Identity-only

Contiene:

* identità;
* elenco dispositivi;
* contatti;
* configurazione;
* nessuna cronologia.

### Full backup

Contiene:

* identità;
* messaggi;
* allegati;
* gruppi;
* configurazioni.

Il backup deve avere:

* formato versionato;
* Argon2id;
* AES-GCM;
* manifest con hash;
* autenticazione dell’intero archivio;
* recovery code ad alta entropia;
* verifica completa prima dell’importazione.

Non clonare direttamente uno stato MLS attivo su un nuovo dispositivo: il nuovo dispositivo deve essere aggiunto come leaf distinta.

## Factory reset

Implementare una sola funzione reale:

```typescript
await styx.factoryReset({
  revokeDevice: true,
  unsubscribePush: true,
  clearCaches: true,
  unregisterServiceWorker: false
});
```

Ordine:

1. Bloccare l’app.
2. Distruggere le chiavi root.
3. Revocare il dispositivo se online.
4. Disiscrivere il push.
5. Chiudere relay e worker.
6. Eliminare IndexedDB.
7. Eliminare Cache Storage.
8. Eliminare `localStorage`.
9. Eliminare dati temporanei.
10. Ricaricare.

La distruzione della chiave root deve avvenire prima della pulizia fisica. Il server può inoltre esporre un endpoint che restituisce `Clear-Site-Data` per richiedere al browser la cancellazione dei dati dell’origin. ([W3C][20])

---

# Fase 11 — Sicurezza web

## CSP consigliata

Da adattare ai relay e al bridge effettivi:

```http
Content-Security-Policy:
  default-src 'none';
  script-src 'self';
  style-src 'self';
  img-src 'self' data: blob:;
  font-src 'self';
  connect-src 'self' wss://relay1.example wss://relay2.example https://push.example;
  worker-src 'self';
  manifest-src 'self';
  base-uri 'none';
  object-src 'none';
  frame-ancestors 'none';
  form-action 'none';
  require-trusted-types-for 'script';
  upgrade-insecure-requests
```

CSP riduce il rischio di injection; Trusted Types impedisce l’uso incontrollato di sink pericolosi come `innerHTML`. ([W3C][2])

Altri header:

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Permissions-Policy: camera=(self), microphone=(), geolocation=()
```

## Integrità degli asset

* hash SRI sul bundle iniziale;
* hash del WASM;
* verifica del WASM prima dell’istanziazione;
* manifest firmato delle release;
* asset con nomi content-addressed;
* nessun CDN esterno;
* nessuno script inline.

SRI permette al browser di rifiutare risorse il cui hash non corrisponde. ([MDN Web Docs][21])

## Crypto Worker

Spostare in un Worker dedicato:

* OpenMLS;
* chiavi;
* KDF;
* cifratura del vault;
* firma;
* pairing.

L’interfaccia deve accettare comandi strettamente tipizzati, mai JavaScript arbitrario.

Questo non rende il Worker un secure enclave, ma riduce:

* esposizione accidentale;
* variabili globali;
* accesso da componenti UI;
* permanenza delle chiavi nel main thread.

---

# Fase 12 — Aggiornamenti PWA sicuri

Non usare aggiornamenti immediati indiscriminati durante una transazione MLS.

Flusso:

1. Il nuovo service worker viene scaricato.
2. Rimane in `waiting`.
3. L’app verifica che:

   * vault sia bloccato oppure inattivo;
   * outbox sia coerente;
   * nessuna migrazione sia in corso;
   * nessun pairing sia in corso.
4. Mostra “Aggiornamento disponibile”.
5. Salva lo stato.
6. Attiva il nuovo worker.
7. Esegue eventuali migrazioni.
8. Mantiene una strategia di recovery se la migrazione fallisce.

Ogni schema deve avere:

```text
minimumReaderVersion
minimumWriterVersion
schemaVersion
cryptoVersion
protocolVersion
```

Non consentire a una vecchia build di scrivere su uno schema più recente.

---

# Fase 13 — Supply chain e CI/CD

La pipeline è parte del sistema di sicurezza.

## Controlli automatici

Ad ogni pull request:

* test TypeScript;
* test Rust;
* lint;
* SAST;
* `cargo audit`;
* `cargo deny`;
* analisi dipendenze npm;
* secret scanning;
* scansione licenze;
* fuzzing dei parser;
* test del bundle production;
* controllo assenza mock;
* generazione SBOM;
* verifica riproducibilità.

Per ogni release:

* lockfile immutabili;
* build in ambiente isolato;
* dipendenze pin;
* SBOM CycloneDX;
* firma dell’artefatto;
* provenance della build;
* due approvazioni per modifiche crittografiche;
* chiavi di firma fuori dalla pipeline ordinaria.

OWASP evidenzia la pipeline CI/CD come bersaglio sensibile e raccomanda controlli su dipendenze, artefatti e provenienza. ([cheatsheetseries.owasp.org][22])

## Logging

Non registrare mai:

* password;
* chiavi;
* ciphertext completi;
* recovery code;
* safety number;
* contenuto;
* token push;
* QR pairing.

Registrare solamente eventi tecnici pseudonimizzati:

```text
relay_connection_failed
mls_epoch_conflict
migration_failed
push_subscription_expired
```

OWASP raccomanda logging di sicurezza, evitando però dati sensibili e segreti. ([cheatsheetseries.owasp.org][23])

---

# Fase 14 — Piano di test

## Test crittografici

* test vector RFC MLS;
* test vector Argon2;
* AES-GCM nonce uniqueness;
* firme valide/non valide;
* ciphertext modificato;
* AAD modificato;
* password errata;
* chiave errata;
* record troncato;
* backup corrotto.

## Test di protocollo

* eventi duplicati;
* replay;
* ordine invertito;
* messaggio di epoca precedente;
* commit concorrenti;
* relay che accetta e poi disconnette;
* relay che rifiuta;
* perdita di ricevuta;
* clock errato;
* recipient key cambiata;
* invito QR riutilizzato;
* pairing scaduto;
* peer malevolo.

## Test di storage

* crash durante la transazione;
* quota piena;
* migrazione interrotta;
* rollback del database;
* cancellazione parziale;
* restore di backup;
* storage non persistente;
* reset offline.

## Test multi-tab

Aprire contemporaneamente:

* PWA installata;
* due schede;
* finestra anonima;
* versione vecchia e nuova;
* aggiornamento durante l’invio.

Deve esistere sempre un solo writer MLS.

## Browser matrix

* Safari/iOS PWA;
* Chrome Android;
* Chrome/Edge desktop;
* Firefox desktop;
* modalità offline;
* sospensione e riattivazione;
* riavvio del dispositivo;
* permessi notifiche revocati.

## Release gate

Non distribuire come “secure” finché:

* nessun dato sensibile è in chiaro;
* nessun mock è presente;
* nessuna vulnerabilità critica o alta è aperta;
* test multi-tab superati;
* audit esterno completato;
* versione OpenMLS verificata;
* recovery testato;
* reset testato;
* documentazione delle garanzie aggiornata.

---

# Funzionalità aggiuntive consigliate

## 1. Modalità alta sicurezza

Un interruttore che:

* blocca automaticamente quando l’app va in background;
* nasconde tutte le anteprime;
* disabilita ricevute e typing;
* impedisce screenshot dove supportato dall’app nativa;
* cancella la clipboard dopo la copia;
* richiede verifica dei contatti;
* usa solo relay scelti dall’utente;
* riduce la retention.

## 2. Security Center

Una pagina che mostri:

```text
Vault locale: cifrato
Contatto: verificato
Dispositivo: protetto con passkey
Relay connessi: 2/3
Push: generico
Backup: aggiornato
Versione protocollo: 2
OpenMLS: versione…
Ultimo controllo integrità: …
```

## 3. Key transparency

Per ridurre attacchi di sostituzione delle chiavi:

* key continuity locale;
* cross-signing dei dispositivi;
* gossip tra contatti;
* log Merkle pubblico opzionale;
* avvisi su chiavi differenti osservate da dispositivi diversi.

## 4. Allegati sicuri

* chiave casuale per file;
* cifratura a chunk;
* hash dell’intero file;
* manifest cifrato;
* limiti di dimensione;
* niente rendering diretto di HTML/SVG;
* rimozione opzionale dei metadati EXIF;
* padding delle dimensioni.

## 5. Messaggi effimeri

Devono essere descritti correttamente:

* l’app elimina la propria copia;
* chiede al destinatario di eliminarla;
* non può impedire screenshot o copie;
* il relay può avere ancora il ciphertext fino alla scadenza.

## 6. Relay e bridge self-hosted

Fornire un pacchetto Docker con:

* relay;
* push bridge;
* rate limiting;
* metriche senza dati personali;
* configurazione Tor opzionale;
* backup;
* aggiornamenti firmati.

## 7. Edizione nativa ad alta garanzia

Riutilizzare UI e logica, ma distribuire:

* Android firmata;
* iOS firmata;
* desktop Tauri;
* chiavi protette da Android Keystore, Apple Keychain o TPM;
* aggiornamenti firmati;
* codice locale anziché caricato a ogni apertura.

La PWA resterebbe l’edizione universale; l’app firmata sarebbe quella consigliata per giornalisti, attivisti o comunicazioni ad alto rischio.

---

# Ordine di implementazione

## Priorità P0 — Bloccanti

1. Eliminazione mock.
2. Disabilitazione funzioni incomplete.
3. Correzione dichiarazioni “serverless”.
4. Verifica e aggiornamento OpenMLS.
5. Factory reset reale.
6. CSP iniziale.
7. Blocco multi-tab minimo.

## Priorità P1 — Beta sicura

1. Vault cifrato IndexedDB.
2. StorageProvider OpenMLS.
3. Outbox persistente.
4. Relay `OK` e retry.
5. Avvio offline.
6. Pairing QR con scadenza.
7. Safety number corretto.
8. Password change e backup identity-only.

## Priorità P2 — Produzione

1. Push bridge privacy-preserving.
2. Mailbox key rotanti.
3. Pairing remoto PAKE.
4. Multi-device.
5. Update flow sicuro.
6. Supply-chain hardening.
7. Audit indipendente.

## Priorità P3 — Alta sicurezza

1. NIP-59/gift wrapping.
2. Padding e metadata protection.
3. Key transparency.
4. Allegati.
5. Gruppi.
6. App native firmate.
7. Modalità alta sicurezza.

---

# Definizione finale di “pronta”

L’app può essere definita pronta per l’uso reale soltanto quando:

* nessun messaggio o stato MLS è salvato in chiaro;
* la password protegge una vera gerarchia di chiavi;
* il reset elimina crittograficamente l’identità;
* la lettura funziona offline;
* l’invio offline usa una outbox;
* `sent` deriva da un ACK reale;
* più schede non possono modificare MLS contemporaneamente;
* tutti i pairing sono autenticati, monouso e con scadenza;
* le notifiche non espongono contenuti;
* il bridge non conosce le identità;
* gli aggiornamenti non interrompono transazioni MLS;
* CSP e Trusted Types sono attivi;
* la build è firmata e riproducibile;
* OpenMLS e dipendenze sono aggiornati;
* un audit indipendente non rileva problemi critici o alti.

La scelta architetturale più importante è questa: **prima rendere sicuri vault, stato MLS, concorrenza e consegna; soltanto dopo aggiungere gruppi, allegati, WebRTC e funzioni avanzate**.

[1]: https://owasp.org/www-project-application-security-verification-standard/?utm_source=chatgpt.com "OWASP Application Security Verification Standard (ASVS)"
[2]: https://www.w3.org/TR/CSP3/?utm_source=chatgpt.com "Content Security Policy Level 3"
[3]: https://github.com/nostr-protocol/nips/blob/master/44.md?utm_source=chatgpt.com "nips/44.md at master · nostr-protocol/nips"
[4]: https://blog.openmls.tech/?utm_source=chatgpt.com "OpenMLS"
[5]: https://www.rfc-editor.org/rfc/rfc9420.html?utm_source=chatgpt.com "RFC 9420: The Messaging Layer Security (MLS) Protocol"
[6]: https://www.w3.org/TR/IndexedDB/?utm_source=chatgpt.com "Indexed Database API 3.0"
[7]: https://developer.mozilla.org/en-US/docs/Web/API/StorageManager/persist?utm_source=chatgpt.com "StorageManager: persist() method - Web APIs | MDN"
[8]: https://www.rfc-editor.org/info/rfc9106/?utm_source=chatgpt.com "Argon2 Memory-Hard Function for Password Hashing and ..."
[9]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API?utm_source=chatgpt.com "Web Crypto API - MDN Web Docs"
[10]: https://book.openmls.tech/user_manual/persistence.html?utm_source=chatgpt.com "Persistence of group state"
[11]: https://book.openmls.tech/user_manual/discarding_commits.html?utm_source=chatgpt.com "Discarding commits"
[12]: https://book.openmls.tech/user_manual/fork-resolution.html?utm_source=chatgpt.com "Fork Resolution"
[13]: https://github.com/nostr-protocol/nips/blob/master/01.md?utm_source=chatgpt.com "nips/01.md at master · nostr-protocol/nips"
[14]: https://github.com/nostr-protocol/nips/blob/master/59.md?utm_source=chatgpt.com "nips/59.md at master · nostr-protocol/nips"
[15]: https://developer.mozilla.org/en-US/docs/Web/API/Background_Synchronization_API?utm_source=chatgpt.com "Background Synchronization API - Web APIs | MDN"
[16]: https://www.w3.org/TR/web-locks/?utm_source=chatgpt.com "Web Locks API"
[17]: https://www.w3.org/TR/push-api/?utm_source=chatgpt.com "Push API"
[18]: https://www.rfc-editor.org/info/rfc9383/?utm_source=chatgpt.com "SPAKE2+, an Augmented Password-Authenticated Key ..."
[19]: https://www.w3.org/TR/webauthn-3/?utm_source=chatgpt.com "An API for accessing Public Key Credentials - Level 3"
[20]: https://www.w3.org/TR/clear-site-data/?utm_source=chatgpt.com "Clear Site Data"
[21]: https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity?utm_source=chatgpt.com "Subresource Integrity - Security - MDN Web Docs"
[22]: https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html?utm_source=chatgpt.com "CI CD Security - OWASP Cheat Sheet Series"
[23]: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html?utm_source=chatgpt.com "Logging Cheat Sheet"

