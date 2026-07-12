# Styx Vault — Design (Blocco 3)

**Status: Proposed** — il design non diventa definitivo finché il piano manuale su
dispositivi reali (M1–M5, §15) non è completato: Safari/iOS PWA, Chrome Android, kill
durante transazione, quota/storage pressure reale, private browsing, Argon2id su
mobile reale, limite di memoria WASM su iPhone, module worker + IndexedDB nel worker
su Safari. I parametri mobile sono provvisori fino a tali prove. L'implementazione
desktop non è bloccata, ma nessun supporto iOS/Android può essere dichiarato prima.

Data: 2026-07-12 · Autore: sessione Fase D · Basato su: spike IndexedDB (PR #29),
spike Crypto Worker (PR #30), spike Argon2id (PR #31), envelope MLS v1 (PR #23,
`b4f00ac`), audit `docs/security/2026-07-10-styx-chat-security-report.md` (H1).

Obiettivo: chiudere H1 (dati in chiaro a riposo in `localStorage`) sostituendo il
backend di persistenza della chat con un **vault cifrato** in IndexedDB, sbloccato da
password tramite Argon2id, gestito interamente da un dedicated Crypto Worker.

Questo documento è una specifica di design. **Non autorizza alcuna implementazione.**

---

## 1. Threat model

### 1.1 Il vault protegge contro

- lettura del profilo browser a riposo (furto del dispositivo spento/bloccato);
- copia dei file IndexedDB (esfiltrazione del profilo, sync di profilo);
- backup del filesystem che includono il profilo;
- accesso ai record senza conoscere la password (tutti i namespace sono cifrati con
  chiavi derivate dalla Root Storage Key, mai persistita in chiaro);
- corruzione parziale dei record (AES-GCM autentica; un record corrotto fallisce in
  modo tipizzato e non silenzioso);
- rollback **rilevabile nei limiti del browser**: manifest con generation counter e
  digest (§11) — rilevazione best-effort, non prevenzione;
- manipolazione dei parametri KDF pre-sblocco (bounds fail-closed, §7);
- processi di migrazione interrotti (sequenza riprendibile, mai distruttiva, §10).

### 1.2 Fuori scope o protezione limitata

- browser compromesso mentre il vault è sbloccato (le chiavi sono in memoria nel
  worker);
- estensione malevola con accesso alla pagina o al contesto del worker;
- sistema operativo compromesso (keylogger, memoria, screen capture);
- screenshot o destinatario malevolo (fuori dal perimetro storage);
- rollback completo del profilo a uno snapshot precedente: **non prevenibile** senza
  un monotonic counter hardware, che il web non offre. Il manifest lo rende
  rilevabile solo se sopravvive un riferimento esterno; nessuna promessa oltre
  questo.
- zeroization garantita: JavaScript/WASM non offrono cancellazione fisica immediata
  della memoria; la zeroization è best-effort (§4). Vale anche per la **password**,
  che attraversa il form e `postMessage` come stringa JS immutabile: non è
  zeroizzabile e possono restarne copie nel runtime;
- **rollback per-record**: il replay di un VECCHIO record valido sulla stessa chiave
  (con il suo `rv` storico) autentica correttamente — `rv` nell'AAD previene lo swap
  di posizione, non il rollback temporale del singolo record; il manifest (§11)
  rileva solo regressioni grossolane dell'intero vault, non per-record;
- **metadati strutturali at-rest**: i valori sono cifrati ma le chiavi dei record
  IndexedDB no (es. `<contactId>:<seq>` in `messages`), quindi chi legge il profilo
  vede identificativi interni dei contatti, conteggi, dimensioni e il nome del DB.
  Rischio registrato e accettato per il Blocco 3; mitigazione designata se servirà:
  chiavi opache derivate (HMAC sotto una subkey di indice). I contenuti restano
  protetti (H1 chiuso comunque).

## 2. Architettura

```text
React/UI (unlock form, error surface — issue #24)
   │  protocollo tipizzato, allowlist chiusa (§9)
   ▼
Dedicated Crypto Worker (module worker, CSP: script-src 'self' 'wasm-unsafe-eval'; worker-src 'self')
   ├── styx-kdf-wasm        → Argon2id (artefatto SEPARATO da OpenMLS, §2.1)
   ├── WebCrypto HKDF-SHA-256 → key hierarchy (§5)
   ├── WebCrypto AES-256-GCM  → record encryption (§6)
   ├── IndexedDB vault        → unico accesso al DB (§8)
   └── (fase 2 del rollout) OpenMLS/WASM → runtime MLS nel worker
```

- Il trasporto Nostr **resta fuori dal worker** (nel main thread, come oggi).
- Un solo worker per tab; l'elezione del writer tra tab resta al Web Lock
  `styx-mls:<ns>` esistente (spike IDB, probe P6/P7).
- Nessun oggetto WASM attraversa il confine worker/pagina (finding W-F3: i handle
  wasm-bindgen si clonano come `{__wbg_ptr}` inerte — il confine è protetto dal
  protocollo, non da DataCloneError).
- Byte grandi: sempre `Transferable` (spike worker: transfer 8 MB ≈ 0,2 ms vs clone
  6,8 ms; la sorgente resta neutralizzata).

### 2.1 Separazione degli artefatti WASM

Decisione (spike Argon2id, aggiornato): **`styx-kdf-wasm` è un artefatto separato**
da `openmls-wasm`. L'envelope MLS v1 registra e verifica `wasmArtifactSha256`:
integrare Argon2id nel binario OpenMLS ne cambierebbe il digest invalidando envelope
già persistiti. Entrambi i crate: toolchain pinnata per digest, `Cargo.lock`
committato, build riproducibile verificata, PROVENANCE, caricati nello stesso worker,
ma con lifecycle e matrice di compatibilità separati. `styx-kdf-wasm` vive nel
monorepo (nessun repository separato).

## 3. Lifecycle

Stati del vault (macchina a stati nel worker, esposta via `STATUS`):

```text
UNINITIALIZED   nessun vault presente (nessun wrapper in meta)
LOCKED          vault presente, Root Key non in memoria
UNLOCKING       Argon2id in corso (cancellabile: terminate+respawn)
UNLOCKED        Root Key e subkey in memoria nel worker
MIGRATING       migrazione legacy→vault o upgrade schema in corso
RECOVERING      classificazione/spazzamento post-crash dei marker pending — SOLO
                operazioni che non richiedono chiavi (commit/scarto di un re-wrap
                pending §7.2, ispezione del manifest di migrazione); la ripresa
                della migrazione vera avviene in MIGRATING dopo UNLOCK
LOCKING         wipe best-effort delle chiavi in corso
DESTROYING      factory reset in corso
ERROR           errore strutturato; solo transizioni di recovery ammesse
```

Transizioni valide:

| Da | A | Trigger |
|---|---|---|
| UNINITIALIZED | UNLOCKED | `CREATE_VAULT` (genera Root Key, scrive wrapper) |
| LOCKED | UNLOCKING | `UNLOCK(password)` |
| UNLOCKING | UNLOCKED | unwrap verificato |
| UNLOCKING | LOCKED | password errata / parametri invalidi (errore tipizzato) |
| LOCKED/UNLOCKED | RECOVERING | marker pending rilevati all'apertura |
| RECOVERING | LOCKED | spazzamento senza-chiavi completato (o refusal fail-closed) |
| UNLOCKED | MIGRATING | `MIGRATE` esplicito, oppure automatico all'UNLOCK se il manifest di migrazione è pending (ripresa §10) |
| MIGRATING | UNLOCKED | migrazione committata |
| MIGRATING | LOCKING → LOCKED | `LOCK`/`pagehide`: il passo transazionale corrente completa o abortisce atomicamente, il manifest resta pending, ripresa al prossimo UNLOCK |
| UNLOCKED | LOCKING → LOCKED | `LOCK`, timeout di inattività, `pagehide` |
| ERROR | LOCKED | riavvio del worker (respawn) o reset esplicito dello stato; le chiavi in memoria sono state scartate |
| qualsiasi | DESTROYING → UNINITIALIZED | `DESTROY` (factory reset, §12) |
| qualsiasi | ERROR | errore non recuperabile nella transizione corrente |

Vietate esplicitamente: UNINITIALIZED→UNLOCKING (niente unlock senza wrapper);
MIGRATING→DESTROYING implicito (il reset durante migrazione è ammesso solo come
`DESTROY` esplicito dell'utente); ERROR→UNLOCKED diretto (da ERROR si passa da
LOCKED e da un nuovo UNLOCK); operazioni che richiedono chiavi in RECOVERING;
qualunque scrittura di record fuori da UNLOCKED/MIGRATING.

## 4. Root Storage Key

- 32 byte da `crypto.getRandomValues` **nel worker**;
- mai derivata direttamente dalla password (la password deriva solo la KEK);
- mai persistita in chiaro; esiste solo: (a) wrappata in `meta` (§7), (b) in memoria
  nel worker in stato UNLOCKED;
- mai trasmessa alla pagina, mai inclusa in messaggi del protocollo, mai loggata;
- re-wrap al cambio password e all'upgrade parametri (§7.2): la Root Key **non cambia
  mai** in queste operazioni → nessuna ri-cifratura dei record;
- `LOCK`: sovrascrittura best-effort dei buffer (`fill(0)`) + rilascio dei
  riferimenti; distruzione forte = `terminate()` del worker + respawn (già validato:
  recovery pulito, costo ~init 8–29 ms);
- **limite documentato**: né JS né WASM garantiscono la cancellazione fisica
  immediata della memoria (GC, copie del runtime). La zeroization è best-effort e
  la UI non deve promettere di più.

## 5. Key hierarchy

HKDF-SHA-256 (WebCrypto) dalla Root Storage Key, con domain separation per info
string; salt HKDF = digest SHA-256 di `styx-vault-v1` (costante, pubblica):

```text
Root Storage Key (32 B, casuale)
 ├── HKDF info "styx/vault/identity/v1"  → K_identity
 ├── HKDF info "styx/vault/contacts/v1"  → K_contacts
 ├── HKDF info "styx/vault/messages/v1"  → K_messages
 ├── HKDF info "styx/vault/mls/v1"       → K_mls
 ├── HKDF info "styx/vault/outbox/v1"    → K_outbox
 ├── HKDF info "styx/vault/push/v1"      → K_push
 ├── HKDF info "styx/vault/settings/v1"  → K_settings
 ├── HKDF info "styx/vault/canary/v1"    → K_canary
 ├── HKDF info "styx/vault/manifest/v1" → K_manifest (HMAC-SHA-256 del manifest, §11)
 └── HKDF info "styx/vault/backup/v1"   → K_backup (export/backup futuri)
```

> **Emendamento (2026-07-12, incorporato dal piano Blocco 3 §B3.0):** l'elenco
> chiuso dei namespace payload v1 è `identity, contacts, messages, mls, outbox,
> push, settings, canary` — `settings` (primo namespace di prodotto, PR‑7 del
> piano) e `canary` (record sintetici end-to-end, PR‑6) hanno le info string
> HKDF `styx/vault/settings/v1` e `styx/vault/canary/v1` riportate sopra; mai
> riuso di subkey tra namespace. Implementazione di riferimento:
> `styx-js/src/crypto/vault-keys.js` (PR‑2).

- Una chiave AES-256 per namespace; **mai** riutilizzare la stessa chiave tra
  namespace; le subkey si derivano on-demand allo sblocco e si distruggono al LOCK.
- Il suffisso `/v1` è la key version del namespace: una rotazione futura introduce
  `/v2` e un migratore per-namespace (§11), senza cambiare la Root Key.
- **`meta` e `migrations` non hanno subkey di cifratura perché non contengono MAI
  payload dell'utente**: `meta` ospita il wrapper (la Root Key lì dentro è già
  protetta dalla KEK) e il manifest (esigenza di integrità, non di confidenzialità:
  `K_manifest`); `migrations` ospita solo marker, conteggi e digest — mai payload,
  né in chiaro né cifrati. Il "backup" pre-verifica della migrazione **È
  localStorage stesso**, che resta fonte di verità fino al passo 6 di §10: non
  esiste alcuna copia dei dati legacy dentro IndexedDB.

## 6. Record encryption

AES-256-GCM (WebCrypto), per singolo record:

- **nonce**: 96 bit da `crypto.getRandomValues` a **ogni scrittura** (anche riscrivendo
  la stessa chiave); mai contatori condivisi, mai riuso con la stessa chiave. Con
  chiavi per-namespace e volumi attesi (≤10^6 scritture/namespace) il rischio di
  collisione casuale è ≪ 2⁻³², molto sotto il bound NIST; il test di unicità è in
  matrice (§13);
- **AAD canonica**: i byte UTF-8 di `JSON.stringify([v, ns, k, rv, kv, ct])` — array
  JSON a ordine fisso, interi in base 10, stringhe con l'escaping di JSON.stringify,
  nessuno spazio. I nomi sono quelli del formato record (sotto): `v` = record format
  version (lo "schemaVersion" dell'AAD), poi namespace, record key, record version,
  key version, content type. La stessa serializzazione vale per qualunque
  implementazione (JS oggi, Dart domani, §16);
- **fonte dell'AAD in lettura** (vincolante): `ns` e `k` si prendono dalla
  RICHIESTA (store e chiave richiesti), mentre `v`, `rv`, `kv`, `ct` dal record
  letto. Così un record valido copiato su un'altra chiave o namespace fallisce
  l'autenticazione. Un'implementazione che ricostruisse l'AAD interamente dai campi
  auto-dichiarati del record annullerebbe in silenzio la proprietà anti-swap: la
  matrice §13 (AAD tampering) deve coprire esattamente questo caso. Il limite
  residuo (replay di un vecchio record della stessa chiave) è dichiarato in §1.2;
- **plaintext**: bytes (i valori strutturati sono serializzati prima, JSON o binario
  secondo `contentType`).

Formato del record persistito (structured clone, binario nativo — niente base64,
finding F10 / issue #25):

```js
{
  v: 1,                    // record format version
  ns: 'messages',          // namespace (ridondante con lo store, verificato)
  k: '<recordKey>',        // out-of-line key dello store
  rv: 3,                   // recordVersion (monotono per chiave, anti-swap in AAD)
  kv: 1,                   // keyVersion del namespace
  ct: 'json',              // contentType: 'json' | 'bytes'
  nonce: Uint8Array(12),
  data: Uint8Array(...),   // ciphertext AES-256-GCM (tag incluso)
}
```

Errori: `VAULT_RECORD_CORRUPTED` (auth fail), `VAULT_RECORD_INVALID` (shape),
mai il plaintext o la chiave nei messaggi/log (stessa disciplina dei codici
`MLS_STATE_*`).

## 7. KDF wrapper (record `meta/kdf-wrapper`)

```js
{
  format: 'styx-vault-wrapper',
  version: 1,
  kdf: 'argon2id',
  kdfVersion: 19,                    // Argon2 v1.3
  mKib: 65536, t: 3, p: 1,           // parametri validati (§7.1)
  profile: 'mobile-balanced',        // informativo, in allowlist
  saltB64: '<16 B casuali>',
  outLen: 32,
  wrapAlg: 'A256GCM',
  wrapNonce: Uint8Array(12),
  wrappedRootKey: Uint8Array(48),    // 32 B + tag GCM
  keyVersion: 1,
  createdAt: '<ISO, solo data>',     // metadata non sensibile
  calibratedMs: 130,                 // informativo, mai fidato
  // AAD dell'unwrap (non persistita): byte UTF-8 di JSON.stringify(
  //   [format, version, kdf, kdfVersion, mKib, t, p, saltB64, outLen, keyVersion])
  rewrapPending: null,               // null | wrapper completo in attesa (§7.2)
}
```

Non si salvano mai: password, KEK, hash della password o qualsiasi valore usabile
come autenticatore separato (l'unica verifica della password è l'unwrap GCM).

### 7.1 Parametri come input non fidato

Il wrapper si legge PRIMA dello sblocco → validazione fail-closed prima di toccare
Argon2id:

**Tutti** i campi del wrapper sono vincolati (nessun campo sconosciuto ammesso,
stessa disciplina del parser envelope):

| Campo | Vincolo |
|---|---|
| `format` | esattamente `styx-vault-wrapper` |
| `version` | esattamente 1 (intero) |
| `kdf` | esattamente `argon2id` |
| `kdfVersion` | esattamente 19 |
| `saltB64` | base64 valida, esattamente 16 byte decodificati |
| `outLen` | esattamente 32 |
| `p` | esattamente 1 (WASM senza thread) |
| `mKib` | intero, min 19456 (floor OWASP) … max 262144 (256 MiB) |
| `t` | intero, min 2 … max 8 |
| `(mKib,t,profile)` | combinazione dentro l'allowlist dei profili |
| `profile` | allowlist: `desktop`, `mobile-balanced`, `mobile-low-memory` |
| `wrapAlg` | esattamente `A256GCM` |
| `wrapNonce` | `Uint8Array` di esattamente 12 byte |
| `wrappedRootKey` | `Uint8Array` di esattamente 48 byte (32 + tag GCM) |
| `keyVersion` | intero ≥ 1 |
| `createdAt` | stringa `YYYY-MM-DD` (10 char, solo data) |
| `calibratedMs` | intero 0…600000, informativo |
| `rewrapPending` | `null` oppure un wrapper che supera INTERA questa tabella, con profondità massima 1 (sotto) |

> **Chiarimento normativo (2026-07-12, PR‑2):** `rewrapPending` NON è ricorsivo
> arbitrariamente. Il wrapper attivo può contenere al più UN wrapper pending
> (`rewrapPending = null | pendingWrapper`); il `rewrapPending` di un
> pendingWrapper DEVE essere `null`. Profondità massima: **1**. Un pending che
> contiene un ulteriore pending è rifiutato con `VAULT_WRAPPER_INVALID`.
> Implementazione di riferimento: `styx-js/src/storage/vault-wrapper.js`
> (`MAX_REWRAP_PENDING_DEPTH`).

La validazione avviene per intero PRIMA di toccare Argon2id o WebCrypto: un wrapper
manipolato non raggiunge mai la derivazione né l'unwrap con valori fuori forma.

Fuori intervallo → `VAULT_KDF_PARAMS_INVALID`, nessuna derivazione (anti-DoS: un
record manipolato non può chiedere 3 GiB o iterazioni arbitrarie). `profile` e
`calibratedMs` sono metadati informativi: non decidono MAI come derivare (decidono i
valori numerici validati).

### 7.2 Re-wrap (upgrade parametri, cambio password)

Atomico, transazionale, riprendibile; non cambia la Root Key; non ri-cifra i record:

```text
 1. unlock con i vecchi parametri → unwrap Root Storage Key
 2. derivazione nuova KEK (nuovo salt; parametri nuovi validati §7.1)
 3. creazione nuovo wrapper → scritto in `rewrapPending` (il wrapper attivo resta)
 4. verifica: unwrap del nuovo wrapper e confronto byte-a-byte della Root Key
 5. commit atomico: il nuovo wrapper diventa attivo (una sola scrittura IDB)
 6. rimozione di `rewrapPending`
```

Crash in qualunque punto: all'apertura successiva esiste sempre almeno un wrapper
funzionante (l'attivo fino al passo 5, il nuovo dopo); `RECOVERING` completa o scarta
il pending. Mai downgrade automatico dei parametri (downgrade = azione esplicita
dell'utente, registrata).

## 8. IndexedDB

Database `styx-vault-<namespace-utente>`, un object store per dominio dati:

```text
meta        wrapper KDF, manifest, versioni schema     (out-of-line key: string)
identity    identità cifrata                            (idem)
contacts    contatti                                    (idem)
messages    messaggi (chiave: `<contactId>:<seq>`)      (idem)
mls         stato MLS: record `state:meta` (header dell'envelope, JSON cifrato) +
            `state:payload` (byte nativi cifrati) — mapping esatto in §10.1
outbox      coda in uscita                              (idem)
push        registrazione push (wake-up only)           (idem)
settings    impostazioni (primo namespace di prodotto, piano PR‑7)   (idem)
canary      record sintetici end-to-end (piano PR‑6)    (idem)
migrations  marker/manifest di migrazione, backup temporanei
```

> **Emendamento (2026-07-12, incorporato dal piano Blocco 3 §B3.0):** gli store
> `settings` e `canary` completano l'elenco chiuso v1 (vedi §5 per le relative
> subkey HKDF). `meta` e `migrations` restano senza subkey di cifratura (§5).

Regole (tutte validate dallo spike, finding F1–F10):

- **API**: IndexedDB nativo, nessun wrapper (idb/Dexie scartati con motivazione);
- **transazioni**: promise risolta su `oncomplete` (mai su `onsuccess` dell'ultima
  request), `durability: 'strict'`; il callback di transazione non può contenere
  `await` esterni (auto-commit); multi-store transaction per gli aggiornamenti che
  toccano `meta` + dati;
- **upgrade**: registry di migratori per versione (stessa struttura del prototipo);
  eccezione nel migratore → `transaction.abort()` → il DB resta alla versione
  precedente, retry possibile (probe P4);
- **auto-close su `versionchange`**: obbligatorio (F5/F6): il worker chiude il DB e
  passa a `LOCKED`/`ERROR` strutturato; mai lasciare open pendenti su DB bloccati
  (deadlock);
- **timeout bounded + retry**: open bloccati → `VAULT_BLOCKED` con retry a backoff
  (50 ms, F4); `navigator.storage.persist()` sempre in race bounded (F8: su Firefox
  può non risolvere mai);
- **quota**: `estimate()` informativo; `QuotaExceededError` → errore tipizzato
  fail-closed e non distruttivo (issue #27: la quota sostituisce il cap dei 16 MiB
  del parser envelope);
- **multi-tab**: nel Blocco 3 l'accesso al vault è **single-tab**: solo la tab che
  detiene il Web Lock esistente apre il vault (in lettura e scrittura); le altre
  restano nello stato "sessione attiva in un'altra scheda" come oggi — nessun reader
  concorrente, nessuna copia delle chiavi in più worker. `onblocked` gestito sempre;
- **destroy**: `deleteDatabase` con gestione `onblocked` (chiusura di tutte le
  connessioni prima, F6);
- **private browsing**: il vault funziona ma è effimero; da verificare in M4.

## 9. Worker protocol

Allowlist chiusa; validazione **runtime** di ogni messaggio (mai solo
TypeScript/JSDoc); payload massimi per tipo; `{id, type, payload}` →
`{id, ok, result | error:{code, details}}` (details in allowlist, issue #26; mai
`causeMessage` auto-propagato):

| Tipo | Direzione pagina→worker | Note |
|---|---|---|
| `INIT` | url wasm in allowlist (`/vendor/…`, `/kdf/…`) | CodeQL: client-side request forgery |
| `CREATE_VAULT` | password (string), profilo richiesto | solo da UNINITIALIZED |
| `UNLOCK` | password | max 1 in volo; cancel = terminate |
| `LOCK` | — | wipe best-effort |
| `GET` / `PUT` / `DELETE` | ns in allowlist, key regex, value bytes (transfer) | solo UNLOCKED/MIGRATING |
| `LIST` | ns, prefix | restituisce chiavi, mai valori in massa non richiesti |
| `TRANSACTION` | lista ops [{op,ns,key,value}] | atomica, un solo commit |
| `MIGRATE` | sorgente ('localStorage-v1') | §10 |
| `STATUS` | — | stato §3 + versioni |
| `DESTROY` | conferma esplicita (token) | §12 |
| `SHUTDOWN` | — | chiusura pulita |

- `onmessage` con origin guard difensivo: su un dedicated worker `event.origin` è
  la stringa vuota, quindi il guard è vacuo come controllo — si mantiene solo come
  difesa in profondità e per CodeQL (js/missing-origin-check); la difesa reale del
  confine è l'allowlist + la validazione runtime;
- chiavi/namespace validati con regex e `Object.fromEntries` su strutture costruite
  (CodeQL js/remote-property-injection);
- nessun oggetto WASM nel protocollo (W-F3); i byte grandi viaggiano come
  `Transferable` nei due sensi;
- risposte di errore: solo codici stabili + details allowlistati; mai payload,
  chiavi, stato serializzato.

## 10. Migrazione localStorage → vault

Riusa la disciplina a 12 passi già rodata (PR #23). Sorgenti: identità cifrata
esistente, contatti, messaggi, envelope MLS, impostazioni, outbox eventuale, push
registration. **Lo stato MLS non viene mai ri-serializzato**: si trasporta
l'envelope validato dal codec esistente.

### 10.1 Mapping envelope MLS ↔ record del vault

Il codec `mls-state-envelope.js` resta l'unico validatore del formato envelope
(§16); il worker lo usa in entrambe le direzioni:

- **scrittura** (migrazione o `_persistMls`): l'envelope viene parsato dal codec;
  `state:meta` = il JSON dell'envelope SENZA il campo `payload` (restano tutti i
  campi header, inclusi `payloadSha256` e `payloadEncoding`), cifrato come
  `ct:'json'`; `state:payload` = i byte del payload decodificati da base64, cifrati
  come `ct:'bytes'` (binario nativo — finding F10, chiude issue #25); i due PUT
  avvengono nella stessa transazione;
- **lettura** (restore): il worker decifra entrambi i record, ricalcola
  `payloadSha256` sui byte e lo confronta con quello in `state:meta` (fail-closed:
  mismatch → `MLS_STATE_CORRUPTED`), ricompone l'envelope e lo passa alla verifica
  di compatibilità e al restore esistenti;
- **verifica di migrazione (passo 4)**: payload byte-identico alla decodifica della
  sorgente + campi header deep-equal + `payloadSha256` ricalcolato sui byte.

```text
 1. vault UNLOCKED (creato con CREATE_VAULT; la migrazione richiede la password)
 2. manifest di migrazione in `migrations` (pending marker, sorgente, conteggi)
 3. per ogni chiave legacy: read → encrypt → PUT nel namespace corrispondente
 4. re-read di OGNI record scritto → decrypt → confronto byte-a-byte con la sorgente
 5. commit del manifest (stato 'verified')
 6. SOLO ORA: rimozione delle chiavi localStorage (ordine: dati → marker legacy)
 7. manifest 'completed'; i backup temporanei si rimuovono per ultimi
```

- Fail-closed: qualunque errore ai passi 2–5 lascia localStorage intatto e il vault
  parziale marcato pending (ripresa in MIGRATING al prossimo UNLOCK, idempotente;
  RECOVERING si limita a classificare i marker, §3);
- crash tra 6 e 7: la ripresa completa la rimozione (i dati sono già verificati);
- mai cancellare localStorage finché ogni record non è scritto, riletto, decifrato,
  confrontato e committato;
- la migrazione non tocca il wire format né l'envelope (che resta il formato interno
  del record `mls/state:*`).

## 11. Rollback e recovery

**Manifest** (record `meta/manifest`, aggiornato in transazione con ogni scrittura
rilevante):

```js
{
  schemaVersion: 1,          // schema del vault
  migrationVersion: 1,       // ultima migrazione completata
  generation: 42,            // counter monotono incrementato a ogni commit
  lastTxId: '<uuid>',        // ultima transazione riuscita
  hmacB64: '<HMAC-SHA-256 sotto K_manifest dei campi precedenti in forma canonica
             (stessa regola di serializzazione dell'AAD, §6)>',
}
```

- L'HMAC sotto `K_manifest` (§5) rende il tampering del manifest rilevabile
  post-sblocco (un attaccante che scrive IDB non ha la subkey); prima dello sblocco
  il manifest non è fidato e nessuna decisione di sicurezza vi si appoggia. Il
  generation
  counter rende **rilevabile** (non prevenibile) un rollback del profilo se un
  riferimento esterno sopravvive (es. il device peer nota `generation` regredita nel
  gossip applicativo futuro). **Nessuna promessa di rollback resistance assoluta**
  senza contatore hardware.

**Recovery per scenario:**

| Scenario | Comportamento |
|---|---|
| worker terminato (crash/kill) | respawn; pending rifiutate `WORKER_TERMINATED`; stato ricostruito da IDB (validato W-F5) |
| DB bloccato (`onblocked`) | retry bounded con backoff; poi `VAULT_BLOCKED` alla UI (F4/F5) |
| quota esaurita | errore tipizzato, transazione abortita, nessuna perdita (P8) |
| record corrotto | `VAULT_RECORD_CORRUPTED` puntuale; il resto del vault resta leggibile; il record NON viene cancellato automaticamente |
| password errata | unwrap GCM fallisce → `VAULT_WRONG_PASSWORD`; nessun contatore persistito che permetta lockout manipolabile |
| wrapper incompatibile | `VAULT_WRAPPER_UNSUPPORTED` con versioni salvate/correnti e azioni (stesso pattern di MLS_STATE_INCOMPATIBLE); mai restore ottimistico |
| migrazione interrotta | ripresa idempotente da manifest/marker (§10) |
| backup temporanei | in `migrations`, rimossi per ultimi, mai auto-ripristinati senza azione esplicita |

## 12. Factory reset

Ordine obbligato — **prima la distruzione della Root Key, poi la pulizia best-effort
dei ciphertext**:

```text
 1. LOCK del worker (wipe best-effort chiavi in memoria)
 2. sovrascrittura del record wrapper in `meta` (best-effort: la `put` IDB non
    cancella fisicamente i byte precedenti nel backing store fino a compaction)
 3. deleteDatabase del vault (tutti gli store, backup e marker inclusi)
 4. localStorage legacy: chiavi `mls:*`, marker di migrazione, resto del namespace
 5. Cache Storage + dati del service worker (unregister o clear scoped)
 6. push subscription (unsubscribe) e record push
 7. outbox
 8. terminate() del worker + respawn in UNINITIALIZED
```

L'ordine (2 prima di 3–7) fa sì che, se la pulizia fallisce parzialmente, gli
eventuali ciphertext residui non abbiano più un wrapper attivo; un residuo fisico
del vecchio wrapper nel backing store resta comunque protetto da Argon2id + qualità
della password (nessuna garanzia di cancellazione fisica: coerente con §4). Il reset
è idempotente e ripetibile.

## 13. Matrice di test

| Categoria | Contenuto minimo |
|---|---|
| unit | validazione wrapper §7.1 (ogni bound, ogni campo), AAD canonica, protocollo (ogni tipo, payload malformati), state machine §3 (transizioni vietate) |
| integration | create→unlock→put/get→lock→unlock cross-worker; TRANSACTION multi-store |
| migration | happy path, crash a ogni passo §10, ripresa idempotente, localStorage intatto su fallimento |
| crash | kill del worker a metà PUT/TRANSACTION (all-or-nothing, P3); kill della pagina |
| corruption | bit-flip su nonce/data/AAD → `VAULT_RECORD_CORRUPTED`, vault utilizzabile |
| quota | QuotaExceeded su PUT e su migrazione → fail-closed non distruttivo |
| multi-tab | writer election, `versionchange` su upgrade con due tab, steal |
| worker termination | pending rifiutate, respawn, stato coerente |
| KDF bounds | ogni parametro fuori intervallo → `VAULT_KDF_PARAMS_INVALID`, nessuna derivazione |
| wrong password | unwrap fallisce, nessun side-effect, retry possibile |
| AAD tampering | record copiato su altra chiave/ns/versione → auth fail |
| nonce uniqueness | campione statistico su N scritture: nessun riuso per chiave |
| schema upgrade | migratore che lancia → versione invariata, retry (P4) |
| factory reset | dopo ogni stato (incl. migrazione parziale): tutto rimosso, ordine §12 |
| offline | vault pienamente funzionante senza rete |
| browser reali | Playwright chromium+firefox (pattern degli spike) |
| dispositivi mobili | piano manuale M1–M5 (§15) |

## 14. Rollout incrementale

Ogni passo con gate e rollback separato; nessun passo inizia senza il precedente
verificato:

1. **Worker + protocollo senza dati**: spawn, INIT, STATUS, ECHO; nessun accesso a
   storage reale. Rollback: rimozione del worker.
2. **`styx-kdf-wasm`**: crate nel monorepo, build riproducibile, PROVENANCE, probe
   di regressione (ancore hex dello spike). Rollback: revert del crate.
3. **Vault nuovo (vuoto)**: CREATE_VAULT/UNLOCK/LOCK su IDB reale, nessun dato di
   prodotto. Rollback: DESTROY + rimozione.
4. **Primo namespace non-MLS cifrato** (es. `contacts`): doppia scrittura
   legacy+vault con confronto, poi switch di lettura. Rollback: si torna a leggere
   legacy (ancora presente).
5. **Namespace restanti non-MLS** (identity, messages, outbox, push, settings):
   stesso pattern.
6. **Stato MLS**: migrazione §10 dell'envelope; localStorage rimosso solo a verifica
   completata. Rollback: pre-commit il legacy è intatto.
7. **Eliminazione del backend legacy**: rimozione del codice di lettura/scrittura
   localStorage; factory reset aggiornato. Rollback: revert del commit.
8. **OpenMLS nel worker** (fase 2 architetturale): il runtime MLS trasloca nel
   worker; la pagina smette di vedere lo stato MLS. Gate dedicato.

## 15. Piano manuale (blocca lo Status: Proposed → Accepted)

M1 Safari/iOS PWA (harness spike: IDB, worker, `persist()`, eviction ITP);
M2 Chrome Android (kill a metà transazione, quota reale);
M3 storage pressure/quota reale su desktop;
M4 private browsing (tutti i motori);
M5 Argon2id su dispositivi reali (profili mobile, limite memoria WASM su iPhone,
   128 MiB + working set) + module worker e IDB-nel-worker su Safari.

## 16. Compatibilità futura

- **StorageProvider Dart**: il formato dei record (§6) e la key hierarchy (§5) non
  presuppongono nulla di JS-specifico (AES-GCM, HKDF, Argon2id sono disponibili
  nello stack Dart); un'implementazione Dart potrà leggere lo stesso layout.
- Il vault sostituisce il backend usato da `styx-chat.js` dietro la stessa
  interfaccia `backend` già iniettabile (get/set/remove) più le transazioni; il
  codec envelope (`mls-state-envelope.js`) resta invariato.
- Blocco 5 (record-per-key ledger): lo schema per-record con AAD posizionale è già
  compatibile (decisione registrata nello spike IDB).
