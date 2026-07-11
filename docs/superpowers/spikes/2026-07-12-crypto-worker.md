# Spike — Crypto Worker (Blocco 3)

Data: 2026-07-12 · Branch: `spike/crypto-worker` · Prototipo: `styx-js/spikes/crypto-worker/`
Mandato: determinare **che cosa** collocare in un Worker (OpenMLS/WASM, KDF, HKDF,
AES-GCM, serializzazione, IndexedDB, migrazione) e come si comporta il confine —
messaggi tipizzati, trasferimenti, errori, terminazione, lock, CSP — valutando
sicurezza, complessità, testabilità e recovery, non solo prestazioni. Nessuna
integrazione nell'app. Eseguito dopo la conclusione dello spike IndexedDB, come da ordine.

## 1. Metodo

Worker **dedicato di tipo module** (`crypto-worker.js`) che possiede il runtime
OpenMLS/WASM vendorizzato e un KV IndexedDB minimale; client tipizzato
(`worker-client.js`: promise correlate per id, transferable opzionali, reject di tutte
le richieste pendenti su crash/terminate). Protocollo:

```text
INIT · UNLOCK · LOCK · VAULT_GET · VAULT_PUT · MLS_RESTORE · MLS_SERIALIZE ·
MLS_DECRYPT · ECHO_TRANSFER · BUSY · LEAK_PROBE · LOCK_PROBE · SHUTDOWN
richiesta  { id, type, payload }
risposta   { id, ok:true, result } | { id, ok:false, error:{ code, message } }
```

10 probe Playwright (W1–W10) su Chromium e Firefox reali, con la **fixture MLS reale**
(`mls-state-v1`) e — in W10 — la **CSP di produzione reale** (`buildCsp()` importata da
`apps/chat/static-server.mjs`, non una copia).

## 2. Risultati

| Probe | Chromium | Firefox | Cosa prova |
|---|---|---|---|
| W1 WASM nel worker | ✅ ~8 ms init | ✅ ~29 ms init | il crate vendorizzato inizializza in un module worker senza modifiche |
| W2 fixture reale nel worker | ✅ | ✅ | restore + decrypt del messaggio di riferimento + serialize; un **secondo worker** ripristina dall'output serializzato (round-trip completo) |
| W3 transfer vs clone (8 MB) | ✅ 0,2 ms vs 6,8 ms | ✅ ~0 ms vs 7 ms | il transfer è ~30× più rapido e **neutralizza il sorgente** (`byteLength 0`): nessuna seconda copia dello stato in RAM |
| W4 errori tipizzati | ✅ | ✅ | stato garbage → `MLS_RESTORE_FAILED` senza payload nel messaggio; il worker sopravvive e risponde; tipo sconosciuto → `WORKER_BAD_REQUEST` |
| W5 terminate a metà operazione | ✅ | ✅ | tutte le pending rifiutate `WORKER_TERMINATED` (mai promise appese); un worker nuovo si inizializza e lavora |
| W6 leak probe | ✅ | ✅ | v. finding W-F3 — il risultato è **l'opposto** dell'assunzione ingenua |
| W7 Web Locks attraverso il confine | ✅ | ✅ | il lock writer preso dalla **pagina** è visto dal worker (`ifAvailable` → false) e acquisibile dopo il rilascio: l'elezione single-writer attuale resta valida invariata |
| W8 IndexedDB nel worker | ✅ | ✅ | round-trip binario nel worker: il worker può possedere lo storage |
| W9 50 cicli restore+serialize | ✅ 0,84→0,16 ms | ✅ 0,8→0,5 ms | nessuna degenerazione (probe di leak grossolana; media ultimi 10 ≤ primi 10) |
| W10 CSP di produzione | ✅ | ✅ | init WASM + restore fixture sotto `script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'`; **controllo negativo**: un worker `blob:` è bloccato dalla CSP |

Esecuzione finale: **20/20**, stabile su 3 run. Bundle di produzione verificato pulito
(gate `STYX_SPIKE_PROTOTYPE`). Suite jest del prodotto intatta.

## 3. Finding

- **W-F1 — Il costo del Worker è trascurabile.** Init WASM 8–29 ms una tantum;
  restore+serialize sub-millisecondo; il confine non aggiunge latenza percepibile alle
  operazioni MLS correnti.
- **W-F2 — Transfer come default per i byte grandi.** ~30× più veloce del clone e
  neutralizza il buffer sorgente: lo stato serializzato non resta duplicato sul main
  thread. Il protocollo del vault deve trasferire (`transferList`), non clonare, ogni
  `Uint8Array` di stato.
- **W-F3 — Nessuna rete di sicurezza della piattaforma sui handle WASM.** Un
  `postMessage(provider)` accidentale **non** lancia `DataCloneError`: il wrapper
  wasm-bindgen è un oggetto JS con un puntatore (`{__wbg_ptr}`) e attraversa il clone
  strutturato come oggetto inerte (il materiale chiave resta nella memoria WASM del
  worker; verificato che il clone contiene solo `__wbg_ptr: number`). Conseguenza di
  design: la sicurezza del confine è responsabilità del **protocollo tipizzato con
  allowlist** — mai postare oggetti non previsti dallo schema.
- **W-F4 — CSP di produzione già pronta.** `worker-src 'self'` + `wasm-unsafe-eval`
  bastano: nessuna modifica CSP necessaria; i worker `blob:` (vettore di iniezione)
  restano bloccati. Vincolo confermato: niente script inline nemmeno negli harness.
- **W-F5 — Recovery pulito.** `terminate()` a metà operazione: pending rifiutate subito
  con codice stabile, riavvio a costo ~init. Un supervisore lato client (ricrea il
  worker e ripete `INIT`+`UNLOCK`) è sufficiente; nessuno stato ibrido possibile perché
  lo stato persistito resta transazionale (spike IndexedDB).
- **W-F6 — Web Locks condivisi pagina/worker.** L'elezione del writer può restare dove
  è oggi (nella pagina, legata al ciclo di vita della UI) anche se crypto+storage
  migrano nel worker: nessun refactoring del lock necessario.
- **W-F7 — Vite.** Il pattern supportato è `new Worker(new URL('./crypto-worker.js',
  import.meta.url), { type: 'module' })`: Vite lo riconosce staticamente e produce un
  chunk worker separato con gli import risolti (incluso il `.wasm` come asset). Nessuna
  configurazione extra attesa; da verificare nel primo build reale del vault (non in
  questo spike, che non tocca l'app).

**Service worker vs dedicated worker** (richiesto dal mandato): il service worker è
**inadatto** a ospitare il runtime MLS — è event-driven e il browser lo termina dopo
pochi secondi di inattività (lo stato in RAM svanirebbe di continuo), è condiviso tra
tutte le tab (conflitto con il modello single-writer), e il suo ciclo di vita
(update/skipWaiting) è indipendente dalla sessione. Il SW resta ciò che è oggi: shell
cache + push wake-up. Il Crypto Worker è un **dedicated worker** posseduto dalla tab
writer.

## 4. Raccomandazione (output richiesto)

**Opzione 3 — IndexedDB e crypto nello stesso dedicated worker — come architettura
target, introdotta progressivamente (percorso dell'opzione 4).**

| Opzione | Valutazione |
|---|---|
| 1. Tutto il core nel worker (incluso transport) | ❌ Nessun guadagno di sicurezza (i plaintext devono comunque raggiungere la UI) e costi concreti: la gestione visibilità/reconnect dei WebSocket è legata a eventi della pagina (`visibilitychange`), e il debugging del transport peggiora. |
| 2. Crypto nel worker, IndexedDB fuori | ❌ Divide la proprietà dello stato: ogni persist attraversa il confine due volte (serialize nel worker → write sul main), reintroducendo copie dello stato sul main thread che W-F2 permette di evitare e raddoppiando i modi di fallimento delle transazioni. |
| **3. IndexedDB + crypto nello stesso worker** | ✅ **Target.** Un solo proprietario di segreti e persistenza: lo stato MLS non appare mai sul main thread (se non come ciphertext/plaintext applicativo), `serialize→put` è locale al worker (transazionale, senza attraversare il confine), Argon2id non bloccherà mai la UI, e il protocollo allowlist (W-F3) è l'unico punto di uscita. Testabilità provata (probe reali); recovery provato (W-F5). |
| 4. Introduzione progressiva | ✅ **Come percorso**, non come stato finale: fase 1 = KDF (Argon2id) + cifratura vault nel worker; fase 2 = trasloco del runtime MLS. Ogni fase è verificabile con le probe di questo spike. |

Collocazione dei componenti del mandato: OpenMLS/WASM ✅ worker (W1/W2); KDF/Argon2id ✅
worker (è la ragione principale: mai sul main thread — spike 3); HKDF/AES-GCM ✅ worker
(WebCrypto è disponibile nei worker; operano sui segreti del vault); serializzazione ✅
worker (W-F2: transfer, mai clone); IndexedDB ✅ worker (W8 + opzione 3); migrazione ✅
worker (stessa sequenza a 12 passi, eseguita dove vivono vault e crypto).

## 5. Compatibilità browser

Chromium (build 1228) e Firefox 146: 20/20. Module worker, WASM-in-worker, Web Locks
nei worker e IndexedDB nei worker sono tutte API baseline (Chrome ≥ 80/69, Firefox ≥
114/96, Safari ≥ 15/16.4). Safari/iOS: nessuna probe eseguibile in questo ambiente
(stessa limitazione dello spike IndexedDB) → aggiunta al piano manuale M1: eseguire
W1/W2/W10 dalla console Safari con l'harness; attenzione nota a Safari per i module
worker più vecchi (< 15) — irrilevante per i target attuali ma da registrare nella
matrice al momento del test reale.

## 6. Cosa NON è stato toccato

Formato wire, pin OpenMLS, artefatto WASM canonico (usato in sola lettura via fetch),
ciphersuite, storage persistente reale, dati utente, UI, factory reset, dipendenze
runtime, stack Dart: **invariati**. Prototipo sotto `styx-js/spikes/`, escluso dal
bundle e verificato dal gate anti-bundle.

## 7. Conclusione

```text
GO
```

Il Crypto Worker è fattibile con costi trascurabili e benefici concreti (Argon2id fuori
dal main thread, stato MLS mai sul main thread, un solo proprietario per segreti e
persistenza). Architettura raccomandata: **opzione 3 via percorso 4**, con le regole di
design W-F2 (transfer obbligatorio), W-F3 (allowlist del protocollo — la piattaforma non
protegge), W-F5 (supervisore di recovery) e W-F6 (lock invariato nella pagina).
Lo spike Argon2id (successivo) va eseguito **nel contesto Worker** scelto qui.
