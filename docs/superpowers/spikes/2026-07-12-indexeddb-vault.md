# Spike — IndexedDB e durabilità per il vault (Blocco 3)

Data: 2026-07-12 · Branch: `spike/indexeddb-vault` · Prototipo: `styx-js/spikes/indexeddb-vault/`
Mandato: validare transazioni atomiche, schema record-oriented, upgrade/versionamento,
multi-tab, crash consistency, quota, persistenza, cancellazione, compatibilità browser e
migrazione futura dal backend attuale — **senza** toccare storage reale, dati, UI o
dipendenze runtime. Nessuna cifratura in questo spike (arriva col vault).

## 1. Metodo

Prototipo isolato (`vault-prototype.js`, IndexedDB nativo, zero dipendenze, mai importato
dal prodotto; marker `STYX_SPIKE_PROTOTYPE` bloccato nel bundle dal gate CI) + 12 probe
Playwright (`vault-spike.spec.js`, P1–P12) eseguite su **browser reali** contro un server
HTTP locale, incluso il **vero** envelope MLS della fixture di regressione. Ogni probe usa
un database fresco; 1 worker (nessuna interferenza tra probe).

API prototipata (quella richiesta dal mandato):

```text
openVault({name, version, migrations})   get(ns, key)     put(ns, key, value)
delete(ns, key)   list(ns)   clear(ns)   transaction(namespaces, callback)
destroy()   probeStorage()
Namespace: meta · identity · contacts · messages · mls · outbox · migrations
```

## 2. Risultati delle probe

| Probe | Chromium | Firefox | Cosa prova |
|---|---|---|---|
| P1 commit multi-record atomico | ✅ | ✅ | 3 namespace in una transazione, visibili solo dopo `oncomplete` |
| P2 abort + eccezione a metà | ✅ | ✅ | rollback totale (valore precedente intatto, marker assente) in entrambe le forme |
| P3+P4 pagina uccisa a metà transazione | ✅ | ✅ | il record committato prima sopravvive; la transazione lunga (2000 put + marker) è **tutta o niente** — mai parziale; riapertura pulita |
| P5 upgrade v1→v2 / upgrade fallito / downgrade | ✅ | ✅ | dati preservati nell'upgrade; migratore che lancia → intero `versionchange` abortito, DB resta v1 coi dati; open con versione più bassa → errore pulito |
| P6 due tab + Web Lock | ✅ | ✅ | scritture transazionali da entrambe le tab senza corruzione; elezione writer con `ifAvailable`; `steal` per il takeover; riacquisizione dopo il rilascio |
| P7 destroy() | ✅ | ✅ | database eliminato (assente da `indexedDB.databases()`), riapertura = DB vergine |
| P8 quota reale esaurita | ⚠️ manuale (M3) | ⚠️ manuale (M3) | v. finding F9: l'override CDP non è applicabile in questo ambiente |
| P9 persist()/persisted()/estimate() | ✅ | ✅ | advisory, mai fatale; v. finding F8 |
| P10 open/delete bloccati da una tab "stuck" | ✅ | ✅ | errore strutturato `VAULT_BLOCKED`, dati intatti in entrambi i DB |
| P11 record MLS reale + record 8 MB | ✅ | ✅ | envelope della fixture come record separati (meta JSON + payload **binario nativo**, niente base64), round-trip byte-identico; 8 MB in un put |
| P12 enumerazione e wipe per namespace | ✅ | ✅ | `list`/`clear` su un namespace non toccano gli altri |

Esecuzione finale: **20 pass + 2 skip** (P8 su firefox by design, P8 su chromium per
l'ambiente — finding F9), stabile su 3 run consecutivi dopo l'hardening F4.

**Misure registrate** (headless, questa macchina):

| Misura | Chromium | Firefox |
|---|---|---|
| Transazione envelope reale (meta+payload) | ~0,5 ms | ~1 ms |
| Scrittura record 8 MB | ~5 ms | ~23–30 ms |
| Lettura record 8 MB | ~6 ms | ~24–34 ms |
| Quota riportata da `estimate()` | ~10 GiB | ~6,1 GiB |
| `persist()` headless | `false` (subito) | **mai risolta** (prompt) → `timeout` |

## 3. Finding (numerati, citati nel codice)

- **F1 — Semantica di durabilità corretta = `oncomplete`.** `transaction()` risolve solo
  su `oncomplete` (con `durability:'strict'` dove supportato): "resolved" significa
  "committato". Vincolo strutturale: il callback non può `await` nulla che non sia
  un'operazione della transazione (IndexedDB auto-committa al primo checkpoint senza
  richieste pendenti). L'API del vault deve imporlo per contratto.
- **F2 — Crash consistency reale.** Uccidere la pagina a metà di una transazione lunga
  non produce **mai** stato parziale: o tutti i 2000 record + marker, o zero. Il dato
  committato prima del crash sopravvive sempre.
- **F3 — Upgrade fail-closed gratis.** Un migratore che lancia abortisce l'intero
  `versionchange`: il DB resta alla versione precedente coi dati intatti. È la stessa
  filosofia della migration policy dell'envelope, fornita dal motore.
- **F4 — Retry sugli open bloccati.** Subito dopo un upgrade abortito, una riapertura può
  essere **transitoriamente** `blocked` mentre la connessione fallita si smonta. Il vault
  deve fare retry con backoff breve su `VAULT_BLOCKED`, non fallire hard (riprodotto ~1/7
  run prima dell'hardening).
- **F5 — Mai abbandonare un open bloccato.** Una richiesta di upgrade rimasta `blocked`
  resta **pendente** anche dopo aver segnalato l'errore: ogni open successivo dello stesso
  DB nella stessa tab si accoda dietro di lei → deadlock. Design: ogni connessione del
  vault DEVE auto-chiudersi su `versionchange` (il prototipo lo fa), e gli open bloccati
  vanno attesi con timeout, non rigettati-e-ritentati.
- **F6 — L'auto-close cambia la semantica del factory reset.** Con l'auto-close su
  `versionchange` in tutte le tab, `deleteDatabase` **non si blocca**: il reset riesce da
  qualunque tab (le altre perdono la connessione — comportamento voluto per il factory
  reset). Solo una tab che *disattiva* l'auto-close (il caso "stuck" simulato in P10)
  blocca upgrade e delete, con errore strutturato e dati intatti.
- **F7 — Web Locks adeguati all'elezione del writer.** `ifAvailable` per l'elezione,
  `steal` per il takeover esplicito, riacquisizione affidabile dopo il rilascio: la
  semantica single-writer già usata dalla chat si trasferisce al vault senza sorprese.
- **F8 — `persist()` può non risolvere MAI.** Su Firefox la promise resta pendente
  finché il prompt di permesso è aperto (headless: per sempre). Il probe del vault deve
  fare race con un timeout e trattare "nessuna risposta" come "non ancora concesso".
  Su Chromium headless: `false` immediato, senza prompt.
- **F9 — Quota non simulabile in questo ambiente.** `Storage.overrideQuotaForOrigin`:
  no-op silenzioso da sessione CDP di pagina; "Internal error" da sessione browser sui
  context isolati di Playwright; accettato ma **non applicato** sul persistent context di
  questo build. Il percorso di errore quota (abort → rollback → vault utilizzabile) è la
  stessa macchina transazionale già provata da P2/P3; la riproduzione con quota reale va
  al piano manuale M3. Un `QuotaExceededError` resta fail-closed e non distruttivo per
  costruzione (la transazione abortisce, niente stato parziale).
- **F10 — Binario nativo, niente base64.** L'envelope reale della fixture viaggia come
  due record (`state:meta` JSON + `state:payload` `Uint8Array` nativo) con round-trip
  byte-identico: la conversione base64 (issue #25) sparisce dal percorso persistente.

## 4. Decisioni (output richiesto dal mandato)

| Decisione | Scelta | Motivazione |
|---|---|---|
| Libreria | **IndexedDB nativo**, nessun wrapper | La superficie richiesta è ~200 righe; `idb` (~5 KB) aggiunge solo zucchero ma entra nel percorso security-critical e nella supply chain; Dexie (~80 KB) porta un query-engine che non serve. Confronto fatto, costo del wrapper > beneficio. |
| Schema iniziale | un object store per namespace (`meta, identity, contacts, messages, mls, outbox, migrations`), chiavi stringa out-of-line, valori structured-clone (binario nativo) | Record-oriented come richiesto; P11 prova il modello con dati MLS reali. |
| Transazioni | una `readwrite` multi-store per unità logica; resolve solo su `oncomplete`; `durability:'strict'`; callback senza await esterni (F1) | Atomicità e durabilità provate da P1/P2/P3. |
| Versionamento | `VAULT_SCHEMA_VERSION` + registro migratori per versione; gap nel registro = errore; migratore che lancia = upgrade abortito (F3); downgrade = errore pulito | Coerente con la migration policy dell'envelope. |
| Web Locks | elezione writer con `ifAvailable` (come oggi), `steal` solo per takeover esplicito dell'utente, retry-con-backoff su `VAULT_BLOCKED` (F4), auto-close su `versionchange` obbligatorio (F5/F6) | P6/P10. |
| Quota/persistenza | `probeStorage()` advisory con `persist()` bounded (F8); quota error = transazione abortita, mai distruttiva; `estimate()` per telemetria locale | P9 + F9. |
| Private browsing | trattato come vault normale con `persisted=false` (Firefox PB: IndexedDB in-memory; Safari PB: quota ridotta) — nessun percorso speciale, solo l'avviso UI "storage non persistente" | Verifica reale nel piano manuale M4. |
| Blocco 5 (StorageProvider granulare) | compatibile per costruzione: il modello record-per-chiave consente di passare da `mls/state:payload` monolitico a record per-gruppo (`mls/group:<id>`) senza cambiare schema, solo nuove chiavi | P11/P12. |

**Migrazione futura dal backend attuale** (validata concettualmente da P11): la
localStorage→IndexedDB seguirà la stessa sequenza a 12 passi della migration policy, con
l'envelope come unità trasportata — letto da `styxchat:*`, verificato dal parser,
scritto come `state:meta`+`state:payload` nel namespace `mls`, e cancellato dal vecchio
backend solo a verifica avvenuta. Nessun passo di questa migrazione è implementato qui.

## 5. Compatibilità browser

| Browser | Stato | Note |
|---|---|---|
| Chromium desktop (build Playwright 1228) | ✅ 10 probe verdi | P8 → M3. Caveat ambiente: Playwright 1.58 non distribuisce browser per ubuntu26.04; usato il build in cache via `executablePath` (drift documentato, irrilevante per le API provate). |
| Firefox desktop 146.0.1 (build Playwright 1509, fallback ubuntu24.04) | ✅ 10 probe verdi | `persist()` = prompt/`timeout` (F8); scritture 8 MB ~5× più lente di Chromium ma abbondantemente adeguate. |
| WebKit (proxy di Safari) | ⚠️ non eseguibile qui | Build 2248 scaricato, launch impossibile: 6 librerie di sistema mancanti (`libicu*74, libxml2, libmanette, libwoff2dec`), niente sudo. → piano manuale M1. |
| Chrome Android | ⚠️ non disponibile | → piano manuale M2. |

### Piano di verifica manuale (preciso, da eseguire prima del design definitivo del vault)

- **M1 — Safari/iOS PWA** (dispositivo reale o Mac+simulatore): servire `styx-js/` con
  `python3 -m http.server` (o lo static server del deploy), aprire
  `spikes/indexeddb-vault/harness.html` in Safari iOS e da PWA installata; in console
  eseguire gli scenari P1, P2, P5, P7, P11 (le funzioni sono su `window.VaultSpike`;
  gli snippet sono le `page.evaluate` del file spec, riusabili tali quali). Verificare
  in più: (a) IndexedDB disponibile in modalità standalone PWA; (b) `persist()` (su iOS
  ritorna tipicamente `false`: registrare); (c) la policy ITP di eviction a 7 giorni di
  inattività NON si applica alle PWA installate — confermare con la versione iOS corrente.
- **M2 — Chrome Android** (dispositivo reale): come M1 via `chrome://inspect` remote
  debugging; in più `estimate()` (quota tipica = % dello storage libero) e P3 (kill
  dell'app a metà transazione dal task switcher).
- **M3 — Quota reale**: profilo Chromium dedicato su una partizione piccola (o tmpfs da
  ~50 MB via `--user-data-dir`), riempire con P8-loop fino a `QuotaExceededError` reale e
  verificare le 4 asserzioni di P8 (errore strutturato, baseline intatta, zero parziali,
  vault utilizzabile).
- **M4 — Private browsing**: Firefox PB (IndexedDB in-memory: dati persi alla chiusura,
  API funzionante) e Safari PB su M1; confermare che il vault apre e che `persisted()`
  è `false`.

## 6. Cosa NON è stato toccato

Formato wire, pin OpenMLS, artefatto WASM, ciphersuite, storage persistente reale
(`localStorage` dell'app), dati utente, UI, factory reset, dipendenze runtime, stack
Dart: **invariati**. Il prototipo vive in `styx-js/spikes/` (fuori da `src/`, mai
importato) e il gate web ora fallisce se `STYX_SPIKE_PROTOTYPE` compare nel bundle.

## 7. Conclusione

```text
GO
```

IndexedDB nativo soddisfa tutti i requisiti del vault con margini larghi: atomicità e
crash consistency reali (P2/P3), upgrade fail-closed (P5), multi-tab governabile con i
Web Locks già in uso (P6), binario nativo che elimina base64 (P11, chiude il design di
issue #25). Condizioni incorporate nel design (non condizioni sospensive): F4 retry sugli
open bloccati, F5 auto-close su `versionchange` obbligatorio, F8 `persist()` bounded,
più il completamento del piano manuale M1–M4 prima del design definitivo del vault.
