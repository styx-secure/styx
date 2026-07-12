# Piano di implementazione — Blocco 3 "Styx Vault"

**Status: Proposed**

Spec di riferimento: `docs/superpowers/specs/2026-07-12-styx-vault-design.md`
(Status: Proposed; review GO in
`docs/security/2026-07-12-review-styx-vault-design.md`, PR #32 → squash `1d82ef2`).

**Questo piano non autorizza alcuna implementazione.** Ogni PR tecnica richiede
autorizzazione esplicita e separata; nessuna PR R3/R4 (§13) può essere eseguita
senza nuova autorizzazione. Fuori scope permanente del Blocco 3: modifiche a pin /
artefatto / ciphersuite OpenMLS, wire format, `@noble/*`, stack Dart.

Principio fondamentale: **nessuna big-bang migration.** Il Blocco 3 è scomposto in
PR piccole, ordinate e reversibili; nessuna PR introduce contemporaneamente il
vault, migra dati reali e cambia il runtime MLS.

---

## B3.0 — Contratti e tracciabilità

Questa sezione è il deliverable di B3.0 (nessun codice): contratti che ogni PR
successiva deve rispettare e la matrice di tracciabilità.

### B3.0.1 Matrice requisito → componente → test → PR

| Requisito (spec §) | Componente | Test (matrice §9) | PR |
|---|---|---|---|
| §2.1 artefatto KDF separato | `styx-js/vendor/styx-kdf-wasm/` | KAT Argon2id, anti-drift, build da clone pulito | PR‑1 |
| §7/§7.1 wrapper validato fail-closed | `src/storage/vault-wrapper.js` | wrapper malformed/future/bounds (ogni campo) | PR‑2 |
| §6 record AES-GCM + AAD canonica | `src/storage/vault-record.js` | AAD tampering, swap ns/key/ct, nonce | PR‑2 |
| §5 gerarchia HKDF | `src/crypto/vault-keys.js` | vettori HKDF stabili, separazione namespace | PR‑2 |
| §9 protocollo worker + supervisore | `src/crypto/vault-worker.js`, `src/crypto/vault-worker-client.js` | protocollo (ogni tipo, malformati), termination/respawn, CSP, anti-bundle | PR‑3 |
| §8 motore IndexedDB | `src/storage/vault-db.js` | crash P3, upgrade P4, blocked F4/F5, quota, versionchange | PR‑4 |
| §3/§4/§7.2 lifecycle + Root Key + re-wrap | `src/storage/vault.js` | state machine, wrong password, crash re-wrap | PR‑5 |
| §6/§13 canary end-to-end | namespace `canary` | tutti gli scenari §13 sul canary | PR‑6 |
| §10 migrazione per namespace | `src/storage/vault-migration.js` | crash point table §6 di questo piano | PR‑7…PR‑10 |
| §10.1 mapping envelope MLS | estensione `vault-migration.js` + `styx-chat.js` | restore fixture reale, payloadSha256, byte-compare | PR‑10 |
| §12 factory reset | estensione `styx-chat.js`/app | reset dopo ogni stato | PR‑11 |
| UI sblocco/errori (issue #24) | `apps/chat/src/` | scenari UI §B3.12 | PR‑12 |
| §2 OpenMLS nel worker (fase 2) | spostamento runtime | regressione completa + fixture | PR‑14 |

### B3.0.2 Formati persistiti (elenco chiuso; ogni aggiunta = aggiornare qui)

1. **Wrapper KDF v1** (`meta/kdf-wrapper`) — spec §7; unica prova della password.
2. **Record cifrato v1** — spec §6 (`{v,ns,k,rv,kv,ct,nonce,data}`).
3. **Manifest v1** (`meta/manifest`) — spec §11, HMAC sotto `K_manifest`.
4. **Marker/manifest di migrazione** (`migrations/*`) — solo marker/conteggi/digest,
   MAI payload (spec §5).
5. **Envelope MLS v1** — INVARIATO (PR #23); nel vault vive scomposto secondo il
   mapping §10.1 della spec.
6. **Schema IndexedDB v1** — 10 store: `meta identity contacts messages mls outbox
   push settings migrations canary`. **Emendamento registrato della spec §5/§8**
   (da riportare nella spec al primo aggiornamento): si aggiungono gli store
   `settings` e `canary` e le corrispondenti info string HKDF
   `styx/vault/settings/v1` e `styx/vault/canary/v1` — mai riuso di subkey di
   altri namespace (invariante B3.0.5.5).
7. **Formato legacy localStorage** — sola lettura durante la migrazione; eliminato
   solo alla fase `legacy removed` (§7 rollout).

### B3.0.3 Error code (stabili; superset dei `MLS_STATE_*` esistenti)

`VAULT_WRAPPER_INVALID` · `VAULT_WRAPPER_UNSUPPORTED` · `VAULT_KDF_PARAMS_INVALID` ·
`VAULT_WRONG_PASSWORD` · `VAULT_RECORD_INVALID` · `VAULT_RECORD_CORRUPTED` ·
`VAULT_MANIFEST_TAMPERED` · `VAULT_BLOCKED` · `VAULT_QUOTA_EXCEEDED` ·
`VAULT_WRONG_STATE` · `VAULT_MIGRATION_FAILED` · `VAULT_DESTROY_FAILED` ·
`WORKER_TERMINATED` · `WORKER_CRASHED` · `BAD_REQUEST` — più i codici
`MLS_STATE_*` esistenti, invariati. Nessun messaggio contiene payload, chiavi o
stato (§11 di questo piano).

### B3.0.4 Limiti dimensionali

Password 8–1024 char (UI incoraggia passphrase); salt 16 B; nonce 12 B; wrapped
Root Key 48 B; record: valore ≤ 16 MiB pre-cifratura (coerente col cap del parser
envelope; la quota IDB è il limite reale — issue #27); messaggi di protocollo
≤ 32 MiB (payload transferable); `LIST` ≤ 10.000 chiavi per chiamata; `calibratedMs`
≤ 600.000.

### B3.0.5 Invarianti crittografiche (verificate da test in OGNI PR pertinente)

1. La Root Storage Key non lascia mai il worker (mai nel protocollo, mai nei log,
   mai persistita in chiaro).
2. La KEK non viene mai persistita; l'unica verifica della password è l'unwrap GCM.
3. Nonce: 96 bit casuali a ogni scrittura; mai contatori condivisi.
4. AAD in lettura: `ns`/`k` dalla RICHIESTA, mai dai campi auto-dichiarati.
5. Una chiave AES per namespace; mai riuso cross-namespace.
6. Il wrapper è validato per intero (tabella spec §7.1) PRIMA di toccare
   Argon2id o WebCrypto.
7. Durante ogni transizione di re-wrap esiste sempre almeno un wrapper valido.
8. localStorage è la fonte di verità di un namespace finché la sua migrazione non
   è `verified` + cleanup committato.
9. Nessun oggetto WASM attraversa il confine worker/pagina.
10. Il codec `mls-state-envelope.js` resta l'unico validatore del formato envelope.

### B3.0.6 Feature flag

Un solo flag persistito localmente, `styx.vault.stage`, con valori ordinati
(§7 rollout): `off → developer-only → test-profile → opt-in → limited-alpha →
default-on → legacy-removed`. Fino a `opt-in` incluso il default è `off`. Il flag
non è un formato di sicurezza: governa solo quale backend legge/scrive.

### B3.0.7 Compatibility matrix (capacità richieste)

| Capacità | Chromium | Firefox | Safari/iOS | Chrome Android |
|---|---|---|---|---|
| IndexedDB nel worker | ✅ spike | ✅ spike | ❓ M1/M5 | ❓ M2 |
| Module worker | ✅ | ✅ | ❓ M5 | ❓ M2 |
| Web Locks | ✅ | ✅ | ❓ M1 | ❓ M2 |
| WebCrypto AES-GCM/HKDF | ✅ | ✅ | ❓ M1 | ❓ M2 |
| WASM ≥128 MiB nel worker | ✅ | ✅ | ❓ M5 (iPhone) | ❓ M5 |
| `storage.persist()` | ✅ (false) | ✅ (timeout, F8) | ❓ M1 (ITP) | ❓ M2 |

### B3.0.8 Risk register iniziale

| ID | Rischio | Prob. | Impatto | Mitigazione |
|---|---|---|---|---|
| RK1 | Safari/iOS: limite memoria WASM sotto il profilo `desktop` | media | alto (M5) | profili più bassi + calibrazione; gate mobile |
| RK2 | Eviction IDB su iOS (ITP) cancella il vault | media | alto | `persist()` + UI "storage non persistente"; localStorage legacy resta finché non verificato |
| RK3 | Perdita password = dati irrecuperabili | certa (by design) | alto | UI esplicita; nessun recovery debole; futuro export/backup (K_backup) fuori scope B3 |
| RK4 | Regressione prestazioni sblocco su device reali | media | medio | calibrazione + M5 prima di default-on |
| RK5 | Bug di migrazione con dati reali eterogenei | media | alto | shadow-read + doppia verifica + legacy intatto fino a cleanup autorizzato |
| RK6 | Supply chain del crate KDF | bassa | alto | stessa pipeline pinnata del crate canonico; cargo audit/deny |
| RK7 | Divergenza silente dei formati tra PR | media | alto | B3.0.2 elenco chiuso + test vector stabili committati in PR‑2 |
| RK8 | SW update durante UNLOCKED/MIGRATING | media | medio | §16.6: il worker non dipende dal SW; test dedicato in PR‑6 |

### B3.0.9 Gate

- **Gate desktop** (per ogni PR): jest + Playwright chromium+firefox verdi, fixture
  MLS restore verde, bundle privo di marker spike e di fallback, tree pulito.
- **Gate mobile** (M1–M5): blocca `Proposed→Accepted` della spec, il supporto
  dichiarato iOS/Android, `default-on`, la migrazione automatica generalizzata e il
  Public Alpha Readiness gate. NON blocca la scrittura del piano né lo sviluppo
  dietro flag `off` (§8).

---

## Fasi e PR (B3.1 → B3.13)

Convenzioni per ogni PR: base = `main`; branch `feat/vault-<slug>`; review di
sicurezza indipendente (agente a contesto pulito) prima del merge; gate esplicito =
"la PR successiva non parte finché questa non è merged con check verdi e il suo
criterio di accettazione è dimostrato". Le classi di rollback sono definite in §13.

### PR‑1 — B3.1 `styx-kdf-wasm` (artefatto KDF separato)

- **Obiettivo**: crate `styx-js/vendor/styx-kdf-wasm/` con `argon2id_derive`
  (RustCrypto `argon2 =0.5.3`, `wasm-bindgen =0.2.126`), separato da OpenMLS.
- **File**: `vendor/styx-kdf-wasm/{Cargo.toml,Cargo.lock,src/lib.rs,build.sh,verify.sh,PROVENANCE.md,pkg/(artefatto+SHA256SUMS),README.md}`;
  test `test/crypto/kdf-wasm.test.js`.
- **Dipendenze**: nessuna (prima PR). **Precondizioni**: autorizzazione esplicita.
- **Vincoli**: stessa immagine Docker pinnata per digest e wasm-pack sha-verificato
  del crate canonico; build riproducibile (doppia build byte-identica, `verify.sh`);
  `--locked`; nessuna integrazione col binario OpenMLS; nessun `hash-wasm`;
  la validazione dei parametri (bounds spec §7.1) sta nel chiamante JS: PR‑1
  introduce il **modulo unico** `src/crypto/kdf-bounds.js` (puro, senza
  dipendenze), riusato tal quale dal validatore del wrapper (PR‑2) e dal worker
  (PR‑3) — un solo validatore, nessuna copia divergente — e testato QUI con un
  harness che dimostra che nessun parametro fuori bounds raggiunge l'allocazione
  WASM; PR‑3 ri-esegue lo stesso harness sul percorso definitivo nel worker.
- **Test**: known-answer test = le tre ancore hex dello spike (`743669d5…`,
  `b0e838c9…`, `fe175848…`) + vettori RFC 9106; cross-check con l'artefatto dello
  spike (byte-identico output, non byte-identico artefatto); anti-drift su
  pin/digest; build da clone pulito in CI (gate WASM esteso al nuovo crate).
- **Accettazione**: KAT verdi su chromium+firefox; digest registrato in PROVENANCE
  e in `SHA256SUMS`; `verify.sh` exit 0. **Non crea né apre alcun vault.**
- **Formati persistiti toccati**: nessuno. **Threat model**: aggiunge superficie
  supply-chain (RK6), mitigata dalla pipeline pinnata.
- **Rollback**: R0. **Gate**: digest `styx-kdf-wasm` congelato per le PR successive.

### PR‑2 — B3.2 Formati crittografici puri

- **Obiettivo**: codec/validatori puri, senza IndexedDB e senza dati reali.
- **File**: `src/storage/vault-wrapper.js` (parse/validate/encode wrapper, tabella
  spec §7.1 completa, rifiuto campi sconosciuti), `src/storage/vault-record.js`
  (encrypt/decrypt record, AAD canonica `JSON.stringify([v,ns,k,rv,kv,ct])`, fonte
  in lettura dalla richiesta), `src/crypto/vault-keys.js` (HKDF subkey, wrap/unwrap
  di una Root Key SINTETICA, HMAC manifest); test speculari in `test/storage/` e
  `test/crypto/`.
- **Dipendenze**: PR‑1 (usa il KDF solo nei test di integrazione wrapper↔KEK).
- **Test**: bounds su OGNI campo del wrapper; wrapper versione futura → 
  `VAULT_WRAPPER_UNSUPPORTED` senza toccare i dati; AAD tampering (swap ns, swap
  key, swap ct, swap rv/kv); nonce fisso accidentale (property test: N encrypt
  della stessa coppia chiave/valore → N nonce distinti); manipolazione
  `wrappedRootKey`/`wrapNonce`; **test vector stabili committati** (fixture JSON
  con chiavi sintetiche) che diventano la regressione anti-divergenza (RK7);
  property test con `fast-check` (già devDependency).
- **Accettazione**: 100% dei casi §13 spec riferiti ai formati; vettori committati.
- **Formati persistiti**: definisce wrapper v1 e record v1 (nessuna scrittura reale).
- **Rollback**: R0. **Gate**: i test vector sono congelati; ogni PR successiva che
  li rompe è bloccata.

### PR‑3 — B3.3 Crypto Worker di produzione + supervisore

- **Obiettivo**: worker reale con protocollo chiuso; NESSUNA migrazione, NESSUN
  OpenMLS nel worker.
- **File**: `src/crypto/vault-worker.js` (module worker: INIT con allowlist URL
  `/vendor/styx-kdf-wasm/…`, handler §9 spec, validazione runtime, payload cap),
  `src/crypto/vault-worker-client.js` (correlazione per id, transfer, timeout,
  `_rejectAll` su terminate/crash), `src/crypto/vault-worker-supervisor.js`
  (respawn con backoff, cancellazione UNLOCK = terminate+respawn).
- **Dipendenze**: PR‑1, PR‑2. 
- **Test**: ogni tipo di messaggio + malformati (fuzz-lite sul protocollo); nessun
  oggetto WASM oltre il confine (probe W-F3); termination/respawn (pending
  rifiutate, stato ricostruibile); timeout; cancellazione di una derivazione in
  corso; CSP di produzione via `buildCsp()` (pattern spike W10) + blob worker
  negato; anti-bundle (il worker entra nel bundle SOLO quando il flag lo abilita —
  in questa PR il prodotto non lo importa affatto); CodeQL pulito.
- **Accettazione**: 100% protocollo coperto; zero riferimenti dal codice prodotto.
- **Rollback**: R0. **Gate**: protocollo congelato (ogni estensione = nuova voce
  allowlist con test).

### PR‑4 — B3.4 Motore IndexedDB del vault

- **Obiettivo**: `src/storage/vault-db.js` dentro il worker: schema v1 (9 store),
  transazioni multi-store risolte su `oncomplete`, `durability:'strict'` dove
  supportato, auto-close su `versionchange`, retry bounded su open bloccati
  (`VAULT_BLOCKED`, backoff 50 ms), quota → `VAULT_QUOTA_EXCEEDED` fail-closed,
  `persist()` bounded, upgrade fail-closed con registry di migratori, destroy con
  `onblocked` gestito, accesso single-tab via Web Lock esistente.
- **Dipendenze**: PR‑3 (vive nel worker). **Solo record sintetici/fixture.**
- **Test**: porting a produzione delle probe P1–P12 dello spike (kill
  mid-transaction all-or-nothing, upgrade abort→retry, blocked/versionchange,
  quota, multi-tab election/steal, 8 MB record binario); crash consistency con
  pagina uccisa.
- **Accettazione**: tutte le probe verdi su chromium+firefox in CI.
- **Formati persistiti**: schema IDB v1 (solo DB di test, nomi prefissati
  `styx-vault-test-*`). **Rollback**: R0. **Gate**: semantica transazionale congelata.

### PR‑5 — B3.5 Lifecycle di un vault nuovo e vuoto

- **Obiettivo**: `src/storage/vault.js` (nel worker): state machine spec §3 +
  `CREATE_VAULT / UNLOCK / LOCK / STATUS / CHANGE_PASSWORD / REWRAP / DESTROY`.
- **Vincoli**: Root Key 32 B casuali nel worker, mai derivata dalla password, mai
  persistita in chiaro, mai oltre il confine; KEK solo da Argon2id validato; re-wrap
  spec §7.2 (sempre ≥1 wrapper valido, `rewrapPending`); password errata →
  `VAULT_WRONG_PASSWORD` non distruttivo; wrapper incompatibile → fail-closed con
  azioni; LOCK = wipe best-effort, cancellazione forte = terminate; **nessuna
  migrazione da localStorage**.
- **Dipendenze**: PR‑1…PR‑4.
- **Test**: ogni transizione valida e vietata della state machine; crash durante
  re-wrap in OGNI punto (§7.2) con riapertura che trova un wrapper funzionante;
  wrong password ripetuta senza side-effect; distinzione password-errata vs
  wrapper-corrotto (§16.8: stessa risposta `VAULT_WRONG_PASSWORD` se l'unwrap
  fallisce con wrapper ben formato; `VAULT_WRAPPER_INVALID` solo per forma invalida
  PRIMA della derivazione — nessun oracle oltre la forma, che è comunque pubblica).
- **File aggiuntivo**: `src/config/vault-stage.js` — implementazione del flag
  `styx.vault.stage` (B3.0.6), introdotta QUI (prima PR che ne ha bisogno); il
  test anti-bundle di PR‑3 viene aggiornato di conseguenza.
- **Accettazione**: vault creabile/sbloccabile/distruggibile dietro flag
  `developer-only`, zero dati di prodotto. **Formati persistiti**: primo uso REALE
  di wrapper v1 + manifest v1. **Rollback**: R1 (flag off; i vault dev si
  eliminano con DESTROY). **Gate**: da qui esistono i primi vault persistiti →
  wrapper v1 e record v1 diventano contratti (decisione irreversibile n. 1, §16.13).

### PR‑6 — B3.6 Namespace canary

- **Obiettivo**: namespace `canary` con record sintetici generati localmente (mai
  informazioni dell'utente) esercitato end-to-end dall'app dietro flag.
- **Test end-to-end**: cifratura, AAD, persistenza, riapertura, password errata,
  corruzione (bit-flip a mano sul DB), crash, re-wrap, cambio password, reset,
  upgrade schema (v1→v2 di prova sul solo canary), SW update durante UNLOCKED
  (RK8), storage eviction simulata (destroy esterno del DB).
- **Dipendenze**: PR‑5. **Accettazione**: matrice §13 spec completa sul canary in
  CI. **Rollback**: R1. **Gate**: da qui in poi si possono toccare dati di
  prodotto.

### PR‑7 — B3.7 Primo namespace di prodotto: `settings` (impostazioni)

- **Scelta motivata** (criteri del mandato): formato semplice e stabile (JSON
  piatto) → confronto col legacy banale; poche dipendenze applicative (letto
  all'avvio, scritto raramente); reversibilità massima (shadow-read possibile,
  doppia scrittura economica); sensibilità bassa → **scala di rischio deliberata**:
  valida la macchina dual-write/shadow-read su dati la cui perdita non è
  catastrofica PRIMA di toccare identità e messaggi (non è scelto "perché è il più
  facile da programmare": è scelto perché minimizza il blast radius del primo
  contatto con dati reali, che è il criterio dominante a parità di copertura);
  comportamento offline: banalmente soddisfatto — `settings` è puramente locale,
  nessuna dipendenza di rete in lettura o scrittura.
  `push` (l'altro candidato non riservato alle fasi successive) è scartato: la
  subscription ha stato esterno (endpoint push) che complica rollback e confronto.
- **Meccanica**: dietro flag (`opt-in` non ancora attivo: solo `developer-only`/
  `test-profile`); dual-write legacy+vault; shadow-read con confronto e log locale
  di divergenza; switch di lettura solo a divergenze zero; **nessuna eliminazione
  del legacy**.
- **Test**: crash point table (§6) applicata a `settings`; divergenza iniettata →
  il legacy vince e l'evento è diagnosticato.
- **Rollback**: R1 (flag off → si legge solo legacy). **Gate**: due cicli di
  utilizzo dev senza divergenze.

### PR‑8a / PR‑8b — B3.8 `identity` poi `contacts`

- **PR separate, gate distinti** (prima `identity`: un solo record, poi `contacts`:
  lista).
- **Da specificare ed eseguire per ciascuna**: chiavi dei record (`identity/self`;
  `contacts/<idpk-hex>`), versionamento (`rv` monotono), AAD, mapping legacy →
  vault, confronto post-decryption byte-a-byte, ripresa dopo crash (manifest per
  namespace), identità parziali (pairing interrotto: si migra solo ciò che il
  legacy considera committato; il resto resta legacy finché il pairing non
  completa), compatibilità con il pairing in corso (la migrazione del namespace è
  rifiutata con `VAULT_WRONG_STATE` se un pairing è attivo), dati non autenticati
  o incompleti → restano nel legacy e vengono diagnosticati, MAI scartati.
- **Rollback**: R2 (legacy presente e leggibile; flag off torna al legacy).
- **Gate**: fixture di identità/contatti reali di test migrate e verificate.

### PR‑9a / PR‑9b — B3.9 `messages` poi `outbox` (+ ri-creazione `push`)

- **Separazioni obbligatorie**: messaggi ricevuti vs inviati (campo direzione nel
  valore, stessa chiave `<contactId>:<seq>`), stato locale di lettura, outbox
  (coda + retry metadata + stato delivery) in store separato; predisposizione
  `contentType` per allegati futuri (fuori scope B3). **I ciphertext MLS di
  trasporto NON sono la cifratura at-rest**: il vault cifra il plaintext
  applicativo dei messaggi memorizzati, come oggi fa localStorage in chiaro — la
  confusione dei due livelli è esplicitamente un difetto da test (§9: un record
  `messages` non contiene mai un evento Nostr).
- **Anti-perdita** (test per ciascuno): crash, reload, cambio password, re-wrap,
  quota esaurita (l'outbox NON scarta: fail-closed e retry), aggiornamento del
  service worker, cambio della tab writer (Web Lock steal: la vecchia tab smette
  di scrivere PRIMA che la nuova inizi — già semantica dello spike P7).
- **Rollback**: R2. **Gate**: N cicli di messaggistica reale di test senza perdite,
  con kill ripetuti.

### PR‑10 — B3.10 Migrazione MLS (ultimo namespace importante)

- **Contratto**: mapping spec §10.1 (`mls/state:meta` + `mls/state:payload`),
  codec unico (`mls-state-envelope.js` INVARIATO), envelope v1, verifica
  `payloadSha256` sui byte, payload binario, entrambi i PUT in una transazione,
  **restore probe col runtime MLS reale PRIMA di dichiarare `verified`** (stessa
  filosofia del `restoreProbe` di PR #23), localStorage fonte di verità fino al
  completamento, confronto byte-a-byte, nessun optimistic restore, nessuna
  modifica a wire format / pin OpenMLS / ciphersuite, **nessuna eliminazione del
  legacy prima del probe reale** (e comunque solo nella fase `legacy removed`).
- **Dipendenze**: PR‑8, PR‑9 (MLS per ultimo). **Rollback**: R2 fino al cleanup.
- **Gate**: fixture `mls-state-v1` migrata e ripristinata col runtime reale in CI;
  sessione reale di test sopravvive a migrazione + reload + scambio messaggi.

### PR‑11 — B3.11 Factory reset (PR dedicata)

- **Ordine**: (1) blocco nuove operazioni (`VAULT_WRONG_STATE`); (2) terminate del
  worker corrente (scarto immediato delle chiavi in memoria e delle operazioni in
  volo — la "cancellazione best-effort della memoria") e **respawn di un worker
  fresco in stato DESTROYING**, che esegue i passi successivi (il worker è l'unico
  accesso al DB: senza respawn i passi 3–9 non avrebbero esecutore); (3) wrapper
  attivo reso irrecuperabile (sovrascrittura record `meta`); (4) `deleteDatabase`;
  (5) localStorage legacy; (6) marker e backup; (7) push subscription; (8) Cache
  Storage pertinente; (9) service worker data; (10) transizione del worker a
  UNINITIALIZED e verifica di riapertura come installazione vergine (probe
  automatica). Crash tra (2) e (4): alla riapertura il wrapper è ancora presente →
  vault normalmente LOCKED, il reset si ripete da capo (idempotente). Nota di
  allineamento alla spec §12 (emendamento registrato): il wipe best-effort del
  LOCK è sostituito dal terminate immediato + respawn dedicato, che è più forte e
  definisce l'esecutore dei passi IDB.
- **Distinzioni dichiarate**: cancellazione **logica** (record non più
  raggiungibili), **crittografica** (wrapper distrutto ⇒ ciphertext residui
  indecifrabili senza password+salt), **fisica** (non garantibile dal browser —
  spec §12/V8).
- **Test**: reset da ogni stato lifecycle, incluso MIGRATING parziale; doppio
  reset; reset con DB bloccato da un'altra connessione.
- **Rollback**: R1 (il codice; il reset in sé è ovviamente irreversibile per i
  dati, ed è il suo scopo). **Gate**: probe "installazione vergine" verde.

### PR‑12 — B3.12 UI e UX (solo dopo il core)

- **Scenari**: creazione password (con indicazioni di passphrase robusta e
  indicatore locale; nessun invio in rete), sblocco con stato di derivazione e
  cancellazione, password errata, vault incompatibile (azioni strutturate, issue
  #24), storage non persistente (avviso RK2), quota, migrazione in corso
  (progresso per namespace), recovery, altra tab attiva, reset (conferma forte),
  password dimenticata.
- **Dichiarazione obbligatoria in UI e docs**: senza un meccanismo di recovery
  progettato separatamente, **la perdita della password può rendere i dati
  irrecuperabili**. Vietati: domande di sicurezza, hint della password, recovery
  deboli. Nessuna claim "zero-knowledge/serverless".
- **Rollback**: R1. **Gate**: revisione UX dei testi (niente promesse eccessive).

### PR‑13 — Rimozione del backend legacy (fase `legacy removed`)

- Rimozione del codice di lettura/scrittura localStorage e dei dual-write; factory
  reset aggiornato. **Rollback: R4** — richiede nuova autorizzazione esplicita e
  tutti i criteri di §7 (`opt-in → default-on` inclusi) già soddisfatti.

### PR‑14 — B3.13 OpenMLS nel Worker (fase 2, DOPO il primo rilascio del vault)

```text
Fase 1 (PR‑1…PR‑13): KDF + vault + cifratura nel Worker; OpenMLS resta dov'è.
Fase 2 (PR‑14):      OpenMLS e serializzazione MLS traslocano nel Worker.
```

- Il trasloco **non cambia il formato persistito** (stesso envelope, stesso
  mapping §10.1): cambiano solo la collocazione del runtime e il percorso dei
  byte (transferable). Regressione completa + fixture. **Rollback**: R1 (flag di
  collocazione). Gate dedicato; fuori dal critical path del Blocco 3.

---

## §6 Migrazione: piano eseguibile

Per OGNI namespace migrato (settings, identity, contacts, messages, outbox, mls)
la PR corrispondente deve compilare questa scheda (qui il contratto comune).
**Decisione per `push`**: la registrazione push NON si migra — si **ri-crea** una
subscription nuova al primo avvio con vault attivo (PR‑9b, stessa PR dell'outbox):
la subscription è stato esterno ri-derivabile (endpoint del push service, spesso
già stale), migrarla non conserva alcun valore e complicherebbe rollback e
confronto; il legacy viene disiscritto e il nuovo record scritto nello store
`push` del vault. Test dedicato: wake-up funzionante dopo la ri-creazione.

- **sorgente legacy**: chiavi localStorage enumerate nella PR;
- **destinazione**: store IDB + schema chiavi;
- **formato**: record v1 con `ct` dichiarato;
- **validazione**: parse del legacy fail-closed (mai migrare ciò che non si sa
  leggere: resta legacy + diagnostica);
- **transazione**: PUT del namespace + manifest nella stessa transazione dove
  possibile; altrimenti manifest-first (pending) e manifest-last (verified);
- **marker**: `migrations/<ns>` = `{state: pending|written|verified|cleaned,
  counts, digests}`;
- **verifica**: re-read → decrypt → confronto byte-a-byte col legacy;
- **cleanup**: rimozione legacy SOLO a `verified` E SOLO nella fase
  `legacy-removed` (PR‑13, autorizzazione R4): le migrazioni di PR‑7…PR‑10 si
  **arrestano a `verified`** e non eseguono mai il cleanup — è questo che rende
  vere le classi R2 e la promessa "flag off ripristina il legacy" (§16.12);
  ordine del cleanup, quando autorizzato: dati → marker;
- **crash point / resume / rollback / errore utente**: tabella sotto.

### Tabella dei crash point (fonte di verità per ciascuno)

| Crash point | Stato al riavvio | Fonte di verità | Resume |
|---|---|---|---|
| prima della lettura | nessun marker | legacy | ripartire da zero |
| dopo la lettura legacy | nessuna scrittura | legacy | ripartire da zero |
| dopo la cifratura (pre-PUT) | marker `pending`, store vuoto/parziale | legacy | ri-cifrare e ri-scrivere (idempotente: stessa chiave, `rv` invariato) |
| durante la transazione | transazione abortita (all-or-nothing, P3) | legacy | come sopra |
| dopo il commit IDB | marker `written` | legacy | passare alla verifica |
| prima della verifica | marker `written` | legacy | verificare |
| dopo la verifica | marker `verified`, legacy presente | **vault** (da qui) | cleanup |
| prima del cleanup legacy | marker `verified` | vault | cleanup |
| durante il cleanup | legacy parziale, marker `verified` | vault | completare il cleanup (idempotente) |
| dopo il cleanup | marker `cleaned` | vault | nulla |

Errore mostrato all'utente: sempre un codice stabile + azioni (issue #24); mai
"contatto nuovo"/perdita silenziosa; la migrazione fallita è sempre ritentabile.

## §7 Feature flag e rollout

| Stage | Chi | Criteri di transizione (misurabili) |
|---|---|---|
| `off` | tutti (default) | — |
| `developer-only` | build dev | PR‑5 merged; reversibile senza toccare dati utente (i vault dev si distruggono) |
| `test-profile` | profili di test dedicati | PR‑6 verde; canary 0 errori su 2 settimane di uso dev |
| `opt-in` | utenti che attivano esplicitamente | PR‑7…PR‑12 merged; migrazione manuale per-namespace; legacy intatto |
| `limited-alpha` | gruppo chiuso | 0 perdite dati note; UX errori validata; factory reset verificato |
| `default-on` | tutti i nuovi sblocchi | **M1–M5 completati**; review di sicurezza; test reali su profili esistenti; backup/restore (export) verificato; 0 bug Critical/High aperti; telemetria solo locale e non sensibile; documentazione utente; factory reset verificato |
| `legacy-removed` | codebase | PR‑13 (R4, nuova autorizzazione) |

`off → developer-only` è reversibile senza toccare dati utente. Ogni transizione è
un commit documentato con i criteri spuntati.

## §8 Test manuali M1–M5 — quando e cosa bloccano

| Test | Quando eseguirlo | Blocca |
|---|---|---|
| M1 Safari/iOS PWA (IDB, worker, persist, ITP) | dopo PR‑6 (harness canary disponibile) | Accepted; supporto iOS; default-on |
| M2 Chrome Android (kill in transazione, quota) | dopo PR‑6 | Accepted; supporto Android; default-on |
| M3 quota/storage pressure reale desktop | dopo PR‑4 | Accepted; default-on |
| M4 private browsing (tutti i motori) | dopo PR‑6 | Accepted; default-on; UX avvisi |
| M5 Argon2id su device reali + memoria WASM iPhone + worker/IDB Safari | dopo PR‑1 (bastano crate+harness) | Accepted; profili mobile definitivi; supporto iOS/Android; default-on |

Non bloccano: la scrittura di questo piano; lo sviluppo dietro flag `off`.
Bloccano (tutti): `Proposed→Accepted`, supporto dichiarato iOS/Android,
`default-on`, migrazione automatica generalizzata, Public Alpha Readiness gate.

## §9 Matrice di test minima (con tipologia)

| Caso | Tipo | PR |
|---|---|---|
| Known-answer Argon2id (ancore spike + RFC 9106) | unit+Playwright | 1 |
| Bounds KDF (ogni campo, ogni estremo) | unit+property | 2 |
| Wrapper malformed / campi sconosciuti | unit | 2 |
| Wrapper future version → dati intatti | unit | 2 |
| Password errata (ripetuta, non distruttiva) | integration | 5 |
| AAD tampering / namespace swap / record-key swap / content-type swap | unit+integration | 2,6 |
| Nonce fisso accidentale (property: unicità su N) | property | 2 |
| Record corrotto (bit-flip su nonce/data) | integration | 6 |
| Record vecchio ripristinato (replay per-record: documentato non rilevato) | integration (documenta il limite) | 6 |
| Manifest HMAC alterato → `VAULT_MANIFEST_TAMPERED` | integration | 5 |
| Crash durante re-wrap (ogni passo §7.2) | integration | 5 |
| Crash durante migrazione (ogni riga della crash table) | integration | 7–10 |
| Worker termination / respawn | integration | 3 |
| IndexedDB blocked / versionchange / upgrade abort | Playwright | 4 |
| Quota / storage eviction | Playwright + M3 | 4,6 |
| Private browsing | M4 (manuale) | — |
| Multi-tab (election, steal, single-tab access) | Playwright | 4 |
| Service worker update durante UNLOCKED/MIGRATING | Playwright | 6 |
| Offline: vault pienamente funzionante senza rete | Playwright | 6 |
| Factory reset da ogni stato | integration | 11 |
| Restore fixture MLS reale post-migrazione | integration | 10 |
| Build da clone pulito (CI) | CI | 1 |
| Bundle privo di spike/fallback/hash-wasm | CI (gate esistente esteso) | 3 |
| Nessun dato sensibile in log/errori (allowlist §11) | unit su ogni modulo | tutte |
| Regressione fixture (test vector PR‑2 + fixture MLS) | CI permanente | 2,10 |

Tipologie coperte: unit, property (`fast-check`), integration (jest), Playwright
su browser reali (chromium+firefox in CI), mobile reale e manuale (M1–M5),
regressione fixture.

## §10 Sicurezza e supply chain

**Nuovo componente unico: `styx-kdf-wasm`** — provenienza: RustCrypto `argon2`
0.5.3 (licenza MIT/Apache-2.0), `wasm-bindgen` 0.2.126 (MIT/Apache-2.0); pin
esatti + `Cargo.lock` committato; checksum: `SHA256SUMS` + digest in
`PROVENANCE.md`; SBOM: `cargo metadata` esportata in PROVENANCE; build
riproducibile verificata (`verify.sh`, doppia build); ownership: il progetto
(vendored); aggiornamento: procedura identica al crate canonico (bump autorizzato
+ PROVENANCE + review); rollback: revert del commit dell'artefatto (byte-identico,
proprietà del vendoring); compatibilità: il digest di `styx-kdf-wasm` NON entra
nell'envelope MLS (separazione §2.1) — un suo aggiornamento non tocca lo stato MLS.

CI (da predisporre in PR‑1, poi permanente): `cargo audit` e `cargo deny`
(licenze+advisory) sul crate; verifica `Cargo.lock` (build `--locked` + drift
guard); verifica dell'artefatto WASM (gate di integrità esteso); CodeQL JS
(esistente); test anti-drift pin/digest (pattern `mls-build-info`); secret
scanning GitHub + `gitleaks` + `trufflehog` in workflow dedicato; guardia
anti-`target/` (`git ls-files | grep '/target/'` → fail, in CI).

Nessuna nuova dipendenza runtime JS. `hash-wasm` resta confinato allo spike (mai
in produzione; il gate anti-bundle lo verifica).

## §11 Logging e diagnostica (allowlist chiusa)

**Consentiti**: codici errore (B3.0.3); versioni schema/wrapper/record; stato
lifecycle; durate arrotondate (10 ms); dimensioni aggregate (KiB arrotondati);
fase e conteggi della migrazione; capability del browser (booleane).
**Vietati**: password, KEK, Root Key, plaintext, ciphertext completi, identità,
contact ID, message ID, conversation ID, stato MLS, eventi Nostr, stack trace
contenenti payload. Enforcement: helper di log unico con serializzatore
allowlist-only + unit test che passa oggetti "avvelenati" e verifica l'output;
`causeMessage` mai auto-propagato (issue #26).

## §12 Compatibilità e aggiornamenti (versioni indipendenti)

| Dimensione | Sorgente | Nota |
|---|---|---|
| Schema DB | `vault-db.js` (IDB version) | migratori per versione |
| Wrapper | `version` nel wrapper | tabella §7.1 |
| Record | `v` nel record | AAD-bound |
| Key version | `kv` + suffisso HKDF `/vN` | rotazione senza cambiare Root Key |
| KDF | `kdfVersion` (19) | bounds §7.1 |
| Envelope MLS | envelope v1 (PR #23) | INVARIATO |
| Pin OpenMLS + digest | `mls-build-info.js` | INVARIATO nel B3 |
| Digest `styx-kdf-wasm` | `PROVENANCE.md` + anti-drift | NON nell'envelope |

Garanzie incrociate (test anti-drift in PR‑1): un aggiornamento di
`styx-kdf-wasm` non può invalidare lo stato MLS (digest non correlati); un
aggiornamento OpenMLS non tocca wrapper né record generici (nessun campo
condiviso).

## §13 Classi di rollback per PR

Definizioni:

```text
R0 — rimozione del codice senza dati persistiti né riferimenti dal prodotto
R1 — feature flag off; i dati nuovi vengono ignorati (o distrutti, se di sviluppo)
R2 — rollback con reader compatibile: il legacy è presente e leggibile
R3 — richiederebbe una migrazione inversa (nessuna PR di questo piano lo è)
R4 — non reversibile senza perdita o export
```

| PR | Classe | Motivazione |
|---|---|---|
| 1 KDF crate | R0 | nessun dato persistito, nessun riferimento dal prodotto |
| 2 formati puri | R0 | idem |
| 3 worker | R0 | non importato dal prodotto |
| 4 motore IDB | R0 | solo DB di test |
| 5 lifecycle | R1 | flag off; vault dev distruggibili |
| 6 canary | R1 | flag off; dati sintetici |
| 7 settings | R1 | flag off → si legge solo legacy (dual-write) |
| 8a/8b identity/contacts | R2 | legacy presente e leggibile fino a cleanup |
| 9a/9b messages/outbox | R2 | idem |
| 10 MLS | R2 | legacy fonte di verità fino a `verified`; cleanup separato |
| 11 factory reset | R1 | codice reversibile (l'azione utente no, by design) |
| 12 UI | R1 | flag off |
| 13 rimozione legacy | **R4** | perdita del percorso di ritorno; **nuova autorizzazione obbligatoria** |
| 14 OpenMLS nel worker | R1 | collocazione, non formato |

Nessuna PR è R3 (nessuna migrazione inversa prevista: il rollback è sempre
"il legacy è ancora lì"). L'unica R4 è PR‑13 e non può essere eseguita senza
nuova autorizzazione esplicita.

## §14 Stime (tre scenari)

Tempo di **lavoro effettivo** (il tempo di calendario dipende dalle attese:
review, dispositivi per M1–M5, eventuale audit — righe separate):

| Voce | Ottimistico | Probabile | Prudente |
|---|---|---|---|
| Sviluppo (PR‑1…PR‑11) | 10 g | 16 g | 24 g |
| Test (inclusi porting probe e property) | 4 g | 7 g | 11 g |
| UI/UX (PR‑12) | 2 g | 4 g | 6 g |
| Review indipendenti + correzioni | 3 g | 5 g | 9 g |
| Documentazione (PROVENANCE, schede migrazione, utente) | 2 g | 3 g | 5 g |
| **Totale lavoro effettivo** | **21 g** | **35 g** | **55 g** |
| Mobile manuale M1–M5 (dipende dai dispositivi) | 2 g | 4 g | 8 g |
| Attesa review/gate (calendario, non lavoro) | 1 sett | 2–3 sett | 5 sett |
| Audit esterno (se richiesto, calendario) | — | 2–4 sett | 6 sett |

PR‑13 (R4) e PR‑14 (fase 2) sono fuori da queste stime (gate propri).

**Critical path**: PR‑1 → PR‑2 → PR‑3 → PR‑4 → PR‑5 → PR‑6 → PR‑7 → PR‑8 → PR‑9 →
PR‑10. PR‑11 e PR‑12 si parallelizzano dopo PR‑6; M5 parte già dopo PR‑1, M1/M2/M4
dopo PR‑6.

## §15 PR plan (tabella riassuntiva)

| # | Titolo | Branch | Dipende da | Formati toccati | Rollback | Gate successivo |
|---|---|---|---|---|---|---|
| 1 | feat(kdf): styx-kdf-wasm pinned crate | feat/vault-kdf-wasm | — | nessuno | R0 | digest congelato; M5 avviabile |
| 2 | feat(storage): vault crypto formats (pure) | feat/vault-formats | 1 | definisce wrapper/record v1 | R0 | test vector congelati |
| 3 | feat(crypto): production crypto worker | feat/vault-worker | 1,2 | nessuno | R0 | protocollo congelato |
| 4 | feat(storage): vault IndexedDB engine | feat/vault-db | 3 | schema IDB v1 (test) | R0 | semantica tx congelata |
| 5 | feat(storage): vault lifecycle (empty vault) | feat/vault-lifecycle | 1–4 | wrapper+manifest reali | R1 | primi vault → contratti attivi |
| 6 | feat(vault): canary namespace e2e | feat/vault-canary | 5 | store canary | R1 | via libera ai dati di prodotto |
| 7 | feat(vault): settings namespace (dual-write) | feat/vault-settings | 6 | store settings | R1 | 2 cicli senza divergenze |
| 8a | feat(vault): identity migration | feat/vault-identity | 7 | store identity | R2 | fixture verificate |
| 8b | feat(vault): contacts migration | feat/vault-contacts | 8a | store contacts | R2 | fixture verificate |
| 9a | feat(vault): messages migration | feat/vault-messages | 8b | store messages | R2 | kill-test senza perdite |
| 9b | feat(vault): outbox migration + push re-creation | feat/vault-outbox | 9a | store outbox, push | R2 (outbox) / R1 (push: si ri-crea) | idem |
| 10 | feat(vault): MLS state migration | feat/vault-mls | 9b | store mls (mapping §10.1) | R2 | restore reale in CI |
| 11 | feat(vault): factory reset | feat/vault-reset | 6 | tutti (distruzione) | R1 | probe vergine |
| 12 | feat(app): vault UI/UX | feat/vault-ui | 6 (core, parallelizzabile) + 7…10 per gli scenari di migrazione/recovery | nessuno | R1 | review testi UX |
| 13 | chore(vault): remove legacy backend | feat/vault-legacy-removal | 10–12 + §7 | rimozione legacy | **R4 — nuova autorizzazione** | Blocco 3 chiuso |
| 14 | feat(crypto): OpenMLS into the worker | feat/vault-mls-worker | 13 (o post-B3) | nessuno | R1 | fase 2 |

Ogni PR: piccola e monotematica; contenuto, file, test e acceptance nelle schede
B3.x; review di sicurezza indipendente obbligatoria; KDF, storage, worker,
migrazione, UI e factory reset **mai nella stessa PR**.

## §16 Criticità (risposte esplicite)

1. **Root Key per stato**: UNINITIALIZED/LOCKED/RECOVERING/ERROR: solo wrappata in
   `meta` (o assente); UNLOCKING: mai in memoria (esiste solo la KEK appena
   derivata + il tentativo di unwrap); UNLOCKED/MIGRATING: nel worker (buffer
   privato); LOCKING: in corso di wipe; DESTROYING: già scartata — il terminate
   del worker precedente l'ha eliminata, e il worker fresco respawnato in
   DESTROYING (PR‑11) esegue la distruzione di wrapper e DB senza mai possederla.
   In UNLOCKING, più precisamente: la Root Key compare in memoria solo come esito
   dell'unwrap riuscito, un istante prima della transizione a UNLOCKED — mai prima.
2. **Confine worker**: verso il worker: password (stringa, limite V10 dichiarato),
   parametri validabili, chiavi/namespace in allowlist, byte transferable; verso
   la pagina: plaintext richiesti dei record, codici errore + details allowlist,
   stato lifecycle. MAI: Root Key, KEK, subkey, oggetti WASM, wrapper decifrato.
3. **KDF manipolati**: tabella spec §7.1 validata per intero nel worker PRIMA di
   qualunque chiamata a `styx-kdf-wasm` (test PR‑1: harness dimostra che
   l'allocazione non avviene su input rifiutato).
4. **Zero wrapper validi impossibile**: il wrapper attivo non viene mai
   toccato prima che `rewrapPending` abbia superato l'unwrap di verifica; il
   commit è una singola scrittura IDB; crash in ogni punto lascia attivo o il
   vecchio (fino al commit) o il nuovo (dopo) — test per ogni passo (PR‑5).
5. **Tab chiusa durante migrazione**: la transazione in corso committa o
   abortisce atomicamente (P3); il manifest resta `pending`/`written`; la fonte di
   verità è la crash table (§6); alla riapertura la migrazione riprende in
   MIGRATING dopo UNLOCK.
6. **SW update durante UNLOCKED/MIGRATING**: il worker non dipende dal SW (è un
   dedicated worker della pagina); l'update del SW può ricaricare la pagina →
   equivale a "tab chiusa" (punto 5); test dedicato in PR‑6 (RK8); il SW non
   cachea mai contenuti del vault.
7. **Fonte di verità per crash point**: tabella §6 — legacy fino a `verified`,
   vault dopo; mai due fonti contemporaneamente autorevoli per lo stesso namespace.
8. **Password errata vs wrapper corrotto senza oracle**: wrapper la cui FORMA
   fallisce la tabella §7.1 → `VAULT_WRAPPER_INVALID` PRIMA della derivazione (la
   forma è visibile a chiunque legga IDB: nessuna informazione nuova); wrapper ben
   formato il cui unwrap GCM fallisce → sempre e solo `VAULT_WRONG_PASSWORD`
   (indistinguibile tra password errata e `wrappedRootKey` manomesso: è
   intenzionale, non esiste un terzo segnale — nessun oracle sul contenuto).
9. **Metadati visibili in IDB**: nome DB, nomi store, chiavi record
   (`<contactId>:<seq>`), conteggi, dimensioni, `rv`/`kv`/`ct`, nonce — registrato
   e accettato (spec §1.2/V7) con mitigazione designata (chiavi opache HMAC).
10. **Log senza dati**: allowlist §11 con helper unico + test di avvelenamento;
    `causeMessage` mai propagato; error details in allowlist per codice.
11. **Restore MLS reale verificato**: restore probe col runtime WASM reale prima
    di `verified` (PR‑10) + fixture `mls-state-v1` in CI + sessione reale di test
    post-migrazione con scambio messaggi.
12. **Ritorno indietro per fase**: colonna Rollback in §15; fino a PR‑10 compresa
    il legacy esiste e il flag off ripristina il comportamento attuale.
13. **Irreversibilità**: (a) dal primo vault reale (PR‑5) wrapper v1/record v1
    diventano contratti → solo migratori versionati; (b) PR‑13 elimina il
    percorso di ritorno (R4); (c) il **cleanup per-namespace** (`verified` →
    `cleaned`, cioè la rimozione delle chiavi localStorage dell'utente) è
    irreversibile per quell'utente — per questo è confinato alla fase
    `legacy-removed` (§6/PR‑13); (d) il digest del primo artefatto
    `styx-kdf-wasm` entra in PROVENANCE (storia, non compatibilità). Tutto il
    resto è reversibile.
14. **Perdita della password**: i dati sono irrecuperabili by design (RK3); UI e
    docs lo dichiarano PRIMA della creazione del vault; niente recovery deboli;
    un meccanismo di export/backup (K_backup) è demandato a un blocco successivo
    con design dedicato.
15. **Eliminazione del legacy**: solo PR‑13, solo a `default-on` raggiunto con i
    criteri §7 (inclusi M1–M5), solo con nuova autorizzazione esplicita (R4).

---

## Review

La review indipendente di questo piano è in
`docs/security/2026-07-12-review-styx-vault-implementation-plan.md`.
