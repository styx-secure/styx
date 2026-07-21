# Review — Runtime isolato del vault worker (Blocco 3, PR‑3)

Oggetto: PR‑3 del piano Blocco 3 ("Isolated vault worker runtime") — protocollo
v1 + loader KDF verificato + runtime del worker + client + supervisor, SENZA
storage/lifecycle/OpenMLS/UI. Moduli
`styx-js/src/crypto/{vault-worker-errors,vault-worker-protocol,vault-kdf-loader,vault-worker-runtime,vault-worker,vault-worker-client,vault-worker-supervisor}.js`,
le tre suite jest, la spec browser Playwright con la fixture
`test/fixtures/vault-worker/test-worker.js`, lo step CI anti-bundle e
l'emendamento `WORKER_TIMEOUT` in B3.0.3.

- **Data:** 2026-07-12
- **Revisore:** indipendente dalla stesura (agente separato, contesto pulito;
  non l'autore, non i revisori delle PR precedenti)
- **Base:** `08c1e35` — **HEAD:** `415d808` (`feat/vault-worker-runtime`)
- **Scope:** esclusivamente il range `08c1e35..HEAD` (primo round sugli 8
  commit fino a `0623c90`, 15 file, +2430/−3; secondo round di verifica del
  fix W1 sul commit `415d808`, vedi §5); riferimenti normativi: spec di design
  §9 (worker protocol) e sezione PR‑3 del piano; fondamenta riusate
  verificate: `vault-shape.js` (snapshot strict) e `buildCsp()` di
  `apps/chat/static-server.mjs`.

Review condotta con verifiche **attive**: riesecuzione delle tre suite jest
(53/53) e della spec Playwright (Chromium + Firefox, 14/14), quattro probe
avversariali scritte dal revisore (181 asserzioni complessive, mai riusando i
test dell'autore) su protocollo chiuso, shape safety con contatori sugli
accessor, limiti dimensionali, sanitizzazione degli errori con eccezioni
portatrici di segreti, matrice URL avversariale del loader (30+ casi), spy su
`fetch`/`initSync`/`derive`, artefatto con byte flippato, semantica fatale del
client, backoff e razze del supervisor; build di produzione della PWA con grep
anti-bundle; grep statici su import dinamici/storage/DOM. Probe in
`scratchpad/review-worker-probes/` (ambiente di review, fuori dal repo).

## 1. Tabella di verifica (checklist del mandato, 17 voci)

| # | Voce | Verdetto | Evidenza attiva |
|---|---|---|---|
| 1 | Protocollo a mondo chiuso: 13 nomi, solo INIT/STATUS/SHUTDOWN attivi | **OK** | Probe A (76/76 PASS): `MESSAGE_TYPES.length === 13`, registri congelati, `ACTIVE_TYPES === ['INIT','STATUS','SHUTDOWN']`. Tutti e 10 i nomi riservati → `VAULT_WRONG_STATE/reserved-type`; nome sconosciuto (`EXFILTRATE`) → `BAD_REQUEST/unknown-type`. Payload oltre budget o shape invalida su un nome riservato → `BAD_REQUEST` PRIMA del ramo riservato (la validazione generica e i limiti precedono ogni handler). Nessun handler riservato deriva chiavi o finge successo: lo stato del runtime resta `NEW` dopo tutti i riservati; l'entry di produzione (`vault-worker.js`) non passa `testOverrides`. |
| 2 | Shape strict via `snapshotStrictPlainObject`, senza secondo validatore divergente | **OK** | Ispezione: request envelope, response envelope, oggetto errore `{code,details}` e payload INIT passano tutti da `snapshotStrictPlainObject` (vault-shape.js, riuso della disciplina F6 di PR‑2); `validateWireValue` è la grammatica dei VALORI (non un validatore di envelope concorrente) e applica le stesse regole (descrittori-dato enumerabili, niente Symbol, niente prototipi custom). Probe A: getter su `id` (contatore a **0** invocazioni, anche via `extractEnvelopeId`), getter annidato nel payload (contatore a 0), Symbol key, extra non-enumerabile, prototipo di classe, campo sconosciuto, id 0/frazionario → tutti `BAD_REQUEST` tipizzati. Origin non vuoto (`https://evil.example`) → `BAD_REQUEST/unexpected-origin` (guard difensivo, vacuo per design su dedicated worker — spec §9). |
| 3 | Limiti dimensionali (32 MiB, depth/nodi/array/stringhe, cicli, esotici) | **OK** | Probe A: `Uint8Array(32MiB+1)` → `over-byte-budget`; depth 20 → `over-depth`; array 16385 → `over-array-length`; stringa 1048577 → `over-string-length`; 65k+ nodi → `over-node-count`; ciclo → `cycle`; funzione (anche annidata) → `function`; bigint/undefined/NaN/Infinity → tipizzati; `SharedArrayBuffer` e vista SAB-backed → `shared-array-buffer`; `Int32Array`/`DataView` → `typed-array`; `Promise`, `CryptoKey` reale, `WebAssembly.Module/Instance/Memory` reali → tipizzati; `{__wbg_ptr: 12345}` → `wbg-handle`; array sparso e array con proprietà nominate → `exotic-array`. |
| 4 | Sanitizzazione errori: 5 codici stabili, allowlist details, nessun contenuto copiato | **OK** | Probe A: eccezione con `PASSWORD=tr0ub4dor`/`deadbeef`/stack sintetico lanciata dal loader → sul confine esce SOLO `{code:'WORKER_CRASHED', details:{reason:'unhandled-exception'}}`, JSON della risposta privo di ogni frammento del messaggio; `sanitizeWorkerErrorDetails` rifiuta chiavi fuori da `{type,phase,reason,attempt}`, valori > 64 char e non-primitivi; codice fuori protocollo o details fuori allowlist in una RISPOSTA → violazione di protocollo (`WORKER_CRASHED`) lato client. Set dei codici == esattamente i 5 di B3.0.3 (`BAD_REQUEST, VAULT_WRONG_STATE, WORKER_TERMINATED, WORKER_CRASHED, WORKER_TIMEOUT`); emendamento `WORKER_TIMEOUT` presente nel diff del piano. |
| 5 | Allowlist URL del loader (matrice avversariale propria) | **OK** | Probe B (56/56 PASS), 30+ casi: cross-origin, host spoofato per suffisso, `blob:` **con inner URL same-origin** (l'origin del blob combacia: respinto dal check di protocollo), `data:`, `file:`, `javascript:`, credenziali, query, fragment, backslash, `..` raw, `%2E%2E`/`%2e%2e`/`.%2e`, `%2f`/`%2F`/`%5c`, path OpenMLS (`wrong-artifact-path`), glue `.js` al posto del `.wasm`, suffisso esteso, > 1024 char, stringa vuota/null, whitespace, protocol-relative `//evil…` → tutti `BAD_REQUEST` tipizzati; accettati solo il path canonico (anche sotto prefisso di deployment) e `http:` esclusivamente su loopback (`127.0.0.1`/`localhost`/`[::1]`; IP LAN respinto). Verificata la necessità del rifiuto sull'input RAW: `new URL('/a/%2E%2E/vendor/x').pathname === '/vendor/x'` — il parser normalizza i dot-segment codificati prima di ogni check sul pathname. |
| 6 | Redirect negati + digest esatto + initSync solo con byte verificati + KAT | **OK** | Probe B con spy: `fetch` invocata con `redirect:'error'` e `credentials:'omit'`; lettura bounded (stream infinito di chunk da 1 MiB abortito a `oversized-artifact`); 42081/42083/42084 byte → fail tipizzato con **initSync mai chiamata**; digest dell'artefatto vendored ricalcolato dal revisore == `ad67202689c58d5e7b7a0b845d7b9d7253ecc04542f8921804c11d62942ae8f5`; **byte flippato → `digest-mismatch` e initSync a 0 chiamate**; happy path → `initSync` riceve ESATTAMENTE i 42082 byte verificati (confronto byte-a-byte con lo spy); KAT errata → `kat-mismatch`, `isLoaded()===false` (READY negato); output KAT (`7a6ebb2e…`) assente da ogni summary/risposta; fallimento fetch con URL interno nel messaggio → sul confine solo `fetch-failed`, URL non copiato. Browser spec: INIT reale con digest+KAT su Chromium e Firefox. |
| 7 | Nessun import dinamico da input; niente blob/data/eval | **OK** | `grep -nE "import\s*\(|blob:|data:|eval\(|new Function" src/crypto/vault-*.js` → solo un commento descrittivo nel loader; il glue è importato STATICAMENTE in `vault-worker.js:9` (e nella fixture di test); l'URL ricevuto via INIT raggiunge esclusivamente `fetch` dopo `validateKdfWasmUrl`. |
| 8 | Nessun oggetto WASM nel protocollo; fail-closed dopo violazione | **OK** | Probe A su `buildResultResponse` diretta: `WebAssembly.Module`, `{__wbg_ptr:7}`, `CryptoKey` → `WORKER_CRASHED` tipizzato, nulla raggiunge postMessage; runtime con override che ritorna `{__wbg_ptr}` o transfer oltre 32 MiB → risposta d'errore + `close()` invocata (stato `FAILED`). Browser spec (GET della fixture): risposta `WORKER_CRASHED` senza `__wbg_ptr` nel JSON e worker morto subito dopo (STATUS successiva → `WORKER_TIMEOUT`). |
| 9 | Client: fatale-una-volta, risposte anomale, timeout, transfer cap pre-postMessage | **OK** | Probe C (32/32 PASS): timeout → richiesta `WORKER_TIMEOUT`, altri pending `WORKER_TERMINATED`, `terminate()` sul worker, `onFatal` esattamente **1** volta; reply tardiva dopo il fatale inerte (nessuna seconda rejectAll/onFatal, promise già rigettata non risolvibile); id duplicato/sconosciuto, envelope malformata, `ok` non booleano, codice ignoto, details ostili, `'garbage'` → tutti fatali `WORKER_CRASHED`; `error`/`messageerror` fatali una sola volta, timer tutti ripuliti; `terminate()` deliberata NON invoca onFatal e tronca la reason a 64 char; 32MiB+1, duplicato, SAB, non-ArrayBuffer → respinti con `worker.postMessage` a **0** chiamate; eccezione di postMessage → fatale tipizzato senza testo dell'eccezione; pending map = solo `{resolve,reject,timer,type}` (ispezione + test dell'autore); id monotoni mai riusati; timeout clampato a [1, 600000]. |
| 10 | Supervisor: generazioni, backoff 100…1600 max 5, stop, cancelUnlock | **OK** (dopo il fix W1, §5) | Probe D: ladder non-fatale (INIT che risponde errore) esattamente `[100,200,400,800,1600]`, FAILED dopo 5, attempt 1…5 in onRespawn, 6 worker totali; eventi di generazioni vecchie ignorati; stop cancella il timer registrato e nessun respawn avviene dopo stop; mai due worker VIVI contemporaneamente (anche nella razza cancelUnlock-durante-spawn: live ≤ 1, RUNNING, attempts 0); cancelUnlock → pendings `WORKER_TERMINATED/unlock-cancelled`, respawn immediato senza consumare attempt né timer di backoff. Nel primo round un crash FATALE durante l'INIT consumava **due** attempt e armava **due** timer per un solo crash (**W1**); risolto in `415d808` e ri-verificato con la stessa probe (18/18 PASS, §5). |
| 11 | Cancellazione reale della KDF (suite browser rieseguita) | **OK** | `PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu24.04-x64 npx playwright test -c playwright.vault-worker.config.js` → **14/14 pass**. Timing della cancellazione: Chromium baseline 684 ms → cancel+respawn+INIT completati in 168 ms; Firefox baseline 3154 ms → 177 ms (cancel avviato a `min(150, baseline/4)` ms; asserzione `cancelMs < baseline*0.8`): la terminate è avvenuta DURANTE la run sincrona di Argon2id (65536 KiB, t=3, 6 round reali), unica cancellazione possibile (§7.2/mandato §15). |
| 12 | Transfer 8 MiB nei due sensi, detach, cap pre-postMessage | **OK** | Browser spec (rieseguita, Chromium+Firefox): 8 MiB random → digest SHA-256 identico all'andata e al ritorno, sorgente detached (`byteLength === 0`) subito dopo la post; 32MiB+1 → `over-transfer-budget` con buffer ANCORA attached (respinto prima di postMessage); duplicato → `duplicate-transferable`; client sopravvive ai rifiuti. Lato unit: probe C (voce 9) e cap speculare del runtime worker→pagina (probe A, voce 8). |
| 13 | CSP: `buildCsp()` riusata, worker-src 'self', denial browser reali | **OK** | Unico generatore: grep su `content-security-policy|worker-src` → solo `apps/chat/static-server.mjs`; la spec browser importa `buildCsp` da lì (riga 12) e la applica a ogni risposta del server di test; `static-server.mjs` non toccato nel range (0 commit). `worker-src 'self'` presente; nessun `blob:`/`data:`/`*`/`unsafe-eval` aggiunto. Test CSP rieseguito: module worker same-origin FUNZIONANTE (INIT+KAT sotto CSP reale), worker `blob:`/`data:`/cross-origin negati su entrambi i browser. `wasm-unsafe-eval` pre-esistente (commit `cf80b26`, PR‑1) e documentato in `docs/security/2026-07-11-*`. |
| 14 | Anti-bundle: build + grep dist | **OK** | `npm run build` in `apps/chat` eseguito dal revisore; `grep -rl 'vault-worker\|WORKER_TERMINATED\|WORKER_TIMEOUT\|argon2id_derive\|styx_kdf_wasm\|ad67202…8f5' dist/` → nessun match; `find dist -name '*vault*'` → vuoto; nessun import di `vault-worker*`/`vault-kdf-loader` da `apps/chat/src`, `apps/chat/index.html`, `src/facade`, `src/chat`, `src/index.js` (grep, exit 1). Nuovo step CI presente nel diff di `styx-js-web.yml` con le stesse firme. |
| 15 | No storage/lifecycle/OpenMLS/UI; STATUS onesto; niente `styx.vault.stage` | **OK** | Grep sui 7 moduli: zero `indexedDB/localStorage/sessionStorage/document./window./navigator.`; unica occorrenza di "openmls" è la capability `openmls: false`. Probe A + browser spec: STATUS → `vaultState: null`, `capabilities: {kdf, storage:false, lifecycle:false, openmls:false}`, `versions {wrapper:1, record:1, key:1}`. `grep -rn 'styx\.vault\.stage' src apps test` → zero. |
| 16 | Zero nuove dipendenze runtime | **OK** | `git diff 08c1e35..0623c90 -- styx-js/package.json styx-js/package-lock.json` → **0 righe**. |
| 17 | Riesecuzione delle tre suite jest | **OK** | `node --experimental-vm-modules node_modules/.bin/jest test/crypto/vault-worker-{protocol,client,supervisor}.test.js --forceExit` → 3 suite, **53/53 pass**. |

Caccia oltre la checklist (esiti negativi = nessun difetto trovato, salvo W1):
INIT concorrente durante INITIALIZING → `VAULT_WRONG_STATE/state:INITIALIZING`;
id duplicato in volo → `BAD_REQUEST/duplicate-id` e il set `inFlight` viene
ripulito nel `finally`; INIT idempotente SOLO a configurazione identica
(`config-mismatch` altrimenti); superficie `testOverrides` non raggiungibile in
produzione (l'entry non ne passa; override di INIT/STATUS/SHUTDOWN o di nomi
fuori registro → `TypeError` alla costruzione; la fixture vive nel test tree ed
è esclusa dal bundle); razza cancelUnlock ↔ spawn in volo → mai due worker
vivi, generazione stale scartata con `terminate('stale-generation')`;
`start()` dopo FAILED consentito con reset del ladder; nessun contenuto
leggibile dagli errori in nessun percorso provato.

## 2. Finding

| ID | Severità | Dove | Finding | Risoluzione proposta | Stato |
|---|---|---|---|---|---|
| W1 | Minor | `vault-worker-supervisor.js:88-124` (`scheduleRespawn`/`startGeneration`/`handleFatal`) | Doppio `scheduleRespawn` per un singolo crash FATALE durante l'INIT: quando il worker muore mentre l'INIT è in volo (error event, timeout, script del worker che non carica), il client rigetta la pending INIT **e** invoca `onFatal` → `handleFatal` schedula un respawn (attempt +1, timer armato), poi il `catch` di `startGeneration` vede `state === BACKOFF` (≠ STOPPED/FAILED) e schedula di NUOVO (attempt +1, secondo timer, `backoffTimer` sovrascritto senza clear). Dimostrato con probe D: dopo UN crash `attempts=2`, timer armati `[100,200]`, `onRespawn` invocata due volte (attempt 1 e 2); a regime FAILED dopo **3** crash fatali invece di 5 e un respawn parte da un timer stale mentre un altro è armato; `stop()` cancella solo l'ultimo timer (il primo, sovrascritto, resta armato — inerte solo grazie al guard `state !== BACKOFF`). Il percorso coperto dai test dell'autore (INIT che RISPONDE con errore, non-fatale) non lo attraversa; il ladder mandato (100/200/400/800/1600, max 5) diverge nel caso realistico. Nessun impatto di riservatezza: si fallisce PRIMA, mai due worker vivi, nessun leak. | Nel `catch` di `startGeneration`, non rischedulare se un respawn è già stato programmato da `handleFatal` per la stessa generazione (es. `if (state === SUPERVISOR_STATES.BACKOFF && backoffTimer !== null) return;`), oppure rendere `scheduleRespawn` idempotente (se `backoffTimer !== null`: clear senza incrementare di nuovo `attempts`). Aggiungere il test unit "crash fatale durante INIT → un solo attempt, un solo timer, ladder 100…1600, FAILED dopo 5". | **risolto (commit `415d808`)** — verificato dal revisore, vedi §5 |
| W2 | Info | `vault-kdf-loader.js:139-141` | Il ramo di fallback senza body stream (`response.arrayBuffer()`) legge l'INTERO corpo in memoria prima del check dimensionale: la "bounded read" è strettamente garantita solo sul ramo `getReader()`. Nei browser reali `response.body` esiste sempre, quindi il ramo è di fatto solo per ambienti di test; il fail-closed sui byte letti regge comunque. | Facoltativo: rifiutare (`fetch-not-ok`/reason dedicata) quando `response.body` è assente, oppure documentare il ramo come test-only. | aperto (accettabile) |
| W3 | Info | `vault-worker-supervisor.js:41-51` | Il JSDoc descrive `jitter` come "injectable 0..1 source (tests only; production defaults are module-internal)" ma il default modulo-interno è `() => 0`: in produzione il backoff NON ha jitter. Con un solo client locale per origin il jitter è irrilevante (nessun thundering herd); è solo una discrepanza documentale. | Facoltativo: allineare il commento ("no jitter by default") o usare `Math.random` come default. | aperto (accettabile) |

Nessun finding Critical o Important. W1 era un difetto di robustezza/conformità
al piano (mandato: ladder esatto e cancellazione dei timer in `stop()`), non di
sicurezza: la direzione dell'errore era fail-closed (FAILED prematuro, mai due
worker vivi, nessun dato attraversa il confine). È stato risolto nel commit
`415d808` e ri-verificato attivamente dal revisore (§5).

## 3. Rischi residui / limiti accettati

1. **Origin guard vacuo by design** (spec §9, dichiarato): su un dedicated
   worker `event.origin` è la stringa vuota; il guard su origin non-vuoto è
   difesa in profondità (verificato attivo dalla probe), la difesa reale è
   allowlist + validazione runtime.
2. **`wasm-unsafe-eval` nella CSP**: pre-esistente (PR‑1, commit `cf80b26`),
   necessario per compilare il WASM del KDF; mitigato dal loader verificato
   (size+digest+KAT) e da `worker-src 'self'`. Nessun allargamento in PR‑3.
3. **Gate CI anti-bundle temporaneo**: come in PR‑2, lo step sarà rivisto solo
   dalla PR (separatamente autorizzata) che collegherà il vault all'app; fino
   ad allora le sei firme coprono moduli, codici d'errore, export WASM e digest.
4. **Fixture `test-worker.js` con override dei tipi riservati**: vive nel test
   tree, usa la stessa runtime factory con la guardia che impedisce override
   dei tipi attivi e di nomi fuori registro; non importabile dal bundle
   (anti-bundle verificato) e mai referenziata dall'entry di produzione.
5. **Fallback Chromium locale non pinnato** in
   `playwright.vault-worker.config.js` (inerte in CI) — stesso caveat delle
   review PR‑1/PR‑2.
6. **Zeroization best-effort** di password/salt/output KAT nel loader e nella
   fixture: limite intrinseco di JS, coerente con quanto già accettato in PR‑2.
7. **Stima dei byte del wire approssimata** (4/8/16 byte per nodo, 2 per char):
   è un budget, non una misura esatta della serializzazione structured-clone;
   i bound su nodi/profondità/stringhe/array chiudono comunque ogni percorso
   di amplificazione provato.

## 4. Verdetto

```text
GO
```

Le 17 voci della checklist risultano verificate attivamente (probe proprie:
76+56+32+18 asserzioni; suite jest 53/53 al primo round; Playwright 14/14 su
Chromium e Firefox con l'artefatto e la CSP di produzione reali; build della
PWA pulita). Le proprietà centrali del mandato reggono alle probe
avversariali: protocollo a mondo chiuso con validazione e limiti PRIMA di ogni
handler, shape strict senza mai invocare accessor, loader verificato in cui un
byte flippato non raggiunge mai `initSync`, errori a 5 codici senza alcun
contenuto copiato, timeout fatale con terminate+respawn, cancellazione reale
di Argon2id sincrona dimostrata dai timing su due browser, nessun oggetto WASM
oltre il confine, worker runtime assente dal bundle di produzione.

Il primo round si era chiuso **GO CON CONDIZIONI** con l'unica condizione di
risolvere **W1** (doppio conteggio del backoff su crash fatale durante l'INIT,
timer stale non cancellabile da `stop()`). Il fix è stato applicato nel commit
`415d808` e **ri-verificato attivamente dal revisore** (§5): la condizione è
sciolta e il verdetto è GO pieno su HEAD `415d808`. Restano aperti solo gli
Info W2 e W3, registrati come accettabili.

## 5. Secondo round — verifica del fix W1 (HEAD `415d808`)

Il commit `415d808` ("fix(vault): schedule exactly one respawn per worker
generation") applica W1. Diff ispezionato (`git show 415d808`): tocca SOLO
`vault-worker-supervisor.js` (+7: variabile `respawnScheduledFor` e guardia
per-generazione in testa a `scheduleRespawn` — `if (respawnScheduledFor ===
generation) return; respawnScheduledFor = generation;`) e la sua suite (+38:
behavior `init-crash` nel FakeWorker e 3 test di regressione); nessun altro
modulo, nessuna dipendenza, `package.json`/lockfile intoccati.

Correttezza della guardia (ispezione): il doppio percorso (onFatal del client
+ rejection della spawn) appartiene per costruzione alla STESSA generazione,
quindi la seconda chiamata rientra sulla guardia senza incrementare `attempts`
né armare un secondo timer; ogni respawn successivo passa da
`startGeneration`, che incrementa `generation`, riabilitando esattamente UNA
schedulazione per la generazione nuova; i percorsi non-fatali (INIT che
risponde errore: solo il `catch`) e i fatali post-READY (solo `handleFatal`)
chiamano `scheduleRespawn` una volta sola e restano invariati.

Verifica attiva del revisore — riesecuzione della MIA probe D (la stessa che
aveva dimostrato il difetto, invariata): **18/18 PASS** (prima: 17/18).
Confronto puntuale prima → dopo sullo stesso scenario:

- crash fatale durante l'INIT, dopo UN solo crash: `attempts` 2 → **1**, timer
  armati `[100,200]` → **`[100]`**, `onRespawn` 2 invocazioni → **1**;
- scala completa con OGNI init in crash fatale: FAILED dopo 3 crash/3 worker →
  **FAILED dopo 5 crash con 6 worker** e delays esattamente
  **`[100,200,400,800,1600]`** (ladder del mandato ripristinato);
- recovery (`init-crash` poi `init-ok`): timer stale residui 1 → **0**,
  RUNNING con un solo worker vivo e `attempts` azzerati;
- `stop()` durante quel backoff: timer ancora armati dopo stop 1 → **0**;
- invarianti confermate: mai due worker vivi nella razza
  cancelUnlock-durante-spawn, generazioni stale ignorate, ladder non-fatale e
  cancelUnlock senza consumo di attempt identici al primo round.

Riesecuzione delle tre suite jest su `415d808`: **56/56 pass** (53 del primo
round + 3 regressioni W1 nuove, che coprono esattamente i tre casi sopra:
contabilità del crash singolo, ladder completo sotto crash fatali, stop
durante quel backoff).

### Verdetto del secondo round

```text
GO
```

W1 risolto e ri-verificato con la probe indipendente che lo aveva scoperto;
nessuna regressione (probe D 18/18, suite 56/56); la condizione del primo
round è sciolta. Il verdetto GO è confermato su HEAD `415d808`.

## 6. Terzo round — verifica dei fix W4–W8 (HEAD `b67c9b0`)

Un gate utente successivo al secondo round ha emesso cinque finding sul
runtime worker, corretti nei commit da `835af17` a `b67c9b0` più il rebase su
`origin/main` (`0a2c2c0`, governance Merge Queue di PR #37). Terzo round
condotto da revisore indipendente a contesto pulito, in un worktree read-only
su `b67c9b0`, con verifiche **attive**: quattro probe proprie (145 asserzioni
complessive, con contatori sulle invocazioni degli accessor e fake
worker/timer del revisore, mai riusando i test dell'autore), riesecuzione
delle sei suite jest (**154/154**), rigenerazione delle fixture congelate
(zero drift), ricalcolo del digest KDF (`ad67202…8f5`, 42082 byte, costanti
del loader identiche), diff di perimetro sull'intero range
`origin/main..HEAD` (15 commit, 17 file, tutti nell'autorizzazione; zero
tocchi a vendor/, @noble, formati wire, Dart, apps/chat; lockfile intoccato).
La spec Playwright non è stata rieseguita (16/16 già documentati su
Chromium+Firefox); il nuovo test browser del circuit breaker è stato
verificato staticamente (`vault-worker.browser.spec.js:151‑187`: crash loop
reale via DESTROY, atteso FAILED con 6 spawn, mai un settimo, nessuno spawn
dopo stop).

| ID | Severità | Finding | Esito |
|---|---|---|---|
| W4 | Important | Base della PR superata/non-mergeable e perdita della semantica Merge Queue del workflow | **risolto** — merge-base == `0a2c2c0`; nel range solo i 15 commit PR‑3; il diff di `styx-js-web.yml` contiene ESCLUSIVAMENTE lo step anti-bundle del worker (+17 righe); sul branch restano `merge_group: [checks_requested]`, `MERGE_GROUP_BASE_SHA` con fallback fail-closed, gate aggregatore fail-closed, action pinnate a SHA, gate KDF e gate formati vault. |
| W5 | Important | Bypass su array via accessor/descrittori esotici in `validateWireValue` (lettura `v[i]`) | **risolto** — probe con contatori (49/49): 14 costruzioni ostili × request/result/diretto → errori tipizzati `BAD_REQUEST`/`WORKER_CRASHED` con **0 invocazioni di getter** e nessun testo dell'attaccante; prototype `Array.prototype` obbligatorio, `length` come data descriptor standard, `Reflect.ownKeys` limitato a length+indici canonici densi, elementi letti SOLO da `desc.value` enumerabile; array validi (densi, annidati, vuoti, `Uint8Array` interni) passano. |
| W6 | Important | Bypass strict-shape sui `details` degli errori (`Object.keys`+`details[key]`) | **risolto** — `sanitizeWorkerErrorDetails` passa da `snapshotStrictPlainObject` con `{requiredKeys: []}`; probe 29/29: 13 shape ostili → `TypeError` con getter a 0 invocazioni; risposta con details ostili → `WORKER_CRASHED/bad-error-details` senza contenuto; il client la tratta come violazione fatale (onFatal ×1, terminate); `toWireError` ri-sanitizza le istanze mutate post-costruzione → `{code:'WORKER_CRASHED', details:{reason:'unhandled-exception'}}`; retro-compatibilità PR‑2 confermata (`vault-wrapper`/`vault-record` a 3 argomenti, tutti i campi obbligatori, suite verdi). |
| W7 | Important | Crash loop post-READY illimitato (attempts azzerati da ogni INIT verificato) | **risolto** — probe con fake worker/timer del revisore (37/37): 6 generazioni INIT-ok-poi-crash → delays `[100,200,400,800,1600]`, FAILED, 6 worker e mai un settimo, mai due vivi, 0 timer residui; la streak NON è azzerata dall'INIT ma solo da 30000 ms continuativi in RUNNING (`STABILITY_RESET_MS`, timer iniettabile) o da `start()` deliberato da STOPPED/FAILED; crash prima della scadenza → 200/attempt 2, dopo la scadenza → 100/attempt 1; `stop()` cancella backoff E stability timer senza reset tardivi; stessa protezione per i TIMEOUT fatali post-READY (ladder completo fino a FAILED); regressione W1 confermata (un solo attempt/timer/onRespawn per crash fatale durante INIT); `cancelUnlock` non consuma né azzera il budget. |
| W8 | Minor | Payload STATUS/SHUTDOWN non chiusi dalla grammatica | **risolto** — probe 30/30: solo `payload === null` accettato; `{}`, stringa, `Uint8Array` da 1 byte e da 32 MiB (massimo del budget), boolean, numero, array → `BAD_REQUEST/unexpected-payload` PRIMA di ogni handler, worker sempre READY; payload con getter respinto dalla grammatica wire con getter mai invocato; SHUTDOWN invalido → `close()` a **0** chiamate e worker ancora attivo; INIT esige esattamente `{wasmUrl}`; i riservati mantengono la sola validazione generica prima di `VAULT_WRONG_STATE`. |

Tre osservazioni informative nuove, nessuna bloccante: N1 — doppia lettura di
`err.code` in `toWireError` (`vault-worker-errors.js:82,87`; TOCTOU teorico
in-realm, contenuto dal rigetto client dei codici ignoti; leggere il codice
una sola volta); N2 — un `Proxy` può superare `validateWireValue` solo per
valori prodotti nello stesso realm (gli input del confine sono già output di
structured clone); da ricordare per gli handler PR‑5; N3 —
`supervisor.request()` non esclude `SHUTDOWN` (auto-DoS in-realm che consuma
un attempt; da chiudere in PR‑5). W2/W3 (Info) restano aperti come accettati.

### Verdetto del terzo round

```text
GO
```

W4, W5, W6 e W7 (Important) e W8 (Minor) risultano risolti e ri-verificati
attivamente su HEAD `b67c9b0`; batteria di non-regressione integralmente
verde (jest 154/154, fixture congelate senza drift, digest KDF invariato,
zero nuove dipendenze, perimetro del range conforme all'autorizzazione,
registri del protocollo invariati: 13 tipi, 3 attivi, v1, 5 codici). Il
verdetto GO è confermato su HEAD `b67c9b0`.
