# Review — Formati crittografici puri del vault (Blocco 3, PR‑2)

Oggetto: PR‑2 del piano Blocco 3 ("Formati crittografici puri") — i moduli
`styx-js/src/crypto/{vault-errors,vault-aad,vault-keys}.js`,
`styx-js/src/storage/{vault-wrapper,vault-record}.js`, le suite jest e la spec
browser, i vettori congelati `styx-js/test/fixtures/vault-crypto-v1/`, gli
emendamenti alla spec di design e lo step anti-bundle in CI.

- **Data:** 2026-07-12
- **Revisore:** indipendente dalla stesura (agente separato, contesto pulito;
  il terzo round è condotto da un ULTERIORE revisore indipendente, a contesto
  pulito, diverso da quello dei primi due round)
- **Base:** `9344985` (main) — **HEAD:** `2ad9504` (`feat/vault-crypto-formats`)
- **Scope:** esclusivamente `git diff 9344985..2ad9504` (primo round su
  `277a671`; secondo round di verifica sul fix `6cf381c`, vedi §5; terzo round
  di verifica dei fix F6–F9 sul range `a0997dc..2ad9504`, vedi §6)

Review condotta con verifiche **attive**: riesecuzione delle tre suite jest
(66/66 su `277a671`; 70/70 su `6cf381c`, §5) e della spec Playwright
(Chromium + Firefox), ri-derivazione
indipendente dei vettori standard (RFC 5869, RFC 4231, AES-256-GCM NIST) e di
TUTTE le fixture congelate con **WebCrypto grezza e AAD costruite a mano**
(mai riusando il codice di test dell'autore), probe avversariali scritte dal
revisore su Base64 canonica, shape safety (array/prototipi/getter/Proxy/TOCTOU),
uniformità degli errori di autenticazione, superficie API dei nonce, doppia
esecuzione del generatore di fixture con diff byte-a-byte, build di produzione
della PWA con grep sul bundle. Probe in
`scratchpad/review-probes/` (ambiente di review, fuori dal repo).

## 1. Tabella di verifica (checklist del mandato, 20 voci)

| # | Voce | Verdetto | Evidenza attiva |
|---|---|---|---|
| 1 | Aderenza ai formati (wrapper §7/§7.1, record §6) | **OK** | Confronto campo-per-campo del codice con la tabella §7.1: tutti i 17 campi del wrapper vincolati (format/version/wrapAlg esatti; kdf/kdfVersion/mKib/t/p/salt/outLen/profile delegati a `kdf-bounds.js`; wrapNonce 12 B; wrappedRootKey 48 B; keyVersion, createdAt data reale `YYYY-MM-DD`, calibratedMs 0…600000, rewrapPending depth 1). Record: `v==1`, ns in allowlist, `k` 1–256 char well-formed senza control char (probe dedicata: NUL/tab/newline/DEL rifiutati, spazio e Unicode accettati), `rv≥1`, `kv==1`, ct `json\|bytes`, nonce 12 B, data 16 B…16 MiB+16 (probe: 15 B e 16 MiB+17 rifiutati, 16 MiB+16 accettato). Nota: `version>1` ben formata → `VAULT_WRAPPER_UNSUPPORTED` (raffinamento fail-closed della tabella, codice dedicato). |
| 2 | Campi sconosciuti rifiutati | **OK** | Probe: campo extra sul wrapper → `VAULT_WRAPPER_INVALID` (`{field}` nel dettaglio); campo extra sul record → `VAULT_RECORD_INVALID`; campo mancante → idem. Vedi però F1 per nomi di campo > 64 char (risolto in `6cf381c`, §5). |
| 3 | Plain-object/accessor safety | **OK** | Probe: array, istanza di classe, getter (`defineProperty`), proprietà ereditata via prototype custom, `toJSON` own → tutti rifiutati con codice tipizzato; `Object.hasOwn` usato per presenza campi e descrittori (`Object.getOwnPropertyDescriptor` + `hasOwn(desc,'value')`); oggetto a prototipo `null` accettato. `toJSON` sul plaintext JSON è onorato da `JSON.stringify` (semantica standard del VALORE, non dei metadati: round-trip coerente, nessun impatto sui formati). |
| 4 | Base64 canonica | **OK** | Probe revisore (`probe-base64.mjs`): padding mancante/extra/triplo, whitespace (spazio, `\n`, `\t`, `\r`, interni e finali), alias a trailing bits non-zero (`QQF=`→rifiutato, `QQE=`→accettato; `QR==`→rifiutato, `QQ==`→accettato; `QS==`→rifiutato), alfabeto URL-safe (`-`,`_`), `=` interno, lunghezza non multipla di 4, astrali, non-stringhe: tutti `null`. Fuzz 20k stringhe casuali: ogni stringa accettata ri-codifica identica (una sola codifica per byte string); round-trip 800 buffer casuali 1–4 B. |
| 5 | `rewrapPending` depth 1 | **OK** | Probe: pending depth 1 accettato; pending-dentro-pending → `VAULT_WRAPPER_INVALID: rewrapPending exceeds the maximum depth of 1`. Emendamento normativo presente nella spec §7.1 (diff verificato). |
| 6 | AAD wrapper canonica + esclusioni documentate | **OK** | Fixture `wrapper-v1.json`: AAD ricostruita **a mano** dalla formula `JSON.stringify([format, version, kdf, kdfVersion, mKib, t, p, saltB64, outLen, keyVersion])` == `aadUtf8` == `aadHex`; unwrap con WebCrypto grezza → `rootKeyHex` dichiarato. Probe: l'AAD non contiene `profile`/`createdAt`/`calibratedMs`; esclusione documentata nel JSDoc di `buildWrapperAadBytes` (vault-aad.js:29-33) e la terna `(mKib,t,p)` in AAD determina univocamente il profilo. |
| 7 | AAD record da RICHIESTA + equality check | **OK** | Verificato **nel codice**: `vault-record.js:242` (`record.ns !== namespace \|\| record.k !== recordKey` → `VAULT_RECORD_INVALID`) e `:246-248` (AAD con `ns: namespace, k: recordKey` dalla richiesta, `v/rv/kv/ct` dal record). Probe anti-swap: record con `ns`/`k` auto-dichiarati riscritti per combaciare con la richiesta ma ciphertext legato ad altra chiave/namespace → `VAULT_RECORD_CORRUPTED` (mai "riparato"). |
| 8 | Nonce non controllabile dal chiamante | **OK** | Ispezione delle firme esportate: nessun parametro nonce/iv in `wrapSyntheticRootKey`, `encryptVaultRecord` (generazione interna `crypto.getRandomValues` a ogni chiamata). Probe: proprietà extra `nonce`/`iv`/`wrapNonce` passate negli input vengono ignorate (nonce interno casuale, mai zero; due chiamate → nonce distinti). Le fixture deterministiche sono prodotte dal generatore separato `generate.js` che re-implementa il lato encrypt (documentato). Vedi F3 (Info). |
| 9 | Separazione subkey / allowlist namespace | **OK** | Probe: `VAULT_NAMESPACES` == esattamente gli 8 della spec emendata; `deriveNamespaceKey` rifiuta `manifest`, `backup`, `meta`, `migrations`, `__proto__`, `constructor`, `toString`, `''` con `VAULT_NAMESPACE_UNSUPPORTED`; info string esatte confermate byte-a-byte dalle 10 derivazioni ricalcolate (voce 10); chiavi derivate non-extractable; keyVersion≠1 rifiutata. Decrypt con la subkey di un altro namespace → `VAULT_RECORD_CORRUPTED`. |
| 10 | Vettore HKDF indipendente | **OK** | Probe revisore (`probe-standard-vectors.mjs`, WebCrypto grezza, nessun file di test riusato): RFC 5869 TC1 → OKM 42 B byte-identico; le 10 derivazioni di `hkdf-v1.json` ricalcolate con `subtle.deriveBits` → 10/10 identiche, root key == SHA-256 del label sintetico, salt == SHA-256(`styx-vault-v1`), 10 OKM a coppie distinti. |
| 11 | Vettore AES-GCM indipendente | **OK** | Probe: AES-256-GCM chiave zero / IV zero / plaintext vuoto → tag `530f8afbc74536b9a963b4f1c4cb738b` (match). |
| 12 | Vettore HMAC indipendente | **OK** | Probe: RFC 4231 TC1 → `b0344c61…2e32cff7` (match); inoltre `manifest-hmac-v1.json` ricalcolato con WebCrypto grezza → MAC identico, chiave == OKM `manifest` della fixture HKDF. |
| 13 | Mappatura uniforme dei fallimenti di autenticazione | **OK** | Probe wrapper: KEK errata, bit-flip ciphertext, bit-flip tag, bit-flip nonce, tamper di campi AAD-bound su wrapper BEN FORMATO (swap profilo coerente `mobile-balanced→desktop` con terna aggiornata; salt canonico diverso) → **stesso** `VAULT_WRONG_PASSWORD\|wrong password or tampered wrapper`, `details === undefined` in tutti i casi. Probe record: bit-flip data/tag/nonce, swap `rv`, swap `ct`, chiave di namespace sbagliata → **stesso** `VAULT_RECORD_CORRUPTED\|record authentication failed`. Il test d'integrazione dell'autore (rieseguito) copre anche la password errata attraverso il VERO artefatto styx-kdf-wasm. Vedi F4 (Info) sul messaggio del solo caso post-autenticazione. |
| 14 | Nessun oracolo aggiuntivo, `details` chiusa | **OK** | `vault-errors.js`: allowlist chiusa `['field','reason','namespace']`, valori solo stringhe ≤ 64 char o safe integer, oggetto `details` congelato, codici in set chiuso. Probe: nessun errore osservato contiene salt, nonce, chiavi, plaintext o ciphertext; i parametri KDF fuori policy hanno codice distinto `VAULT_KDF_PARAMS_INVALID` (validazione pre-crypto, non oracolo di autenticazione — 3 GiB richiesti → mai raggiunta la derivazione). Vedi F1 sul caso limite > 64 char (risolto in `6cf381c`, §5). |
| 15 | Vettori sintetici + generatore deterministico | **OK** | Ispezione: ogni segreto derivato via SHA-256 da label `STYX-VAULT-TEST-ONLY … v1`; plaintext campione = preferenze UI fittizie; nessun dato reale nei 5 JSON (grep su pattern di chiavi/mnemonic/email: nulla). `generate.js` eseguito **due volte** dal revisore: `sha256sum` dei 5 JSON identico a prima e tra le due run (`diff` vuoti, repo pulito dopo). Nessuna fonte di casualità o clock nel generatore. |
| 16 | Assenza dal bundle | **OK** | `npm run build` in `apps/chat` eseguito dal revisore; `grep -rl 'styx-vault-wrapper\|VAULT_WRAPPER_INVALID\|styx/vault/identity/v1' dist/` → nessun match; grep esteso (`VAULT_RECORD_CORRUPTED`, `VAULT_WRONG_PASSWORD`, `styx-vault-v1`, `styx/vault/`) → nessun match. Nessun import dei 5 moduli vault da `styx-js/src/` né da `apps/chat/src/` (grep). Step CI anti-bundle presente nel diff di `styx-js-web.yml`. |
| 17 | No storage, no worker | **OK** | `grep -nE 'indexedDB\|localStorage\|sessionStorage\|Worker\|postMessage\|navigator\|console\.'` sui 5 moduli src: zero usi (solo due commenti descrittivi "no IndexedDB, no localStorage"). |
| 18 | Nessuna nuova dipendenza runtime | **OK** | `git diff 9344985..277a671 -- styx-js/package.json styx-js/package-lock.json` → 0 righe; `fast-check` già devDependency alla base (`git show 9344985:styx-js/package.json`). |
| 19 | Nessun materiale sensibile in log/errori | **OK** | Nessun `console.*` nei moduli (voce 17); messaggi d'errore statici verificati dalle probe (voci 13/14); l'unico contenuto variabile è il NOME di un campo/namespace in `details` (≤ 64 char, mai valori). |
| 20 | Riesecuzione suite | **OK** | `node --experimental-vm-modules node_modules/.bin/jest test/storage/vault-wrapper.test.js test/storage/vault-record.test.js test/crypto/vault-keys.test.js --forceExit` → 3 suite, **66/66 pass** (inclusa l'integrazione con il vero artefatto styx-kdf-wasm). `PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu24.04-x64 npx playwright test -c playwright.vault.config.js` → **2/2 pass** (Chromium 95 ms, Firefox 517 ms). |

## 2. Finding

| ID | Severità | Dove | Finding | Risoluzione proposta | Stato |
|---|---|---|---|---|---|
| F1 | Minor | `vault-errors.js` (via `vault-wrapper.js:66`, `vault-record.js:68`) | Un campo sconosciuto con nome > 64 caratteri fa fallire la COSTRUZIONE dell'errore tipizzato: `assertDetailsAllowed` lancia `TypeError: VaultCryptoError details value for "field" is not a short primitive` invece di `VaultCryptoError(VAULT_WRAPPER_INVALID/RECORD_INVALID)`. Dimostrato con probe (wrapper con campo `'x'.repeat(65)`). Il fail-closed regge (si lancia comunque), ma il contratto dell'errore tipizzato si rompe: un chiamante che filtra su `e instanceof VaultCryptoError` o `e.code` vedrebbe un `TypeError` non gestito. | Troncare il nome prima di metterlo in `details` (`{ field: String(key).slice(0, 64) }`), come già fatto per `reason` con `e.message.slice(0, 64)` nel ramo KdfBoundsError. | **risolto (commit `6cf381c`)** — verificato dal revisore, vedi §5 |
| F2 | Minor | `vault-wrapper.js:308-327` (`unwrapSyntheticRootKey`) | TOCTOU: dopo `validateVaultWrapper(wrapper)` la funzione attraversa `await importKek(kek)` e poi RILEGGE `wrapper.wrapNonce`/`wrapper.wrappedRootKey` e i campi AAD dall'oggetto del chiamante. Probe: mutando `wrapper.wrapNonce` in un `Uint8Array(13)` subito dopo la chiamata (gap del microtask), il nonce da 13 byte HA RAGGIUNTO `subtle.decrypt` (errore assorbito in `VAULT_WRONG_PASSWORD`); una Proxy con descrittori-dato può analogamente scambiare i valori tra le due letture (`wrapNonce` letto 2 volte). Contraddice l'invariante dichiarato in testa al modulo ("validation completes BEFORE … WebCrypto could ever be reached with out-of-shape values"). Impatto pratico nullo nel threat model PR‑2 (input da structured clone; serve un attaccante già nello stesso realm JS) e il percorso resta fail-closed — ma `parseVaultWrapper` esiste esattamente per questo e non viene usato. | In `unwrapSyntheticRootKey`, operare su una copia profonda congelata: `const w = parseVaultWrapper(wrapper);` e usare `w` per AAD e decrypt. Stesso irrobustimento (gratuito) valutabile per coerenza in `buildWrapperAad`. `decryptVaultRecord` NON ha il gap (letture sincrone nello stesso tick della validazione). | **risolto (commit `6cf381c`)** — verificato dal revisore, vedi §5 |
| F3 | Info | `vault-record.js` / `vault-wrapper.js` (API encrypt/wrap) | Le API di scrittura ignorano silenziosamente le proprietà sconosciute dei loro oggetti input (probe: `nonce`/`iv`/`wrapNonce` extra ignorati, nonce interno comunque casuale) — asimmetria con la validazione strict dei formati letti. Il nonce NON è comunque iniettabile; solo una questione di coerenza d'interfaccia. | Facoltativo: rifiutare chiavi sconosciute anche negli input di `encryptVaultRecord`/`wrapSyntheticRootKey`. | aperto (accettabile) |
| F4 | Info | `vault-record.js:269` | Il payload autenticato ma non decodificabile (UTF-8/JSON) produce `VAULT_RECORD_CORRUPTED` con messaggio DIVERSO (`authenticated payload is not decodable` vs `record authentication failed`). Il codice è uniforme e il ramo è raggiungibile SOLO con la chiave giusta (post-autenticazione GCM), quindi non è un oracolo di password/corruzione; distingue però due stati interni nel messaggio. | Facoltativo: unificare il messaggio, o registrare esplicitamente che i messaggi (a differenza dei codici) non sono superficie UI. | aperto (accettabile) |
| F5 | Info | `vault-keys.js:51-55` | `hkdfSalt()` memoizza la promise del digest: se il primo `subtle.digest` fallisse (ambiente degradato), la promise rigettata resta in cache per sempre e ogni derivazione successiva fallisce anche a ambiente ripristinato. Solo robustezza, nessun impatto di sicurezza. | Facoltativo: azzerare la cache su rejection (`saltPromise = null` nel catch). | aperto (accettabile) |
| F6 | **Important** | `vault-wrapper.js` / `vault-record.js` (validazione shape su `a0997dc`) | Bypass accessor/non-enumerable: la validazione strict usava `Object.keys`, che vede solo le proprietà STRING ENUMERABILI — chiavi Symbol e campi extra non-enumerabili passavano inosservati, e un campo OBBLIGATORIO definito come accessor (anche non-enumerabile, anche throwing) superava il check di shape con INVOCAZIONE del getter ostile (side effect ed eccezioni native non tipizzate raggiungibili dal chiamante). Sollevato al gate utente (NO-GO). | Gate unico `snapshotStrictPlainObject` (`vault-shape.js`): `Reflect.ownKeys`, solo data property enumerabili da allowlist chiusa, Symbol rifiutati, snapshot costruito dai DESCRITTORI (accessor rifiutati senza mai invocarli); i codec usano esclusivamente lo snapshot. | **risolto (commit `dea63a9`)** — verificato dal revisore del terzo round, vedi §6 |
| F7 | **Important** | `vault-keys.js` / `vault-wrapper.js` / `vault-record.js` (su `a0997dc`) | Contratto CryptoKey incompleto: veniva verificato solo `algorithm.name`, quindi AES-GCM-128/192, chiavi extractable, chiavi single-usage e HMAC su hash sbagliato erano accettate come KEK/subkey/manifest key (una HMAC-SHA-1 produceva un MAC di manifest di 20 byte invece dei 32 del contratto). Sollevato al gate utente (NO-GO). | `vault-key-guards.js`: `assertAes256GcmCryptoKey` (secret, AES-GCM, 256 bit, non-extractable, usages esattamente encrypt+decrypt) e `assertHmacSha256CryptoKey` (secret, HMAC-SHA-256, 256 bit, non-extractable, usages esattamente sign+verify), applicati PRIMA di ogni chiamata WebCrypto; guardia esplicita sulla lunghezza del MAC (32 byte) in `signManifestBytes`. | **risolto (commit `1a6ec73`)** — verificato dal revisore del terzo round, vedi §6 |
| F8 | **Important** | `vault-wrapper.js` (`wrapSyntheticRootKey`, su `a0997dc`) | WebCrypto prima della validazione completa: `wrapSyntheticRootKey` chiamava `subtle.importKey` e `crypto.getRandomValues` PRIMA che il wrapper draft fosse interamente validato — metadati invalidi (data impossibile, profilo incoerente, parametri KDF fuori policy) raggiungevano comunque crypto/RNG. Sollevato al gate utente (NO-GO). | Ordine normativo documentato e implementato: shape → draft con placeholder DETERMINISTICI → validazione COMPLETA (`validateVaultWrapper`) → contratto/import KEK → nonce (RNG) → AAD → AES-GCM → validazione dell'output. | **risolto (commit `0e36913`)** — verificato dal revisore del terzo round, vedi §6 |
| F9 | Minor | `docs/superpowers/plans/2026-07-12-styx-vault-implementation-plan.md` (obiettivo PR‑4) | L'obiettivo PR‑4 diceva "schema v1 (9 store)" mentre l'elenco congelato (B3.0.1, spec §8 emendata) ne conta dieci. Incoerenza documentale, nessun impatto sul codice. | Elencare i 10 store per nome nell'obiettivo PR‑4, coerente con §B3.0.1. | **risolto (commit `118f32e`)** — verificato dal revisore del terzo round, vedi §6 |

Nessun finding Critical. I primi due round non avevano rilevato Important; i
tre Important F6–F8 (più il Minor F9) sono stati sollevati al **gate utente**
(NO-GO) sullo stato `a0997dc` e risultano risolti nei commit
`1a6ec73..2ad9504`, ri-verificati attivamente nel terzo round (§6).

## 3. Rischi residui / limiti accettati

1. **Zeroization best-effort** (spec §4, dichiarato nei moduli): JS non
   garantisce la cancellazione fisica dei buffer; `fill(0)` su copie interne e
   salt decodificato è il massimo ottenibile; le subkey vivono solo come
   `CryptoKey` non-extractable.
2. **Replay per-record**: un vecchio record della STESSA chiave/namespace
   ri-autentica (limite dichiarato in spec §1.2; `rv` in AAD mitiga lo swap ma
   non il replay del valore integrale precedente) — fuori scope PR‑2.
3. **`profile` fuori AAD**: legato solo indirettamente via terna
   `(mKib,t,p)` in AAD; oggi la mappa profilo→terna è iniettiva, quindi il
   profilo è di fatto vincolato. Se un profilo futuro condividesse la terna con
   un altro, l'etichetta diventerebbe malleabile (informativa, mai usata per
   derivare — rischio accettato e coerente con la spec).
4. **`createdAt`/`calibratedMs` malleabili** (esclusi dall'AAD by design,
   documentato): metadati informativi, mai fidati.
5. **Vettori "wrapper/record" congelati generati con gli AAD builder di
   produzione** (contratto condiviso, non duplicato — scelta documentata):
   compensato dai vettori standard indipendenti (RFC 5869/4231, GCM NIST)
   verificati come letterali nei test E ri-derivati dal revisore, e dalla
   ri-decodifica di tutte le fixture con WebCrypto grezza e AAD costruite a
   mano in questa review.
6. **Fallback Chromium locale non pinnato** in `playwright.vault.config.js`
   (inerte in CI) — stesso caveat K6 della review PR‑1.
7. **Gate CI anti-bundle temporaneo**: lo step sarà rivisto dalla PR che
   integrerà il vault nell'app; fino ad allora la tripla firma
   (`styx-vault-wrapper`, `VAULT_WRAPPER_INVALID`, `styx/vault/identity/v1`)
   copre wrapper, errori e info string.

## 4. Verdetto

```text
GO
```

Nessun finding Critical o Important nei primi due round (per gli Important
F6–F8 sollevati al gate utente e risolti, vedi §2 e §6). Le 20 voci della checklist risultano
verificate attivamente, i vettori congelati sono stati ri-derivati in modo
indipendente (WebCrypto grezza, AAD a mano) e le proprietà di sicurezza
dichiarate (fail-closed, no oracolo, nonce non iniettabile, separazione dei
domini HKDF, canonicità Base64) reggono alle probe avversariali. I due Minor
del primo round (F1: `TypeError` al posto dell'errore tipizzato su nomi di
campo > 64 char; F2: rilettura del wrapper dopo l'`await` in
`unwrapSyntheticRootKey` invece della copia `parseVaultWrapper`) sono stati
**applicati nel commit `6cf381c` e ri-verificati attivamente dal revisore**
(§5). Restano aperti solo gli Info F3–F5, registrati come accettabili.

## 5. Secondo round — verifica dei fix F1/F2 (HEAD `6cf381c`)

Il commit `6cf381c` ("fix(vault): harden error details and snapshot untrusted
inputs before await") applica F1 e F2. Diff ispezionato (`git diff
277a671..6cf381c`): tocca solo `vault-wrapper.js`, `vault-record.js` e le due
suite (4 test di regressione nuovi); nessun altro modulo, nessuna fixture,
nessuna dipendenza.

Verifica attiva del revisore (probe nuova `probe-f1-f2-fix.mjs`, 15/15 PASS,
con **spy su `SubtleCrypto.prototype.decrypt`** per osservare cosa raggiunge
davvero WebCrypto):

- **F1** — campo sconosciuto da 200 char su wrapper E record (anche come
  accessor): ora `VaultCryptoError` con codice `VAULT_WRAPPER_INVALID` /
  `VAULT_RECORD_INVALID` e `details.field` troncato a esattamente 64 char
  (`key.slice(0, 64)` in entrambi i moduli). La probe del primo round che
  falliva (`65-char … VaultCryptoError (not TypeError)`) ora passa.
- **F2 wrapper** — `unwrapSyntheticRootKey` ora fa `parseVaultWrapper`
  sincrono (validazione + deep copy) prima di ogni `await`: mutando
  `wrapNonce → Uint8Array(13)` e azzerando `wrappedRootKey` subito dopo
  l'avvio della chiamata, lo spy registra **una sola** chiamata a
  `subtle.decrypt` con **iv di 12 byte, byte-identico al nonce originale
  validato** e ciphertext di 48 byte; l'unwrap restituisce la Root Key
  corretta. Il valore mutato non raggiunge più WebCrypto (nel primo round lo
  raggiungeva). La Proxy che scambia il nonce alla seconda lettura fallisce
  in validazione (`VAULT_WRAPPER_INVALID`) con **zero** chiamate a decrypt.
- **F2 record** — `decryptVaultRecord` prende uno snapshot sincrono
  (`v/rv/kv/ct` + `nonce.slice()`/`data.slice()`) post-validazione e lo usa
  anche nei return path: mutando `nonce → 13 byte`, `data.fill(0)` e
  `ct → 'bytes'` dopo l'avvio, il decrypt riesce sul valore snapshottato
  (`value {"a":1}`, `contentType 'json'`) e lo spy vede solo iv da 12 byte.

Riesecuzioni su `6cf381c`: le tre suite jest → **70/70 pass** (66 + 4
regressioni F1/F2); le probe avversariali del primo round
(`probe-wrapper-adversarial.mjs`, `probe-record-keys.mjs`) → tutte PASS,
inclusa la voce prima fallita.

### Verdetto del secondo round

```text
GO
```

F1 e F2 risolti e ri-verificati; nessuna regressione; il verdetto GO è
confermato su HEAD `6cf381c`.

## 6. Terzo round — verifica dei fix F6–F9 (HEAD `2ad9504`)

Round condotto da un **nuovo revisore indipendente a contesto pulito** (non
l'autore, non il revisore dei round 1–2) sul range `a0997dc..2ad9504`
(5 commit: `1a6ec73` contratti chiave, `dea63a9` shape strict, `0e36913`
ordine wrap, `118f32e` conteggio store, `2ad9504` test). Verifica **attiva**:
tre probe nuove scritte dal revisore in `scratchpad/review3-probes/`
(`probe-f6-shape.mjs`, `probe-f7-keys.mjs`, `probe-f8-order.mjs`), con **spy
contatori su `SubtleCrypto.prototype.{decrypt,encrypt,sign,importKey}` e
`Crypto.prototype.getRandomValues`** per osservare che cosa raggiunge davvero
WebCrypto/RNG; mai riusando i test dell'autore.

**F6 — shape strict via snapshot da descrittori (`dea63a9`), probe 17/17 PASS:**

- campo OBBLIGATORIO come getter NON-enumerabile (wrapper `format`) e come
  getter ENUMERABILE (wrapper `createdAt`) → `VAULT_WRAPPER_INVALID` con
  **contatore del getter a 0** in entrambi i casi (mai invocato);
- accessor THROWING (`wrappedRootKey` con `get(){ throw new RangeError }`) →
  `VaultCryptoError`/`VAULT_WRAPPER_INVALID`, il `RangeError` nativo non
  emerge mai (il descrittore è rifiutato senza lettura);
- proprietà Symbol su wrapper e record → `VAULT_WRAPPER_INVALID` /
  `VAULT_RECORD_INVALID` ("symbol properties are not allowed");
- extra SCONOSCIUTO non-enumerabile → rifiutato ("unknown field", `field`
  troncato); campo OBBLIGATORIO come data property NON-enumerabile (wrapper e
  record) → rifiutato ("fields must be enumerable");
- record con `data` getter-backed passato a `decryptVaultRecord` →
  `VAULT_RECORD_INVALID` con getter a 0 e **0 chiamate a `subtle.decrypt`**;
- oggetti a **prototipo null** con soli data field enumerabili validi →
  ACCETTATI (wrapper e record);
- semantica snapshot: output di `parseVaultWrapper` congelato e costruito dai
  valori dei descrittori — mutazione successiva dei buffer e dei campi
  dell'input irrilevante; mutazione ostile nel gap di microtask di
  `unwrapSyntheticRootKey` irrilevante (Root Key fixture ricavata intatta,
  TOCTOU F2 tuttora chiuso).

**F7 — contratti CryptoKey esatti (`1a6ec73`), probe 23/23 PASS (WebCrypto
reale, chiavi generate dal revisore):**

- AES: AES-GCM **128** e **192** bit, AES-GCM-256 **extractable**,
  **encrypt-only**, **decrypt-only**, **usages extra** (wrapKey/unwrapKey),
  **AES-CBC-256**, chiave EC **pubblica** e **privata** (ECDH P-256), oggetto
  **impostore** plain che mima la shape di una CryptoKey → tutti rifiutati
  `VAULT_CRYPTO_FAILED` su `unwrapSyntheticRootKey` + `decryptVaultRecord` +
  `encryptVaultRecord`, con **`subtle.decrypt` = 0 e `subtle.encrypt` = 0** in
  ogni caso;
- HMAC: **SHA-1**, **SHA-384**, **SHA-512**, HMAC-SHA-256 a **512 bit**
  (esplicito E default di `generateKey`), **extractable**, **sign-only**,
  **verify-only** → tutti rifiutati `VAULT_CRYPTO_FAILED` su
  `signManifestBytes` + `verifyManifestBytes` con **`subtle.sign` = 0**;
  verificato che una HMAC-SHA-1 grezza produce davvero un MAC di 20 byte
  (l'hazard originario);
- guardia di lunghezza del MAC attiva: `subtle.sign` dirottato a restituire 20
  byte con chiave CONFORME → `VAULT_CRYPTO_FAILED: unexpected manifest MAC
  length`;
- vettori CONGELATI riprodotti esattamente con chiavi conformi: unwrap del
  wrapper fixture → `rootKeyHex` identico; decrypt del record fixture →
  plaintext identico; HMAC manifest → `macHex` identico (e verifica OK).

**F8 — nessuna crypto/RNG prima della validazione completa (`0e36913`),
probe 16/16 PASS (spy su `importKey`, `encrypt`, `getRandomValues`):**

- KEK invalida (Uint8Array da 31 byte; CryptoKey AES-CBC) →
  `VAULT_CRYPTO_FAILED` con **importKey=0, encrypt=0, getRandomValues=0**;
- ogni caso di metadati invalidi — data impossibile `2026-02-30`, profilo
  incoerente (`desktop` con terna mobile), profilo fuori allowlist, `mKib`
  sopra il massimo (524288) e sotto il floor OWASP (8192), salt da 15 byte,
  `calibratedMs` 600001 e −1 → errore tipizzato atteso
  (`VAULT_WRAPPER_INVALID`/`VAULT_KDF_PARAMS_INVALID`) con **tutti e tre i
  contatori a 0**;
- KEK invalida **E** metadati invalidi insieme → emerge l'errore dei METADATI
  (la validazione precede il passo KEK), contatori a 0;
- controllo positivo: wrap valido → esattamente importKey=1, encrypt=1,
  getRandomValues=1; l'output fa round-trip `encodeVaultWrapper` →
  `parseVaultWrapper` → `unwrapSyntheticRootKey` sulla stessa Root Key; due
  wrap → nonce interni distinti;
- lettura del codice: l'ordine normativo `shape → draft con placeholder
  deterministici → validazione completa → import KEK → nonce → AAD → encrypt
  → validazione output` è commentato e rispettato (`vault-wrapper.js:241-295`).

**F9 — conteggio store (`118f32e`):** l'obiettivo PR‑4 del piano ora elenca i
**10 store per nome** (`meta, identity, contacts, messages, mls, outbox,
push, settings, migrations, canary`, coerente con §B3.0.1); zero occorrenze
residue di "9 store" nel piano.

**Regressioni e invarianza dei formati:**

- diff del range su `vault-aad.js`, `vault-errors.js`, `kdf-bounds.js`,
  fixture e `package.json`/lockfile (root e app): **0 righe** — AAD builder,
  info string HKDF e vettori intoccati;
- `node test/fixtures/vault-crypto-v1/generate.js` eseguito **due volte** dal
  revisore + `git diff --exit-code -- test/fixtures/vault-crypto-v1` →
  fixture byte-identiche (repo pulito dopo);
- regola AAD lato richiesta tuttora vincolante (probe): richiesta `push` su
  record `settings` → `VAULT_RECORD_INVALID` (equality gate); record con `ns`
  auto-dichiarato riscritto per combaciare → `VAULT_RECORD_CORRUPTED` (AAD
  dalla RICHIESTA, mai "riparato");
- nessun percorso rilegge l'oggetto grezzo dopo la validazione: wrapper e
  record operano solo su snapshot/copie congelate (ispezione + probe TOCTOU).

**Riesecuzioni del revisore su `2ad9504`:** le tre suite jest vault → **84/84
pass** (70 del secondo round + 14 regressioni F6/F7/F8 nuove); spec browser
`PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu24.04-x64 npx playwright test -c
playwright.vault.config.js` → **2/2 pass** (Chromium 79 ms, Firefox 518 ms);
`npm run build` in `apps/chat` + grep su `dist/` → **11 firme assenti** (le
tre del gate CI più `VAULT_RECORD_CORRUPTED`, `VAULT_WRONG_PASSWORD`,
`styx-vault-v1` e i NUOVI identificatori `vault-shape`, `vault-key-guards`,
`snapshotStrictPlainObject`, `assertAes256GcmCryptoKey`,
`assertHmacSha256CryptoKey`); zero nuove dipendenze runtime.

### Verdetto del terzo round

```text
GO
```

F6, F7, F8 (Important) e F9 (Minor) risolti e ri-verificati attivamente con
probe indipendenti (56/56 PASS complessivi, contatori spy a zero su ogni
percorso di rifiuto); vettori congelati invariati e riprodotti; suite 84/84 +
2/2; bundle pulito; nessuna regressione introdotta dai fix. Il verdetto GO è
confermato su HEAD `2ad9504`.
