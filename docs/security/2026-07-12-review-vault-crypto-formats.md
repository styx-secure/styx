# Review — Formati crittografici puri del vault (Blocco 3, PR‑2)

Oggetto: PR‑2 del piano Blocco 3 ("Formati crittografici puri") — i moduli
`styx-js/src/crypto/{vault-errors,vault-aad,vault-keys}.js`,
`styx-js/src/storage/{vault-wrapper,vault-record}.js`, le suite jest e la spec
browser, i vettori congelati `styx-js/test/fixtures/vault-crypto-v1/`, gli
emendamenti alla spec di design e lo step anti-bundle in CI.

- **Data:** 2026-07-12
- **Revisore:** indipendente dalla stesura (agente separato, contesto pulito)
- **Base:** `9344985` (main) — **HEAD:** `6cf381c` (`feat/vault-crypto-formats`)
- **Scope:** esclusivamente `git diff 9344985..6cf381c` (primo round su
  `277a671`; secondo round di verifica sul fix `6cf381c`, vedi §5)

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

Nessun finding Critical o Important.

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

Nessun finding Critical o Important. Le 20 voci della checklist risultano
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
