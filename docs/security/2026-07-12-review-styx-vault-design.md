# Review di sicurezza — Styx Vault Design (Blocco 3)

Documento sotto review: `docs/superpowers/specs/2026-07-12-styx-vault-design.md`
(Status: Proposed). Review condotta da un revisore **indipendente dalla stesura**
(agente separato, contesto pulito, accesso a: spike IndexedDB/Crypto Worker/Argon2id,
policy di migrazione MLS, spec envelope v1, `mls-state-envelope.js`,
`mls-state-migration.js`). Le risoluzioni in coda sono state applicate alla spec
nello stesso branch (`docs/vault-design`) prima di questo commit.

## 1. Tabella di verifica (checklist obbligatoria del mandato)

| # | Voce | Verdetto | Sintesi |
|---|---|---|---|
| 1 | Separazione OpenMLS/KDF | **OK** | §2.1 recepisce la decisione dello spike: `styx-kdf-wasm` separato, motivato col pin `wasmArtifactSha256` dell'envelope v1; toolchain pinnata, `Cargo.lock`, PROVENANCE, lifecycle separato, monorepo. Crate canonico intatto. |
| 2 | Parametri KDF bounded | **OK** | §7.1: wrapper trattato come input non fidato pre-sblocco; vincoli esatti su kdf/versione/salt/outLen/p, intervalli su mKib (floor OWASP 19456) e t, allowlist di profili e combinazioni, rifiuto fail-closed senza derivazione; `profile`/`calibratedMs` informativi. Completezza dei campi non-KDF → era V1, risolto. |
| 3 | Root Key lifecycle | **OK** | §4: 32 B casuali nel worker, mai derivata dalla password, mai in chiaro a riposo, solo memoria worker in UNLOCKED; §7.2 re-wrap senza cambiare la chiave né ri-cifrare; zeroization dichiarata best-effort con vincolo sulla UI. |
| 4 | Nonce strategy | **OK** | 96 bit casuali a ogni scrittura, chiavi per-namespace; a 10⁶ scritture/chiave la probabilità di collisione ≈ n²/2⁹⁷ ≈ 2⁻⁵⁷, ampiamente sotto il bound NIST SP 800-38D; il test §13 è una regressione anti-nonce-fisso, non una prova statistica. |
| 5 | AAD | ISSUE Important → **risolto** | V2/V5: fonte dell'AAD in lettura non specificata (rischio di ricostruzione dai campi auto-dichiarati che annulla l'anti-swap), serializzazione canonica non pinnata, naming `schemaVersion`/`v` incoerente, rollback per-record non dichiarato. |
| 6 | Worker protocol | **OK** | Allowlist chiusa, validazione runtime, payload cap, W-F3 recepito, transferable, codici stabili + details allowlistati. Origin guard vacuo su dedicated worker → era V11, risolto (riformulato come non-controllo). |
| 7 | Migrazione | ISSUE Important → **risolto** | Disciplina corretta (fail-closed, localStorage fonte di verità, re-read+confronto, ripresa idempotente), ma: contenuto dei backup in `migrations` non specificato rispetto alla cifratura (V3) e ripresa attribuita a RECOVERING che gira senza chiavi (V4). |
| 8 | Crash consistency | **OK** | §8 incorpora F1/F3/F4/F5/F6/F8 e P3/P4 dello spike: `oncomplete`, durability strict, niente await esterni, kill-mid-transaction, upgrade abort, auto-close, retry bounded, `persist()` bounded. |
| 9 | Recovery | **OK** | §11: tutti gli scenari richiesti con comportamento definito e non distruttivo; record corrotto mai cancellato automaticamente; password errata senza lockout manipolabile; wrapper incompatibile con pattern `MLS_STATE_INCOMPATIBLE`. |
| 10 | Factory reset | ISSUE Minor → **risolto** | Ordine corretto (wrapper prima dei ciphertext) e copertura completa; "il wrapped Root Key smette di esistere" sovrastimava (nessuna cancellazione fisica fino a compaction) — V8, riformulato. |
| 11 | Compatibilità StorageProvider Dart | ISSUE Minor → **risolto** | Tesi plausibile ma dipendente dalla canonicalizzazione esatta dell'AAD (V5) — ora pinnata (array JSON a ordine fisso, UTF-8, naming risolto). |
| 12 | Nessuna promessa irrealistica | ISSUE Minor → **risolto** | Documento nel complesso onesto (rollback "rilevabile non prevenibile", zeroization best-effort); sbavature: wording §12 (V8), leak dei metadati delle chiavi IDB non dichiarato (V7), password non zeroizzabile non dichiarata (V10) — tutte risolte in §1.2/§12. |

Nessuna violazione dei vincoli di progetto rilevata: pin/artefatto/ciphersuite
OpenMLS intatti, wire format intatto, localStorage fonte di verità fino a verifica,
errori senza payload/chiavi/stato, nessuna claim "zero-knowledge/serverless".

## 2. Finding del revisore e risoluzioni

| ID | Severità | Finding (sezione) | Risoluzione applicata |
|---|---|---|---|
| V1 | Important | §7.1 vincolava solo i campi KDF: `format`, `version`, `wrapAlg`, lunghezze di `wrapNonce`/`wrappedRootKey`, `keyVersion`, `rewrapPending`, `createdAt` non validati — un wrapper manipolato poteva raggiungere WebCrypto/memoria con valori fuori forma. | Tabella §7.1 estesa a TUTTI i campi con vincoli esatti (incluso `rewrapPending` = null o wrapper che supera l'intera tabella); validazione completa prima di toccare Argon2id/WebCrypto; nessun campo sconosciuto ammesso. |
| V2 | Important | Fonte dell'AAD in lettura non specificata: ricostruirla dai campi auto-dichiarati del record annulla l'anti-swap; `rv` in AAD non previene il replay di un vecchio record della stessa chiave e il limite non era dichiarato. | §6: fonte in lettura vincolante (`ns`/`k` dalla richiesta, `v`/`rv`/`kv`/`ct` dal record) con test dedicato richiesto in §13; §1.2: rollback per-record dichiarato esplicitamente come non rilevato. |
| V3 | Important | `meta`/`migrations` fuori dalla gerarchia §5; contenuto dei "backup temporanei" non specificato: un backup in chiaro dentro IndexedDB riaprirebbe H1 durante una migrazione interrotta. | §5: politica esplicita — `migrations` contiene solo marker/conteggi/digest, MAI payload; il backup pre-verifica È localStorage stesso (fonte di verità fino al passo 6 di §10); nessuna copia dei dati legacy in IDB. |
| V4 | Important | RECOVERING raggiungibile da LOCKED (senza chiavi) ma incaricato della ripresa della migrazione (che richiede cifrare/verificare); transizioni da ERROR e LOCK durante MIGRATING non definite. | §3: RECOVERING limitato a operazioni senza chiavi (commit/scarto re-wrap, ispezione marker); ripresa migrazione in MIGRATING dopo UNLOCK (automatica se manifest pending); aggiunte transizioni ERROR→LOCKED e MIGRATING→LOCKING→LOCKED (passo atomico completa/abortisce, manifest pending); §10 allineato. |
| V5 | Important | Serializzazione canonica dell'AAD non fissata ("ordine di campi fisso, UTF-8" non è una specifica); naming `schemaVersion` (AAD) vs `v` (record); AAD del wrapper non enumerata — implementazioni divergenti = `VAULT_RECORD_CORRUPTED` di massa senza corruzione. | §6: AAD = byte UTF-8 di `JSON.stringify([v, ns, k, rv, kv, ct])`, ordine fisso, interi base 10, naming risolto (`v` = record format version); §7: AAD del wrapper enumerata esattamente (`[format, version, kdf, kdfVersion, mKib, t, p, saltB64, outLen, keyVersion]`); stessa regola per l'HMAC del manifest. |
| V6 | Important | Contraddizione §8 ("envelope scomposto in `state:meta`+`state:payload`") vs §10 ("envelope cifrato com'è"): implementazioni divergenti dei passi 3–4 e rischio di perdere la verifica `payloadSha256` nello split. | Nuova §10.1: mapping esatto scrittura/lettura/verifica — header senza `payload` in `state:meta` (JSON cifrato), byte decodificati in `state:payload` (binario cifrato), stessi PUT in una transazione; in lettura ricalcolo `payloadSha256` sui byte (mismatch → `MLS_STATE_CORRUPTED`), ricomposizione nel worker, codec unico validatore; §8 rimanda a §10.1. |
| V7 | Important | Chiavi IndexedDB in chiaro (`<contactId>:<seq>`, nome DB): metadato sociale visibile esattamente nello scenario che §1.1 dichiara coperto; la spec non sceglieva tra mitigare e dichiarare. | Decisione presa e registrata in §1.2: leak accettato per il Blocco 3 (i contenuti restano protetti, H1 chiuso), mitigazione designata (chiavi opache HMAC sotto subkey di indice) se i metadati at-rest entreranno in scope. |
| V8 | Minor | §12 "il wrapped Root Key smette di esistere"/"garantisce": una `put` IDB non cancella fisicamente i byte fino a compaction. | Riformulato best-effort; la garanzia reale (residuo protetto da Argon2id + password) esplicitata, coerente con §4. |
| V9 | Minor | `digestB64` del manifest era SHA-256 semplice: chi scrive IDB lo ricalcola — solo anti-corruzione. | Adottato HMAC-SHA-256 sotto `K_manifest` (nuova subkey in §5): tampering rilevabile post-sblocco; pre-sblocco il manifest resta non fidato e nessuna decisione di sicurezza vi si appoggia. |
| V10 | Minor | Password come stringa JS immutabile: non zeroizzabile, copie nel form/main thread/structured clone; limite non dichiarato. | Dichiarato in §1.2 accanto al limite di zeroization delle chiavi. |
| V11 | Minor | "Origin guard" presentato come misura: su un dedicated worker `event.origin` è vuoto, il guard è vacuo. | §9 riformulato: difesa in profondità/CodeQL, non un controllo; la difesa reale è allowlist + validazione runtime. |
| V12 | Minor | Accesso dei reader multi-tab sottospecificato (ogni tab un worker → N copie delle chiavi?). | §8: nel Blocco 3 accesso single-tab (solo la tab col Web Lock apre il vault; le altre restano "sessione attiva in un'altra scheda" come oggi); nessun reader concorrente. |

## 3. Rischi residui accettati (registrati)

1. **Rollback completo del profilo non prevenibile** (nessun monotonic counter
   hardware sul web); rilevazione solo se sopravvive un riferimento esterno
   (§1.2/§11).
2. **Zeroization best-effort** di chiavi e password (limite di piattaforma JS/WASM,
   §1.2/§4).
3. **Browser/OS/estensione compromessi a vault sbloccato**: fuori scope (§1.2).
4. **Eviction/quota**: `persist()` advisory (F8); in private browsing il vault è
   effimero — perdita di disponibilità, non di confidenzialità; conferma in M4.
5. **Bound dei nonce legato al volume**: nessun contatore enforced; margine di molti
   ordini di grandezza sul bound NIST + regressione in §13.
6. **Parametri mobile provvisori** fino a M5 (incluso il limite di memoria WASM su
   iPhone per il profilo `desktop`) — condizione dello Status: Proposed.
7. **Nessun lockout sui tentativi di password** (scelta deliberata: un contatore
   persistito sarebbe manipolabile): la resistenza offline è interamente
   Argon2id + qualità della password; da riflettere nella UX di scelta password.
8. **Metadati strutturali at-rest visibili** (chiavi record, conteggi, nome DB) —
   accettato per il Blocco 3 con mitigazione designata (V7, §1.2).

## 4. Verdetto

Verdetto del revisore indipendente: **GO WITH CONDITIONS** — condizioni = fix
puntuali V1–V7 prima di usare la spec come base del piano di implementazione.

**Le sette condizioni sono state applicate** al documento nello stesso branch (più i
minor V8–V12, raccomandati e non bloccanti). Restano vincolanti, come scritto nella
spec: completamento di M1–M5 prima di Proposed→Accepted; nessuna dichiarazione di
supporto iOS/Android prima delle prove reali.

```text
GO
```

La spec `2026-07-12-styx-vault-design.md`, nella versione presente in questo branch,
è idonea come base del piano di implementazione del Blocco 3. Questo documento non
autorizza l'implementazione del vault.
