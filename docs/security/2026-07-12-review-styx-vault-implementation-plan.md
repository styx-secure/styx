# Review — Piano di implementazione Blocco 3 "Styx Vault"

Documento sotto review:
`docs/superpowers/plans/2026-07-12-styx-vault-implementation-plan.md`
(Status: Proposed). Review condotta da un revisore **indipendente dalla stesura**
(agente separato, contesto pulito; riferimenti: spec vault post-V1–V7, review
della spec, i tre spike, policy di migrazione MLS, `mls-state-envelope.js`,
`mls-state-migration.js`, chiavi legacy reali del codice). Le risoluzioni sono
state applicate al piano nello stesso branch prima di questo commit.

## 1. Tabella di verifica (checklist del mandato §17)

| # | Voce | Verdetto | Sintesi |
|---|---|---|---|
| 1 | Aderenza completa alla spec | ISSUE Important → **risolto** | Matrice B3.0.1 solida, ma: `push` senza PR di migrazione (P2); store `settings`/`canary` e relative subkey HKDF assenti dall'elenco chiuso e dalla spec §5/§8 (P1); test `offline` mancante dalla matrice (P8). |
| 2 | Ordine delle PR | **OK** | 1→2→3→4→5→6→7→8→9→10 senza usi anticipati; KDF prima del worker, IDB nel worker, canary prima dei dati reali, MLS ultimo. L'inversione worker/crate rispetto a spec §14 è migliorativa. |
| 3 | Dipendenze dichiarate | ISSUE Minor → **risolto** | PR‑12 dipendeva solo da PR‑6 ma gli scenari di migrazione richiedono PR‑7…10 (P9); flag `styx.vault.stage` non assegnato ad alcuna PR (P10). |
| 4 | Nessuna big-bang migration | **OK** | Nessuna PR introduce insieme vault + migrazione dati reali + runtime MLS; PR‑14 (OpenMLS nel worker) è fase separata post-rilascio. |
| 5 | Feature flag | **OK** | Ladder completa, transizioni misurabili, `off→developer-only` reversibile senza toccare dati utente. Criteri "2 cicli"/"2 settimane" da quantificare prima di `limited-alpha` (rischio residuo 2). |
| 6 | Rollback | ISSUE Minor → **risolto** | Classi assegnate a ogni PR, unica R4 = PR‑13 con nuova autorizzazione; mancava la legenda R0–R4 (P6). L'onestà delle classi R2 dipendeva da P4, risolto. |
| 7 | Crash consistency | **OK** | Crash table completa con fonte di verità unica per riga; switch legacy→vault a `verified`; re-wrap coperto passo-passo in PR‑5. |
| 8 | Root Key lifecycle | ISSUE Important → **risolto** | §16.1 completo ma DESTROYING contraddiceva spec §12 e lasciava i passi IDB senza esecutore dopo il terminate (P3). |
| 9 | KDF bounds | **OK** | Validazione integrale prima dell'allocazione, harness anti-allocazione; il validatore era collocato in tre punti diversi (P7, risolto: modulo unico `kdf-bounds.js`). |
| 10 | Worker boundary | **OK** | §16.2 enumera cosa attraversa e cosa mai (Root Key, KEK, subkey, oggetti WASM, wrapper decifrato); coerente con spec §9, limite V10 sulla password riconosciuto. |
| 11 | Nonce/AAD | **OK** | Invarianti portate nei test (property di unicità nonce, AAD tampering, fonte AAD dalla richiesta); replay per-record correttamente documentato come limite, non promessa. |
| 12 | Migrazione MLS | **OK** | Ultimo namespace importante; codec invariato e unico validatore; restore probe reale prima di `verified`; localStorage fonte di verità; mapping §10.1 con `payloadSha256`. |
| 13 | Factory reset | ISSUE Important → **risolto** | PR dedicata e distinzione logica/crittografica/fisica ✓; ordine con terminate al passo 2 senza esecutore per i passi IDB (P3). |
| 14 | Gate mobile M1–M5 | ISSUE Minor → **risolto** | Tempi e blocchi dichiarati; M3/M4 non bloccavano `Accepted` in tabella pur bloccandolo nella riga di chiusura e nella spec (P5). |
| 15 | Supply chain | **OK** | Pipeline pinnata identica al crate canonico, `--locked`, doppia build, PROVENANCE+SHA256SUMS, cargo audit/deny, anti-drift, anti-`target/`, digest KDF fuori dall'envelope MLS, hash-wasm mai in produzione. |
| 16 | Stime | **OK** | Tre scenari (21/35/55 giorni di lavoro effettivo), attese separate (review, dispositivi, audit), M1–M5 e PR‑13/14 fuori stima. |
| 17 | Passaggi irreversibili | ISSUE Minor → **risolto** | Identificati (contratti da PR‑5, PR‑13, digest PROVENANCE) ma mancava il cleanup per-namespace (parte di P4). |

Vincoli di progetto: **rispettati** (OpenMLS pin/artefatto/ciphersuite e wire
format intoccati; nessun codice autorizzato dal piano; errori senza payload;
claim "zero-knowledge/serverless" vietate in PR‑12). Scelta di `settings` come
primo namespace: motivata su tutti i criteri (blast radius come criterio
dominante, `push` scartato per lo stato esterno); il criterio `offline` mancava
(P11, risolto). Granularità delle PR: corretta (split 8a/8b e 9a/9b giusti,
nulla da fondere).

## 2. Finding e risoluzioni

| ID | Severità | Sezione | Impatto | Risoluzione | Stato |
|---|---|---|---|---|---|
| P1 | Important | B3.0.2 / PR‑7 / spec §5–§8 | PR‑4/5 congelano uno schema a 9 store senza `settings`; PR‑7 avrebbe richiesto un upgrade non pianificato o il riuso improprio di subkey (violazione invariante B3.0.5.5). | Elenco chiuso portato a 10 store (`settings` incluso); info string `styx/vault/settings/v1` e `styx/vault/canary/v1` dichiarate come emendamento registrato della spec §5/§8. | Applicato |
| P2 | Important | B3.0.1 / §6 / §15 | `push` elencato tra le sorgenti ma senza PR: dopo PR‑13 la registrazione restava orfana (persa o bloccante). | Decisione motivata: `push` NON si migra, si **ri-crea** (subscription = stato esterno ri-derivabile, endpoint spesso stale) in PR‑9b, con disiscrizione del legacy e test di wake-up post ri-creazione; §15 aggiornata (R1 per push). | Applicato |
| P3 | Important | PR‑11 / §16.1 vs spec §12 | Terminate al passo 2 prima di wrapper/deleteDatabase: il worker è l'unico accesso al DB → passi 3–9 senza esecutore; crash tra terminate e delete senza ripresa definita. | Ordine riallineato: terminate del worker corrente (scarto immediato delle chiavi) + **respawn di un worker fresco in DESTROYING** che esegue i passi IDB; crash tra (2) e (4) → wrapper ancora presente, vault LOCKED, reset ripetibile (idempotente); §16.1/DESTROYING corretto; emendamento della spec §12 registrato (terminate anticipato + respawn dedicato, più forte del wipe del LOCK). | Applicato |
| P4 | Important | §6 / §7 / PR‑7…10 / §16.12–13 | Il contratto ammetteva il cleanup "a `verified`" senza dire in quale stage: un'implementazione letterale l'avrebbe eseguito in `opt-in`, azzerando R2 e la promessa "flag off ripristina il legacy". | Stato `cleaned` raggiungibile SOLO nella fase `legacy-removed` (PR‑13, autorizzazione R4); PR‑7…10 si arrestano a `verified`; cleanup aggiunto ai passaggi irreversibili (§16.13c). | Applicato |
| P5 | Minor | §8 | M3/M4 bloccavano solo `default-on` in tabella, contraddicendo la riga di chiusura e spec §15. | "Accepted" aggiunto alla colonna Blocca di M3 e M4. | Applicato |
| P6 | Minor | §13 / preambolo | Classi R0–R4 mai definite; R3 citata ma inesistente. | Legenda R0–R4 aggiunta in testa a §13. | Applicato |
| P7 | Minor | PR‑1 / PR‑2 / §16.3 | Validatore bounds collocato in tre punti (chiamante JS, `vault-wrapper.js`, worker): rischio di copie divergenti. | Modulo unico `src/crypto/kdf-bounds.js` introdotto in PR‑1, riusato da PR‑2 e PR‑3; harness anti-allocazione rieseguito in PR‑3 sul percorso definitivo. | Applicato |
| P8 | Minor | §9 vs spec §13 | Test `offline` richiesto dalla spec assente dalla matrice del piano. | Riga aggiunta (Playwright, PR‑6). | Applicato |
| P9 | Minor | §15 riga 12 | PR‑12 dichiarava solo la dipendenza da PR‑6 ma gli scenari di migrazione richiedono PR‑7…10. | Dipendenza aggiornata: "6 (core, parallelizzabile) + 7…10 per gli scenari di migrazione/recovery". | Applicato |
| P10 | Minor | B3.0.6 / PR‑3 / PR‑5 | Flag `styx.vault.stage` usato come gate ma non implementato da nessuna PR. | Assegnato a PR‑5 (`src/config/vault-stage.js`), con aggiornamento del test anti-bundle di PR‑3. | Applicato |
| P11 | Minor | PR‑7 | Motivazione di `settings` senza il criterio `offline`. | Frase aggiunta (namespace puramente locale, criterio banalmente soddisfatto). | Applicato |

## 3. Rischi residui accettabili (registrati)

1. Root Key transitoriamente in memoria nell'istante finale di UNLOCKING (solo
   come esito dell'unwrap riuscito — riformulato in §16.1): inevitabile.
2. Criteri di transizione "2 cicli"/"2 settimane di uso dev" non quantificati
   formalmente: accettabile per gli stage di sviluppo, **da quantificare prima di
   `limited-alpha`**.
3. RK1–RK8 del risk register del piano e i residui della review della spec
   (rollback di profilo non prevenibile, zeroization best-effort, nessun lockout
   password, metadati IDB visibili, bound nonce legato al volume, parametri
   mobile provvisori): coerentemente riportati.
4. Replay per-record non rilevato: correttamente trasformato in test che
   documenta il limite, non in falsa garanzia.

## 4. Verdetto

Verdetto del revisore indipendente: **GO WITH CONDITIONS** — condizioni = P1,
P2, P3, P4.

**Le quattro condizioni sono state applicate** al piano nello stesso branch
(più i minor P5–P11, raccomandati). Il piano emendato non contiene big-bang
migration, ha ordine e dipendenze corretti, crash table con fonte di verità
unica, MLS per ultimo con restore probe reale, supply chain rigorosa e stime
oneste.

```text
GO
```

Il piano `2026-07-12-styx-vault-implementation-plan.md`, nella versione presente
in questo branch, è idoneo come base di esecuzione del Blocco 3. Resta inteso
che: non autorizza alcuna implementazione; ogni PR richiede autorizzazione
separata; PR‑13 (R4) richiede una nuova autorizzazione esplicita; M1–M5 bloccano
`Proposed→Accepted`, il supporto dichiarato iOS/Android, `default-on`, la
migrazione automatica generalizzata e il Public Alpha Readiness gate.
