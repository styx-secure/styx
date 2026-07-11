# Styx Chat — Fattibilità del piano di hardening (`docs/piano-utente.md`)

**Data:** 2026-07-11 · **Branch:** `feature/pwa-push-bridge` · **Metodo:** verifica del piano contro il codice (`styx-js/`), la storia git (67 commit) e il crate WASM vendorizzato (`styx-js/vendor/openmls-wasm/`), incrociata con il security report `docs/security/2026-07-10-styx-chat-security-report.md`.

> ### Rettifica del 2026-07-11 (in fase di esecuzione del Blocco 1)
>
> La prima versione di questo documento affermava che il pin OpenMLS `09e9277` fosse
> **precedente ai fix dell'audit SRLabs**, e prescriveva di aggiornarlo (§3.1 punto 2, §5
> Blocco 1 punto 2). **L'affermazione era falsa.** Verificato all'esecuzione:
>
> - il pin (2026-07-08) è **discendente del tag `openmls-v0.8.1`** (2026-02-13): 76 commit
>   avanti, **0 indietro**;
> - il fix **S3-7** (High, CWE-354) è **presente nel sorgente al pin**: `equal_ct` in
>   `openmls/src/ciphersuite/mod.rs` esegue il controllo di lunghezza che in v0.7.0 mancava
>   (senza il quale un MAC troncato risultava uguale, perché `zip` si ferma al più corto).
>
> **Conseguenza:** nessun bump. Aggiornare al tag v0.8.1 sarebbe stato un **downgrade** di 76
> commit e avrebbe **rotto il formato di storage MLS persistito** (PR #2034, presente al pin e
> assente in 0.8.1). Il requisito 2 del Blocco 1 diventa *verificare e documentare* il pin, non
> aggiornarlo — vedi `styx-js/vendor/openmls-wasm/PROVENANCE.md`.
>
> **Rischio residuo, che resta reale:** il pin è un commit di `main` **non rilasciato**; quei
> 76 commit non appartengono ad alcuna release pubblicata né rientravano nell'audit. Follow-up:
> spostare il pin al primo tag upstream che discenda da questo commit.
>
> Il punto 3 di §0 (il crate come critical path) **non cambia**: resta valido per
> `StorageProvider`, commit ack-gated, fork detection e multi-device.

---

## 0. Verdetto

**Il piano è tecnicamente fondato e fattibile. Otto delle dieci affermazioni fattuali sul codice sono pienamente confermate e due sono confermate parzialmente** (push bridge: cieco sui contenuti ma registra `pubkey → subscription`; CSP: parziale, non assente).

**Il punto che modifica il critical path dell'intero progetto:** diverse attività che il piano tratta come lavoro JavaScript richiedono in realtà **modifiche al crate Rust/WASM vendorizzato** — `StorageProvider`, merge dei commit MLS subordinato agli ACK, esposizione di epoch/group context/tree hash, fork detection, multi-device. Il crate diventa il collo di bottiglia: ogni blocco MLS successivo dipende da API oggi non esposte.

Il documento distingue esplicitamente quattro categorie epistemiche (tabella completa in §7.3):
- **Fatti verificati direttamente nel codice** (con riferimenti file:riga);
- **Inferenze architetturali** (conseguenze logiche dei fatti, non osservate direttamente);
- **Stime di sviluppo** (giudizio esperto, non misure);
- **Rischi da validare con prototipi** prima di confermare le stime.

## 1. Verifica delle affermazioni del piano

| # | Claim del piano | Verdetto | Evidenza |
|---|---|---|---|
| 1 | Fallback automatico a `MockStyxChat` | **CONFERMATO** | `apps/chat/src/lib/styx-adapter.js:20-29`; il mock auto-semina 4 contatti demo, safety number non crittografico |
| 2 | Backend default `localStorage`, MLS e messaggi in chiaro | **CONFERMATO** | `src/chat/styx-chat.js:34-39,497,502-505`; solo la chiave identità è cifrata (PBKDF2 210k). `indexeddb-store.js` esiste ma non usato dalla chat |
| 3 | `publish()` senza attendere `OK` NIP-01 | **CONFERMATO** | `nostr-transport.js:58-68` fire-and-forget; `sent` anche con 0 relay connessi. `OutboxWorker` (`failover.js:167`) serve solo il ledger |
| 4 | Nessun coordinamento multi-tab | **CONFERMATO** | Zero `navigator.locks`; ogni tab ri-persiste il blob MLS dopo ogni operazione |
| 5 | Factory reset finto | **CONFERMATO** | `App.jsx:67-74` rimuove solo la chiave del mock; identità reale, stato MLS, messaggi, roster restano |
| 6 | Push bridge da rifare | **PARZIALE** | Bridge costruito, payload vuoto, notifica generica (`sw.js:13-17`) **ma** registra `pubkey → [subscription]` (`push_bridge/src/registry.js:9,23-27`): il handle anonimo del piano non esiste |
| 7 | CSP/Trusted Types/SRI assenti | **PARZIALE** | `static-server.mjs:24-29`: CSP parziale (object-src, base-uri, frame-ancestors) + nosniff/referrer/XFO; mancano script-src/connect-src/default-src, Trusted Types, SRI |
| 8 | Crypto sul main thread | **CONFERMATO** | `mls-engine.js` chiama il wasm inline; nessun Worker |
| 9 | QR senza scadenza temporale | **CONFERMATO** | Nonce monouso presente (A2) ma nessun TTL |
| 10 | Funzioni stub esposte | **CONFERMATO** | Pairing remoto lancia `not implemented` con UI completa (`PairingModal.jsx:135-226`); WebRTC non cablato; backup assente; presenza solo mock |

Note a favore della fattibilità: `src/crypto/spake2.js` e `RemotePairingService` (`src/pairing/trust-store.js:183-230`) esistono già non cablati; il codebase Dart (`packages/`, ~25k LOC) contiene SPAKE2/Shamir/rekey testati ma è un'implementazione parallela non collegata alla PWA.

## 2. Lavoro già completato (da scontare dal piano)

| Già fatto | Commit | Copre |
|---|---|---|
| Verifica firma+id eventi Nostr inbound (A1) | `d0a4462` | prerequisito Fase 4 |
| Welcome legato a nonce QR monouso, HMAC constant-time (A2) | `4be65e6` | metà Fase 9.1 |
| No sovrascrittura sessione MLS (A3 + fix scanner-side) | `4d5564d`, `bfb65e0` (review H1) | peer malevolo, parte |
| Pairing esplicito + alias dentro MLS (A4) | `f34d007` | Fase 9 |
| Safety number da export secret MLS (A5) | `3790300` | Fase 9.3 (mancano QR reciproco, cronologia, avviso bloccante) |
| Blocco trasporto non autenticato (A6) | `82b09be` | Fase 0.2 parziale |
| Password change su `EncryptedKeyStore` | pre-esistente | Fase 10 parziale (da rifare sul nuovo vault) |
| Push bridge cieco sui contenuti, registrazione firmata | serie fino a `da59ff1` | Fase 8 ≈ 60% |
| Piano di hardening del crate vendorizzato (N1, N2, pin, riproducibilità) | doc `docs/superpowers/plans/2026-07-11-blocco1-wasm-hardening.md` | il Blocco 1 |

Vulnerabilità del security report ancora aperte e mappate al piano: **H1** (storage in chiaro → Blocco 3), **H2** (metadati → Blocco metadati pre-audit), M4/M5/M6, N1–N4, R1–R6. Nessuna vulnerabilità aperta risulta non mappata.

## 3. Correzioni strutturali al piano (approvate)

### 3.1 Nuova Fase 0.5 — Hardening Rust/WASM (prerequisito di tutto il lavoro MLS)

1. Eliminazione di tutti gli `unwrap()`/`expect()` raggiungibili da input di rete (oggi: `patch/lib.rs:319` `tls_deserialize(..).unwrap()` su bytes del relay → trap; più `:172,240,329-331,450,477,494`);
2. ~~aggiornamento OpenMLS a versione post-audit supportata (pin attuale `09e9277` pre-audit)~~ → **rettificato:** il pin porta già i fix (S3-7 verificato nel sorgente). Il requisito diventa *verificare e documentare* il pin in `PROVENANCE.md`, incluso il rischio residuo di stare su `main` non rilasciato. **Non aggiornare** al tag v0.8.1: sarebbe un downgrade e romperebbe il formato di storage persistito. Vedi la rettifica in testa al documento;
3. aggiunta di `clear_pending_commit` e delle API mancanti;
4. esposizione controllata di epoch, group context, tree hash e dati per la fork detection (oggi il wasm non espone nulla di tutto ciò — unico valore confrontabile: exporter secret);
5. pin della toolchain Rust (oggi `rust:latest`);
6. pin di `wasm-pack`;
7. aggiunta e commit di `Cargo.lock` (oggi assente: dipendenze transitive non riproducibili);
8. build riproducibile;
9. riconciliazione README ↔ ciphersuite compilata (README dichiara AES-128-GCM, il sorgente compila ChaCha20-Poly1305, `patch/lib.rs:29`);
10. test con ciphertext, Welcome e commit malformati.

Ulteriore fatto a supporto: istanza wasm e `Provider` unici per tutti i contatti (`mls-engine.js:95-97`) — un trap è un failure domain dell'intera app e lo stato corrotto viene persistito dopo ogni operazione.

### 3.2 Fase 3.1 sdoppiata

**3.1a — Mitigazione immediata:** cifrare il blob MLS completo; cifrare messaggi, contatti e metadati; spostare tutto in IndexedDB; Root Storage Key; migrazione atomica e versionata. Chiude rapidamente la confidenzialità at-rest (H1).

**3.1b — StorageProvider nativo:** persistenza granulare; cancellazione delle chiavi per epoca; transazioni coerenti con OpenMLS; recovery selettivo; riduzione delle riscritture (oggi O(stato-totale) per messaggio); controllo più preciso della concorrenza.

Il blob cifrato risolve la confidenzialità locale ma **non** risolve lifecycle MLS, rollback, cancellazione per epoca e recovery granulare — quelli richiedono 3.1b.

### 3.3 Multi-device come epic separata (non task da 4–8 settimane)

Epic dipendente da: (1) trasporto dei commit MLS sul filo (oggi i commit non viaggiano mai: gruppo 1:1 formato localmente + Welcome); (2) commit pending; (3) ACK del Delivery Service; (4) fork detection; (5) device credential separate; (6) leaf MLS distinta per dispositivo; (7) revoca dispositivo; (8) recovery dopo perdita di un dispositivo; (9) sincronizzazione della cronologia; (10) test con dispositivi concorrenti e offline.

**Stima prudente: 6–16 settimane**, in funzione delle modifiche al crate WASM.

### 3.4 Push handle e mailbox key: progettati insieme, valori distinti

```text
Conversation Transport Secret
   ├── HKDF("nostr-mailbox") → Mailbox Key
   └── HKDF("push-handle")   → Push Handle
```

Requisiti: domain separation; rotazione coordinata; versionamento; revoca indipendente; nessun legame con la chiave identitaria. Il bridge non deve poter associare il push handle alla pubkey permanente (oggi la conosce direttamente: `registry.js:9`).

### 3.5 Argon2id

Valutare **prima di tutto l'implementazione nel crate Rust/WASM già controllato**. Se si usa `hash-wasm`: versione fissata, inclusione in SBOM, test vector, dependency scanning, stessa policy di supply-chain del crate Rust.

### 3.6 Protezione dei metadati anticipata prima dell'audit

Da spostare prima dell'audit finale (target giornalisti/attivisti — un audit su un sistema che espone il grafo sociale ai relay sarebbe incoerente): mailbox key non identitaria; outer key effimera; gift wrapping; ricevute cifrate; typing cifrato o disattivabile; notifiche senza identità; documentazione dei metadati residui. Restano successivi: padding, batching avanzato, key transparency.

Fatti a supporto: ogni evento espone il destinatario in tag `p` in chiaro ed è firmato con la chiave identitaria a lungo termine (`nostr-chat-transport.js:70,88-95`); kind 1059 è usato come evento regolare, **senza** gift-wrap NIP-59 né NIP-44 (commento esplicito a `nostr-chat-transport.js:8-9`).

### 3.7 CSP

Verificare **sperimentalmente** se browser e build richiedono `'wasm-unsafe-eval'` (non inserirlo automaticamente). Criteri di completamento: app funzionante con CSP attiva; WASM funzionante; nessun `unsafe-inline`; nessun `unsafe-eval`; Trusted Types testato con React/Vite; test automatici anti-regressione.

### 3.8 Due livelli di prodotto (la nativa non è "automaticamente sicura")

- **PWA hardened**: uso generale; E2EE; vault cifrato; supply chain controllata; garanzie e limiti documentati.
- **Native High-Assurance**: Android/iOS/desktop firmati; Keystore/Keychain/TPM; aggiornamenti firmati; codice installato localmente; **threat model proprio e audit separato**; minore rischio di sostituzione dinamica del JavaScript.

## 4. Stime

Le stime comprendono: sviluppo, test, migrazioni, documentazione, compatibilità browser, revisione interna e correzioni post-audit. Il **costo dell'audit** va indicato separatamente dal costo delle **correzioni richieste dall'audit** e dell'eventuale **retest**.

| Voce | Stima |
|---|---|
| Blocco 1 (WASM) | 2–4 settimane |
| Blocco 2 (riduzione rischio) | ~2 settimane |
| Blocco 3 (vault minimo) | 3–5 settimane |
| Blocco 4 (trasporto affidabile) | 2–4 settimane |
| Blocco 5 (evoluzione MLS, esclusa epic multi-device) | 4–8 settimane |
| Epic multi-device | 6–16 settimane |
| Metadati pre-audit | 2–4 settimane |
| Audit esterno | 30–80 k€ (fee), 4–8 settimane calendario; correzioni + retest a parte |

**Scenari fino a "beta auditabile":**

| Scenario | Beta auditabile |
|---|---:|
| Ottimistico | 5–7 mesi |
| Probabile | 7–10 mesi |
| Prudenziale | 10–14 mesi |

## 5. Ordine operativo approvato

### Blocco 1 — Emergenza WASM
1. eliminazione dei panic da input; 2. ~~aggiornamento OpenMLS~~ → **verifica e documentazione del pin** (vedi rettifica in testa: il pin porta già i fix dell'audit; aggiornarlo sarebbe un downgrade); 3. pin toolchain; 4. `Cargo.lock`; 5. build riproducibile; 6. correzione doc ciphersuite; 7. test con input malevoli.

### Blocco 2 — Riduzione immediata del rischio
1. eliminazione del mock dalla build production; 2. disabilitazione stub; 3. factory reset reale; 4. Web Locks; 5. CSP e header; 6. correzione copy "serverless"; 7. test CI che blocchi la presenza del mock.

### Blocco 3 — Vault minimo sicuro
1. IndexedDB; 2. Root Storage Key; 3. wrapping con Argon2id; 4. cifratura blob MLS; 5. cifratura messaggi/contatti/metadati; 6. migrazione atomica; 7. protezione rollback; 8. test crash-consistency; 9. test quota piena; 10. recovery.

### Blocco 4 — Affidabilità del trasporto
1. ACK NIP-01; 2. outbox persistente; 3. retry e backoff; 4. stati reali di invio; 5. deduplicazione; 6. funzionamento offline; 7. ricevute cifrate.

### Blocco 5 — Evoluzione MLS
1. pending commit; 2. merge solo dopo ACK; 3. fork detection; 4. StorageProvider granulare; 5. rekey; 6. multi-device (epic).

## 6. Modalità di implementazione

Non implementare P0–P2 in parallelo. Per ogni blocco: issue separate, dipendenze, acceptance criteria, test obbligatori, rollback plan, file coinvolti, rischi, eventuali modifiche al protocollo, commit piccoli e revisionabili. **Review architetturale al termine di ogni blocco prima del successivo.**

## 7. Appendici

### 7.1 Diagramma delle dipendenze

```text
Blocco 1 (WASM) ────────────┬──► Blocco 5 (evoluzione MLS) ──► Epic multi-device
                            │
Blocco 2 (rischio) ──► Blocco 3 (vault) ──► Blocco 4 (trasporto) ──► Blocco 5
        (Web Locks del Blocco 2 è prerequisito della migrazione del Blocco 3)

Blocco 4 ──► Metadati pre-audit (mailbox/push handle, gift wrap) ──► Audit esterno
Blocco 1.4 (epoch/context API) ──► fork detection (Blocco 5.3) ──► multi-device
```

### 7.2 Critical path

`Blocco 1 → Blocco 3 → Blocco 4 → Blocco 5 → epic multi-device → metadati → audit`. Il crate WASM compare due volte sul percorso (Blocco 1 e Blocco 5): ogni ritardo lì si propaga all'intero progetto.

### 7.3 Tabella fatti / inferenze / stime / rischi da prototipare

| Categoria | Elementi |
|---|---|
| **Fatti verificati** | tutte le verifiche di §1; API wasm senza `clear_pending_commit` né epoch/tree-hash getter (`openmls_wasm.d.ts`); auto-merge dentro `process_message` (`patch/lib.rs:346-354`); merge ottimistico JS (`mls-engine.js:127`); bridge keyed su pubkey; assenza `Cargo.lock`; mismatch README/ciphersuite; panic path `patch/lib.rs:319` |
| **Inferenze architetturali** | corruzione ratchet multi-tab (dedotta dal codice, non riprodotta con test); failure domain unico per trap wasm; incompatibilità trait storage sincrono ↔ IndexedDB async (richiede cache write-through); necessità di coordinare mailbox key e push handle |
| **Stime di sviluppo** | tutte le durate di §4; costo audit |
| **Rischi da prototipare** | (1) ponte sync/async del StorageProvider: performance e correttezza; (2) necessità effettiva di `'wasm-unsafe-eval'` nella CSP; (3) Argon2id in-crate: tempi/memoria su mobile; (4) durabilità/quota IndexedDB cross-browser (Safari PWA in primis); (5) ristrutturazione di `process_message` per il merge gated senza rompere sessioni esistenti; (6) riproducibilità byte-identica della build wasm; (7) migrazione localStorage→IndexedDB su dataset reali senza perdita |

### 7.4 Scenari temporali
Vedi §4 (ottimistico 5–7, probabile 7–10, prudenziale 10–14 mesi).

### 7.5 Criteri di uscita per priorità

- **P0 (fine Blocchi 1–2):** nessun mock nel bundle production (gate CI); stub disabilitati; reset elimina esplicitamente IndexedDB, `localStorage`, Cache Storage, outbox, stato MLS, sottoscrizione push, eventuali service worker registration e dati temporanei; un solo writer MLS (Web Locks); CSP attiva senza unsafe-inline; copy onesto; pin OpenMLS verificato post-audit e documentato in `PROVENANCE.md` (incluso il rischio residuo di `main` non rilasciato); nessun panic noto raggiungibile da input non fidato, con parser coperti da test negativi, fuzzing e gestione esplicita degli errori; `Cargo.lock` committato.
- **P1 (fine Blocchi 3–4):** nessun dato sensibile in chiaro a riposo; Root Key avvolta con Argon2id; migrazione atomica versionata con protezione rollback; `sent` = almeno un `OK=true`; outbox persistente; lettura/composizione offline; TTL sugli inviti QR; backup identity-only.
- **P2 (fine Blocco 5 + metadati):** il bridge non conserva alcuna relazione applicativa tra identità permanente e subscription (restano possibili correlazioni tramite IP, tempi e volumi di traffico, da documentare come metadati residui); pairing remoto PAKE; update flow sicuro; supply chain completa (SBOM, firma, build riproducibile); gift wrap e mailbox key attivi; audit esterno senza finding critici o alti; correzioni post-audit chiuse e retestate.

### 7.6 Rischi che richiedono prototipazione prima di confermare le stime
Elencati in §7.3, riga "Rischi da prototipare": ciascuno va validato con uno spike a inizio del blocco corrispondente (spike 1–3 giorni, esito documentato) prima di impegnare la stima del blocco.
