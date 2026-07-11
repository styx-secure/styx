# Styx — Panoramica architetturale del progetto

**Snapshot:** 2026-07-11 · **Branch:** `feature/pwa-push-bridge` · **Autore del documento:** review architetturale trasversale su repo, storia git e codice.

Questo documento è la fotografia completa del progetto: cos'è, com'è strutturato, cosa funziona, cosa manca, e una valutazione architetturale d'insieme. È **descrittivo e non normativo** — per la direzione di lavoro vedi `docs/security/2026-07-11-fattibilita-piano-utente.md` (roadmap) e i piani in `docs/superpowers/plans/`.

---

## 0. In una frase

Styx è **due implementazioni parallele e volutamente non interoperabili** di una piattaforma di comunicazione sovrana peer-to-peer: (1) una libreria **Dart** completa per ledger crittografici a catena di eventi, e (2) una **chat E2EE su MLS** in JavaScript con PWA, che è la linea di sviluppo attiva. Condividono la filosofia (nessun server centrale di fiducia, crittografia lato client) ma non il codice né il modello crittografico.

---

## 1. Informazioni sul repository

| | |
|---|---|
| Repository canonico | `github.com/styx-secure/styx` — **pubblico** (dal 2026-07-12) |
| Branch canonico | `main` (SHA baseline migrazione: `8b275bc`) |
| Remote legacy | `github.com/maverde73/styx` (sola lettura, intatto) |
| Commit totali | 94 (+ CI/security baseline PR post-migrazione) |
| Arco temporale | 2026-02-23 → 2026-07-12 (~4,5 mesi) |
| Autore | maverde73 &lt;cirrosi@gmail.com&gt; (unico) |
| Dimensione tracciata | ~6,1 MB (di cui 1,8 MB è l'artefatto WASM vendorizzato) |
| Licenza | vendored OpenMLS: MIT; licenza di progetto **non ancora applicata** (ADR-0004 *Proposta*). Repo "public-source experimental"; contributi esterni sospesi |
| Blocchi | 1 (WASM hardening) ✅ · 2 (riduzione rischio) ✅ · review Blocco 2 **GO** · Fase D envelope MLS ✅ (PR #23, squash `b4f00ac`) |
| CI | `styx-js web` ✅ verde · Dart reference stack ✅ verde (dopo fix baseline) · WASM integrity ✅ · CodeQL (JS/TS) ✅ |
| Sicurezza GitHub | secret scanning + push protection, Dependabot, PVR, CodeQL, ruleset su `main`, SHA-pinning, token read-only (vedi `docs/security/2026-07-12-github-security-baseline.md`) |

**Linguaggi** (file tracciati): 170 Dart · 150 JS · 42 Markdown · 18 YAML · 15 JSX · 11 HTML · 9 Go · 3 shell · 3 MJS · 2 TS.

**Righe di codice per area** (esclusi test, vendor, generati):

| Area | LOC prod | LOC test | Note |
|---|---:|---:|---|
| `packages/` (Dart lib) | ~10.660 | ~11.810 | +2.862 generati (Drift). Test > sorgente. |
| `styx-js/src` (JS lib) | 6.690 | 7.868 | il motore chat MLS + ledger port |
| `styx-js/apps/chat/src` | 2.206 | — | PWA React |
| `push_bridge/` (Node) | 247 | — | bridge push attivo |
| `push_bridge_server/` (Go) | 888 | — | bridge legacy (scaffold) |

**Test complessivi:** 61 file `*_test.dart` + 58 file `*.test.js`. La suite JS è verde (646 test, dopo l'envelope MLS di PR #23); la suite Dart è **verde** dopo il fix della baseline CI (390 test: 135 crypto_core, 76 styx, 69 ledger_engine, 61 transport, 37 storage, 11 push_bridge_client, 1 test_integration; `themis_survey` Flutter escluso dallo stack di riferimento). La coverage Dart è gestita a **baseline non-regressione** per package: il 90% resta un obiettivo, non ancora raggiunto ovunque (storage ~78%, styx ~82%, transport ~85%; gli altri ≥90%).

---

## 2. Struttura del progetto

```text
Styx/
├── packages/                     # ── STACK DART: libreria ledger P2P (Melos workspace) ──
│   ├── crypto_core/              #   Ed25519/X25519, hashing, BIP39, Shamir, SPAKE2
│   ├── storage/                  #   persistenza cifrata Drift/SQLite (eventi, peer, outbox)
│   ├── ledger_engine/            #   catena di eventi hash-linked, HLC, vector clock, merge, pruning
│   ├── transport/                #   Nostr + Email(IMAP/SMTP) + Tor + failover/outbox
│   ├── push_bridge_client/       #   client push Flutter (dummy detection, privacy profiles)
│   ├── styx/                     #   FACCIATA pubblica: SovereignLedger (identità→ledger→trasporto→pairing)
│   └── themis_survey/            #   app Flutter di sondaggi (separata, opzionalmente su Styx)
├── test_integration/             #   generatore di test-vector cross-linguaggio + stub
│
├── styx-js/                      # ── STACK JS: chat E2EE su MLS (LINEA ATTIVA) ──
│   ├── src/
│   │   ├── crypto/               #   identità, KDF, Shamir, SPAKE2, e mls/ (motore OpenMLS)
│   │   ├── chat/                 #   styx-chat.js (il cuore della chat), contact-roster
│   │   ├── transport/            #   Nostr chat transport, RelayPool, WebRTC, BroadcastChannel(dev)
│   │   ├── storage/              #   EncryptedKeyStore, LocalStorageBackend, IndexedDB(inutilizzato)
│   │   ├── pairing/ push/ ledger/ facade/   #   trust-store, push registrar, port del ledger JS
│   ├── apps/chat/                #   PWA React/Vite (UnlockScreen, ChatShell, PairingModal, SW…)
│   └── vendor/openmls-wasm/      #   OpenMLS→WASM vendorizzato (patch Rust, build.sh, verify.sh, PROVENANCE)
│
├── push_bridge/                  #   bridge push Node (Web Push/VAPID) per la chat JS — ATTIVO
├── push_bridge_server/           #   bridge push Go (FCM/APNs) per il client Dart — LEGACY/scaffold
│
├── docs/
│   ├── security/                 #   security report + documento di fattibilità (roadmap normativa)
│   ├── superpowers/plans+specs/  #   piani di implementazione e design spec
│   └── archive/                  #   TASK_00-12, ROADMAP, Blueprint v2 (storici, non normativi)
├── .github/workflows/            #   ci.yml (Dart) + styx-js-web.yml (build+gate PWA)
├── CLAUDE.md · AGENTS.md · README.md
└── pubspec.yaml · analysis_options.yaml · tool/check_coverage.sh
```

---

## 3. I due stack in dettaglio

### 3.1 Stack Dart — la libreria ledger (`packages/`)

Monorepo Melos 7 + Pub Workspaces. **Codice eccezionalmente pulito**: zero `TODO`/`UnimplementedError`/stub reali in tutto `packages/*/lib`. Test comportamentali reali (non mock), più 6 suite property-based con `glados`. Modello crittografico proprietario a **catena di eventi firmati** (non MLS).

| Package | Cosa fa | Stato | Test |
|---|---|---|---|
| **crypto_core** | Ed25519 sign/verify, X25519 ECDH+HKDF, SHA-256 hash-chain, BIP39, Shamir GF(256), SPAKE2 su P-256 | completo | 18 file, 4 property-based |
| **storage** | schema Drift + DAO tipizzati (Events/Peers/Outbox/Config) su SQLite | completo | 6 file, incl. performance |
| **ledger_engine** | eventi hash-linked + prev-hash, HLC, vector clock, merge deterministico, fork detection, pruning GDPR | completo | 12 file, 2 property-based |
| **transport** | 3 trasporti reali (Nostr, Email IMAP/SMTP, decorator Tor) + failover/outbox | completo | 10 file |
| **push_bridge_client** | distinzione push reali vs dummy, profili privacy, orchestrazione wake-up | completo (codice) | **1 file** (breadth debole) |
| **styx** (facciata) | `SovereignLedger`: pairing QR + remoto SPAKE2, transazioni/messaggi/SOS, backup Shamir, re-key/migrazione device | completo | 10 file, 3.872 LOC |

**È un sistema end-to-end reale.** Il test `packages/styx/test/e2e_integration_test.dart` (971 righe, 11 test) prova: due peer che fanno QR-pairing e scambiano 100 transazioni con catena valida; re-key con blessing event; backup Shamir 2-di-3 e restore; pairing remoto completo (mnemonic → SPAKE2 → codice Double-Check a 6 cifre); stress a **10.000 eventi**; 1.000 payload casuali fino a 100 KB. *Caveat:* lo scambio tra peer è simulato via store condiviso in memoria + `FakeTransport` — il ledger/crypto/pairing sono esercitati davvero, ma **due peer su un socket reale (Nostr/Email/Tor) non hanno un test automatico**.

### 3.2 Stack JS/MLS — la chat (`styx-js/`) — linea attiva

Il motore crittografico è **MLS (RFC 9420)** via OpenMLS compilato in WASM (`vendor/openmls-wasm/`). Trasporto **Nostr**. Frontend **PWA React/Vite** in `apps/chat/`. Modello: conversazione 1:1 = gruppo MLS a 2 membri.

- **`src/chat/styx-chat.js`** — il cuore: identità secp256k1 (Nostr), sessioni MLS per contatto, pairing QR con nonce monouso + HMAC, safety number, binding credenziale MLS↔pubkey di trasporto, persistenza dello stato.
- **`src/crypto/mls/`** — `MlsEngine`/`MlsSession` sopra il WASM; parser di rete che non trappano (hardening Blocco 1).
- **`src/transport/nostr-chat-transport.js`** — verifica firma+id in ingresso, RelayPool con reconnect. *I metadati (mittente/destinatario/tempo) sono esposti al relay* — gift-wrap NIP-59 non ancora implementato.
- **`apps/chat/`** — PWA completa: onboarding, roster, conversazione, pairing, safety number, impostazioni, service worker, push opt-in. Dopo il Blocco 2: mock isolato dalla produzione, factory reset reale, Web Lock un-solo-writer, CSP completa.
- **Interoperabilità Dart:** **volutamente rotta** (22 test di interop lo documentano). La chat JS è web-only e non condivide crypto col ledger Dart.

### 3.3 Componenti di supporto

- **`push_bridge/` (Node, attivo)** — bridge Web Push/VAPID per la chat JS. Cieco sui contenuti (push vuoto), ascolta i relay per kind 1059 e sveglia il device. Registrazione firmata schnorr. **Limite noto:** la registry è keyed su pubkey Nostr, quindi il bridge apprende quali pubkey sono registrati e li correla al push endpoint (nessun handle anonimo — target del Blocco 2 della roadmap, workstream P2).
- **`push_bridge_server/` (Go, legacy)** — bridge FCM/APNs per il client Dart, deliverable del vecchio TASK_10 (in `docs/archive/`). **Scaffold**: le dipendenze FCM/APNs/Nostr sono dichiarate in `go.mod` ma non importate, nessun `go.sum`, relay `nil`, sender no-op. I profili privacy con dummy Poisson sono implementati come logica, ma non c'è invio push reale. Da trattare come implementazione precedente inattiva.
- **`themis_survey` (Flutter)** — motore di sondaggi con UI, **decoupled dal core** (nessuna dipendenza `styx_*`, si integra via callback iniettato `SurveyStyxBridge`). Fuori dal workspace e dalla CI.

---

## 4. Funzionalità completate

**Stack Dart (libreria, completa e testata):**
- Identità Ed25519, firma/verifica, X25519 ECDH con chiavi direzionali HKDF.
- Ledger append-only con hash-chain, HLC, vector clock, merge deterministico dei fork, pruning/retention GDPR.
- Tre trasporti (Nostr, Email, Tor) con failover e outbox.
- Pairing QR e pairing remoto (SPAKE2 + Double-Check), backup Shamir, re-key e migrazione device.
- Persistenza cifrata Drift/SQLite.

**Stack JS/chat (linea attiva):**
- Chat 1:1 E2EE su MLS con forward secrecy e post-compromise security.
- Pairing QR autenticato: nonce monouso, prova-di-scansione HMAC, no-overwrite di sessione, safety number verificabile, **binding credenziale MLS↔identità di trasporto** (N2).
- Trasporto Nostr con verifica firma in ingresso; push notification cieche sui contenuti.
- PWA installabile: offline app-shell, service worker, tema, scanner QR.
- **Hardening Blocco 1 (crate WASM):** nessun panic da input di rete (provato), toolchain pinnata per digest, `Cargo.lock` vendorizzato, **build byte-riproducibile**, `restore_state` con aritmetica checked.
- **Hardening Blocco 2 (app):** mock fuori dalla produzione con fail-hard, stub disabilitati, copy onesto, **factory reset reale** (backend, cache, SW, push, IDB), **Web Lock un-solo-writer** multi-tab, **CSP completa** verificata in browser, gate CI anti-mock.

---

## 5. Funzionalità mancanti / aperte

Mappate ai blocchi della roadmap (`docs/security/2026-07-11-fattibilita-piano-utente.md`). Due vulnerabilità di testa restano aperte: **H1** (dati in chiaro a riposo) e **H2** (metadati esposti al relay).

| Area mancante | Blocco | Impatto |
|---|---|---|
| Vault cifrato a riposo (IndexedDB, Root Key, Argon2id, migrazione atomica) — oggi stato MLS/messaggi/contatti in `localStorage` in chiaro | **3** | chiude **H1** |
| Versionamento del blob di stato MLS + migration policy (debito R1 della review Blocco 1) | pre-**3** | senza, al prossimo bump OpenMLS le sessioni svaniscono in silenzio |
| Trasporto affidabile: ACK NIP-01, outbox persistente, retry/backoff, stati di invio reali, ricevute cifrate | **4** | oggi "sent" non deriva da un ACK reale |
| Evoluzione MLS: pending commit, merge ack-gated, fork detection, StorageProvider granulare, rekey | **5** | API wasm da esporre (epoch/tree-hash) — "Blocco 5.0" |
| Multi-device (device credential separate, leaf per device, revoca, history sync) | **5** (epic) | 6–16 settimane a sé |
| Protezione metadati: mailbox key non identitaria, gift-wrap NIP-59, push handle anonimo, padding | pre-audit | chiude **H2** |
| Pairing remoto PAKE nella chat JS (stub — la logica SPAKE2 esiste in `src/crypto/spake2.js` ma non è cablata) | 2/5 | oggi nascosto dietro demo |
| Allegati, gruppi (N>2), key transparency, app native firmate | P3 | lungo termine |
| Audit esterno indipendente | pre-release | requisito per il target "comunicazioni sensibili" |

Debiti at-rest tracciati (Blocco 1/2): residuo forense di un join rifiutato in `mls:state` (il crate non espone delete); DoS di griefing sul QR fotografato che brucia l'invito.

---

## 6. Stato della roadmap (5 blocchi)

| Blocco | Contenuto | Stato |
|---|---|---|
| **0.5 / 1 — Emergenza WASM** | panic-free, pin OpenMLS verificato, toolchain+lockfile, build riproducibile, binding N2 | ✅ **fatto** (commit `363a3ad`…`80a0ded`) |
| **2 — Riduzione rischio** | mock fuori prod, stub off, factory reset, Web Lock, CSP, copy, gate CI | ✅ **fatto** (commit `4e40721`…`598fee8`) |
| **3 — Vault minimo** | IndexedDB, Root Key, Argon2id, cifratura at-rest, migrazione | 🟡 preparazione: envelope MLS versionato + migration policy ✅ (PR #23, `b4f00ac`); spike autorizzati; vault non iniziato (chiude H1) |
| **4 — Trasporto affidabile** | ACK, outbox, retry, ricevute cifrate | ⬜ da fare |
| **5 — Evoluzione MLS** | ack-gating, fork detection, StorageProvider, rekey, multi-device | ⬜ da fare |
| Metadati pre-audit + Audit | gift-wrap, mailbox/push handle; audit esterno | ⬜ da fare (chiude H2) |

**Stime a "beta auditabile":** ottimistico 5–7 mesi, probabile 7–10, prudenziale 10–14 (ne è passato ~1). Modalità: un blocco alla volta con **review architetturale tra i blocchi** (Blocco 1 in `§7.7` del documento di fattibilità; **review del Blocco 2 fatta, verdetto GO**, in `docs/security/2026-07-11-review-architetturale-blocco-2.md`). Tra il Blocco 2 e il Blocco 3 è stato inserito un gate di consolidamento GitHub/CI (repo reso pubblico, protezioni, CI Dart resa verde, integrità WASM in CI).

---

## 7. Valutazione architetturale

**Cosa è solido.**
- Lo **stack Dart** è software maturo: separazione netta per package, interfacce iniettabili (DI ovunque), test che superano il sorgente in righe, property-based sugli invarianti crittografici, un e2e che regge 10.000 eventi. Se il progetto tornasse alla direzione Dart/Flutter, la fondazione c'è.
- Il **motore MLS** della chat, dopo il Blocco 1, è su basi corrette: parser che non trappano (provato contro l'artefatto pre-fix), build riproducibile e auditabile, identità MLS legata al trasporto. Poggiare altro lavoro qui è ragionevole.
- La **disciplina di processo** è visibile nella storia git: security report → documento di fattibilità → piani per blocco → esecuzione con commit piccoli e review. I documenti sono onesti (le rettifiche restano visibili, es. R1).

**La tensione architetturale principale: due implementazioni.**
Il progetto porta il costo di **due basi di codice che fanno cose sovrapposte** con modelli crittografici diversi (catena di eventi firmati in Dart; MLS in JS) e interoperabilità *volutamente* rotta. Paradossalmente il lato **meno completo in funzionalità** (JS: pairing remoto, backup, multi-device sono stub o assenti) è la **linea attiva**, mentre il lato **più completo** (Dart) è fermo. Questo non è un bug — riflette il pivot verso una PWA E2EE — ma va nominato: il valore del lavoro Dart è oggi latente, e ogni feature "nuova" della chat JS (backup, pairing remoto, migrazione device) è in realtà una **re-implementazione** di qualcosa che in Dart esiste ed è testato. Vale la pena decidere esplicitamente se il Dart è (a) archiviato, (b) una riserva di design da cui attingere, o (c) un target futuro — oggi è in un limbo non dichiarato.

**Postura di sicurezza — onesta ma non ancora pronta.**
La chat non è adatta a comunicazioni sensibili finché H1 (storage in chiaro) e H2 (metadati al relay) sono aperte. Il Blocco 2 ha rimosso i claim fuorvianti ("serverless"), il che è la cosa giusta: il sistema ora dichiara i propri limiti invece di nasconderli. Ma la barra dichiarata (giornalisti/attivisti) richiede l'intero percorso, audit incluso.

**Rischi sul percorso** (dalla review del Blocco 1, ancora validi):
- Il blob di stato MLS non è versionato → fragile al prossimo bump del pin (da chiudere **prima** del Blocco 3, in JS, senza rebuild).
- `patch/lib.rs` è una sostituzione integrale del file upstream → una modifica upstream a quel file verrebbe scartata in silenzio. Convertire in crate Styx-owned prima di ulteriore lavoro sul crate.
- Il loop di build WASM non ha caching → ostile allo sviluppo iterativo dello StorageProvider (Blocco 5).
- Il binding N2 non sopravvive al multi-device così com'è, ma la primitiva (`member_identities`) generalizza: è da evolvere, non da strappare.

**Igiene del repository.**
Un solo autore, storia lineare e leggibile, `docs/` riordinata (gli storici in `archive/`, i `CLAUDE.md`/`AGENTS.md` allineati alla realtà dopo il Blocco 2). CI Dart, CI web, integrità WASM e CodeQL tutte verdi su `main`, con ruleset e protezioni GitHub attive; azioni pinnate a SHA e token read-only. Punti deboli: `push_bridge_server` (Go) è uno scaffold inattivo che convive col bridge Node attivo (potenziale confusione — andrebbe marcato come legacy nel suo README); `test_integration` è quasi solo il generatore di vector con un test stub; `push_bridge_client` ha una copertura test sottile (1 file per 6 sorgenti).

**Giudizio complessivo.** Fondazioni solide su entrambi gli stack, processo di sicurezza serio e onesto, e due blocchi di hardening completati bene. Il progetto è **circa a un terzo** del percorso verso una beta auditabile per il target dichiarato, con il critical path che passa dal vault cifrato (Blocco 3) e dalla protezione dei metadati. La cosa più utile da decidere a livello di prodotto non è tecnica: **chiarire lo status dello stack Dart**, per non pagare due volte funzionalità che esistono già.

---

## 8. Indice dei documenti chiave

- **Roadmap normativa:** `docs/security/2026-07-11-fattibilita-piano-utente.md` (5 blocchi, criteri di uscita, review Blocco 1 in §7.7)
- **Audit di sicurezza:** `docs/security/2026-07-10-styx-chat-security-report.md` (C1-C3, H1-H3, M1-M6, N1-N4; stato di attuazione aggiornato)
- **Piani attivi:** `docs/superpowers/plans/2026-07-11-blocco1-wasm-hardening.md`, `…-blocco2-risk-reduction.md`
- **Design spec:** `docs/superpowers/specs/2026-07-09-styx-chat-mls-design.md` e affini
- **Provenienza WASM:** `styx-js/vendor/openmls-wasm/PROVENANCE.md`
- **API Dart:** `docs/API_REFERENCE.md` / `docs/API_REFERENCE_IT.md`
- **Istruzioni agenti:** `CLAUDE.md` (panoramica dei due stack), `AGENTS.md` (landmine operative)
- **Storici (non normativi):** `docs/archive/` (TASK_00-12, ROADMAP, Blueprint v2)
