# Styx — Piano di Sviluppo Task-by-Task

## Filosofia di Sviluppo

**Bottom-up con spike parallelo sul Push Bridge.** Ogni layer viene costruito come package indipendente nel monorepo, con test esaustivi che vengono rieseguiti integralmente ad ogni task successivo. Il Push Bridge, pur essendo la priorità #1 dal punto di vista del rischio, richiede crypto e transport per funzionare — quindi viene prototipato in parallelo (spike) e completato per ultimo.

**Regola d'oro:** nessun task si considera completato se i test di TUTTI i task precedenti non passano al 100%.

---

## Struttura Monorepo

```
styx/
├── melos.yaml
├── pubspec.yaml                      # Pub Workspace root
├── packages/
│   ├── crypto_core/                  # Task 1-3
│   ├── storage/                      # Task 4
│   ├── ledger_engine/                # Task 5-6
│   ├── transport/                    # Task 7-9
│   ├── push_bridge_client/           # Task 10
│   └── styx/             # Task 11 — façade pubblica
├── push_bridge_server/               # Task 10 (Go microservice)
├── test_integration/                 # Test cross-package
└── .github/workflows/ci.yml
```

---

## Task 0 — Scaffolding del Monorepo

**Obiettivo:** Infrastruttura di progetto, CI, linting, coverage gate.

**Azioni:**
- Inizializzare il monorepo con `melos` 7.x + Pub Workspaces
- Configurare `very_good_analysis` come baseline lint
- Creare il workflow GitHub Actions con matrix testing
- Impostare coverage gate al 90% con lcov
- Creare lo script `melos run test:all` che esegue tutti i test di tutti i package

**Dipendenze esterne:** `melos`, `very_good_analysis`, `dart_code_linter`

**Test:** Il CI deve passare con zero warning e zero errori su un package placeholder vuoto.

**Criteri di completamento:**
- [ ] `melos bootstrap` esegue senza errori
- [ ] `melos run test:all` esegue senza errori
- [ ] CI GitHub Actions green
- [ ] Coverage gate attivo (fallisce se < 90%)

---

## Task 1 — Crypto Core: Chiavi e Firme

**Obiettivo:** Generazione keypair Ed25519/X25519, firma, verifica, hashing SHA-256.

**Package:** `packages/crypto_core/`

**Dipendenze esterne:** `cryptography` ^2.9.0, `cryptography_flutter` ^2.3.4, `crypto` ^3.0.7

**Componenti da implementare:**
- `KeyPair` — wrapper tipizzato per Ed25519 keypair
- `IdentityManager` — genera, esporta (bytes), importa keypair
- `Signer` — firma binaria con Ed25519
- `Verifier` — verifica firma dato payload + pubkey
- `Hasher` — SHA-256 su bytes arbitrari, con supporto per hash chain (hash di hash precedente + payload)
- `KeyConverter` — conversione Ed25519 → X25519 per DH

**Test (≥95% coverage):**
- Generazione keypair: chiave privata ≠ chiave pubblica, lunghezze corrette (32 bytes ciascuna)
- Firma e verifica: round-trip (firma → verifica = true)
- Firma invalida: payload alterato → verifica = false
- Firma con chiave sbagliata: verifica = false
- Hash chain: SHA-256 deterministico, vettori RFC 6234
- Conversione Ed25519→X25519: round-trip con DH agreement
- **Property-based (glados):** per qualsiasi payload random, sign+verify = true
- **Property-based:** per qualsiasi coppia di payload diversi, hash(a) ≠ hash(b)
- **Edge cases:** payload vuoto, payload da 1 byte, payload da 10MB

**Criteri di completamento:**
- [ ] Tutti i test passano
- [ ] Coverage ≥ 95%
- [ ] `melos run test:all` (include Task 0)

---

## Task 2 — Crypto Core: Key Exchange (X25519 + SPAKE2)

**Obiettivo:** Diffie-Hellman X25519 e SPAKE2 per pairing remoto.

**Package:** `packages/crypto_core/` (estensione)

**Dipendenze esterne:** `cryptography` (già presente). Per SPAKE2: FFI custom verso libsodium o implementazione pure-Dart.

**Strategia SPAKE2:**
Dato che non esiste un package cross-platform, si valutano due approcci:
1. **Opzione A (raccomandata):** Implementazione pure-Dart di SPAKE2 usando le primitive EC di `cryptography` (Ristretto255 o P-256). Più portabile, nessun FFI.
2. **Opzione B:** FFI verso `libspake2` (C) con build hooks `package_ffi`. Più performante, più complesso da buildare.

**Componenti da implementare:**
- `DiffieHellman` — X25519 key agreement → shared secret
- `KeyDerivation` — HKDF-SHA256 per derivare chiavi simmetriche dal shared secret
- `Spake2Session` — stato della sessione SPAKE2 (init, process, finish)
- `Spake2Protocol` — orchestrazione del protocollo a 2 messaggi
- `SessionVerifier` — derivazione codice di controllo a 6 cifre (Double Check) da session key

**Test:**
- X25519: due peer generano keypair → DH agreement → stessa chiave condivisa
- X25519: chiave condivisa differisce con keypair diversi
- HKDF: vettori di test RFC 5869
- SPAKE2: round-trip completo tra due parti con lo stesso codice
- SPAKE2: codice diverso → fallimento negoziazione
- SPAKE2: resistenza a replay (stessa sessione non riutilizzabile)
- Double Check: stesso session key → stesso codice 6 cifre; session key diversa → codice diverso
- **Property-based:** per qualsiasi coppia di keypair, DH è commutativo (A⊕B = B⊕A)

**Criteri di completamento:**
- [ ] Tutti i test passano (Task 1 + Task 2)
- [ ] Coverage ≥ 95%
- [ ] SPAKE2 funziona su Android e iOS (test su emulatore se FFI)

---

## Task 3 — Crypto Core: Key Storage, BIP-39, Shamir

**Obiettivo:** Persistenza sicura delle chiavi, mnemonic per pairing, backup via SSS.

**Package:** `packages/crypto_core/` (estensione)

**Dipendenze esterne:** `flutter_secure_storage` ^10.0.0, `bip39_mnemonic`, implementazione SSS custom

**Componenti da implementare:**
- `SecureKeyStore` — wrapper attorno a flutter_secure_storage con encrypt/decrypt della chiave Ed25519 privata usando AES-256-GCM con chiave derivata dal Keystore/Keychain hardware
- `MnemonicGenerator` — generazione codice 6-8 parole BIP-39 con entropia configurabile
- `MnemonicValidator` — validazione checksum BIP-39
- `ShamirSplitter` — split di un secret in N shares con threshold T (default 2-of-3) su GF(256)
- `ShamirReconstructor` — ricostruzione del secret da T shares
- `KeyBackup` — orchestrazione: prende chiave privata → Shamir split → output shares

**Test:**
- SecureKeyStore: store → retrieve → chiave identica
- SecureKeyStore: store → delete → retrieve = null
- SecureKeyStore: overwrite → retrieve = nuova chiave
- BIP-39: mnemonic di 6 parole = 66 bit entropia (verifica lunghezza)
- BIP-39: mnemonic di 8 parole = 88 bit entropia
- BIP-39: checksum valido dopo generazione
- BIP-39: checksum invalido con parola alterata
- Shamir 2-of-3: ricostruzione con 2 share qualsiasi → secret originale
- Shamir 2-of-3: ricostruzione con 1 solo share → fallimento
- Shamir 3-of-5: ricostruzione con 3 share qualsiasi → secret originale
- Shamir: tutte le combinazioni di T share su N → tutte producono lo stesso secret
- **Property-based:** per qualsiasi secret random e qualsiasi combinazione valida di share, ricostruzione = originale

**Criteri di completamento:**
- [ ] Tutti i test passano (Task 1 + 2 + 3)
- [ ] Coverage ≥ 95%
- [ ] SecureKeyStore testato su emulatore Android e iOS

---

## Task 4 — Storage: Database Cifrato con Drift + SQLCipher

**Obiettivo:** Schema del database, encryption at rest, migration framework.

**Package:** `packages/storage/`

**Dipendenze esterne:** `drift` ^2.30.1, `drift_dev`, `sqlcipher_flutter_libs` ^0.6.8, `build_runner`

**Componenti da implementare:**
- `EncryptedDatabase` — factory per NativeDatabase con SQLCipher + passphrase da SecureKeyStore
- Schema tabelle:
  - `events` — append-only (id, event_id, type, payload_encrypted, previous_hash, event_hash, hlc_timestamp, hlc_node_id, hlc_counter, sender_pubkey, signature, created_at)
  - `peers` — trust store (pubkey, alias, paired_at, is_active, rekey_history)
  - `outbox` — coda invio (event_id, status [pending/sent/confirmed], transport_used, retry_count, next_retry_at)
  - `config` — chiave-valore (settings utente, profilo privacy)
- `EventDao` — insert append-only, query per range, query per hash, verifica catena completa
- `OutboxDao` — enqueue, dequeue, mark sent, retry logic
- `PeerDao` — CRUD peers, update trust store
- `MigrationStrategy` — versioning schema con rollback

**Test:**
- Open/close database con encryption: riapertura con stessa passphrase → dati intatti
- Open con passphrase sbagliata → errore (non crash)
- Insert evento + query per event_id → match
- Append-only enforcement: tentativo di UPDATE su events → errore o no-op
- Outbox FIFO: enqueue 3 eventi → dequeue nell'ordine corretto
- Outbox retry: mark failed → next_retry_at aggiornato con backoff
- Chain verification: inserire 100 eventi → verifica catena OK → alterare 1 byte nel DB → verifica catena FAIL
- Migration: creare DB v1, aggiornare a v2, verificare dati preservati
- **Performance:** insert 10.000 eventi in < 5 secondi
- **Concurrency:** read e write da isolate diversi senza deadlock (WAL mode)

**Criteri di completamento:**
- [ ] Tutti i test passano (Task 1-4)
- [ ] Coverage ≥ 90% (drift genera molto codice boilerplate)
- [ ] DB funziona su Android e iOS con SQLCipher

---

## Task 5 — Ledger Engine: Event Sourcing + Hash Chain

**Obiettivo:** Creazione, validazione e persistenza di eventi nella catena crittografica.

**Package:** `packages/ledger_engine/`

**Dipendenze interne:** `crypto_core`, `storage`

**Componenti da implementare:**
- `LedgerEvent` — modello dominio con tutti i campi (type, payload, previousHash, eventHash, hlc, vectorClock, senderPubkey, signature)
- `EventTypes` — enum: TRANSACTION, SOS, CONFIG, REKEY, MERGE, PRUNE_REQUEST, PRUNE_ACK, MESSAGE
- `EventFactory` — costruisce un evento dato il tipo e il payload, calcola hash, firma con chiave privata
- `ChainValidator` — verifica ricorsiva dell'intera catena (hash linkage + firme)
- `HlcClock` — Hybrid Logical Clock (usando `crdt` package come reference, o implementazione standalone)
- `LedgerService` — façade: appendEvent(), getHistory(), validateChain()

**Test:**
- Creazione evento: hash calcolato correttamente = SHA-256(previousHash || type || payload || hlc)
- Firma valida su ogni evento creato
- Append 1000 eventi → validateChain() = true
- Alterare 1 byte in evento #500 → validateChain() = false, con indicazione dell'evento corrotto
- HLC: eventi sullo stesso nodo → counter monotonicamente crescente
- HLC: evento ricevuto con timestamp futuro → clock avanza correttamente
- HLC: evento ricevuto con timestamp passato → counter incrementa comunque
- Genesis event: primo evento della catena ha previousHash = null e viene gestito correttamente
- **Property-based:** per qualsiasi sequenza di N eventi, validateChain() = true
- **Property-based:** per qualsiasi alterazione di un singolo byte in qualsiasi evento, validateChain() = false

**Criteri di completamento:**
- [ ] Tutti i test passano (Task 1-5)
- [ ] Coverage ≥ 95%

---

## Task 6 — Ledger Engine: Conflict Resolution + Pruning

**Obiettivo:** Gestione fork, merge deterministico, protocollo di pruning GDPR.

**Package:** `packages/ledger_engine/` (estensione)

**Componenti da implementare:**
- `VectorClock` — struttura a 2 elementi {A: counter, B: counter}
- `CausalityChecker` — determina relazione tra due vector clock: BEFORE, AFTER, CONCURRENT
- `ForkDetector` — rileva fork quando si ricevono eventi concorrenti
- `DeterministicMerge` — ordinamento: (1) somma contatori, (2) a parità → ordine lessicografico pubkey mittente
- `MergeEventFactory` — crea evento MERGE che referenzia entrambe le punte del fork
- `PruneProtocol` — stato machine: IDLE → REQUEST_SENT → WAITING_ACK → PRUNED
- `PruneExecutor` — elimina payload conservando hash nell'evento

**Test:**
- VectorClock: [2,1] domina [1,1] → BEFORE/AFTER corretto
- VectorClock: [2,1] vs [1,2] → CONCURRENT
- Fork detection: due eventi con stesso previousHash → fork rilevato
- Merge deterministico: dato lo stesso fork, entrambi i peer producono lo stesso ordinamento
- Merge deterministico: 1000 fork randomici → entrambi i peer convergono sempre
- Merge event: dopo merge, la catena è di nuovo lineare
- Pruning bilaterale: REQUEST → ACK → payload rimosso su entrambi, hash preservato
- Pruning unilaterale (Art. 17): REQUEST senza ACK → payload rimosso localmente, hash preservato
- Chain integrity post-pruning: validateChain() = true anche dopo pruning
- **Property-based (commutatività):** merge(A, B) produce lo stesso risultato di merge(B, A)
- **Property-based (idempotenza):** merge(A, A) = A
- **Property-based:** dopo qualsiasi sequenza di fork+merge, validateChain() = true

**Criteri di completamento:**
- [ ] Tutti i test passano (Task 1-6)
- [ ] Coverage ≥ 95%
- [ ] Il merge è dimostrabilmente deterministico (test con 10.000 scenari randomici)

---

## Task 7 — Transport: Nostr Client

**Obiettivo:** Connessione a relay Nostr, invio/ricezione messaggi cifrati E2E.

**Package:** `packages/transport/`

**Dipendenze interne:** `crypto_core`
**Dipendenze esterne:** `ndk` ^0.6.0, `web_socket_client` ^0.2.1

**Componenti da implementare:**
- `TransportMessage` — envelope: {encryptedPayload, senderPubkey, recipientPubkey, nonce, timestamp}
- `TransportInterface` — interfaccia astratta: send(), receive() stream, connect(), disconnect()
- `NostrTransport` implements `TransportInterface` — connessione a pool di relay, publish/subscribe
- `NostrEncryptor` — cifratura payload con X25519 shared secret + ChaCha20-Poly1305 (o NIP-44/NIP-59 via ndk)
- `RelayPool` — gestione connessioni multiple con health check e failover
- `MessageSerializer` — serializzazione/deserializzazione dei LedgerEvent in formato trasporto

**Test:**
- Connessione a relay di test (locale o pubblico di staging)
- Invio messaggio → ricezione sull'altro peer → decrypt → payload originale
- Messaggio cifrato: relay non può leggere il contenuto (verifica che il relay vede solo blob)
- Relay disconnect → reconnect automatico → messaggi in coda inviati
- Pool multi-relay: invio su 3 relay → ricezione da almeno 1
- Messaggio per pubkey sbagliata → decrypt fallisce → messaggio scartato
- **Integration test con 2 isolate** che simulano 2 peer sullo stesso device
- Throughput: 100 messaggi/sec su relay locale

**Criteri di completamento:**
- [ ] Tutti i test passano (Task 1-7)
- [ ] Coverage ≥ 90% (parti di ndk non mockabili)
- [ ] Funziona su Android e iOS con relay pubblici

---

## Task 8 — Transport: Email Fallback

**Obiettivo:** Invio/ricezione di eventi cifrati via IMAP/SMTP come fallback.

**Package:** `packages/transport/` (estensione)

**Dipendenze esterne:** `enough_mail` ^2.1.7

**Componenti da implementare:**
- `EmailTransport` implements `TransportInterface`
- `EmailConfig` — credenziali IMAP/SMTP (stored in SecureKeyStore)
- `EmailEncoder` — payload cifrato → MIME attachment (application/octet-stream)
- `EmailDecoder` — MIME attachment → payload cifrato
- `ImapPoller` — IMAP IDLE per push-style + fallback polling ogni N minuti
- `EmailFilter` — filtra messaggi per subject pattern (es. `[SL:v1:{recipient_pubkey_short}]`)

**Test:**
- Round-trip: invio email con payload cifrato → ricezione via IMAP → decrypt → payload originale
- Encoding: payload binario → attachment MIME → decodifica = originale
- IMAP IDLE: nuovo messaggio → callback ricevuto entro 5 secondi
- Credenziali errate → errore gestito (non crash)
- Messaggio con subject non matching → ignorato
- Messaggio con attachment corrotto → errore gestito, messaggio flaggato
- **Mock test** (senza server reale): verifica del flusso completo con mock IMAP/SMTP

**Criteri di completamento:**
- [ ] Tutti i test passano (Task 1-8)
- [ ] Coverage ≥ 90%
- [ ] Testato con almeno un provider reale (Gmail o altro)

---

## Task 9 — Transport: Tor Overlay + Failover Engine

**Obiettivo:** Routing opzionale via Tor e motore di failover multi-transport.

**Package:** `packages/transport/` (estensione)

**Dipendenze esterne:** `tor` ^0.1.1, `socks5_proxy` ^2.1.1, `retry` ^3.1.2

**Componenti da implementare:**
- `TorManager` — bootstrap Tor, esponi SOCKS5 proxy port, stato (bootstrapping/ready/error)
- `TorTransportDecorator` — decorator pattern: wrappa qualsiasi `TransportInterface` per routare via Tor
- `TransportFailover` — engine: Nostr (3 tentativi, 5s timeout) → Email (2 tentativi, 30s timeout)
- `TransportSelector` — seleziona il trasporto in base a connettività, configurazione utente, e stato Tor
- `OutboxWorker` — processa la coda outbox usando TransportFailover, rispettando ordine causale (HLC)

**Test:**
- Tor bootstrap: avvio → stato READY entro 60 secondi
- Connessione a relay Nostr via Tor → IP reale non visibile al relay (verificare con relay di test)
- Failover: Nostr non raggiungibile → automatico switch a Email → messaggio inviato
- Failover: entrambi non raggiungibili → messaggio resta in outbox con stato `pending`
- Recovery: connettività ripristinata → outbox svuotato nell'ordine corretto
- OutboxWorker: 50 messaggi in coda → tutti inviati in ordine causale
- Retry con backoff esponenziale: verificare timing tra tentativi
- **Tor timeout:** bootstrap > 120s → errore gestito, fallback a trasporto diretto

**Criteri di completamento:**
- [ ] Tutti i test passano (Task 1-9)
- [ ] Coverage ≥ 85% (Tor bootstrap non completamente controllabile in test)
- [ ] Failover Nostr→Email funziona end-to-end

---

## Task 10 — Push Bridge: Server + Client

**Obiettivo:** Microservizio stateless per wake-up + client Flutter con profili privacy.

**Package server:** `push_bridge_server/` (Go)
**Package client:** `packages/push_bridge_client/`

**Dipendenze server:** Go, `firebase-admin-go`, `sideshow/apns2`
**Dipendenze client:** `firebase_messaging` ^16.1.1, `flutter_local_notifications` ^20.0.0

**Componenti server:**
- `BridgeServer` — HTTP endpoint: POST /register {fcm_token, nostr_pubkey}, POST /unregister
- `NostrSubscriber` — sottoscrive relay per pubkey registrate
- `PushDispatcher` — alla ricezione di un evento Nostr → invia push data-only a FCM/APNs
- `DummyScheduler` — generazione dummy push secondo profilo (Poisson λ configurabile)
- Zero state: nessun log, nessun DB, solo token map in-memory

**Componenti client:**
- `PushBridgeClient` — registrazione/deregistrazione al bridge
- `PushHandler` — gestione push in background (top-level callback per firebase_messaging)
- `DummyDetector` — distingue push reale da dummy (tentativo decrypt: se fallisce → dummy)
- `PrivacyProfile` — enum: Balanced, Private, Paranoid con configurazione λ
- `WakeUpOrchestrator` — alla ricezione push reale: connect a relay → download eventi → process → sleep

**Test server:**
- Register → token memorizzato → unregister → token rimosso
- Evento Nostr ricevuto → push FCM inviato con payload minimale
- Push non contiene dati sensibili (solo flag)
- Dummy push: distribuzione Poisson verificata su 1000 campioni (chi-square test)
- Server restart → stato azzerato (stateless verified)

**Test client:**
- Push ricevuta in background → handler eseguito
- Push reale → connessione a relay → download eventi
- Push dummy → nessuna connessione di rete (verificare con mock)
- Profilo Private: dummy push → app si sveglia e torna a dormire senza I/O
- Profilo Paranoid: dummy push → connessione reale al relay
- Registrazione al bridge → token FCM inviato correttamente
- Token FCM rinnovato → ri-registrazione automatica

**Criteri di completamento:**
- [ ] Tutti i test passano (Task 1-10)
- [ ] Coverage ≥ 90% (client), ≥ 85% (server)
- [ ] Push funziona su device Android reale
- [ ] Push funziona su device iOS reale (con Notification Service Extension)

---

## Task 11 — Pairing Protocol + Device Migration

**Obiettivo:** Flusso completo di pairing (QR + remoto) e re-keying.

**Package:** `packages/styx/` (façade)

**Dipendenze interne:** tutti i package precedenti

**Componenti da implementare:**
- `QrPairingService` — genera QR con pubkey + nonce → peer scansiona → scambio chiavi
- `RemotePairingService` — genera mnemonic BIP-39 → SPAKE2 handshake via relay → scambio chiavi → Double Check
- `DoubleCheckVerifier` — mostra codice 6 cifre, attende conferma utente
- `TrustStoreManager` — gestisce il trust store (aggiunta/revoca peer)
- `ReKeyProtocol` — vecchio device firma REKEY con nuova pubkey → peer aggiorna trust store
- `KeyMigrationService` — orchestrazione: genera keypair su nuovo device → REKEY event → sync → done
- `ShamirBackupService` — backup chiave → split → output share (QR o testo)
- `ShamirRestoreService` — input T share → ricostruzione chiave → restore identità

**Test:**
- QR pairing: genera QR → scansiona → entrambi i peer hanno la pubkey dell'altro
- Remote pairing: mnemonic 6 parole → SPAKE2 → scambio chiavi → Double Check match
- Remote pairing con mnemonic sbagliato → handshake fallisce
- MITM simulation: attaccante intercetta → Double Check codes diversi → utente rileva
- Re-keying: vecchio device firma REKEY → peer aggiorna trust store → nuovi eventi firmati con nuova chiave accettati
- Re-keying: evento firmato con VECCHIA chiave dopo REKEY → rifiutato
- Shamir backup + restore: backup → delete chiave → restore da share → chiave identica
- **Full integration:** pairing → scambio 10 eventi → re-key → scambio altri 10 eventi → validate chain = true

**Criteri di completamento:**
- [ ] Tutti i test passano (Task 1-11)
- [ ] Coverage ≥ 90%
- [ ] Pairing QR funziona su device reale
- [ ] Pairing remoto funziona tra due device reali

---

## Task 12 — Façade Pubblica + Integration Test End-to-End

**Obiettivo:** API pubblica della libreria e test di integrazione completi.

**Package:** `packages/styx/` (completamento)

**Componenti da implementare:**
- `SovereignLedger` — entry point unico: init(), pair(), sendTransaction(), sendSOS(), getHistory(), prune(), setPrivacyProfile()
- `LedgerConfig` — configurazione: relay list, email config, privacy profile, retention policy
- `LedgerEventStream` — stream reattivo di eventi (nuovi, ricevuti, merge)
- Documentazione API completa (dartdoc)

**Test end-to-end (integration):**
- Scenario completo: init → pairing → invio 100 transazioni → ricezione → validate chain
- Scenario offline: peer A crea 10 eventi offline, peer B crea 10 eventi offline → reconnect → merge → entrambi vedono tutti 20 eventi nello stesso ordine
- Scenario pruning: invio foto scontrino → prune request → ack → payload eliminato → chain valida
- Scenario SOS: invio SOS → ricezione immediata con priorità alta
- Scenario re-key: migrazione device → continuità catena
- Scenario Tor: tutti gli scenari sopra via Tor overlay
- **Stress test:** 10.000 eventi → validate chain < 2 secondi
- **Fuzzing:** payload random, timestamp futuri, firme corrotte → nessun crash, errori gestiti

**Criteri di completamento:**
- [ ] TUTTI i test di TUTTI i task passano
- [ ] Coverage globale ≥ 90%
- [ ] API documentata al 100%
- [ ] Nessun warning del linter

---

## Strategia di Regression Testing

```
Ad ogni task N:
  1. Sviluppo dei componenti del Task N
  2. Scrivi test del Task N
  3. Esegui `melos run test:all` (tutti i test da Task 0 a Task N)
  4. Se qualsiasi test fallisce → FIX PRIMA di procedere
  5. Verifica coverage ≥ soglia per ogni package
  6. Commit solo se CI è green
```

**Pipeline CI per ogni PR:**
```
analyze → format check → test:all → coverage gate → build Android → build iOS
```

---

## Timeline Stimata

| Task | Durata stimata | Dipendenze |
|------|---------------|------------|
| 0 — Scaffolding | 1 giorno | Nessuna |
| 1 — Chiavi e Firme | 2-3 giorni | Task 0 |
| 2 — Key Exchange + SPAKE2 | 5-7 giorni | Task 1 (SPAKE2 è il rischio maggiore) |
| 3 — Key Storage + BIP-39 + Shamir | 3-4 giorni | Task 1, 2 |
| 4 — Database cifrato | 3-4 giorni | Task 1, 3 |
| 5 — Event Sourcing + Hash Chain | 3-4 giorni | Task 1, 4 |
| 6 — Conflict Resolution + Pruning | 4-5 giorni | Task 5 |
| 7 — Nostr Client | 4-5 giorni | Task 1, 5 |
| 8 — Email Fallback | 3-4 giorni | Task 7 |
| 9 — Tor + Failover | 3-4 giorni | Task 7, 8 |
| 10 — Push Bridge | 5-7 giorni | Task 7, 4 |
| 11 — Pairing + Migration | 4-5 giorni | Task 2, 3, 7 |
| 12 — Façade + E2E | 3-5 giorni | Tutti |

**Totale stimato: 45-60 giorni lavorativi** (sviluppatore senior, a tempo pieno)

---

## Decisioni Architettoniche Chiave

1. **HLC vs Vector Clock:** Il manifesto specifica Vector Clock a 2 elementi, ma per un sistema a 2 soli peer un HLC è equivalente e più semplice. Implementare VectorClock come wrapper su HLC con logica specifica per il caso N=2.

2. **SPAKE2:** Iniziare con implementazione pure-Dart su P-256 (più semplice, `cryptography` la supporta nativamente). Se le performance non bastano, migrare a FFI.

3. **Merge DAG vs Lineare:** Il manifesto prevede un MERGE event che rende la catena lineare. Questo è più semplice di un DAG persistente ma richiede che il merge sia deterministico. Usare l'ordinamento (somma VC, poi pubkey) come descritto nel manifesto.

4. **Notification Service Extension (iOS):** Necessaria per push affidabili. Va scritta in Swift nativo, fuori da Flutter. Il client push_bridge deve includere un esempio/template Swift.
