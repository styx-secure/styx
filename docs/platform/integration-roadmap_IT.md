<!-- styx-translation:v1 canonical="docs/platform/integration-roadmap.md" sha256="9dd23f7bd84ad240a6c624445e28678a6d022d183ff76f836f99deecbc3d8ee4" -->
# Roadmap per integrare le capacità applicative in Styx

[English canonical version](integration-roadmap.md)

> **Stato:** proposta esplorativa, non normativa
> **Base osservata:** `main @ d90931a3f59ce89c1594cad64ce385d58857b305`
> Questa roadmap propone candidati per future Issue. Non autorizza codice,
> crittografia, formati persistenti, migrazioni o modifiche al vault.

## 1. Metodo e legenda

La valutazione parte dal codice e dalle decisioni correnti. I quattro stati
ammessi sono:

- **implemented**: esiste un percorso funzionante e testato nello stack
  indicato; non implica audit o produzione;
- **partial**: esiste una primitiva o un percorso incompleto/non integrato;
- **missing**: non esiste un percorso utilizzabile nel prodotto indicato;
- **separate design decision**: l'implementazione non deve iniziare prima di
  una decisione tecnica o di sicurezza approvata.

Lo stack JavaScript/Rust/MLS è il prodotto canonico
(`docs/architecture/decisions/ADR-0001-canonical-product-stack.md`). Lo stack
Dart è reference implementation e fonte di requisiti/test, non un secondo core
da estendere (ADR-0003).

## 2. Stato sintetico

| Capacità | Prodotto JS/MLS | Reference Dart | Evidenza e limite principale |
|---|---|---|---|
| Chat E2EE 1:1 | **implemented** | **implemented** per il diverso ledger | JS: `styx-js/src/chat/styx-chat.js`, `styx-js/src/crypto/mls/mls-engine.js`. Dart: `packages/styx/lib/src/sovereign_ledger.dart`. I due modelli non sono interoperabili. |
| Pairing QR autenticato | **implemented** | **implemented** | JS: `styx-js/src/chat/styx-chat.js`. Dart: `packages/styx/lib/src/pairing/qr_pairing_service.dart`. Non equivale a identità civile. |
| Safety number / verifica peer | **implemented** | **partial** | JS: `styx-js/src/chat/styx-chat.js`, `styx-js/src/chat/contact-roster.js`. Dart: `packages/crypto_core/lib/src/session_verifier.dart`, `packages/styx/lib/src/trust/trust_store_manager.dart`. |
| Pairing remoto nel prodotto | **missing** | **implemented** | JS: `styx-js/src/chat/styx-chat.js` solleva `remote pairing not implemented yet`. Dart: `packages/styx/lib/src/pairing/remote_pairing_service.dart`. |
| Identità persistente autocustodita | **implemented** | **implemented** | `styx-js/src/crypto/identity.js`; `packages/crypto_core/lib/src/identity_manager.dart`. L'identità durevole è correlabile. |
| Identità applicativa separata | **missing** | **missing** | Nessun contratto `application context` o derivazione per app. |
| Identità effimera per caso | **missing** | **missing** | Nessun lifecycle per chiave monouso e nessuna garanzia cross-case. |
| Anonymous return capability | **missing** | **missing** | Non esiste una mailbox riapribile tramite capability senza account. |
| Gruppi di prodotto N>2 | **partial** | **separate design decision** | JS: `styx-js/src/crypto/mls/mls-engine.js` gestisce il core MLS, mentre `styx-js/src/chat/styx-chat.js` modella una sessione per contatto e non espone membership completa. Dart non va esteso come core. |
| Ruoli, delega e revoca applicativa | **missing** | **missing** | Trust/pairing non costituiscono RBAC o capability authorization. |
| Vault IndexedDB cifrato | **partial** | **missing** | JS: `styx-js/src/storage/vault-db.js`, `styx-js/src/storage/vault-record.js`, `styx-js/docs/vault-test-matrix.md`; la matrice è canary-only e rinvia il cross-worker a US-008. Il Dart non implementa questo vault web canonico. |
| Migrazione dei dati chat nel vault | **missing** | **separate design decision** | `styx-js/docs/vault-test-matrix.md` marca la migrazione `N/A`; schema, rollback e product namespace richiedono Issue dedicate. |
| Worker con segreti confinati | **partial** | **missing** nel modello web | JS: `styx-js/src/crypto/vault-worker-runtime.js`, `styx-js/src/crypto/vault-worker-supervisor.js`, `styx-js/src/crypto/vault-worker-protocol.js`; il lifecycle completo è oggetto di US-008. |
| Trasporto Nostr federato | **implemented** | **implemented** come reference | `styx-js/src/transport/nostr-chat-transport.js`; `packages/transport/lib/src/nostr/`. Il prodotto usa relay multipli ma non nasconde i metadati. |
| Verifica firma evento in ingresso | **implemented** | **missing** | JS: `styx-js/src/transport/nostr-chat-transport.js`. Dart: `packages/transport/lib/src/nostr/nostr_transport.dart` filtra e decifra ma non verifica una firma Nostr. |
| Deduplicazione replay | **partial** | **partial** | JS: `styx-js/src/transport/nostr-chat-transport.js` usa `_seen` in memoria, limitato a 5000. Dart: `packages/transport/lib/src/nostr/nostr_transport.dart` usa una cache LRU in memoria. Entrambe si perdono al riavvio. |
| Outbox persistente del prodotto | **missing** | **implemented** come reference | JS: `styx-js/src/chat/styx-chat.js` persiste il messaggio ma invia direttamente. Dart: `packages/transport/lib/src/failover/outbox_worker.dart`, `packages/storage/lib/src/dao/outbox_dao.dart`. |
| ACK reale e stati di consegna | **missing** | **missing** | JS: `styx-js/src/transport/nostr-chat-transport.js` chiama `publish()` senza attesa e `styx-js/src/chat/styx-chat.js` marca `sent` dopo il ritorno. Nessuno stack dimostra publish ACK più device ACK end-to-end. |
| Retry/backoff e dead-letter | **missing** nel percorso chat | **partial** | JS: `styx-js/src/transport/failover.js` contiene primitive legacy non integrate in `styx-js/src/chat/styx-chat.js`. Dart: `packages/transport/lib/src/failover/transport_failover.dart`, `packages/transport/lib/src/failover/outbox_worker.dart`. |
| Idempotenza persistente | **missing** | **partial** | JS: UUID e dedup in memoria in `styx-js/src/transport/nostr-chat-transport.js` non sono crash-safe. Dart: identificatori in `packages/ledger_engine/lib/src/event_factory.dart` e persistenza outbox in `packages/storage/lib/src/dao/outbox_dao.dart` sono reference, non prova del prodotto. |
| Ordering e merge applicativo | **missing** nel prodotto chat | **implemented** come reference ledger | Dart: `packages/ledger_engine/lib/src/hlc.dart`, `packages/ledger_engine/lib/src/vector_clock.dart`, `packages/ledger_engine/lib/src/conflict/deterministic_merge.dart`. Il port legacy `styx-js/src/ledger/` è separato da `StyxChat`; la policy resta app-specific. |
| Pending commit / ACK-gating MLS | **missing** | **separate design decision** | Debito esplicito in `docs/security/2026-07-11-fattibilita-piano-utente.md` §3.5; richiede API Rust/WASM. |
| Fork detection MLS | **missing** | **separate design decision** | Mancano epoch/tree hash/context esposti dal core; stesso piano §3.5. |
| Read receipt cifrata | **implemented** | **missing** come prodotto | JS: `styx-js/src/chat/styx-chat.js` cifra `markRead/_sendReceipt` nel percorso MLS; il relay vede comunque evento, timing e relazione. |
| Typing cifrato nel payload | **missing** | **missing** | JS: `styx-js/src/chat/styx-chat.js` invia `{t: 'typing'}` fuori da MLS; `styx-js/src/transport/nostr-chat-transport.js` applica solo Base64. Il limite M4 è aperto in `docs/security/2026-07-10-styx-chat-security-report.md`. |
| Metadata protection esterna | **missing** | **partial** concettuale | JS: H2 è aperto in `docs/security/2026-07-10-styx-chat-security-report.md`; `styx-js/src/transport/nostr-chat-transport.js` espone `pubkey`, tag `p`, tempo e dimensione. Dart: `packages/push_bridge_client/lib/src/privacy_profile.dart` offre solo profili di riferimento. |
| Gift wrap / mailbox non identitaria | **missing** | **missing** | Debito esplicito in `docs/security/2026-07-11-fattibilita-piano-utente.md` §3.6. Il kind `1059` corrente non è un gift wrap. Tecnica concreta: **separate design decision**. |
| Tor/onion nel prodotto web | **missing** | **partial** | JS: `styx-js/README.md` prevede uso esterno di Tor Browser, non un overlay. Dart: `packages/transport/lib/src/tor/tor_manager.dart`, `packages/transport/lib/src/tor/tor_transport_decorator.dart`; il decorator non prova routing end-to-end. |
| Push senza correlazione identitaria | **missing** | **partial** | JS/server: `push_bridge/src/registry.js` registra endpoint rispetto a handle osservabili. Dart: `packages/push_bridge_client/lib/src/push_bridge_client.dart`, `packages/push_bridge_client/lib/src/privacy_profile.dart`; manca un handle anonimo end-to-end. |
| Padding, batching, cover traffic | **missing** | **partial** concettuale | Dart: `packages/push_bridge_client/lib/src/privacy_profile.dart`, `packages/push_bridge_client/lib/src/dummy_detector.dart`; sono reference e non dimostrano la proprietà nel prodotto. Nessun percorso JS attivo. |
| Allegati sicuri | **missing** | **partial** | Dart: `packages/transport/lib/src/email/email_encoder.dart` gestisce allegati email ma non sanitizzazione e metadati per app sensibili. Nessun percorso nella chat JS. |
| Backup identità | **missing** nel prodotto chat | **implemented** come reference | `packages/styx/lib/src/backup/shamir_backup_service.dart`; primitive Shamir JS legacy non sono integrate nel core MLS canonico. |
| Multi-device e revoca device | **missing** | **partial** come reference | Dart: `packages/styx/lib/src/migration/rekey_protocol.dart`, `packages/styx/lib/src/migration/key_migration_service.dart`, `packages/styx/lib/src/sovereign_ledger.dart`. Il prodotto MLS richiede epic e design separati. |
| Retention e pruning | **missing** nel prodotto chat | **implemented** come reference | Dart: `packages/ledger_engine/lib/src/pruning/prune_protocol.dart`, `packages/ledger_engine/lib/src/pruning/retention_manager.dart`. Il port `styx-js/src/ledger/pruning.js` è separato da `StyxChat`; nulla garantisce cancellazione dal destinatario. |
| Export controllato / legal hold | **missing** | **missing** | Nessuna policy applicativa o separazione di ruolo. |
| Audit amministrativo privacy-safe | **missing** | **missing** | Event history non equivale a operator audit. |
| Build WASM riproducibile | **implemented** | **separate design decision** | JS: `styx-js/vendor/openmls-wasm/PROVENANCE.md`, `styx-js/vendor/openmls-wasm/build.sh`, `styx-js/vendor/openmls-wasm/verify.sh`; non autentica da sola la PWA servita. |
| Autenticità first-load/update PWA | **partial** | **separate design decision** | JS: service worker in `styx-js/apps/chat/src/sw.js` e header CSP in `styx-js/apps/chat/static-server.mjs` riducono alcuni rischi; un'origine compromessa può ancora servire un client malevolo. |
| SDK indipendente dalla chat | **missing** | **partial** come reference facade | JS: `styx-js/src/chat/styx-chat.js` è chat-specific. Dart: `packages/styx/lib/src/sovereign_ledger.dart` è una facade sul core non canonico. |
| Capability/version discovery | **missing** | **missing** | Il worker ha protocol version interno, non un contratto di piattaforma applicativa. |
| Compliance hooks | **missing** | **partial** | Dart: `packages/ledger_engine/lib/src/pruning/retention_manager.dart` offre retention di riferimento; mancano workflow, ruoli, legal hold e routing normativo. |
| Assurance profiles verificabili | **missing** | **partial** concettuale | Dart: `packages/push_bridge_client/lib/src/privacy_profile.dart` definisce profili locali, non profili di garanzia end-to-end verificati. |
| Audit esterno del prodotto completo | **missing** | **missing** | Il README vieta uso high-risk; audit OpenMLS upstream non copre patch, PWA, protocollo e operazioni Styx. |

## 3. Cosa riutilizzare e cosa non riutilizzare

### Dal prodotto JavaScript attivo

Da preservare come base:

- MLS e binding dell'identità di trasporto nel percorso chat;
- pairing QR autenticato e safety number;
- verifica degli eventi Nostr in ingresso;
- envelope MLS versionato e comportamento fail-closed;
- worker dedicato e protocollo a grammatica chiusa;
- vault canary e relativi test di atomicità/corruzione;
- build riproducibile del confine WASM;
- CSP, reset e disciplina CI.

Da disaccoppiare dalla chat:

- identità;
- storage degli oggetti;
- stati di delivery;
- schema dei payload applicativi;
- scelta di relay e notifiche;
- policy di retention/recovery.

### Dalla reference implementation Dart

Da trasformare in requisiti o test:

- outbox ordinata e retry;
- failover di trasporto;
- HLC/vector clock e merge deterministico;
- pruning bilaterale/unilaterale e retention;
- pairing remoto con verifica out-of-band;
- backup threshold;
- re-key e blessing del nuovo dispositivo.

Da non trasferire implicitamente:

- primitive o formati crittografici incompatibili con MLS;
- affermazioni Tor senza prova sul client canonico;
- semantica ledger come soluzione universale ai conflitti;
- facciata `SovereignLedger` come API di prodotto;
- test vector cross-stack come prova di interoperabilità della chat MLS.

## 4. Sequenza di integrazione proposta

La sequenza protegge il critical path corrente e rimanda le scelte sensibili ai
relativi human gate.

```text
US-008: vault nel worker (canary)
       │
       ├── product namespace + migrazione verificata
       │
application context + identity profiles
       │
secure object contract + SDK minimo
       │
reliable delivery + sync policy
       │
metadata-minimizing transport
       │
recovery / multi-device / role custody
       │
anonymous-dialogue reference application
       │
independent review → controlled pilot
```

### Incremento A — Consolidare il vault canary

**Dipendenza:** US-008.
**Outcome futuro:** lifecycle e operazioni canary realmente nel worker, test e
CI completi.
**Non include:** dati di prodotto o migrazione.

Questo incremento è già contrattualizzato separatamente e non deve essere
allargato dalla piattaforma.

### Incremento B — Product namespace e migrazione

**Dipendenza:** A.
**Outcome candidato:** decisione esplicita su database di prodotto, namespace,
classi dati, ordine di bootstrap e migrazione `localStorage → vault` con
rollback verificato.
**Human gate:** formato persistente, migrazione e vault architecture.

Prima del design occorre inventariare ogni dato oggi persistito da `StyxChat`,
inclusi alias, roster, messaggi, gruppi e stato MLS. Non è un side effect
ammissibile di una feature applicativa.

### Incremento C — Application context e domain separation

**Dipendenza:** B per la persistenza; può avere uno spike puramente formale
prima.
**Outcome candidato:** modello di contesto applicativo e per-caso, con test di
separazione di chiavi, AAD, namespace e identificatori.
**Human gate:** derivazioni e formati.

Non introduce anonimato; costruisce il confine necessario per poterlo
verificare in seguito.

### Incremento D — Identity profile lifecycle

**Dipendenza:** C.
**Outcome candidato:** API dati-only per creare, ruotare, revocare e distruggere
identità `persistent`, `application` e `case-ephemeral`; threat model e test di
non riuso.
**Design separato:** `anonymous-capability` e custodia organizzativa.

### Incremento E — Secure application object contract

**Dipendenze:** C, D.
**Outcome candidato:** schema envelope applicativo versionato, limiti, AAD,
idempotency key e gestione di tipi sconosciuti.
**Non include:** un formato universale di merge o un linguaggio eseguibile.

L'obiettivo è permettere a chat, contabilità e casework di condividere la
pipeline senza condividere semantica.

### Incremento F — SDK minimo indipendente dalla chat

**Dipendenza:** E.
**Outcome candidato:** facciata limitata per contesto, identità, sessione,
oggetto, capability discovery e subscription tipizzata. `StyxChat` diventa un
consumer/adattatore, non il luogo in cui vivono tutte le primitive.

Il mock di design non può essere la sorgente del contratto di produzione.

### Incremento G — Reliable delivery

**Dipendenze:** B, E.
**Outcome candidato:** outbox nel vault, publish acknowledgement, ACK cifrato
del dispositivo/app, retry, backoff, dedup persistente, scadenza e
riconciliazione dopo crash.
**Success criterion:** nessuno stato “sent” sulla sola chiamata a `publish()`.

Le idee di `packages/transport/lib/src/failover/outbox_worker.dart` sono reference, non
codice da collegare allo stack canonico.

### Incremento H — Synchronization and conflict policy

**Dipendenza:** G.
**Outcome candidato:** primitive di sequenza, gap/replay/fork e API per policy
app-specific.
**Design separato:** pending commit/ACK-gating/fork detection MLS, perché
richiedono API Rust/WASM e decisioni sul formato.

### Incremento I — Metadata-minimizing routing

**Dipendenze:** D, G.
**Outcome candidato:** mailbox non identitaria, envelope esterno protetto,
chiavi esterne effimere, padding, timestamp policy e analisi dei metadati
residui.
**Human gate:** scelta e profilo concreto di NIP-44/NIP-59 o alternativa.

Il lavoro deve includere relay ostile, relay collusi, osservatore di rete e
push provider. Nascondere il mittente ma lasciare un destinatario stabile non
chiude H2.

### Incremento J — Tor/onion e notification profile

**Dipendenza:** I.
**Outcome candidato:** percorso documentato e testato via Tor Browser/onion o
client nativo, con leak tests; notifiche disattivabili e modalità di polling
manuale.
**Non-goal:** promessa contro osservatore globale.

### Incremento K — Recovery e multi-device

**Dipendenze:** B, D, H.
**Outcome candidato:** credenziali per device, elenco/revoca, rotazione,
recovery e history sync.
**Human gate:** stato MLS, formati persistenti, backup e compromissione.

Il backup Shamir Dart diventa un requisito da riesaminare, non la soluzione
automatica per MLS.

### Incremento L — Organization roles and custody

**Dipendenze:** D, F, K.
**Outcome candidato:** ruoli, assegnazione, revoca, separazione dei compiti e
audit amministrativo.
**Design separato:** threshold/multi-recipient/escrow.

### Incremento M — Anonymous return capability

**Dipendenze:** C, D, G, I; J per il profilo più forte.
**Outcome candidato:** capability ad alta entropia generata localmente,
mailbox/caso non collegabile, recovery UX e protezione brute force.
**Human gate:** rappresentazione, storage, protocollo e rotazione.

### Incremento N — Reference application: anonymous dialogue

**Dipendenze:** F, G, I, M; L se gestita da organizzazione.
**Outcome candidato:** applicazione `text-only` con invio, follow-up, stati
operatore, retention e avvisi di sicurezza.
**Non include:** dichiarazione di conformità o anonimato assoluto.

### Incremento O — Distribution assurance

Può avanzare in parallelo quando i file non si sovrappongono.
**Outcome candidato:** verifica della PWA e degli aggiornamenti, manifest di
release, trasparenza o firme appropriate, confronto indipendente degli
artefatti e profilo native high-assurance separato.

### Incremento P — Review e controlled pilot

**Dipendenze:** quelle richieste dal profilo scelto.
**Outcome candidato:** review indipendente del prodotto completo, remediation,
retest, pilot limitato e raccolta di metriche privacy-safe.

Nessun pilot high-risk deve iniziare con H1/H2 aperti o con job CI richiesti
falliti, cancellati, assenti o saltati senza autorizzazione.

## 5. Candidati per future Issue contrattuali

Ogni riga è intenzionalmente atomica e necessita di un contratto completo.

| Candidato | Outcome osservabile | Dipendenze | Gate sensibile probabile |
|---|---|---|---|
| `platform-context-model` | contesti e test cross-context | vault product design | crypto/persisted format |
| `platform-identity-profiles` | lifecycle persistent/application/case | context | crypto/vault |
| `platform-object-envelope` | schema dati-only versionato | context/identity | persisted/wire format |
| `platform-sdk-minimum` | API indipendente dalla chat | object envelope | shared interface |
| `transport-reliable-outbox` | ACK, retry, idempotenza crash-safe | product vault | workflow/possibly format |
| `transport-mailbox-privacy-design` | threat model e decision record | identity/reliable transport | crypto/protocol |
| `transport-mailbox-privacy-implementation` | metadata layer testata | design approvato | crypto/wire format |
| `platform-anonymous-capability-design` | capability e recovery model | context/identity | crypto/persisted format |
| `platform-anonymous-capability-runtime` | case mailbox riapribile | design + metadata | vault/protocol |
| `platform-organization-roles` | ruoli/revoca/audit | SDK/device identity | authorization/key custody |
| `app-anonymous-dialogue-mvp` | flusso text-only end-to-end | platform prerequisites | privacy/legal review |
| `distribution-authenticity-design` | modello first-load/update | reproducible builds | release architecture |
| `relay-reference-deployment` | configurazione riproducibile | metadata design | runtime manifests/secrets |
| `platform-independent-audit` | report, remediation e retest | candidate release | mandatory human review |

## 6. Criteri di non-regressione

L'evoluzione a piattaforma non deve:

- riattivare i claim “serverless”, “zero metadata” o “absolute anonymity”;
- creare una seconda implementazione crittografica di prodotto in Dart;
- esporre Root Key, KEK, password, plaintext o handle WASM alla pagina;
- riusare identità chat durevoli come identità anonime;
- rendere opzionale la verifica di firma degli eventi in ingresso;
- marcare consegna senza un'evidenza definita;
- migrare o cancellare dati senza rollback e human gate;
- usare analytics o terze parti silenziose nei profili sensibili;
- trattare un audit upstream come audit del prodotto completo;
- trasformare un documento esplorativo in una decisione crittografica.

## 7. Decisioni aperte da non anticipare

Restano esplicitamente aperti:

- derivazione e rappresentazione degli `application context`;
- forma e lifecycle delle mailbox;
- NIP-44/NIP-59, altro envelope o trasporto onion diretto;
- modello di gruppi e ruoli applicativi;
- formato degli oggetti e politica di version negotiation;
- schema di ACK e idempotenza;
- recovery secret e backup;
- threshold o multi-recipient custody;
- update transparency e autenticazione fra client;
- integrazione fra vault e dati reali della chat;
- standard di evidenza e timestamp;
- policy allegati e sanitizzazione.

La prossima azione utile non è implementarle insieme: è trasformare una
decisione per volta in Issue approvata, con threat model, non-goal, test e
rollback.
