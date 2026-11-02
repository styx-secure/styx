# Persistenza: mappa del chiamante e gap M3

PROTOTIPO — NON UNIRE. Nessuna modifica SDK, crypto, vendor, manifesti o contratti normativi.
Autorizzazione: card Kanban t_892091c7, corsia prototipo dell'owner.
Base letta: `m3/integration` a `3b314074568aa435572bca44ec4348e1a084c60e`.
Ramo separato: `proto/sdk-demo-2026-11`, base prototipo `55e6311e8a25d92e75bd02e1a995c3dd2bc88b0c`.
I sorgenti sotto indicati sono identici fra queste due basi; i riferimenti sono relativi alla radice del repository.

## A. Già ottenibile dalle porte del chiamante

| Funzione | Evidenza file:riga | Cosa fa il prototipo |
| --- | --- | --- |
| Identità Nostr stabile | `styx-js/src/sdk/client.js:149-153,1580-1596`; `docs/architecture/m3/sdk-interface.md:268-278` | `getPublicKey` e `sign` sono iniettati. Il seed casuale della demo rimane nel file cifrato; una chiave AES di 32 byte arriva da `DEMO_STATE_KEY`, non da argomenti/log. Stessa chiave pubblica dopo ogni riavvio del processo membro. |
| Esportazione/ripristino provider MLS | `styx-js/src/crypto/mls/mls-engine.js:51-91` | `serializeState`, `identityPublicKey`, `restore`, `loadSession` sono API già esistenti. Snapshot cifrato dopo ogni mutazione, prima di restituire dalla porta. L'intestazione alle righe 7-9 è obsoleta rispetto ai metodi effettivamente implementati. |
| Associazione contatto/gruppo e verifica del membro | `styx-js/src/crypto/mls/mls-engine.js:120-157,177-181`; `styx-js/src/crypto/mls/mls-session.js:49-60` | L'invitante conserva `groupId` restituito da `startSession`. L'invitato lo apprende dal primo payload applicativo autenticato e verifica `loadSession` e `peerIdentity`. Non si interpreta il blob del provider né si usano campi privati. |
| Copia persistente dei record outbox | `styx-js/src/sdk/delivery/outbox.js:730-733,944-966`; `docs/architecture/m3/sdk-interface.md:235-247`; `docs/architecture/m3/delivery-layer.md:226-228` | Le cinque operazioni storage salvano i record opachi e mantengono i `Uint8Array` alla rilettura. I record dei processi precedenti sono archiviati, non ripresi dall'SDK. Ogni processo nuovo usa un namespace nuovo e realmente vuoto. |
| Registro applicativo ricevuti | `styx-js/src/sdk/client.js:1204-1207`; `docs/architecture/m3/sdk-interface.md:220-227` | Il payload sintetico include un identificatore applicativo; la callback conserva un inbox cifrato e conta anche qualsiasi callback duplicata. Questo non rende atomica la ricezione SDK. |

Implementazione confinata a `styx-js/demo/sdk-two-machines/persistent-*`.
File locale cifrato con AES-256-GCM di Node, nonce casuale per scrittura, scrittura su file temporaneo, fsync, rename e fsync della directory; directory 0700 e file 0600. È un formato privato usa-e-getta del prototipo, NON un formato approvato Styx né una proposta crittografica per il prodotto.

## B. Mancante nell'SDK: non aggirato

### 1. Ripresa dell'outbox e delle ricevute

Evidenza: `styx-js/src/sdk/client.js:1569-1577`, `styx-js/src/sdk/delivery/outbox.js:595-604,2095-2123`; `docs/architecture/m3/sdk-interface.md:247`; `docs/architecture/m3/delivery-layer.md:24,130-131,228`.

`start()` rifiuta un archivio non vuoto con `E_SDK_STORAGE_NOT_EMPTY`, anche con record validi o terminali. Lo storage è una copia dello stato autorevole in memoria, non una sorgente di idratazione. La prova negativa `persistent-checks.mjs` conferma il rifiuto con il vero SDK, prima di qualsiasi connessione. Nessuna porta ripristina timer, tentativi, accettazioni, ricevute o `getDelivery` del processo precedente. Gli identificatori `d1`, `d2`, ecc. ricominciano ad ogni processo: l'archivio applicativo distingue anche il namespace.

Conseguenza nel prototipo: il record non terminale trovato dopo SIGKILL rimane archiviato e produce `FAILED_AFTER_RESTART_UNKNOWN_OUTCOME`, valore SOLO applicativo, non un nuovo stato SDK. Non significa «il destinatario non ha ricevuto»: può averlo già ricevuto. Nessuna nuova chiamata `send` per quel payload e nessuna promessa di ricevere la sua ricevuta tardiva. Il nuovo client usa un nuovo namespace; non si falsifica `list()` di quello precedente e non si spaccia questo per recovery nativo.

Proposta di contratto M3 da discutere: porta separata `recoveryStore` con `loadCheckpoint`, `commitTransition` e `resolvePending`; checkpoint versionato che identifichi client/identità/sessione, deliveryId persistente, evento firmato e ciphertext originali, accettazioni, scadenza assoluta e tentativi già consumati. Il contratto deve scegliere esplicitamente fra ripresa e fallimento durevole con esito sconosciuto. Nessuna cancellazione silenziosa, nessun reinvio con un nuovo identificatore, nessuna nuova cifratura dello stesso tentativo. Ripresa atomica e compatibilità con la versione del formato devono essere approvate prima dell'implementazione.

### 2. Cursori di catch-up per relay

Evidenza: `styx-js/src/sdk/delivery/catch-up.js:14-15,21-50,88-90`; `styx-js/src/sdk/client.js:1616-1641,1670-1672`; `docs/architecture/m3/delivery-layer.md:174-180`.

`syncedUntil` e `outstanding` sono solo nella closure, inizializzati a null. Il client non espone una porta di caricamento/salvataggio né un checkpoint. I tempi provengono dall'orologio locale; avanzamento tramite EOSE, non da `created_at` dell'evento. Il clock iniettato non è una porta di persistenza dei cursori.

Conseguenza: nessun cursore SDK persistito nel prototipo. Al riavvio si sottoscrive nuovamente senza cursore precedente. I replay di eventi già consumati possono fallire nella sessione MLS ripristinata; gli scarti non sono spacciati per nuove consegne. Non si intercettano o riscrivono i REQ per simulare una funzione assente.

Proposta: porta `catchUpStore.load(relayUrl, identity, subscriptionScope)` / `commit(...)`, con schema e versione; chiave per URL canonico e identità, non per posizione nell'array dei relay. Salvare solo un EOSE relativo ad una richiesta locale tracciata; margine di sovrapposizione e gestione del clock che arretra espliciti. Il cursore non deve avanzare oltre la lavorazione durevole degli eventi: EOSE da solo non attesta che callback e snapshot siano già su disco. Decidere nel contratto il coordinamento con inbox e stato MLS.

### 3. Inbox/ricevute e mutazione MLS non transazionali

Evidenza: `styx-js/src/sdk/delivery/receipts.js:478-486`; `styx-js/src/sdk/client.js:1204-1207`; `docs/architecture/m3/sdk-interface.md:225-227,253-256,327`; `docs/architecture/m3/delivery-layer.md:22-24,239-257`.

La finestra di deduplicazione e le ricevute dovute non sono porte durevoli. `MESSAGE_RECEIVED` espone solo mittente e payload, non un identificatore stabile dell'evento. `seal/open` possono salvare MLS, ma lo storage outbox e l'emissione della callback sono operazioni separate. La callback che genera errore è ignorata dall'SDK: non fornisce un commit o un ack applicativo durevole.

Conseguenza: lo snapshot del ratchet viene scritto prima della callback. Un crash in quella finestra può consumare un messaggio senza registrarlo nell'inbox applicativo; un crash fra cifratura e `put` può consumare una generazione senza creare un record. Le prove esercitano SIGKILL durante pubblicazione, non tutte le finestre possibili. Zero duplicati osservati NON dimostra exactly-once o assenza di perdita in generale. L'identificatore nel payload è una scelta del chiamante della demo.

Proposta: identità stabile dell'inbound nel contratto pubblico; transazione o journal che colleghi stato sessione, inbox e obbligo di ricevuta. Fissare l'ordine fra `prepareReceive`, `commitReceive`, notifica applicativa e invio ricevuta, con riconsegna dopo crash e ack esplicito se necessario. Decidere prima i requisiti di perdita/duplicazione, senza promettere exactly-once solo perché esiste un database.

### 4. groupId dell'invitato e checkpoint dell'invito

Evidenza: `styx-js/src/crypto/mls/mls-engine.js:85-90,124-133,146-157`; `styx-js/vendor/openmls-wasm/openmls_wasm.js:128-155`; `docs/architecture/m3/sdk-interface.md:262-266`.

Il join restituisce `MlsSession` senza un accessor pubblico del groupId; la porta SDK restituisce solo `true`. `loadSession` richiede invece il groupId. L'invitante lo conosce; l'invitato no. Il prototipo lo comunica nel primo messaggio applicativo cifrato e autenticato, mantenendo un normale payload SDK. Nessun protocollo wire o invito SDK è modificato.

Limite: crash dell'invitato dopo il join ma prima di tale messaggio non coperto. L'SDK non espone un ripristino della fase d'invito pendente o del suo KeyPackageEventId. Il supervisore riavvia solo processi con gruppo già stabilito e associazione già salvata.

Proposta: checkpoint opaco/versionato della sessione e accessor/ritorno pubblico del binding contatto/gruppo; se richiede modifica di engine/vendor serve una card e revisione proprie, non una lettura dei campi `_group`. Gli inviti incompleti devono riprendere o fallire con un esito esplicito senza sostituire un gruppo esistente.

### 5. Provisioning della chiave e ciclo di vita

Evidenza: `docs/architecture/m3/sdk-interface.md:275-278` e `styx-js/src/crypto/mls/mls-engine.js:184-195`.

L'SDK non gestisce la chiave di cifratura a riposo. La demo la genera nella memoria del supervisore su ciascun host e la passa nell'ambiente dei processi membri. Sopravvive ai riavvii/SIGKILL dei membri, non alla morte del supervisore o a un reboot della macchina senza reprovisioning esterno. Un key manager di prodotto non è realizzato qui. La rimozione dei file verifica la scomparsa del percorso, non cancellazione forense di SSD, cache, snapshot o copie in RAM. L'engine documenta inoltre residui di gruppi rimossi nel provider serializzato.

Proposta: contratto del key provider, rotazione/errore/indisponibilità, cancellazione e versioni del checkpoint da approvare separatamente; nessun riuso automatico di stato incompatibile e nessun reset silenzioso a identità nuova.

## Test di accettazione da fissare per la fase normale

1. Riavvio pulito di ciascun nodo: stessa identità, gruppo e impronta; nessun nuovo invito; invii e ricevute prima/dopo contati.
2. SIGKILL ai confini prima/dopo seal, put, firma, pubblicazione, accettazione, open, commit inbox, callback, firma/pubblicazione ricevuta; nessun successo inventato. Conservare tutti i tentativi falliti.
3. Pendenti: ripresa con stessi byte/eventId e tentativi/scadenza conservati, oppure fallimento durevole con esito sconosciuto; niente duplicazioni applicative introdotte dal recovery.
4. Ripristino di ricevute dovute e ricevute tardive, record terminali, deliveryId ripetuti da processi differenti e clock che arretra.
5. Cursori per relay: riordino/aggiunta/rimozione URL, EOSE perso/tardivo/non corrispondente, crash durante catch-up; mai saltare inbox non committato.
6. Stato cifrato alterato, troncato, chiave errata/assente, versione incompatibile, spazio disco esaurito e errore fsync/rename: fallimento esplicito, nessun reset a vuoto.
7. Associazione gruppo dell'invitato già durevole subito dopo join e invito interrotto senza ripair silenzioso.
8. Ripetere loopback e due reti reali; verificare rimozione dello stato sintetico e invarianti dei servizi host.

Questa è una bozza per la successiva issue di contratto e relativa review ordinaria. Non apre un gate, non ratifica formati o interfacce e non autorizza modifiche SDK. Le prove attuali e i loro limiti sono in `RISULTATI-PERSISTENZA.IT.md` nel workspace della card; nessuna review LLM e nessun merge.

## C. Supplemento misurato: destinatario spento

Card `t_83b2206a`, base prototipo `971e23bfd260a144e9409aaf9f01cc7fd9294c8d`. Dettaglio, comandi, tentativi e limiti in `DESTINATARIO-SPENTO.IT.md`; numeri ricalcolabili da `offline-verify.py` e `OFFLINE-EVIDENCE-SUMMARY.json`. Le sezioni precedenti rimangono valide: questi risultati non colmano i gap di contratto.

Alice AI395 resta accesa; Bob invitato MVLINNA termina pulitamente dopo invito e m1/m2 con ricevuta. Alice invia m3/m4 offline, entrambi accettati da tutti e tre i relay. Scadenza del nuovo harness: 90 s reali. Nessun nuovo invito, identità/gruppo/impronta stabili al ripristino del file cifrato. Sempre due macchine, inclusa la variante con tre relay locali AI395 raggiunti da Bob via tunnel SSH.

| Variante | Ripetizioni | Bob fermo | Esito m3/m4 dopo restart | Frame tornati per m1/m2/m3/m4 | Scarti Bob per prova |
| --- | ---: | --- | --- | --- | --- |
| pubblica, prima della deadline | 3 | 65,042–65,045 s | una callback ciascuno, ricevute prima della deadline | 12 / 12 / 12 / 12 | 2 E_SDK_SESSION_FAILED |
| pubblica, oltre deadline | 3 | 105,034–105,042 s | una callback ciascuno, prime ricevute tardive ma FAILED_NO_RECEIPT invariato | 6 / 6 / 6 / 6 | 2 E_SDK_SESSION_FAILED |
| locale AI395, prima della deadline | 1 | 65,055 s | una callback ciascuno, ricevute prima della deadline | 12 / 12 / 12 / 12 | 2 E_SDK_SESSION_FAILED |

Totali finali: 14 messaggi offline ricevuti, 28 callback totali senza duplicati, 264 frame di quattro eventi distinti per prova (28 fra le sette prove), 14 E_SDK_SESSION_FAILED. m1/m2 ritornano realmente dai relay senza nuove callback. I codici SDK di scarto non espongono eventId: si conservano separatamente conteggi per evento e codici per generazione, senza attribuzioni arbitrarie. Le sei prime ricevute tardive reali arrivano ai socket di Alice, ma non riaprono gli stati terminali; lastCode resta null, nessun INBOUND_DISCARDED Alice. È coerente con `styx-js/src/sdk/delivery/outbox.js:2030-2067`, che salta i terminali e rifiuta ricevute oltre deadline. Le repliche di una ricevuta già vista non sono altre prime ricevute tardive.

Conseguenze concrete per i gap:
- Cursori (§B.2): i primi REQ reali dopo restart sono senza since. Il recupero dei due eventi nuovi funziona nelle prove, ma ripresenta anche i consumati; nessun cursore persistito/simulato e nessun REQ riscritto o sostituito. I frame sono osservati passivamente e inoltrati invariati.
- Ricezione (§B.3): nessuna callback duplicata osservata; resta la mancanza di transazione fra ratchet, inbox e ricevuta. Queste prove non dimostrano exactly-once né coprono altre finestre di crash.
- Outbox (§B.1): Alice non riparte; la ricevuta tardiva non cambia FAILED_NO_RECEIPT nello stesso processo. Questo non dimostra recovery dell'outbox. Il prototipo osserva soltanto il binding pubblico deliveryId/eventId durante put/update: gli event/ciphertext dei terminali vengono azzerati dall'SDK (`outbox.js:1016-1018`), quindi non si possono ricavare dopo dalla sola fotografia terminale.
- Commit MLS offline: non applicabile. `persistent-ports.mjs:45-65`, `mls-engine.js:120-133`, `mls-session.js:22-37` e il vendor `patch/lib.rs:1428-1472`, tutti letti senza modifiche, mostrano solo il commit iniziale di aggiunta; dopo pairing il prototipo genera messaggi applicativi, non rekey/commit. Nessun commit artificiale introdotto.

Tre preliminari completi e un nuovo fallimento DNS prima dei membri sono conservati fuori dai totali finali; l'originale interrotto persistence-offline-01 è immutato via hash. Cleanup finale dei percorsi sintetici verificato su entrambi gli host, compreso il vecchio residuo cifrato, senza toccare le evidenze. Minimo MemAvailable AI395 84.657.725.440 byte, servizi invariati, lock/nice 19/ionice idle per ogni prova; zero differenze nei 92 file protetti e confronto SHA-256 di 97 file fra gli host. Nessuna modifica SDK, crypto, vendor, manifesti, lockfile o workflow; nessuna PR/merge/review LLM.
