# Destinatario spento: supplemento di persistenza

PROTOTIPO — NON UNIRE. Card `t_83b2206a`, base `971e23bfd260a144e9409aaf9f01cc7fd9294c8d`, solo ramo `proto/sdk-demo-2026-11`. Nessuna PR, merge, release o review LLM.

## Misura reale

Alice è su AI395; Bob, invitato, è su MVLINNA in tutte le prove, inclusa quella locale. Dopo invito e m1/m2 con ricevuta, Bob termina con `shutdown()`, snapshot e uscita 0; il supervisore conserva la chiave del file cifrato in memoria. Alice rimane accesa, invia m3 e m4 mentre nessun processo membro Bob è attivo. I due invii possono restare pendenti insieme. Bob riparte dallo stato su disco, senza nuovo invito, dopo circa 65 oppure 105 secondi. Non è un reboot fisico degli host.

La scadenza reale configurata nel nuovo harness è 90.000 ms, `maxAttempts: 5`, `perRelayTimeoutMs: 12000`: consente una ripartenza dopo almeno 60 s ma prima della scadenza. L'orologio è Date.now/timer reali, non accelerato o simulato. La seconda variante aspetta oltre la scadenza. Dopo il ritorno di `start()` di Bob si osservano altri 32 s. Durante `start()` possono già arrivare eventi e callback: il conteggio usa tutta la generazione 2, non solo gli eventi successivi al log `started`.

Tre ripetizioni finali per variante sui relay pubblici `wss://relay.nostr.net`, `wss://relay.primal.net`, `wss://offchain.pub`. La variante prima della scadenza è ripetuta anche su tre relay WebSocket reali, con storie separate e verifica firme, su AI395. Bob vi accede con tre tunnel SSH locali; entrambi i membri rimangono su macchine diverse.

## Conteggi dai JSON grezzi

| Esecuzione | Relay | Bob spento (s) | Frame tornati per m1/m2/m3/m4 | Callback nuove m3/m4 | Esito finale Alice m3/m4 |
| --- | --- | ---: | --- | --- | --- |
| offline-public-before-04 | pubblici | 65,043 | 12 / 12 / 12 / 12 | 1 / 1 | ricevuta / ricevuta |
| offline-public-before-05 | pubblici | 65,042 | 12 / 12 / 12 / 12 | 1 / 1 | ricevuta / ricevuta |
| offline-public-before-06 | pubblici | 65,045 | 12 / 12 / 12 / 12 | 1 / 1 | ricevuta / ricevuta |
| offline-public-after-02 | pubblici | 105,042 | 6 / 6 / 6 / 6 | 1 / 1 | FAILED_NO_RECEIPT / FAILED_NO_RECEIPT |
| offline-public-after-03 | pubblici | 105,034 | 6 / 6 / 6 / 6 | 1 / 1 | FAILED_NO_RECEIPT / FAILED_NO_RECEIPT |
| offline-public-after-04 | pubblici | 105,040 | 6 / 6 / 6 / 6 | 1 / 1 | FAILED_NO_RECEIPT / FAILED_NO_RECEIPT |
| offline-local-before-01 | locali AI395 | 65,055 | 12 / 12 / 12 / 12 | 1 / 1 | ricevuta / ricevuta |

I frame sono tutte le occorrenze in entrata ai socket di Bob nella generazione ripristinata, compresi più relay e successivi catch-up, non eventi unici né callback. In ogni riga tornano quattro eventId distinti: i due già consumati e i due offline. La diversa quantità di frame è osservata nella finestra del test, non una garanzia di periodicità o conservazione del relay. Il dettaglio per relay e l'associazione identificatore applicativo → deliveryId → eventId sono in `OFFLINE-EVIDENCE-SUMMARY.json`.

Totali delle sole sette finali: 264 frame storici per 28 eventi distinti fra le esecuzioni; 28 callback applicative totali, di cui 14 per m3/m4 dopo restart; zero callback duplicate e zero nuove callback di m1/m2 dopo restart. Ogni esecuzione emette due `E_SDK_SESSION_FAILED` su Bob ripristinato (14 totali). L'evento SDK di scarto espone solo il codice, non eventId: i conteggi per ID vengono dai frame/callback, i codici di scarto sono aggregati per generazione, senza inventare un binding individuale non esposto.

Per tutti i 14 invii offline gli `OK true` originali dimostrano accettazione da tutti e tre i relay prima del riavvio. Nella variante 65 s, lo snapshot pre-riavvio mostra `RELAY_ACCEPTED_AWAITING_RECEIPT`, poi la prima ricevuta arriva prima di `deadlineAt` e il terminale è `RECIPIENT_RECEIPT_RECEIVED`.

Nella variante 105 s, m3/m4 diventano `FAILED_NO_RECEIPT` mentre Bob è ancora fermo; il relativo `lastCode` è null, non un codice di errore aggiunto dall'harness. Dopo il ripristino Bob riceve entrambi e Alice riceve davvero i kind 4742 con autore Bob e tag `e` degli eventi originali: sei prime ricevute tardive, una per messaggio offline delle tre prove. Gli stati restano `FAILED_NO_RECEIPT` anche nello snapshot finale. Alice non emette `INBOUND_DISCARDED` per questi casi. Le successive repliche di una ricevuta già osservata non vengono contate come altre prime ricevute tardive.

## Nessun commit MLS post-invito

Verifica in sola lettura del prototipo e del motore:
- `persistent-ports.mjs:45-65`: dopo start/join usa soltanto encrypt/decrypt; non espone un'operazione rekey/commit.
- `styx-js/src/crypto/mls/mls-engine.js:120-133`: `propose_and_commit_add` e `merge_pending_commit` appartengono alla creazione iniziale; al chiamante torna il Welcome con ratchet tree e groupId, non il commit iniziale.
- `styx-js/src/crypto/mls/mls-session.js:22-37`: encrypt chiama `create_message`; decrypt può applicare handshake ricevuti, non li genera.
- `styx-js/vendor/openmls-wasm/patch/lib.rs:1428-1472`: generazione proposal/commit add e creazione del messaggio applicativo sono operazioni separate; nessuna ricompilazione o modifica vendor.

La variante «commit pubblicato mentre Bob è fermo» non è applicabile a questo prototipo. Non è stato aggiunto un commit artificiale. Per le ricevute tardive è coerente il motore delivery: `styx-js/src/sdk/delivery/outbox.js:2030-2067` salta i record terminali e rifiuta le ricevute oltre deadline.

## Osservazione e limiti

Nuovi file confinati alla demo: `offline-member.mjs`, `offline-host.py`, `offline-run.py`, `offline-verify.py`. Le porte persistenti preesistenti e l'SDK rimangono invariati. Il socket osserva e conserva i frame originali, inoltrando gli stessi byte: nessun REQ viene riscritto, sostituito, soppresso o riprodotto; nessun cursore viene salvato, simulato o introdotto. I primi REQ reali di Bob ripristinato sono senza `since`. L'osservatore storage conserva soltanto il binding pubblico deliveryId/eventId quando l'SDK lo presenta a put/update; inoltra gli argomenti originali e non cambia record, stati o ricevute.

Identità, gruppo e impronta MLS invariati dopo il riavvio; una sola coppia di eventi `paired` per esecuzione. Zero duplicati osservati non è exactly-once: non copre finestre di crash diverse, atomicità inbox/ratchet/ricevuta o conservazione arbitraria dei relay. L'outbox di Alice non è riavviata: qui la ricevuta tardiva riguarda una consegna scaduta nello stesso processo, non recovery di un'outbox precedente. Le conclusioni sono misure di questo harness, non garanzie aggiunte al contratto SDK.

## Tentativi conservati e cleanup

Oltre alle sette finali sono conservate tre prove preliminari complete (`offline-public-before-02`, `03`, `offline-public-after-01`), escluse dai totali finali. La prima provava il flusso; le altre hanno mostrato che leggere eventId solo dallo snapshot terminale non basta: l'SDK azzera event/ciphertext a terminale (`outbox.js:1016-1018`). Perciò è stato aggiunto il solo osservatore del binding e rifatta l'intera serie finale.

Fallimenti conservati:
- `persistence-offline-01/` e console: il tentativo precedente interrotto rimane byte per byte uguale, verificato con `offline-interrupted-hashes.json`.
- `offline-public-before-01/summary.json` e console: DNS di api.ipify.org fallito su AI395 prima dell'avvio dei membri. Nuova directory e endpoint checkip.amazonaws.com; delle reti si conserva solo il booleano di egress distinto, vero in tutte le prove pubbliche.
- `offline-verification-partial-01.log`: verificatore fermato perché il JSON del supervisore Alice non era ancora copiato da AI395. Copiati gli originali, verifica ripetuta con successo e log precedenti conservati.
- Primo comando di readback del cleanup remoto fallito per quoting dopo aver già rimosso un vecchio residuo sintetico. Corretto con `offline-final-checks.py`; nessuna cancellazione aggiuntiva e verifica finale riuscita.

Nessun processo membro, supervisore, relay di test o tunnel rimasto. Minimo MemAvailable AI395 nelle sette finali: 84.657.725.440 byte, sempre sopra 15.000.000.000. Nice 19, ionice idle e lock `/home/mverde/reviews/styx-kanban/.ai395-test.lock` mantenuto dal supervisore Alice per tutta ogni prova, inclusi i relay locali. `llama-swap` resta attivo PID 7744; ds4-glm-full e ComfyUI letti senza modificarli. PC4070TI mai contattata. MVLINNA esegue solo Bob e il coordinamento leggero.

Tutti i supervisori verificano directory 0700, stato cifrato 0600 e rimozione dei propri percorsi. Rimosso anche l'unico vecchio stato sintetico residuo del tentativo interrotto, distinto dalle sue evidenze conservate. Readback finale: zero percorsi `sdk-persistence-*` su entrambi gli host. È rimozione dei percorsi, non secure erase. Nessuno stato cifrato, seed o chiave in evidenza. Confronto SHA-256 di 97 file fra gli host: zero differenze; confronto finale dei 92 file protetti con la baseline: invariati.

## Riproduzione e collocazione

Dal workspace della card, con nuova directory di output a ogni tentativo:

    python3 styx-nov/styx-js/demo/sdk-two-machines/offline-run.py --variant before-deadline --relay-mode public --out "$PWD/offline-public-before-NUOVA"
    python3 styx-nov/styx-js/demo/sdk-two-machines/offline-run.py --variant after-deadline --relay-mode public --out "$PWD/offline-public-after-NUOVA"
    python3 styx-nov/styx-js/demo/sdk-two-machines/offline-run.py --variant before-deadline --relay-mode local --out "$PWD/offline-local-before-NUOVA"

Distribuire prima `offline-member.mjs` e `offline-host.py` nella demo AI395 documentata dal prototipo precedente. Il controller conserva tutti gli eventi nel proprio `controller.jsonl`; i file originali `inviter-events.jsonl` e `inviter-host.json` sono copiati in aggiunta da AI395 a fine prova. Nessuno stato di protocollo passa tra i membri attraverso il controller. Il verificatore finale rilegge questi originali e richiede le sette directory finali indicate sopra, i tre preliminari, i manifesti dell'interrotto e il precedente tentativo interrotto:

    python3 styx-nov/styx-js/demo/sdk-two-machines/offline-verify.py --root "$PWD" --output offline-verification-final.json
    python3 offline-final-checks.py

Evidenze complete nel workspace `/home/mverde/reviews/styx-kanban/workspaces/sdk-proto-2026-10`: directory `offline-*`, `offline-verification-final.json`, manifesti `offline-source-parity.json`, `offline-protected-before.json`, `offline-protected-after.json`, `offline-cleanup-final.json`, `offline-static-inspection.json`. Archivio consegnabile: `PERSISTENZA-OFFLINE-EVIDENZE.zip`. Il JSON aggregato versionato accanto a questo documento è ricalcolato dai grezzi, non una sostituzione dei log. Nessuna suite generale prodotto è dichiarata: eseguiti scenari reali, controlli sintattici e verifiche offline mirate.
