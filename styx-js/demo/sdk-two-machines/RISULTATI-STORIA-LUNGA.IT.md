# Risultati: storia lunga e destinatario senza ascoltatore

Prototipo separato, non destinato al merge. Misure su AI395; SDK `m3/integration` @ `3b314074` invariato, base prototipo `20e57c2eb5211fdf2de0c925dd800bb5593e1322`.

## Metodo e perimetro

La storia è reale: 5.000 invii tramite SDK, crittografia MLS reale e relative 5.000 ricevute firmate. Ai checkpoint 100/500/1.000/2.000/5.000 si copiano gli stati MLS persistiti e cifrati di entrambi i membri. Ogni prova ripristina una copia separata dello stesso checkpoint: niente nuova identità o invito al riavvio. Le prove usano quattro scenari indipendenti concorrenti, tutti nello stesso lock; i tempi non sono un benchmark a macchina esclusiva.

Ogni relay conserva N eventi 4741 Alice→Bob più N ricevute 4742 Bob→Alice. Il filtro #p di Bob seleziona N messaggi, NON 2N frame: le ricevute sono indirizzate ad Alice. La storia è dello stesso gruppo; durante la generazione entrambi gli orologi applicativi hanno un offset coerente di −3.600.000 ms, già dall’avvio. Al riavvio gli orologi sono quelli reali: questo isola storia più vecchia del margine di 120 s da messaggi nuovi. Non rappresenta una storia tutta concentrata negli ultimi due minuti.

Il nuovo evento è prodotto e firmato dallo SDK di Alice prima dell’avvio di Bob, ma il relay ne trattiene pubblicazione e OK. Il primo REQ di Bob lo rende disponibile in tutti i relay durante start(); nella modalità oldest è collocato dopo la storia, nella modalità newest prima. È un caso sincronizzato di pubblicazione durante il riavvio, non un invio casuale sulla rete. Una sola nuova pubblicazione, maxAttempts=1: nessun reinvio del mittente può mascherare la perdita; il catch-up resta quello reale ogni 10 s.

Configurazione: perRelayTimeoutMs=12000 (default SDK), deadlineMs=60000, receiptMode=RECIPIENT_RECEIPT. start() attende sempre la fase di connessione di 12 s, anche sul loopback. Il primo catch-up periodico arriva quindi circa 22 s dopo il primo REQ, cioè circa 10 s dopo la risoluzione di start(). La finestra termina 12,5 s dopo start(): copre il primo catch-up. Nessuna conclusione di perdita permanente oltre questa finestra.

Osservazione della coda: unicamente nell’harness, JSON.parse aggiunge a ciascun frame un getter osservativo per sig, con le stesse sette chiavi e gli stessi valori. Il primo accesso avviene in receipts.validateEvent (righe 647–656), dopo l’estrazione dalla coda; non in catchUp.observe né nel trasporto. Il numero di sequenza distingue le copie del medesimo id. Frame arrivati al socket ma mai validati sono contati come cadute pre-validazione; si verifica inoltre che l’ultima validazione preceda lo snapshot di oltre 1 s. SDK, trasporto, crittografia e vendor non sono modificati. Un controllo aggiuntivo senza getter verifica il comportamento senza questa osservazione; non può misurare direttamente le cadute.

Wall time: dalla chiamata start() di Bob alla callback applicativa del nuovo messaggio. CPU: user+system del solo processo Bob, dall’inizio dell’harness membro (include ripristino MLS e osservazione); non CPU del relay o Alice. Le colonne frame EVENT ed errori riportano totale della finestra / numero fino alla consegna del nuovo. I file per caso conservano tutti gli identificativi, copie e tempi.

Macchina: AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, 32 processori logici; Node v24.18.0; Linux-7.0.0-38-generic-x86_64-with-glibc2.43. Integrità: 80 file protetti confrontati con il clone autorizzato, zero divergenze.

## Matrice completa

`all` = nessun tetto; `cap500` = massimo 500 risultati per filtro; `oldest` = ordine di generazione; `newest` = created_at decrescente, spareggio id decrescente. Il tetto agisce sui risultati storici di ciascun REQ, non sulla capacità totale né sulle notifiche live.

| Storia N | Relay | Politica | Frame | E_SDK_SESSION_FAILED | Cadute storia / nuovo | Nuovo: copie | Tempo ms | CPU ms fino al nuovo |
|---:|---:|---|---:|---:|---:|---:|---:|---:|
| 100 | 1 | all-newest | 102 / 74 | 100 / 0 | 0 / 0 | 1 | 33.1 | 111.1 |
| 100 | 1 | all-oldest | 102 / 101 | 100 / 100 | 0 / 0 | 1 | 206.4 | 322.8 |
| 100 | 1 | cap500-newest | 102 / 37 | 100 / 0 | 0 / 0 | 1 | 31.2 | 108.8 |
| 100 | 1 | cap500-oldest | 102 / 101 | 100 / 100 | 0 / 0 | 1 | 197.2 | 318.7 |
| 100 | 3 | all-newest | 306 / 74 | 100 / 0 | 0 / 0 | 1 | 43.7 | 125.0 |
| 100 | 3 | all-oldest | 306 / 101 | 100 / 100 | 0 / 0 | 1 | 210.8 | 329.3 |
| 100 | 3 | cap500-newest | 306 / 74 | 100 / 0 | 0 / 0 | 1 | 55.0 | 121.1 |
| 100 | 3 | cap500-oldest | 306 / 101 | 100 / 100 | 0 / 0 | 1 | 204.0 | 306.5 |
| 500 | 1 | all-newest | 502 / 74 | 500 / 0 | 0 / 0 | 1 | 34.7 | 105.6 |
| 500 | 1 | all-oldest | 502 / 501 | 500 / 500 | 0 / 0 | 1 | 654.0 | 820.4 |
| 500 | 1 | cap500-newest | 501 / 74 | 499 / 0 | 0 / 0 | 1 | 37.8 | 118.9 |
| 500 | 1 | cap500-oldest | 501 / 501 | 500 / 500 | 0 / 0 | 1 | 22042.5 | 846.6 |
| 500 | 3 | all-newest | 1506 / 74 | 500 / 0 | 0 / 0 | 1 | 40.6 | 110.2 |
| 500 | 3 | all-oldest | 1506 / 863 | 500 / 500 | 0 / 0 | 1 | 1021.5 | 1166.9 |
| 500 | 3 | cap500-newest | 1503 / 74 | 499 / 0 | 0 / 0 | 1 | 39.4 | 87.7 |
| 500 | 3 | cap500-oldest | 1503 / 1501 | 500 / 500 | 0 / 0 | 1 | 22124.3 | 1855.5 |
| 1000 | 1 | all-newest | 1002 / 74 | 1000 / 0 | 0 / 0 | 1 | 37.1 | 113.5 |
| 1000 | 1 | all-oldest | 1002 / 1001 | 1000 / 1000 | 0 / 0 | 1 | 1193.1 | 1384.9 |
| 1000 | 1 | cap500-newest | 501 / 74 | 499 / 0 | 0 / 0 | 1 | 39.1 | 118.2 |
| 1000 | 1 | cap500-oldest | 501 / 501 | 500 / 500 | 0 / 0 | 1 | 22041.4 | 811.5 |
| 1000 | 3 | all-newest | 3006 / 74 | 1000 / 0 | 0 / 0 | 1 | 42.1 | 113.7 |
| 1000 | 3 | all-oldest | 3006 / 2401 | 1000 / 1000 | 0 / 0 | 1 | 2841.8 | 2995.1 |
| 1000 | 3 | cap500-newest | 1503 / 74 | 499 / 0 | 0 / 0 | 1 | 41.3 | 114.4 |
| 1000 | 3 | cap500-oldest | 1503 / 1501 | 500 / 500 | 0 / 0 | 1 | 22043.3 | 1912.3 |
| 2000 | 1 | all-newest | 2002 / 74 | 2000 / 0 | 0 / 0 | 1 | 42.9 | 111.2 |
| 2000 | 1 | all-oldest | 2002 / 2001 | 2000 / 2000 | 0 / 0 | 1 | 2285.9 | 2513.0 |
| 2000 | 1 | cap500-newest | 501 / 74 | 499 / 0 | 0 / 0 | 1 | 39.3 | 110.3 |
| 2000 | 1 | cap500-oldest | 501 / 501 | 500 / 500 | 0 / 0 | 1 | 22042.6 | 823.9 |
| 2000 | 3 | all-newest | 6006 / 74 | 2000 / 0 | 0 / 0 | 1 | 48.9 | 115.3 |
| 2000 | 3 | all-oldest | 6006 / 5469 | 2000 / 2000 | 0 / 0 | 1 | 6090.0 | 6407.5 |
| 2000 | 3 | cap500-newest | 1503 / 74 | 499 / 0 | 0 / 0 | 1 | 46.3 | 117.9 |
| 2000 | 3 | cap500-oldest | 1503 / 1501 | 500 / 500 | 0 / 0 | 1 | 22039.7 | 1939.4 |
| 5000 | 1 | all-newest | 5002 / 74 | 5001 / 0 | 0 / 0 | 1 | 62.1 | 109.5 |
| 5000 | 1 | all-oldest | 5002 / 5001 | 5000 / 5000 | 0 / 0 | 1 | 5536.7 | 5790.7 |
| 5000 | 1 | cap500-newest | 501 / 74 | 499 / 0 | 0 / 0 | 1 | 67.8 | 99.8 |
| 5000 | 1 | cap500-oldest | 501 / 501 | 500 / 500 | 0 / 0 | 1 | 22047.5 | 753.1 |
| 5000 | 3 | all-newest | 15006 / 74 | 5001 / 0 | 0 / 0 | 1 | 55.0 | 103.8 |
| 5000 | 3 | all-oldest | 15006 / 14675 | 5000 / 5000 | 0 / 0 | 1 | 15758.3 | 16300.6 |
| 5000 | 3 | cap500-newest | 1503 / 74 | 499 / 0 | 0 / 0 | 1 | 41.0 | 112.4 |
| 5000 | 3 | cap500-oldest | 1503 / 1501 | 500 / 500 | 0 / 0 | 1 | 22128.9 | 2027.6 |

## Lettura dei risultati

Casi principali: 40; consegna del nuovo nella finestra: 40; casi con almeno una caduta del nuovo: 0; casi con cadute storiche: 0.

Una caduta riguarda un frame, non necessariamente l’identificativo definitivamente perduto: altre copie o il catch-up possono recuperarlo. Le ricevute e i duplicati passano comunque attraverso la validazione prima della deduplicazione. EOSE fa avanzare il cursore con l’orologio locale, non con l’esito delle elaborazioni. Queste misure mostrano il comportamento del caso qui costruito, non una garanzia generale di recupero dopo overflow, troncamento o retention.

### Controllo senza getter

n5000-r3-all-oldest-unobserved: frame=15006, errori sessione=5000, copie nuove=1, tempo=15210.842109 ms. Nessuna misura di caduta pre-validazione in questo controllo.

## Diagnosi separata della coda a 1.024

Nella matrice WebSocket ordinaria non si osserva overflow: non basta sommare i frame dell’intera risposta per dedurre il picco di coda. Per verificare il limite in modo riproducibile, una seconda esecuzione genera 2.000 messaggi e ricevute reali. Solo nel suo adattatore socket trattiene i frame EVENT fino a EOSE, poi li inoltra tutti nello stesso turno JavaScript. Il contenuto e lo SDK rimangono invariati. Questa è una condizione di ingresso forzata, NON una misura della segmentazione TCP ordinaria né la prova che i relay pubblici si comportino così.

| Relay | Ordine | Frame | Validati | Cadute storia / nuovo | Copie nuove | Tempo al nuovo ms |
|---:|---|---:|---:|---:|---:|---:|
| 1 | all-newest | 2002 | 1025 | 977 / 0 | 1 | 123.877327 |
| 1 | all-oldest | 2002 | 1025 | 976 / 1 | 1 | 22040.571635 |
| 3 | all-newest | 6006 | 3075 | 2931 / 0 | 1 | 121.56497800000002 |
| 3 | all-oldest | 6006 | 3075 | 2928 / 3 | 1 | 22031.438335 |

Gli identificativi delle copie scartate sono in burst/n2000-r*-*.json, campo dropped, e quelli della matrice ordinaria sono anche aggregati in final2/per-id-counts.json. Cadute del nuovo seguite da consegna misurano recupero da altra copia o dal catch-up: non vanno chiamate perdita definitiva.

Comando della diagnosi (stesso guard e stesso lock):

    EVIDENCE_DIR=/home/mverde/reviews/sdk-demo-2026-11/long-history-evidence/burst SIZES=2000 BURST_ONLY=1 DEMO_NODE=$HOME/.nvm/versions/node/v24.18.0/bin/node nice -n 19 ionice -c 3 python3 styx-js/demo/sdk-two-machines/long-history-guard.py

## Nessuno in ascolto

| Listener dopo start() | Decifrati | Senza listener | Consegnati all’app dopo iscrizione | Ricevute firmate |
|---:|---:|---:|---:|---:|
| 1000 ms | 1 | 1 | 0 | 1 |
| 10000 ms | 1 | 1 | 0 | 1 |

Non è stato registrato un listener spia: non avrebbe più rappresentato “nessuno in ascolto”. Il conteggio usa open riuscito con plaintext valido, listener=false, e relativa ricevuta pubblicata; nel codice invariato receipts.js:966–971 l’emissione precede la ricevuta. client.js:1141–1158 fotografa l’audience presente in quel momento, senza replay per ascoltatori futuri. Le evidenze mostrano inoltre il ritorno del messaggio dal catch-up senza una successiva consegna applicativa. Questo è un messaggio perso per l’applicazione nonostante la ricevuta al mittente, non un errore di decifratura.

## Limiti dei relay: fonti primarie, sola lettura

- strfry: [configurazione](https://github.com/hoytech/strfry/blob/master/strfry.conf), maxFilterLimit=500; [parser filtri](https://github.com/hoytech/strfry/blob/master/src/filters.h). Copie integrali ed ETag in sources-final/.
- nostr-rs-relay non ha genericamente un default 500: [SQLite](https://github.com/scsibug/nostr-rs-relay/blob/master/src/repo/sqlite.rs), righe 1149–1155, aggiunge LIMIT soltanto se f.limit è presente e altrimenti ordina ASC; [PostgreSQL](https://github.com/scsibug/nostr-rs-relay/blob/master/src/repo/postgres.rs), righe 891–899, applica invece ASC LIMIT 1000 senza limit. [Configurazione](https://github.com/scsibug/nostr-rs-relay/blob/master/config.toml). Pertanto la variante a 500 è un modello strfry, non una proprietà universale dei due server.
- NIP-11 distingue max_limit (tetto a limit esplicito) da default_limit (senza limit): [specifica](https://github.com/nostr-protocol/nips/blob/master/11.md). Nessun default_limit può essere dedotto automaticamente dal solo max_limit pubblicizzato.

| Relay pubblico | max_limit | max_subscriptions | default_limit | retention |
|---|---:|---:|---|---|
| relay.nostr.net | 100 | 100 | non dichiarato | non dichiarata |
| relay.primal.net | 500 | 20 | non dichiarato | non dichiarata |
| offchain.pub | 500 | 20 | non dichiarato | non dichiarata |

Acquisizione HTTPS con Accept: application/nostr+json; richieste aggiuntive alle sole pagine HTML dei relay. Nessun collegamento WebSocket pubblico né pubblicazione sintetica. Nei documenti e nelle pagine relay acquisite non risultano politiche di retention o link specifici a tali politiche; ciò non prova conservazione illimitata né l’assenza di altre politiche sul sito dell’operatore. Data, URL e intestazioni HTTP sono conservati in sources-final/sources.json.

## Riproduzione e salvaguardie

Comando effettivo da MVLINNA (coordinamento):

    ssh AI395 'cd /home/mverde/reviews/sdk-demo-2026-11/styx && EVIDENCE_DIR=/home/mverde/reviews/sdk-demo-2026-11/long-history-evidence/final2 DEMO_NODE=$HOME/.nvm/versions/node/v24.18.0/bin/node nice -n 19 ionice -c 3 python3 styx-js/demo/sdk-two-machines/long-history-guard.py'

Il guard acquisisce /home/mverde/reviews/styx-kanban/.ai395-test.lock per tutta la matrice, campiona MemAvailable ogni 2 s e confronta stato e PID di llama-swap, ds4-glm-full e ComfyUI senza modificarli. Tutti i figli ereditano nice 19 e ionice idle. Stato cifrato sintetico solo in una sottocartella privata temporanea delle evidenze, cancellata al termine e verificata assente. Nessuna chiave di stato o seed nei log.

Minimo RAM disponibile: 86009524224 byte. Servizi invariati: True. Stato eliminato: True; figli residui: 0.

Verifica/rendere report, sempre su AI395:

    nice -n 19 ionice -c 3 python3 styx-js/demo/sdk-two-machines/long-history-report.py --evidence /home/mverde/reviews/sdk-demo-2026-11/long-history-evidence --report /home/mverde/reviews/sdk-demo-2026-11/RISULTATI-STORIA-LUNGA.IT.md --summary styx-js/demo/sdk-two-machines/LONG-HISTORY-SUMMARY.json

## Fallimenti conservati e limiti

pilot, pilot2, pilot3, pilot4: E_SDK_INVITE_TIMEOUT dell’harness perché deadline=30 s non copriva le fasi di connessione configurate a 30 s. pilot5: E_SDK_INVALID_CONFIG per timeout relay inferiore al minimo di 11 s. pilot6: FAILED_NO_RECEIPT generando eventi vecchi dopo avere arretrato un orologio già sincronizzato: i nuovi filtri since li escludevano. Corretto mantenendo l’offset storico coerente dall’avvio dei generatori. final: esecuzione interrotta esplicitamente per spostare lo stato temporaneo da /tmp al perimetro delle evidenze; rimozione verificata in manual-cleanup.json. Questi sono errori/limiti del banco prova, non risultati della matrice final2.

Una ripetizione per cella, più un controllo senza getter: nessuna distribuzione statistica o promessa di latenza di produzione. TCP loopback e risposte accorpate in burst favoriscono l’overflow; non sono un’emulazione della segmentazione di tutti i relay reali. Non viene dimostrata una perdita permanente in tutte le possibili condizioni di rete: si misura una finestra con un catch-up e una storia vecchia. Il tetto risultati può omettere messaggi senza riempire la coda; il caso con nuovo creato ora può essere recuperato dal since successivo, senza recuperare storia più vecchia eventualmente omessa. Nessun contratto M3 è stato cambiato, nessuna review LLM e nessun merge.

Evidenze complete nel workspace: long-history-evidence/; solo dati sintetici, identificativi e misure, niente stato cifrato residuo. Il commit del prototipo contiene harness, questo rapporto e riepilogo verificato; le evidenze dettagliate sono conservate separatamente. Il riferimento di pubblicazione è registrato dopo il push nel file PUBBLICAZIONE-STORIA-LUNGA.json del workspace.
