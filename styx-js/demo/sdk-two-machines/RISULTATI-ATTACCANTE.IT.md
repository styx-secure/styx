# Prototipo SDK: attaccante remoto senza chiavi del gruppo

Data: 1 novembre 2026. Solo ramo `proto/sdk-demo-2026-11`, base della prova `d20330a`. Nulla unito. Dati sintetici; software sperimentale, non sottoposto ad audit. Nessuna modifica a SDK, crittografia o vendor.

## Risultato misurato

Tre esecuzioni complete contro il client SDK, usando esclusivamente la sua API pubblica. Nessuno degli attacchi osservati ha prodotto un messaggio applicativo estraneo o una conferma di consegna anticipata. Questo non equivale a una dimostrazione universale di sicurezza.

| Esecuzione | Messaggi legittimi ricevuti / attesi | Ricevute vere | Scarti applicativi esposti dall'SDK | Snapshot in attesa dopo ricevuta falsa | Tempo invio → conferma |
|---|---:|---:|---|---:|---:|
| run-2 | 2 / 2 | 2 / 2 | 2 × E_SDK_SESSION_FAILED | 42 | 110,260 s |
| run-3 | 2 / 2 | 2 / 2 | 2 × E_SDK_SESSION_FAILED | 41 | 110,592 s |
| run-4 | 2 / 2 | 2 / 2 | 2 × E_SDK_SESSION_FAILED | 43 | 110,371 s |

Il tentativo run-1 è fallito prima della prova per dipendenze mancanti: non conta tra le tre esecuzioni. È conservato separatamente, senza trasformarlo in successo.

## Topologia e confine dell'attaccante

Invitante su AI395, invitato su MVLINNA, uscite pubbliche dei due nodi verificate diverse. Tre relay: relay.nostr.net, relay.primal.net, offchain.pub. Nessun impiego di PC4070TI. Su MVLINNA soltanto nodo leggero, coordinamento e cattura; codifica video su AI395.

L'attaccante è il Worker dedicato `styx-sdk-mallory-nov`, con Durable Object e chiave sintetica propria, diverso dal vecchio Worker. Il coordinatore gli comunica soltanto chiavi pubbliche, relay e parametri temporali. Legge gli eventi pubblici e sceglie il bersaglio dal relay; non riceve chiavi MLS, esportatori, Welcome decifrati o stati di protocollo. La propria chiave effimera viene generata e mantenuta dal Durable Object, non inclusa nelle evidenze esportate. Nessuna credenziale Cloudflare è cercata o copiata: utilizzata esclusivamente l'autenticazione Wrangler già configurata nei tentativi precedenti.

Il Worker non è un agente adattivo: esegue uno script fisso, avanzato tramite tick HTTP esterni. Il campo colo di /health riguarda la richiesta HTTP, e i campi country/asn/ip hash descrivono il chiamante: non certificano l'uscita effettiva del Worker verso i relay. La separazione dell'esecutore è data dal deployment Cloudflare; non è una prova di geolocalizzazione dell'attaccante.

## Quattro attacchi e controprove

1. Replay invariato di un 4741 intercettato. Risposta del relay: `duplicate: have this event`. Il destinatario applicativo riceve il messaggio legittimo una sola volta; il socket SDK vede anche copie durante catch-up e su relay multipli. Limite: il replay ripubblicato può essere assorbito dai relay; non si attribuisce al solo SDK un blocco che non può essere isolato da questa prova.

2. Manomissione del contenuto in due varianti. La copia senza rifirma conserva id e firma originali: relay.primal.net e offchain.pub rispondono `invalid: bad event id`; relay.nostr.net può rispondere duplicato in base all'id già noto. Questo non significa che il contenuto alterato sia stato consegnato. La copia rifirmata con la chiave dell'attaccante ha un nuovo id, viene accettata dai relay e arriva all'osservatore grezzo e al socket SDK del destinatario. L'applicazione non riceve un secondo payload. Compare E_SDK_SESSION_FAILED.

3. Iniezione 4741 da non membro con contenuto casuale. Accettata dal relay e osservata realmente al destinatario, ma non consegnata all'applicazione. Compare E_SDK_SESSION_FAILED. Per esecuzione sono presenti complessivamente due scarti, uno per copia rifirmata e uno per iniezione, con gli id e le adiacenze temporali riportati nell'attribuzione.

4. Ricevuta falsa 4742, strutturalmente costruita con destinatario, id del messaggio, versione, nonce casuale e contenuto vuoto, firmata dall'attaccante. Le pubblicazioni sono accettate e arrivano al socket SDK del mittente. Il trasporto chiamante trattiene le tre copie della ricevuta vera per 110 secondi; non modifica SDK né sessione MLS. Tutti gli snapshot misurati dopo la falsa ricevuta e prima del rilascio restano `RELAY_ACCEPTED_AWAITING_RECEIPT`, non terminali. Solo dopo il rilascio della ricevuta vera si osserva `RECIPIENT_RECEIPT_RECEIVED`.

Non compare INBOUND_DISCARDED per le ricevute estranee, né per ogni duplicato. Non sono stati inventati codici mancanti: per la ricevuta falsa la controprova è l'arrivo al socket più lo stato persistente d'attesa, seguito dal successo della ricevuta vera. Riferimenti di lettura: `src/sdk/delivery/receipts.js` (finestra duplicati e preparazione ricevute) e `src/sdk/delivery/outbox.js` (condizioni item-side della ricevuta). Nessun file interno modificato.

## Attribuzione, evidenze e limiti

`evidence-attacker/aggregate.json` e ciascun `run-N/attribution.json` contengono tutti gli id completi pubblicati, le risposte relay, i conteggi per osservatore grezzo e socket SDK su entrambi gli host, i tempi della prima osservazione, gli scarti immediatamente adiacenti e la sequenza attesa/rilascio/conferma. Gli zeri sull'altro host sono attesi quando il tag destinatario riguarda un solo nodo; non provano assenza dal relay.

Il callback pubblico INBOUND_DISCARDED non contiene l'id: la correlazione dello scarto è per adiacenza nel log, non un nesso causale fornito dall'SDK. Le catture sanificate abbreviano gli id a otto caratteri; l'attribuzione forte dell'evento usa gli id completi di osservatori e socket. Il numero di frame non è il numero di attacchi distinti: più relay e catch-up possono ripetere lo stesso id.

I log di rete mostrano TLS e, dopo decifratura con le sole chiavi TLS dei nodi della demo, eventi Nostr con ciphertext MLS: non una promessa di anonimato. Metadati e KeyPackage restano pubblici. Identità/sessioni volatili, relay pubblici non controllati, singola coppia di partecipanti, nessun audit e nessuna garanzia di produzione.

Catture grezze e key log rimossi con shred dopo l'estrazione su ciascun host; verifiche registrate in host-inviter.json e host-invitee.json. Gli indirizzi IP non sono esportati. Memoria minima disponibile AI395: 86,597 / 86,025 / 86,217 GB decimali; limite richiesto 15 GB. llama-swap rimane PID 7744 prima e dopo ogni prova; ds4-glm-full e ComfyUI non modificati. Processi invitanti e codifica nice 19, ionice idle, lock dedicato. Worker disarmato a fine di ogni esecuzione.

## Video e riproduzione

`sdk-attaccante-2026-11.mp4`: 100,000 secondi, 1280×720; scene esplicitamente etichettate come montaggio delle evidenze, non ripresa continua. `video-source-lines.json` conserva gli oggetti sorgente delle scene. Il video riassume il run-2 e confronta i tre risultati, senza simulare una schermata dal vivo.

Il pacchetto evidenze scaricabile conserva log sintetici, estratti di rete, risposte dell'attaccante e attribuzioni. Gli script sono nella directory demo:

- attack-member.mjs / attack-host.py: client e cattura, identità effimere in memoria e chiave TLS transitoria;
- run-attack.py: coordinamento dei due host, configurato per i percorsi e il Worker di questa prova;
- analyze-attacker.py: analisi in sola lettura e asserzioni sulle evidenze;
- render-attacker.py: rendering su AI395;
- mallory-sdk/: Worker derivato dal kit del 19 ottobre.

Per ripetere occorrono le dipendenze già previste dalla demo, accesso SSH ad AI395, dumpcap/tshark e il Worker autorizzato. Eseguire run-attack.py tre volte con directory nuove sotto evidence-attacker, poi analyze-attacker.py. Renderizzare con render-attacker.py solo su AI395, sotto lock e dopo controllo memoria. Le prove non richiedono modifiche all'SDK. Non distribuire altrove né armare il Worker verso gruppi non autorizzati.

Ripristino: disarmare il Worker dedicato e rimuovere/revertire soltanto gli artefatti della demo sul ramo prototipo. Nessuna merge, PR di prodotto o revisione del consiglio eseguita.
