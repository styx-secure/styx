# Risultati del prototipo SDK su due macchine — 1 novembre 2026

PROTOTIPO — NON UNIRE. Solo dati sintetici, prima dell'audit.

Card: t_403664d9. Base esatta: 3b314074568aa435572bca44ec4348e1a084c60e.
Ramo separato: proto/sdk-demo-2026-11.

## Risultato misurato

Tre prove complete, two-host-2 / two-host-3 / two-host-4, tutte riuscite:
18 messaggi su 18 con ricevuta del destinatario (tre messaggi e tre risposte
per prova). L'impronta, calcolata come hash di un exporter MLS, coincide fra i
due membri in ciascuna prova. Non viene registrato il valore segreto esportato.

Nodo invitante su AI395; nodo invitato su MVLINNA. Il confronto degli indirizzi
pubblici di uscita ha confermato reti distinte in tutte le prove: conservato solo
il booleano, non gli indirizzi. PC4070TI non è stata contattata.

Il KeyPackage firmato (kind 4743) è stato pubblicato dall'invitato e recuperato
dall'invitante tramite l'SDK. Il Welcome e l'albero MLS sono passati nel gift wrap
NIP-59 (kind 1059, rumor 4744). Il destinatario attende la chiave pubblica
specificata dell'invitante: non accetta un mittente scelto implicitamente dal
primo invito ricevuto. L'invito è stato accettato dai tre relay configurati.
Nessuna identità privata, KeyPackage, Welcome o stato MLS è stato trasferito
fra le macchine. Il coordinamento passa soltanto le chiavi pubbliche dei peer;
la raccolta successiva copia soltanto le prove, non lo stato del protocollo.

Relay pubblici impiegati:

- wss://relay.nostr.net
- wss://relay.primal.net
- wss://offchain.pub

## Guasti e recupero

Dopo il primo scambio viene escluso relay.nostr.net nel solo processo invitante:
la connessione viene chiusa e le nuove connessioni rifiutate dal wrapper locale.
Il relay pubblico rimane acceso e utilizzabile dagli altri utenti e dall'invitato.
Il secondo messaggio passa sugli altri relay e ottiene la ricevuta.

Poi il processo invitante scarta i frame in entrambe le direzioni sugli altri
due collegamenti. Il primo tentativo del terzo messaggio scade; vengono
ripristinati quei due collegamenti e l'SDK ritenta. Il terzo messaggio ottiene
la ricevuta al secondo tentativo in tutte e tre le prove.

La seconda risposta parte dal destinatario durante lo stallo. Il recupero
periodico dell'SDK la consegna una sola volta dopo il ritorno della rete:

| Prova | Messaggi con ricevuta | Tentativi del terzo messaggio | Recupero dopo ripristino |
|---|---:|---:|---:|
| two-host-2 | 6/6 | 2 | 7,538 secondi |
| two-host-3 | 6/6 | 2 | 1,579 secondi |
| two-host-4 | 6/6 | 2 | 8,621 secondi |

Il verificatore confronta anche mittenti attesi, testi sintetici, assenza di
ricezioni duplicate e ordine temporale invio-nello-stallo/ripristino/ricezione.
Non è una prova di tolleranza a guasti arbitrari o a interruzioni indefinite.

## Catture e cifratura osservata

Per ogni prova completa sono disponibili due viste su ciascun host:

1. Senza chiavi: record TLS, dimensioni, tempi e nome del relay.
2. Dopo la rimozione del proprio TLS: frame WebSocket con KeyPackage pubblico,
   gift wrap, eventi messaggio 4741 e ricevute 4742. Il contenuto degli eventi
   messaggio rimane cifrato MLS; i testi sintetici non compaiono nei frame.

Gli indirizzi sono mascherati. Il lettore conserva solo i flussi il cui
ClientHello corrisponde al key log del proprio processo, non traffico di altri
processi. Il passaggio dei segreti TLS a tshark avviene tramite un blocco pcapng
in una pipe in memoria, senza modificare AppArmor e senza usare /tmp di sistema.
Dopo l'estrazione, catture originali e key log sono stati rimossi con shred:
la rimozione è verificata nei riepiloghi per host. Restano gli hash delle catture
e le viste sanificate. La sovrascrittura su filesystem moderni non costituisce
una garanzia forense di cancellazione sicura.

Le viste complete e i conteggi, senza aggregazioni manuali, sono in
`evidence-nov/verification-final.json` e nelle sottocartelle delle tre prove.

## Verifiche del codice

- Prova loopback su AI395: tre relay locali con verifica delle firme, due processi
  indipendenti, vero motore MLS, vero NIP-59 cifrato, sei ricevute, retry e recupero.
- Controlli negativi: rifiuto del gift wrap alterato, impossibilità di aprirlo
  con una terza identità, rifiuto del KeyPackage con credenziale MLS errata.
- Solo nuove porte e applicazione in styx-js/demo/sdk-two-machines/.
- Nessun import diretto delle implementazioni interne dell'SDK: invito e consegna
  usano esclusivamente src/sdk/index.js. L'adattatore del chiamante richiama
  MlsEngine come nel test sdk-mls; non ne modifica il codice.
- Diff SDK, crypto, vendor, manifesti e workflow vuoto rispetto alla base.
  I 105 file di src+vendor sono identici anche nel deployment AI395;
  hash SHA-256 aggregato f124fc13298f9d7e8156135bd0b4fb1a37947cde0df4e4543897452e31c40d12.
- Regressione SDK + sdk-mls su AI395: 16 suite e 1.135 test su 1.135 superati,
  uscita 0, durata 867,43 secondi. Esecuzione diretta di Jest, senza --forceExit;
  esiti JSON e log completi in evidence-nov/sdk-regression-final.*.
  La selezione comprende anche guardia degli import, recupero, chiusura e
  integrazione dei relay. Non è stato eseguito il resto della suite del repository.

Ambiente: Node v24.18.0 su AI395; nostr-tools 2.25.2, ws 8.21.0,
@noble/curves 1.9.7, @noble/hashes 1.8.0. Le versioni e gli hash del codice
eseguito sono registrati in evidence-nov/environment-ai395-final.json.
ESLint sul codice JavaScript del prototipo: uscita 0, con controlli espliciti
anche su variabili inutilizzate, duplicati e codice irraggiungibile.
La dipendenza nostr-tools era già presente nell'ambiente dimostrativo: non sono
stati cambiati manifesti o lockfile del prodotto. La riproduzione non è ermetica:
chi prepara un ambiente nuovo deve procurare esplicitamente tale dipendenza.

## Risorse e servizi

Su AI395: nice 19, ionice idle e lock condiviso .ai395-test.lock.
Durante le tre prove complete la memoria disponibile minima misurata è stata
79,20 GB, sopra il limite di 15 GB. Il PID di llama-swap è rimasto 7744 prima e
dopo ogni prova. ds4-glm-full e ComfyUI non risultavano processi locali attivi
nella fotografia iniziale: non sono stati avviati, fermati o riconfigurati.
Nessun build o test pesante su MVLINNA; vi sono girati il nodo leggero,
la cattura e la breve estrazione della propria cattura.

## Tentativi non riusciti, conservati senza mascherarli

- loopback-1: invito fallito con E_SDK_IDENTITY_FAILED perché nostr-tools aggiunge
  all'evento un Symbol di verifica, non ammesso dall'oggetto chiuso dell'SDK.
  Correzione nella sola porta dimostrativa: restituzione dell'evento Nostr puro,
  senza quel metadato. loopback-2 è poi riuscito.
- two-host-1: lo scambio ha ottenuto sei ricevute e impronte uguali, ma
  l'estrazione delle catture è fallita per i vincoli AppArmor sui percorsi.
  Non viene contato come prova completa. La lettura via pipe ha risolto il
  problema; nessuna policy del sistema è stata cambiata.
- Prima regressione SDK: comando interrotto dopo 300 secondi, senza esito
  complessivo e senza test falliti fino a quel momento. È una verifica
  incompleta, non un risultato verde; log conservato e regressione rilanciata.

## Video

Video di 100 secondi, sette scene etichettate, derivato dalle righe reali della
prova two-host-2 e dalle sue catture. È un montaggio di evidenze, esplicitamente
etichettato come tale, non una registrazione continua dello schermo in diretta.
`video-source-lines.json` riporta le righe di origine mostrate.
Il file e il suo hash sono consegnati separatamente, non inseriti nel repository.
File: video-nov/sdk-two-machines-2026-11.mp4; durata verificata 100,000 secondi,
664.139 byte; SHA-256
708980740170e6bbae56813978864dc0036f9bdad7ac22a118cebcec56f2199a.

## Limiti: ciò che NON è dimostrato

- Nessun audit, prova formale, anonimato o idoneità alla produzione/uso sensibile.
- Chiavi pubbliche, destinatari, kind, tempi, dimensioni e metadati di routing
  restano osservabili. I KeyPackage sono pubblici: non «tutto sui relay è cifrato».
- Il pin della chiave pubblica non prova l'identità civile di una persona.
- Kind sperimentali 4743/4744: nessuna dichiarazione di interoperabilità Marmot.
- Stato e identità sono volatili; non vengono dimostrati persistenza, riavvio,
  rotazione delle chiavi o recupero dopo perdita del processo.
- Tre secondi di attesa finale sono una precauzione della demo, non un nuovo
  contratto di shutdown o una garanzia aggiuntiva del prodotto.
- Non eseguito un attaccante remoto per replay/iniezione. Il kit precedente
  era legato al diverso harness del ledger; non è stato trapiantato in questa
  dimostrazione SDK. I controlli negativi locali non lo sostituiscono.
- I relay pubblici possono cambiare comportamento o disponibilità; le misure
  riguardano soltanto queste esecuzioni, non una promessa di servizio.

Nessuna review del consiglio, nessun merge, nessuna mail inviata.
L'eventuale integrazione futura dovrà seguire il processo ordinario separato.
