<!-- styx-translation:v1 canonical="docs/platform/application-capability-model.md" sha256="3fda0f0e750c678f676d8839dbec1c676152f9adc8556d1cd84f87a678afceb9" -->
# Modello delle capacità applicative di Styx

[English canonical version](application-capability-model.md)

> **Stato:** proposta esplorativa, non normativa
> **Snapshot:** `main @ d90931a3f59ce89c1594cad64ce385d58857b305`
> Gli esempi di componenti o API sono illustrativi e non congelano interfacce,
> primitive crittografiche o formati persistenti.

## 1. Obiettivo

Il modello stabilisce quali proprietà Styx dovrebbe poter offrire affinché
applicazioni diverse possano condividere un'infrastruttura sicura senza
condividere necessariamente identità, schemi dati o politiche.

Il criterio guida è la composizione: un'applicazione seleziona capacità e
policy; non eredita automaticamente tutte le promesse della chat. Ogni capacità
deve avere:

- un contratto osservabile;
- un modello di minaccia;
- una rappresentazione versionata quando attraversa rete o storage;
- errori fail-closed;
- test positivi, negativi, di crash e interoperabilità dove applicabili;
- una dichiarazione dei rischi residui.

## 2. Vocabolario

| Termine | Significato nel modello |
|---|---|
| **Identità civile** | Informazioni che collegano una persona a nome, recapito o ruolo nel mondo reale. Non deve essere confusa con una chiave. |
| **Identità crittografica** | Chiave o insieme di credenziali usato per autenticare azioni. Può essere persistente, di dispositivo, applicativa o effimera. |
| **Anonimato** | L'avversario definito non riesce a collegare un'azione a una persona reale entro il modello dichiarato. Non è una proprietà assoluta. |
| **Riservatezza** | Soggetti non autorizzati non leggono il contenuto. Il gestore potrebbe comunque conoscere l'identità. |
| **Pseudonimato** | Le azioni sono collegate a uno pseudonimo stabile, non necessariamente a un'identità civile. |
| **Unlinkability** | L'avversario non riesce a stabilire che due azioni, casi o identità appartengano allo stesso soggetto. |
| **Capability** | Segreto o token non falsificabile il cui possesso autorizza un'operazione, per esempio riaprire un caso anonimo. |
| **Application context** | Dominio logico che separa chiavi, identificatori, dati e policy di un'applicazione dalle altre. |
| **Case context** | Sottodominio monouso o limitato a una pratica, conversazione o gruppo. |
| **E2EE object** | Oggetto cifrato e autenticato per destinatari espliciti, con schema e versione applicativi. |
| **Tamper-evident** | Una modifica successiva può essere rilevata secondo determinati invarianti. Non prova che il dato originario fosse vero. |
| **Assurance profile** | Insieme verificabile di capacità, configurazione, client e requisiti operativi. |

## 3. Attori e confini di fiducia

Il modello non assume un “server cattivo” unico. Separa almeno:

- **utente e dispositivo**: generano input, custodiscono chiavi e mostrano
  plaintext;
- **applicazione**: interpreta schemi, ruoli e workflow;
- **Styx core**: cifra, autentica, persiste e sincronizza;
- **relay o store-and-forward provider**: osserva connessioni e conserva blob;
- **push provider**: osserva endpoint, tempi e wake-up;
- **publisher del client**: distribuisce HTML, JavaScript, WASM o binari;
- **operatore organizzativo**: gestisce casi, gruppi, ruoli o infrastruttura;
- **peer autorizzato**: legge dati ma può copiarli o divulgarli;
- **osservatore di rete**: vede origini, destinazioni, tempi e volumi;
- **amministratore del dispositivo**: può controllare browser, estensioni,
  input, schermo e memoria;
- **fornitore di backup o sistema operativo**: può conservare repliche non
  visibili all'applicazione.

Una proprietà deve indicare rispetto a quali attori vale. “Il relay non legge
il messaggio” è compatibile con “il relay vede l'indirizzo IP e il tag di
instradamento”.

## 4. Architettura logica proposta

### 4.1 Application layer

Contiene UI, workflow, schema semantico, validazioni di dominio e regole
organizzative. Non riceve chiavi grezze quando può richiedere operazioni al
core. Non decide primitive crittografiche.

### 4.2 Policy and capability layer

Traduce il threat model in policy: tipo di identità, destinatari, retention,
recovery, numero di relay, routing, notifiche, allegati e livello di audit.
Rifiuta combinazioni che non raggiungono il profilo richiesto.

### 4.3 Secure object and session layer

Gestisce sessioni E2EE, oggetti applicativi versionati, membership, rotazione,
autenticazione, sequenze e stato crittografico. MLS è il core canonico per il
prodotto, ma non tutte le applicazioni sono automaticamente modellabili come
messaggi di chat.

### 4.4 Reliability and synchronization layer

Gestisce outbox persistente, retry, ACK, deduplicazione, idempotenza, ordering,
replay e politiche di conflitto. Distingue “pubblicato su un relay”,
“ricevuto da un dispositivo” e “letto da una persona”.

### 4.5 Privacy transport layer

Seleziona relay, route, onion endpoint, mailbox key, padding, batching e
notifiche. La cifratura del contenuto non sostituisce questo livello.

### 4.6 Local custody layer

Il vault confina chiavi e plaintext, applica lock/unlock, transazioni, reset,
migrazioni e recovery. La pagina consuma un protocollo dati chiuso; non riceve
Root Key, KEK, `CryptoKey` o handle WASM.

### 4.7 Distribution and operations layer

Rende verificabili build, aggiornamenti, configurazioni e continuità operativa.
Comprende separazione dei ruoli, audit amministrativo, backup infrastrutturale
e osservabilità senza dati sensibili.

## 5. Capacità richieste

### 5.1 Application context e domain separation

Ogni applicazione deve avere un identificatore di contesto non ambiguo usato
nella derivazione delle chiavi, nell'AAD, negli schemi e nelle policy. Due app
installate sullo stesso dispositivo non devono riutilizzare automaticamente:

- chiavi di identità o mailbox;
- namespace del vault;
- group identifier;
- contatori, nonce o sequenze;
- endpoint push;
- alias e contact graph;
- recovery secret.

Il `case context` deve poter aggiungere separazione ulteriore. Una segnalazione
anonima e una seconda segnalazione dello stesso browser non devono essere
collegabili attraverso un identificatore persistente del protocollo.

**Evidenza minima:** test cross-context che provano chiavi/AAD diversi e
rifiuto di ciphertext spostato fra contesti.

### 5.2 Profili di identità

Il core dovrebbe supportare profili distinti, senza simularli con un unico
account durevole:

| Profilo | Durata e uso |
|---|---|
| `persistent-personal` | Identità autocustodita e verificabile per relazioni durevoli. |
| `device` | Credenziale revocabile di un singolo dispositivo, subordinata a una relazione o account. |
| `application` | Identità separata per un'applicazione; non riutilizzata altrove. |
| `case-ephemeral` | Identità casuale per un singolo caso o gruppo, senza riuso. |
| `anonymous-capability` | Nessun account; una capability ad alta entropia permette il ritorno al caso. |
| `organization-role` | Credenziale associata a un ruolo operativo e ruotabile senza confonderla con la persona. |

Generazione, rotazione, revoca, scadenza ed esportazione devono essere
esplicite. Una chiave pubblica non deve essere descritta come anonima soltanto
perché non contiene un nome.

### 5.3 Unlinkability

La separazione crittografica non basta se rete, push e storage usano handle
stabili. Il profilo deve esaminare congiuntamente:

- chiave esterna degli eventi;
- tag e mailbox di instradamento;
- set di relay;
- endpoint push;
- tempistica e dimensione;
- fingerprint del client;
- recovery e backup;
- nomi delle chiavi e namespace locali.

L'unlinkability va testata come proprietà negativa: nessun campo comune e
nessun mapping accessibile all'avversario dichiarato. Contro un osservatore
globale restano possibili correlazioni statistiche e temporali.

### 5.4 E2EE objects e schema applicativo

Le applicazioni devono poter definire oggetti cifrati diversi dai messaggi di
testo: operazioni contabili, assegnazioni, moduli, ricevute, commenti, stati di
workflow. Ogni oggetto richiede almeno:

- `application context` e versione dello schema;
- identificatore casuale e chiave di idempotenza;
- autore crittografico e destinatari o gruppo;
- tipo e versione della policy;
- timestamp logico e, se necessario, dipendenze causali;
- payload con limiti di dimensione e grammatica chiusa;
- regole di evoluzione e gestione delle versioni sconosciute.

Il formato concreto è una decisione separata. Il core non deve deserializzare
oggetti applicativi in forme eseguibili, accettare callback o consentire accessi
dinamici non validati.

### 5.5 Conversazioni, gruppi e membership

Servono primitive per:

- sessioni 1:1;
- gruppi con membri e dispositivi distinti;
- invito e verifica out-of-band;
- aggiunta, rimozione e sospensione;
- rotazione dopo compromissione;
- autorizzazione delle modifiche alla membership;
- gestione di commit pendenti, ACK e fork;
- esportazione minima dello stato per debug senza segreti.

MLS offre primitive utili, ma il prodotto deve definire Authentication Service,
Delivery Service, policy di membership e recovery. Forward secrecy e
post-compromise security dipendono anche da rotazioni e cancellazione di
materiale, non soltanto dalla scelta di MLS.

### 5.6 Autorizzazione, ruoli e delega

Una chiave che può decifrare non dovrebbe automaticamente poter amministrare.
Il modello deve distinguere:

- lettura, scrittura e commento;
- invito o rimozione di membri;
- assegnazione di casi;
- esportazione e cancellazione;
- modifica di retention e policy;
- accesso ai log amministrativi;
- rotazione e recovery.

Ruoli, deleghe e revoche devono essere autenticati, versionati e valutati
localmente. Le operazioni ad alto impatto possono richiedere autorizzazione
multi-persona o threshold, ma la tecnica concreta richiede design separato.

### 5.7 Vault locale e confinamento dei segreti

Il vault applicativo deve:

- cifrare record e manifest prima della persistenza;
- derivare e separare chiavi per namespace e scopo;
- eseguire KDF, unwrap e operazioni sensibili in un worker dedicato;
- esporre un protocollo chiuso con payload limitati;
- serializzare mutazioni e usare transazioni atomiche;
- chiudersi in modo deterministico su lock, timeout, reset e crash;
- impedire la restituzione di chiavi, plaintext e stack sensibili;
- distinguere cancellazione logica da erasure fisica non dimostrabile;
- gestire migrazioni senza distruggere i dati originali prima della verifica.

La password resta una stringa JavaScript non azzerabile con certezza. Browser o
sistema compromessi mentre il vault è sbloccato restano fuori dalla protezione
del solo vault.

### 5.8 Trasporti e relay federation

Il core dovrebbe dipendere da un contratto di trasporto, non da un relay
specifico. Un adattatore dichiara:

- semantica di pubblicazione e conferma;
- persistenza o effimerità;
- limiti e quote;
- informazioni visibili all'operatore;
- autenticazione e protezione replay;
- comportamento su duplicazione, riordine e perdita;
- capacità di cancellazione, se presente;
- modalità diretta, federata o onion.

Relay multipli aumentano disponibilità ma possono aumentare superficie di
osservazione. La replica non va confusa con consenso: l'applicazione deve sapere
se basta una pubblicazione, un quorum di relay o l'ACK del destinatario.

### 5.9 Affidabilità e store-and-forward

Ogni mutazione in uscita attraversa una outbox persistente prima dell'invio. Il
modello distingue stati come:

```text
queued → published → device-acknowledged → application-acknowledged
                         ↘ expired / rejected / conflicted
```

I nomi sono illustrativi. Requisiti essenziali:

- retry con backoff e jitter;
- idempotency key stabile per l'operazione;
- deduplicazione persistente, non soltanto in memoria;
- ACK autenticato e cifrato;
- riconciliazione dopo crash fra commit locale e risposta;
- limiti di tentativi, scadenza e dead-letter state;
- semantica chiara per messaggi effimeri;
- nessun “sent” derivato dalla sola chiamata `publish()`.

### 5.10 Ordering, sincronizzazione e conflitti

La chat può tollerare un ordinamento diverso da una contabilità. Il core deve
offrire primitive, mentre l'app dichiara la policy:

- sequenza per autore o dispositivo;
- dipendenze causali;
- rilevamento di gap, replay e fork;
- merge commutativo quando semanticamente valido;
- rifiuto o revisione umana per conflitti non componibili;
- snapshot e compattazione verificabili;
- rollback detection entro limiti dichiarati.

Non esiste un merge universale. Sommare due spese può essere corretto; accettare
due assegnazioni incompatibili dello stesso caso può non esserlo.

### 5.11 Protezione dei metadati

Un profilo metadata-minimizing deve considerare almeno:

- chiave esterna effimera o non identitaria;
- mailbox key ruotabile e distinta dall'identità;
- cifratura dell'envelope esterno;
- timestamp offuscato;
- padding a bucket con floor minimo;
- batching o ritardi opzionali;
- scelta e rotazione dei relay;
- Tor/onion routing;
- disattivazione di typing, presence e read receipt;
- notifiche senza mapping identitario diretto;
- policy per traffico dummy, costo, batteria e latenza.

NIP-59/NIP-44 sono opzioni da valutare, non decisioni assunte da questo
documento. Anche un gift wrap può lasciare visibile un destinatario o un handle
stabile; il threat model deve verificare la variante concreta.

### 5.12 Allegati e contenuti complessi

Gli allegati aggiungono rischi indipendenti dalla cifratura:

- EXIF, autore, percorso, cronologia e metadati del documento;
- watermark, canary e identificatori invisibili;
- malware e parser vulnerabili sul dispositivo ricevente;
- dimensione e firma statistica;
- anteprime o scansioni affidate a terzi;
- persistenza in cache e applicazioni esterne;
- deduplicazione per hash che collega casi diversi.

Il core dovrebbe fornire streaming cifrato, chunk autenticati, limiti, padding e
integrità. Sanitizzazione, conversione e avvisi appartengono a un servizio
isolato o all'app. Un profilo anonimo può iniziare `text-only` e vietare gli
allegati finché il percorso non è verificato.

### 5.13 Multi-device, rotazione e compromise response

Ogni dispositivo richiede credenziale distinta, stato e revoca. Il modello
deve coprire:

- aggiunta verificata di un dispositivo;
- elenco dispositivi comprensibile all'utente;
- revoca con rotazione del gruppo;
- perdita, furto e compromissione;
- sincronizzazione selettiva della cronologia;
- recupero senza clonare indefinitamente una chiave personale;
- epoch/generation monotona e rilevamento di rollback;
- procedura di emergenza che non nasconda la compromissione.

Backup di una chiave e multi-device non sono la stessa cosa. Ripristinare una
chiave durevole può conservare l'identità, ma non risolve revoca e stato MLS.

### 5.14 Recovery e capability custody

Il recovery deve dichiarare cosa recupera: identità, accesso a un caso, dati o
membership. Possibili modelli includono segreto singolo, più share, altro
dispositivo o custodia organizzativa; la scelta richiede analisi separata.

Una `anonymous capability` deve avere entropia sufficiente, essere generata
localmente e non essere derivata da dati personali. L'interfaccia può
rappresentarla come QR o parole, ma deve proteggere contro:

- screenshot e cloud backup automatici;
- furto fisico;
- phishing e brute force online;
- perdita definitiva;
- riuso fra casi;
- supporto tecnico che chieda il segreto.

Il server non deve poter rigenerare la capability. La perdita può comportare
l'impossibilità intenzionale di riaprire il caso.

### 5.15 Retention, redazione, cancellazione ed export

Ogni classe di dato necessita policy indipendente:

- durata operativa;
- base e motivo della conservazione;
- scadenza e legal hold;
- cancellazione locale e richiesta ai peer;
- redazione del payload mantenendo o meno una prova di sequenza;
- eliminazione di indici, cache, notifiche e backup;
- export cifrato o in chiaro con consenso e audit;
- comportamento offline e su dispositivi non più raggiungibili.

Una hash chain può conservare impronte di dati cancellati. Il design deve
valutare se l'impronta stessa sia personale o correlabile. Styx non può
garantire che un destinatario cancelli una copia o uno screenshot.

### 5.16 Audit, ricevute ed evidenza

Servono registri distinti:

- **security audit log** locale: accessi e operazioni sensibili;
- **shared event history**: eventi applicativi autenticati;
- **operator audit**: assegnazioni, export, retention e amministrazione;
- **delivery evidence**: publish e ACK autenticati.

I log devono minimizzare contenuto e identificatori, avere accesso separato e
non diventare un nuovo grafo sociale. Firma, timestamp locale e hash chain non
forniscono automaticamente timestamp qualificato, identità civile, verità del
contenuto o ammissibilità giuridica. Tali proprietà richiedono processi e
servizi separati.

### 5.17 SDK applicativo e capability discovery

Lo SDK dovrebbe esporre concetti applicativi stabili senza consegnare segreti:

- apertura di un `application context`;
- creazione o importazione di un profilo di identità;
- gestione di sessioni e oggetti cifrati;
- query di capability e versione;
- subscribe a eventi tipizzati e limitati;
- operazioni transazionali dati-only;
- gestione esplicita di stati offline, lock e recovery;
- adattatori di trasporto e storage registrati staticamente;
- errori tipizzati senza payload o stack sensibili.

Version negotiation deve fallire chiuso su formati incompatibili. Feature flag
e capability discovery non devono permettere downgrade silenziosi.

### 5.18 Distribuzione autentica e aggiornamenti

Una PWA cifrata non è sicura se la prima risposta può consegnare JavaScript
malevolo che esfiltra plaintext prima della cifratura. Servono livelli
complementari:

- build riproducibile e artefatti verificabili;
- provenienza e pin delle dipendenze;
- CSP e assenza di risorse terze;
- service worker con policy di update e rollback;
- firma o trasparenza degli artefatti dove supportata;
- distribuzione da origini indipendenti o client installati;
- canale di verifica esterno al server compromettibile;
- client nativo firmato per profili di garanzia più alti.

Un hash comunicato dallo stesso server non autentica il server. La verifica tra
client può aiutare soltanto se ha una radice di fiducia e resiste a Sybil,
rollback ed eclissi; il protocollo concreto è una decisione separata.

### 5.19 Osservabilità privacy-safe e continuità

L'operatore necessita indicatori senza registrare utenti o contenuti:

- disponibilità e latenza dei relay;
- errori aggregati con cardinalità limitata;
- versioni client e compatibilità in forma minimizzata;
- saturazione di quote e code senza record key;
- audit dell'amministrazione separato dalla telemetria;
- log opt-in, locali e redatti per diagnosi;
- runbook per perdita di relay, chiavi e fornitori.

Analytics, crash reporter, CDN, font e script terzi devono essere vietati nei
profili sensibili o valutati esplicitamente. La ridondanza geografica migliora
continuità, ma richiede gestione delle chiavi, patching, monitoraggio e test di
restore.

### 5.20 Custodia organizzativa e separazione dei compiti

Applicazioni gestite da organizzazioni richiedono:

- chiavi del ruolo separate dalle identità personali;
- assegnazione e riassegnazione dei casi;
- principio del minimo privilegio;
- revoca immediata di operatori;
- doppia autorizzazione per export, distruzione o cambio policy;
- continuità quando una persona lascia il ruolo;
- accesso di emergenza dichiarato e auditato;
- nessuna chiave universale silenziosa.

Una chiave master dell'organizzazione semplifica il recupero ma aumenta
drasticamente l'impatto di compromissione e abuso interno. Threshold,
multi-recipient encryption o escrow sono alternative da sottoporre a design e
review, non scelte di questo modello.

### 5.21 Compliance hooks

Il core può facilitare un processo regolato con:

- retention configurabile;
- data minimization;
- ruoli e audit;
- export e legal hold;
- informative versionate e consenso dove pertinente;
- scadenze, reminder e stati di workflow;
- registrazione della base/policy applicata;
- separazione fra canali con regimi diversi.

Non può determinare autonomamente la legge applicabile, qualificare una
segnalazione, assicurare indipendenza del gestore, impedire ritorsioni o
conferire certificazioni. DPIA, procedure, formazione e controllo umano restano
responsabilità dell'organizzazione.

### 5.22 Abuse resistance e safety

L'anonimato può essere usato per spam, minacce e materiale illecito. Senza
identificare il segnalante, un'app deve poter applicare:

- limiti per capability, finestra e costo;
- proof-of-work o challenge accessibili, dopo analisi del rischio;
- code di quarantena e scansione locale isolata;
- blocco di un caso senza bloccare tutti gli utenti;
- separazione tra abuso del canale e merito della segnalazione;
- escalation per pericolo immediato;
- protezione degli operatori da contenuti traumatici;
- preservazione controllata dell'evidenza quando obbligatoria.

Rate limit per IP può danneggiare utenti dietro Tor o NAT e creare log
identificativi. Ogni mitigazione deve essere valutata nel threat model.

## 6. Profili di garanzia

I nomi seguenti descrivono obiettivi, non certificazioni.

### `content-confidential`

E2EE, verifica del peer, storage protetto e relay non fidato. Lascia visibili
metadati di trasporto e non protegge un endpoint compromesso.

### `resilient-collaboration`

Aggiunge outbox persistente, ACK, idempotenza, relay multipli, recovery e
politiche di conflitto. Mira a continuità e coerenza, non anonimato.

### `metadata-minimizing`

Aggiunge identità applicative, mailbox ruotabili, envelope esterno protetto,
padding, policy notifiche e opzioni Tor/onion. Riduce osservabilità ma non
elimina correlazione globale.

### `anonymous-dialogue`

Aggiunge identità per caso, capability di ritorno, nessun recapito obbligatorio,
no cross-case linking e workflow operatore. L'anonimato vale soltanto rispetto
agli avversari e alle condizioni dichiarate.

### `native-high-assurance`

Richiede client nativo firmato, secure hardware quando disponibile, update
verificabili, threat model specifico e audit separato. Non deriva
automaticamente dalla PWA.

## 7. Invarianti trasversali

Ogni futura implementazione dovrebbe preservare:

1. nessun segreto attraversa confini non necessari;
2. nessun input di rete decide codice o accesso dinamico;
3. namespace, schema e versione sono autenticati;
4. un errore di persistenza non viene presentato come successo;
5. una pubblicazione non equivale a consegna;
6. una chiave non equivale a identità civile;
7. un relay multiplo non equivale a anonimato;
8. una cancellazione non promette erasure fisica;
9. una recovery path non aggira revoca e audit;
10. una feature non è disponibile finché test, CI e documentazione non la
    coprono nel prodotto che la usa.

## 8. Criterio di prontezza per una nuova applicazione

Prima di un pilot, l'applicazione deve produrre:

- threat model con attori, asset e assunzioni;
- data-flow diagram con metadati visibili;
- matrice delle capacità e dipendenze;
- schema/version policy approvati;
- piano di perdita, crash, rollback e recovery;
- politica allegati, retention ed export;
- test end-to-end su client e infrastruttura reali;
- review indipendente e lista dei rischi residui;
- copy UI che non superi le garanzie provate;
- procedura organizzativa e contatti di emergenza, se applicabili.

La presenza delle primitive nel repository non è sufficiente: la proprietà deve
essere dimostrata sul percorso completo dell'applicazione.
