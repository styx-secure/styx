<!-- styx-translation:v1 canonical="docs/platform/use-cases/anonymous-dialogue.md" sha256="fe4fae379c613cc5a6af8d4518e21f862406892b64123f8c02af3f61d9626e0c" -->
# Dialogo anonimo bidirezionale

[English canonical version](anonymous-dialogue.md)

> **Stato:** proposta esplorativa, non normativa.
>
> Questo documento non definisce un protocollo di produzione, non fornisce
> consulenza legale e non dimostra conformità a leggi, prassi, certificazioni o
> procedure organizzative.

## 1. Scopo

Il caso d'uso descrive come una futura applicazione costruita su Styx potrebbe
consentire a una persona di inviare una segnalazione e continuare a dialogare
senza fornire email, numero di telefono, identità chat ordinaria o altro
recapito stabile.

L'obiettivo è una **mailbox di caso bidirezionale e pseudonima** che possa
offrire anonimato rispetto all'organizzazione destinataria entro un modello di
minaccia dichiarato. Non è una garanzia universale di anonimato.

La stessa capacità potrebbe sostenere canali etici, safeguarding, contatti fra
fonti e giornalisti, raccolta di testimonianze sensibili e altri workflow di
casework. Ogni applicazione resta responsabile di base giuridica, governance,
retention, escalation e protezione delle persone.

## 2. Termini e proprietà richieste

- **Riservatezza:** soggetti non autorizzati non leggono il contenuto protetto.
- **Pseudonimato:** un identificatore specifico del caso sostituisce l'identità
  civile, ma le azioni dello stesso caso restano collegabili.
- **Anonimato rispetto a un osservatore:** quell'osservatore non riesce
  ragionevolmente a collegare il caso a una persona entro le assunzioni
  dichiarate.
- **Unlinkability:** l'osservatore non riesce a collegare casi distinti allo
  stesso soggetto.
- **Return capability:** segreto ad alta entropia che autorizza l'accesso a una
  sola mailbox. Non è uno username né un'identità riutilizzabile.

Un profilo conforme dovrebbe fornire:

1. riservatezza e integrità end-to-end tra client del segnalante e operatori
   autorizzati;
2. contesto crittografico nuovo e non collegabile per ogni caso;
3. risposte asincrone senza raccogliere recapiti convenzionali;
4. ricevute esplicite, distinguendo storage del relay, ricezione crittografica,
   presa in carico umana e lettura;
5. esposizione dei metadati minima, dichiarata e misurabile;
6. custodia organizzativa per ruolo, rotazione e revoca degli operatori;
7. retention limitata e audit senza registro in chiaro;
8. esportazione e passaggio di consegne controllati quando richiesti.

## 3. Non-obiettivi

La capacità non:

- prova che la segnalazione sia vera o che il segnalante agisca in buona fede;
- nasconde automaticamente origine IP, tempi, fingerprint, dimensione,
  stile di scrittura, fatti noti a poche persone o metadati degli allegati;
- protegge un dispositivo, browser o operatore compromesso mentre il caso è
  aperto;
- rende sicuri un dispositivo o una rete controllati dal datore di lavoro;
- decide se una segnalazione rientra nel whistleblowing tutelato;
- sostituisce operatori formati, indagini, procedure di emergenza o obblighi di
  protezione dei dati;
- garantisce disponibilità, consegna o cancellazione mediante la sola
  crittografia.

L'identità Nostr o Styx ordinaria e durevole della chat non deve essere
riutilizzata. Il riuso collegherebbe casi distinti e potrebbe esporre il grafo
sociale del segnalante.

## 4. Confine normativo e instradamento in Italia

Il canale tecnico e la qualificazione giuridica del singolo caso sono due piani
distinti.

UNI/PdR 125:2022 è una prassi di riferimento volontaria per sistemi di gestione
della parità di genere, non una legge nazionale. Il §6.3.2.6 prevede una
metodologia di segnalazione anonima per abusi e molestie fisiche, verbali o
digitali. Ciò non rende ogni segnalazione un caso di whistleblowing.

Il D.Lgs. 24/2023 disciplina il whistleblowing entro il proprio ambito
soggettivo e oggettivo. Per i canali interni prevede, fra l'altro:

- riservatezza delle identità, del contenuto e dei documenti;
- gestione autonoma da parte di persone o uffici specificamente formati;
- segnalazioni scritte oppure orali;
- avviso di ricevimento entro sette giorni;
- mantenimento del dialogo e diligente seguito;
- riscontro normalmente entro tre mesi.

Non ogni abuso, molestia, discriminazione, conflitto lavorativo o vertenza
individuale rientra nel D.Lgs. 24/2023. Le contestazioni legate esclusivamente al
rapporto individuale di lavoro o ai rapporti con i superiori possono restarne
escluse. La qualificazione deve essere svolta da persone competenti o da regole
organizzative approvate, non dedotta automaticamente dal protocollo.

L'interfaccia dovrebbe quindi:

- spiegare i percorsi disponibili senza pretendere che il segnalante classifichi
  correttamente la norma;
- accettare la segnalazione prima di chiedere dati identificativi facoltativi;
- mostrare quale organizzazione o ufficio indipendente riceve ogni percorso;
- associare retention e policy solo mediante un'azione autorizzata;
- trasferire un caso tramite handover esplicito, riservato e verificabile;
- mostrare fuori dal flusso asincrono le istruzioni per emergenze e pericolo
  immediato.

Una distribuzione reale richiede validazione di consulenti legali, DPO quando
applicabile, rappresentanze dei lavoratori, esperti di safeguarding e funzioni
organizzative responsabili.

## 5. Attori

- **Segnalante:** crea e riapre un caso senza account ordinario.
- **Client del segnalante:** custodisce temporaneamente plaintext e segreti del
  caso.
- **Relay o servizio di intake:** memorizza e inoltra envelope opachi; non è
  fidato per contenuto o identità.
- **Operatore del caso:** persona autorizzata e formata che legge e risponde.
- **Custode organizzativo:** gestisce chiavi di ruolo, rotazioni e retention
  senza ottenere per default accesso illimitato al plaintext.
- **Destinatario indipendente:** ufficio o professionista esterno usato quando
  esiste conflitto d'interesse.
- **Auditor:** verifica eventi di workflow e policy senza ricevere
  automaticamente il contenuto.
- **Avversario:** può gestire infrastruttura, osservare reti, inviare traffico
  abusivo, compromettere endpoint o correlare più punti di osservazione.

## 6. Asset e confini di fiducia

### Asset protetti

- testo di segnalazioni e risposte;
- esistenza, stato e cronologia del caso;
- identità e origine di rete del segnalante;
- return capability e chiavi locali;
- identità degli operatori quando la policy lo richiede;
- allegati e metadati;
- informazioni di routing, retention, export e audit.

### Confini

1. **Endpoint del segnalante:** dispositivo, sistema operativo, browser,
   estensioni, clipboard, schermo e storage locale.
2. **Distribuzione:** il codice ricevuto deve corrispondere alla release
   verificata e non a una versione malevola mirata.
3. **Rete:** ISP, DNS, proxy, firewall e osservatori Tor possono vedere
   metadati.
4. **Infrastruttura:** amministratori di relay e hosting possono osservare,
   ritardare, riprodurre, eliminare o servire selettivamente dati cifrati.
5. **Organizzazione:** custodi, operatori, auditor e investigatori hanno poteri
   legittimi differenti e possibili conflitti.
6. **Persone:** un destinatario può copiare il plaintext, acquisire schermate o
   inferire l'identità dal contenuto.

## 7. Modello di minaccia

L'avversario di base può gestire uno o più relay, osservare una normale tratta
di rete, enumerare eventi pubblici, riprodurre ciphertext validi e inviare
molte segnalazioni. Un avversario più forte può controllare l'origine web o un
amministratore organizzativo, correlare più reti oppure compromettere un
endpoint.

La riservatezza e l'integrità del contenuto devono resistere a un relay
malevolo. Infrastrutture indipendenti riducono alcuni rischi di disponibilità.
La resistenza alla traffic analysis può essere dichiarata solo se trasporto,
padding, batching, polling e deployment sono provati contro l'osservatore
indicato. Più relay possono aumentare la continuità ma anche il numero di
osservatori.

Compromissione degli endpoint, distribuzione mirata di codice alterato,
coercizione e identificazione dal contenuto restano rischi residui. Un profilo
più forte può richiedere client nativo firmato, build riproducibili, Tor/onion e
un canale indipendente di verifica della release. Sono decisioni separate.

## 8. Architettura concettuale

```text
client del segnalante
  -> nuovo contesto crittografico per caso
  -> envelope cifrato del caso
  -> adattatore di trasporto con minimizzazione dei metadati
  -> uno o più servizi store-and-forward non fidati
  -> adattatore di intake organizzativo
  -> workspace degli operatori autorizzati

risposta dell'operatore
  -> envelope cifrato del caso
  -> servizi store-and-forward
  -> polling capability-based del client
```

Il profilo applicativo definisce stati, ricevute, routing, ruoli, retention e
UX. Il core Styx fornisce oggetti cifrati versionati, protezione da replay,
stato di delivery, gestione capability e astrazione del trasporto. Nostr,
dropbox HTTPS, onion service e supporti offline sono adattatori: nessuno di essi
deve definire identità del caso o schema plaintext.

Cifra, envelope, costruzione delle chiavi destinatario, multi-recipient,
padding e codifica della capability richiedono processi crittografici e di
formato persistente separati e approvati. Questo documento non li seleziona.

## 9. Flusso end-to-end

### 9.1 Accesso sicuro

Prima dell'inserimento, il client avverte che dispositivi e reti di lavoro
possono essere monitorati. Un deployment ad alta garanzia offre un client
verificabile separatamente e un percorso di rete adatto al threat model.

Email, SMS, analytics, font di terze parti, pubblicità, telemetria remota con
payload e notifiche push legate all'identità sono esclusi dal flusso predefinito.

### 9.2 Creazione

Il client genera localmente:

- un contesto nuovo per il caso;
- una return capability casuale ad alta entropia;
- il materiale necessario a proteggere il dialogo.

Non consulta account Styx, chiavi Nostr, rubrica o sessioni chat precedenti. La
domain separation impedisce il riuso di chiavi, firme e identificatori fra app
o casi.

Il client acquisisce un descrittore di intake autenticato che indica ruolo
destinatario, versioni supportate, scadenza, trasporti e identità della release.
La fiducia nel descrittore e nel suo canale di distribuzione deve essere
visibile e documentata.

### 9.3 Invio

Il client cifra un oggetto di caso versionato per il ruolo autorizzato, applica
la policy di minimizzazione e invia envelope opachi ridondanti.

Gli stati devono restare distinti:

1. salvataggio locale durevole;
2. accettazione da parte del relay;
3. ricezione crittografica del workspace;
4. presa in carico umana;
5. lettura o risposta.

L'interfaccia non può mostrare “ricevuta dall'organizzazione” dopo la sola
accettazione del relay.

### 9.4 Return capability

Dopo un salvataggio locale durevole, il client mostra una volta la capability
in una forma gestibile, per esempio scheda di recupero o QR. Codifica e backup
sono decisioni separate; il segreto sottostante deve resistere a tentativi
online e offline.

La capability:

- autorizza un solo caso;
- non compare in query URL, log, cronologia, telemetria, crash report, referrer o
  tabella account server-side;
- non deriva da frase debole, numero pratica, email o hash di dati indovinabili;
- non viene correlata a un'identità durevole.

Senza escrow o identificazione il server non può recuperare una capability
persa. Il prodotto deve dirlo prima che il segnalante lasci il flusso.

### 9.5 Dialogo

Il segnalante torna attraverso l'accesso sicuro e presenta localmente la
capability. Il client riapre il contesto, esegue polling tramite token di
trasporto non collegabile, verifica la cronologia e invia nuove risposte.

Il polling manuale è il default più prudente. Le notifiche sono facoltative solo
dopo aver spiegato correlazione e metadati. Il protocollo richiede idempotenza,
ordering autenticato, deduplica e gestione esplicita dei gap. Un vecchio oggetto
valido riprodotto dal relay non deve sostituire silenziosamente lo stato
corrente.

### 9.6 Divulgazione facoltativa dell'identità

Rivelare l'identità è un'azione distinta ed esplicita. L'UI mostra campi e
destinatari esatti; l'oggetto risultante registra scopo e consenso. Una
divulgazione successiva non autorizza a collegare retroattivamente altri casi.

## 10. Gestione del segreto di recupero

Il client dovrebbe:

- generare la capability con sorgente casuale crittograficamente sicura;
- escluderla da DOM persistente, URL, log, telemetria e clipboard dove possibile;
- conservarla nel vault locale cifrato solo con scelta esplicita;
- suggerire una copia offline privata, avvertendo su screenshot e cloud foto;
- applicare rate limit e risposte che non diventino un oracolo di enumerazione;
- ridurre differenze di contenuto e timing fra lookup validi e non validi;
- offrire rimozione locale senza promettere cancellazione fisica da flash,
  backup, profili sincronizzati o IndexedDB.

Recovery diviso o delegato può ridurre le perdite ma crea nuovi poteri di
correlazione e custodia. Richiede una decisione separata e non può essere
abilitato invisibilmente.

## 11. Workflow degli operatori

Un deployment organizzativo definisce almeno:

1. titolarità dell'intake e routing dei conflitti d'interesse;
2. operatori principali e sostituti formati, con least privilege;
3. scadenze di ricezione, seguito e riscontro per ogni percorso;
4. stati quali inviato, ricevuto tecnicamente, preso in carico, in valutazione,
   in attesa, trasferito, chiuso e conservato;
5. richieste di chiarimento che non inducano a identificarsi;
6. escalation per pericolo, safeguarding, conservazione delle prove e obblighi
   esterni;
7. sostituzione operatori, rotazione chiavi e copertura delle assenze;
8. autorizzazione di export, redazione, disclosure e cancellazione;
9. comunicazione al segnalante di incidenti e scadenze mancate;
10. verifica indipendente periodica di accessi, routing, retention e continuità.

Quando si applica il D.Lgs. 24/2023, il workflow deve essere configurato e
validato per i relativi termini. Altri canali possono avere scadenze diverse:
un unico timer generico sarebbe fuorviante.

Le chiavi organizzative rappresentano un ruolo e una policy, non la normale
identità chat del dipendente. Rotazioni e revoche producono eventi verificabili.
Destinatario dedicato, multi-recipient, threshold custody e HSM sono alternative
da decidere separatamente.

## 12. Minimizzazione dei metadati

Il profilo considera congiuntamente:

- IP e percorso di rete;
- account relay, chiave pubblica o client identifier stabile;
- tempi di invio e polling;
- dimensioni di eventi e allegati;
- fingerprint e richieste di terze parti;
- tag destinatario e marker organizzativi;
- esistenza, stato e frequenza di accesso al caso;
- log che colleghino amministrazione e sessione del segnalante.

Tor/onion, batching, ritardi, classi di padding e cover traffic possono ridurre
alcune esposizioni ma hanno costi e limiti. La cifratura del contenuto non le
nasconde.

Un proxy o firewall aziendale registrato può osservare l'accesso alla
piattaforma. Nessun client rende invisibile a quella rete un accesso effettuato
direttamente attraverso di essa.

## 13. Allegati e sicurezza del contenuto

Il primo profilo ad alta garanzia dovrebbe essere text-only. Gli allegati
possono contenere autore, dispositivo, posizione, timestamp, cronologia,
thumbnail, malware, contenuti attivi e dettagli visivi identificanti.

Prima di abilitarli servono:

- ispezione e rimozione locale dei metadati;
- conversione in formati sicuri e isolamento malware;
- chunk cifrati, manifest autenticato e ripresa degli invii;
- padding per classi di dimensione;
- policy separate per originale e copia sanitizzata;
- avviso che la sanitizzazione non elimina indizi visibili.

Anche il testo libero può identificare tramite fatti, lessico o stile. Il client
può offrire avvisi e anteprima locale, ma non deve riscrivere silenziosamente
una possibile evidenza.

## 14. Resistenza agli abusi

Un canale anonimo può ricevere spam, flood, sonde, malware e molestie. I
controlli non devono ricreare tracking identitario. Candidati:

- limiti di messaggi e allegati;
- quote per capability e rate limit dipendenti dallo stato;
- proof-of-work o credenziali anonime di rate limiting;
- limiti grossolani prima delle operazioni crittografiche costose;
- isolamento delle code, backpressure e budget di storage;
- controlli di sicurezza locali e lato operatore;
- capability revocabile con policy di riapertura;
- failover senza blocklist globale dei segnalanti.

CAPTCHA, verifica telefonica, cookie stabili, reputazione IP e servizi antifrode
commerciali possono danneggiare anonimato e accessibilità. Ogni uso richiede
valutazione specifica e test contro denial of service per utenti legittimi,
inclusi Tor e tecnologie assistive.

## 15. Retention, audit ed export

La retention dipende dal percorso validato e parte da un evento definito. Anche
dati cifrati riferibili a persone possono essere dati personali. Il sistema
dovrebbe supportare scadenza automatica, legal hold autorizzato, chiusura
visibile quando appropriato e rimozione delle repliche senza promettere
cancellazione fisica non dimostrabile.

L'audit può registrare pubblicazione del descrittore, cambi di ruolo, accessi,
presa in carico, routing, export e variazioni della policy. Deve evitare
plaintext, capability, metadati di origine e identificatori stabili superflui.
La tamper evidence rileva alcune alterazioni ma non prova che l'azione umana sia
corretta o che nessuna azione sia stata nascosta.

Gli export richiedono manifest autenticato, redazione, destinatario, scopo,
verifica d'integrità e scadenza. Un PDF plaintext non costituisce da solo un
handover sicuro.

## 16. Disponibilità e continuità

Il trasporto dovrebbe tollerare un relay indisponibile o censorio, riconciliare
duplicati e distinguere ritardo da ricezione confermata. L'organizzazione
necessita di intake di riserva monitorato, recovery delle chiavi provato,
copertura delle assenze e canale incidenti che non esponga casi attivi.

Federazione e più relay riducono alcuni single point of failure, ma non
eliminano server, operatori, capacity planning, denial of service o difetti
software comuni. I drill devono includere perdita di relay, regione, operatore
e custode delle chiavi.

## 17. Relazione con il repository corrente

Il repository contiene primitive utili, ma non un prodotto di segnalazione
anonima:

- lo stack JavaScript attivo fornisce sessioni cifrate, trasporto Nostr e un
  vault locale ancora in evoluzione;
- chat e identità durevole correnti sono inadatte alla creazione anonima;
- pubblicazione sul relay non equivale a ricevuta end-to-end;
- pairing remoto, outbox durevole, domain separation applicativa, multi-device,
  routing con metadati ridotti e custodia per ruolo sono incompleti o richiedono
  decisioni separate;
- la fiducia first-load della PWA non resiste da sola a un'origine malevola
  mirata;
- lo stack Dart è reference implementation, non il percorso di prodotto.

Il vault può fungere da canary per la custodia locale, ma completarlo non
soddisfa da solo questo caso d'uso.

## 18. Validazione per fasi

### Fase A — Protocollo e governance

- approvare threat model e assurance profile;
- definire oggetti, stati, ricevute, replay e domain separation;
- completare review crittografica e dei formati;
- mappare ruoli, routing, retention, incidenti e responsabilità;
- eseguire una DPIA quando richiesta.

### Fase B — Pilota tecnico text-only

- identità nuova per caso e capability senza account;
- invio, presa in carico, chiarimento, risposta e chiusura cifrati;
- outbox/inbox durevoli, replay, deduplica, failover e padding limitato;
- polling manuale, senza allegati, analytics o codice di terze parti;
- rotazione operatori e percorso verso destinatario indipendente.

### Fase C — Verifica avversariale

- review indipendente di protocollo, client, workspace e deployment;
- test di relay malevolo, rollback, enumerazione, spam, esaurimento code,
  revoca e outage regionale;
- misura dei metadati visibili a relay, hosting, reti aziendali e osservatori
  collusi;
- test della distribuzione mirata e della verifica degli artefatti;
- studi di usabilità e accessibilità sotto stress.

### Fase D — Pilota organizzativo limitato

- percorso e popolazione esplicitamente limitati;
- formazione e test di scadenze, escalation, assenze e incident response;
- pubblicazione dei limiti e di un canale alternativo sicuro;
- sole metriche aggregate non identificanti;
- decisione congiunta di security, privacy, legal, safeguarding e responsabili
  organizzativi prima dell'espansione.

## 19. Evidenze di accettazione future

Un'implementazione dovrebbe provare che:

- due casi dello stesso client pulito non condividono identificatori di
  protocollo;
- la creazione non legge né emette identità chat o Nostr ordinarie;
- compromissione di relay, origine e database non rivela plaintext protetto;
- oggetti alterati, riordinati, duplicati, mancanti o in rollback falliscono in
  modo chiuso o producono uno stato esplicito;
- storage relay e presa in carico umana non vengono confusi;
- perdita e revoca degli operatori seguono il modello di custodia;
- enumerazione e guessing della capability rispettano obiettivi misurati;
- l'osservatore dichiarato vede soltanto i metadati consentiti dal profilo;
- retention ed export producono audit minimizzato;
- ogni client supportato copre offline, recovery e accessibilità;
- revisori indipendenti riproducono i test in ambienti puliti.

Il superamento vale soltanto per profilo e deployment esaminati e non autorizza
affermazioni generiche di anonimato o conformità.

## 20. Rischi residui

Restano:

- endpoint compromessi, estensioni malevole, keylogger, screenshot, shoulder
  surfing e coercizione;
- distribuzione first-load mirata di codice modificato;
- correlazione temporale e di traffico da osservatori capaci o collusi;
- censura, ritardo e cancellazione da parte di relay o organizzazione;
- identificazione tramite fatti, stile, allegati o insieme anonimo ristretto;
- uso di rete monitorata, riuso di testo, condivisione della capability o
  salvataggio in account sincronizzato;
- copia e disclosure non autorizzata da parte dei destinatari;
- impossibilità di recuperare una capability non escrowed realmente persa;
- cancellazione fisica incompleta da dispositivi, backup, IndexedDB e relay;
- cambi normativi e decisioni umane di routing errate.

Questi rischi devono essere comunicati a segnalanti e operatori nel momento
della decisione, non nascosti in un'appendice tecnica.

## 21. Fonti ufficiali

Fonti consultate il **2026-08-06**. Sono riferimenti contestuali: professionisti
qualificati devono verificarne testo corrente e applicazione al deployment.

- [UNI/PdR 125:2022, Linee guida sul sistema di gestione per la parità di genere](https://certificazione.pariopportunita.gov.it/public/dist/resources/prassi-di-riferimento-unipdr-pdr100866103.pdf), in particolare §6.3.2.6.
- [D.Lgs. 24/2023, art. 4 — canali di segnalazione interna](https://www.gazzettaufficiale.it/atto/serie_generale/caricaArticolo?art.codiceRedazionale=23G00032&art.dataPubblicazioneGazzetta=2023-03-15&art.flagTipoArticolo=0&art.idArticolo=4&art.idGruppo=2&art.idSottoArticolo=1&art.idSottoArticolo1=10&art.progressivo=0&art.versione=1).
- [D.Lgs. 24/2023, art. 5 — gestione del canale interno](https://www.gazzettaufficiale.it/atto/serie_generale/caricaArticolo?art.codiceRedazionale=23G00032&art.dataPubblicazioneGazzetta=2023-03-15&art.flagTipoArticolo=0&art.idArticolo=5&art.idGruppo=2&art.idSottoArticolo=1&art.idSottoArticolo1=10&art.progressivo=0&art.versione=1).
- [ANAC, Whistleblowing](https://www.anticorruzione.it/-/whistleblowing).
- [ANAC, segnalazioni escluse dall'ambito oggettivo del D.Lgs. 24/2023](https://www.anticorruzione.it/documents/91439/146849359/7.%2BApprofondimenti%2Bambito%2Boggettivo%2B%E2%80%93%2BLe%2Bsegnalazioni%2Bescluse%2Bdall%E2%80%99applicazione%2Bdella%2Bnormativa%2B%C2%A7%2B2.1.1.pdf/8d2cdc24-20bf-1c72-c73b-e72adf5efaae?t=1689329633903).
- [Garante per la protezione dei dati personali, parere sulle linee guida ANAC 2025](https://www.garanteprivacy.it/home/docweb/-/docweb-display/docweb/10184673), incluse osservazioni su privacy by design, DPIA, retention, cifratura, log email e rete lavorativa.
