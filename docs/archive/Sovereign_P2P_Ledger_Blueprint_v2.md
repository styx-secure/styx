Ecco il **Manifesto Tecnico e la Guida all'Implementazione** della libreria. Questo documento è progettato per fornire a uno sviluppatore senior una visione d'insieme chiara, i dettagli crittografici necessari e le soluzioni architettoniche per costruire il sistema da zero.

---

# 📖 Specifica Tecnica: P2P Ledger Core Library — v2

**Visione:** Creare un sistema di documentazione finanziaria e accountability dove la fiducia è garantita dalla matematica e la privacy dall'assenza totale di server centrali.

---

## 1. Il Concept Core: "Fiducia Crittografica"

L'idea base è trasformare ogni azione finanziaria (una spesa, un messaggio, un SOS) in un **evento immutabile** all'interno di un registro distribuito tra due soli attori: l'**Affidante** e il **Custode**.

* **Zero-Server:** Nessun dato transita o risiede su server proprietari. L'unica eccezione tollerata è un Push Bridge stateless (Sezione 6B) che non vede, non conserva e non decifra alcun dato.

* **Peer-to-Peer:** La comunicazione avviene direttamente tra i due dispositivi.

* **Sovranità del dato:** L'utente è l'unico possessore delle proprie chiavi e dei propri dati.

---

## 2. Architettura dell'Identità (Identity Layer)

Non esistono nomi utente o password. L'identità è determinata da una coppia di chiavi asimmetriche generate localmente.

* **Algoritmo:** **Ed25519** per le firme digitali e **X25519** per lo scambio di chiavi (Diffie-Hellman).

* **Storage:** Le chiavi private devono risiedere esclusivamente in enclave hardware isolate (**Android Keystore** / **iOS Keychain**).

* **Immutabilità dell'ID:** Una volta generata, l'identità è legata permanentemente al dispositivo a meno di un backup manuale (es. via Shamir's Secret Sharing con threshold scheme 2-of-3).

### 2A. Device Migration (Re-Keying Protocol)

Quando un utente cambia dispositivo, è necessario un protocollo di migrazione che preservi la continuità dell'identità senza compromettere la sicurezza.

* **Blessing Event:** Il vecchio dispositivo firma un evento di tipo `REKEY` contenente la nuova chiave pubblica generata sul nuovo dispositivo. Questo evento viene inserito nella catena come qualsiasi altro, garantendo tracciabilità.

* **Trust Store Update:** Il peer ricevente verifica la firma del vecchio dispositivo e aggiorna il proprio trust store con la nuova chiave pubblica.

* **Pruning del Re-Key:** L'evento di re-keying stabilisce una correlazione tra due identità crittografiche dello stesso utente (dato personale ai fini GDPR). Una volta che entrambi i peer lo hanno processato, il payload può essere eliminato tramite Secure Pruning (Sezione 7), conservando solo l'hash.

* **Fallback — Export Cifrato:** Se il vecchio dispositivo non è più disponibile, l'utente può ripristinare la propria identità da un backup Shamir precedentemente creato. In questo caso non è necessario re-keying perché la chiave originale viene ricostruita.

---

## 3. Il Ledger: Catena Append-Only (Integrity Layer)

Ogni evento è un anello di una catena crittografica che non può essere spezzata o alterata.

* **Struttura Evento:** Ogni record contiene l'hash **SHA-256** dell'evento precedente, un timestamp ISO 8601, il **Vector Clock** corrente (Sezione 3A), il tipo di evento (TRANSACTION, SOS, CONFIG, REKEY, PRUNE_REQUEST, PRUNE_ACK) e il payload cifrato.

* **Firma obbligatoria:** Ogni evento deve essere firmato dal mittente per essere considerato valido dal ricevente.

* **Verifica della catena:** All'apertura dell'app, il sistema ricalcola ricorsivamente tutti gli hash. Se un solo bit è stato alterato nel database locale, la catena risulta corrotta.

### 3A. Conflict Resolution (Vector Clocks)

Con due peer che possono operare offline simultaneamente, possono verificarsi fork nella catena quando entrambi creano eventi a partire dallo stesso "ultimo evento". Per risolvere questo problema senza arbitri centrali, ogni evento include un **Vector Clock** a due elementi.

* **Struttura:** `{ "A": <counter_A>, "B": <counter_B> }` dove ogni peer incrementa il proprio contatore ad ogni evento creato.

* **Causalità:** Se il vector clock di un evento domina strettamente quello di un altro (tutti i contatori ≥ e almeno uno >), l'evento è causalmente successivo. Se nessuno dei due domina, gli eventi sono **concorrenti** (fork).

* **Merge deterministico:** In caso di fork, entrambi i peer applicano la stessa regola di ordinamento deterministica: si ordina per contatore totale (somma dei componenti), e a parità si ordina per chiave pubblica del mittente (ordine lessicografico). Questo garantisce che entrambi i peer convergano sulla stessa sequenza senza comunicazione aggiuntiva.

* **Merge Event:** Dopo la riconciliazione, il peer che rileva il fork crea un evento speciale di tipo `MERGE` che referenzia entrambe le punte del fork tramite i rispettivi hash, ristabilendo una catena lineare.

* **Impatto su Pruning e GDPR:** I vector clock sono metadati strutturali privi di informazioni personali. Risiedono nell'header dell'evento e non sono soggetti a pruning.

---

## 4. Protocolli di Comunicazione (Transport Layer)

La libreria è agnostica rispetto al trasporto ma definisce una **gerarchia esplicita** con tre livelli di priorità:

### 4A. Nostr — Trasporto Primario

Utilizzo di relay decentralizzati per scambiarsi "Eventi Nostr" cifrati via WebSockets. Questo è il canale preferito per la sua natura P2P nativa, la bassa latenza e l'assenza di account centralizzati.

* La libreria si connette a un pool configurabile di relay pubblici o privati.
* I messaggi sono cifrati end-to-end prima di essere pubblicati come eventi Nostr (NIP-04 o NIP-44).
* Il relay non vede il contenuto — funge esclusivamente da casella postale cieca.

### 4B. Email — Fallback Universale

Utilizza account email esistenti tramite **IMAP/SMTP** come canale di fallback quando Nostr non è raggiungibile.

* I messaggi cifrati vengono inseriti come allegati binari o header custom.
* Questo canale garantisce interoperabilità massima: qualsiasi utente con un indirizzo email può partecipare.
* Lo svantaggio è la latenza maggiore e la dipendenza da provider email potenzialmente centralizzati (mitigata dalla cifratura E2E del payload).

### 4C. Tor — Overlay Opzionale di Anonimato

Tor non è un trasporto separato ma un **overlay di rete** applicabile ai canali precedenti.

* I relay Nostr possono essere raggiunti attraverso Tor, nascondendo l'IP reale del dispositivo.
* L'attivazione di Tor è opzionale e configurabile dall'utente, dato che introduce latenza significativa, bootstrap lento e consumo di batteria non trascurabile.
* Tor è consigliato solo in scenari ad alto rischio dove l'anonimato di rete è prioritario rispetto alla reattività.

---

## 5. Pairing ed Handshake (Trust Layer)

L'abbinamento è l'unico momento in cui le chiavi pubbliche vengono scambiate.

### 5A. Pairing Fisico (QR Code)

Scansione diretta per garantire che la chiave appartenga alla persona presente fisicamente. Il QR contiene la chiave pubblica Ed25519 del peer e un nonce monouso.

### 5B. Pairing Remoto (SPAKE2 + Mnemonic)

Il pairing remoto utilizza il protocollo **SPAKE2** (Simple Password Authenticated Key Exchange) per rendere sicuro l'utilizzo di un codice mnemonico corto come punto di incontro.

* **Mnemonic:** Generazione di un codice di **6-8 parole** dalla wordlist **BIP-39** (~66-88 bit di entropia), comunicato fuori banda (voce, SMS, altro canale).
* **SPAKE2 Handshake:** Il codice mnemonico viene usato come password condivisa nel protocollo SPAKE2, che genera una chiave di sessione sicura anche se il codice ha entropia relativamente bassa. SPAKE2 è resistente ad attacchi dizionario offline: un attaccante che osserva lo scambio sui relay non può derivare la password provando tutte le combinazioni.
* **Key Exchange:** Una volta stabilita la chiave di sessione SPAKE2, i peer si scambiano le rispettive chiavi pubbliche Ed25519 attraverso il canale cifrato.

### 5C. Double Check (Verifica MITM)

Dopo lo scambio, viene mostrato un codice di controllo a 6 cifre (derivato dall'hash della sessione) che gli utenti devono confermare vocalmente o via altro canale per prevenire attacchi Man-in-the-Middle.

---

## 6. Soluzioni alle Sfide Mobile (Reliability Layer)

### 6A. Local Outbox (Offline Resilience)

Per gestire la mancanza di rete, la libreria implementa una coda di invio persistente in SQLite. I messaggi vengono salvati in stato `pending` e inviati automaticamente non appena viene rilevata connettività, rispettando l'ordine causale definito dai Vector Clocks (non solo cronologico).

### 6B. Wake-Up e Notifiche (Push Bridge Architecture)

Il polling periodico è **eliminato**. Il dispositivo non si sveglia mai autonomamente per controllare nuovi dati. L'unico meccanismo di wake-up è basato su **push notifications** tramite un Push Bridge stateless.

#### Push Bridge Stateless

Un microservizio minimale che funge da ponte tra i relay Nostr e il servizio di push nativo del sistema operativo (FCM per Android, APNs per iOS).

* **Funzionamento:** Il bridge sottoscrive i relay Nostr per conto del dispositivo. Quando rileva un nuovo evento destinato alla pubkey registrata, invia un **data-only message** (FCM) o **background notification** (APNs) contenente esclusivamente un flag "ci sono dati nuovi". Nessun payload sensibile transita attraverso il bridge.
* **Stateless by design:** Il bridge non conserva messaggi, non possiede chiavi private, non mantiene log. Conosce esclusivamente il token FCM/APNs e il filtro Nostr (pubkey destinatario). Non è in grado di leggere o decifrare alcun contenuto.
* **Sovranità preservata:** Il bridge è l'equivalente digitale di un campanello: sa solo che qualcuno ha bussato, non sa cosa c'è dentro casa. Non viola il principio zero-server perché non tratta dati personali.

#### Ricezione lato Device

Alla ricezione della push notification, l'app si sveglia in background, si connette direttamente al relay Nostr, scarica gli eventi cifrati e li processa localmente. Il bridge non è mai coinvolto nel trasferimento dei dati reali.

#### Profili Privacy-Batteria

Per mitigare il rischio di **metadata leakage** (Google/Apple possono osservare i pattern temporali delle notifiche), la libreria offre tre profili configurabili dall'utente:

* **Balanced (default):** Nessuna dummy notification. Il bridge invia segnali solo quando ci sono eventi reali. Consumo batteria minimo. Privacy buona ma non perfetta — il provider push conosce i tempi di comunicazione.

* **Private:** Dummy notifications a intervalli casuali con **distribuzione di Poisson** (media configurabile, es. 4-6 al giorno). Le dummy portano un flag interno che l'app riconosce immediatamente al wake-up: controlla il flag locale, rileva che è una dummy, e **torna a dormire senza alcuna connessione di rete**. Il costo energetico è trascurabile (pochi millisecondi di CPU, zero I/O di rete). I pattern temporali delle notifiche reali diventano indistinguibili dal rumore.

* **Paranoid:** Dummy ad alta frequenza con **connessione reale al relay** ad ogni wake-up, incluse le dummy. Questo rende indistinguibile anche il pattern di traffico di rete, non solo quello delle notifiche. Il costo batteria è misurabile e l'utente viene informato al momento della selezione del profilo.

---

## 7. Conformità e Data Lifecycle (Compliance Layer)

Sebbene il ledger sia immutabile, la libreria deve rispettare il **GDPR**.

### 7A. Secure Pruning con Consenso Bilaterale

La cancellazione di contenuti sensibili richiede un protocollo di consenso tra entrambi i peer per evitare asimmetrie informative.

* **PRUNE_REQUEST:** Il peer che desidera eliminare un payload invia un evento di tipo `PRUNE_REQUEST` referenziando l'hash dell'evento target e il motivo (retention scaduta, richiesta utente, esercizio Art. 17 GDPR).
* **PRUNE_ACK:** Il peer ricevente conferma con un evento `PRUNE_ACK`. A questo punto entrambi i peer eliminano il payload localmente.
* **Hash Persistence:** Viene rimosso il payload ma conservato l'hash originale. Questo permette di mantenere integra la catena crittografica dimostrando che l'evento è esistito, pur distruggendo l'informazione privata.
* **Pruning unilaterale (Art. 17 GDPR):** Se un peer esercita il diritto alla cancellazione e l'altro non conferma, il richiedente può comunque eliminare il proprio payload locale. L'hash resta come prova di esistenza sulla catena dell'altro peer, soddisfacendo sia il diritto alla cancellazione sia l'integrità della catena. L'evento `PRUNE_REQUEST` viene registrato nella catena come prova della richiesta.

### 7B. Retention Automatica

È possibile configurare periodi di retention dopo i quali il sistema avvia automaticamente il protocollo di pruning per contenuti sensibili (es. foto di scontrini, allegati).

### 7C. Database Encryption

Tutto il database locale è protetto da **SQLCipher (AES-256)**.

---

## 8. Schema di Implementazione per lo Sviluppatore

1. **Setup Crittografico:** Implementare la generazione delle chiavi Ed25519/X25519 in hardware-safe mode. Includere la logica SPAKE2 per il pairing remoto.

2. **Database Engine:** Creare il ledger in SQLite/SQLCipher con logica di Event Sourcing. Includere i Vector Clocks nella struttura degli eventi e la logica di merge deterministico.

3. **Transport Interface:** Implementare il modulo di invio/ricezione con gerarchia Nostr (primario) → Email (fallback). Tor come overlay opzionale.

4. **Push Bridge:** Implementare il microservizio stateless per il wake-up via FCM/APNs. Implementare i tre profili privacy-batteria (Balanced, Private, Paranoid) con logica dummy lato client.

5. **Pairing UI:** Sviluppare i widget Flutter per la generazione QR, l'inserimento codici mnemonici a 6-8 parole e la verifica Double Check.

6. **Pruning Protocol:** Implementare il flusso bilaterale PRUNE_REQUEST → PRUNE_ACK con fallback unilaterale per Art. 17.

7. **Device Migration:** Implementare il protocollo di Re-Keying con Blessing Event e aggiornamento del trust store.

8. **Background Worker:** Configurare il wake-up esclusivamente via push notification. Nessun polling.

---

Questa architettura garantisce che l'applicazione sia **privata per design, sicura per matematica, resiliente per architettura e sovrana per scelta dell'utente**.
