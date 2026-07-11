# Styx Chat — Security Report: Audit e Piano di Remediation

**Data:** 2026-07-10
**Branch analizzato:** `feature/styx-chat-mls` @ `4c9f7de`
**Perimetro:** `styx-js/src/chat/`, `styx-js/src/crypto/mls/`, `styx-js/src/transport/`, `styx-js/src/storage/`, `styx-js/vendor/openmls-wasm/`
**Metodo:** revisione manuale del codice sorgente. Nessun test dinamico, nessun exploit eseguito, nessuna modifica al codice.
**Domanda posta:** *è possibile intercettare e leggere i messaggi? è possibile capire chi invia a chi?*
**Struttura del documento:** §0–4 audit delle vulnerabilità (§4B: seconda passata a occhi freschi, N1–N4); §5 modello dell'avversario di rete; §6 piano di remediation (Fasi A–D); §7 validazione esterna e nuove strategie (ricerca deep-research su fonti primarie); §8 limiti. La **Fase C** (§6) include il **design implementativo completo** della privacy dei metadati (gift-wrap NIP-59) — prima un documento separato, ora integrato qui come documento unico.

---

## Stato di attuazione — aggiornato al 2026-07-11

Il documento resta l'audit originale; questa sezione dice soltanto **cosa è stato chiuso da allora**, per non lasciar credere aperto ciò che non lo è più.

**Chiuso — Fase A, autenticazione del canale** (JS, commit `d0a4462`…`6999cb0`): **C1** (verifica firma/id Nostr in ricezione), **C2** (nessuna sovrascrittura di sessione), **C3** (trasporto non autenticato dietro opt-in di sviluppo), **H3** (safety number verificabile dall'utente), **M1**, **M2**, **M3**.

**Chiuso — Blocco 1, hardening del crate vendorizzato** (commit `363a3ad`…`d7445fd`; piano: `docs/superpowers/plans/2026-07-11-blocco1-wasm-hardening.md`):

| Voce | Esito |
|---|---|
| **N1** — panic del WASM = DoS del motore | **Chiusa.** `process_message` restituisce errori invece di trappare. Dimostrata empiricamente: contro l'artefatto pre-fix i test catturano un `WebAssembly.RuntimeError`; dopo il fix l'engine continua a funzionare. Copertura: `test/crypto/mls-panic.test.js` + `test/crypto/mls-adversarial.test.js` (Welcome, ratchet tree, KeyPackage corrotti + fuzz seminato su 300 parse). |
| **N2** — binding credenziale MLS↔identità | **Chiusa.** `Group.member_identities()` nel patch Rust, `MlsEngine.peerIdentity()` in JS, e il rifiuto del join se la credenziale del peer ≠ il pubkey che ha inviato il gruppo. Erano **due** buchi vivi, entrambi dimostrati da test rossi prima del fix: lato scanner (QR forgiato con il KeyPackage di un terzo) e lato wire (Welcome di terzi rilanciato da chi ha fotografato il QR). |
| **R1** — versione OpenMLS | **Rettificata, non applicata.** Il pin `09e9277` **portava già** i fix dell'audit SRLabs: è discendente del tag `openmls-v0.8.1` (76 commit avanti, 0 indietro) e il fix S3-7 è verificato nel sorgente (`equal_ct` esegue il controllo di lunghezza che in v0.7.0 mancava). Aggiornare al tag sarebbe stato un **downgrade** e avrebbe rotto il formato di storage persistito. Vedi `vendor/openmls-wasm/PROVENANCE.md`. |
| Supply chain del crate | Toolchain pinnata per digest, wasm-pack con sha256 verificato, `Cargo.lock` vendorizzato, build **riproducibile byte per byte** (`verify.sh`), README riallineato al ciphersuite realmente compilato. |

**Scoperto durante il lavoro, ancora aperto:** processare un Welcome fa **consumare a MLS la chiave init privata** del KeyPackage. Un invito QR è quindi speso anche quando il gruppo viene rifiutato: chi fotografa il QR può bruciarlo (DoS di griefing). Mitigato (l'invito viene ritirato onestamente e l'app riceve un evento `invite-rejected`), non eliminato — rientra in **N4**/R2, insieme alla scadenza degli inviti.

**Emerso dalla review architetturale (2026-07-11):**
- **Residuo forense at-rest.** Un join MLS rifiutato (impostore lato scanner o lato wire) lascia la **credenziale e il materiale di gruppo del peer respinto** dentro `mls:state`: `serialize_state` scarica l'intera HashMap del provider e il crate non espone una delete, quindi `removeSession` dimentica solo l'handle JS. Su un dispositivo sequestrato, il blob rivela **chi ha tentato il pairing** — rilevante per il threat model giornalisti/attivisti. Il commento di `removeSession` ora lo dichiara onestamente; la cancellazione per-gruppo è tracciata per il Blocco 5.0 (batch API wasm).
- **Trap in `restore_state` — chiusa.** La deserializzazione del blob di stato faceva aritmetica di offset non controllata (`u64 as usize` + `i+kl+vl` che va in wrap su wasm32): un `mls:state` corrotto o ostile trappava l'istanza all'init — la stessa classe di N1. Chiusa con aritmetica checked; regressione provata (`test/crypto/mls-adversarial.test.js`, il caso di wrap trappa sull'artefatto pre-fix). Oggi il blob viene da `localStorage` (self-brick), ma con state sync/backup/StorageProvider sarebbe diventata raggiungibile da remoto.

**Restano aperte:** **H1** (storage in chiaro a riposo), **H2** (metadati esposti al relay), **M4**, **M5**, **M6**, **N3**, **N4**, **R2**–**R6**, Fasi B/C/D. La roadmap normativa è `docs/security/2026-07-11-fattibilita-piano-utente.md`.

---

## 0. Verdetto

**Intercettare e leggere i messaggi: possibile, ma a una precondizione precisa.** Non è alla portata di un relay dal nulla: la chiave d'invito (il **KeyPackage**, con il suo `init_key` a cui è sigillato il Welcome MLS) viaggia **solo dentro il QR** e non tocca mai la rete. Finché il QR è scambiato di persona e resta confidenziale, il contenuto è protetto **anche contro un relay attivo**. L'attacco diventa possibile solo quando l'invito passa su un **canale osservabile** (email, telefono, screenshot, QR riusato o mostrato in videochiamata) o quando il pairing è **remoto**: in quel caso un relay ostile monta un MITM completo e **non rilevabile**, senza rompere la crittografia. Il difetto quindi non è in MLS, né "il QR è insicuro" — è che **manca ogni difesa in profondità** (verifica firma, rifiuto di sessioni sostitutive, safety number), così la fuga dell'invito diventa catastrofica invece che innocua. Vedi C1, C2, H3 e la §5.2.

**Capire chi invia a chi: sì, banalmente.** Ogni relay vede il grafo sociale completo in chiaro. Questa non è una svista: è documentata in un commento nel codice come debito tecnico accettato per la fase di test.

Il motore crittografico è la parte solida del sistema. La superficie che lo circonda — autenticazione del peer, privacy dei metadati, protezione a riposo — non è ancora stata costruita. È esattamente lo stato che ci si aspetta da un MVP funzionante, ma **non è uno stato in cui l'applicazione possa essere usata da persone che dipendono dalla sua sicurezza.**

**Aggiornamento (seconda passata + ricerca esterna).** Una rilettura successiva ha aggiunto quattro vulnerabilità (§4B), tra cui una **Critica di disponibilità** (N1): un singolo messaggio malformato blocca l'intero motore crittografico via panic del WASM — asse distinto da lettura/metadati. Una ricerca su fonti primarie (§7) ha **validato** il nucleo MLS/OpenMLS e il modello di fiducia relay-non-fidato, e ha aggiunto sei azioni di hardening (R1–R6) — dal pin di OpenMLS a una release post-audit alla rotazione delle signing key necessaria per una forward secrecy reale.

### Cosa funziona già bene

| Componente | Giudizio |
|---|---|
| Cifratura del contenuto | **Solida.** MLS (RFC 9420) via OpenMLS-WASM, l'unica implementazione MLS audita (SRLabs) e in produzione. Forward secrecy e post-compromise security native. |
| Applicazione di MLS | **Corretta.** Il testo dei messaggi *e* le ricevute di consegna/lettura passano dentro `session.encrypt()`. Il ratchet viene fatto avanzare e persistito su ogni encrypt/decrypt. Un relay vede base64 opaco. |
| Custodia della chiave d'identità | **Solida.** `EncryptedKeyStore`: PBKDF2-SHA256 a 210.000 iterazioni (linea guida OWASP 2023), AES-GCM-256, salt e IV casuali per record, WebCrypto. Il cambio password ri-cifra correttamente. |
| Scelta architetturale di fondo | **Corretta.** MLS al posto di un Double Ratchet artigianale; il ledger hash-chain esplicitamente degradato da confine di sicurezza a strato di ordinamento. Entrambe le decisioni sono documentate e motivate. |

### Riepilogo delle vulnerabilità

| # | Severità | Titolo | File |
|---|---|---|---|
| **C1** | **Critica** | Nessuna verifica delle firme Nostr in ricezione | `transport/nostr-chat-transport.js:94` |
| **C2** | **Critica** | Un `welcome` non sollecitato sovrascrive una sessione MLS esistente | `chat/styx-chat.js:352`, `crypto/mls/mls-engine.js:139` |
| **C3** | **Critica** | Trasporto BroadcastChannel: mittente auto-dichiarato, nessuna autenticazione | `transport/broadcast-channel-transport.js:21` |
| **H1** | Alta | Stato MLS e cronologia messaggi persistiti in chiaro | `chat/styx-chat.js:336`, `storage/local-storage-backend.js` |
| **H2** | Alta | Metadati completamente esposti al relay (chi → chi, quando, quanto) | `transport/nostr-chat-transport.js:62` |
| **H3** | Alta | Nessun ancoraggio di fiducia verificabile dall'utente (safety number assente) | — (assente) |
| **M1** | Media | Alias trasmesso in chiaro fuori da MLS nell'envelope di pairing | `chat/styx-chat.js:222` |
| **M2** | Media | Auto-inserimento nel roster su `welcome`, con alias controllato dall'attaccante | `chat/styx-chat.js:356` |
| **M3** | Media | Invito QR riutilizzabile, senza nonce né scadenza | `chat/styx-chat.js:205` |
| **M4** | Media | Envelope `typing` non cifrato, non autenticato, accettato da sconosciuti | `chat/styx-chat.js:367` |
| **M5** | Media | Code non limitate: DoS di memoria da mittenti arbitrari | `chat/styx-chat.js:74`, `364` |
| **M6** | Media | Lunghezza del messaggio in chiaro sul filo (nessun padding) | `transport/nostr-chat-transport.js:67` |
| **L1** | Bassa | Firma fittizia a zeri come fallback | `transport/nostr-transport.js:362` |
| **L2** | Bassa | `localStorage` sincrono e con quota ~5 MB per lo stato MLS in crescita | `storage/local-storage-backend.js` |
| **N1** | **Critica** | Panic del WASM (`.unwrap()`/`todo!()` su input di rete) blocca l'intero motore MLS — DoS remoto | `vendor/openmls-wasm/patch/lib.rs:319,329-331` |
| **N2** | Alta | Binding credenziale MLS↔pubkey verificabile (credenziale = pubkey) ma non verificato né esposto dal WASM | `crypto/mls/mls-engine.js:47`, `patch/lib.rs` |
| **N3** | Bassa | `bytesToBase64` va in stack overflow su payload grandi (allegati) | `utils.js:36` |
| **N4** | Media | KeyPackage riusato viola il single-use MLS (init_key non cancellato, nessuna scadenza) | `chat/styx-chat.js:205`, `crypto/mls/mls-engine.js:107` |

---

## 1. Vulnerabilità critiche

### C1 — Nessuna verifica delle firme Nostr in ricezione

**Dove:** `styx-js/src/transport/nostr-chat-transport.js:94-113` (`_onRelay`)

**Descrizione.** Il client firma gli eventi in uscita (`_sign`, riga 84) ma **non verifica mai** quelli in entrata. La stringa `schnorr.verify` non compare in nessun file del codebase. `_onRelay` estrae `ev.pubkey` dal JSON consegnato dal relay e lo passa direttamente al gestore come identità autenticata del mittente:

```js
this._handler?.(ev.pubkey, base64ToBytes(ev.content));
```

Né `ev.id` viene ricalcolato dalla serializzazione canonica, né `ev.sig` viene controllato. L'unico filtro applicato è che l'evento porti un tag `p` con il nostro pubkey — un campo che chiunque può scrivere.

**Impatto.** Il modello di sicurezza dell'applicazione dipende interamente dal fatto che il relay si comporti onestamente. Un relay compromesso, malevolo, o semplicemente non conforme può iniettare eventi con un campo `pubkey` arbitrario. Poiché `from` è l'identificatore su cui `StyxChat` indicizza sessioni MLS, roster e cronologia, **il relay può impersonare qualsiasi contatto verso qualsiasi utente.** Il fatto che i relay pubblici (strfry incluso) validino le firme per conto proprio non è una difesa: è precisamente la fiducia nel relay che l'architettura E2E dichiara di non voler concedere.

**Nota.** Questa è la vulnerabilità abilitante. Da sola non decifra nulla; combinata con C2, produce un MITM completo.

---

### C2 — Un `welcome` non sollecitato sovrascrive una sessione MLS esistente

**Dove:** `styx-js/src/chat/styx-chat.js:352-360` (`_onWire`), `styx-js/src/crypto/mls/mls-engine.js:139-148` (`joinSession`)

**Descrizione.** Il ramo `welcome` di `_onWire` non pone alcuna condizione:

```js
if (env.t === 'welcome') {
  this._engine.joinSession(from, base64ToBytes(env.welcome), base64ToBytes(env.tree));
  if (env.groupId) this._groups[from] = env.groupId;
  await this._persistMls();
  if (!(await this._roster.get(from))) {
    await this._roster.add({ pubkey: from, alias: env.from?.alias || from });
  }
  ...
}
```

Non verifica che esista un invito pendente. Non verifica che una sessione con `from` non esista già. E `joinSession` conclude con `this._sessions.set(contactId, session)`, che rimpiazza incondizionatamente. `this._groups[from]` viene sovrascritto e lo stato persistito.

Non esiste inoltre alcun legame fra la credenziale MLS del gruppo e l'identità Nostr del mittente. La credenziale viene inizializzata con il pubkey hex (`mls-engine.js:47`, `new Identity(provider, name)`), ma **nessuno la rilegge mai per confrontarla.** Il wrapper WASM non lo permetterebbe: `Group` non espone `members()` e `KeyPackage` offre solo `to_bytes`/`from_bytes` (verificato in `vendor/openmls-wasm/openmls_wasm.d.ts` e in `patch/lib.rs`).

**Precondizione dell'attacco — da esplicitare, perché limita la sfruttabilità.** Perché la vittima "entri" nel gruppo dell'attaccante deve poter **decifrare un Welcome**, e un Welcome MLS è sigillato all'`init_key` contenuto nel **KeyPackage** della vittima. La metà privata di quell'`init_key` non lascia mai il dispositivo; la metà pubblica (l'intero KeyPackage) viaggia **solo dentro il QR** (`createQrInvite`, `styx-chat.js:205-214`) e **non è mai pubblicata sui relay** (verificato). Quindi un avversario che non ha mai visto il QR **non può forgiare un Welcome che la vittima accetti**: con un QR scambiato di persona e mantenuto confidenziale, questo MITM **non è disponibile**, nemmeno per un relay attivo. È la garanzia reale che l'utente si aspetta, e regge — a quella condizione.

**Quando la precondizione cade — ed è qui il difetto.** L'attacco diventa possibile ogni volta che l'attaccante ottiene il KeyPackage della vittima, cioè quando:
- l'invito è consegnato su un **canale osservabile** anziché di persona: email, dettatura al telefono, screenshot inoltrato, QR mostrato in videochiamata o in streaming;
- il QR viene **riusato o fotografato** (M3): non è monouso né scade, quindi una singola cattura basta;
- si usa il **pairing remoto** (progettato, oggi non implementato — `styx-chat.js:244`), che per definizione fa transitare il materiale su un canale di rete.

**Catena, una volta ottenuto il KeyPackage.** Alice e Bob si accoppiano; l'attaccante ha catturato il KeyPackage di Alice dal canale d'invito.
1. L'attaccante crea un gruppo a due e vi aggiunge Alice **usando il suo KeyPackage**, producendo un `welcome` + `ratchetTree` che Alice può realmente decifrare.
2. Inietta verso Alice un evento con `pubkey = <pubkey di Bob>` e contenuto `{ t:'welcome', ... }`. Alice non verifica la firma (C1), quindi accetta `from = Bob`.
3. `_onWire` chiama `joinSession('Bob', ...)`: **la sessione MLS legittima con Bob viene sostituita** — e C2 lo consente anche se una sessione con Bob esiste già.
4. Da qui ogni `sendText(Bob, ...)` di Alice è cifrato verso il gruppo dell'attaccante, che decifra in chiaro, rilegge, ri-cifra verso il vero Bob e inoltra. Nulla lo segnala: non c'è safety number (H3), e lo stato ostile è persistito da `_persistMls()`, quindi il MITM sopravvive ai riavvii.

**Perché resta Critica nonostante la precondizione.** Il difetto non è "il QR è insicuro" — il QR confidenziale in presenza è solido. Il difetto è l'**assenza di difesa in profondità**: nel momento in cui l'invito passa su un canale osservabile — cosa che l'app intende esplicitamente supportare (pairing remoto in roadmap, invito condivisibile) — il MITM è immediato **e non rilevabile**. Un sistema corretto fallirebbe in sicurezza anche allora, grazie alle tre difese oggi assenti: firma verificata (C1), rifiuto dei Welcome non sollecitati e delle sostituzioni di sessione (C2), safety number confrontabile (H3).

**Osservazione sulla superficie di pairing.** Anche assumendo C1 risolta, resta un'asimmetria: nel flusso QR, chi scansiona autentica chi mostra il codice (canale fisico fidato), ma chi mostra il QR non ha modo di sapere chi gli ha risposto — accetta un `welcome` da chiunque conosca il suo pubkey. La verifica delle firme prova che il mittente possiede *una* chiave, non che sia *la persona che ha inquadrato lo schermo*.

---

### C3 — Trasporto BroadcastChannel senza autenticazione del mittente

**Dove:** `styx-js/src/transport/broadcast-channel-transport.js:21-25`

**Descrizione.** Il framing è `{ to, from, data }` e la consegna filtra solo su `to`:

```js
this._bc.onmessage = (ev) => {
  const m = ev.data;
  if (!m || m.to !== this._self) return;
  this._handler?.(m.from, m.data);
};
```

`from` è auto-dichiarato dal mittente. Nessuna firma, nessuna verifica.

**Impatto.** Questo è il trasporto usato ogni volta che `init()` viene chiamato senza `relays` (`styx-chat.js:151-153`) — cioè il percorso di sviluppo, la demo, e i test end-to-end Playwright. Qualsiasi codice in esecuzione sulla stessa origin (una XSS, uno script di terze parti, un'estensione con accesso alla pagina) può aprire il `BroadcastChannel` e inviare un `welcome` con `from` arbitrario, ottenendo C2 senza nemmeno bisogno di un relay ostile. Va trattato esplicitamente come trasporto **non sicuro, solo per sviluppo**, e la libreria dovrebbe rifiutarsi di usarlo in produzione.

---

## 2. Vulnerabilità alte

### H1 — Stato MLS e cronologia dei messaggi persistiti in chiaro

**Dove:** `styx-js/src/chat/styx-chat.js:336-346`, `styx-js/src/storage/local-storage-backend.js`

**Descrizione.** `LocalStorageBackend` esegue un semplice `JSON.stringify` verso `localStorage`. Attraverso di esso `StyxChat` persiste:

| Chiave | Contenuto | Cifrato? |
|---|---|---|
| `styx:identity` | chiave privata secp256k1 | **sì** (`EncryptedKeyStore`) |
| `mls:state` | `provider.serialize_state()` — **tutti i segreti di gruppo, chiavi di ratchet, epoch secrets** | no |
| `mls:idpk` | chiave pubblica di firma MLS | no (non sensibile) |
| `mls:groups` | mappa contatto → groupId | no |
| `msgs` | **cronologia completa dei messaggi in chiaro** | no |
| `styx:contacts` | roster: pubkey, alias, anteprima dell'ultimo messaggio | no |
| `alias` | alias locale | no |

Solo la chiave d'identità è protetta. Tutto ciò che quella chiave serve a proteggere non lo è.

**Impatto.** Chiunque ottenga lettura del profilo del browser — furto del dispositivo, backup non cifrato, estensione malevola, XSS, accesso fisico a una sessione sbloccata — legge l'intera cronologia in chiaro, l'intero grafo dei contatti, e i segreti di ratchet correnti di ogni gruppo. Quest'ultimo punto è il più grave: **annulla la forward secrecy che MLS fornisce sul filo.** MLS garantisce che un attaccante che registri il traffico cifrato non possa decifrarlo dopo aver compromesso il dispositivo; qui i segreti passati sono comunque su disco, e la garanzia svanisce.

L'ironia è che l'infrastruttura per risolverlo esiste già ed è ben fatta: `EncryptedKeyStore` viene semplicemente usato per una sola chiave invece che per l'intero volume dei dati.

---

### H2 — Metadati completamente esposti al relay

**Dove:** `styx-js/src/transport/nostr-chat-transport.js:62-68`

**Descrizione.** Ogni messaggio diventa un evento Nostr con struttura:

```js
{
  kind: 1059,
  pubkey: <mittente, identità permanente, in chiaro>,
  created_at: <timestamp unix, in chiaro>,
  tags: [['p', <destinatario, identità permanente, in chiaro>], ['nonce', ...]],
  content: <base64 del ciphertext MLS>,
}
```

Il debito è dichiarato dal codice stesso, alle righe 8-9: *"Metadata (who ↔ who, timing) is visible to relays — acceptable for a test; production would NIP-44 gift-wrap it."* Il gift-wrap non è implementato. Nonostante l'uso del `kind: 1059`, che appartiene all'intervallo NIP-59 "gift wrap", **l'evento non è un gift wrap**: il kind è stato scelto (riga 17-19) per la sua semantica di persistenza sui relay, non per la sua semantica di privacy.

**Impatto.** Un relay — e chiunque possa interrogarlo, poiché su Nostr le sottoscrizioni sono aperte — ricostruisce senza alcuno sforzo:

- **il grafo sociale completo:** chi parla con chi;
- **la cronologia temporale:** quando, con quale frequenza, secondo quali ritmi circadiani;
- **il volume:** quanti messaggi, e — tramite la dimensione di `content` — quanto lunghi (vedi M6);
- **la correlazione a lungo termine:** poiché i pubkey sono identità permanenti e mai ruotate, la stessa persona è tracciabile nel tempo, e la sua attività è unificabile tra relay diversi.

Per molti modelli di minaccia reali, *chi parla con chi* è informazione più sensibile del contenuto stesso. Un'applicazione che protegge il secondo e non il primo offre una garanzia che l'utente quasi certamente frainenderà.

---

### H3 — Nessun ancoraggio di fiducia verificabile dall'utente

**Dove:** assente dal codebase.

**Descrizione.** Non esiste alcun safety number, fingerprint, o codice di verifica confrontabile fuori banda. Il roster non ha un flag `verified`. Non c'è modo, né per l'utente né per il codice, di accorgersi che la sessione MLS con un contatto è stata sostituita.

**Impatto.** È ciò che rende C2 *silenzioso* anziché *rilevabile*. Anche se le firme venissero verificate, un attaccante che riesca a interporsi durante il pairing resterebbe invisibile per sempre. Tutte le applicazioni serie di questa categoria (Signal, WhatsApp, Wire) espongono un fingerprint confrontabile proprio perché nessuna difesa automatica del pairing è completa.

**Nota tecnica, rilevante per la soluzione.** Il wrapper WASM **espone già** `Group.export_key(provider, label, context, key_length)`, cioè l'MLS exporter di RFC 9420 (`openmls_wasm.d.ts`, classe `Group`). Un safety number derivato da questo segreto è legato allo stato reale del gruppo: sotto MITM i gruppi sono due e distinti, quindi i numeri **non coincidono**. Non serve estendere il Rust.

---

## 3. Vulnerabilità medie

### M1 — Alias in chiaro fuori da MLS nell'envelope di pairing
`chat/styx-chat.js:222-228`. L'envelope `welcome` trasporta `from: { pubkey, alias }` come JSON in chiaro dentro il `content` dell'evento. È l'unico dato applicativo che non passa da MLS. Il relay legge l'alias scelto dall'utente — spesso un nome reale — e lo associa al pubkey. Va spostato dentro MLS, come primo messaggio applicativo dopo il join.

### M2 — Auto-inserimento nel roster con alias controllato dall'attaccante
`chat/styx-chat.js:356-358`. Alla ricezione di un `welcome`, il contatto viene aggiunto al roster automaticamente, usando `env.from?.alias` — una stringa arbitraria fornita dal mittente non autenticato. Oltre a completare C2 rendendo l'attaccante un contatto legittimo agli occhi dell'interfaccia, apre a spoofing dell'identità visuale (un attaccante si presenta come *"Mamma"*) e, a seconda del frontend, a injection tramite la stringa alias. L'API espone già `confirmPairing()` per l'aggiunta esplicita: il percorso automatico non dovrebbe esistere. Nessuna validazione è applicata all'alias (lunghezza, charset, caratteri di controllo o bidi).

### M3 — Invito QR riutilizzabile e senza scadenza
`chat/styx-chat.js:205-215`. `createQrInvite()` produce un payload che non contiene né nonce né timestamp, e il KeyPackage generato resta valido a tempo indeterminato. Chiunque fotografi lo schermo, o riceva lo screenshot, può accoppiarsi in un momento arbitrario nel futuro. Non esiste un concetto di invito pendente, monouso, consumato al primo `welcome` valido — che è esattamente il meccanismo che servirebbe per chiudere l'asimmetria del pairing descritta in C2.

### M4 — Envelope `typing` non cifrato, non autenticato, accettato da sconosciuti
`chat/styx-chat.js:367-369`. `{ t:'typing', on }` viaggia in chiaro (fuori da MLS) e viene emesso verso il frontend senza verificare che `from` sia un contatto noto. Un relay legge lo stato di digitazione — un canale laterale sui ritmi della conversazione — e chiunque può iniettare eventi typing per un pubkey qualsiasi. Basso impatto sulla riservatezza, ma è una superficie non necessaria.

### M5 — Code non limitate: DoS di memoria
`chat/styx-chat.js:74` e `364`. `_pendingApp[from]` accumula envelope non decifrabili **indicizzati su un `from` arbitrario e non autenticato**, senza tetto né su numero di mittenti né su messaggi per mittente. `_seenIncoming` cresce senza limite (a differenza di `_seen` in `nostr-chat-transport.js:106`, che è correttamente limitato a 5000). Un mittente ostile satura la memoria della scheda; peggio, `_persistMessages()` scrive su `localStorage` a ogni messaggio e la quota (~5 MB) può essere esaurita, provocando l'eccezione che blocca la persistenza dello stato MLS.

### M6 — Lunghezza del messaggio visibile sul filo
`transport/nostr-chat-transport.js:67`. `content` è il base64 del ciphertext MLS, la cui lunghezza è funzione diretta di quella del plaintext. Combinato con H2, il relay conosce mittente, destinatario, istante e **dimensione approssimativa** di ogni messaggio. Sufficiente, in molti casi, a distinguere un "ok" da un indirizzo. Serve padding a bucket discreti.

---

## 4. Osservazioni minori e di igiene

**L1 — Firma fittizia a zeri.** `transport/nostr-transport.js:355-363`: in assenza di chiave privata l'evento viene firmato con `'0'.repeat(128)` e pubblicato comunque. Il commento prevede che il relay lo rifiuti. Riguarda il trasporto del ledger, non quello della chat, ma è un pattern da eliminare: un evento non firmabile va rifiutato in locale, non spedito con una firma finta e la speranza che qualcun altro lo scarti.

**L2 — `localStorage` come sede dello stato MLS.** API sincrona (blocca il thread principale a ogni `encrypt`/`decrypt`, dato che `_persistMls()` riserializza *l'intero* stato del provider a ogni operazione) e quota di ~5 MB condivisa con i messaggi. Problema di affidabilità e prestazioni prima che di sicurezza, ma il fallimento della persistenza dello stato MLS ha conseguenze di sicurezza: sessioni disallineate e potenziale riuso di chiavi.

**L3 — Crittografia post-quantistica.** Assente, come da progetto (OpenMLS in configurazione classica). Rilevante solo contro un avversario che archivi oggi per decifrare domani. Da tracciare, non da risolvere ora.

**L4 — Multi-device e pairing remoto.** `startRemotePairing`/`joinRemotePairing` lanciano un'eccezione (`styx-chat.js:244-245`). `spake2.js` esiste ma non è cablato. Non è una vulnerabilità; è una funzionalità la cui assenza va documentata all'utente, perché il pairing è oggi possibile **solo di persona**.

---

## 4B. Vulnerabilità dalla seconda passata (N1–N4)

Trovate in una rilettura a occhi freschi del codice e del patch Rust, successiva alla stesura di §1–4.

### N1 — Panic del WASM = DoS totale del motore crypto *(Critica)*
`vendor/openmls-wasm/patch/lib.rs:319` (`process_message`) fa `.unwrap()` sulla deserializzazione di byte **controllati dall'attaccante**, e le righe 329–331 hanno tre rami `todo!()` per messaggi Welcome/GroupInfo/KeyPackage. Il build è `wasm-pack --target web` su `wasm32-unknown-unknown`, dove un panic Rust è un **trap che rende inutilizzabile l'intera istanza WASM**. Poiché un solo `Provider`/`MlsEngine` è condiviso da *tutte* le conversazioni (`styx-chat.js`, un engine, N sessioni), un singolo ciphertext malformato recapitato al proprio tag `#p` **blocca il motore MLS per ogni contatto** fino al reload della pagina; il `try/catch` JS in `_processApp` cattura il throw ma l'istanza è già avvelenata e da lì ogni encrypt/decrypt va in trap. Trigger: qualunque mittente che consegni `{t:'app', ct:<garbage>}`; pre-Fase-A, qualunque relay. È un DoS remoto non autenticato sull'intero strato crittografico — più grave di M5 (crescita di memoria). **Coerente con l'audit SRLabs**, che classifica i problemi OpenMLS come per lo più DoS da input malformati (vedi §7). *Fix:* nel patch Rust sostituire `.unwrap()`/`todo!()` con ritorno di `Result`/errore gestito; nel JS isolare l'engine per-contatto o ricostruirlo su errore fatale.

### N2 — Binding credenziale MLS↔identità: verificabile ma non verificato *(Alta; precisa C2)*
La credenziale MLS è una `BasicCredential` inizializzata **esattamente con il pubkey hex** (`mls-engine.js:47`, `new Identity(provider, name)`, `name` = pubkey). Quindi il controllo "la credenziale del membro aggiunto == il pubkey da cui arriva il welcome" sarebbe banale e taglierebbe l'impersonazione a livello MLS. L'audit (C2) diceva "nessun legame"; la precisazione è che **il legame naturale esiste già (credenziale = pubkey), va solo esposto e confrontato.** Il wrapper WASM non espone però le credenziali dei membri, quindi serve un accessor `member_credentials()` nel patch Rust perché la Fase A possa confrontarlo al join. La ricerca conferma la posta in gioco: in MLS l'*Authentication Service* è l'ancora di fiducia dell'identità, e in un sistema serverless quel ruolo va costruito esplicitamente (vedi §7).

### N3 — `bytesToBase64` in stack overflow su payload grandi *(Bassa)*
`utils.js:36`: `btoa(String.fromCharCode(...bytes))` fa lo spread dell'intero array sullo stack. Con gli allegati immagine previsti in roadmap, oltre ~100 KB va in "Maximum call stack size exceeded". Affidabilità con risvolto DoS su input grande. *Fix:* encoding a chunk.

### N4 — KeyPackage riusato viola il single-use MLS *(Media; rafforza M3)*
In MLS un KeyPackage (il suo `init_key`) è **monouso**: il Welcome è sigillato ad esso, e riusarlo o non cancellarne la parte privata dopo il join **indebolisce la forward secrecy** dell'invito. `createQrInvite` (`styx-chat.js:205`) genera un KeyPackage che resta valido e viene riusato se il QR è mostrato/rifotografato più volte; manca gestione di scadenza. La ricerca lo conferma come requisito normativo (RFC 9750, NIP-EE) e aggiunge che il Delivery Service (relay) **non può** farlo rispettare, quindi la difesa è tutta lato client. *Fix:* KeyPackage monouso, `init_key` privato cancellato al primo join, invito con scadenza. Confluisce nel workstream FS/PCS di §7 (R2).

---

## 5. Modello dell'avversario di rete

Questa sezione risponde a una domanda diretta: *dato l'accesso al traffico di rete, cosa si può estrarre?* Distingue due avversari, perché la differenza è netta e determina la severità reale delle vulnerabilità precedenti.

**Cardine tecnico.** L'app di chat (`apps/chat/src/lib/config.js`) usa di default relay pubblici **su TLS** (`wss://relay.damus.io`, `wss://nos.lol`). Il `ws://` in chiaro compare solo nella demo `fidesvox` su `localhost`. Non esiste overlay Tor (la Fase D non è implementata), quindi l'IP reale del client è sempre esposto. Su Nostr, inoltre, le sottoscrizioni ai relay sono **aperte**: chiunque può collegarsi a un relay pubblico come normale client e leggerne gli eventi.

### 5.1 Avversario passivo (osserva ogni pacchetto, non interviene)

**Cosa NON estrae:** il **testo dei messaggi**. Restando passivo non può eseguire il MITM di C1+C2 (che richiede iniezione), quindi il contenuto resta protetto due volte — da MLS e, sul filo, da TLS.

**Cosa estrae comunque — l'intero contesto tranne il contenuto:**

- **Grafo sociale completo.** Non serve nemmeno rompere TLS: basta sottoscrivere il relay pubblico come client. Ogni evento porta `pubkey` (mittente) e tag `p` (destinatario) in chiaro (H2). Si ricostruisce chi-parla-con-chi, per intero.
- **Cronologia temporale.** `created_at` in chiaro e senza jitter → orari, frequenza, fuso orario, ore di sonno, inizio e fine di ogni relazione.
- **Volume e lunghezza.** Conteggio dei messaggi; e senza padding (M6) la dimensione del `content` rivela la lunghezza approssimativa di ciascuno.
- **Formazione di nuove relazioni.** L'evento `welcome` del pairing è osservabile: si vede l'istante esatto in cui due persone si aggiungono.
- **Presenza.** Connessioni WebSocket ed eventi effimeri `typing` (M4) segnalano chi è attivo e quando scrive.

**In più, dalla posizione di rete (livello TLS):**

- **IP reale → abbonato/luogo.** Lega l'attività a livello di pubkey (che il relay vede) alla persona fisica. Il relay conosce lo pseudonimo; l'osservatore di rete lo lega all'IP.
- **Quali relay usa ciascuno**, via SNI e DNS in chiaro (salvo ECH).
- **Correlazione dei due estremi — funziona anche solo su TLS, senza decifrare.** TLS non maschera bene dimensione e tempo dei record: un frame di ~400 byte pubblicato da Alice e uno di dimensione corrispondente ricevuto da Bob 150 ms dopo, dallo stesso relay, li collega senza leggere un byte. È l'attacco classico di correlazione end-to-end, e restituisce il grafo sociale.

**Deanonimizzazione.** I pubkey sono identità permanenti mai ruotate (H2), spesso già pubbliche altrove nell'ecosistema Nostr. Incrociando il grafo estratto con quei registri, gli pseudonimi diventano nomi; l'IP li lega alle persone fisiche. Il risultato non è "metadati anonimi": è una mappa nominativa di chi conosce chi, quando, con che intensità, da dove.

**Sintesi passivo:** sfugge **solo il testo**. Per la parte più sensibile — il grafo sociale — non serve nemmeno essere sulla rete: basta collegarsi al relay pubblico. Per molti modelli di minaccia reali (fonte giornalistica, dissidente) nascondere *una relazione* conta più che nascondere *un contenuto*, e quella relazione è già interamente esposta.

### 5.2 Avversario attivo (inietta, scarta, ritarda, gestisce o compromette un relay)

Il salto dall'attivo è che ottiene ciò che al passivo mancava: **il contenuto**, più la capacità di scrivere.

**Confine tecnico.** Con TLS l'attivo non può iniettare nel flusso di un terzo senza rompere TLS; ma non gli serve — gli basta essere l'**endpoint TLS** con cui il client parla. Tre strade, in ordine di facilità: (a) gestire uno dei relay della lista — sono di terzi, e il client accetta eventi da qualunque relay connesso senza verificarne la firma (C1); (b) spingere il client verso un relay controllato (la lista è configurabile via URL); (c) a livello nazione-stato, dirottare DNS/BGP di un hostname di relay e terminare TLS con un certificato mal-emesso.

Una volta endpoint, l'assenza di verifica firma (C1) e la sovrascrivibilità delle sessioni (C2) abilitano:

1. **Lettura del contenuto — MITM trasparente, ma con una precondizione.** Richiede il **KeyPackage della vittima** per sigillarle un Welcome che accetti (vedi C2): quindi funziona **solo se l'invito è passato su un canale osservabile, se il QR è stato riusato/fotografato, o con pairing remoto** — non contro un QR confidenziale scambiato di persona, il cui `init_key` non tocca mai la rete. Soddisfatta la precondizione: `welcome` fabbricato con `pubkey = Bob` → la sessione MLS di Alice con Bob viene rimpiazzata → Alice cifra verso il gruppo dell'attaccante, che decifra, rilegge, ri-cifra verso il vero Bob e inoltra. **Invisibile** (nessun safety number, H3) e **persistente**. Peggiore del MITM classico: C2 sovrascrive **anche una sessione già consolidata**, quindi una conversazione in corso può essere dirottata in qualsiasi momento, non solo al pairing.
2. **Scrittura — impersonazione e iniezione.** Posseduto il gruppo, l'attaccante fabbrica messaggi che appaiono da "Bob" e che Alice legge come autentici. Controllo bidirezionale: legge, modifica in transito, inietta.
3. **Censura, ritardo, riordino.** Come relay può scartare selettivamente messaggi o ricevute `delivered`/`read` (manipolando ciò che ciascuno crede arrivato), ritardare, riordinare. Nessuna garanzia di consegna regge.
4. **Attacco al pairing — la finestra più pulita.** Senza nonce nell'invito (M3) e senza prova-di-scansione nel `welcome`, l'attivo inietta un `welcome` durante il pairing e la persona che mostra il QR si accoppia con l'attaccante dall'inizio, senza dover sovrascrivere nulla.
5. **Denial of service.** Alluvione di `welcome` falsi, o saturazione delle code non limitate (M5), fino a rompere la persistenza dello stato MLS.
6. **Downgrade forzato.** Bloccando il percorso preferito (WebRTC P2P, quando cablato) si costringe il traffico sul relay controllato.

**Cosa nemmeno l'attivo può fare.** Rompere MLS: AEAD e ratchet reggono — l'attacco passa *accanto* alla crittografia (autenticazione), non *attraverso*. E non recupera i messaggi scambiati sotto una sessione genuina *prima* dell'inserimento (forward secrecy). Soprattutto: oggi il MITM è invisibile, ma **dopo la Fase A diventerebbe rilevabile** (safety number discordante) e in gran parte impossibile (firma verificata + `welcome` legato al nonce del QR).

### 5.3 Sintesi

| Capacità dell'avversario | Passivo | Attivo |
|---|---|---|
| Testo dei messaggi | **no** (MLS+TLS) | **sì, ma solo se** l'invito è passato su canale osservabile / QR riusato / pairing remoto (serve il KeyPackage della vittima); **no** con QR confidenziale in presenza |
| Grafo sociale chi ↔ chi | sì (H2) | sì |
| Timing, frequenza, volume, lunghezza | sì (H2, M6) | sì |
| IP reale → persona fisica | sì (no Tor) | sì |
| Rilevare formazione di nuove relazioni | sì (`welcome` osservabile) | sì |
| Impersonare un contatto / iniettare messaggi | no | **sì** (dopo MITM) |
| Censurare / ritardare / riordinare | no | **sì** |
| Rompere il nucleo crittografico MLS | no | no |
| Essere rilevato **oggi** | — | **no** (manca H3) |
| Essere rilevato/bloccato **dopo Fase A** | — | sì |

La riga decisiva è quella del contenuto: MLS regge, e con un QR confidenziale in presenza l'avversario non lo aggira. Ma il codice non offre difesa in profondità, quindi **non appena l'invito passa su un canale osservabile** l'avversario gli gira intorno — senza essere rilevato (H3). La Fase A chiude questo giro rendendolo impossibile e comunque rilevabile; la Fase C affronta l'esposizione dei metadati, che resta anche contro il solo passivo e con QR confidenziale.

---

## 6. Soluzioni proposte

Presentate in ordine di rapporto danno-evitato/costo. **La sequenza conta.** Cifrare i metadati mentre un relay può ancora leggere il contenuto significa mettere le tende in una casa senza porte.

### Fase A — Autenticazione del canale *(chiude C1, C2, C3, H3, M1, M2, M3)*

Ancoraggio di fiducia deciso: **il QR è il canale fidato** (scansione di persona), rafforzato da un safety number confrontabile a voce. È il modello Signal. Non introduce crittografia nuova.

**A1. Verificare le firme in ingresso.** In `NostrChatTransport._onRelay`, prima di ogni altro controllo: ricalcolare l'id NIP-01 dalla serializzazione canonica `[0, pubkey, created_at, kind, tags, content]`, confrontarlo con `ev.id`, quindi verificare `schnorr.verify(ev.sig, ev.id, ev.pubkey)`. Scartare in silenzio ciò che non passa, incrementando un contatore diagnostico. È la riga che trasforma `from` da *campo suggerito dal relay* a *identità dimostrata*. Tutto il resto poggia su questa.

**A2. Rendere il `welcome` una prova di aver visto il QR.** Aggiungere al payload dell'invito un nonce casuale a 32 byte, che vive solo nel QR e nella memoria di chi lo ha generato. L'envelope `welcome` deve portare `HMAC-SHA256(nonce, welcome_bytes ‖ tree_bytes ‖ groupId)`. Chi non ha inquadrato lo schermo non può fabbricarlo. L'invito è **monouso**: verificato l'HMAC, il nonce è consumato e l'invito scade. Questo chiude l'asimmetria del pairing e risolve M3 nello stesso movimento.

**A3. Nessuna sessione viene mai sovrascritta.** In `_onWire`, il ramo `welcome` rifiuta se non esiste un invito pendente, **e** rifiuta se `this._groups[from]` esiste già. In `MlsEngine.joinSession`, sollevare un'eccezione anziché rimpiazzare quando `_sessions.has(contactId)`. La sostituzione di una sessione stabilita non deve essere un percorso raggiungibile dalla rete: se una sessione va davvero ricreata, dev'essere un'azione esplicita dell'utente (`removeContact` seguito da un nuovo pairing).

**A4. Aggiunta al roster solo esplicita.** Rimuovere l'auto-`add` da `_onWire`. Il `welcome` valido crea uno *stato di pairing pendente*, che l'interfaccia presenta e che diventa un contatto solo passando da `confirmPairing()`. L'alias esce dall'envelope in chiaro e viaggia come primo messaggio applicativo dentro MLS (chiude M1). Validare l'alias in ingresso: lunghezza massima, niente caratteri di controllo, niente override bidirezionali Unicode.

**A5. Safety number.** Esporre `StyxChat.safetyNumber(pubkey)`, calcolato come

```
export_key(provider, "styx:safety-number:v1", pubkeyA ‖ pubkeyB /* ordinati lessicograficamente */, 32)
```

reso in 60 cifre decimali raggruppate a cinque, alla maniera di Signal. Persistere nel roster un flag `verified` e la sua data. Se il numero cambia dopo la verifica, l'interfaccia deve avvisare in modo non ignorabile. **Nessuna modifica al Rust è necessaria:** `Group.export_key` è già esposto dal wrapper.

**A6. Vietare il trasporto non autenticato in produzione.** `BroadcastChannelTransport` va marcato come solo-sviluppo. O si aggiunge una firma sul framing `{to, from, data}` con la chiave d'identità (soluzione minima: riusare `_sign`/`verify` di A1), oppure la libreria rifiuta di istanziarlo quando non è in un build di sviluppo. La seconda è preferibile: un trasporto che non trasporta firme non dovrebbe esistere nel bundle di produzione.

Al termine della Fase A, un relay ostile può ancora **rifiutarsi di consegnare, riordinare o ritardare** i messaggi — la disponibilità non è difendibile a questo strato — ma non può più leggerli né impersonare nessuno.

### Fase B — Cifratura a riposo *(chiude H1)*

**B1. Introdurre una DEK (data encryption key).** Alla creazione dell'identità, generare una chiave AES-256 casuale, cifrarla con la KEK derivata dalla password (lo stesso PBKDF2 già in `EncryptedKeyStore`) e persisterla come `styx:dek`. Il cambio password ri-cifra **solo la DEK**, non l'intero volume dei dati: è il pattern corretto e rende `changePassword` un'operazione costante.

**B2. `EncryptedBackend` come decoratore.** Un wrapper che implementa la stessa interfaccia `get`/`set`/`delete` di `LocalStorageBackend` e cifra i valori con AES-GCM sotto la DEK, IV casuale per record. Composizione, non ereditarietà: nessun consumatore (`ContactRoster`, il codice di persistenza di `StyxChat`) cambia una riga.

**B3. Cablare l'ordine di inizializzazione.** La DEK è disponibile solo dopo `unlock({ password })`. `init()` deve quindi: sbloccare l'identità → decifrare la DEK → costruire l'`EncryptedBackend` → *solo allora* caricare `alias`, `styx:contacts`, `mls:state`, `mls:groups`, `msgs`. Oggi `alias` viene letto prima dello sblocco (`styx-chat.js:112`) e va spostato dietro il muro. `styx:identity` e `styx:dek` restano necessariamente sul backend in chiaro (sono già protetti da password) — sono gli unici due.

**B4. Migrazione.** Al primo avvio dopo l'aggiornamento, i dati esistenti in chiaro vanno letti, ri-scritti cifrati, e le chiavi vecchie rimosse. Va previsto un numero di versione dello schema di storage.

**B5. Considerare IndexedDB.** Risolve anche L2 (quota, sincronia). `storage/indexeddb-store.js` esiste già nel codebase e non è usato da `StyxChat`. Da valutare come parte della stessa fase, o subito dopo.

### Fase C — Privacy dei metadati *(chiude H2, M4, M6, residuo di M1)*

Va affrontata come ciclo autonomo, **indipendente da A e B** (non ne dipende tecnicamente; l'ordine di priorità resta A → B → C perché cifrare i metadati mentre il contenuto è ancora leggibile ha poco valore). **Vincolo di fondo:** per la consegna offline attraverso un relay non fidato, *qualcosa* deve dire al relay dove archiviare e ripescare ogni messaggio — quindi il **destinatario** è l'unica informazione non nascondibile a costo zero. Per questo la fase si divide in due sotto-cicli spec → plan → implementazione:

- **Spec C.1 — gift-wrap del mittente (vittorie facili):** nasconde mittente, tipo, alias di pairing, timestamp e dimensione. Rischio nullo sulla consegna, spedibile subito. *Dettagliato sotto.*
- **Spec C.2 — nascondere il destinatario:** tag di instradamento ruotante con manopola di k-anonimato. Ciclo successivo. *Abbozzato sotto.*

---

#### Spec C.1 — Gift-wrap del mittente

**Obiettivo.** Un evento oggi espone cinque cose oltre al contenuto (già cifrato da MLS): mittente, destinatario, timestamp, dimensione, tipo (app/welcome/typing). Peggio, `content` è solo il base64 dell'envelope JSON, quindi il relay può decodificarlo e leggerne la **struttura** — il tipo, e nel `welcome` l'**alias e il pubkey in chiaro** (M1). Questo spec incapsula l'intero envelope in un **gift-wrap NIP-59**: il relay vede solo un mittente effimero usa-e-getta, il tag del destinatario, un timestamp offuscato e un blob cifrato di lunghezza quantizzata. In particolare **i pairing smettono di essere osservabili** (§5.1).

**Confine (cosa NON fa):** non nasconde il destinatario (→ Spec C.2); non nasconde l'IP (→ Fase D); non è l'hardening di autenticazione (→ Fase A). *Sinergia gratuita:* il livello *seal* è firmato dalla chiave reale del mittente, quindi il trasporto consegna a `StyxChat` un `from` **autenticato** invece del `pubkey` suggerito dal relay — utile alla Fase A, soprattutto sul `welcome` pre-MLS. Non tocca `BroadcastChannelTransport` (same-origin, solo-sviluppo).

**Architettura — un solo strato al confine del trasporto; `StyxChat` invariato.** L'orchestratore continua a chiamare `transport.send(toPubkey, bytes)` e a ricevere `(from, bytes)` in chiaro; wrap/unwrap vivono dentro `NostrChatTransport` più due moduli crypto puri:

1. **`crypto/nip44.js`** — NIP-44 v2 (`encrypt`/`decrypt`): ECDH secp256k1 → HKDF-SHA256 → ChaCha20 + HMAC-SHA256, con padding incorporato. Dai primitivi `@noble` **oppure** vendorizzato da un modulo già rivisto.
2. **`crypto/gift-wrap.js`** — sopra nip44: `wrap(envelopeBytes, senderSk, recipientPk, {ephemeral}) → event` e `unwrap(event, recipientSk) → {from, bytes} | null`.
3. **`transport/nostr-chat-transport.js`** — `send` fa `wrap` prima di pubblicare (kind esterno secondo `ephemeral`); `_onRelay` fa `unwrap` e consegna il `from` autenticato dal seal; staleness effimera sul timestamp interno; `since` di recupero allargato di `W`.
4. **Config** — finestra di offuscamento timestamp `W`, floor di padding.

**Meccanica NIP-59 — tre livelli, ognuno con un compito:**

1. **Rumor** — evento **non firmato** che porta l'envelope StyxChat reale. Non firmato apposta: nessuna firma che identifichi il mittente se trapelasse.
2. **Seal (kind 13)** — il rumor, cifrato NIP-44 verso il destinatario e **firmato con la chiave d'identità reale del mittente**. Solo il destinatario lo decifra; la firma gli prova chi ha inviato.
3. **Gift-wrap (kind 1059, o kind effimero 20000–29999 per il typing)** — il seal, cifrato NIP-44 verso il destinatario e firmato con una **chiave effimera monouso**, con tag `#p` = destinatario e `created_at` offuscato. È ciò che il relay archivia.

Perché *entrambi* i livelli: il *wrap* nasconde il mittente al relay (chiave effimera); il *seal* dà al destinatario un mittente **autenticato**. Togliere il seal renderebbe non fidabile il mittente del `welcome`, che è pre-MLS. **Gate non negoziabile:** passare i **test-vector ufficiali NIP-44** prima di ogni integrazione.

**Le tre interazioni delicate:**

- **(a) Padding — al livello gift-wrap, non dentro MLS.** Lo schema di padding di NIP-44 quantizza il plaintext; applicato attorno all'intero rumor nasconde la lunghezza del `ct` MLS interno *e* la struttura dell'envelope. Con un **floor minimo** perché anche un "ok" cada in un bucket dignitoso. Chiude M6. *(Nota: raffina l'idea originale "padding prima di MLS" — imbottire al livello esterno protegge di più.)*
- **(b) Timestamp offuscato vs recupero offline — l'edge case da centrare.** Randomizzare `created_at` nel passato romperebbe il recupero via `since = ultimo_visto` (un wrap datato prima verrebbe mancato). Soluzione accoppiata: limitare l'offuscamento a una finestra **W** (default 15–60 min) **e** allargare la sottoscrizione a `since = ultimo_visto − W`; il dedup esistente (`_seen`) assorbe la sovrapposizione. L'orario reale viaggia già dentro MLS (`styx-chat.js:263`), quindi la precisione sul filo è irrilevante per la UX.
- **(c) Typing / effimeri — nella stessa pipeline, su kind effimero.** Ogni envelope in uscita passa da `wrap()`, il flag `ephemeral` sceglie un kind esterno effimero (non archiviato dai relay). Sul filo nulla distingue un typing da un messaggio. La staleness (`nostr-chat-transport.js:102`) va giudicata sul **timestamp interno** al rumor, non su `created_at` ora offuscato. *(Raffina l'idea originale "typing dentro MLS o rimuoverlo": il gift-wrap uniforme è più semplice e non intreccia il typing con le sessioni MLS.)*

**Cosa vede il relay — prima e dopo:**

| Campo | Oggi | Dopo Spec C.1 |
|---|---|---|
| Identità mittente | stabile, in chiaro | chiave **effimera** per evento |
| Tipo (app/welcome/typing) | leggibile | **nascosto** |
| Alias nel welcome | in chiaro (M1) | **nascosto** |
| Rilevabilità dei pairing | osservabile | **nascosta** |
| Timestamp | esatto | offuscato entro `W` |
| Dimensione | reale (M6) | **quantizzata** |
| Destinatario (`#p`) | pubkey reale | pubkey reale (→ Spec C.2) |
| Contenuto | cifrato MLS | cifrato MLS |
| `from` consegnato a `StyxChat` | `ev.pubkey` non verificato | **autenticato dal seal** |

**Test:** test-vector NIP-44 (gate); round-trip (A→B dà plaintext + pubkey autenticato di A, C non decifra); **vista-relay avversariale** (l'evento pubblicato non contiene mittente stabile, né tipo, né alias; lunghezza quantizzata; `created_at` entro `W`); recupero offline sotto jitter (wrap datato nel passato arriva via `since` allargato, dedup evita doppioni); tamper (wrap alterato → scartato); i 458 test esistenti restano verdi.

**Rischi:** correttezza NIP-44 (mitigata dai test-vector / modulo rivisto); overhead crypto per messaggio (trascurabile vs MLS; typing già throttled); accoppiamento `created_at`↔`since` (unico cambio comportamentale, coperto dal test di recupero); nessun nuovo storage di chiavi (si riusa l'identità secp256k1; le effimere sono per-messaggio e scartate).

---

#### Spec C.2 — Nascondere il destinatario *(ciclo successivo)*

Il tag di instradamento deve restare *qualcosa* perché il relay consegni offline; la vera fuga, più del tag sul messaggio, è la **sottoscrizione** del destinatario, che racconta al relay cosa gli interessa. Tre approcci, tutti compatibili con la consegna offline:

| Approccio | Filtro di ricezione = cosa vede il relay | Correlazione residua | Costo |
|---|---|---|---|
| **Solo C.1** | pubkey stabile del destinatario | mittente nascosto, ma gli *estremi* no: il grafo resta in gran parte ricostruibile | minimo |
| **Tag ruotante** | insieme dei tag `H(segreto‖epoca)` dei contatti | nessuna identità stabile; correlazione a lungo termine spezzata dalla rotazione, ma il relay raggruppa i contatti per connessione+IP | medio |
| **Inbox + trial-decrypt** | un bucket largo, non legato al destinatario | il relay non impara **nulla** sul destinatario né sul grafo; resta solo "un IP scarica" | alto (banda ∝ traffico del relay) |

**Raccomandazione: tag ruotante con manopola di k-anonimato.** Il segreto condiviso è già disponibile via `Group.export_key` (lo stesso di A5): un tag `export_key("styx:routing", epoca, …)` ruota da solo, entrambi i peer lo calcolano uguale, e derivandolo da materiale che ratcheta i tag passati non sono ricomputabili se il segreto trapela dopo. **Troncando** il tag a pochi bit si ottiene un insieme di k-anonimato: con k=1 è instradamento preciso (zero trial-decrypt); alzando k il relay vede un tag condiviso da k coppie e si fa trial-decrypt entro quel gruppetto, a costo k×. Una sola manopola copre lo spettro da "tag ruotante" a "inbox", permettendo di partire pragmatici e stringere dopo senza riscrivere il protocollo. Riusa l'intera pipeline di C.1, cambiando solo come si sceglie il tag e il filtro di sottoscrizione.

### Fase D — Resistenza all'analisi del traffico — ricerca, non impegno

Overlay Tor, traffico dummy con distribuzione di Poisson, mixing. Il `CLAUDE.md` del progetto prevede già i profili *Balanced / Private / Paranoid* per il push bridge: l'impalcatura concettuale esiste.

Va detto con franchezza: **senza A, B e C completate, la Fase D è teatro.** E anche con quelle, contro un avversario che osservi simultaneamente tutti i relay e la rete sottostante, la protezione resta parziale e si paga in latenza e batteria. È il livello a cui operano Tor e i mixnet; nessuna applicazione di messaggistica mainstream, Signal inclusa, lo raggiunge davvero. Merita ricerca, non una promessa all'utente.

### Igiene trasversale

- **M5:** limitare `_pendingApp` (per mittente e in totale, con scadenza), e limitare `_seenIncoming` come già fa `_seen` in `nostr-chat-transport.js:106`. Scartare gli envelope `app` e `typing` provenienti da `from` che non siano contatti noti o pairing pendenti.
- **L1:** rimuovere il fallback della firma a zeri; un evento non firmabile va rifiutato localmente.
- **Test:** ogni difesa della Fase A richiede un test **avversariale**, non solo il cammino felice. Nello specifico: un relay simulato che inietta un `welcome` con `pubkey` falsificato deve produrre un rifiuto; un `welcome` senza HMAC valido deve essere scartato; un secondo `welcome` per un contatto già stabilito deve sollevare un'eccezione; e due sessioni sotto MITM devono produrre safety number **diversi**. Sono questi test, non quelli di funzionamento, a dimostrare che le vulnerabilità sono chiuse.

---

## 7. Validazione esterna e nuove strategie

Sintesi di una ricerca approfondita su fonti primarie (RFC 9420/9750, audit SRLabs di OpenMLS, spec Nostr NIP-44/59/EE, Apple Security Research su iMessage CKV, letteratura peer-reviewed sull'usabilità della verifica chiavi). Metodo: decomposizione in 5 angoli, ricerca parallela, estrazione di affermazioni falsificabili, **verifica avversariale a 3 voti** (24 confermate su 25, 1 refutata). Serve a due scopi: validare il piano §6 e scoprire ciò che il piano non copriva.

### 7.1 Cosa la ricerca **valida** del piano

- **Nucleo MLS/OpenMLS solido.** OpenMLS ha passato un audit indipendente SRLabs (8 problemi, **0 critici**: 1 High, 3 Medium, 2 Low, 2 info), per lo più DoS da bug logici/di sincronizzazione, tutti risolti. Il core crittografico è una base sana *a condizione di fissare una release post-audit*. [SRLabs PDF](https://blog.openmls.tech/SRL-OpenMLS_security_assurance_assessment.pdf), [phnx.im](https://blog.phnx.im/openmls-independent-security-audit/)
- **Modello di fiducia DS/AS corretto.** Un relay ostile (Delivery Service) non può aggiungersi ai gruppi, recuperare la group key o leggere i `PrivateMessage`; può solo scartare/riordinare/negare. Valida l'uso di Nostr come trasporto. [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html)
- **Gift-wrap NIP-59 esatto come lo Spec C.1.** Tre livelli rumor → seal(13) → gift-wrap(1059) con chiave effimera; il seal rivela il mittente **solo** al destinatario. Corrisponde alla lettera. [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md)
- **NIP-44 senza FS/PCS/deniability** → conferma che MLS sopra è la scelta giusta, e che NIP-44 va usato solo come busta di trasporto. [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md)
- **Safety number/SAS è il ceremony giusto** per rilevare il MITM al pairing (Fase A, A5). [Apple CKV](https://security.apple.com/blog/imessage-contact-key-verification/)

### 7.2 Azioni nuove emerse (oltre il piano) — R1–R6

- **R1 — Fissare OpenMLS a una release post-audit.** Il build vendorizzato usa il commit `09e92777…`: verificare che includa i fix **S3-7** (confronto MAC `equal_ct` troncato a `min(len)`, **High**, CWE-354 → impersonazione/fork con signing key compromessa) e **S2-5** (blank-leaf che rompe *permanentemente* la decifratura di messaggi ritardati). I fix sono nelle crate **v8.1 / v7.3**. S2-5 è sul percorso critico perché con la consegna offline il ritardo è il caso normale. Se il commit è anteriore, ricostruire. *Fase 0, fondamentale e a basso costo.*
- **R2 — FS/PCS non sono automatici (nuovo workstream).** Richiedono: **cancellare l'`init_key` privato dopo il Welcome**, **ruotare la signing key subito al join e periodicamente**, forzare Update/Commit alla riconnessione ed eviction dei client inattivi. Oggi il codice non fa nulla di questo, e lo scenario offline-gift-wrap è esattamente il caso di erosione FS/PCS segnalato dalla RFC 9750. Ingloba N4. [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html), [NIP-EE](https://github.com/nostr-protocol/nips/blob/master/EE.md)
- **R3 — Il leak del destinatario dipende dalla cooperazione del relay.** Il pubkey del destinatario nel tag `p` del gift-wrap è protetto solo da un `SHOULD` non applicabile; NIP-EE lascia inoltre osservabile "questo utente riceve gift-wrap" e usa un tag di gruppo `h` stabile (vettore di linkability). **Valida lo Spec C.2** e aggiunge il requisito: il tag di instradamento deve ruotare *e* non esporre un group-id stabile sul filo. [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md), [NIP-EE](https://github.com/nostr-protocol/nips/blob/master/EE.md)
- **R4 — Il safety number da solo non basta.** Gli studi di usabilità danno completamento ~11–14%; il redesign di Signal (UI bloccante/nudging) arriva a ~90%. Quindi la A5 va rafforzata con UX **non ignorabile**. A lungo termine, poiché un sistema serverless non ha un *Authentication Service*, l'ancora forte è una **key transparency con gossip** (modello iMessage CKV) — da valutare se realizzabile senza server. [arXiv 2410.16098](https://arxiv.org/pdf/2410.16098), [Apple CKV](https://security.apple.com/blog/imessage-contact-key-verification/)
- **R5 — At-rest: rivedere i parametri (rafforza Fase B).** *Non validato dalla ricerca* (angolo D senza evidenze sopravvissute), ma è emersa la guida OWASP: i **210k iterazioni PBKDF2 sono probabilmente sotto la soglia OWASP corrente (600k per PBKDF2-HMAC-SHA256)**; valutare **Argon2id**, e soprattutto **WebAuthn PRF / chiavi WebCrypto non-extractable** così il materiale grezzo non risiede mai in storage esfiltrabile via XSS (mitiga H1). Da confermare con una verifica dedicata.
- **R6 — Testare esplicitamente la consegna ritardata/tardiva.** Per la classe di bug S2-5 (blank-leaf), scrivere un test che verifichi la decifratura di messaggi di epoche passate consegnati in ritardo — il caso normale con relay offline.

### 7.3 Lacune di copertura e affermazione refutata

- **Angoli non validati:** at-rest (localStorage/IndexedDB, PBKDF2 vs Argon2id, WebAuthn PRF) e secp256k1/analisi del traffico non hanno prodotto affermazioni sopravvissute alla verifica. Restano domande aperte; **la Fase D resta confermata come sola ricerca**, non impegno. I parametri at-rest specifici vanno verificati a parte (R5).
- **Refutata (0-3):** la tesi che "un attaccante che apprende la sender key di un membro possa intercettare passivamente in modo indefinito tra un update e l'altro" è stata **respinta** dalla verifica avversariale contro RFC 9420 — non va usata come motivazione.

---

## 8. Limiti di questo audit

Questo è un lavoro di lettura del codice, non un test di penetrazione. In particolare:

- **Nessun exploit è stato costruito né eseguito.** Le catene di attacco descritte in C2 sono derivate dalla lettura del flusso di controllo e ritenute solide, ma non dimostrate empiricamente. Il modo corretto di confermarle è scriverne i test avversariali, che servono comunque come regressione.
- **OpenMLS e il patch Rust in `vendor/openmls-wasm/patch/lib.rs` non sono stati auditati.** Si è assunta la correttezza di OpenMLS sulla base dell'audit SRLabs. Il patch locale — in particolare `serialize_state`/`restore_state`, che non appartengono a OpenMLS upstream e manipolano direttamente lo storage del provider — **non è coperto da quell'audit e meriterebbe una revisione dedicata.**
- **Il frontend non è stato esaminato.** Injection dell'alias (M2), gestione della password in memoria, e Content-Security-Policy della PWA sono fuori dal perimetro. Data H1, la CSP è una difesa di prima linea e non un dettaglio.
- **La superficie PWA/push non è stata esaminata.** Le specifiche di `2026-07-10-pwa-push-notifications-design.md` introducono un push bridge; il suo impatto sui metadati va valutato quando l'implementazione esisterà.
- **Nessuna analisi delle dipendenze** (`npm audit`, provenienza dei pacchetti, integrità del `.wasm` vendorizzato). Il `.wasm` è un binario committato nel repository: la sua riproducibilità a partire da `build.sh` andrebbe verificata.
