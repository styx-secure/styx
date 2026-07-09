# Handoff: Styx Chat — Frontend web di messaggistica E2E

## Overview
Frontend web di **Styx Chat**, un'app di messaggistica cifrata end-to-end e *serverless*, in
stile WhatsApp Web / Signal Desktop. È una **Single Page Application React interamente
client-side**: nessuna chiamata di rete verso backend. Tutta la logica di rete, crittografia
e persistenza è fornita da un modulo esterno già esistente, `StyxChat` (importato come
`import { StyxChat } from 'styx-js'`). Il frontend si limita a **consumare l'API e renderizzare
stato ed eventi** — non implementa crittografia né networking.

Se `StyxChat` non è disponibile a runtime, il frontend deve usare un **mock in-memory con la
stessa firma**, così la UI è dimostrabile in isolamento (ne è incluso uno funzionante, vedi
`styx-lib.js`).

## About the Design Files
I file in questo bundle sono **riferimenti di design realizzati in HTML** — un prototipo
funzionante che mostra look e comportamento voluti, **non** codice di produzione da copiare
tal quale. Il compito è **ricreare questo design nell'ambiente del codebase target** (React con
hook e function components, come richiesto), usando i pattern e le librerie del progetto. Se
non esiste ancora un ambiente, crea un progetto React (Vite consigliato) e implementa lì.

Il prototipo è scritto come singolo componente auto-contenuto per la resa live; nel codebase
reale va **scomposto nei componenti a singola responsabilità** elencati più sotto, più un hook
`useStyxChat`.

## Fidelity
**High-fidelity (hifi).** Colori, tipografia, spaziature, stati e interazioni sono finali.
Ricrea la UI fedelmente usando le librerie/pattern del codebase. I token esatti sono in fondo.

---

## Architettura richiesta (componenti + hook)

```
<App>
├── useStyxChat()            hook: incapsula l'istanza StyxChat + tutte le sottoscrizioni
├── <UnlockScreen>           sblocco / onboarding
└── <ChatShell>              layout a due colonne (responsive → stack su mobile)
    ├── <ContactList>        colonna sinistra
    │   └── <ContactRow>     singola riga contatto
    ├── <ConversationView>   colonna destra
    │   ├── header presenza + "sta scrivendo…"
    │   ├── <MessageBubble>  bolla singola (in/out + spunte stato)
    │   └── <Composer>       textarea auto-grow + invio
    ├── <PairingModal>       nuovo contatto (QR | remoto)
    └── <SettingsPanel>      alias, pubkey, gestione contatti, sicurezza
```

### `useStyxChat` — responsabilità
- Crea **una sola** istanza `new StyxChat()` dopo lo sblocco (`chat.init({ password })`).
- Al **mount** dopo l'init, sottoscrive: `onMessage`, `onMessageState`, `onContactsChanged`,
  `onTyping`. Allo **unmount** disiscrive tutte (ognuna restituisce una funzione di unsub) e
  distrugge l'istanza.
- Espone: `me`, `contacts`, `messagesByContact`, `typingByContact`, e i metodi wrappati
  (`sendText`, `markRead`, `setTyping`, `listMessages`, pairing, `removeContact`, `setAlias`).
- **Invio ottimistico**: su `sendText` la bolla appare subito in stato `sending` (il mock emette
  `onMessage` sincrono dentro `sendText`); riconcilia gli stati via `onMessageState`
  (`sending → sent → delivered → read` / `failed`). Deduplica per `message.id`.
- **markRead**: chiama `chat.markRead(pubkey, lastMsgId)` all'apertura di una conversazione e su
  ogni messaggio in arrivo mentre quella conversazione è aperta (approssima "entrato nel viewport").

---

## Contratto API `StyxChat` (da usare — già esistente)

```ts
Contact = { pubkey, alias, online, unread, lastPreview, lastTs }
Message = { id, contactPubkey, direction:'in'|'out', text, ts,
            state:'sending'|'sent'|'delivered'|'read'|'failed', attachments? }

const chat = new StyxChat();
await chat.init({ password });                 // sblocco iniziale; throw su password errata
chat.me                                          // { pubkey, alias }
await chat.setAlias(alias)
await chat.listContacts()                        // -> Contact[]
chat.onContactsChanged(cb)                        // roster live; -> unsubscribe fn
await chat.createQrInvite()                      // -> { qr }  (stringa → render come QR)
await chat.acceptQrInvite(payload)               // -> { contactPubkey }
await chat.startRemotePairing()                  // -> { mnemonic } (12 parole)
await chat.joinRemotePairing(mnemonic)           // -> { doubleCheckCode } (6 cifre)
await chat.confirmPairing({ contactPubkey, alias })
await chat.removeContact(pubkey)
await chat.listMessages(pubkey, { before, limit })  // -> Message[]  (paginazione all'indietro)
await chat.sendText(pubkey, text)                // -> Message (state iniziale 'sending')
chat.onMessage(cb)                                // messaggi in arrivo/uscita
chat.onMessageState(cb)                           // (messageId, nuovoStato) → aggiorna spunte
chat.onTyping(cb)                                 // (pubkey, isTyping)
await chat.setTyping(pubkey, isTyping)
await chat.markRead(pubkey, messageId)
```

> **Nota mock**: `styx-lib.js` incluso implementa questa firma in-memory + due utility
> (`StyxUtil.identicon(pubkey)`, `StyxUtil.qrSvg(text)`) e simula progressione spunte, risposte
> automatiche, typing e presenza per rendere la UI dimostrabile. In `useStyxChat` fai il
> fallback: `const Impl = (typeof StyxChat !== 'undefined') ? StyxChat : MockStyxChat`.

---

## Screens / Views

### 1. UnlockScreen (sblocco / onboarding)
- **Purpose**: creare l'identità al primo avvio, o sbloccare agli avvii successivi.
- **Layout**: colonna centrata, `max-width: 400px`, padding `32px 20px`. In alto logo (scudo
  con check) + wordmark "Styx Chat" e sottotitolo "Messaggistica sovrana, end-to-end".
- **Due modalità** (determina con `StyxChat.hasIdentity()` o equivalente):
  - *Primo avvio* → titolo **"Crea la tua identità"**, campi **Alias pubblico** + **Password locale**,
    CTA **"Crea identità"**. `chat.init({ password, alias })` (il mock accetta alias in init; con
    la lib reale: `init({password})` poi `setAlias(alias)`).
  - *Ritorno* → titolo **"Bentornato"**, solo campo **Password locale**, CTA **"Sblocca"**.
- **Campi**: `height 46px`, `border 1px var(--border-2)`, `radius 12px`, `font-size 15px`.
- **Errore password**: su throw mostrare box rosso (`--danger` su `--danger-soft`, radius 10px,
  con icona ⚠) — testo dal `err.message` (es. "Password errata").
- **Claim E2E**: sotto un divisore, riga con icona lucchetto + testo su nessun server e
  **forward secrecy** (parole chiave evidenziate).
- **Copy esatta**:
  - Sub creazione: "Scegli un alias e una password. La password cifra le tue chiavi solo su
    questo dispositivo — non lascia mai il tuo browser."
  - Sub ritorno: "Inserisci la password per decifrare le tue chiavi e sbloccare le conversazioni."
  - Claim: "Nessun server, nessun account. Le chiavi restano cifrate qui, e ogni messaggio usa
    forward secrecy: il passato resta illeggibile anche se una chiave viene compromessa."

### 2. ChatShell — layout a due colonne
- **Desktop (≥820px)**: sinistra `width 360px` (fissa) + destra `flex:1`. Bordo verticale
  `1px var(--border)` tra le due.
- **Mobile (<820px)**: stack a schermata singola. Stato `mobileView: 'list' | 'convo'`.
  Aprire un contatto → `'convo'`; freccia "indietro" in header conversazione → `'list'`.
  La freccia indietro è visibile **solo** su mobile.

### 2a. ContactList (sinistra)
- **Header** (`padding 14px 16px 12px`, bordo sotto): avatar-identicon utente (38px, radius 11px)
  + alias + riga "● identità sbloccata" in `--accent`; a destra due bottoni icona 36px
  (toggle tema sole/luna, impostazioni ingranaggio).
- **Barra di ricerca**: input `height 40px`, icona lente a sinistra (left 12px), placeholder
  "Cerca contatti", filtra per alias + anteprima (case-insensitive).
- **Lista** (scroll): ordinata per `lastTs` desc. Ogni `<ContactRow>`:
  - Avatar identicon 48px radius 14px, con **pallino presenza** 13px in basso a destra
    (bordo `2.5px var(--panel)`): verde `--accent` se online, `--text-faint` se offline.
  - Alias (font 14.5px, weight 650), timestamp relativo a destra (ora/m/HH:MM/giorno).
  - Anteprima ultimo messaggio (13px `--text-dim`, ellipsis).
  - **Badge non-letti**: pill `--accent`, testo `--accent-ink`, min-width 20px, `animation pop`.
  - Riga attiva: `background --panel-3` + `border-left 3px var(--accent)`.
- **Footer**: bottone pieno **"＋ Nuovo contatto"** (`--accent`, height 46px, radius 12px).

### 2b. ConversationView (destra)
- **Empty state** (desktop senza chat aperta): scudo in card, "Seleziona una conversazione" +
  paragrafo su forward secrecy / nessun server.
- **Header** (`padding 11px 16px`, bordo sotto, `background --panel`): [freccia indietro solo
  mobile] avatar 40px, alias, sotto riga presenza: **"sta scrivendo…"** con 3 pallini animati
  (`blink`) quando `typing`, altrimenti "online"/"offline" (colore `--accent` se online/typing,
  `--text-faint` se offline). A destra badge lucchetto **"E2E"**.
- **Lista messaggi** (`padding 14px 6% 8px`, `background --convo`, scroll):
  - Banner in cima "🔒 I messaggi sono cifrati end-to-end".
  - **Separatori giorno**: pill centrata `--panel-3` con "Oggi"/"Ieri"/data estesa, quando cambia
    il giorno rispetto al messaggio precedente.
  - **Scroll infinito verso l'alto**: quando `scrollTop < 36`, chiama
    `listMessages(pubkey, { before: oldestTs, limit: 20 })`, **prepende** e mantiene la posizione
    di scroll (`scrollTop = newScrollHeight - prevScrollHeight`). Ferma quando la risposta è vuota.
    Mostra "Carico messaggi precedenti…" durante il fetch.
- **Composer** (`padding 12px 14px 14px`, bordo sopra, `background --panel`):
  - Textarea **auto-grow** (`max-height 140px`; ricalcola `height = auto` poi `scrollHeight`),
    dentro un contenitore pill `--panel-2` radius 16px. Placeholder "Scrivi un messaggio…".
  - **Enter** (senza Shift) → invia; **Shift+Enter** → newline.
  - Mentre si scrive: `setTyping(pubkey, true)`, con debounce a **1500ms** → `setTyping(false)`.
    Su invio: `setTyping(false)` + reset altezza textarea.
  - Bottone invia 46px radius 15px: disabilitato (grigio `--panel-3`) se testo vuoto, altrimenti
    `--accent`. Icona paperplane.

### 2c. MessageBubble
- **Allineamento**: `out` (inviati) a destra, `in` (ricevuti) a sinistra.
- **Bolla**: `max-width 76%`, `padding 8px 11px 7px`, `font-size 14.5px`, `line-height 1.42`,
  `box-shadow var(--shadow)`.
  - out: `background --bubble-out`, testo `--bubble-out-text`, radius `16px 16px 5px 16px`.
  - in: `background --bubble-in`, testo `--bubble-in-text`, radius `16px 16px 16px 5px`,
    `border 1px var(--border)`.
- **Meta** (in fondo, allineata a destra): orario `HH:MM` (opacity .75) + **spunte solo per out**:
  - `sending` → **orologio** (cerchio + lancette)
  - `sent` → **singolo ✓**
  - `delivered` → **doppio ✓✓** colore normale
  - `read` → **doppio ✓✓** colore `--read` (blu)
  - `failed` → **"! riprova"** in `--danger`, cliccabile → re-invio dello stesso testo
- **Animazione ingresso**: `msg-in` — `opacity 0 → 1`, `translateY(8px) scale(.985) → none`,
  `.22s cubic-bezier(.22,1,.36,1)`.
- **Auto-scroll**: alla fine su nuova conversazione aperta; su nuovo messaggio solo se l'utente è
  "vicino al fondo" (`scrollHeight - scrollTop - clientHeight < 160`) oppure se il messaggio è `out`.

### 3. PairingModal (nuovo contatto) — due tab
Overlay `rgba(6,12,16,.55)` + blur; card `max-width 460px` radius 22px, animazione `sheet`
(`translateY(24px) scale(.98) → none`, .26s). Click fuori o ✕ chiude. Tab "Codice QR" / "Pairing remoto".

- **Tab QR**:
  - **Il tuo invito**: all'apertura `createQrInvite()` → renderizza la stringa `qr` come **QR** in
    riquadro bianco 180px (radius 14px). Usa una libreria QR inclusa inline (nel prototipo il QR è
    decorativo-deterministico; nel codebase reale usa un vero encoder, es. `qrcode`).
  - **Invito ricevuto**: textarea mono per incollare `styx://…`, bottone "Accetta invito" →
    `acceptQrInvite(payload)` → `{ contactPubkey }`. Poi appare campo **alias** + "Aggiungi contatto"
    → `confirmPairing({ contactPubkey, alias })`.
- **Tab Remoto** (`rmode: 'choose' | 'generate' | 'join'`):
  - *Genera 12 parole* → `startRemotePairing()` → mostra le 12 parole in griglia 3-colonne
    numerate; deriva/mostra il **codice a 6 cifre** (con la lib reale lo mostra il flusso; nel mock
    è derivato dal mnemonic per farlo coincidere con l'altro lato).
  - *Inserisci 12 parole* → textarea, "Continua" → `joinRemotePairing(mnemonic)` →
    `{ doubleCheckCode }` (6 cifre).
  - **Verifica anti-MITM**: mostra il codice a 6 cifre grande (mono, 38px) in card `--accent-soft`,
    con la riga: *"Confermate a voce che vedete lo stesso codice: se coincide, nessuno si è messo in
    mezzo (protezione MITM)."* Checkbox "I codici coincidono su entrambi i dispositivi" +
    campo alias → **"Conferma e aggiungi"** (`confirmPairing`), abilitato solo con checkbox spuntata.
  - Dopo l'aggiunta: chiudi modale, `contactsChanged` aggiorna il roster, apri la nuova chat.

### 4. SettingsPanel
Stesso overlay/card della modale.
- **Profilo**: avatar 56px + campo **alias** editabile + "Salva" → `setAlias(v)`.
- **La tua chiave pubblica**: box mono con `me.pubkey`, bottone **copia** → `navigator.clipboard.writeText`
  (feedback "Copiato ✓" per ~1.6s).
- **Sicurezza**: card `--accent-soft` con lucchetto: *"Ogni messaggio usa forward secrecy: le chiavi
  ruotano di continuo, quindi compromettere una chiave non rivela le conversazioni passate."*
- **Gestione contatti**: elenco con avatar + alias + pubkey abbreviata + bottone cestino
  (`--danger`) → `removeContact(pubkey)` (se era la chat attiva, deselezionala).
- **Azioni sessione**: "Blocca" (teardown sottoscrizioni + torna a UnlockScreen, richiede di nuovo
  la password) e "Reimposta identità" (rimuove l'identità locale + torna all'onboarding).

---

## State Management
Stato principale (nell'`useStyxChat` hook + componente radice):
- `phase: 'unlock' | 'app'`, `firstRun: boolean`, `unlocking`, `unlockError`
- `me: {pubkey, alias} | null`
- `contacts: Contact[]` (dallo store, aggiornati da `onContactsChanged`)
- `activeKey: string | null` (pubkey conversazione aperta)
- `messagesByContact: Record<pubkey, Message[]>` (append da `onMessage`, patch da `onMessageState`)
- `typingByContact: Record<pubkey, boolean>` (da `onTyping`)
- `draft: string` (testo composer), `search: string`
- `theme: 'light' | 'dark'` (persistito in `localStorage`, default da `prefers-color-scheme`)
- `isMobile: boolean` (listener `resize`, soglia 820px), `mobileView: 'list' | 'convo'`
- `modal: null | 'new' | 'settings'`, oggetto `pair` (stato della modale pairing), `toast`
- `noMore: Record<pubkey, boolean>` (fine paginazione), `loadingMore`

Transizioni chiave: unlock ok → `phase='app'` + load contatti; open contact → load `listMessages`
+ markRead + scroll bottom; send → optimistic + reconcile; receive (attivo) → append + markRead.

---

## Interactions & Behavior (riepilogo)
- Sottoscrivi al mount, disiscrivi allo unmount (ogni `on*` restituisce l'unsub).
- Invio ottimistico + riconciliazione via `onMessageState`.
- `markRead` all'apertura chat e su messaggi in arrivo mentre è aperta.
- Scroll infinito verso l'alto con conservazione posizione.
- Typing con debounce 1500ms.
- Responsive con switch list/convo su mobile.
- **Accessibilità**: `role="dialog"`/`aria-modal` sulle modali, `aria-label` su bottoni icona,
  `:focus-visible` outline `2px var(--accent)`, navigazione tastiera (Enter invia), `role="alert"`
  sull'errore password, contrasto AA sul testo.
- **Animazioni**: `msg-in` (bolle), `pop` (badge/toast), `sheet` (modali), `fade` (overlay/schermate),
  `blink` (pallini typing). `prefers-reduced-motion`: considerare di ridurle.

---

## Design Tokens

Tema chiaro / scuro via CSS custom properties su `[data-theme]`, default da `prefers-color-scheme`.

### Colori — LIGHT
```
--bg:#e9edf1  --panel:#ffffff  --panel-2:#f4f6f8  --panel-3:#eceff2
--border:#e0e5ea  --border-2:#d3dae0
--text:#0f1720  --text-dim:#5b6774  --text-faint:#93a0ab
--accent:#0d9f6e  --accent-2:#0b8a60  --accent-ink:#ffffff  --accent-soft:#e2f4ec
--bubble-out:#d5f0e4  --bubble-out-text:#0a3527
--bubble-in:#ffffff   --bubble-in-text:#101820
--read:#2f7fed  --danger:#e0403f  --danger-soft:#fbe6e6  --convo:#e4e9ed
```
### Colori — DARK
```
--bg:#04070a  --panel:#0d1317  --panel-2:#141c22  --panel-3:#0f171c
--border:#1d272e  --border-2:#26333c
--text:#e8eef2  --text-dim:#95a3ad  --text-faint:#5f6c76
--accent:#18b981  --accent-2:#13a06f  --accent-ink:#04130c  --accent-soft:#0f2921
--bubble-out:#123a2c  --bubble-out-text:#d4f5e6
--bubble-in:#161f26    --bubble-in-text:#e8eef2
--read:#5aa2ff  --danger:#ff5d5d  --danger-soft:#341617  --convo:#070c10
```
### Tipografia
- Font stack: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif`
- Mono (pubkey, codici, mnemonic): `ui-monospace, SFMono-Regular, Menlo, monospace`
- Scala: titoli schermate 26px/700, titoli modali 17px/700, alias 14.5–15.5px/650–700,
  corpo bolle 14.5px, meta/timestamp 10.5–12px, label sezioni 11px/700 uppercase `.05em`.
- `letter-spacing` titoli ≈ `-.02em`.

### Raggi / Ombre / Spazi
```
radius: bottoni 12–15px · card/modali 22px · avatar 11–16px · pill/badge 10–20px · bolle 16px (angolo interno 5px)
shadow:    0 1px 2px rgba(16,24,32,.06), 0 8px 24px rgba(16,24,32,.06)
shadow-lg: 0 24px 64px rgba(9,15,20,.18)   (dark: valori più profondi, vedi styx-lib/DC)
spacing: gap tipici 6/8/10/12/14px; padding pannelli 14–20px
breakpoint mobile: 820px
```
### Icone
Tutte **SVG inline** (nessun asset esterno): scudo+check (logo/E2E), lucchetto, lente, ＋,
ingranaggio, sole/luna, freccia indietro, paperplane, orologio, ✓, ✓✓, ⚠, ✕, matita, QR-frame,
copia, cestino. Stroke `currentColor`, width 1.7–2.4.

### Avatar & QR
- **Identicon** deterministico dalla `pubkey`: griglia simmetrica 5×5, tinta HSL da hash della
  chiave, resa come SVG data-URI. (Vedi `StyxUtil.identicon` in `styx-lib.js`.)
- **QR**: renderizza la stringa di `createQrInvite().qr`. Nel prototipo è decorativo-deterministico;
  in produzione usa un encoder reale.

---

## Assets
Nessun asset binario esterno. Tutte le icone sono SVG inline; avatar e QR sono generati a runtime
come SVG data-URI. Nessun font esterno (solo stack di sistema) — nessun `fetch` verso host esterni.

## Files (in questo bundle)
- `Styx Chat.dc.html` — prototipo di riferimento completo (tutte le schermate e le interazioni).
- `styx-lib.js` — mock in-memory `StyxChat` con la firma del contratto + `StyxUtil` (identicon, QR).
  Riusabile come fallback quando `styx-js` non è caricato. Contiene anche la logica di simulazione
  (progressione spunte, risposte automatiche, typing, presenza) utile per test/demo.

> Il `.dc.html` è un formato di prototipo con runtime proprietario: **apri e guarda il comportamento**,
> ma implementa da zero in React seguendo questo README (la logica è nella classe `Component`,
> il markup nel template — mappali su hook + JSX).
