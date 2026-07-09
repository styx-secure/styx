# Styx Chat — Brief unico e definitivo per Claude Design

> **Questo è l'unico documento necessario.** Contiene ogni requisito: cosa consegnare, il
> contratto API da consumare, tutte le schermate con la copy esatta, lo state management, le
> interazioni, l'accessibilità e i design token completi. Sostituisce ogni brief precedente
> (README di handoff e note di correzione): dove qui e altrove divergono, **vale questo**.

---

## 0. Cosa consegnare (formato)

Consegna un **progetto React eseguibile con Vite** — **non** un file `.dc.html`, non un prototipo
in formato proprietario. Deve poter essere copiato in `styx-js/apps/chat/` e avviato con
`npm install && npm run dev`, e funzionare in isolamento sul mock incluso.

L'app è una **Single Page Application React interamente client-side**: **nessun `fetch` verso host
esterni**, nessun backend, nessun font remoto (solo stack di sistema), tutte le icone **SVG
inline**, avatar e QR generati a runtime. Tutta la logica di rete/crittografia/persistenza è
fornita da un modulo esterno, `StyxChat`; **il frontend non implementa crypto né networking** —
consuma l'API e renderizza stato ed eventi.

### Struttura del progetto attesa
```
apps/chat/
├── package.json          # React 18 + Vite; dip.: qrcode, @zxing/browser
├── vite.config.js
├── index.html
└── src/
    ├── main.jsx
    ├── App.jsx
    ├── hooks/useStyxChat.js
    ├── lib/
    │   ├── styx-adapter.js    # sceglie lib reale vs mock, normalizza l'API (§2)
    │   ├── styx-lib-mock.js   # il mock in-memory, come modulo ESM (esporta MockStyxChat + util)
    │   ├── identicon.js       # util di sola UI
    │   └── qr.js              # encoder QR reale + wrapper scanner camera
    ├── components/
    │   ├── UnlockScreen.jsx
    │   ├── ChatShell.jsx
    │   ├── ContactList.jsx    ├── ContactRow.jsx
    │   ├── ConversationView.jsx ├── MessageBubble.jsx ├── Composer.jsx
    │   ├── PairingModal.jsx
    │   └── SettingsPanel.jsx
    └── styles/tokens.css      # i design token del §9 come CSS custom properties
```

### Criterio di accettazione
- `npm install && npm run dev` avvia l'app; con `styx-js` **assente** parte sul **mock** e la UI è
  completamente navigabile (onboarding, roster demo, chat, pairing, settings, temi).
- Puntando l'adapter alla libreria reale, l'app funziona **senza modifiche ai componenti**.
- Look & behavior fedeli a questo brief; token del §9 rispettati in light **e** dark.
- Componenti piccoli, a singola responsabilità; tutta l'interazione con la libreria passa dal
  solo hook `useStyxChat`.

---

## 1. Architettura componenti + hook

```
<App>
├── useStyxChat()            hook: incapsula l'istanza StyxChat + tutte le sottoscrizioni
├── <UnlockScreen>           sblocco / onboarding
└── <ChatShell>              layout a due colonne (responsive → stack su mobile)
    ├── <ContactList> → <ContactRow>
    ├── <ConversationView> → header presenza/typing · <MessageBubble> · <Composer>
    ├── <PairingModal>       nuovo contatto (QR | remoto)
    └── <SettingsPanel>      alias, pubkey, gestione contatti, sicurezza
```

### `useStyxChat` — responsabilità
- Crea **una sola** istanza dopo lo sblocco e chiama `chat.init({ password })`.
- Al **mount** (dopo init) sottoscrive `onMessage`, `onMessageState`, `onContactsChanged`,
  `onTyping`; allo **unmount** disiscrive tutte (ogni `on*` ritorna una funzione di unsubscribe)
  e distrugge l'istanza.
- Espone: `me`, `contacts`, `messagesByContact`, `typingByContact`, e i metodi wrappati
  (`sendText`, `markRead`, `setTyping`, `listMessages`, pairing, `removeContact`, `setAlias`).
- **Invio ottimistico**: su `sendText` la bolla appare subito in stato `sending`; riconcilia gli
  stati via `onMessageState` (`sending → sent → delivered → read` / `failed`). **Deduplica per
  `message.id`** (la lib reale può emettere `onMessage` anche per il messaggio in uscita).
- **markRead**: `chat.markRead(pubkey, lastMsgId)` all'apertura di una conversazione e su ogni
  messaggio in arrivo mentre quella conversazione è aperta.

---

## 2. Contratto API `StyxChat` (da consumare — già esistente)

```ts
Contact = { pubkey, alias, online, unread, lastPreview, lastTs }
Message = { id, contactPubkey, direction:'in'|'out', text, ts,
            state:'sending'|'sent'|'delivered'|'read'|'failed', attachments? }

class StyxChat {
  static async hasIdentity()                     // rilevamento primo-avvio → await StyxChat.hasIdentity()
  async init({ password })                       // sblocca/crea identità; THROW su password errata
  get me()                                       // { pubkey, alias }
  async setAlias(alias)
  async listContacts() -> Contact[]
  onContactsChanged(cb) -> unsubscribe
  async createQrInvite() -> { qr }               // stringa → rendila come QR reale
  async acceptQrInvite(payload) -> { contactPubkey }
  async startRemotePairing() -> { mnemonic }     // 12 parole
  async joinRemotePairing(mnemonic) -> { doubleCheckCode, contactPubkey }  // usa entrambi
  async confirmPairing({ contactPubkey, alias })
  async removeContact(pubkey)
  async listMessages(pubkey, { before?, limit? }) -> Message[]  // paginazione all'indietro
  async sendText(pubkey, text) -> Message        // state iniziale 'sending'
  onMessage(cb) -> unsubscribe
  onMessageState(cb) -> unsubscribe              // (messageId, nuovoStato)
  onTyping(cb) -> unsubscribe                    // (pubkey, isTyping)
  async setTyping(pubkey, isTyping)
  async markRead(pubkey, messageId)
}
```

### Selezione lib reale vs mock (obbligatoria)
`src/lib/styx-adapter.js` deve provare la libreria reale (ESM) e, se assente, cadere sul mock:
```js
let StyxChat;
try   { ({ StyxChat } = await import('styx-js')); }
catch { ({ MockStyxChat: StyxChat } = await import('./styx-lib-mock.js')); }
export { StyxChat };
```
Porta il mock a modulo ESM `src/lib/styx-lib-mock.js` che **esporta** `MockStyxChat` (invece di
scrivere su `window`). Le util `identicon`/`shortKey`/`qr` stanno nel frontend (§8), **non** nel
core: non aspettarti alcun `StyxUtil` dalla libreria.

### Allineamenti API (il mock differisce leggermente dalla lib reale — gestisci entrambi)
- `StyxChat.hasIdentity()` è **statico e async**.
- **Primo avvio**: `await chat.init({ password })` **poi** `await chat.setAlias(alias)`. La lib
  reale **non** accetta l'alias dentro `init` (il mock sì → funziona comunque se passi l'alias,
  ma il flusso corretto è init+setAlias).
- **Errore password**: `init` lancia un `Error` con messaggio **`"Invalid password"`** → mostra
  il box d'errore usando `err.message` (non dipendere da `err.code`).
- `me` è un **getter**.
- **Solo testo** in questa versione: nessun allegato/media (il campo `attachments` resta nel tipo
  ma non va implementato).

---

## 3. UnlockScreen (sblocco / onboarding)
- **Scopo**: creare l'identità al primo avvio, o sbloccare agli avvii successivi.
- **Layout**: colonna centrata, `max-width: 400px`, padding `32px 20px`. In alto logo (scudo con
  check) + wordmark "Styx Chat" e sottotitolo "Messaggistica sovrana, end-to-end".
- **Due modalità** (determina con `await StyxChat.hasIdentity()`):
  - *Primo avvio* → titolo **"Crea la tua identità"**, campi **Alias pubblico** + **Password
    locale**, CTA **"Crea identità"** → `init({ password })` poi `setAlias(alias)`.
  - *Ritorno* → titolo **"Bentornato"**, solo **Password locale**, CTA **"Sblocca"** → `init({ password })`.
- **Campi**: `height 46px`, `border 1px var(--border-2)`, `radius 12px`, `font-size 15px`.
- **Errore password**: su throw, box rosso (`--danger` su `--danger-soft`, radius 10px, icona ⚠,
  `role="alert"`), testo da `err.message`.
- **Claim E2E**: sotto un divisore, riga con icona lucchetto + testo su nessun server e forward
  secrecy (parole chiave evidenziate).
- **Copy esatta**:
  - Sub creazione: «Scegli un alias e una password. La password cifra le tue chiavi solo su questo
    dispositivo — non lascia mai il tuo browser.»
  - Sub ritorno: «Inserisci la password per decifrare le tue chiavi e sbloccare le conversazioni.»
  - Claim: «Nessun server, nessun account. Le chiavi restano cifrate qui, e ogni messaggio usa
    forward secrecy: il passato resta illeggibile anche se una chiave viene compromessa.»

---

## 4. ChatShell — layout a due colonne
- **Desktop (≥820px)**: sinistra `width 360px` (fissa) + destra `flex:1`; bordo verticale
  `1px var(--border)` tra le due.
- **Mobile (<820px)**: stack a schermata singola. Stato `mobileView: 'list' | 'convo'`. Aprire un
  contatto → `'convo'`; freccia "indietro" in header conversazione → `'list'` (visibile **solo**
  su mobile).

### 4a. ContactList (sinistra)
- **Header** (`padding 14px 16px 12px`, bordo sotto): avatar-identicon utente (38px, radius 11px)
  + alias + riga "● identità sbloccata" in `--accent`; a destra due bottoni icona 36px (toggle
  tema sole/luna, impostazioni ingranaggio).
- **Barra di ricerca**: input `height 40px`, icona lente a sinistra (left 12px), placeholder
  "Cerca contatti", filtra per alias + anteprima (case-insensitive).
- **Lista** (scroll), ordinata per `lastTs` desc. Ogni `<ContactRow>`:
  - Avatar identicon 48px radius 14px con **pallino presenza** 13px in basso a destra (bordo
    `2.5px var(--panel)`): verde `--accent` se online, `--text-faint` se offline.
  - Alias (14.5px, weight 650), timestamp relativo a destra (ora/m/HH:MM/giorno).
  - Anteprima ultimo messaggio (13px `--text-dim`, ellipsis).
  - **Badge non-letti**: pill `--accent`, testo `--accent-ink`, min-width 20px, `animation pop`.
  - Riga attiva: `background --panel-3` + `border-left 3px var(--accent)`.
- **Footer**: bottone pieno **"＋ Nuovo contatto"** (`--accent`, height 46px, radius 12px).

### 4b. ConversationView (destra)
- **Empty state** (desktop, nessuna chat aperta): scudo in card, "Seleziona una conversazione" +
  paragrafo su forward secrecy / nessun server.
- **Header** (`padding 11px 16px`, bordo sotto, `background --panel`): [freccia indietro solo
  mobile] avatar 40px, alias, sotto riga presenza: **"sta scrivendo…"** con 3 pallini animati
  (`blink`) quando `typing`, altrimenti "online"/"offline" (colore `--accent` se online/typing,
  `--text-faint` se offline). A destra badge lucchetto **"E2E"**.
- **Lista messaggi** (`padding 14px 6% 8px`, `background --convo`, scroll):
  - Banner in cima «🔒 I messaggi sono cifrati end-to-end».
  - **Separatori giorno**: pill centrata `--panel-3` con "Oggi"/"Ieri"/data estesa, quando cambia
    il giorno rispetto al messaggio precedente.
  - **Scroll infinito verso l'alto**: a `scrollTop < 36`, chiama `listMessages(pubkey, { before:
    oldestTs, limit: 20 })`, **prepende** e conserva la posizione (`scrollTop = newScrollHeight -
    prevScrollHeight`). Ferma quando la risposta è vuota. Mostra "Carico messaggi precedenti…".
- **Composer** (`padding 12px 14px 14px`, bordo sopra, `background --panel`):
  - Textarea **auto-grow** (`max-height 140px`; `height='auto'` poi `scrollHeight`) dentro un
    contenitore pill `--panel-2` radius 16px. Placeholder "Scrivi un messaggio…".
  - **Enter** (senza Shift) → invia; **Shift+Enter** → newline.
  - Mentre si scrive: `setTyping(pubkey, true)`, debounce **1500ms** → `setTyping(false)`. Su
    invio: `setTyping(false)` + reset altezza.
  - Bottone invia 46px radius 15px: disabilitato (grigio `--panel-3`) se vuoto, altrimenti
    `--accent`; icona paperplane.

### 4c. MessageBubble
- **Allineamento**: `out` a destra, `in` a sinistra.
- **Bolla**: `max-width 76%`, `padding 8px 11px 7px`, `font-size 14.5px`, `line-height 1.42`,
  `box-shadow var(--shadow)`.
  - out: `background --bubble-out`, testo `--bubble-out-text`, radius `16px 16px 5px 16px`.
  - in: `background --bubble-in`, testo `--bubble-in-text`, radius `16px 16px 16px 5px`,
    `border 1px var(--border)`.
- **Meta** (in fondo, a destra): orario `HH:MM` (opacity .75) + **spunte solo per `out`**:
  - `sending` → **orologio** · `sent` → **✓** · `delivered` → **✓✓** normale · `read` → **✓✓**
    colore `--read` (blu) · `failed` → **"! riprova"** in `--danger`, cliccabile → re-invio dello
    stesso testo.
- **Animazione ingresso**: `msg-in` — `opacity 0→1`, `translateY(8px) scale(.985)→none`,
  `.22s cubic-bezier(.22,1,.36,1)`.
- **Auto-scroll**: al fondo su nuova conversazione aperta; su nuovo messaggio solo se l'utente è
  "vicino al fondo" (`scrollHeight - scrollTop - clientHeight < 160`) o se il messaggio è `out`.

---

## 5. PairingModal (nuovo contatto) — due tab
Overlay `rgba(6,12,16,.55)` + blur; card `max-width 460px` radius 22px, animazione `sheet`
(`translateY(24px) scale(.98)→none`, .26s), `role="dialog"` `aria-modal`. Click fuori o ✕ chiude.
Tab "Codice QR" / "Pairing remoto".

- **Tab QR**:
  - **Il tuo invito**: all'apertura `createQrInvite()` → renderizza la stringa `qr` come **QR
    reale e scansionabile** con la libreria `qrcode`, in riquadro bianco 180px (radius 14px).
  - **Invito ricevuto**: **scanner con camera** (`@zxing/browser`) come opzione primaria su mobile
    **più** una textarea mono per incollare `styx://…` (fallback, e per desktop). Gestisci il
    permesso camera negato ricadendo sull'incolla. Bottone "Accetta invito" →
    `acceptQrInvite(payload)` → `{ contactPubkey }`; poi campo **alias** + "Aggiungi contatto" →
    `confirmPairing({ contactPubkey, alias })`.
- **Tab Remoto** (`rmode: 'choose' | 'generate' | 'join'`):
  - *Genera 12 parole* → `startRemotePairing()` → mostra le 12 parole in griglia 3-colonne
    numerate (mono) + il **codice a 6 cifre** del flusso.
  - *Inserisci 12 parole* → textarea, "Continua" → `joinRemotePairing(mnemonic)` →
    `{ doubleCheckCode, contactPubkey }`.
  - **Verifica anti-MITM**: codice a 6 cifre grande (mono, 38px) in card `--accent-soft`, con la
    riga: «Confermate a voce che vedete lo stesso codice: se coincide, nessuno si è messo in mezzo
    (protezione MITM).» Checkbox "I codici coincidono su entrambi i dispositivi" + campo alias →
    **"Conferma e aggiungi"** (`confirmPairing`), abilitato solo con checkbox spuntata.
  - Dopo l'aggiunta: chiudi modale, `onContactsChanged` aggiorna il roster, apri la nuova chat.

---

## 6. SettingsPanel
Stesso overlay/card della modale (`role="dialog"`).
- **Profilo**: avatar 56px + campo **alias** editabile + "Salva" → `setAlias(v)`.
- **La tua chiave pubblica**: box mono con `me.pubkey`, bottone **copia** →
  `navigator.clipboard.writeText` (feedback "Copiato ✓" ~1.6s).
- **Sicurezza**: card `--accent-soft` con lucchetto: «Ogni messaggio usa forward secrecy: le
  chiavi ruotano di continuo, quindi compromettere una chiave non rivela le conversazioni passate.»
- **Gestione contatti**: elenco con avatar + alias + pubkey abbreviata + cestino (`--danger`) →
  `removeContact(pubkey)` (se era la chat attiva, deselezionala).
- **Azioni sessione**: "Blocca" (teardown sottoscrizioni + torna a UnlockScreen, richiede di nuovo
  la password) e "Reimposta identità" (rimuove l'identità locale + torna all'onboarding).

---

## 7. State management & interazioni
Stato principale (in `useStyxChat` + radice):
- `phase: 'unlock' | 'app'`, `firstRun`, `unlocking`, `unlockError`
- `me: {pubkey, alias} | null`
- `contacts: Contact[]` (da `onContactsChanged`)
- `activeKey: string | null` (pubkey conversazione aperta)
- `messagesByContact: Record<pubkey, Message[]>` (append da `onMessage`, patch da `onMessageState`)
- `typingByContact: Record<pubkey, boolean>` (da `onTyping`)
- `draft`, `search`
- `theme: 'light' | 'dark'` (persistito in `localStorage`, default da `prefers-color-scheme`)
- `isMobile` (listener `resize`, soglia 820px), `mobileView: 'list' | 'convo'`
- `modal: null | 'new' | 'settings'`, oggetto `pair`, `toast`
- `noMore: Record<pubkey, boolean>`, `loadingMore`

Transizioni chiave: unlock ok → `phase='app'` + carica contatti; apri contatto → `listMessages` +
`markRead` + scroll bottom; invia → ottimistico + riconcilia; ricevi (chat attiva) → append +
`markRead`.

Comportamenti: sottoscrivi al mount / disiscrivi allo unmount; invio ottimistico + riconciliazione;
scroll infinito verso l'alto con conservazione posizione; typing debounce 1500ms; responsive
list/convo.

---

## 8. Avatar, QR, icone
- **Identicon** deterministico dalla `pubkey`: griglia simmetrica 5×5, tinta HSL da hash della
  chiave, reso come SVG data-URI. Implementalo in `src/lib/identicon.js` (puoi riusare l'algoritmo
  del mock incluso).
- **QR reale**: genera con `qrcode` la stringa di `createQrInvite().qr` (scansionabile — **non** il
  QR decorativo del mock). Scanner in ricezione con `@zxing/browser`. Tutto in `src/lib/qr.js`.
- **shortKey(pubkey)**: `abcd1234…wxyz` per abbreviare le chiavi (in `src/lib/`).
- **Icone**: tutte **SVG inline**, stroke `currentColor`, width 1.7–2.4 — scudo+check (logo/E2E),
  lucchetto, lente, ＋, ingranaggio, sole/luna, freccia indietro, paperplane, orologio, ✓, ✓✓, ⚠,
  ✕, matita, QR-frame, copia, cestino.

---

## 9. Design tokens (finali — rispettali)
Tema chiaro/scuro via CSS custom properties su `[data-theme]`, default da `prefers-color-scheme`,
con toggle che persiste in `localStorage`.

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
- Scala: titoli schermate 26px/700, titoli modali 17px/700, alias 14.5–15.5px/650–700, corpo bolle
  14.5px, meta/timestamp 10.5–12px, label sezioni 11px/700 uppercase `.05em`. `letter-spacing`
  titoli ≈ `-.02em`.
### Raggi / Ombre / Spazi
```
radius: bottoni 12–15px · card/modali 22px · avatar 11–16px · pill/badge 10–20px · bolle 16px (angolo interno 5px)
shadow:    0 1px 2px rgba(16,24,32,.06), 0 8px 24px rgba(16,24,32,.06)
shadow-lg: 0 24px 64px rgba(9,15,20,.18)   (dark: più profondo)
spacing: gap 6/8/10/12/14px; padding pannelli 14–20px; breakpoint mobile 820px
```

---

## 10. Accessibilità & motion
- `role="dialog"`/`aria-modal` sulle modali; `aria-label` sui bottoni icona; `:focus-visible`
  outline `2px var(--accent)`; navigazione da tastiera (Enter invia); `role="alert"` sull'errore
  password; contrasto AA sul testo.
- Animazioni: `msg-in` (bolle), `pop` (badge/toast), `sheet` (modali), `fade` (overlay/schermate),
  `blink` (pallini typing). Rispetta **`prefers-reduced-motion`** riducendole/disattivandole.

---

## 11. Note operative finali
- Nessun `fetch` esterno; `qrcode` e `@zxing/browser` inclusi come dipendenze npm del progetto
  (bundizzate, non caricate da CDN).
- Il **mock** incluso (`styx-lib-mock.js`) simula progressione spunte, risposte automatiche,
  typing e presenza: serve a rendere la UI dimostrabile e a testare tutte le interazioni senza la
  libreria reale. Non è codice di produzione.
- Consegna un progetto pulito e ordinato: componenti isolati, un solo punto di contatto con la
  libreria (`useStyxChat` + `styx-adapter`), token centralizzati in `tokens.css`.
```
