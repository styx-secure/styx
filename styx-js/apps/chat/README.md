# Styx Chat — frontend web

SPA React/Vite dell'app di messaggistica E2E serverless. Consuma il contratto `StyxChat`
tramite `src/lib/styx-adapter.js`: usa la libreria reale (`import { StyxChat } from 'styx-js'`)
se presente, altrimenti ripiega sul **mock in-memory** (`src/lib/styx-lib-mock.js`), così la UI
è navigabile in isolamento.

## Avvio
```bash
npm install
npm run dev      # http://localhost:5175
npm run build    # bundle di produzione in dist/
npm run preview  # serve dist/
```

## Struttura
- `src/hooks/useStyxChat.js` — unico punto di contatto con la libreria: istanza singola,
  sottoscrizioni (`onMessage`/`onMessageState`/`onContactsChanged`/`onTyping`), invio ottimistico
  con dedup per `id`, paginazione, presenza/typing.
- `src/lib/styx-adapter.js` — selezione lib reale vs mock. `identicon.js`, `qr.js` (QR reale con
  `qrcode` + scanner camera `@zxing/browser`), `format.js` (date IT).
- `src/components/` — `UnlockScreen`, `ChatShell`, `ContactList`/`ContactRow`,
  `ConversationView`/`MessageBubble`/`Composer`, `PairingModal`, `SettingsPanel`, `Icons`.
- `src/styles/tokens.css` — design token (light/dark) e keyframes; `app.css` — stili componenti.
- `design/` — handoff di riferimento di Claude Design (prototipo `.dc.html`, README, brief, mock).

## Note
- Verificato in Chromium (Playwright): onboarding → roster demo → invio messaggio → tema/impostazioni,
  senza errori di pagina.
- Il contratto `onContactsChanged` è trattato come segnale: se non porta la lista (come nel mock)
  la UI la rifetcha con `listContacts()`.
- Il bundle include `@zxing/browser` (scanner QR), che è pesante: candidato a lazy-load futuro.
- **Solo mock**: nessuna crittografia/rete reale finché non si collega `styx-js` (MLS/OpenMLS).
