# Styx Chat — frontend web

> ⚠️ **EXPERIMENTAL SOFTWARE** — Styx is under active development and has **not** completed an
> independent security audit. Do not use current builds for sensitive, high-risk, or
> life-critical communications.

SPA React/Vite dell'app di messaggistica E2E su relay federati (Nostr). Consuma il contratto `StyxChat`
tramite `src/lib/styx-adapter.js`: una build di produzione usa **solo** la libreria reale
(`import { StyxChat } from 'styx-js'`) e si arresta con un errore se il modulo crittografico manca —
nessun fallback silenzioso. Il **mock in-memory** (`src/lib/styx-lib-mock.js`) è incluso solo nella
build demo (`npm run build:demo`, `VITE_DEMO=1`) e viene eliminato dal bundle di produzione.

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
- **Build di produzione = crittografia reale.** `npm run build` produce solo la lib reale (MLS/OpenMLS);
  se il modulo crittografico manca, l'app si ferma con un errore, non ripiega su dati finti. Il mock vive
  solo nel build demo: `npm run build:demo` → `dist-demo/` (da servire su un'origine separata).

## Deployment (static-server.mjs)

`static-server.mjs` serve `dist/` senza dipendenze npm e applica una CSP completa più gli header di
sicurezza. Due allowance non ovvie:

- `script-src` include `'wasm-unsafe-eval'` perché OpenMLS compila WebAssembly
  (`WebAssembly.instantiateStreaming`). Nessun `'unsafe-inline'` sugli script (Vite emette solo
  `/assets/*.js` esterni e `/registerSW.js`). Verificato in Chromium: il WASM istanzia e non ci sono
  violazioni CSP.
- `style-src` mantiene `'unsafe-inline'` per gli attributi `style=` inline di React — eccezione
  documentata e a basso rischio (iniezione di stile, non esecuzione di script); eliminarla richiede di
  spostare gli stili inline in classi (follow-up tracciato).

`connect-src` è limitato a `self` + i relay di default. Un deployer che usa relay o un push bridge
propri li aggiunge con la variabile d'ambiente `STYX_CONNECT_SRC` (origini separate da spazio), es.
`STYX_CONNECT_SRC="https://push.miodominio wss://relay.miodominio" node static-server.mjs`.
