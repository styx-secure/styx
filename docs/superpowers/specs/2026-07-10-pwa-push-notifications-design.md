# Spec — PWA installabile + notifiche (locali e push)

**Data:** 2026-07-10 · **Scope:** Styx Chat (styx-js / apps/chat + nuovo push_bridge) · **Stato:** approvato

## Obiettivo

Due cose accoppiate:
1. Rendere Styx Chat una **PWA installabile** (iPhone/Android): icona in home, avvio a
   schermo intero, shell offline, più **notifiche locali** quando l'app è viva.
2. Aggiungere un meccanismo per ricevere **notifiche di messaggi e inviti anche ad app
   chiusa**, tramite Web Push e un piccolo **bridge cieco e opzionale**.

Sono accoppiate perché su iOS il Web Push funziona **solo** per una PWA installata in home
(da iOS 16.4): la Fase 1 è il prerequisito tecnico della Fase 2. Un unico design, due fasi
indipendenti — la Fase 1 è spedibile e testabile da sola.

## Principi (validi per tutto il design)

1. **Bridge opt-in e cieco.** L'app resta pienamente funzionante e serverless senza bridge.
   Le push si attivano puntando l'app a un bridge (URL configurabile). Il bridge vede solo
   ciphertext + metadati di instradamento (la pubkey X ha traffico in arrivo, e quando) —
   esattamente ciò che ogni relay Nostr già vede. Non memorizza messaggi né chiavi.
2. **Notifica generica.** Payload push vuoto: "Hai un nuovo messaggio". Vale sia per i
   messaggi sia per gli inviti: un invito accettato è un evento kind-1059 verso la tua
   pubkey, indistinguibile da un messaggio → stessa notifica. Nessun contenuto, mai. È il
   prezzo esatto dell'E2E: se il testo non lo legge nessuno tranne te, nessun intermediario
   può metterlo nella notifica.
3. **Registrazione firmata.** Il client si registra al bridge firmando il payload con la
   propria chiave Nostr (schnorr). Solo il proprietario di una pubkey può iscriverla: nessuno
   può registrare la *tua* pubkey verso il *suo* endpoint per spiare la tua attività.

## Modello mentale: tre stati, tre comportamenti

| Stato | Chi è sveglio | Meccanismo |
|---|---|---|
| App in primo piano | l'app (socket ai relay vivo) | nessuno — il messaggio appare |
| App in background, telefono sbloccato, da poco | l'app, finché il SO non la sospende | **notifica locale** (Fase 1) |
| App chiusa / telefono bloccato | nessuno nel telefono | **notifica push** dal bridge (Fase 2) |

---

## Fase 1 — PWA installabile + notifiche locali

**Deliverable:** app installabile su iPhone/Android, apre offline (app shell + WASM in cache),
mostra una notifica locale quando arriva un messaggio mentre l'app è viva ma non in primo piano.

### Componenti

- **Web App Manifest** (`apps/chat/public/manifest.webmanifest`): `name`/`short_name`,
  `display: standalone`, `theme_color`/`background_color` dai token (verde accent/dark),
  `start_url: "/"`, `id`, `orientation: portrait`, `lang: it`, set icone.
- **Set icone** generato da un mark SVG: PNG 192 e 512, una variante `maskable`, e un
  `apple-touch-icon` 180×180 referenziato nell'`index.html` (iOS non legge il manifest per
  l'icona di home). Generazione in un piccolo script di build (SVG → PNG).
- **Service worker** via `vite-plugin-pwa` in strategia **`injectManifest`** (SW nostro che
  Workbox arricchisce col precache). Responsabilità Fase 1: precache dell'app shell **inclusa
  la WASM da ~1.8 MB** (così l'app apre offline e la crypto funziona), navigation fallback a
  `index.html`, cache-first per gli asset statici, rete per i relay (WebSocket non in cache).
  Il file SW predispone già lo scheletro dei listener `push`/`notificationclick`, che la Fase 2
  riempie.
- **Modulo notifiche locali** (`apps/chat/src/lib/notify.js`, isolato e testabile): decide se
  mostrare una notifica in base a `permesso × document.visibilityState × coalescing`. Se il
  permesso è concesso e la pagina non è visibile, all'arrivo di un evento (`onMessage`) chiama
  `new Notification('Styx Chat', { body: 'Hai un nuovo messaggio', tag: 'styx-new' })`.
  Il coalescing (una notifica per raffica ravvicinata, via `tag` + una finestra temporale)
  evita lo spam. L'aggancio a `onMessage` vive nell'hook `useStyxChat`.
- **UX permesso + install:** la richiesta del permesso avviene **su gesto utente** (un pulsante
  in Impostazioni / un prompt one-shot dopo il primo messaggio), mai al load (iOS lo richiede).
  Su iOS Safari, un hint "Aggiungi a Home per installare / abilitare le notifiche"; su Android,
  pulsante install custom agganciato a `beforeinstallprompt`.

### Limite onesto

Su iOS una PWA in background viene sospesa in fretta: le notifiche *locali* coprono soprattutto
Android/desktop e il background breve. La copertura ad app chiusa è ciò che risolve la Fase 2.

### Test (Fase 1)

- **Manifest:** un test verifica che `manifest.webmanifest` contenga i campi richiesti
  (name, start_url, display, icons 192/512, theme/background color).
- **Offline shell:** Playwright — installa il SW, va offline, ricarica: l'app shell renderizza
  (schermata di sblocco visibile).
- **`notify()`:** unit test con `Notification` mockato — copre permesso concesso/negato,
  pagina visibile vs nascosta, e coalescing (due eventi ravvicinati → una notifica).
- **Installabilità:** Lighthouse PWA (manuale).

---

## Fase 2 — Bridge + Web Push (notifiche ad app chiusa)

**Deliverable:** notifica anche a telefono bloccato / app chiusa, tramite un bridge Node
sempre-acceso, cieco e opt-in.

### Il bridge (`push_bridge/`, nuovo, Node.js)

Node perché riusa direttamente il `RelayPool`/client Nostr di `styx-js` e la libreria standard
`web-push` — tutto JS, stessa base di codice.

- **Ascolto relay:** sottoscrizioni ai relay con filtro `{ kinds:[1059], '#p':[...pubkey
  registrate] }`. **Solo kind 1059** (messaggi/inviti stored); il kind 20000 (typing/presence,
  effimero) non viene mai notificato. Dedup per `event.id` (niente doppie sul replay dei relay).
- **API HTTP** (piccola: Node `http` o express):
  - `GET /vapidPublicKey` → chiave pubblica VAPID che il client usa per iscriversi.
  - `POST /register` `{ pubkey, subscription, sig }` → verifica la firma schnorr sul payload
    canonico con `pubkey`; se valida, salva `pubkey → [subscription]` e aggiunge la pubkey al
    filtro dei relay. Firma non valida → 401.
  - `POST /unregister` `{ pubkey, sig }` → firmato, rimuove la subscription/pubkey.
- **Invio push:** su evento per la pubkey X → per ogni subscription di X, Web Push VAPID con
  **payload vuoto**. Coalescing per pubkey (una notifica per raffica ravvicinata). Su `410 Gone`
  o `404` (subscription scaduta) → rimozione dal registro.
- **Persistenza:** solo il registro `pubkey → [subscription]` (file JSON o SQLite). Nessun
  messaggio, nessuna chiave — è l'unico stato, ed è instradamento, non dati. Config via env:
  lista relay, chiavi VAPID (pubblica/privata), porta. Gira dietro il tunnel Cloudflare
  (secondo hostname o path).

### Integrazione client (`styx-js` + app)

- **`PushRegistrar`** (`styx-js/src/push/push-registrar.js`): dopo unlock + permesso,
  `registration.pushManager.subscribe({ userVisibleOnly:true, applicationServerKey })` con la
  VAPID key presa da `GET /vapidPublicKey`, poi `POST /register` firmato con la chiave Nostr.
  Subscription salvata localmente; ri-registra se cambia. **Bridge URL configurabile**: se
  assente → nessuna push, l'app funziona comunque (degrado morbido). Firma la registrazione
  riusando lo schnorr già presente in `NostrChatTransport`.
- **Service worker — handler `push`:** su push → `self.registration.showNotification('Styx
  Chat', { body:'Hai un nuovo messaggio', tag:'styx-new' })`. Su `notificationclick` →
  focus di un client esistente o apertura della PWA. La logica decisionale dell'handler è
  estratta in una funzione pura testabile.

### Sicurezza / privacy

- Registrazione firmata: solo il proprietario iscrive la sua pubkey.
- Payload vuoto; Web Push è comunque cifrato (RFC 8291) → i push service (Apple/Google/Mozilla)
  non leggono contenuto (non c'è).
- Bridge cieco al contenuto; opt-in; spegnendolo l'app resta funzionante.
- Il design documenta esplicitamente cosa vede il bridge (= quanto vedono i relay: la pubkey X
  ha traffico in arrivo, e quando).

### Test (Fase 2)

- **Bridge:** `register`/`unregister` con verifica firma, incluso il **rifiuto di una
  registrazione contraffatta** (firma di un'altra chiave → 401); dispatch evento→push con
  `web-push` e un relay finti; cleanup su 410; coalescing/dedup per event.id.
- **`PushRegistrar`:** unit test con `pushManager` e `fetch` mockati (subscribe → register
  firmato; nessun bridge URL → no-op).
- **Handler `push`:** funzione pura estratta e unit-testata (payload → decisione showNotification).
- **End-to-end manuale:** due telefoni, app chiusa, invio messaggio → la notifica arriva; tap
  → apre la PWA che decifra E2E.

---

## Casi limite (comportamento atteso)

- **Multi-dispositivo:** una pubkey può avere più subscription (un device per riga). Il bridge
  le sveglia tutte. (Il multi-device MLS vero e proprio resta fuori scope, come da piano
  generale; qui si tratta solo di più caselle push per la stessa identità.)
- **Offline da giorni:** i relay conservano i kind-1059; alla riapertura l'app scarica gli
  arretrati. Il bridge notifica all'arrivo dell'evento sul relay, non "recupera" storia.
- **Bridge spento:** nessuna push; notifiche locali e messaggistica invariati.
- **Permesso negato:** nessuna notifica (locale o push); l'app segnala che sono disattivate e
  offre di riattivarle da Impostazioni.

## File toccati / nuovi

**Fase 1**
- `apps/chat/public/manifest.webmanifest` (nuovo), icone in `apps/chat/public/` (nuove)
- `apps/chat/vite.config.js` — `vite-plugin-pwa` (`injectManifest`)
- `apps/chat/src/sw.js` (nuovo) — SW con precache + scheletro `push`/`notificationclick`
- `apps/chat/src/lib/notify.js` (nuovo) + aggancio in `apps/chat/src/hooks/useStyxChat.js`
- `apps/chat/index.html` — `apple-touch-icon`, theme-color, link manifest
- componente/impostazione UI per permesso + hint install

**Fase 2**
- `push_bridge/` (nuovo, Node): server HTTP + listener relay + dispatch web-push + registro
- `styx-js/src/push/push-registrar.js` (nuovo) + export da `styx-js/src/index.js`
- `apps/chat/src/sw.js` — riempimento handler `push`/`notificationclick`
- `apps/chat/src/lib/config.js` — bridge URL configurabile
