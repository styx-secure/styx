# Styx Chat — Design & Feasibility Spec

**Data:** 2026-07-09 · **Stato:** MVP **funzionante e testato end-to-end** (crypto MLS reale) ·
**Scope:** app di chat 1:1 multi-contatto, serverless, E2E, per iPhone/Android, su `styx-js`.

> **Aggiornamento — MVP completo e testato.** L'app gira sulla libreria reale (OpenMLS-WASM):
> due tab (identità Ed25519 distinte) si accoppiano via invito e si scambiano messaggi cifrati
> MLS end-to-end, verificato da una spec Playwright a due pagine (`apps/chat/e2e/pairing.spec.js`).
> Trasporto **interim**: `BroadcastChannelTransport` (serverless, stesso origin) — WebRTC P2P-first
> + Nostr fallback restano lo swap di produzione dietro la stessa interfaccia. Suite JS: 458 test.
> Persistenza dello stato MLS tra reload e packaging mobile (PWA/Capacitor) sono i prossimi passi.

## 1. Obiettivo e verdetto di fattibilità

Costruire un'app di messaggistica **tipo WhatsApp** — 1:1 multi-contatto (niente gruppi),
**serverless**, **end-to-end encrypted**, con **identità auto-custodita** (nessun account, nessun
numero di telefono) — riusando ed estendendo la libreria JavaScript `styx-js`.

**Verdetto: fattibile.** `styx-js` fornisce già trasporto (WebRTC + Nostr), storage IndexedDB,
pairing (QR + remoto BIP-39/SPAKE2), identità Ed25519 e un ledger hash-chain. Il lavoro nuovo è
tre pezzi: (1) orchestrazione **multi-contatto**, (2) layer crittografico **MLS** con forward
secrecy, (3) **frontend** web (realizzato da Claude Design). Delivery mobile e custodia chiavi
sono coperti da wrapper nativo e WebAuthn PRF.

## 2. Decisioni (con motivazione da ricerca verificata)

Due cicli di deep-research (fonti primarie, verifica avversariale) hanno guidato le scelte:

| Ambito | Decisione | Motivo |
|---|---|---|
| **Crypto** | **MLS (RFC 9420) via OpenMLS-WASM** | Il Double Ratchet in JS **non ha librerie audite/mantenute** (`libsignal-protocol-javascript` è deprecato) → ci obbligherebbe a crypto non audita. OpenMLS è l'**unica lib MLS audita** (SRLabs) e **in produzione** (XMTP/libxmtp). MLS dà FS+PCS nativi per il gruppo-di-2 (1:1), più multi-device e gruppi futuri. |
| **Trasporto** | **P2P-first WebRTC + relay Nostr fallback** | Scelta dell'utente (sovranità sul transito). Realtà: il P2P puro fallisce ~20% dietro NAT su mobile → il fallback relay dev'essere solido (i relay vedono solo cifrato). MLS è agnostico al trasporto → si incastra pulito. |
| **Delivery mobile** | **Wrapper Capacitor + push-bridge stateless** | Web Push su iOS è solo per PWA in home-screen, senza push data-only; il plugin Capacitor non fa iOS silent push. Serve nativo + bridge APNs/FCM stateless (sveglia soltanto, contenuto mai nel payload → E2E intatto). |
| **Custodia chiavi** | **WebAuthn PRF (hardware) + password fallback** | PRF (CTAP2 hmac-secret) dà 32 byte di IKM dal secure element → HKDF → wrapping key. Fallback: `EncryptedKeyStore` (PBKDF2+AES-GCM) già implementato. |
| **Multi-device** | **Rimandato** (day-1: 1 device per identità) | MLS lo abilita nativamente (device = membro), ma lo sfruttiamo dopo. |

**Scartati:** Double Ratchet a mano (no lib audita); `ts-mls` (non audito, benché PQ-ready e
npm-nativo); NIP-17 come layer primario (E2E ma **non** forward-secret); wire-format Marmot
(relay-centrico, ancora in flux — ne prendiamo solo i pattern KeyPackage/Welcome).

**Rischio principale aperto:** peso bundle / cold-start di OpenMLS-WASM su mobile (non
quantificato dalla ricerca) → da misurare nel primo spike; il wrapper Capacitor lo mitiga.
**PQ** non è day-1 (OpenMLS default classico) → migrazione futura.

## 3. Architettura

```
┌──────────────────────────────────────────────────────────┐
│  Frontend Web  (React SPA da Claude Design)              │  self-contained, no fetch esterni
│  UnlockScreen · ChatShell · Pairing · Settings           │
└──────────────────────────┬───────────────────────────────┘
                           │  contratto API "StyxChat" (§4)
┌──────────────────────────┴───────────────────────────────┐
│  StyxChat  (orchestratore multi-contatto)                │  roster, N conversazioni,
│  ChatManager · ContactRoster · Conversation              │  receipts, typing, unread
├──────────────────────────────────────────────────────────┤
│  MlsSession ×N (una per contatto = gruppo MLS 2-membri)  │  FS+PCS, KeyPackage/Welcome
│      └─ MlsEngine → OpenMLS-WASM (motore audito)        │  RFC 9420
│  LedgerStore ×N (storia/ordinamento locale)              │  esistente, riusato
├──────────────────────────────────────────────────────────┤
│  Transport: WebRTC P2P (primario) + Nostr relay (fallback)│  esistente, MLS-agnostico
│  Storage: IndexedDB per-contatto + EncryptedKeyStore     │  esistente + nuovo
│  Custodia: WebAuthn PRF (hardware) + password fallback   │  nuovo
│  Crypto base: @noble (Ed25519 identity) + OpenMLS (E2E)  │  esistente + nuovo
└──────────────────────────────────────────────────────────┘
```

Il ledger hash-chain **non è più il confine di sicurezza** (lo è MLS): resta come persistenza e
ordinamento causale locale della storia dei messaggi.

## 4. Contratto API `StyxChat` (ponte frontend ↔ core)

```
Contact = { pubkey, alias, online, unread, lastPreview, lastTs }
Message = { id, contactPubkey, direction:'in'|'out', text, ts,
            state:'sending'|'sent'|'delivered'|'read'|'failed', attachments? }

class StyxChat {
  static async hasIdentity()                     // per il rilevamento primo-avvio
  async init({ password })                       // sblocca/crea identità, apre IndexedDB
  get me()                                       // { pubkey, alias }
  async setAlias(alias)
  async listContacts() -> Contact[]
  onContactsChanged(cb) -> unsubscribe
  async createQrInvite() -> { qr }
  async acceptQrInvite(payload) -> { contactPubkey }
  async startRemotePairing() -> { mnemonic }
  async joinRemotePairing(mnemonic) -> { doubleCheckCode, contactPubkey }
  async confirmPairing({ contactPubkey, alias })
  async removeContact(pubkey)
  async listMessages(pubkey, { before?, limit? }) -> Message[]
  async sendText(pubkey, text) -> Message
  onMessage(cb) -> unsubscribe
  onMessageState(cb) -> unsubscribe              // (messageId, state)
  onTyping(cb) -> unsubscribe                    // (pubkey, isTyping)
  async setTyping(pubkey, isTyping)
  async markRead(pubkey, messageId)
}
```

Le utility puramente UI (`identicon`, `shortKey`, encoder QR) **non** fanno parte del core: vivono
nel frontend. Il core espone solo dati e comportamento.

## 5. Fasi

1. **Fondamenta multi-contatto** — `src/chat/` (`StyxChat`, `ContactRoster`, `Conversation`),
   N sessioni per contatto con namespace IndexedDB dedicato, custodia identità. *Fatto:*
   `EncryptedKeyStore` (8 test), `ContactRoster` (11 test).
2. **Motore MLS (OpenMLS-WASM)** — (a) build OpenMLS→WASM (wasm-pack) + misura bundle/cold-start;
   (b) `MlsEngine` + `MlsSession` (gruppo 2-membri, KeyPackage/Welcome, commit/ratchet,
   skipped-keys); (c) sostituisce `StyxEncryptor` in `_setupPairedState`.
3. **Esperienza chat** — receipt consegna/lettura, typing/presence effimeri, unread, allegati
   (MVP immagini piccole con chunking).
4. **Frontend (Claude Design)** — React SPA che consuma `StyxChat` (vedi §6).
5. **Hardening + packaging mobile** — WebAuthn PRF, PWA (manifest/service worker), wrapper
   Capacitor + push-bridge stateless, build TestFlight/Play.

## 6. Frontend: stato della consegna Claude Design

Il bundle è in `styx-js/apps/chat/design/` (`README.md`, `styx-chat.dc.html`, `styx-lib.js`).
È un **riferimento di design high-fidelity**, non codice React di produzione:

- **`README.md`** — handoff completo: architettura componenti, contratto API (allineato al §4),
  tutte le schermate con copy esatta, state management, accessibilità, design token (light/dark).
- **`styx-chat.dc.html`** — prototipo nel formato proprietario Design Composer (`text/x-dc`,
  richiede un `support.js` non incluso): **da guardare per look & behavior**, da re-implementare
  in React (Vite).
- **`styx-lib.js`** — mock in-memory fedele del contratto + `StyxUtil` (identicon, QR
  decorativo, mnemonic). Riusabile come **fallback di sviluppo** quando `styx-js` non è caricato.

**Correzioni/adattamenti per la produzione** (non difetti di design, ma gap di integrazione):
- Re-implementare in **React reale** (il `.dc.html` non è eseguibile senza il runtime DC).
- Sostituire il **QR decorativo** del mock con un **encoder reale** (`qrcode`) e aggiungere uno
  **scanner camera** (mobile) per `acceptQrInvite` oltre all'incolla `styx://`.
- Allineare la **superficie API**: `StyxChat.hasIdentity()` statico; messaggi d'errore (`init`
  lancia `Invalid password`); import **ESM** (`import { StyxChat } from 'styx-js'`) invece del
  global `window.StyxChat` del prototipo; tenere `identicon/shortKey` nel frontend.
- La UI modella già `sending/sent/delivered/read/failed` e l'invio ottimistico → pronta per la
  **latenza/fallimenti reali** di MLS+trasporto. Presence/typing reali si cablano in Fase 3.
- Vincoli rispettati: **nessun asset/fetch esterno**, solo font di sistema, SVG inline →
  compatibile con CSP stretta e con il modello serverless.

## 7. Verifica end-to-end

1. **Jest:** `cd styx-js && npm test` — nuovi test per `MlsSession` (FS dopo commit; out-of-order;
   join via Welcome) e `StyxChat` (roster, invio/ricezione, receipts, unread).
2. **Playwright due-peer:** due contesti browser che si accoppiano via QR, scambiano messaggi
   cifrati, verificano spunte e persistenza dopo reload; relay Nostr locale via
   `docker-compose.test.yml`.
3. **Manuale:** build del bundle chat, due browser, pairing, chat; typing/presence e offline.
4. **Crypto review:** `superpowers:requesting-code-review` sul modulo MLS prima del merge.

## 8. Esito spike MLS (2026-07-09)

**Blocco iniziale (risolto):** il 403 su `static.crates.io` sembrava impedire la build, ma era un
falso allarme (HEAD fuorviante). In realtà rustup, indice sparse crates.io, GitHub e **Docker**
sono tutti disponibili → la build è stata eseguita qui.

**Verdetto: GO, e blocco superato.** Sequenza completata:
1. *Ergonomia* validata prima con `ts-mls` (npm, RFC 9420) — round-trip 1:1 verde (KeyPackage →
   gruppo 2-membri → Welcome → join → messaggi bidirezionali; epoca avanza sul commit).
2. **Motore di produzione compilato e verificato:** OpenMLS (commit `09e9277`, MIT) → **WASM** via
   `rust:latest` in Docker + `wasm-pack`. Vendorizzato in **`styx-js/vendor/openmls-wasm/`** con
   README di provenienza, `build.sh` riproducibile e `roundtrip.mjs`. Round-trip 1:1 col motore
   reale **verde** in Node (KeyPackage 275B, Welcome 346B, messaggi bidirezionali decifrati).
3. **Peso bundle risolto:** `openmls_wasm_bg.wasm` ≈ 1.8 MB raw / **≈ 655 KB gzip** — accettabile
   per PWA/Capacitor. Ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (MTI OpenMLS).

**Unico gap noto per la Fase 2:** il `Provider` tiene lo stato in memoria → per la persistenza
tra reload serve esporre serialize/restore dello storage (o backarlo su IndexedDB via il trait
`StorageProvider`). È l'unica estensione Rust oltre all'artefatto ufficiale.

**Interfaccia `MlsSession` derivata dallo spike** (wrapper che isola OpenMLS dal resto):
```
class MlsEngine {
  static async init()                                   // carica ciphersuite (WASM per OpenMLS)
  async generateKeyPackage(identity) -> { publicPackage, privatePackage }
}
class MlsSession {                                       // una per contatto = gruppo 2-membri
  static async create({ groupId, selfKp, peerKpWire }) -> { session, welcomeWire, ratchetTree }
  static async join({ welcomeWire, selfKp, ratchetTree }) -> { session }
  async encrypt(bytes) -> wireBytes                      // application message
  async decrypt(wireBytes) -> { kind:'app'|'handshake', plaintext? }
  async commit() -> handshakeWire                        // ratchet epoca (rekey / PCS)
  serializeState() -> bytes / static restoreState(bytes) // persistenza IndexedDB
}
```
**Note d'integrazione emerse:** (a) il pairing deve trasportare il **KeyPackage** del peer (non la
sola pubkey), e il creatore deve inviare **Welcome + ratchet tree** al joiner; (b) lo stato MLS è
**immutabile/funzionale** (ogni op ritorna `newState`) → il wrapper tiene e sostituisce lo stato e
lo persiste (`encodeGroupState`/`decodeGroupState`); (c) le chiavi `consumed` vanno azzerate dopo
ogni op (igiene FS); (d) handshake e messaggi applicativi arrivano dallo stesso path di decrypt,
distinti dal `kind`.
