# Spec — Orario d'invio + spunte di consegna/lettura (WhatsApp-style)

**Data:** 2026-07-10 · **Scope:** Styx Chat (styx-js) · **Stato:** approvato

## Problema

1. I messaggi mostrano l'ora in cui il destinatario li **riceve**, non quando il mittente
   li ha **inviati** (tutti finiscono con lo stesso orario dopo un recupero offline).
2. Non esistono stati reali di consegna/lettura: il mittente sa solo `sent`. Servono le
   spunte tipo WhatsApp: **inviato** (1 spunta grigia), **consegnato** (2 grigie),
   **letto** (2 verdi).

## Requisito di privacy (vincolante)

Le ricevute NON devono essere leggibili da osservatori esterni. Viaggiano **dentro la stessa
cifratura MLS** dei messaggi: il relay vede solo un blob opaco, indistinguibile da un messaggio
di testo — non può capire che è una ricevuta né a quale messaggio si riferisce. Essendo cifrate
come i messaggi, sono anche **memorizzate** sui relay → affidabili (le spunte si aggiornano alla
riconnessione) **e** private.

## Design

### Payload cifrato tipizzato

Oggi si cifra il solo testo. D'ora in poi il plaintext MLS è un oggetto JSON con discriminatore:
- Messaggio: `{ t: 'msg', id, text, ts }`
- Ricevuta:  `{ t: 'receipt', ref, kind: 'delivered' | 'read' }`

`id` e `ts` sono generati dal mittente e viaggiano cifrati. Il destinatario mostra il `ts` del
mittente e usa `id` per deduplicare e per correlare le ricevute.

### Flusso

- **Invio:** `sendText` crea `{t:'msg', id, text, ts}`, stato `sending` (orologio); appena
  pubblicato sul relay → `sent` (1 spunta grigia).
- **Consegna:** il destinatario decifra un `{t:'msg'}`, lo mostra con `ts` del mittente, e
  rimanda (cifrato) `{t:'receipt', ref:id, kind:'delivered'}`. Il mittente, decifrando la
  ricevuta, emette `onMessageState(id, 'delivered')` → 2 spunte grigie.
- **Lettura:** all'apertura della conversazione (o su messaggio in arrivo mentre è aperta) il
  destinatario chiama `markRead`, che invia `{t:'receipt', ref:id, kind:'read'}` per ogni
  messaggio in arrivo non ancora segnalato come letto. Il mittente → `onMessageState(id,'read')`
  → 2 spunte verdi.

### Regole

- **Anti-regressione:** ordine stati `sending < sent < delivered < read`. Una ricevuta in
  ritardo non declassa la spunta (es. un `delivered` dopo un `read` viene ignorato).
- **Niente ricevute per le ricevute:** si risponde con una `delivered` solo ai `{t:'msg}`, mai
  a un `{t:'receipt'}` (evita loop).
- **Dedup per `id` del mittente:** il destinatario usa l'`id` del payload (non ne genera uno
  nuovo), così il replay del relay e l'aggiornamento stato colpiscono lo stesso messaggio.
- **Lettura sempre attiva (MVP):** nessun interruttore privacy per ora (annotato come futuro).

### UI

Le spunte esistono già (`MessageBubble`): orologio/✓/✓✓. Cambiano solo i colori:
`sent`/`delivered` = **grigie**, `read` = **verdi** (`--accent`). L'anti-regressione vive
nell'hook `useStyxChat` (patch stato solo in avanti).

## File toccati

- `styx-js/src/chat/styx-chat.js` — payload tipizzato in `sendText`; in `_processApp` distinguere
  `msg` vs `receipt`, inviare la `delivered`, applicare le ricevute via `onMessageState`;
  `markRead` invia le `read`. Coda out-of-order invariata.
- `styx-js/apps/chat/src/hooks/useStyxChat.js` — `patchMessageState` avanza solo in avanti.
- `styx-js/apps/chat/src/components/MessageBubble.jsx` + `styles/app.css` — colori spunte.

## Test

- Unit (real MLS, in-memory transport): A invia → B auto-consegna → stato A `delivered`; B
  `markRead` → stato A `read`. Verifica ordine e no-regressione (un `delivered` tardivo non
  declassa `read`).
- Orario: il destinatario mostra il `ts` del mittente, non l'ora di ricezione.
- Privacy: sul filo il payload (msg e receipt) è un blob opaco (già garantito da MLS; verificato
  che il transport non veda mai il tipo).
