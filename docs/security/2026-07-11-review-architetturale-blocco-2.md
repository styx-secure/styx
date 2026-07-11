# Review architetturale — Blocco 2 (Riduzione immediata del rischio)

**Data:** 2026-07-11 · **Branch:** `review/block-2` (da `feature/pwa-push-bridge`) · **Gate:** GO/NO-GO per l'avvio del Blocco 3.

**Metodo:** due verificatori indipendenti hanno controllato in modo avversariale i sette item del Blocco 2 contro il codice reale (file:riga), più suite completa e build. I finding sono stati verificati di persona e i bloccanti **chiusi in questa stessa sessione** (commit `a7686ce`, `421844e` sul repo sito, e la riconciliazione documentale). Questo documento riporta esito, finding e verdetto.

**Perimetro:** `styx-js/apps/chat/` (mock, stub, factory reset, Web Lock, CSP, copy), il gate CI, e — per la sola parte copy/trasparenza — i README del repo e il sito `styx-secure/styx-website`.

**Suite:** `npm test -- --testTimeout=20000` → **597/597, 58 suite** verdi. Nessuna regressione.

---

## 1. Verifica dei sette item

### Mock e build — ✅ VERIFICATO
- Il mock è **assente dal bundle di produzione**: il branch demo è dietro `import.meta.env && import.meta.env.VITE_DEMO === '1'` (`styx-adapter.js:25`), staticamente ripiegato a `false` da Vite → tree-shaking del chunk mock. `grep` su `dist/` pulito; nessun chunk `styx-lib-mock` emesso.
- Il **gate CI** (`.github/workflows/styx-js-web.yml`) builda `apps/chat` e fallisce su marcatori distintivi (`MockStyxChat|styx-lib-mock|seedDemo|Nodo Berlino`). Efficace; nota minore: robusto solo sui quattro marcatori attuali.
- **Fallimento del modulo crittografico = blocco esplicito**: `getStyxChat()` lancia `FatalCryptoError`, catturato in `useStyxChat.unlock`, che rende una schermata bloccante (`App.jsx:85-94`). **Nessun percorso di fallback silenzioso residuo.**

### Stub — ✅ VERIFICATO (dopo fix)
- Pairing remoto non raggiungibile in produzione: tab e `RemoteTab` dietro `REMOTE_PAIRING` (demo-only, `PairingModal.jsx:8`); i metodi che lanciano (`styx-chat.js:398-399`) non hanno più chiamanti raggiungibili nel bundle prod.
- WebRTC: nessun riferimento UI.
- **Presenza — MISS trovato e CORRETTO.** `ContactRow` era già a posto, ma `ConversationView.jsx` leggeva ancora `contact.online` mostrando un "offline" **perpetuo e immeritato** (la lib non ha protocollo di presenza; `setOnline` non è mai chiamato). Rimossa la riga online/offline; l'indicatore "sta scrivendo…" (reale) resta. Nessun read residuo di `online` nella UI.
- Nessun pulsante raggiunge un `not implemented` in produzione.

### Factory reset — ✅ VERIFICATO (dopo fix)
Ogni superficie sensibile è coperta: `localStorage` prefissato `styxchat:` (via `backend.clear()`), Cache Storage, stato MLS (`mls:*`), messaggi, roster, sottoscrizione push (con **unregister firmato** al bridge + `unsubscribe`), service worker, `styx-ledger` IndexedDB (difensivo), chiavi legacy. **Fix:** aggiunta `styx-install-dismissed` alle chiavi rimosse (era l'unica app-key sopravvissuta; non sensibile). Nota: non esiste una outbox della chat oggi; se aggiunta sotto il prefisso, `clear()` la coprirebbe.

### Web Lock (un solo writer MLS) — ✅ VERIFICATO, con un caveat onesto
- Lock esclusivo per-namespace (`writer-lock.js`), acquisito **prima** di costruire l'engine: una seconda scheda non diventa writer (`secondaryTab` → schermata bloccante) e non scrive nulla.
- Nessun deadlock: il lock è rilasciato al logout e all'unmount, e liberato automaticamente alla chiusura della scheda.
- Reset gira sul leader che detiene il lock.
- **Caveat (item 10):** la seconda scheda **non si auto-promuove** alla chiusura del leader — il recovery richiede un **reload manuale** (bottone "Ricarica"). È coerente con lo scope minimo scelto e con il copy della UI, ma va letto come recovery *manuale*, non automatico. Il fallback a lease IndexedDB resta rimandato (scelta di scope).

### CSP — ✅ VERIFICATO
- `script-src 'self' 'wasm-unsafe-eval'` — **nessun `unsafe-inline` sugli script, nessun `unsafe-eval`**. `'wasm-unsafe-eval'` è necessario (il WASM usa `instantiateStreaming`) e distinto da `unsafe-eval` (non abilita `eval()`).
- `default-src 'none'`; `connect-src` limitato a self + i due relay di default (+ `STYX_CONNECT_SRC` per self-hoster); tutte le altre direttive strette. `dist/index.html` non ha script inline.
- Verificato in Chromium: WASM istanzia, app monta, zero violazioni CSP.
- **`style-src 'unsafe-inline'` — eccezione documentata, NON bloccante.** Serve agli attributi `style=` di React (~62 occorrenze); rischio = iniezione di stile, non esecuzione di codice. Il documento di fattibilità è stato **riconciliato**: il criterio ora recita "nessun `unsafe-inline` sugli script" con l'eccezione style-src esplicitata (prima diceva, erroneamente, "nessun unsafe-inline" in assoluto).
- Trusted Types: assente ma **documentato** come lavoro futuro.

### Copy — ✅ VERIFICATO (dopo fix)
- Chat UI, manifest, package.json: nessun claim vietato (verificato con grep; anche il mock, demo-only, è pulito).
- **Fix:** il README root conteneva *"No servers … unbreakable chain"* (claim vietati "no server" + overclaim) e il README chat descriveva il fallback al mock ormai rimosso. Entrambi riscritti con dicitura onesta e ora portano il **warning "⚠️ EXPERIMENTAL SOFTWARE"** richiesto dal piano §9.
- Sito `styx-website/index.html`: copy conforme ("metadata-minimizing", "end-to-end encrypted", box di stato sperimentale). **Fix:** `security.txt` era non conforme a RFC 9116 (mancava `Expires`) — aggiunti `Expires` (2027-07-11), `Canonical`, `Policy`, `it` tra le lingue (commit `421844e` nel repo sito, **non ancora pushato**).

---

## 2. Finding

### Bloccanti — tutti CHIUSI in questa sessione
| ID | Finding | Esito |
|---|---|---|
| B2-1 | `ConversationView` mostra un "offline" perpetuo immeritato (presenza non rimossa del tutto) | **corretto** (`a7686ce`) |
| B2-2 | Warning EXPERIMENTAL assente dai README; README root con claim "no server/unbreakable" | **corretto** (`a7686ce`) |
| B2-3 | `security.txt` non conforme (manca `Expires` RFC-9116) | **corretto** (`421844e`, repo sito) |
| B2-4 | Documento di fattibilità: "nessun unsafe-inline" in contraddizione col piano | **riconciliato** |

### Differibili / debiti tracciati (non bloccanti)
- **D-1** `style-src 'unsafe-inline'`: rimuoverlo richiede di spostare gli stili inline di React in classi. Follow-up di polish, non di sicurezza (script-src resta stretto).
- **D-2** Web Lock: recovery solo via reload manuale; il fallback a lease IndexedDB per browser senza Web Locks è rimandato (scope minimo).
- **D-3** Gate CI mock: robusto sui quattro marcatori attuali; un mock rinominato del tutto sfuggirebbe. Irrobustire con un controllo più semantico è un miglioramento futuro.
- **D-4** `security.txt` `Policy:` punta a `/security.html` non ancora pubblicata (pagina sito futura); `Expires` da rinnovare prima della scadenza.
- **D-5** Residui at-rest già noti dal Blocco 1 (credenziale di un join rifiutato in `mls:state`; DoS di griefing sul QR fotografato) — tracciati per Blocco 5.0/N4.

### Regressioni
Nessuna. 597/597 test verdi prima e dopo i fix; build di produzione verde.

---

## 3. Verdetto

## **GO** per l'avvio del Blocco 3.

**Motivazione.** I sette item del Blocco 2 sono verificati da revisori indipendenti sul codice reale. I quattro finding bloccanti — tutti sulla dimensione presenza/trasparenza, nessuno una regressione di sicurezza del percorso crypto/vault — sono stati **chiusi in questa sessione**. I debiti residui (D-1…D-5) sono differibili e documentati, e nessuno è un prerequisito del vault. La suite è verde, la CSP è dimostrata funzionante in browser, il factory reset copre ogni superficie sensibile, e un solo writer MLS è garantito.

**Condizioni operative prima della migrazione pubblica** (non bloccano il Blocco 3, ma vanno chiuse in Fase B/C del piano operativo):
1. push del fix `security.txt` sul repo `styx-secure/styx-website`;
2. bonifica del finding S-1 (JWT_SECRET demo) prima del trasferimento del repo storico;
3. i prerequisiti del Blocco 3 restano invariati: **envelope MLS versionato + migration policy + design del vault approvati** prima di scrivere il vault (piano operativo §11, §13; debito R1 della review Blocco 1).

**Prossimo passo previsto:** Fase D del piano operativo (envelope MLS, migration policy, spike Argon2id/IndexedDB/Crypto Worker), poi design del Blocco 3. Il Blocco 3 **non** inizia finché quei design non sono approvati.
