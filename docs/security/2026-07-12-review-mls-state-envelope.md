# Review di sicurezza — MLS state envelope (Fase D)

Data: 2026-07-12 · Branch: `feature/mls-state-envelope` (base `main@6ab94f6`)
Ambito: envelope v1, migrazione legacy, integrazione `StyxChat.init`, fixture, test.
Metodo: review indipendente del diff completo (reviewer dedicato, worktree isolato,
esecuzione reale delle suite), verifica empirica dei percorsi di ripresa, quindi fix
dei rilievi e ri-verifica (646/646 test verdi, build PWA ok).

## Verifiche richieste dal piano di fase

| Proprietà | Esito | Evidenza |
|---|---|---|
| Assenza di perdita silenziosa | ✅ | `init()` fail-closed: envelope corrotto/incompatibile/futuro o `mls:idpk` assente → `MlsStateError`, mai engine nuovo; storage confrontato byte-per-byte nei test (`styx-chat-envelope.test.js`) |
| Migrazione idempotente | ✅ | seconda esecuzione no-op con storage identico (`mls-state-migration.test.js`); ripresa post-crash completata da `init` (riga 3 della matrice, test `env-resume`) |
| Compatibilità esplicita | ✅ | casi A/C/D con codici dedicati e `details` (revisione salvata/corrente, versioni, `actions`); caso B = registro migratori vuoto in v1, per costruzione |
| Fixture non sensibile | ✅ | identità sintetiche `11…`/`22…` generate dallo script, nessun blob da browser/conversazioni reali, README di provenienza e rigenerazione |
| Nessuna regressione factory reset | ✅ | `wipe()` → `backend.clear()` rimuove envelope, backup e marker anche a migrazione interrotta (test dedicati lib + integrazione) |
| Nessuna modifica del protocollo | ✅ | diff verificato: nessun cambiamento a wire format, transport Nostr, vendor/, pin, `.wasm`, ciphersuite, `Cargo.lock`, toolchain, `@noble/*`, Dart/Flutter |
| Errori fail-closed | ✅ | parser rigoroso (magic, allowlist campi con `Object.hasOwn`, tipi, hex, size-gate pre-decodifica, digest); nessun percorso d'errore scrive/cancella |
| Nessun materiale MLS nei log | ✅ | asserito nei test per ogni codice (`expectCode`/`expectCodeAsync`: messaggio e `details` mai contengono il payload) |
| Test di corruzione | ✅ | bit-flip, troncamento, digest errato, base64 rotto, schema alieno, garbage digest-valido dentro il runtime reale: sempre `Error` pulito, mai `WebAssembly.RuntimeError` |
| Comportamento multi-tab | ✅ | precondizione Web Lock documentata e testata con `acquireWriterLock` reale (writer unico, seconda tab esclusa, nuova tab dopo release → no-op); rilascio del lock su init fallito fixato |

## Rilievi della review indipendente e risoluzione

- **Importante I1 — risolto (`26878f0`).** Il resume path della migrazione (envelope +
  marker residui, crash tra i passi 9 e 12) non era raggiungibile da `init`: il backup —
  copia **in chiaro** dello stato pre-migrazione, con segreti di ratchet che la forward
  secrecy avrebbe ritirato — sarebbe sopravvissuto indefinitamente. Ora `init` invoca la
  migrazione anche quando trova marker residui accanto a un envelope; test di
  integrazione aggiunto.
- **Importante I2 — risolto (`26878f0`).** `useStyxChat.unlock` non rilasciava il Web
  Lock su `init` fallito: al retry la stessa tab si vedeva negare il lock (non
  rientrante) e mostrava una schermata "tab secondaria" fuorviante — proprio nel punto
  in cui i nuovi errori strutturati raggiungono l'utente. Ora il lock è rilasciato nel
  catch.
- **Minori risolti:** `mls:idpk` non decodificabile → `MLS_STATE_INVALID` strutturato;
  `Object.hasOwn` al posto di `in` (hardening prototype-chain); policy §5.1 esplicita
  che il backup è artefatto di recovery *manuale* (mai riletto automaticamente).

## Residui accettati (registrati, non bloccanti)

1. **`causeMessage`** in `MIGRATION_FAILED`/`RESTORE_FAILED` inoltra il messaggio del
   runtime WASM. Il boundary indurito del crate restituisce errori puliti (verificato
   dai test "no trap"), quindi il canale non trasporta materiale MLS; resta l'unico
   campo non allowlistato dei `details`. Riesaminare quando il vault introdurrà la
   cifratura degli errori di superficie.
2. **`bytesToBase64` spread-based** (`src/utils.js`, pre-esistente, non toccato) va in
   RangeError ben sotto il cap di 16 MiB dell'envelope: il limite reale di `_persistMls`
   è l'helper, non il parser. Da sistemare con il passaggio a IndexedDB/vault (Blocco
   3), dove la codifica base64 sparisce comunque.
3. **La UI di sblocco mostra `err.message` grezzo**: contiene il codice stabile ma non
   presenta le `actions` di `MLS_STATE_OPENMLS_INCOMPATIBLE` in forma guidata. Follow-up
   UI, non di sicurezza: nessun dato sensibile nei messaggi (verificato dai test).
4. I residui già noti e invariati: payload in chiaro at-rest (H1, Blocco 3), dump
   integrale del provider con eventuali gruppi orfani (documentato in `mls-engine.js`).

## Esito

```text
GO
```

La fase envelope soddisfa i criteri di completamento della spec: il formato è
auto-descrittivo e fail-closed, la migrazione è protetta/riprendibile/idempotente, la
fixture è reale e non sensibile, i vincoli di non-modifica sono rispettati. GO anche
come prerequisito per gli spike successivi (Argon2id, IndexedDB, Crypto Worker), che
restano **non iniziati** e subordinati a nuova autorizzazione esplicita.
