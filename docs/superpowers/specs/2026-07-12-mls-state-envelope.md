# Spec — Envelope versionato dello stato MLS (v1)

Data: 2026-07-12 · Branch: `feature/mls-state-envelope` · Stato: specifica di implementazione

Policy normativa di riferimento: `docs/architecture/mls-state-migration-policy.md`
(riconoscimento formato, casi A–D, sequenza di migrazione, matrice di ripresa, factory
reset, errori). Questa spec fissa il **formato concreto**, l'**API del modulo**, la
**fixture** e i **criteri di completamento**. In caso di conflitto prevale la policy.

## 1. Problema

`mls:state` è oggi una stringa base64 nuda: non dichiara da quale revisione di OpenMLS,
artefatto WASM, ciphersuite o schema proviene. Un futuro cambiamento del formato interno
di `serialize_state` non sarebbe diagnosticabile e il fallimento del restore oggi
(`styx-chat.js`: `savedState && savedIdPk` altrimenti engine nuovo) degrada in perdita
silenziosa della sessione. L'envelope rende lo stato auto-descrittivo e il caricamento
fail-closed.

## 2. Formato dell'envelope v1

Valore JSON memorizzato sotto la chiave `mls:state` (il backend serializza in JSON;
il legacy era una *stringa*, l'envelope è un *oggetto* — v. policy §3):

```json
{
  "format": "styx-mls-state",
  "envelopeVersion": 1,
  "storageSchemaVersion": 1,
  "openMlsRevision": "09e92777dba0528d3d29e2e5e681b7e91637c7be",
  "wasmArtifactSha256": "b56e3ea095c3be3dc9a589e27ad2092bcc6de663cc788db30853e89c02ff386a",
  "ciphersuite": "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519",
  "payloadEncoding": "base64",
  "payloadSha256": "<sha256 esadecimale dei byte GREZZI del payload>",
  "payload": "<base64 dell'output di Provider.serialize_state()>"
}
```

Semantica dei campi:

| Campo | Tipo | Vincolo v1 |
|---|---|---|
| `format` | string | magic, esattamente `"styx-mls-state"` |
| `envelopeVersion` | integer | esattamente `1` (versioni maggiori → caso D) |
| `storageSchemaVersion` | integer | esattamente `1`; versiona il *contenuto* del payload (formato `serialize_state` della revisione pinnata) |
| `openMlsRevision` | string | 40 hex; confrontata con la build corrente (caso C) |
| `wasmArtifactSha256` | string | 64 hex; digest dell'artefatto `.wasm` che ha scritto lo stato |
| `ciphersuite` | string | nome completo; mismatch → `MLS_STATE_CIPHERSUITE_MISMATCH` |
| `payloadEncoding` | string | esattamente `"base64"` in v1 |
| `payloadSha256` | string | 64 hex; SHA-256 dei byte decodificati — rileva **corruzione accidentale**, non è autenticazione (policy §8) |
| `payload` | string | base64, non vuoto, ≤ `MAX_PAYLOAD_BYTES` decodificati |

Nessun timestamp, nessun identificatore utente, nessun metadato ulteriore (privacy by
design: l'envelope non deve raccontare *chi* o *quando*).

`MAX_PAYLOAD_BYTES = 16 MiB` (decodificati): ordini di grandezza sopra qualunque stato
reale a 2 peer (~KB), sotto la soglia in cui un JSON ostile degrada il parser. Costante
esportata, documentata nel modulo.

`mls:idpk` e `mls:groups` restano invariati: sono già JSON tipizzati, non contengono
materiale segreto MLS serializzato e il loro versionamento viaggia con
`storageSchemaVersion` dell'envelope.

## 3. Costanti di build

Nuovo modulo `styx-js/src/crypto/mls/mls-build-info.js`:

```js
export const MLS_BUILD_INFO = Object.freeze({
  openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
  wasmArtifactSha256: 'b56e3ea095c3be3dc9a589e27ad2092bcc6de663cc788db30853e89c02ff386a',
  ciphersuite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
});
export const COMPATIBLE_OPENMLS_REVISIONS = Object.freeze([MLS_BUILD_INFO.openMlsRevision]);
```

Anti-drift: un test Node legge `vendor/openmls-wasm/build.sh` (OPENMLS_COMMIT), calcola
lo sha256 di `vendor/openmls-wasm/openmls_wasm_bg.wasm` e legge la ciphersuite da
`vendor/openmls-wasm/patch/lib.rs`, e li confronta con le costanti. Un bump del pin senza
aggiornare il modulo fa fallire la suite (oltre al gate CI wasm-integrity già esistente).

## 4. API del modulo codec

Nuovo modulo `styx-js/src/storage/mls-state-envelope.js` — puro, senza dipendenze da UI,
password, vault, relay, protocollo wire o stato interno MLS:

```js
export const MLS_STATE_FORMAT = 'styx-mls-state';
export const MLS_ENVELOPE_VERSION = 1;
export const MLS_STORAGE_SCHEMA_VERSION = 1;
export const MAX_PAYLOAD_BYTES = 16 * 1024 * 1024;

export class MlsStateError extends Error { /* code, details (mai payload/chiavi) */ }

export function detectMlsStateFormat(value)        // 'none'|'legacy-base64'|'envelope'|'unknown'
export function encodeMlsStateEnvelope(stateBytes, buildInfo = MLS_BUILD_INFO) // → oggetto envelope
export function parseMlsStateEnvelope(value, { maxPayloadBytes } = {})         // → { envelope, stateBytes }
export function assertMlsStateCompatibility(envelope, buildInfo = MLS_BUILD_INFO,
                                            compatibleRevisions = COMPATIBLE_OPENMLS_REVISIONS)
export async function migrateLegacyMlsState({ backend, restoreProbe, buildInfo })
```

### Parser (fail-closed, policy §3–§4)

`parseMlsStateEnvelope` verifica nell'ordine: tipo oggetto → `format` → tipi di *tutti* i
campi → `envelopeVersion` (caso D) → `storageSchemaVersion` (caso D) → `payloadEncoding`
→ presenza/non-vuotezza payload → validità base64 → limite dimensione → digest. Ogni
violazione lancia `MlsStateError` con il codice della policy §6. Non invoca mai
`restore_state`; non cancella né riscrive nulla; non crea sessioni.

`assertMlsStateCompatibility` applica i casi A/C: revisione non in
`compatibleRevisions` → `MLS_STATE_OPENMLS_INCOMPATIBLE` (details: revisione salvata,
corrente, envelope/schema version, `actions` suggerite); artefatto diverso a parità di
revisione → idem; ciphersuite diversa → `MLS_STATE_CIPHERSUITE_MISMATCH`.

### Migrazione (policy §5, sequenza a 12 passi)

`migrateLegacyMlsState({ backend, restoreProbe })`:

- **precondizione documentata**: il chiamante detiene il Web Lock MLS (`styx-mls:<ns>`,
  acquisito da `useStyxChat` prima di `init()`; non rientrante, quindi mai ri-acquisito
  qui);
- `restoreProbe(stateBytes)` è iniettato (async, lancia se il runtime corrente non sa
  interpretare i byte) — il modulo storage non importa il WASM;
- implementa la sequenza 1–12 e la matrice di ripresa §5.1 (incluso il completamento di
  una migrazione interrotta tra i passi 9 e 12 e l'idempotenza della seconda esecuzione);
- chiavi: `mls:state`, `mls:state:migration:pending`, `mls:state:migration:backup`,
  `mls:state:migration:version` (namespacing del backend già esistente);
- ritorna `{ migrated: boolean, envelope }`; su errore lancia
  `MLS_STATE_MIGRATION_FAILED` con la causa annidata, legacy e backup intatti.

## 5. Integrazione in `StyxChat.init` (minima e testabile)

Sostituzione del blocco attuale (`styx-chat.js:176-187`):

1. leggi `mls:state`, `detectMlsStateFormat`;
2. `legacy-base64` → `migrateLegacyMlsState` (probe = `MlsEngine.restore` con
   `mls:idpk`), poi prosegui come envelope;
3. `envelope` → `parseMlsStateEnvelope` + `assertMlsStateCompatibility` +
   `MlsEngine.restore`; un fallimento del restore diventa `MLS_STATE_RESTORE_FAILED`;
4. `none` → engine nuovo (unico caso lecito);
5. `unknown` → `MLS_STATE_INVALID`;
6. stato presente ma `mls:idpk` assente → `MLS_STATE_INVALID` (oggi degraderebbe in
   engine nuovo: comportamento vietato dalla policy §2).

Ogni errore **propaga** da `init()` (fail-closed): la UI decide come presentarlo; la
libreria non ripara, non cancella, non ricrea.

`_persistMls` scrive l'envelope (`encodeMlsStateEnvelope(serializeState())`) al posto
della stringa base64. `wipe()` resta invariato: `backend.clear()` copre anche le chiavi
di migrazione (test dedicato con migrazione interrotta a metà).

## 6. Fixture reale

Percorso: `styx-js/test/fixtures/mls-state-v1/` con:

- `envelope.json` — envelope v1 il cui payload è un vero `serialize_state()` prodotto
  dall'artefatto WASM corrente;
- `context.json` — ciò che serve al restore: `name` (pubkey di test), `idpk` (base64),
  `groups` (mappa contact→groupId), pubkey del peer, un messaggio di riferimento cifrato
  scambiato prima dello snapshot;
- `README.md` — comando di generazione, revisione OpenMLS, sha256 dell'artefatto,
  ciphersuite, schema, descrizione dei dati sintetici, modalità di rigenerazione;
- `generate.js` — lo script che la produce (eseguibile con `node`).

Generazione: due engine di test (identità generate al momento, mai usate fuori dai test),
pairing `startSession`/`joinSession`, un messaggio applicativo in ciascuna direzione,
poi `serialize_state()` del lato inviter → envelope. **Nessun blob estratto da un browser
o da conversazioni reali; nessun segreto riusato.**

Determinismo: la generazione delle chiavi nel WASM usa CSPRNG di sistema → il blob non è
byte-deterministico. Documentato nel README; la fixture committata è quindi un **artefatto
di regressione fissato**: i test la ripristinano e verificano contenuto logico atteso
(identità, membership, decifratura del messaggio di riferimento), non byte-uguaglianza.

## 7. Test obbligatori

Suites nuove sotto `styx-js/test/storage/` e `test/crypto/`:

**Envelope (`test/storage/mls-state-envelope.test.js`):** round-trip serialize→parse e
parse→serialize; payload vuoto; base64 malformato; digest errato; `format` errato; campo
obbligatorio assente; tipo errato per ogni campo; `envelopeVersion` sconosciuta;
`storageSchemaVersion` sconosciuta; revisione OpenMLS incompatibile; ciphersuite diversa;
digest WASM diverso; payload oltre `MAX_PAYLOAD_BYTES`; `detectMlsStateFormat` su tutti i
formati; coerenza costanti ↔ vendor (anti-drift §3).

**Restore (`test/crypto/mls-state-restore.test.js`):** restore della fixture (identità,
gruppo, `peerIdentity`, decifratura del messaggio di riferimento); restore ripetuto;
corruzione di un byte del payload (digest fallisce → `MLS_STATE_CORRUPTED`); payload
troncato; fixture con schema alterato → `MLS_STATE_SCHEMA_UNSUPPORTED`; nessun trap WASM
(`WebAssembly.RuntimeError`) in nessun caso negativo; nessuna perdita silenziosa (l'errore
propaga, lo storage resta intatto).

**Migrazione (`test/storage/mls-state-migration.test.js`):** migrazione riuscita (legacy
reale → envelope, backup rimosso, marker version scritto); interruzione prima della
scrittura (probe che fallisce → legacy intatto, backup conservato, `MLS_STATE_MIGRATION_FAILED`);
interruzione dopo la scrittura (envelope presente + marker residui → completamento);
restore fallito; quota esaurita simulata (backend il cui `set` lancia); retry dopo errore;
seconda esecuzione idempotente; due tab sotto Web Lock (la seconda non è writer → non
migra; con `acquireWriterLock` reale su un lock manager finto); factory reset dopo
migrazione parziale (`clear()` non lascia residui).

**Integrazione (`test/chat/styx-chat-envelope.test.js`):** `init()` su storage legacy →
migra e ripristina la stessa sessione; `init()` su envelope corrotto → lancia, non crea
engine nuovo, storage intatto; `init()` su envelope di revisione diversa → 
`MLS_STATE_OPENMLS_INCOMPATIBLE`; persistenza post-init scrive envelope.

**Regressioni:** i 601 test esistenti restano verdi; gate anti-mock, WASM integrity e
CodeQL verdi in PR; nessuna modifica allo stack Dart.

## 8. Cosa NON cambia (vincoli, piano §12)

Pin OpenMLS, artefatto WASM e suo digest, ciphersuite, `Cargo.lock`, toolchain Rust,
protocollo Nostr, formato dei messaggi sul wire, dipendenze `@noble/*`, IndexedDB,
Argon2id, Root Storage Key, vault, Flutter, stack Dart. Nessuno spike viene iniziato.

## 9. Criteri di completamento

1. Codec + migrazione implementati nei moduli dedicati (nessuna logica envelope nei
   componenti React); integrazione in `styx-chat.js` limitata a init/_persistMls.
2. Tutti i test del §7 verdi; suite completa `npm test` verde (601 preesistenti + nuovi);
   soglie di coverage jest invariate e rispettate.
3. Fixture committata con README di provenienza; rigenerabile con `generate.js`.
4. Nessun percorso che porti da "errore di restore" a "engine nuovo" o a cancellazione.
5. Nessun materiale MLS (payload, chiavi, stato) in messaggi d'errore o log.
6. Review `docs/security/2026-07-12-review-mls-state-envelope.md` con esito GO/NO-GO.
7. PR `feature/mls-state-envelope → main` con tutti i required check verdi.
