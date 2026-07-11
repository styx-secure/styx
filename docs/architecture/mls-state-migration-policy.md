# MLS state migration policy

Data: 2026-07-12 · Ambito: `styx-js` (chat MLS) · Stato: **normativo per la Fase D (envelope)**

Questo documento definisce come lo stato MLS persistito viene versionato, riconosciuto,
migrato e — quando incompatibile — **rifiutato senza perdita di dati**. Vale per il
backend di persistenza attuale (`LocalStorageBackend`, chiavi `styxchat:*`) e resta
valido quando il backend cambierà (vault del Blocco 3): la policy è sul *formato*, non
sul supporto fisico.

## 1. Contesto: cosa viene persistito oggi

| Chiave (namespaced dal backend) | Contenuto | Formato attuale (legacy) |
|---|---|---|
| `mls:state` | dump completo del Provider OpenMLS (`serialize_state()`) | **stringa** base64, nessun metadato |
| `mls:idpk` | chiave pubblica di firma MLS (per `Identity.load`) | stringa base64 |
| `mls:groups` | mappa `contactPubkey → groupId` | oggetto JSON |

Il backend (`LocalStorageBackend`) serializza ogni valore in JSON: un valore legacy di
`mls:state` è quindi una *stringa JSON* in `localStorage`; l'envelope è un *oggetto JSON*.
Questa differenza di tipo è la base del riconoscimento del formato (§3).

Il problema che l'envelope risolve: il blob legacy non dichiara **da quale revisione di
OpenMLS, quale artefatto WASM e quale ciphersuite** proviene. Un bump futuro del crate che
cambiasse il formato interno di `serialize_state` produrrebbe un restore fallito o —
peggio — uno stato interpretato male, senza alcun modo di diagnosticarlo. L'audit del pin
(`vendor/openmls-wasm/PROVENANCE.md`) documenta che il formato di storage è *già* cambiato
una volta upstream (PR #2034 vs feature `0-8-1-storage-format`): il rischio è reale.

## 2. Invariante fondamentale: nessuna perdita silenziosa

Il comportamento vietato, in ogni caso e in ogni versione futura:

```text
errore di restore → sessione ignorata → engine ricreato da zero → contatto "nuovo"
```

Conseguenze operative, non negoziabili:

- un errore di parse/validazione/restore **interrompe l'init** con un errore strutturato
  (§6); non si crea mai automaticamente un nuovo engine quando esiste uno stato salvato;
- **nessun percorso d'errore cancella o sovrascrive** il dato salvato;
- un nuovo pairing non viene mai forzato silenziosamente: è sempre un'azione esplicita
  dell'utente (già oggi: guard A3 in `styx-chat.js`);
- l'unica cancellazione legittima dello stato è il **factory reset** esplicito (§7).

## 3. Riconoscimento del formato

`detectMlsStateFormat(value)` classifica il valore letto da `mls:state`:

| Esito | Condizione | Azione |
|---|---|---|
| `none` | `null`/`undefined` (chiave assente) | primo avvio: engine nuovo (unico caso in cui è lecito) |
| `legacy-base64` | stringa non vuota, alfabeto base64 valido | migrazione (§5) |
| `envelope` | oggetto con `format === "styx-mls-state"` | parse rigoroso + policy di compatibilità (§4) |
| `unknown` | qualsiasi altra cosa (numero, array, stringa non-base64, oggetto con `format` diverso…) | **fail-closed**: `MLS_STATE_INVALID`, dato intatto |

Il riconoscimento del legacy è inequivocabile per costruzione: il formato legacy è una
stringa, ogni versione dell'envelope (presente e futura) è un oggetto con il magic
`format: "styx-mls-state"`. Non esiste un terzo formato storico.

## 4. Policy di compatibilità al load

L'envelope dichiara: `envelopeVersion`, `storageSchemaVersion`, `openMlsRevision`,
`wasmArtifactSha256`, `ciphersuite` (formato completo nella spec
`docs/superpowers/specs/2026-07-12-mls-state-envelope.md`). Il runtime dichiara i propri
valori in `src/crypto/mls/mls-build-info.js`, tenuto coerente con
`vendor/openmls-wasm/{build.sh,PROVENANCE.md}` da un test dedicato.

### Caso A — envelope, schema e revisione conosciuti → load

`envelopeVersion` e `storageSchemaVersion` supportati, `openMlsRevision` uguale alla
revisione corrente (o presente nella tabella delle revisioni validate, §4.1),
`ciphersuite` uguale, digest del payload corretto → `restore_state` viene invocato.
Un fallimento del restore a questo punto è `MLS_STATE_RESTORE_FAILED` (dato intatto).

### Caso B — envelope di versione precedente con migratore registrato → migrazione

Quando esisterà una `envelopeVersion` 2, il codec manterrà un registro di migratori
`v(n) → v(n+1)`. La migrazione segue la stessa sequenza protetta del §5 (backup →
trasforma → verifica → scrivi → pulisci). Oggi il registro è vuoto: la v1 è la prima.

### Caso C — envelope conosciuto, revisione OpenMLS diversa e non validata → rifiuto esplicito

**Nessun restore ottimistico.** Errore `MLS_STATE_OPENMLS_INCOMPATIBLE` che riporta:
revisione salvata, revisione corrente, `envelopeVersion`, `storageSchemaVersion` e le
azioni possibili (tornare alla build precedente; attendere una migrazione ufficiale;
factory reset esplicito come ultima risorsa). Il dato resta intatto.

Lo stesso trattamento fail-closed si applica a:

- `ciphersuite` diversa → `MLS_STATE_CIPHERSUITE_MISMATCH`;
- `wasmArtifactSha256` diverso a parità di revisione → `MLS_STATE_OPENMLS_INCOMPATIBLE`
  (la build è riproducibile byte-per-byte: un digest diverso significa toolchain o patch
  diversi, cioè un runtime che non è quello che ha scritto lo stato).

#### 4.1 Tabella delle revisioni validate

`COMPATIBLE_OPENMLS_REVISIONS` in `mls-build-info.js` elenca le revisioni il cui formato
`serialize_state` è **verificato** compatibile con il runtime corrente. Oggi contiene solo
la revisione pinnata (`09e92777…`). Una revisione entra in tabella soltanto dopo un test
di restore reale (fixture della vecchia revisione ripristinata dalla nuova), mai per
ottimismo. Nota upstream rilevante: PR #2034 mantiene la compatibilità serde con v0.7.1 di
default — è un indizio, non una prova; senza fixture-test la revisione non entra.

### Caso D — versione futura sconosciuta → rifiuto esplicito

`envelopeVersion` maggiore di quella supportata → `MLS_STATE_VERSION_UNSUPPORTED`;
`storageSchemaVersion` sconosciuto → `MLS_STATE_SCHEMA_UNSUPPORTED`. Tipico rollback
dell'app dopo un upgrade. Il dato **non viene modificato**: la build più recente che l'ha
scritto deve poterlo rileggere.

## 5. Migrazione dal formato legacy

Precondizione: il chiamante detiene il **Web Lock MLS** (`styx-mls:<ns>`, esclusivo, già
acquisito da `useStyxChat` per l'intera vita della sessione prima di `init()`; la seconda
tab non diventa mai writer — `apps/chat/src/lib/writer-lock.js`). La migrazione non
ri-acquisisce il lock (i Web Lock non sono rientranti): lo *eredita* come precondizione
documentata e testata.

Chiavi di lavoro (namespaced dal backend, quindi nel namespace del profilo):

```text
mls:state                      valore principale (legacy → envelope)
mls:state:migration:pending    marker: migrazione in corso
mls:state:migration:backup     copia intatta del valore legacy
mls:state:migration:version    marker: migrazione completata (→ 1)
```

Sequenza (ogni passo verificato prima del successivo):

1. lock detenuto dal chiamante (precondizione);
2. leggere il valore legacy da `mls:state`;
3. scrivere la copia intatta in `…:backup` e il marker `…:pending`;
4. validare che il payload sia base64 decodificabile e non vuoto;
5. costruire l'envelope v1 (metadati dalla build corrente);
6. serializzarlo (il backend serializza in JSON);
7. ri-verificarlo con il parser rigoroso (round-trip);
8. **provare il restore** dal payload dell'envelope (probe con il runtime reale:
   `Provider.restore_state` + `Identity.load`);
9. scrivere il nuovo valore in `mls:state`;
10. rileggere e ri-parsare per verifica;
11. scrivere `…:version = 1` e cancellare `…:pending`;
12. cancellare `…:backup` soltanto al termine.

Se un passo fallisce: il valore legacy resta al suo posto (fino al passo 9 `mls:state`
non viene toccato), il backup resta, nessuno stato parziale viene scritto, la sessione
non viene eliminata, l'errore è `MLS_STATE_MIGRATION_FAILED` (con la causa annidata), e
un nuovo tentativo al prossimo avvio è lecito.

### 5.1 Ripresa dopo interruzione (matrice degli stati)

| `mls:state` | marker presenti | Diagnosi | Azione |
|---|---|---|---|
| legacy | nessuno | migrazione mai tentata | migrazione normale |
| legacy | `pending` (± `backup`) | tentativo precedente fallito prima del passo 9 | ripetere da capo (il legacy è ancora la fonte di verità) |
| envelope | `pending`/`backup` residui | interruzione tra i passi 9 e 12 | completare: verificare l'envelope, scrivere `version`, cancellare i residui |
| envelope | nessuno | migrazione completata | nulla (idempotenza) |

La seconda esecuzione su uno stato già migrato è un no-op verificabile.

Il percorso di caricamento (`StyxChat.init`) invoca la migrazione **sia** quando lo stato
è legacy **sia** quando esistono marker residui accanto a un envelope: la riga 3 della
matrice deve essere raggiungibile a ogni avvio, perché il backup contiene una copia in
chiaro dello stato pre-migrazione che non deve sopravvivere alla migrazione. Il backup è
un artefatto di recovery *manuale*: nessun percorso di codice lo rilegge automaticamente
per ripristinare — evita che un bug di ripresa possa reintrodurre stato vecchio da solo.

### 5.2 Perché non serve (ancora) più atomicità

`localStorage` è sincrono e single-key-atomico: ogni `setItem` riesce o lancia
(`QuotaExceededError`), non esistono scritture parziali di un singolo valore. Non offre
transazioni multi-chiave: la sequenza sopra è ordinata proprio perché ogni singolo passo
lasci l'insieme delle chiavi in uno stato riconoscibile dalla matrice §5.1. Il Web Lock
esclude la concorrenza tra tab; l'interruzione (crash/chiusura) è gestita dalla ripresa.
IndexedDB e la cifratura del vault sono **fuori scope** (Blocco 3) e non vengono
introdotti qui.

Duplicazione temporanea: durante la migrazione il materiale MLS esiste in due copie
(`mls:state` legacy + `…:backup`). È intenzionale e **temporaneo**: al passo 12 il backup
viene rimosso; dopo una migrazione riuscita non resta alcuna copia duplicata permanente.

## 6. Errori strutturati

Codici stabili (classe `MlsStateError`, proprietà `code` + `details`):

```text
MLS_STATE_INVALID               valore non riconducibile a nessun formato / campo malformato
MLS_STATE_CORRUPTED             digest del payload errato, base64 rotto, payload vuoto/troncato
MLS_STATE_VERSION_UNSUPPORTED   envelopeVersion futura/sconosciuta
MLS_STATE_SCHEMA_UNSUPPORTED    storageSchemaVersion sconosciuta
MLS_STATE_OPENMLS_INCOMPATIBLE  revisione OpenMLS o artefatto WASM non validati
MLS_STATE_CIPHERSUITE_MISMATCH  ciphersuite diversa da quella compilata
MLS_STATE_MIGRATION_FAILED      un passo della sequenza §5 è fallito (causa annidata)
MLS_STATE_RESTORE_FAILED        envelope valido ma restore_state/Identity.load falliti
```

`details` contiene **solo** versioni, revisioni (hex), digest e codici — mai payload,
chiavi, stato serializzato o altro materiale MLS. Vale anche per i log di sviluppo.

## 7. Factory reset

Il factory reset (lib: `StyxChat.wipe()` → `backend.clear()`; app:
`apps/chat/src/lib/factory-reset.js`) deve eliminare **tutte** le chiavi del §5, incluse
quelle di una migrazione interrotta: `clear()` cancella l'intero prefisso del backend,
quindi envelope, backup temporanei e marker cadono insieme. Un test lo verifica con una
migrazione lasciata deliberatamente a metà. Le fixture non sono coinvolte: vivono solo
nel test tree, mai nello storage del browser.

## 8. Limiti noti e rinvii espliciti

- **Il digest del payload rileva corruzione accidentale, non manomissione**: chi può
  scrivere `localStorage` può riscrivere anche il digest. La protezione autenticata
  (cifratura + MAC sotto chiave derivata) arriva con il vault del Blocco 3; l'envelope è
  progettato per esserne *avvolto* senza cambiare formato.
- Il payload resta **in chiaro at-rest** (finding H1 dell'audit): questa fase non lo
  risolve e non pretende di farlo; rende però lo stato *migrabile in sicurezza* quando
  il vault arriverà.
- `serialize_state` scarica l'intera mappa del provider, inclusi gruppi orfani di pairing
  rifiutati (documentato in `mls-engine.js`): l'envelope non cambia questo comportamento.
- Nessun dato personale né identificatore utente nell'envelope: i soli metadati sono
  versioni, revisione, digest e ciphersuite.
