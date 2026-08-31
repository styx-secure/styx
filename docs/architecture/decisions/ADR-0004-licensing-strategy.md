# ADR-0004 — Strategia di licenza

- **Stato:** **ACCETTATA E APPLICATA** (2026-07-12).
- **Decisione umana:** gate GitHub **#40** — GO esplicito del titolare del copyright
  (`@maverde73`, Maurizio Verde) il 2026-07-12.
- **Implementazione:** Issue GitHub **#41** (sei vettori esistenti) e successivi
  emendamenti **#253** (sei path C0.3 interamente sintetici) e **#291** (sei
  path futuri SS-0 interamente sintetici), tramite Draft PR dedicate. Mappa
  esatta: `LICENSING.md` + `REUSE.toml` (REUSE 3.3).
- **Contesto normativo:** piano operativo Styx Secure §8 (ADR-0004), §9, §15.

## Decisione

1. **Materiale originale Styx** (codice prodotto, applicazioni, servizi, test, script,
   configurazione, documentazione, tooling di build/verifica): **`AGPL-3.0-or-later`**.
   Testo canonico in `LICENSE` (byte-identico a `LICENSES/AGPL-3.0-or-later.txt`).
2. **Eccezioni Apache-2.0 — esattamente diciotto path**, approvati singolarmente dal
   titolare: sei file nella Issue #41 (vettori d'interoperabilità sintetici e
   congelati):
   - `styx-js/test/fixtures/vault-crypto-v1/hkdf-v1.json`
   - `styx-js/test/fixtures/vault-crypto-v1/manifest-hmac-v1.json`
   - `styx-js/test/fixtures/vault-crypto-v1/record-v1-bytes.json`
   - `styx-js/test/fixtures/vault-crypto-v1/record-v1-json.json`
   - `styx-js/test/fixtures/vault-crypto-v1/wrapper-v1.json`
   - `styx-js/test/fixtures/kdf-kat-vectors.js`

   e sei path futuri nella Issue #253, pre-registrati mentre assenti e riservati
   esclusivamente a dati C0.3 interamente sintetici generati da Styx:
   - `conformance/application-protocol/c03/manifest.json`
   - `conformance/application-protocol/c03/valid-transcript-vectors.json`
   - `conformance/application-protocol/c03/invalid-transcript-vectors.json`
   - `conformance/application-protocol/c03/state-machine-scenarios.json`
   - `conformance/application-protocol/c03/adversarial-mutations.json`
   - `conformance/application-protocol/c03/expected-traces.json`

   e sei path approvati nella Issue #291, pre-registrati mentre assenti e
   popolati dalla Issue #293 esclusivamente con dati SS-0 interamente sintetici
   generati da Styx:
   - `conformance/secure-session/ss0/manifest.json`
   - `conformance/secure-session/ss0/valid-session-vectors.json`
   - `conformance/secure-session/ss0/invalid-session-vectors.json`
   - `conformance/secure-session/ss0/state-machine-scenarios.json`
   - `conformance/secure-session/ss0/adversarial-mutations.json`
   - `conformance/secure-session/ss0/expected-traces.json`

   Nessun glob di directory è approvato; ogni futura eccezione richiede nuovo
   inventario, lista esatta, emendamento umano e review indipendente. La licenza
   dei sei path C0.3 si applica solo quando ciascun file esiste come dato
   interamente sintetico Styx; non sono autorizzati byte di terzi e questo
   emendamento non crea il corpus né autorizza C0.3.
3. **Materiale di terzi e vendorizzato:** mantiene **integralmente** le licenze
   originali e le attribuzioni. Classificazione path-per-path del vendor OpenMLS:
   - `patch/lib.rs`: **derivato MIT** (Copyright OpenMLS Authors + modifiche
     Maurizio Verde) — né puro upstream né puro codice Styx;
   - artefatti/metadata generati (`openmls_wasm.*`, `package.json`, `Cargo.lock`):
     classificazione MIT upstream/derivata;
   - script e documentazione Styx nella stessa directory (`build.sh`, `verify.sh`,
     `roundtrip.mjs`, `README.md`, `PROVENANCE.md`): AGPL.
   Attribuzioni complete in `THIRD_PARTY_NOTICES.md`.
4. **`styx-js/vendor/styx-kdf-wasm`** è software originale Styx: il manifest passa da
   `MIT OR Apache-2.0` ad **`AGPL-3.0-or-later`**; `deny.toml` esclude dal check licenze
   il solo crate radice non pubblicato (`private = { ignore = true }`) senza indebolire
   l'allowlist delle dipendenze. Artefatto, binding e digest invariati byte-per-byte
   (riverificato con la doppia build riproducibile).
5. **Marchi:** "Styx" e "Styx Secure", loghi, build e servizi ufficiali restano fuori
   dalle licenze software → `TRADEMARKS.md`.
6. **Contributi esterni:** restano **sospesi**; i termini per i contributori (eventuale
   CLA) sono un **task futuro separato** con gate umano dedicato. Nessun CLA, DCO o
   copyright assignment è introdotto oggi.
7. **Dual licensing commerciale:** possibile in futuro come concessione **aggiuntiva e
   separata** del titolare; non rimuove né indebolisce l'edizione open-source pubblica.
   Nessuna licenza commerciale è inclusa nel repository.

## Titolarità (dichiarata dal titolare, 2026-07-11)

Il titolare dichiara di essere, per quanto a sua conoscenza, **unico autore e titolare
del copyright del codice originale** di Styx nel repository (prima attività: 2026-02-23,
verificata dalla history Git). Restano esclusi e mantengono le rispettive licenze:

- **OpenMLS** e ogni materiale vendorizzato o derivato (MIT — header e attribuzioni
  **non vanno rimossi**);
- codice di terzi, incluse le crate compilate staticamente negli artefatti WASM
  committati;
- librerie e asset soggetti a licenze originali.

## Conseguenze

- Il repository non è più "public-source experimental": è un progetto open-source
  licenziato in modo esplicito e machine-readable (`reuse lint` verde su ogni file
  tracciato).
- La disciplina è a path esatti: ogni nuovo vendor, artefatto generato o eccezione
  richiede aggiornamento di `REUSE.toml`/`LICENSING.md` sotto lo stesso change control
  (Issue + gate umani).
- I contributi esterni non si accettano finché il gate sui termini dei contributori non
  è GO.
- Questo processo di repository non sostituisce una consulenza legale professionale.

## Storia

- **2026-07-11 — PROPOSTA (non applicata):** strategia tracciata, nessun file di
  licenza applicato, contributi sospesi, repo pubblicato come "public-source
  experimental" con notice temporaneo nel README.
- **2026-07-12 — Gate #40:** GO del titolare sul modello AGPL/Apache/terze parti.
- **2026-07-12 — Issue #41 Fase A:** inventario completo read-only (base
  `0a2c2c0ff2114cb6da078cf925b48e405c0ba305`), registrato in
  `docs/legal/2026-07-12-licensing-inventory.md`.
- **2026-07-12 — Issue #41 Fase B:** applicazione (questa revisione), con review
  indipendente in `docs/legal/2026-07-12-review-open-source-licensing.md`.
- **2026-08-27 — Issue #253:** emendamento del titolare per sei path futuri C0.3
  interamente sintetici, pre-registrati mentre assenti; nessun byte di corpus,
  materiale di terzi o autorizzazione C0.3 introdotti.
- **2026-08-31 — Issue #291:** emendamento del titolare per sei path futuri SS-0
  interamente sintetici, pre-registrati mentre assenti; nessun byte di corpus,
  materiale di terzi o autorizzazione adapter/prodotto introdotti.
- **2026-09-01 — Issue #293:** popolazione dei sei path SS-0 con soli dati
  sintetici Styx, manifest canonico, replay indipendente e mutazioni chiuse;
  nessun byte upstream o autorizzazione adapter/prodotto introdotti.
