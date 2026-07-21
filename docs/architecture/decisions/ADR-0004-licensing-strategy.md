# ADR-0004 — Strategia di licenza

- **Stato:** **ACCETTATA E APPLICATA** (2026-07-12).
- **Decisione umana:** gate GitHub **#40** — GO esplicito del titolare del copyright
  (`@maverde73`, Maurizio Verde) il 2026-07-12.
- **Implementazione:** Issue GitHub **#41** (Fase A: inventario read-only; Fase B:
  applicazione), tramite Draft PR dedicata. Mappa esatta: `LICENSING.md` + `REUSE.toml`
  (REUSE 3.3).
- **Contesto normativo:** piano operativo Styx Secure §8 (ADR-0004), §9, §15.

## Decisione

1. **Materiale originale Styx** (codice prodotto, applicazioni, servizi, test, script,
   configurazione, documentazione, tooling di build/verifica): **`AGPL-3.0-or-later`**.
   Testo canonico in `LICENSE` (byte-identico a `LICENSES/AGPL-3.0-or-later.txt`).
2. **Eccezioni Apache-2.0 — esattamente sei file**, approvati singolarmente dal titolare
   nella Issue #41 (vettori d'interoperabilità sintetici e congelati):
   - `styx-js/test/fixtures/vault-crypto-v1/hkdf-v1.json`
   - `styx-js/test/fixtures/vault-crypto-v1/manifest-hmac-v1.json`
   - `styx-js/test/fixtures/vault-crypto-v1/record-v1-bytes.json`
   - `styx-js/test/fixtures/vault-crypto-v1/record-v1-json.json`
   - `styx-js/test/fixtures/vault-crypto-v1/wrapper-v1.json`
   - `styx-js/test/fixtures/kdf-kat-vectors.js`

   Nessun glob di directory è approvato; ogni futura eccezione richiede nuovo
   inventario, lista esatta, emendamento umano e review indipendente.
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
