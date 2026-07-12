# Inventario licenze e copyright — Fase A, Issue #41 (2026-07-12)

Record permanente del report di Fase A (inventario read-only) dell'Issue GitHub #41,
eseguito su `main @ 0a2c2c0ff2114cb6da078cf925b48e405c0ba305`. Il contenuto riproduce il
report consegnato al checkpoint umano; le decisioni finali del titolare sono registrate
nell'Issue #41 (sezioni "Approved Apache-2.0 exceptions" e "Human checkpoint decisions")
e prevalgono su ogni proposta qui contenuta. La proposta di mappa Apache del §20 è stata
approvata senza modifiche (gli stessi sei file).

## 1. Base SHA and working-tree status

- HEAD: `0a2c2c0ff2114cb6da078cf925b48e405c0ba305` — coincidente con la base registrata
  nell'Issue #41 e nel gate #40; working tree pulito (`git status --short` vuoto).
- GO umano su #40 presente (titolare `@maverde73`): AGPL-3.0-or-later per il codice
  originale; Apache-2.0 solo per specifiche/vettori identificati nella mappa; licenze
  originali per il materiale di terzi/vendorizzato; marchi esclusi; contributi sospesi.
- File tracciati: 577. Autori nella history: `maverde73` (117 commit) e `dependabot[bot]`
  (3 commit di soli bump manifest, privi di contributo creativo rilevante).

## 2. Active PR/path-overlap check

| PR | Path toccati | Sovrapposizione con la Fase B |
|---|---|---|
| #20 (dependabot npm) | `styx-js/package.json`, `styx-js/package-lock.json` | DIRETTA — gli stessi due file che la Fase B deve modificare |
| #19 (dependabot) | `styx-js/package-lock.json` | Diretta sul lockfile |
| #21, #11, #10 | `styx-js/apps/chat/package.json` + lock | Potenziale, solo se la Fase B avesse aggiunto un campo license (poi escluso dal checkpoint) |
| #5 | `push_bridge/package.json` + lock | Potenziale, come sopra |
| #13 | tutti i `pubspec.yaml` | Teorica: pubspec non supporta un campo licenza |
| #7, #6, #4, #8 | `go.mod`, workflow | Nessuna |
| #39 (vault worker) | `styx-js/src/crypto/**`, test, workflow, docs | Nessuna |

Raccomandazione registrata: chiudere o fondere #19/#20 prima della Fase B (condizione poi
recepita nel contratto; entrambe risultavano CLOSED all'avvio della Fase B).

## 3. Existing license and notice files

- Nessun file `LICENSE`, `COPYING`, `NOTICE`, `AUTHORS`, `THIRD_PARTY_NOTICES` in tutto
  il repository; nessun tag `SPDX-License-Identifier`; nessuna intestazione di copyright
  nel codice (unica occorrenza testuale: ADR-0004).
- Materiale attributivo esistente: `styx-js/vendor/openmls-wasm/{PROVENANCE,README}.md`,
  `styx-js/vendor/styx-kdf-wasm/{PROVENANCE,README}.md`, `deny.toml` (allowlist), ADR-0004,
  sezione "Licensing status" del README.
- Gap sostanziale: il testo MIT di OpenMLS non era presente nel repository benché
  l'artefatto WASM committato contenga porzioni sostanziali di OpenMLS.

## 4. Manifest license inventory

| Path | Nome | Privato/pubblicabile | Licenza | Note |
|---|---|---|---|---|
| `styx-js/package.json` | styx-js 1.0.0 | nessun `private: true` | **MIT** (errato) | lock root replica MIT |
| `styx-js/package-lock.json` (root) | styx-js | — | **MIT** (specchio) | sync consentito |
| `styx-js/apps/chat/package.json` | styx-chat-app | `private: true` | assente | lock in path vietato |
| `push_bridge/package.json` | styx-push-bridge | `private: true` | assente | idem |
| `styx-js/spikes/argon2id/package.json` | argon2id-spike | `private: true` | assente | idem |
| `styx-js/vendor/openmls-wasm/package.json` | openmls-wasm | vendor | MIT, "OpenMLS Authors" | generato da wasm-pack; non toccare (trigger CI) |
| `styx-js/vendor/styx-kdf-wasm/Cargo.toml` | styx-kdf-wasm | `publish = false` | **MIT OR Apache-2.0** | incoerente col default AGPL |
| `styx-js/spikes/argon2id/crate/Cargo.toml` | argon2id-spike | spike | assente | lacuna minore |
| `pubspec.yaml` ×9 | styx_* / themis_survey | tutti `publish_to: none` | campo non supportato | corretto non aggiungerlo |
| `push_bridge_server/go.mod` | module legacy `AlessandroVerde` | — | campo non supportato | nessun `go.sum` tracciato |

## 5. Original Styx material

`packages/**` (7 package Dart), `test_integration/**`, `tool/**`, config root;
`styx-js/src/**`, `styx-js/test/**` (fixture incluse: dati generati da codice Styx),
`styx-js/apps/chat/**` (icone PWA incluse, aggiunte da maverde73 il 2026-07-10),
`styx-js/demo/**`, `styx-js/examples/**`, config JS; `styx-js/spikes/**` (sorgenti);
`push_bridge/**`, `push_bridge_server/**`; `docs/**`, `README.md`, `AGENTS.md`,
`CLAUDE.md`, `.github/**`; nel vendor OpenMLS: `build.sh`, `verify.sh`, `roundtrip.mjs`,
`README.md`, `PROVENANCE.md`; l'intero lato sorgente di `styx-js/vendor/styx-kdf-wasm/`.

## 6. Styx-authored modifications to third-party material

`styx-js/vendor/openmls-wasm/patch/lib.rs`: derivato dell'upstream MIT
`openmls-wasm/src/lib.rs` al commit `09e92777…` — incipit identico riga per riga,
15.399 byte upstream contro 21.220 del patch; `build.sh` lo applica con `cp` sopra il
file upstream. Né codice puramente Styx né upstream inalterato. Trattamento corretto:
MIT con doppio copyright (OpenMLS Authors + Maurizio Verde, modifiche).

## 7. Unmodified third-party material

Nessun sorgente di terzi inalterato è committato (l'upstream è clonato a build-time).
`openmls-wasm/Cargo.lock`: lockfile del workspace upstream (487 crate pinnate, inclusi
rami non linkati: `ring`, `libcrux-*`, `openmls-fuzz`). `openmls-wasm/package.json`:
generato da wasm-pack dai metadati upstream. Terze parti incorporate nei binari:
OpenMLS + catena RustCrypto in `openmls_wasm_bg.wasm`; argon2/blake2 (MIT OR
Apache-2.0), `subtle` (BSD-3-Clause), `generic-array` (MIT), runtime wasm-bindgen in
`styx_kdf_wasm_bg.wasm` e nello spike.

## 8. Generated files and binary artifacts

wasm-bindgen output (`openmls_wasm.js`/`.d.ts`, `styx_kdf_wasm.*`, spike `pkg/*`);
3 binari WASM committati; lockfile npm ×4 e Cargo ×3 (`pubspec.lock` gitignorato);
fixture generate da `generate.js` (mls-state-v1, vault-crypto-v1);
`tool/coverage_baseline.tsv`; icone PWA ×4.

## 9. OpenMLS classification

- Upstream inalterato committato: nessuno. Licenza upstream: MIT, "Copyright (c) 2020
  OpenMLS Authors"; nessun NOTICE esiste upstream al commit pinnato (verificato via API).
- Patch Styx: `patch/lib.rs` (derivato MIT). Generato: `openmls_wasm.js`, `.d.ts` ×2,
  `package.json`. Artefatto: `openmls_wasm_bg.wasm` (aggregato MIT + patch + crate terze).
- Docs/script Styx: `README.md`, `PROVENANCE.md`, `build.sh`, `verify.sh`,
  `roundtrip.mjs`, più `Cargo.lock` vendorizzato come pin.
- Linguaggio impreciso rilevato: il `package.json` generato presenta l'intero pacchetto
  come opera degli "OpenMLS Authors"; il README di vendor diceva "Licenza: MIT" senza
  distinguere le opere Styx nella stessa directory; ADR-0004 estendeva "licenza MIT"
  all'intera directory. Correzione prevista nella mappa REUSE path-per-path.

## 10. styx-kdf-wasm classification

Sorgente interamente Styx (nessun clone esterno); binding `pkg/*` generati; WASM
committato (42.082 byte) con crate permissive linkate; 32 dipendenze da crates.io
checksummate; `deny.toml` allowlist `["MIT","Apache-2.0","BSD-3-Clause","Unicode-3.0"]`.
Effetti di un cambio del solo campo `license`: (1) i byte del WASM non dipendono dal
campo, ma la prova è `verify.sh`; (2) i binding committati sono invariati — il
`pkg/package.json` generato da wasm-pack è gitignorato; (3) nessuno script hash-a il
manifest; (4) vincolo CI: ogni modifica sotto `styx-js/vendor/styx-kdf-wasm/` attiva
`kdf-hermetic` (verify + audit/cargo-deny) — con licenza AGPL sul crate radice,
`cargo deny check licenses` fallirebbe senza un adeguamento minimo di `deny.toml`
(risolto al checkpoint con `private = { ignore = true }`); (5) `PROVENANCE.md` non
hash-a il manifest.

## 11. Current incorrect or ambiguous metadata

1. `styx-js/package.json` → MIT (falso), replicato nel lock; 2. assenza di
`private: true` su styx-js (rischio `npm publish` accidentale); 3. crate KDF
`MIT OR Apache-2.0` su codice originale Styx; 4. spike Cargo.toml senza licenza;
5. README vendor/ADR-0004 con "licenza MIT" estesa all'intera directory;
6. `package.json` OpenMLS generato che attribuisce tutto agli OpenMLS Authors;
7. (fuori scope licenze) `go.mod` con path legacy e `go.sum` assente.

## 12. Required canonical license texts

`LICENSES/AGPL-3.0-or-later.txt` (+ `LICENSE` root byte-identico);
`LICENSES/MIT.txt` (OpenMLS, generic-array, elezione MIT delle dual);
`LICENSES/BSD-3-Clause.txt` (`subtle` in entrambi gli artefatti);
`LICENSES/Apache-2.0.txt` (eccezioni approvate). `Unicode-3.0` non necessario
(`unicode-ident` è solo build-time, non distribuito).

## 13. NOTICE requirements

Nessun materiale Apache-licensed contenuto nel repo porta un NOTICE upstream;
OpenMLS è MIT senza NOTICE; le crate dual sono distribuite sotto il ramo MIT.
Conclusione: root `NOTICE` non richiesto → non crearlo; attribuzioni in
`THIRD_PARTY_NOTICES.md`.

## 14. Proposed THIRD_PARTY_NOTICES.md inventory

OpenMLS (MIT, commit pin, dove contenuto); crate Rust incorporate nei 3 artefatti WASM
(RustCrypto MIT-election, `subtle` BSD-3, `generic-array` MIT, runtime wasm-bindgen);
dichiarazione dell'elezione MIT per le dual; esclusione delle dipendenze solo scaricate.

## 15. Candidate Apache-2.0 paths

INCLUDE: i 5 JSON di `styx-js/test/fixtures/vault-crypto-v1/` (vettori KAT congelati,
sintetici, contratto di compatibilità) e `styx-js/test/fixtures/kdf-kat-vectors.js`
(ancore Argon2id cross-validate su due implementazioni). EXTRACT INTO A FUTURE
DEDICATED SPEC: `docs/superpowers/specs/2026-07-12-mls-state-envelope.md` (formato +
contenuto interno misti). EXCLUDE: vault design, migration policy, `mls-state-v1/**`
(artefatto legato al digest del runtime), `generate.js`, README della fixture,
`docs/API_REFERENCE*`. Nessun glob largo.

## 16. Files that must remain AGPL

Tutto il materiale del §5 (default), inclusi: `styx-js/src/**`, `packages/**`,
`styx-kdf-wasm/src/lib.rs`, script/doc Styx dei vendor, `generate.js` e README delle
fixture, `mls-state-v1/**`, spec/piani/review in `docs/**`, spike, icone PWA.

## 17. Files that must retain upstream licenses

`patch/lib.rs` (MIT derivato); `openmls_wasm.js`, `.d.ts` ×2, `openmls_wasm_bg.wasm`;
`openmls-wasm/package.json` e `Cargo.lock`; il codice di terzi incorporato in
`styx_kdf_wasm_bg.wasm` e `argon2id_spike_bg.wasm`.

## 18. Proposed REUSE mapping

`REUSE.toml` unico alla radice, zero header SPDX nei file: default `**` AGPL (© 2026
Maurizio Verde) dichiarato per primo; poi le sei eccezioni Apache; per ultime (vincenti)
le classificazioni di terzi/derivati: patch MIT doppio copyright, metadata upstream MIT,
glue generato MIT (porzioni wasm-bindgen), artefatti WASM come aggregati con espressioni
composte (MIT AND BSD-3-Clause; AGPL AND MIT AND BSD-3-Clause per KDF/spike).

## 19. Earliest copyright year and evidence

**2026.** `git log --reverse --format='%ad %h %s' --date=short | head` → primo commit
`d24d962` "Task 0: monorepo scaffolding", 2026-02-23; intera history nel 2026;
`git shortlog -sne HEAD` → unico autore umano `maverde73`. Riga: `Copyright (C) 2026
Maurizio Verde`.

## 20. Proposed amendment (Apache exceptions)

Proposta: esattamente i sei file (5 JSON vault-crypto-v1 + kdf-kat-vectors.js), con
esclusioni esplicite di README/generate.js/mls-state-v1/envelope-spec. **Esito: approvata
senza modifiche dal titolare nell'Issue #41 (2026-07-12).**

## 21. Blocking ambiguities

1. Licenza della crate KDF vs allowlist `deny.toml` fuori dai path allora consentiti →
   risolta al checkpoint: AGPL + `private = { ignore = true }`, path autorizzato.
2. Ordine rispetto alle PR dependabot #19/#20 → risolta: chiuse prima della Fase B.
3. Campi license nei package privati con lock vietati → risolta: non modificarli,
   copertura via REUSE.toml.
4. Inventario esatto delle crate linkate in `openmls_wasm_bg.wasm` non registrato nel
   repo (il lockfile upstream include rami non compilati) → residuo, documentato.
5. Provenienza delle 4 icone PWA (presumibilmente originali del titolare) → residuo
   minore da confermare.

## 22. Residual risks

Disciplina exact-path permanente; elezione MIT delle dual da dichiarare; styx-js
pubblicabile finché privo di `private: true` (fino alla Fase B); GitHub license
detection mostrerà il solo AGPL dal LICENSE root (precedenza completa in LICENSING.md);
`go.mod` legacy senza `go.sum` (fuori scope); questo inventario non è un parere legale.

## 23. Phase B decision

**READY** — subordinato alle decisioni del checkpoint umano (mappa Apache, crate KDF,
ordine PR dependabot), tutte poi registrate e approvate nell'Issue #41.
