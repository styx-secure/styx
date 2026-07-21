# Review indipendente — applicazione del modello di licenza open-source (Issue #41, PR #42)

- **Data:** 2026-07-12
- **Oggetto:** Draft PR #42 `chore(legal): apply open-source licensing model`,
  branch `task/41-apply-open-source-licensing`,
  base `main @ 0a2c2c0ff2114cb6da078cf925b48e405c0ba305`.
- **Reviewer:** licensing/spec reviewer indipendente, contesto pulito e separato
  dall'implementatore, checkout read-only; punto di partenza: Issue #40 (GO umano),
  Issue #41 (contratto completo), record di Fase A
  (`docs/legal/2026-07-12-licensing-inventory.md`), diff finale, ADR-0004, licenze e
  notice upstream, manifest modificati, metadata REUSE finale.
- **Esito:** **PASS-WITH-FINDINGS — 27/27 punti verificati OK; nessun finding Critical
  o Important; 2 finding Minor, entrambi rimediati e riverificati (sotto).**

## Punti verificati attivamente (27/27 OK)

1. Testo AGPL canonico: `LICENSES/AGPL-3.0-or-later.txt` byte-identico al testo SPDX
   canonico (sezioni 0–17, END OF TERMS, "How to Apply" presenti).
2. Testo Apache-2.0 canonico: byte-identico al canonico SPDX.
3. Testo MIT canonico: byte-identico al canonico SPDX.
4. `cmp LICENSE LICENSES/AGPL-3.0-or-later.txt` → identici.
5. Eccezioni Apache: `reuse spdx` risolve **esattamente sei** file ad Apache-2.0 — i
   cinque JSON `vault-crypto-v1` + `kdf-kat-vectors.js` — e nessun altro.
6. Nessun glob Apache largo in `REUSE.toml` né in `LICENSING.md`.
7. Default AGPL: spot-check su sorgenti, package Dart e docs → `AGPL-3.0-or-later`,
   © 2026 Maurizio Verde.
8. Vendor OpenMLS classificato path-per-path (mai come directory intera).
9. `patch/lib.rs`: MIT con doppio copyright (OpenMLS Authors 2020 + Maurizio Verde 2026,
   modifiche); file byte-identico alla base, nessun header inserito.
10. Crate KDF: `Cargo.toml` → `AGPL-3.0-or-later`; sorgenti risolti AGPL da REUSE.
11. `deny.toml`: diff limitato a `[licenses] private = { ignore = true }` + commenti.
12. Allowlist dipendenze invariata (`MIT, Apache-2.0, BSD-3-Clause, Unicode-3.0`);
    AGPL NON aggiunta; enforcement non indebolito.
13. File generati classificati esplicitamente (glue MIT / AGPL AND MIT; artefatti WASM
    con espressioni composte incluso BSD-3-Clause).
14. Binari (3 × .wasm, 4 × .png) tutti risolti da REUSE.
15. Lockfile root: confronto JSON con `packages[""].license` rimosso da base e HEAD →
    deep-equal (solo il campo autorizzato differisce).
16. `THIRD_PARTY_NOTICES.md` completo: OpenMLS (MIT, copyright, commit pin), `subtle`
    (BSD-3-Clause + copyright), elezione MIT delle crate dual (wasm-bindgen,
    RustCrypto), `generic-array`; nessuna rivendicazione di authorship su upstream.
17. Nessun `NOTICE` root; assenza deliberata documentata in `LICENSING.md`.
18. `reuse lint` (reuse 6.2.0): conforme REUSE 3.3, 582/582 file, zero errori.
19. `TRADEMARKS.md`: riserva Styx/Styx Secure/loghi/build/servizi ufficiali; permette
    usi nominativi veritieri; richiede ai fork di non presentarsi come ufficiali; non
    limita la discussione veritiera.
20. `CONTRIBUTING.md`: contributi di codice esterni in pausa; issue e feedback benvenuti;
    vulnerabilità → GitHub Private Vulnerability Reporting; nessun CLA/DCO.
21. Nessuna modifica a sorgenti prodotto (`styx-js/src/**`, `packages/**/lib|test/**`,
    Go, apps src, `test_integration/**`).
22. Nessuna modifica binaria (`git diff --numstat` senza entry "-").
23. Nessuna modifica alle fixture (`styx-js/test/fixtures/**` intatto).
24. Nessuna modifica a dipendenze/lockfile (solo il campo license del lock root npm).
25. Nessun CLA in alcun file nuovo.
26. Nessun testo di licenza commerciale: solo la frase consentita "Separate commercial
    terms may be available from the copyright holder.", senza implicare una concessione
    esistente.
27. Nessuna eccezione app-store / permesso addizionale AGPL §7.

In aggiunta: 21 path modificati, tutti nell'allowlist dell'Issue #41; path vietati
intatti; ADR-0004 registra il GO di #40, l'implementazione in #41 e lo stato
accettata/applicata; il README non descrive più il repo come unlicensed/public-source;
nessuna falsa attribuzione di copyright Styx a file di terzi; nessuna rilicenziazione
di codice di terzi.

## Finding e rimediazioni

| # | Severità | Finding | Rimediazione | Riverifica |
|---|---|---|---|---|
| 1 | Minor | ADR-0004 referenzia `docs/legal/2026-07-12-review-open-source-licensing.md`, non ancora presente nella PR al momento della review. | Questo stesso record è stato committato al path referenziato nel commit di chiusura della PR. | Il file esiste al path citato; il riferimento dell'ADR risolve. |
| 2 | Minor | La wordlist inglese BIP-39 (`packages/crypto_core/lib/src/bip39_english.dart`, ripresa in `styx-js/src/crypto/mnemonic.js`) — dato di riferimento della specifica BIP-39 — ricade nel default `**` (AGPL, © Maurizio Verde) e non era esaminata nell'inventario di Fase A §7. Probabilmente non copyrightabile / de minimis, ma da registrare; nessuna azione unilaterale dell'esecutore è ammessa. | Registrata come ambiguità residua nell'inventario (`docs/legal/2026-07-12-licensing-inventory.md`, §21) e nei rischi residui della PR; ogni eventuale riclassificazione richiede un emendamento umano dell'Issue. | Nota presente nell'inventario e nella descrizione della PR; nessuna riclassificazione eseguita. |

Nota non bloccante registrata dal reviewer: `git diff --check base...HEAD` segnala un
trailing whitespace in `LICENSES/BSD-3-Clause.txt:1`; è un byte del testo canonico SPDX
(file byte-identico al canonico) e NON va "corretto". Il test richiesto dall'Issue
(`git diff --check` sul working tree) passa.

## Evidenze principali del reviewer

- `cmp` dei quattro testi in `LICENSES/` contro i testi canonici SPDX
  (license-list-data): tutti byte-identici.
- `reuse lint` e `reuse spdx` eseguiti nella venv pinnata (`reuse==6.2.0`).
- Diff verificato con `git diff 0a2c2c0…...HEAD` (`--name-only`, `--numstat`,
  per-file `--quiet` su patch, fixture e artefatti).
- Confronto semantico JSON del lockfile root npm (base vs HEAD).
- Grep mirati su CLA/DCO/app-store/§7/commercial in tutti i file nuovi.

## Conclusione

Nessun finding Critical o Important. I due finding Minor sono rimediati e riverificati.
La PR resta **Draft**: l'approvazione finale, il gate del titolare e l'ingresso in Merge
Queue restano decisioni umane, fuori dal mandato di questa review.

## Addendum — riverifica del round correttivo REUSE

La review originale sopra riportata è stata eseguita **prima** che questo stesso
record venisse committato nella PR. I valori storici che essa riporta —
**21 path modificati** e **582/582 file coperti da REUSE** — sono quindi corretti
per lo stato allora esaminato e non vanno riscritti.

Questa riverifica, condotta in un contesto pulito e indipendente, copre il round
correttivo successivo. Il commit correttivo esaminato è:

```text
9c67473d102f176e98fdcc2942c0506860ff2fa5
```

(`chore(legal): make REUSE annotation precedence explicit` — da leggersi come il
commit correttivo oggetto di riverifica, non come la testa finale della PR dopo
il commit di questo addendum).

Esiti della riverifica:

1. **Path modificati.** La PR contiene ora esattamente **22 path modificati**
   (`git diff --name-only 0a2c2c0…...9c67473…`): i 21 originali più questo
   stesso record di review, committato al path referenziato da ADR-0004.
   Tutti i path restano nell'allowlist dell'Issue #41.
2. **REUSE lint.** `reuse lint` con `reuse==6.2.0` in venv pinnata passa,
   conforme alla REUSE Specification 3.3, con esattamente **583/583** file
   dotati di informazioni di copyright e licenza (582 + questo record);
   0 licenze bad/deprecated/missing/unused; licenze usate:
   `AGPL-3.0-or-later`, `Apache-2.0`, `BSD-3-Clause`, `MIT`.
3. **Eccezioni Apache.** `reuse spdx` risolve ad `Apache-2.0` **esattamente i
   sei file approvati dal titolare** — i cinque JSON di
   `styx-js/test/fixtures/vault-crypto-v1/` più
   `styx-js/test/fixtures/kdf-kat-vectors.js` — e nessun altro file
   (verificato programmaticamente sull'output SPDX completo).
4. **Precedenza delle annotazioni.** In `REUSE.toml` ogni annotazione esatta
   non-default (eccezioni Apache, patch OpenMLS, metadata upstream, output
   generati, artefatti WASM, spike Argon2id) usa `precedence = "override"`;
   l'annotazione larga di fallback AGPL (`path = "**"`) **non** usa `override`
   e mantiene il comportamento implicito `closest`. Il diff del commit
   correttivo aggiunge soltanto le righe `precedence = "override"` e commenti
   esplicativi: le risoluzioni per file sono invariate.
5. **Classificazioni invariate.** Le classificazioni di OpenMLS (patch MIT a
   doppio copyright, metadata upstream MIT, output generati MIT, artefatto
   `MIT AND BSD-3-Clause`), della crate KDF (`AGPL-3.0-or-later` con output
   generati `AGPL AND MIT` / `AGPL AND MIT AND BSD-3-Clause`) e dello spike
   Argon2id sono immutate rispetto alla review originale.
6. **Nessuna nuova eccezione.** Nessuna nuova eccezione di licenza è stata
   introdotta nel round correttivo.
7. **Nessuna modifica di prodotto.** Nessun sorgente di prodotto, fixture,
   vettore, grafo di dipendenze, dipendenza di lockfile, artefatto generato,
   WASM o workflow è cambiato: il commit correttivo tocca esclusivamente
   `REUSE.toml`.
8. **Finding.** Nessun nuovo finding Critical, Important o Minor è stato
   identificato in questa riverifica.
9. **Esito sostanziale.** Il risultato resta **PASS-WITH-FINDINGS**, con i due
   finding Minor originali già rimediati e riverificati.

Questa riverifica, come la review originale, è una review di governance di
repository e di licensing tecnico; non costituisce parere legale professionale.
