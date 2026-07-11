# ADR-0002 — Strategia monorepo

- **Stato:** Accettato (2026-07-11)
- **Contesto normativo:** piano operativo Styx Secure §6, §7.

## Contesto

L'organizzazione GitHub `styx-secure` ospita più repository. Serve decidere quanto tenere unito e quando frammentare, evitando una separazione prematura che complicherebbe lo sviluppo prima ancora di avere una beta stabile.

## Decisione

- **`styx` resta il monorepo canonico** almeno fino alla **beta auditabile**: PWA, core Rust/WASM, bridge push, codice Dart storico, documentazione, test e pipeline.
- Restano repository **separati** solo: **`styx-website`** (sito pubblico) e **`.github`** (profilo organizzazione e community health).
- **Nessuna frammentazione prematura** in repository separati per core, SDK, relay o client. I nomi `styx-audits`, `styx-deploy`, `styx-protocol`, `styx-sdk` sono solo **pianificati**, non creati.
- La struttura fisica target del monorepo (`apps/`, `crates/`, `services/`, `packages/`, `legacy/`…) è documentata come **destinazione** in `docs/architecture/target-repository-layout.md`, non come refactor immediato: nessuna grande movimentazione fisica prima di aver stabilizzato il Blocco 3.

## Conseguenze

- Lo sviluppo resta a basso attrito (un solo repo da clonare, testare, versionare).
- La riorganizzazione fisica è un lavoro successivo, con regole precise (un solo spostamento logico per PR, `git mv`, test verdi, nessuna modifica funzionale nello stesso commit).

## Alternative scartate

- **Poly-repo subito** (core/SDK/relay/client separati): overhead di coordinamento e versioning sproporzionato a un team maturo, non a un singolo maintainer in fase pre-beta.
