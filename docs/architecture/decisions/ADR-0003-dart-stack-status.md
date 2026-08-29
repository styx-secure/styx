# ADR-0003 — Stato dello stack Dart

- **Stato:** Accettato (2026-07-11), chiarito da
  [ADR-0007](ADR-0007-application-protocol-authority.md) (2026-08-17).
- **Contesto normativo:** piano operativo Styx Secure §3; `docs/PANORAMICA-PROGETTO.md` §3.1, §7.

> **Chiarimento corrente:** il congelamento della linea di funzionalità Dart
> resta confermato, ma avverrà dopo l'estrazione una tantum dei comportamenti e
> dei casi limite necessari al corpus di conformità language-neutral. Dart non
> è la specifica; anche i vettori originati da Dart diventano autoritativi solo
> quando appartengono al corpus governato dal protocollo e sono consumati da
> implementazioni indipendenti. OpenMLS/Rust è un motore del profilo di
> sessione sicura, non l'autorità del protocollo applicativo.

## Contesto

Lo stack Dart (`packages/`) è software maturo e testato: ~10.660 righe di libreria, ~11.810 di test, zero stub, property-based testing, un e2e che regge 10.000 eventi. Implementa identità, ledger a catena di eventi, tre trasporti, pairing (QR e remoto SPAKE2), backup Shamir, re-key e migrazione device. Ma usa un modello crittografico **diverso e non interoperabile** con la chat MLS (vedi ADR-0001). Serve decidere cosa farne, per non lasciarlo in un limbo non dichiarato.

## Decisione

- **Conservato** come **reference implementation** e fonte di **design e test vector**.
- **Nessun nuovo sviluppo di prodotto** sul ledger Dart.
- **Nessuna eliminazione immediata.**
- **Possibile trasferimento futuro sotto `legacy/`** dopo il Blocco 3 (vedi ADR-0002 e `target-repository-layout.md`).
- **Nessun riuso automatico** di primitive crittografiche Dart incompatibili con MLS: idee e test possono diventare **requisiti o test vector**, non una seconda implementazione canonica.

## Conseguenze

- Il valore del lavoro Dart resta accessibile (design, invarianti, vettori di interop documentati in `test_integration/vectors/`), senza costare manutenzione come secondo prodotto.
- I comportamenti applicativi futuri possono essere estratti dal Dart come
  candidati a requisiti e vettori del protocollo language-neutral. Il motore
  Rust/OpenMLS resta limitato al profilo di sessione sicura e non ospita la
  logica applicativa.

## Note

- `flegias_survey` (chiamato `themis_survey` prima della decisione di rinomina
  del 2026-08-29) è un package Flutter di sondaggi già decoupled dal core e non
  rientra in questa decisione: è un consumatore opzionale, non parte del ledger.
- Il bridge Go `push_bridge_server` è lo scaffold della vecchia linea Dart (vedi PANORAMICA §3.3): candidato a `legacy/go-push-bridge/` nella struttura target.
