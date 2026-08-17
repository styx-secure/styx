# ADR-0001 — Stack di prodotto canonico

- **Stato:** Superato per l'autorità applicativa e il framing di prodotto da
  [ADR-0007](ADR-0007-application-protocol-authority.md) (2026-08-17).
  Resta una testimonianza storica della scelta di OpenMLS/Rust per il profilo
  di sessione sicura.
- **Contesto normativo:** `docs/security/2026-07-11-fattibilita-piano-utente.md`, piano operativo Styx Secure §3.

> **Nota di supersessione:** le sezioni seguenti conservano la decisione del
> 2026-07-11 nel suo testo storico. I riferimenti al core "protocollare
> canonico", alla chat come prodotto, alla PWA come accesso universale e alle
> funzionalità applicative implementate tutte nel core Rust/MLS non descrivono
> più l'architettura approvata. ADR-0007 separa il protocollo applicativo
> language-neutral dal profilo di sessione sicura, dai profili runtime e dai
> verticali di prodotto.

## Contesto

Il repository contiene due basi di codice con modelli crittografici diversi e non interoperabili: una libreria **Dart** matura per ledger a catena di eventi (`packages/`) e una **chat E2EE su MLS** in JavaScript (`styx-js/`) con PWA. Serve una decisione esplicita su quale sia il core canonico del prodotto, per non pagare due volte le stesse funzionalità e per orientare tutto il lavoro futuro.

## Decisione

- **Core crittografico e protocollare canonico:** **Rust + OpenMLS** (RFC 9420), oggi compilato in WASM per il web (`styx-js/vendor/openmls-wasm/`).
- **Client web:** **PWA React/Vite** mantenuta come accesso universale.
- **Nessuna nuova implementazione crittografica parallela in Dart.** Non si estende il ledger Dart come core della chat, non si riscrive OpenMLS in Dart, non si introduce una seconda libreria crittografica (vedi anche piano operativo §19).
- Il futuro client mobile userà il core Rust via FFI (vedi ADR-0005).

## Conseguenze

- Ogni funzionalità della chat (backup, pairing remoto, migrazione device, multi-device) si implementa **una sola volta**, sul core Rust/MLS.
- Lo stack Dart non è il core del prodotto (vedi ADR-0003 per il suo status).
- Il critical path resta il crate Rust/WASM: le API mancanti (StorageProvider granulare, epoch/tree-hash, ack-gating) si aggiungono lì.

## Alternative scartate

- **Estendere il ledger Dart come core:** modello crittografico incompatibile con MLS; comporterebbe di riscrivere o adattare MLS, o mantenere due protocolli.
- **Due core paralleli mantenuti:** costo di manutenzione doppio, superficie di sicurezza doppia, interoperabilità volutamente rotta già oggi.
