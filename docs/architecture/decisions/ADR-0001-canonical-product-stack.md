# ADR-0001 — Stack di prodotto canonico

- **Stato:** Accettato (2026-07-11)
- **Contesto normativo:** `docs/security/2026-07-11-fattibilita-piano-utente.md`, piano operativo Styx Secure §3.

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
