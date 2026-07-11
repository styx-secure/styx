# Valutazione di pertinenza — demo `fidesvox`

**Data:** 2026-07-11 · **Scopo:** decidere se mantenere, spostare sotto `legacy/` o rimuovere la demo `styx-js/demo/fidesvox/`. **Decisione rimandata** (per ora si mantiene, bonificata — S-1).

## Cos'è

Un'app demo **standalone**: server Express + SQLite + un subscriber Nostr, con autenticazione JWT e pagine (login/register/dashboard/form). Illustra come un prodotto di form/reporting potrebbe instradare risposte private attraverso Styx.

## Rapporto col prodotto canonico

- **Non è parte del prodotto:** non importata dalla chat (`apps/chat`) né dalla libreria (`styx-js/src`); non entra nel bundle di produzione; non è in CI.
- **Stack diverso:** usa un proprio server, un proprio DB e un proprio modello di auth (JWT) — nessuno di questi è il core Rust/MLS canonico (ADR-0001).
- **Concetto affine, non codice condiviso:** l'idea (risposte private via Styx) si sovrappone a `themis_survey` (Dart) più che alla chat MLS.
- **Peso:** ~5 file tracciati + asset; porta dipendenze pesanti (express, bcrypt, jsonwebtoken) fuori dal grafo della chat.

## Rischi se mantenuta nel repo canonico

- Confonde il perimetro del prodotto (una demo con auth propria in un repo che punta a MLS).
- Superficie di sicurezza extra (S-1 era qui); resta l'identità Nostr hardcoded (demo, usa-e-getta).
- Un repo pubblico futuro la esporrebbe come se fosse parte dell'offerta.

## Opzioni

1. **Mantenere in `demo/`** — ok finché serve come esempio vivo; va tenuta chiaramente marcata "DEMO ONLY" (fatto nel README).
2. **Spostare sotto `legacy/demos/fidesvox/`** (struttura target §7) — segnala che non è prodotto, riduce il rumore nel percorso principale.
3. **Rimuovere dal repo canonico** — se non serve più come esempio; resta recuperabile dalla storia git.

## Raccomandazione

**Spostare sotto `legacy/` al momento del refactor fisico del monorepo** (dopo il Blocco 3, ADR-0002), non ora. Fino ad allora resta in `demo/`, bonificata e marcata DEMO ONLY. Decisione finale (mantieni/legacy/rimuovi) da prendere insieme al refactor della struttura.
