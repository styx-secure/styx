# ADR-0004 — Strategia di licenza

- **Stato:** **PROPOSTA — NON APPLICATA.** Richiede revisione legale prima di qualsiasi applicazione definitiva e prima di accettare contributi esterni.
- **Contesto normativo:** piano operativo Styx Secure §8 (ADR-0004), §9, §15.

## Contesto

Il repository non ha ancora una `LICENSE` a livello di prodotto. Prima di renderlo pubblico serve una strategia di licenza coerente col modello (comunicazione sovrana, sicurezza) e con la presenza di dipendenze vendorizzate con licenze proprie (OpenMLS, MIT).

## Titolarità (dichiarata dal titolare, 2026-07-11)

Il titolare dichiara di essere, per quanto a sua conoscenza, **unico autore e titolare del copyright del codice originale** di Styx attualmente nel repository. Restano esclusi e mantengono le rispettive licenze:

- **OpenMLS** e ogni dipendenza vendorizzata (es. `styx-js/vendor/openmls-wasm/`, licenza MIT — gli header MIT e le attribuzioni **non vanno rimossi**);
- codice di terzi;
- librerie e asset soggetti a licenze originali.

## Proposta (da confermare con revisione legale)

- **Applicazioni e servizi ufficiali:** `AGPL-3.0-or-later`.
- **Specifiche e test vector interoperabili:** `Apache-2.0`.
- **Dipendenze:** mantenimento **integrale** delle licenze originali; `NOTICE` con le attribuzioni.
- **Marchio "Styx Secure":** separato dalla licenza del codice (vedi `TRADEMARKS.md` futuro).
- **Dual licensing commerciale:** possibile in futuro, solo dopo chiarimento della titolarità.

## Vincoli operativi (fino all'approvazione)

- **Non aggiungere** ancora `LICENSE`, un CLA definitivo, o intestazioni SPDX al codice senza approvazione successiva del titolare.
- La pubblicazione del repo `styx` richiede prima: identificazione del titolare (fatta), verifica pubblicabilità del codice, controllo licenze vendor, `NOTICE`, scansione segreti e licenze, e il warning sperimentale (piano §15).

## Conseguenze

- La strategia è tracciata e pronta, ma **nessun file di licenza viene applicato** in questo ciclo.
- I contributi esterni non si accettano finché CLA/licenza non sono approvati.
