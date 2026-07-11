# ADR-0005 — Strategia client mobile

- **Stato:** Accettato (2026-07-11)
- **Contesto normativo:** piano operativo Styx Secure §8 (ADR-0005); dipende da ADR-0001.

## Contesto

Il prodotto oggi è una PWA. Serve una strategia per i client mobile nativi (iOS/Android) coerente con il core canonico Rust/OpenMLS (ADR-0001), senza duplicare la crittografia e senza avviare lavoro mobile prima che il core sia stabile.

## Decisione

- **PWA mantenuta** come accesso universale.
- **Futuro client iOS/Android in Flutter**, come UI e integrazione di piattaforma.
- **Core Rust condiviso via FFI** — nessuna reimplementazione crittografica in Dart/Flutter (coerente con ADR-0001 e ADR-0003).
- **Integrazioni native Swift/Kotlin** per il materiale sensibile e il push di piattaforma: Keychain, Secure Enclave, Keystore, StrongBox, APNs, FCM.
- **Nessun lavoro mobile** prima del **completamento del Blocco 3** e della **stabilizzazione dell'API del core**.

## Conseguenze

- La superficie crittografica resta unica (il crate Rust), esposta a Flutter via FFI e al web via WASM.
- Il lavoro mobile è esplicitamente **fuori scope** fino a Blocco 3 chiuso e API core stabile — evita di costruire su fondamenta ancora in movimento.

## Alternative scartate

- **Reimplementare il protocollo in Dart per Flutter:** violerebbe ADR-0001 (nessun core crittografico parallelo) e moltiplicherebbe la superficie di sicurezza.
- **App native separate (Swift/Kotlin) senza core condiviso:** triplicherebbe l'implementazione del protocollo.
