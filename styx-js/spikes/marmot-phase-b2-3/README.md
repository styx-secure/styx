# Phase B2.3 crash-consistent lifecycle spike

`STYX_SPIKE_PROTOTYPE`: this directory is an isolated proof for Issue #151. It
is not a product module, is not imported by `styx-js/src/` or the chat app, and
must not be used with user data.

The spike composes the pinned Phase B2.2 OpenMLS WASM surface with a private
IndexedDB journal. Every operation restores a fresh Provider from the exact
durable snapshot and releases all engine handles before returning. The only
durable states are `STABLE` and `PREPARED`; a single atomic compare-and-swap
installs each successor.

## Files

- `b2-3-canonical.mjs`: frozen tuple, bounds, canonical primitives and strict
  Provider-snapshot validation.
- `b2-3-record.mjs`: closed head, transition, evidence and bounded-projection
  codecs.
- `b2-3-journal.mjs`: four-store private journal and atomic CAS.
- `b2-3-engine-adapter.mjs`: disposable outbound, inbound and recovery
  composition over the B2.2 generated API.
- `harness.html`, `journal.browser.spec.js`, `playwright.config.js`: Chromium
  and Firefox IndexedDB collision, reload and abort evidence.

The private database name is `styx-b2-3-poc-<databaseTag>`. One database is
restricted to one PoC group and has exactly four stores: `head`, `snapshot`,
`transition` and `evidence`. `destroy()` deletes only the exact opened database;
no wildcard deletion exists.

## Run

From `styx-js/`:

```bash
npm test -- --runInBand --testTimeout=30000 test/crypto/mls-phase-b2-3-journal.test.js
npx playwright test -c spikes/marmot-phase-b2-3/playwright.config.js
```

The browser suite runs 100 real two-connection CAS races on each of Chromium
and Firefox, plus competing prepare/inbound-accept and reload/abort probes.

## Bounded claim

The proof establishes tested local crash consistency for one PoC group. It
does not establish peer convergence, delivery, power-loss survival, rollback
resistance, at-rest secrecy, authorization, Marmot interoperability or product
security. Web Locks, leases and stale JavaScript/WASM objects are not safety
inputs.

All code in this directory is independently authored for Styx and remains
under the repository's default AGPL-3.0-or-later licensing classification. It
contains no copied Marmot, MDK, Darkmatter or audit implementation material.
