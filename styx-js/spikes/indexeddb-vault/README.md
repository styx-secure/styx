# IndexedDB vault spike (STYX_SPIKE_PROTOTYPE)

Prototype + real-browser probes for the Blocco 3 vault design. **Not production
code**: nothing here is imported by the app or the library, and the web-gate CI
job fails if the `STYX_SPIKE_PROTOTYPE` marker ever appears in the production
bundle. Results and decisions: `docs/superpowers/spikes/2026-07-12-indexeddb-vault.md`.

Run (from `styx-js/`):

```bash
npx playwright test -c spikes/indexeddb-vault/playwright.spike.config.js               # both browsers
npx playwright test -c spikes/indexeddb-vault/playwright.spike.config.js --project=chromium
```

Files:

- `vault-prototype.js` — the API under evaluation (`openVault`, `get/put/delete/list/clear`,
  `transaction`, `destroy`, `probeStorage`), native IndexedDB, no dependencies.
- `vault-spike.spec.js` — probes P1–P12 (atomicity, rollback, crash, upgrade,
  multi-tab + Web Locks, destroy, quota, persistence, blocked open/delete,
  realistic MLS records, namespace wipe).
- `harness.html` — page loaded by the spec (and usable manually via any static server).
- `playwright.spike.config.js` — chromium + firefox projects, 1 worker.
