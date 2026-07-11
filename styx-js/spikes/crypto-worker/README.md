# Crypto Worker spike (STYX_SPIKE_PROTOTYPE)

Dedicated-module-worker prototype for the Blocco 3 architecture question: what
belongs inside a Crypto Worker. **Not production code**; never imported by the
app, blocked from the bundle by the web-gate marker check. Results and the
architecture recommendation: `docs/superpowers/spikes/2026-07-12-crypto-worker.md`.

Run (from `styx-js/`):

```bash
npx playwright test -c spikes/crypto-worker/playwright.spike.config.js
```

Files:

- `crypto-worker.js` — module worker owning the vendored OpenMLS/WASM runtime and
  (a minimal) IndexedDB; typed message protocol INIT/UNLOCK/LOCK/VAULT_GET/
  VAULT_PUT/MLS_RESTORE/MLS_SERIALIZE/MLS_DECRYPT/…/SHUTDOWN with an allowlisted
  error surface.
- `worker-client.js` — id-correlated request/response client; rejects all pending
  requests on crash/termination (recovery property).
- `worker-spike.spec.js` — probes W1–W10 (WASM-in-worker, real-fixture restore,
  transfer vs clone, typed errors, mid-operation termination + restart, the
  W6 leak probe, Web Locks across the boundary, IndexedDB-in-worker, repeated
  cycles, the REAL production CSP with a blob-worker negative control).
- `harness.html` + `harness.js` — external-module bootstrap (the production CSP
  forbids inline scripts, and probe W10 runs under that exact CSP via
  `buildCsp()` imported from `apps/chat/static-server.mjs`).
