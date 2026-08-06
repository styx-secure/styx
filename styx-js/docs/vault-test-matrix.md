# Vault test matrix — coverage map (spec §13)

This document maps every row of the test matrix in
[`docs/superpowers/specs/2026-07-12-styx-vault-design.md`](../../docs/superpowers/specs/2026-07-12-styx-vault-design.md)
§13 to where it is actually covered, honestly including what is **not** covered
and why. Migration remains out of scope and real mobile devices remain manual;
all canary worker integration owned by US-008 is represented explicitly.

Status values:

- **covered** — exercised by an automated suite that runs in CI;
- **partial** — the part in scope is covered; the remainder has a named owner;
- **N/A** — genuinely out of scope for this block, with the reason;
- **manual** — covered by the manual verification plan, not by CI.

| # | §13 row | Status | Where / why |
|---|---|---|---|
| 1 | unit (wrapper §7.1, canonical AAD, protocol, state machine §3) | covered | `test/storage/vault-wrapper.test.js` (every bound and field), `test/crypto/vault-keys.test.js` (canonical AAD and manifest vectors), `test/crypto/vault-worker-protocol.test.js` (every message type, malformed payloads), `test/storage/vault.test.js` (§3 forbidden transitions) |
| 2 | integration (create→unlock→put/get→lock→unlock cross-worker; multi-store TRANSACTION) | covered | `test/crypto/vault-worker.browser.spec.js` runs the full lifecycle through the production dedicated worker and real IndexedDB on Chromium and Firefox. `test/storage/vault-canary.test.js` proves a bounded mixed PUT/DELETE batch commits atomically with exactly one manifest bump |
| 3 | migration (happy path, crash at each §10 step, localStorage intact) | N/A | No localStorage→vault migration exists yet: it is explicitly excluded from US-006 and US-007 and belongs to the migration story (plan PR‑10). Nothing here can be green until that story lands |
| 4 | crash (worker killed mid-PUT/TRANSACTION; page killed) | covered | Page kill mid-transaction is covered by `test/storage/vault-db.browser.spec.js` (P3+P4). `test/crypto/vault-worker.browser.spec.js` stalls after a real IndexedDB PUT and multi-record TRANSACTION commit, lets the fatal client timeout terminate the worker, then respawns, unlocks, verifies the signed manifest and observes the complete committed state—never a partial batch |
| 5 | corruption (bit-flip on nonce/data/AAD → `VAULT_RECORD_CORRUPTED`, vault usable) | covered | `test/storage/vault-canary.test.js` (ciphertext and nonce bit-flips, bystander record still readable, corrupted record never auto-deleted) and `test/storage/vault.browser.spec.js` on real IndexedDB |
| 6 | quota (QuotaExceeded on PUT and on migration → fail-closed, non-destructive) | partial | PUT-level quota mapping is covered deterministically in `test/storage/vault-db.test.js` and exercised in `test/storage/vault-db.browser.spec.js` (P8, which skips honestly where the CDP quota override is not enforced — manual item M3). Migration quota is N/A for the same reason as row 3 |
| 7 | multi-tab (writer election, `versionchange`, steal) | covered | `test/storage/vault-db.browser.spec.js` (P6, P10) |
| 8 | worker termination (pending rejected, respawn, coherent state) | covered | `test/crypto/vault-worker-supervisor.test.js` covers timeout/crash/cancel/factory-reset generation ownership; `test/crypto/vault-worker.browser.spec.js` covers real worker termination, verified reinitialization and coherent persisted state |
| 9 | KDF bounds (every out-of-range parameter → `VAULT_KDF_PARAMS_INVALID`, no derivation) | covered | `test/crypto/kdf-bounds.test.js`, `test/crypto/kdf-wasm.test.js` (component bounds called directly), plus the password-policy tests in `test/storage/vault.test.js` proving Argon2id is never invoked for invalid input |
| 10 | wrong password (unwrap fails, no side effect, retry possible) | covered | `test/storage/vault.test.js` (no-oracle block: repeated failures leave the wrapper byte-identical, no persisted counter) |
| 11 | AAD tampering (record copied to another key/namespace/version → auth fail) | covered | Two distinct properties, both proven. `test/storage/vault-record.test.js` (PR‑2) covers the codec-level AAD binding across every field. `test/storage/vault-canary.test.js` covers it end-to-end through the vault: an intact envelope moved to another key is stopped by the namespace/key guard (`VAULT_RECORD_INVALID`) **before** decryption, and — the stronger case — an envelope rewritten to be self-consistent with its new key passes that guard and then fails GCM (`VAULT_RECORD_CORRUPTED`), which is what actually proves the §6 request-side binding |
| 12 | nonce uniqueness (statistical sample over N writes) | covered | `test/storage/vault-canary.test.js` (64 writes, all nonces distinct) |
| 13 | schema upgrade (migrator throws → version unchanged, retry) | covered | Engine level: `test/storage/vault-db.browser.spec.js` (P5, failed upgrade leaves v1 intact). Vault level: the trial v1→v2 canary upgrade and its high-water-mark reconciliation in `test/storage/vault.browser.spec.js` and `test/storage/vault-canary.test.js` |
| 14 | factory reset (after every state, §12 order) | partial | Reset from UNLOCKED, LOCKED and malformed/ERROR state is covered by `test/storage/vault-canary.test.js` and `test/storage/vault.test.js`; wrapper overwrite precedes database deletion and the key-wipe post-condition is asserted. Worker step 8 is covered by supervisor unit tests and the production-worker browser lifecycle, which retires the DB-owning generation and respawns. Steps 4–7 (legacy localStorage, Cache Storage, push subscription, outbox) still have no subject in this canary block |
| 15 | offline (vault fully functional without network) | covered | `test/storage/vault.browser.spec.js` with the browser context set offline |
| 16 | real browsers (Playwright chromium + firefox) | covered | The `Vault browser probes` CI job runs all four configs on both engines: `playwright.vault.config.js`, `playwright.vault-worker.config.js`, `playwright.vault-db.config.js` and `playwright.vault-lifecycle.config.js`. The WASM integrity workflow separately runs its browser KDF checks |
| 17 | mobile devices (manual plan M1–M5, §15) | manual | Not CI-able by construction: real devices. Tracked by the manual plan in the implementation plan §8 (M1, M2, M4, M5 due after PR‑6; M3 after PR‑4) |

## US-008 worker and PWA-context evidence

The RK8 probe in `test/crypto/vault-worker.browser.spec.js` installs a service
worker, keeps the dedicated vault worker UNLOCKED across a service-worker
update, and proves the vault remains usable without any key crossing the
protocol. Reloading the PWA retires that dedicated worker; a fresh production
worker reopens the same canary database LOCKED and requires a new unlock. This
is a process-confinement check, not a claim of guaranteed physical erasure from
JavaScript memory.

Rows 3 and 17 remain N/A/manual: migration has no subject yet, and real mobile
devices are manual by definition. Row 14 remains partial only for reset steps
whose product subsystems do not exist in this canary block. Everything owned by
the US-008 worker integration is automated on both desktop browser engines with
synthetic records only.
