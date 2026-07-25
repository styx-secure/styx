# Vault test matrix — coverage map (spec §13)

This document maps every row of the test matrix in
[`docs/superpowers/specs/2026-07-12-styx-vault-design.md`](../../docs/superpowers/specs/2026-07-12-styx-vault-design.md)
§13 to where it is actually covered, honestly including what is **not** covered
and why. It exists because the acceptance criterion of US-007 ("every §13 row
green on the canary") is **not literally satisfiable**: three rows depend on
work that is deliberately out of scope or deferred, and saying so explicitly is
better than a green tick that hides it.

Status values:

- **covered** — exercised by an automated suite that runs in CI;
- **partial** — the part in scope is covered; the remainder has a named owner;
- **N/A** — genuinely out of scope for this block, with the reason;
- **manual** — covered by the manual verification plan, not by CI.

| # | §13 row | Status | Where / why |
|---|---|---|---|
| 1 | unit (wrapper §7.1, canonical AAD, protocol, state machine §3) | covered | `test/storage/vault-wrapper.test.js` (every bound and field), `test/crypto/vault-keys.test.js` (canonical AAD and manifest vectors), `test/crypto/vault-worker-protocol.test.js` (every message type, malformed payloads), `test/storage/vault.test.js` (§3 forbidden transitions) |
| 2 | integration (create→unlock→put/get→lock→unlock cross-worker; multi-store TRANSACTION) | partial | The full cycle runs in-process on real IndexedDB (`test/storage/vault.browser.spec.js`, canary round-trip) and every record write is a multi-store transaction (`test/storage/vault-canary.test.js`, atomicity test; `test/storage/vault-db.browser.spec.js` P1). **Cross-worker is deferred to US-008** (the lifecycle is not yet wired into the crypto worker protocol) |
| 3 | migration (happy path, crash at each §10 step, localStorage intact) | N/A | No localStorage→vault migration exists yet: it is explicitly excluded from US-006 and US-007 and belongs to the migration story (plan PR‑10). Nothing here can be green until that story lands |
| 4 | crash (worker killed mid-PUT/TRANSACTION; page killed) | partial | Page kill mid-transaction is covered by `test/storage/vault-db.browser.spec.js` (P3+P4, all-or-nothing); record+manifest atomicity by `test/storage/vault-canary.test.js`; re-wrap crash at each persistence point by `test/storage/vault.test.js`. **Worker kill mid-PUT is deferred to US-008** |
| 5 | corruption (bit-flip on nonce/data/AAD → `VAULT_RECORD_CORRUPTED`, vault usable) | covered | `test/storage/vault-canary.test.js` (ciphertext and nonce bit-flips, bystander record still readable, corrupted record never auto-deleted) and `test/storage/vault.browser.spec.js` on real IndexedDB |
| 6 | quota (QuotaExceeded on PUT and on migration → fail-closed, non-destructive) | partial | PUT-level quota mapping is covered deterministically in `test/storage/vault-db.test.js` and exercised in `test/storage/vault-db.browser.spec.js` (P8, which skips honestly where the CDP quota override is not enforced — manual item M3). Migration quota is N/A for the same reason as row 3 |
| 7 | multi-tab (writer election, `versionchange`, steal) | covered | `test/storage/vault-db.browser.spec.js` (P6, P10) |
| 8 | worker termination (pending rejected, respawn, coherent state) | covered | `test/crypto/vault-worker-supervisor.test.js`, `test/crypto/vault-worker.browser.spec.js` |
| 9 | KDF bounds (every out-of-range parameter → `VAULT_KDF_PARAMS_INVALID`, no derivation) | covered | `test/crypto/kdf-bounds.test.js`, `test/crypto/kdf-wasm.test.js` (component bounds called directly), plus the password-policy tests in `test/storage/vault.test.js` proving Argon2id is never invoked for invalid input |
| 10 | wrong password (unwrap fails, no side effect, retry possible) | covered | `test/storage/vault.test.js` (no-oracle block: repeated failures leave the wrapper byte-identical, no persisted counter) |
| 11 | AAD tampering (record copied to another key/namespace/version → auth fail) | covered | Two distinct properties, both proven. `test/storage/vault-record.test.js` (PR‑2) covers the codec-level AAD binding across every field. `test/storage/vault-canary.test.js` covers it end-to-end through the vault: an intact envelope moved to another key is stopped by the namespace/key guard (`VAULT_RECORD_INVALID`) **before** decryption, and — the stronger case — an envelope rewritten to be self-consistent with its new key passes that guard and then fails GCM (`VAULT_RECORD_CORRUPTED`), which is what actually proves the §6 request-side binding |
| 12 | nonce uniqueness (statistical sample over N writes) | covered | `test/storage/vault-canary.test.js` (64 writes, all nonces distinct) |
| 13 | schema upgrade (migrator throws → version unchanged, retry) | covered | Engine level: `test/storage/vault-db.browser.spec.js` (P5, failed upgrade leaves v1 intact). Vault level: the trial v1→v2 canary upgrade and its high-water-mark reconciliation in `test/storage/vault.browser.spec.js` and `test/storage/vault-canary.test.js` |
| 14 | factory reset (after every state, §12 order) | partial | Reset from UNLOCKED, LOCKED and a malformed/ERROR vault is covered (`test/storage/vault-canary.test.js`, `test/storage/vault.test.js`). Of the §12 ordering, steps 2→3 (overwrite the wrapper, then delete the database) are asserted directly by observing the call order; step 1 (key wipe) is asserted by its **post-condition** — after a reset every keyed operation is refused — not by observing the moment it happens. Steps 4–7 (legacy localStorage, Cache Storage, push subscription, outbox) have no subject yet in this block; step 8 (worker terminate/respawn) is deferred to US-008 |
| 15 | offline (vault fully functional without network) | covered | `test/storage/vault.browser.spec.js` with the browser context set offline |
| 16 | real browsers (Playwright chromium + firefox) | partial | The vault suites that CI actually runs on both engines are `vault-db.browser.spec.js` and `vault.browser.spec.js` (job `Vault engine browser probes`, configs `playwright.vault-db.config.js` and `playwright.vault-lifecycle.config.js`), plus `kdf-wasm.browser.spec.js` in the WASM integrity workflow. **`vault-crypto.browser.spec.js` and `vault-worker.browser.spec.js` are not invoked by any workflow** — a pre-existing CI gap, unrelated to this story but recorded here rather than papered over; wiring them belongs with US-008, which already touches the worker browser path |
| 17 | mobile devices (manual plan M1–M5, §15) | manual | Not CI-able by construction: real devices. Tracked by the manual plan in the implementation plan §8 (M1, M2, M4, M5 due after PR‑6; M3 after PR‑4) |

## What this means for the US-007 gate

Rows 3 and 17 cannot be closed by this story: one has no subject yet
(no migration exists), the other is manual by definition. Rows 2, 4 and 14 are
closed for everything except the parts that need the vault to live inside the
crypto worker — which is exactly the content of **US-008**.

Everything a canary-scoped story can prove is proven, on both browser engines,
with synthetic records only.
