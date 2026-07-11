# Blocco 2 — Riduzione immediata del rischio — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or superpowers:subagent-driven-development) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Tasks are largely independent; execute in order for a clean review sequence.

**Goal:** Close the seven P0 "immediate risk reduction" items from the feasibility document (`docs/security/2026-07-11-fattibilita-piano-utente.md` §5, Blocco 2; exit criteria §7.5 P0): stop shipping the mock in production, disable stub features, ship a real factory reset, add a minimal single-writer multi-tab lock, a full CSP, honest copy, and a CI gate that fails the build if the mock leaks into the bundle.

**Why this block:** the app currently ships a fake fallback that silently replaces real crypto with seeded demo data on any WASM failure, exposes non-functional features as if they worked, and its "reset" wipes nothing real. None of this touches the vendored crate (Blocco 1's domain), so it builds on stable ground.

**Architecture:** All work is in `styx-js/apps/chat/` (Vite + React PWA), `styx-js/src/chat/styx-chat.js` (the library the app consumes), the dependency-free static server (`apps/chat/static-server.mjs`), the service worker (`apps/chat/src/sw.js`), and CI (`.github/workflows/`). The library gets a `wipe()` primitive (backend + push, DI-testable); the browser-global surfaces (Cache Storage, service worker, IndexedDB) are cleared at the app layer.

**Tech Stack:** Vite 5 + `@vitejs/plugin-react` + `vite-plugin-pwa` (injectManifest, hand-written `sw.js`); React 18; Jest (native ESM via `node --experimental-vm-modules`, run with `npm test` from `styx-js/`); Playwright (`apps/chat/playwright.pwa.config.js` builds+previews `dist/`); Web Locks / Push / Cache Storage / Service Worker browser APIs.

## Global Constraints

- **Run the JS test suite from `styx-js/`** with `npm test` (it wraps `node --experimental-vm-modules`). `npx jest` directly fails with an ESM error. The root jest also collects `apps/chat/test/*.test.js`. `e2e.test.js` flakes on the default timeout — use `npm test -- --testTimeout=20000` for full runs (documented in `AGENTS.md`).
- **Do not weaken Blocco 1 or Fase A.** The MLS engine, the N2 identity binding, and the panic-free parsers are done — this block does not touch `vendor/openmls-wasm/` or the crypto path.
- **Real backend key namespace is `styxchat:`** (prefix from `LocalStorageBackend`, `styx-chat.js:34-39`). The mock's key is the unprefixed `styx-identity`. A real reset must clear the former; the latter is legacy/demo-only.
- **Default relays:** `wss://relay.damus.io`, `wss://nos.lol` (`apps/chat/src/lib/config.js:7`). Push bridge origin: `VITE_BRIDGE_URL` or `?bridge=` (`config.js:38-51`). These are the only remote origins the app contacts.
- **Honest copy rule (feasibility §0.3):** no "serverless" / "zero-server" / "nessun server" / "tutto peer-to-peer" claims. Replace with: messages are E2E-encrypted and distributed via federated relays that cannot read content but observe some transport metadata.
- **Commit messages:** Conventional Commits, English, ending with the `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` trailer.
- **CSP scope (user decision):** full CSP, no `unsafe-inline` for scripts, `'wasm-unsafe-eval'` verified experimentally in a real browser before it ships. Trusted Types is attempted-but-not-blocking. `style-src` may keep `'unsafe-inline'` for React inline `style=` attributes — documented as a low-risk exception, not silently.
- **Web Locks scope (user decision):** minimal single-writer lock only. A second tab must not become an MLS writer. No leader/follower snapshot channel and no IndexedDB-lease fallback in this block — if `navigator.locks` is absent, degrade with a logged warning (the lease fallback is deferred).

---

## Current-state anchors (verified 2026-07-11)

- **Mock fallback (unconditional, no env guard):** `apps/chat/src/lib/styx-adapter.js:14-31`. The mock is `apps/chat/src/lib/styx-lib-mock.js` (seeds fake contacts Aurora/Marco/Nodo Berlino/Lucia, fakes remote pairing, presence, ticks). It **currently ships**: `dist/assets/styx-lib-mock-*.js` exists and `index-*.js` references it. Real lib resolved via Vite alias `styx-js` → `../../src/index.js` (`vite.config.js:9,32-34`). Only env use in the app: `import.meta.env.VITE_BRIDGE_URL` (`config.js:49`).
- **Stub UI:** remote-pairing tab always visible (`PairingModal.jsx:16`), handlers call `api.startRemotePairing()`/`joinRemotePairing()` (`:146,153`) which throw in the real lib (`styx-chat.js:398-399`). Presence dot always visible (`ContactRow.jsx:16`), `online` only set by the mock. WebRTC/backup have no UI.
- **Fake reset:** `App.jsx:67-74` removes only `styx-identity` (mock key). Real teardown `useStyxChat.js:139-153` is in-memory only.
- **Copy:** `apps/chat/index.html:7`, `apps/chat/pwa.config.js:6`, `src/components/UnlockScreen.jsx:82`, `src/components/ConversationView.jsx:69`, `README.md:3`.
- **MLS writer / race:** `_persistMls` `styx-chat.js:526-531`, called at `:308,335,372,420,456,467,575,602`; loaded once in `init` `:176-203`. No `navigator.locks` anywhere. Session created at `useStyxChat.js:85-95`, torn down `:139-153`.
- **CSP today (partial):** `static-server.mjs:24-29`. No CSP meta in `index.html`/`dist/index.html`. WASM instantiated via `WebAssembly.instantiateStreaming` (`openmls_wasm.js:753-811`) → needs `'wasm-unsafe-eval'`.
- **SW:** `apps/chat/src/sw.js` (skipWaiting + clientsClaim + content-free push). Registered by `dist/registerSW.js`.
- **CI:** `.github/workflows/ci.yml` is Dart-only. No Node/npm job. Prod bundle: `cd apps/chat && npm run build`.

---

## Task 1: Isolate the mock; production fails hard when the real lib is absent

**Files:**
- Modify: `apps/chat/src/lib/styx-adapter.js` (invert the fallback: demo-gated mock, hard-fail otherwise)
- Create: `apps/chat/src/lib/fatal-error.js` (typed error)
- Modify: `apps/chat/package.json` (add `build:demo` script)
- Modify: `apps/chat/src/hooks/useStyxChat.js` + `apps/chat/src/App.jsx` (surface a fatal-error state instead of falling through)
- Create: `apps/chat/test/styx-adapter.test.js`

**Interfaces:**
- Produces: `getStyxChat(): Promise<StyxChatClass>` — returns the real `StyxChat` in every build except a demo build (`VITE_DEMO === '1'`), and throws `FatalCryptoError` if the real module is unavailable. The mock is only imported on the demo branch, so a production build tree-shakes it out entirely.
- Produces: `class FatalCryptoError extends Error` with `name = 'FatalCryptoError'`.

- [ ] **Step 1: Add the typed error**

Create `apps/chat/src/lib/fatal-error.js`:

```js
// A crypto-module failure the app must NOT paper over. Surfaced to the user as a
// hard stop, never as a silent downgrade to fake data.
export class FatalCryptoError extends Error {
  constructor(cause) {
    super('Il modulo crittografico non è disponibile. L\'app non può avviarsi in sicurezza.');
    this.name = 'FatalCryptoError';
    this.cause = cause;
  }
}
```

- [ ] **Step 2: Invert the adapter — demo-gated mock, hard-fail otherwise**

Replace the body of `apps/chat/src/lib/styx-adapter.js` (keep any existing module-level `_cached`):

```js
import { FatalCryptoError } from './fatal-error.js';

let _cached = null;

/**
 * Resolve the chat implementation.
 * - Demo build (VITE_DEMO === '1'): the in-memory mock, and ONLY the mock.
 * - Every other build: the real library. If it cannot load, throw — never fall
 *   back to fake data. A silent downgrade would show seeded contacts and fake
 *   "delivered" ticks while the user believes they are talking securely.
 */
export async function getStyxChat() {
  if (_cached) return _cached;

  // Statically foldable: in a production build `import.meta.env.VITE_DEMO` is
  // replaced with `undefined`, so this whole branch — and the mock import — is
  // dead-code-eliminated and never ships.
  if (import.meta.env.VITE_DEMO === '1') {
    const { MockStyxChat } = await import('./styx-lib-mock.js');
    _cached = MockStyxChat;
    return _cached;
  }

  try {
    const mod = await import('styx-js');
    if (!mod?.StyxChat) throw new Error('styx-js loaded but StyxChat export missing');
    _cached = mod.StyxChat;
    return _cached;
  } catch (e) {
    throw new FatalCryptoError(e);
  }
}
```

- [ ] **Step 3: Add a demo build script**

In `apps/chat/package.json` `scripts`, add after `"build"`:

```json
    "build:demo": "VITE_DEMO=1 vite build --outDir dist-demo",
```

(The demo build goes to a separate `dist-demo/` so it can be deployed to a demo-only origin; the default `dist/` is always production and mock-free.)

- [ ] **Step 4: Surface the fatal error instead of falling through**

In `apps/chat/src/hooks/useStyxChat.js`, in `unlock` where `getStyxChat()` / `chat.init()` is called (~`:85-95`), let `FatalCryptoError` propagate to a state flag. Add near the other `useState` hooks a `const [fatalError, setFatalError] = useState(null);`, wrap the unlock body so `catch (e) { if (e?.name === 'FatalCryptoError') { setFatalError(e); return; } throw e; }`, and return `fatalError` from the hook.

In `apps/chat/src/App.jsx`, when `fatalError` is set, render a blocking screen instead of the unlock/chat UI:

```jsx
if (fatalError) {
  return (
    <div className="fatal">
      <h1>Impossibile avviare Styx in sicurezza</h1>
      <p>{fatalError.message}</p>
      <p>Ricarica la pagina. Se il problema persiste, la build potrebbe essere corrotta o incompleta.</p>
      <button onClick={() => location.reload()}>Ricarica</button>
    </div>
  );
}
```

- [ ] **Step 5: Write the test**

Create `apps/chat/test/styx-adapter.test.js`. The adapter reads `import.meta.env.VITE_DEMO`; under jest (not Vite) `import.meta.env` is undefined, so the demo branch is skipped and the real-vs-throw path is what we assert. Mock the `styx-js` import to force the failure path:

```js
import { describe, test, expect, jest, beforeEach } from '@jest/globals';

// Force the real-lib import to fail, so getStyxChat must throw FatalCryptoError
// (never fall back to the mock) outside demo mode.
jest.unstable_mockModule('styx-js', () => { throw new Error('wasm unavailable'); });

beforeEach(() => jest.resetModules());

test('outside demo mode, a missing real lib throws FatalCryptoError — no mock fallback', async () => {
  const { getStyxChat } = await import('../src/lib/styx-adapter.js');
  await expect(getStyxChat()).rejects.toMatchObject({ name: 'FatalCryptoError' });
});
```

- [ ] **Step 6: Run the test and the build**

Run: `cd styx-js && npm test -- apps/chat/test/styx-adapter.test.js` → PASS.
Run: `cd styx-js/apps/chat && npm run build && ! grep -rl "MockStyxChat\|styx-lib-mock" dist/ && echo "CLEAN: no mock in prod bundle"` → prints CLEAN (Task 7 makes this a CI gate).

- [ ] **Step 7: Commit**

```bash
git add apps/chat/src/lib/styx-adapter.js apps/chat/src/lib/fatal-error.js apps/chat/package.json apps/chat/src/hooks/useStyxChat.js apps/chat/src/App.jsx apps/chat/test/styx-adapter.test.js
git commit -m "feat(chat): fail hard instead of silently falling back to the mock"
```

---

## Task 2: Disable stub features when the real lib is active

**Files:**
- Modify: `apps/chat/src/components/PairingModal.jsx` (hide the remote-pairing tab outside demo)
- Modify: `apps/chat/src/components/ContactRow.jsx` (drop the presence dot, which is mock-only)
- Modify: `apps/chat/test/` — add `apps/chat/test/no-stub-ui.test.js`

**Interfaces:** consumes `import.meta.env.VITE_DEMO`. No new exports.

- [ ] **Step 1: Hide the remote-pairing tab unless demo**

In `apps/chat/src/components/PairingModal.jsx`, the remote tab button (`:16`) and its `RemoteTab` render must be conditional. At the top of the component add `const demo = import.meta.env.VITE_DEMO === '1';`, then guard the tab button:

```jsx
{demo && (
  <button className={`tab${tab === 'remote' ? ' active' : ''}`} onClick={() => setTab('remote')}>Pairing remoto</button>
)}
```

and guard the `{tab === 'remote' && <RemoteTab … />}` render the same way. QR pairing (the real, working path) stays. In production the tab that calls the throwing `startRemotePairing`/`joinRemotePairing` is simply absent.

- [ ] **Step 2: Drop the mock-only presence dot**

In `apps/chat/src/components/ContactRow.jsx:16`, the `<span className="presence…" />` reflects `contact.online`, which the real lib never sets. Remove the element (and stop threading the `online` prop). Presence returns only when a real presence protocol exists (not in this block). Leave the demo mock's data untouched — the element is just gone from the UI.

- [ ] **Step 3: Write the test**

Create `apps/chat/test/no-stub-ui.test.js` — assert the built production bundle contains no remote-pairing wiring string and the source no longer renders a presence dot:

```js
import { describe, test, expect } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const contactRow = readFileSync(
  fileURLToPath(new URL('../src/components/ContactRow.jsx', import.meta.url)), 'utf8');

test('ContactRow no longer renders a presence dot (mock-only data)', () => {
  expect(contactRow).not.toMatch(/className=["'`]presence/);
});
```

(The remote-pairing-absent-in-prod assertion is enforced by the Task 7 CI bundle grep, which also covers demo-string leakage.)

- [ ] **Step 4: Run and commit**

Run: `cd styx-js && npm test -- apps/chat/test/no-stub-ui.test.js` → PASS.

```bash
git add apps/chat/src/components/PairingModal.jsx apps/chat/src/components/ContactRow.jsx apps/chat/test/no-stub-ui.test.js
git commit -m "feat(chat): hide non-functional remote-pairing and presence outside demo"
```

---

## Task 3: Honest copy — no "serverless"

**Files:**
- Modify: `apps/chat/index.html:7`, `apps/chat/pwa.config.js:6`, `apps/chat/src/components/UnlockScreen.jsx:82`, `apps/chat/src/components/ConversationView.jsx:69`, `apps/chat/README.md:3`
- Modify: `apps/chat/test/pwa-manifest.test.js` (assert the manifest description is honest)

**Interfaces:** none.

- [ ] **Step 1: Replace each claim**

Apply these exact replacements (the honest formulation from feasibility §0.3):

- `apps/chat/index.html:7` description meta → `Messaggistica cifrata end-to-end, distribuita tramite relay federati.`
- `apps/chat/pwa.config.js:6` `description` → `Messaggistica cifrata end-to-end, distribuita tramite relay federati.`
- `apps/chat/src/components/UnlockScreen.jsx:82` — replace "Nessun server, nessun account." with: `Cifratura end-to-end con forward secrecy. I messaggi viaggiano su relay federati che non possono leggerne il contenuto, ma vedono parte dei metadati di trasporto.`
- `apps/chat/src/components/ConversationView.jsx:69` — replace "Nessun server conserva i tuoi dati." with: `Cifrato end-to-end. I relay instradano i messaggi ma non possono leggerli.`
- `apps/chat/README.md:3` — replace "E2E serverless" with `app di messaggistica E2E su relay federati (Nostr).`

- [ ] **Step 2: Assert the manifest is honest**

In `apps/chat/test/pwa-manifest.test.js`, add:

```js
test('the PWA description makes no serverless / no-server claim', async () => {
  const { manifest } = await import('../pwa.config.js');
  expect(manifest.description).not.toMatch(/serverless|nessun server|zero.server|peer-to-peer/i);
});
```

(Adjust the import to however `pwa.config.js` exports the manifest — the existing test in this file already reads it.)

- [ ] **Step 3: Run and commit**

Run: `cd styx-js && npm test -- apps/chat/test/pwa-manifest.test.js` → PASS.

```bash
git add apps/chat/index.html apps/chat/pwa.config.js apps/chat/src/components/UnlockScreen.jsx apps/chat/src/components/ConversationView.jsx apps/chat/README.md apps/chat/test/pwa-manifest.test.js
git commit -m "docs(chat): replace serverless claims with honest federated-relay wording"
```

---

## Task 4: Real factory reset

**Files:**
- Modify: `styx-js/src/chat/styx-chat.js` (add `wipe()` — clears its own backend + push)
- Create: `styx-js/test/chat/styx-chat-wipe.test.js`
- Create: `apps/chat/src/lib/factory-reset.js` (app-layer: wipe + browser globals)
- Modify: `apps/chat/src/App.jsx` (confirm dialog → factoryReset)
- Modify: `apps/chat/src/components/SettingsPanel.jsx` (the "Reimposta identità" button wording/flow)

**Interfaces:**
- Produces (lib): `StyxChat.wipe({ unsubscribePush = true } = {}): Promise<void>` — closes transport, unsubscribes push and notifies the bridge, and deletes every key this instance's backend owns. Testable with an in-memory backend.
- Produces (app): `factoryReset({ chat }): Promise<void>` — calls `chat.wipe()`, then clears Cache Storage, unregisters the service worker, deletes the `styx-ledger` IndexedDB defensively, removes legacy unprefixed keys (`styx-identity`, `styx-theme`), and reloads.

- [ ] **Step 1: Write the lib test first**

Create `styx-js/test/chat/styx-chat-wipe.test.js`. Build a StyxChat over an in-memory backend (mirror `test/chat/styx-chat-no-overwrite.test.js`'s DI construction), write some state (pair, send), then assert `wipe()` empties the backend:

```js
test('wipe() removes every key the backend owns', async () => {
  // ... construct a paired StyxChat `bob` over an in-memory backend `mem` ...
  expect(mem.size).toBeGreaterThan(0);
  await bob.wipe({ unsubscribePush: false });
  expect(mem.size).toBe(0);
});
```

Use whatever the in-memory backend exposes to count keys (add a `size`/`keys()` helper to the test's memBackend, since `LocalStorageBackend` is not used in DI tests).

- [ ] **Step 2: Implement `wipe()` in the lib**

In `styx-js/src/chat/styx-chat.js`, add a method. It must enumerate and delete the backend's keys — the backend abstraction needs a way to clear everything it owns. If `LocalStorageBackend`/the backend interface lacks a `clear()`/`keys()`, add `clear()` to `src/storage/local-storage-backend.js` (delete all keys under its prefix via `Object.keys(localStorage)`) and to the store interface, then:

```js
/**
 * Irreversibly wipe this identity: stop the transport, drop push, and delete every
 * record this backend owns. Order matters — kill the identity material first so a
 * crash mid-wipe cannot leave a usable-but-partial state.
 */
async wipe({ unsubscribePush = true } = {}) {
  try { if (unsubscribePush) await this._unregisterPush?.(); } catch { /* best effort */ }
  try { this.destroy?.(); } catch { /* best effort */ }
  this._engine = null;
  this._groups = {};
  await this._backend?.clear?.();
}
```

(Wire `_unregisterPush` to the existing push registrar's unsubscribe + `signBridgeRegistration('unregister', …)` path referenced at `styx-chat.js:270`.)

- [ ] **Step 3: Run the lib test** → PASS. Commit the lib change.

```bash
git add styx-js/src/chat/styx-chat.js styx-js/src/storage/local-storage-backend.js styx-js/test/chat/styx-chat-wipe.test.js
git commit -m "feat(chat): StyxChat.wipe() clears backend and push (real reset, lib layer)"
```

- [ ] **Step 4: App-layer factory reset**

Create `apps/chat/src/lib/factory-reset.js`:

```js
// A real factory reset: after this, the origin holds nothing recoverable about the
// identity. Order: destroy identity/push (via the lib) BEFORE the physical wipe, so an
// interrupted reset cannot leave a working key behind a half-cleared cache.
export async function factoryReset({ chat } = {}) {
  try { await chat?.wipe?.({ unsubscribePush: true }); } catch { /* best effort */ }

  // Cache Storage (Workbox precache: app shell + WASM).
  try {
    const names = await caches.keys();
    await Promise.all(names.map((n) => caches.delete(n)));
  } catch { /* not available / already gone */ }

  // Service worker.
  try {
    const regs = await navigator.serviceWorker?.getRegistrations?.() ?? [];
    await Promise.all(regs.map((r) => r.unregister()));
  } catch { /* ignore */ }

  // Defensive: the ledger DB the chat never writes, in case a prior build did.
  try { indexedDB.deleteDatabase('styx-ledger'); } catch { /* ignore */ }

  // Legacy / app-level unprefixed keys the lib does not own.
  try { localStorage.removeItem('styx-identity'); localStorage.removeItem('styx-theme'); } catch { /* ignore */ }

  location.reload();
}
```

- [ ] **Step 5: Wire the UI with a typed confirmation**

In `apps/chat/src/App.jsx`, replace `onReset` (`:67-74`) so it requires an explicit confirm and calls `factoryReset`:

```jsx
const onReset = async () => {
  if (!window.confirm('Reset totale: identità, messaggi, contatti e chiavi verranno eliminati da questo dispositivo. Irreversibile. Procedere?')) return;
  await factoryReset({ chat: chatRef.current });
};
```

Import `factoryReset` and ensure `chatRef` (the live StyxChat) is reachable from `App` (it lives in `useStyxChat`; expose it from the hook if not already). Update `SettingsPanel.jsx`'s button label to "Reset totale del dispositivo" so it reads as destructive, not a soft "reimposta identità".

- [ ] **Step 6: E2E verification**

Add/extend a Playwright test under `apps/chat/e2e/` that: unlocks (creates identity), reloads to confirm persistence, triggers reset (auto-accept the confirm), and asserts after reload that `localStorage` has no `styxchat:`-prefixed keys and `caches.keys()` is empty. Run: `cd styx-js/apps/chat && npm run test:e2e:pwa` (or the dev e2e config).

- [ ] **Step 7: Commit**

```bash
git add apps/chat/src/lib/factory-reset.js apps/chat/src/App.jsx apps/chat/src/components/SettingsPanel.jsx apps/chat/e2e/
git commit -m "feat(chat): real factory reset — backend, caches, SW, push, IDB"
```

---

## Task 5: Minimal single-writer multi-tab lock

**Files:**
- Modify: `apps/chat/src/hooks/useStyxChat.js` (wrap the session in a Web Lock)
- Modify: `apps/chat/src/App.jsx` (a "already open in another tab" state)
- Create: `apps/chat/test/mls-writer-lock.test.js`

**Interfaces:** produces a hook return field `secondaryTab: boolean` — true when this tab could not acquire the exclusive MLS-writer lock (another tab holds it). When true, the app does not start an MLS writer.

- [ ] **Step 1: Acquire an exclusive lock for the session lifetime**

In `apps/chat/src/hooks/useStyxChat.js` `unlock` (~`:85-95`), before `new StyxChat()` / `chat.init()`, acquire `navigator.locks` exclusively and hold it for the session. The lock name is per-namespace so `?ns=` profiles don't block each other:

```js
const lockName = `styx-mls:${peerNamespace()}`;
if (navigator.locks?.request) {
  const held = await new Promise((resolve) => {
    navigator.locks.request(lockName, { mode: 'exclusive', ifAvailable: true }, (lock) => {
      if (!lock) { resolve(false); return; }        // another tab is the writer
      resolve(true);
      // Hold the lock until teardown releases it (or the tab closes — Web Locks
      // auto-releases then, so there is no stale-lock problem).
      return new Promise((release) => { lockReleaseRef.current = release; });
    });
  });
  if (!held) { setSecondaryTab(true); return; }     // do NOT become an MLS writer
} else {
  console.warn('[styx] Web Locks unavailable — multi-tab MLS safety is degraded');
}
```

Store `lockReleaseRef` (a `useRef`) and call `lockReleaseRef.current?.()` inside `lock()`/teardown (`:139-153`) so the lock frees on logout as well as on tab close.

- [ ] **Step 2: Block the secondary tab in the UI**

In `App.jsx`, when `secondaryTab` is true, render a stop screen: "Styx è già aperto in un'altra scheda. Usa quella, oppure chiudila e ricarica qui." — with a "Ricarica" button. The secondary tab never constructs a writable engine, so it cannot clobber `mls:state`.

- [ ] **Step 3: Test the lock predicate**

Create `apps/chat/test/mls-writer-lock.test.js`. Web Locks is not in jsdom, so unit-test the decision helper: extract the acquire logic into a small pure function `acquireWriterLock(locksApi, name)` returning `{held, release}` and test that a stubbed `locks.request` returning a null lock yields `held:false`, and a granted lock yields `held:true`. (The real cross-tab behavior is covered by a Playwright two-context e2e if feasible; otherwise document it as manually verified per the browser matrix.)

- [ ] **Step 4: Commit**

```bash
git add apps/chat/src/hooks/useStyxChat.js apps/chat/src/App.jsx apps/chat/test/mls-writer-lock.test.js
git commit -m "feat(chat): single-writer Web Lock so a second tab cannot corrupt MLS state"
```

---

## Task 6: Full CSP and security headers

**Files:**
- Modify: `apps/chat/static-server.mjs:20-29` (the header block)
- Create: `apps/chat/test/csp-headers.test.js` (assert the served CSP shape)
- Modify: `apps/chat/README.md` (document the `STYX_CONNECT_SRC` env and the style-src exception)

**Interfaces:** the static server reads an optional `STYX_CONNECT_SRC` env (space-separated extra origins) to extend `connect-src` for self-hosters using custom relays/bridge.

- [ ] **Step 1: Write the full CSP**

Replace `SECURITY_HEADERS` in `apps/chat/static-server.mjs`:

```js
const EXTRA_CONNECT = (process.env.STYX_CONNECT_SRC || '').trim();
const CSP = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",       // wasm-unsafe-eval: OpenMLS compiles WASM
  "style-src 'self' 'unsafe-inline'",           // React inline style= attributes (documented exception)
  "img-src 'self' data: blob:",
  "font-src 'self'",
  "manifest-src 'self'",
  "worker-src 'self'",
  `connect-src 'self' wss://relay.damus.io wss://nos.lol${EXTRA_CONNECT ? ' ' + EXTRA_CONNECT : ''}`,
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'none'",
  "upgrade-insecure-requests",
].join('; ');

const SECURITY_HEADERS = {
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'cross-origin-opener-policy': 'same-origin',
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'permissions-policy': 'camera=(self), microphone=(), geolocation=()',
};
```

(`camera=(self)` keeps the QR scanner working; everything else off.)

- [ ] **Step 2: Verify experimentally in a real browser — this is the gate for `'wasm-unsafe-eval'`**

Run: `cd styx-js/apps/chat && npm run build && npm run preview -- --port 8090` in one shell, then drive it (Playwright or manual): load the app, unlock, and confirm (a) the WASM instantiates (no CSP `wasm-unsafe-eval` violation in the console), (b) a relay connects (`connect-src` allows the wss), (c) no `unsafe-inline` **script** violation. If the WASM is blocked, the app cannot start — that is the signal `'wasm-unsafe-eval'` is required (it is, per `instantiateStreaming`), and it is already in the policy. Record the result. If any *script* violation appears, fix the offending inline script (there should be none — Vite emits external `/assets/*.js` + `/registerSW.js`).

> The static server does not serve `dist/` by default in preview (Vite's preview does). To test the *server's* headers, serve `dist/` through `static-server.mjs` and curl: `curl -sI http://localhost:<port>/ | grep -i content-security-policy`.

- [ ] **Step 3: Test the header shape**

Create `apps/chat/test/csp-headers.test.js` — import the CSP builder (extract it to a small exported function `buildCsp(extraConnect)` in `static-server.mjs` so it is unit-testable) and assert: `default-src 'none'`, script-src has `'wasm-unsafe-eval'` and no `'unsafe-inline'`, connect-src has both default relays, and `STYX_CONNECT_SRC` extras are appended.

- [ ] **Step 4: Commit**

```bash
git add apps/chat/static-server.mjs apps/chat/test/csp-headers.test.js apps/chat/README.md
git commit -m "feat(deploy): full CSP + security headers on the static server"
```

---

## Task 7: CI gate — build the web app and fail on mock/demo leakage

**Files:**
- Create: `.github/workflows/styx-js-web.yml`

**Interfaces:** none — a CI workflow.

- [ ] **Step 1: Add the workflow**

Create `.github/workflows/styx-js-web.yml`:

```yaml
name: styx-js web
on:
  pull_request:
    paths: ['styx-js/**']
  push:
    branches: [main]
    paths: ['styx-js/**']
jobs:
  build-and-gate:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: styx-js
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - name: Unit tests
        run: npm test -- --testTimeout=20000
      - name: Build the PWA
        working-directory: styx-js/apps/chat
        run: npm ci && npm run build
      - name: Fail if the mock or demo data shipped
        working-directory: styx-js/apps/chat
        run: |
          if grep -rlE 'MockStyxChat|styx-lib-mock|seedDemo|Aurora|Nodo Berlino' dist/; then
            echo "::error::Mock/demo artifacts found in the production bundle"; exit 1
          fi
          echo "Production bundle is mock-free."
```

- [ ] **Step 2: Verify the gate locally (both directions)**

Run the grep against a clean build → passes. Then temporarily revert Task 1's adapter, rebuild, and confirm the grep **fails** (proving the gate has teeth). Restore Task 1.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/styx-js-web.yml
git commit -m "ci(web): build the PWA and fail the build if the mock leaks into it"
```

---

## Acceptance criteria — Blocco 2 (feasibility §7.5, P0 non-WASM part)

1. **No mock in the production bundle:** `grep -rE 'MockStyxChat|styx-lib-mock|Aurora|Nodo Berlino' apps/chat/dist/` is empty; the CI gate enforces it. A real-lib failure yields the fatal-error screen, never fake data.
2. **Stubs disabled:** no button reachable in a production build calls a `not implemented` method; no presence dot renders with the real lib.
3. **Honest copy:** no "serverless"/"nessun server"/"peer-to-peer" claim in shipped UI, manifest, or `index.html`; manifest test enforces it.
4. **Real factory reset:** wipes `styxchat:`-prefixed localStorage, Cache Storage, the service worker registration, the push subscription (+ bridge unregister), and legacy keys — verified by e2e.
5. **Single MLS writer:** a second tab cannot become an MLS writer (Web Lock); it shows the "already open" screen.
6. **Full CSP live:** `default-src 'none'`, `script-src 'self' 'wasm-unsafe-eval'` with no script `unsafe-inline`, `connect-src` limited to `self` + the configured relays/bridge; the app demonstrably runs under it (WASM instantiates, relay connects).
7. **CI covers the web app:** the new workflow builds `apps/chat`, runs the jest suite, and gates on mock leakage.

## Rollback

Every task is a separate commit and independently revertable — the tasks touch disjoint files (adapter, components, copy, reset, lock, server, CI). The highest-risk change is the CSP (Task 6): if a header breaks the app in a browser the header block reverts in one commit without touching app code. Task 1 changes app startup semantics; its fatal-error path is additive (it only triggers when the real lib was already failing — which previously produced silent fake data, a strictly worse outcome).

## Open decisions the executor should surface (do not guess)

1. **Demo deployment origin.** This plan makes the mock demo-only and DCE'd from prod, plus a `build:demo` → `dist-demo/`. Whether/where to host the demo (the feasibility doc suggests a separate `demo.` domain) is a deployment decision, not code.
2. **`style-src 'unsafe-inline'`.** Kept for React inline `style=` attributes (low risk — style injection, not script execution). Eliminating it means refactoring inline styles to classes; out of scope for P0 but worth a tracked follow-up if the audit flags it.
3. **Web Locks fallback.** If `navigator.locks` is unavailable (very old Safari), this block degrades with a warning rather than building the IndexedDB-lease fallback. Confirm the browser matrix makes that acceptable, or schedule the lease fallback.
4. **`connect-src` and custom relays.** A user-supplied `?relay=` outside the served allowlist is blocked by CSP. Self-hosters extend it via `STYX_CONNECT_SRC`. Confirm this is the intended trust model (it matches "relay scelti dall'utente" being a deployment/config choice, not an in-page override).
