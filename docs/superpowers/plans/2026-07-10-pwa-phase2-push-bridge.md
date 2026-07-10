# PWA Fase 2 — Bridge + Web Push — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ricevere notifiche di messaggi e inviti anche ad app chiusa, tramite un bridge Node cieco e opt-in che ascolta i relay Nostr e invia Web Push a payload vuoto, più il client che si registra e la service worker che mostra la notifica.

**Architecture:** Un microservizio Node stateless (`push_bridge/`) riusa il `RelayPool` di `styx-js` per ascoltare gli eventi kind-1059 indirizzati alle pubkey registrate; quando ne vede uno, invia una Web Push VAPID a payload vuoto ai device di quella pubkey. Il registro `pubkey → [subscription]` è l'unico stato (file JSON), e le registrazioni sono firmate schnorr con la chiave Nostr del proprietario. Lato client, un `PushRegistrar` in `styx-js/src/push/` si iscrive via `pushManager` e chiama il bridge; la service worker (scheletro già presente dalla Fase 1) mostra una notifica generica. Il bridge URL è configurabile: senza, l'app resta pienamente funzionante (degrado morbido).

**Tech Stack:** Node ≥ 20 (ESM), `web-push` (VAPID), `@noble/curves` (schnorr verify), il `RelayPool` di styx-js; test del bridge con `node --test` (nessun jest); test client con il Jest del root styx-js; service worker Workbox (vite-plugin-pwa).

## Global Constraints

- **Lingua UI/copy:** italiano; codice/identificatori/commenti/commit in inglese.
- **Commit:** Conventional Commits, ognuno chiuso da `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Branch:** lavorare su `feature/pwa-push-bridge` (ramificato da `feature/styx-chat-mls`, dove la Fase 1 è già mergiata). Non committare su `main`.
- **Payload push:** SEMPRE vuoto. La notifica mostrata è sempre e solo `title: 'Styx Chat'`, `body: 'Hai un nuovo messaggio'`. Nessun contenuto, nessun mittente, nessuna pubkey nel payload (vincolo E2E della spec).
- **Solo kind 1059:** il bridge notifica esclusivamente gli eventi Nostr `kind === 1059` (messaggi/inviti stored). Mai il kind 20000 (typing/presence, effimero).
- **Registrazione firmata:** ogni `register`/`unregister` è firmato schnorr con la chiave Nostr del proprietario; il bridge rifiuta (401) le firme non valide. Digest canonico condiviso: `sha256("styx-push:" + action + ":" + pubkey + ":" + endpoint)`.
- **Bridge opt-in:** il bridge URL è configurabile; se assente, il client non registra nulla e l'app funziona comunque (nessuna push).
- **Bridge cieco/stateless:** memorizza SOLO `pubkey → [subscription]`. Mai messaggi, mai chiavi.
- **Test del bridge:** file `push_bridge/test/*.test.js`, eseguiti con `node --test` dalla dir `push_bridge`. ESM (`"type":"module"`), asserzioni con `node:assert/strict`. NON usano web-push reale né socket reali: le dipendenze esterne (sender push, clock, relay) sono iniettate.
- **Test client (styx-js):** file `styx-js/test/push/*.test.js`, eseguiti col Jest del root da `styx-js`: `node --experimental-vm-modules node_modules/.bin/jest test/push/<file> --forceExit`. Root jest ha `transform: {}` e `testMatch: ['**/test/**/*.test.js']`.
- **Test app (apps/chat):** file `styx-js/apps/chat/test/*.test.js`, stesso Jest del root (da `styx-js`: `... jest apps/chat/test/<file> --forceExit`).
- **Digest condiviso una sola volta:** `registrationDigest` vive in `styx-js/src/push/registration-digest.js` ed è importato SIA dal client SIA dal bridge (import relativo cross-package). Non duplicarlo.

---

## File Structure

**Client / libreria (`styx-js/`):**
- `src/push/registration-digest.js` — `registrationDigest(action, pubkey, endpoint)` puro, condiviso client+bridge.
- `src/push/push-registrar.js` — `PushRegistrar` (iscrizione pushManager + POST firmato al bridge) + `urlBase64ToUint8Array`.
- `src/chat/styx-chat.js` — aggiunge `signBridgeRegistration(action, endpoint)` (firma col segreto Nostr interno).
- `src/index.js` — esporta `PushRegistrar`, `registrationDigest`.
- `test/push/registration-digest.test.js`, `test/push/styx-chat-sign.test.js`, `test/push/push-registrar.test.js`.

**Bridge (`push_bridge/`, nuovo pacchetto Node):**
- `package.json` — `"type":"module"`, dep `web-push` + `@noble/curves`; script `start`, `test`.
- `src/registry.js` — `Registry` (mappa `pubkey → [subscription]`, persistita su file JSON).
- `src/signature.js` — `verifyRegistration({pubkey, action, endpoint, sig})` (schnorr + digest condiviso).
- `src/dispatcher.js` — `Dispatcher` (coalescing per-pubkey, invio push, cleanup 410/404).
- `src/relay-message.js` — `handleRelayMessage(data, seen, watched)` puro (parsing/dedup/kind-filter).
- `src/relay-listener.js` — `RelayListener` (avvolge `RelayPool`, usa `handleRelayMessage`).
- `src/web-push-sender.js` — `makeSender({subject, publicKey, privateKey})` (wrapper `web-push`).
- `src/server.js` — `createServer({registry, vapidPublicKey, dispatcher})` (routing HTTP register/unregister/vapidPublicKey).
- `index.js` — entrypoint: legge env, costruisce tutto, avvia.
- `test/registry.test.js`, `test/signature.test.js`, `test/dispatcher.test.js`, `test/relay-message.test.js`, `test/server.test.js`.
- `README.md` — come generare le chiavi VAPID e avviare.

**App (`styx-js/apps/chat/`):**
- `src/sw.js` — riempimento dell'handler `push`.
- `src/lib/notify.js` — esporta la costante `NOTIFICATION` (titolo/corpo/tag) condivisa da notifier locale e SW.
- `src/lib/config.js` — `getBridgeUrl()`.
- `src/hooks/useStyxChat.js` — `enablePush()` (costruisce il registrar dopo unlock/permesso).
- `src/components/SettingsPanel.jsx`, `src/App.jsx` — invocano `enablePush` dopo la concessione del permesso.
- `test/notify-payload.test.js`, `test/config-bridge.test.js`.

---

## Task 0: Branch di lavoro

- [ ] **Step 1: Creare il branch da feature/styx-chat-mls**

```bash
cd /mnt/storage/home-mverde/src/Styx
git checkout feature/styx-chat-mls
git checkout -b feature/pwa-push-bridge
git branch --show-current   # atteso: feature/pwa-push-bridge
```

---

## Task 1: Digest condiviso + firma lato StyxChat

**Files:**
- Create: `styx-js/src/push/registration-digest.js`
- Modify: `styx-js/src/chat/styx-chat.js` (nuovo metodo `signBridgeRegistration`)
- Modify: `styx-js/src/index.js` (export `registrationDigest`)
- Test: `styx-js/test/push/registration-digest.test.js`, `styx-js/test/push/styx-chat-sign.test.js`

**Interfaces:**
- Produces: `registrationDigest(action: string, pubkey: string, endpoint: string) -> Uint8Array` (32-byte sha256).
- Produces: `StyxChat.signBridgeRegistration(action: string, endpoint: string) -> Promise<string>` (schnorr sig, hex).

- [ ] **Step 1: Scrivere il test del digest (fallisce)**

Create `styx-js/test/push/registration-digest.test.js`:

```js
// test/push/registration-digest.test.js — the canonical, deterministic digest
// both the client and the bridge sign/verify. Binding the action, identity and
// endpoint prevents a signature being replayed for a different registration.
import { describe, test, expect } from '@jest/globals';
import { registrationDigest } from '../../src/push/registration-digest.js';
import { bytesToHex } from '../../src/utils.js';

describe('registrationDigest', () => {
  test('is 32 bytes and deterministic for the same inputs', () => {
    const a = registrationDigest('register', 'pk1', 'https://push/abc');
    const b = registrationDigest('register', 'pk1', 'https://push/abc');
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a.length).toBe(32);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  test('changes when action, pubkey or endpoint changes', () => {
    const base = bytesToHex(registrationDigest('register', 'pk1', 'https://push/abc'));
    expect(bytesToHex(registrationDigest('unregister', 'pk1', 'https://push/abc'))).not.toBe(base);
    expect(bytesToHex(registrationDigest('register', 'pk2', 'https://push/abc'))).not.toBe(base);
    expect(bytesToHex(registrationDigest('register', 'pk1', 'https://push/xyz'))).not.toBe(base);
  });
});
```

- [ ] **Step 2: Eseguire → deve fallire**

Run (da `styx-js`):
```bash
node --experimental-vm-modules node_modules/.bin/jest test/push/registration-digest.test.js --forceExit
```
Expected: FAIL — `Cannot find module '../../src/push/registration-digest.js'`.

- [ ] **Step 3: Implementare il digest**

Create `styx-js/src/push/registration-digest.js`:

```js
// registration-digest.js — the canonical message the client signs and the bridge
// verifies for a push registration. Binding action + identity + endpoint stops a
// signature being replayed for a different action, key, or device subscription.
// Shared verbatim by the client (PushRegistrar / StyxChat) and the push_bridge.
import { sha256 } from '@noble/hashes/sha256';
import { utf8Encode } from '../utils.js';

/**
 * @param {'register'|'unregister'} action
 * @param {string} pubkey hex x-only Nostr pubkey (the identity)
 * @param {string} endpoint the Web Push subscription endpoint URL
 * @returns {Uint8Array} 32-byte digest
 */
export function registrationDigest(action, pubkey, endpoint) {
  return sha256(utf8Encode(`styx-push:${action}:${pubkey}:${endpoint}`));
}
```

- [ ] **Step 4: Eseguire → deve passare**

Run (da `styx-js`):
```bash
node --experimental-vm-modules node_modules/.bin/jest test/push/registration-digest.test.js --forceExit
```
Expected: PASS (2 test).

- [ ] **Step 5: Scrivere il test della firma StyxChat (fallisce)**

Create `styx-js/test/push/styx-chat-sign.test.js`:

```js
// test/push/styx-chat-sign.test.js — StyxChat signs a push registration with its
// internal Nostr secret; the signature must verify against its public key over
// the shared digest (i.e. it's a real, bound schnorr signature).
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { schnorr } from '@noble/curves/secp256k1';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { registrationDigest } from '../../src/push/registration-digest.js';
import { hexToBytes } from '../../src/utils.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

function memBackend() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
  };
}

describe('StyxChat.signBridgeRegistration', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('produces a schnorr signature that verifies over the shared digest', async () => {
    const chat = new StyxChat();
    await chat.init({ password: 'pw', backend: memBackend(), channelName: 'sign-1', alias: 'A' });
    const endpoint = 'https://push.example/xyz';
    const sig = await chat.signBridgeRegistration('register', endpoint);
    const digest = registrationDigest('register', chat.me.pubkey, endpoint);
    expect(typeof sig).toBe('string');
    expect(schnorr.verify(hexToBytes(sig), digest, chat.me.pubkey)).toBe(true);
    // A signature for a different action must NOT verify against the register digest.
    const sig2 = await chat.signBridgeRegistration('unregister', endpoint);
    expect(schnorr.verify(hexToBytes(sig2), digest, chat.me.pubkey)).toBe(false);
    chat.destroy();
  });
});
```

- [ ] **Step 6: Eseguire → deve fallire**

Run (da `styx-js`):
```bash
node --experimental-vm-modules node_modules/.bin/jest test/push/styx-chat-sign.test.js --forceExit
```
Expected: FAIL — `chat.signBridgeRegistration is not a function`.

- [ ] **Step 7: Implementare `signBridgeRegistration`**

In `styx-js/src/chat/styx-chat.js`, add the import near the other imports (after the `EncryptedKeyStore` import line):

```js
import { registrationDigest } from '../push/registration-digest.js';
```

Then add this method inside the `StyxChat` class, right after the `setAlias` method:

```js
  /**
   * Sign a push-bridge registration with the internal Nostr secret. Keeps the
   * secret key encapsulated — callers get only a signature over the exact
   * (action, our pubkey, endpoint) digest, never a general signing oracle.
   * @param {'register'|'unregister'} action
   * @param {string} endpoint the Web Push subscription endpoint
   * @returns {Promise<string>} schnorr signature, hex
   */
  async signBridgeRegistration(action, endpoint) {
    if (!this._nostrSecret) throw new Error('No identity to sign with');
    const digest = registrationDigest(action, this._identity.pubkey, endpoint);
    return bytesToHex(schnorr.sign(digest, this._nostrSecret));
  }
```

(`schnorr` and `bytesToHex` are already imported in `styx-chat.js`.)

- [ ] **Step 8: Esportare `registrationDigest` dall'index**

In `styx-js/src/index.js`, add near the other exports (after the `StyxChat` export line):

```js
export { registrationDigest } from './push/registration-digest.js';
```

- [ ] **Step 9: Eseguire entrambi i test → devono passare**

Run (da `styx-js`):
```bash
node --experimental-vm-modules node_modules/.bin/jest test/push/registration-digest.test.js test/push/styx-chat-sign.test.js --forceExit
```
Expected: PASS (3 test totali).

- [ ] **Step 10: Commit**

```bash
cd /mnt/storage/home-mverde/src/Styx
git add styx-js/src/push/registration-digest.js styx-js/src/chat/styx-chat.js styx-js/src/index.js styx-js/test/push/
git commit -m "feat(push): shared registration digest + StyxChat schnorr signing

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Bridge — pacchetto + registro persistente

**Files:**
- Create: `push_bridge/package.json`
- Create: `push_bridge/src/registry.js`
- Create: `push_bridge/README.md`
- Test: `push_bridge/test/registry.test.js`

**Interfaces:**
- Produces: `class Registry { constructor({ filePath }); async load(); add(pubkey, subscription): boolean; remove(pubkey, endpoint): boolean; get(pubkey): object[]; pubkeys(): string[] }`. `add`/`remove` persist to `filePath` (JSON) and return whether the set changed. Subscriptions are de-duplicated by `endpoint`.

- [ ] **Step 1: Creare il package.json del bridge**

Create `push_bridge/package.json`:

```json
{
  "name": "styx-push-bridge",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "description": "Stateless, blind Web Push bridge for Styx Chat — listens to Nostr relays and wakes registered devices.",
  "scripts": {
    "start": "node index.js",
    "test": "node --test"
  },
  "dependencies": {
    "@noble/curves": "^1.6.0",
    "@noble/hashes": "^1.5.0",
    "web-push": "^3.6.7"
  }
}
```

Then install (from `push_bridge`):
```bash
cd /mnt/storage/home-mverde/src/Styx/push_bridge && npm install
```
Expected: creates `node_modules` with `web-push` and `@noble/curves`.

- [ ] **Step 2: Scrivere il test del registro (fallisce)**

Create `push_bridge/test/registry.test.js`:

```js
// test/registry.test.js — the registry is the bridge's only state: pubkey →
// [subscription]. It must dedupe by endpoint and survive a restart (reload).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Registry } from '../src/registry.js';

function tmpFile() {
  const dir = mkdtempSync(join(tmpdir(), 'styx-reg-'));
  return { path: join(dir, 'reg.json'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const subA = { endpoint: 'https://push/a', keys: { p256dh: 'x', auth: 'y' } };
const subB = { endpoint: 'https://push/b', keys: { p256dh: 'x', auth: 'y' } };

test('add stores a subscription and get returns it', async () => {
  const { path, cleanup } = tmpFile();
  try {
    const r = new Registry({ filePath: path });
    await r.load();
    assert.equal(r.add('pk1', subA), true);
    assert.deepEqual(r.get('pk1'), [subA]);
    assert.deepEqual(r.pubkeys(), ['pk1']);
  } finally { cleanup(); }
});

test('add is idempotent per endpoint (dedupe)', async () => {
  const { path, cleanup } = tmpFile();
  try {
    const r = new Registry({ filePath: path });
    await r.load();
    r.add('pk1', subA);
    assert.equal(r.add('pk1', subA), false); // same endpoint → no change
    r.add('pk1', subB);
    assert.equal(r.get('pk1').length, 2);
  } finally { cleanup(); }
});

test('remove drops one subscription by endpoint and forgets an empty pubkey', async () => {
  const { path, cleanup } = tmpFile();
  try {
    const r = new Registry({ filePath: path });
    await r.load();
    r.add('pk1', subA); r.add('pk1', subB);
    assert.equal(r.remove('pk1', subA.endpoint), true);
    assert.deepEqual(r.get('pk1'), [subB]);
    r.remove('pk1', subB.endpoint);
    assert.deepEqual(r.pubkeys(), []); // pubkey with no subs is forgotten
  } finally { cleanup(); }
});

test('state survives a reload from disk', async () => {
  const { path, cleanup } = tmpFile();
  try {
    const r1 = new Registry({ filePath: path });
    await r1.load();
    r1.add('pk1', subA);
    const r2 = new Registry({ filePath: path });
    await r2.load();
    assert.deepEqual(r2.get('pk1'), [subA]);
  } finally { cleanup(); }
});
```

- [ ] **Step 3: Eseguire → deve fallire**

Run (da `push_bridge`):
```bash
node --test 2>&1 | tail -15
```
Expected: FAIL — cannot find `../src/registry.js`.

- [ ] **Step 4: Implementare il registro**

Create `push_bridge/src/registry.js`:

```js
// registry.js — the bridge's only persistent state: a map pubkey → [subscription].
// No messages, no keys — just Web Push routing. Persisted as JSON so it survives
// a restart. Subscriptions are keyed by their endpoint (dedupe).
import { readFile, writeFile } from 'node:fs/promises';

export class Registry {
  constructor({ filePath }) {
    this._filePath = filePath;
    this._map = new Map(); // pubkey → Map(endpoint → subscription)
  }

  async load() {
    try {
      const raw = JSON.parse(await readFile(this._filePath, 'utf8'));
      this._map = new Map(
        Object.entries(raw).map(([pk, subs]) => [pk, new Map(subs.map((s) => [s.endpoint, s]))]),
      );
    } catch (e) {
      if (e.code !== 'ENOENT') throw e; // fresh start if the file doesn't exist yet
    }
  }

  async _save() {
    const obj = {};
    for (const [pk, subs] of this._map) obj[pk] = [...subs.values()];
    await writeFile(this._filePath, JSON.stringify(obj), 'utf8');
  }

  /** @returns {boolean} whether the set changed. */
  add(pubkey, subscription) {
    const subs = this._map.get(pubkey) || new Map();
    if (subs.has(subscription.endpoint)) return false;
    subs.set(subscription.endpoint, subscription);
    this._map.set(pubkey, subs);
    this._save().catch((e) => console.error('[registry] save failed:', e));
    return true;
  }

  /** @returns {boolean} whether something was removed. */
  remove(pubkey, endpoint) {
    const subs = this._map.get(pubkey);
    if (!subs || !subs.delete(endpoint)) return false;
    if (subs.size === 0) this._map.delete(pubkey);
    this._save().catch((e) => console.error('[registry] save failed:', e));
    return true;
  }

  get(pubkey) { return [...(this._map.get(pubkey)?.values() || [])]; }
  pubkeys() { return [...this._map.keys()]; }
}
```

Create `push_bridge/README.md`:

```markdown
# Styx Push Bridge

Stateless, blind Web Push bridge for Styx Chat. It listens to Nostr relays for
kind-1059 events addressed to registered pubkeys and sends an **empty** Web Push
to wake the device — the content stays end-to-end encrypted and is never seen by
the bridge. Its only state is a `pubkey → [subscription]` registry (JSON file).

## Setup

```bash
npm install
npx web-push generate-vapid-keys   # prints a public and a private key
```

## Run

```bash
VAPID_PUBLIC_KEY=... VAPID_PRIVATE_KEY=... VAPID_SUBJECT=mailto:you@example.com \
RELAYS=wss://relay.damus.io,wss://nos.lol \
PORT=8095 REGISTRY_FILE=./registry.json \
npm start
```

Point the app at it with `?bridge=https://your-bridge-host` (or the build-time
`VITE_BRIDGE_URL`). The bridge is optional: without it the app still works, just
without notifications while closed.

## Test

```bash
npm test
```
```

- [ ] **Step 5: Eseguire → deve passare**

Run (da `push_bridge`):
```bash
node --test 2>&1 | tail -15
```
Expected: PASS (4 test registry).

- [ ] **Step 6: Commit**

```bash
cd /mnt/storage/home-mverde/src/Styx
git add push_bridge/package.json push_bridge/package-lock.json push_bridge/src/registry.js push_bridge/README.md push_bridge/test/registry.test.js
git commit -m "feat(bridge): scaffold push bridge package + persistent subscription registry

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Bridge — verifica firma registrazione

**Files:**
- Create: `push_bridge/src/signature.js`
- Test: `push_bridge/test/signature.test.js`

**Interfaces:**
- Consumes: `registrationDigest` da `../../styx-js/src/push/registration-digest.js` (Task 1).
- Produces: `verifyRegistration({ pubkey: string, action: string, endpoint: string, sig: string }) -> boolean`.

- [ ] **Step 1: Scrivere il test (fallisce)**

Create `push_bridge/test/signature.test.js`:

```js
// test/signature.test.js — the bridge only accepts a registration whose schnorr
// signature (over the shared digest) verifies against the claimed pubkey. This
// stops anyone registering a victim's pubkey to their own push endpoint.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { registrationDigest } from '../../styx-js/src/push/registration-digest.js';
import { verifyRegistration } from '../src/signature.js';

function keypair() {
  const sk = schnorr.utils.randomPrivateKey();
  return { sk, pk: bytesToHex(schnorr.getPublicKey(sk)) };
}

test('accepts a correctly signed registration', () => {
  const { sk, pk } = keypair();
  const endpoint = 'https://push/abc';
  const sig = bytesToHex(schnorr.sign(registrationDigest('register', pk, endpoint), sk));
  assert.equal(verifyRegistration({ pubkey: pk, action: 'register', endpoint, sig }), true);
});

test('rejects a signature from a different key (forgery)', () => {
  const victim = keypair();
  const attacker = keypair();
  const endpoint = 'https://push/abc';
  // Attacker signs the victim's-pubkey digest with the attacker's key.
  const sig = bytesToHex(schnorr.sign(registrationDigest('register', victim.pk, endpoint), attacker.sk));
  assert.equal(verifyRegistration({ pubkey: victim.pk, action: 'register', endpoint, sig }), false);
});

test('rejects when the endpoint or action is tampered', () => {
  const { sk, pk } = keypair();
  const sig = bytesToHex(schnorr.sign(registrationDigest('register', pk, 'https://push/abc'), sk));
  assert.equal(verifyRegistration({ pubkey: pk, action: 'register', endpoint: 'https://push/OTHER', sig }), false);
  assert.equal(verifyRegistration({ pubkey: pk, action: 'unregister', endpoint: 'https://push/abc', sig }), false);
});

test('returns false on malformed input instead of throwing', () => {
  assert.equal(verifyRegistration({ pubkey: 'zz', action: 'register', endpoint: 'e', sig: 'nothex' }), false);
});
```

- [ ] **Step 2: Eseguire → deve fallire**

Run (da `push_bridge`):
```bash
node --test test/signature.test.js 2>&1 | tail -15
```
Expected: FAIL — cannot find `../src/signature.js`.

- [ ] **Step 3: Implementare la verifica**

Create `push_bridge/src/signature.js`:

```js
// signature.js — verify that a registration was signed by the owner of the
// claimed pubkey, over the shared registrationDigest. Reuses the exact digest
// the client signs (imported from styx-js) so the two can never drift.
import { schnorr } from '@noble/curves/secp256k1';
import { hexToBytes } from '@noble/hashes/utils';
import { registrationDigest } from '../../styx-js/src/push/registration-digest.js';

/**
 * @param {object} r
 * @param {string} r.pubkey hex x-only Nostr pubkey
 * @param {'register'|'unregister'} r.action
 * @param {string} r.endpoint Web Push subscription endpoint
 * @param {string} r.sig schnorr signature, hex
 * @returns {boolean}
 */
export function verifyRegistration({ pubkey, action, endpoint, sig }) {
  try {
    const digest = registrationDigest(action, pubkey, endpoint);
    return schnorr.verify(hexToBytes(sig), digest, pubkey);
  } catch {
    return false;
  }
}
```

- [ ] **Step 4: Eseguire → deve passare**

Run (da `push_bridge`):
```bash
node --test test/signature.test.js 2>&1 | tail -15
```
Expected: PASS (4 test).

- [ ] **Step 5: Commit**

```bash
cd /mnt/storage/home-mverde/src/Styx
git add push_bridge/src/signature.js push_bridge/test/signature.test.js
git commit -m "feat(bridge): verify schnorr-signed registrations against the shared digest

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Bridge — dispatcher (coalescing + invio + cleanup 410)

**Files:**
- Create: `push_bridge/src/dispatcher.js`
- Test: `push_bridge/test/dispatcher.test.js`

**Interfaces:**
- Consumes: `Registry` (Task 2) — usa `get(pubkey)` e `remove(pubkey, endpoint)`.
- Produces: `class Dispatcher { constructor({ registry, send, now, coalesceMs }); async notify(pubkey): Promise<{sent:number, skipped:boolean}> }`. `send(subscription) -> Promise<void>` invia una push; se rigetta con `err.statusCode` 410/404 la subscription viene rimossa dal registro. `now() -> number` (ms). `coalesceMs` default 4000.

- [ ] **Step 1: Scrivere il test (fallisce)**

Create `push_bridge/test/dispatcher.test.js`:

```js
// test/dispatcher.test.js — on a new event for a pubkey the dispatcher pushes to
// each of its devices, coalesces bursts within a window, and prunes subscriptions
// the push service reports as gone (410/404). Uses an injected sender + clock.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Dispatcher } from '../src/dispatcher.js';

function fakeRegistry(initial) {
  const map = new Map(Object.entries(initial));
  return {
    get: (pk) => map.get(pk) || [],
    remove: (pk, endpoint) => {
      const subs = (map.get(pk) || []).filter((s) => s.endpoint !== endpoint);
      if (subs.length) map.set(pk, subs); else map.delete(pk);
      return true;
    },
    _map: map,
  };
}
const sub = (e) => ({ endpoint: e, keys: {} });

test('pushes to every subscription of the pubkey', async () => {
  const reg = fakeRegistry({ pk1: [sub('a'), sub('b')] });
  const sent = [];
  const d = new Dispatcher({ registry: reg, send: async (s) => { sent.push(s.endpoint); }, now: () => 0 });
  const r = await d.notify('pk1');
  assert.deepEqual(sent.sort(), ['a', 'b']);
  assert.equal(r.sent, 2);
  assert.equal(r.skipped, false);
});

test('coalesces a second notify within the window', async () => {
  const reg = fakeRegistry({ pk1: [sub('a')] });
  let t = 1000; const sent = [];
  const d = new Dispatcher({ registry: reg, send: async (s) => { sent.push(s.endpoint); }, now: () => t, coalesceMs: 4000 });
  await d.notify('pk1');            // t=1000 → sends
  t = 2000; const r = await d.notify('pk1'); // within 4s → skipped
  assert.equal(r.skipped, true);
  t = 6000; await d.notify('pk1');  // window elapsed → sends again
  assert.deepEqual(sent, ['a', 'a']);
});

test('removes a subscription the push service reports as 410 Gone', async () => {
  const reg = fakeRegistry({ pk1: [sub('gone'), sub('ok')] });
  const send = async (s) => { if (s.endpoint === 'gone') { const e = new Error('gone'); e.statusCode = 410; throw e; } };
  const d = new Dispatcher({ registry: reg, send, now: () => 0 });
  await d.notify('pk1');
  assert.deepEqual(reg.get('pk1').map((s) => s.endpoint), ['ok']); // 'gone' pruned
});

test('a send failure other than 410/404 does not prune the subscription', async () => {
  const reg = fakeRegistry({ pk1: [sub('flaky')] });
  const send = async () => { const e = new Error('boom'); e.statusCode = 500; throw e; };
  const d = new Dispatcher({ registry: reg, send, now: () => 0 });
  await d.notify('pk1');
  assert.deepEqual(reg.get('pk1').map((s) => s.endpoint), ['flaky']); // kept
});
```

- [ ] **Step 2: Eseguire → deve fallire**

Run (da `push_bridge`):
```bash
node --test test/dispatcher.test.js 2>&1 | tail -15
```
Expected: FAIL — cannot find `../src/dispatcher.js`.

- [ ] **Step 3: Implementare il dispatcher**

Create `push_bridge/src/dispatcher.js`:

```js
// dispatcher.js — turn "pubkey X has a new event" into Web Pushes. Coalesces
// bursts per pubkey (one wake per window), fans out to every registered device,
// and prunes subscriptions the push service reports as gone (410/404).
const GONE = new Set([404, 410]);

export class Dispatcher {
  constructor({ registry, send, now, coalesceMs = 4000 }) {
    this._registry = registry;
    this._send = send;
    this._now = now;
    this._coalesceMs = coalesceMs;
    this._lastSentAt = new Map(); // pubkey → ms
  }

  /** @returns {Promise<{sent:number, skipped:boolean}>} */
  async notify(pubkey) {
    const t = this._now();
    const last = this._lastSentAt.get(pubkey) ?? -Infinity;
    if (t - last < this._coalesceMs) return { sent: 0, skipped: true };
    this._lastSentAt.set(pubkey, t);

    const subs = this._registry.get(pubkey);
    let sent = 0;
    for (const sub of subs) {
      try {
        // eslint-disable-next-line no-await-in-loop
        await this._send(sub);
        sent += 1;
      } catch (e) {
        if (GONE.has(e?.statusCode)) this._registry.remove(pubkey, sub.endpoint);
        else console.error('[dispatcher] push failed:', e?.statusCode || e?.message);
      }
    }
    return { sent, skipped: false };
  }
}
```

- [ ] **Step 4: Eseguire → deve passare**

Run (da `push_bridge`):
```bash
node --test test/dispatcher.test.js 2>&1 | tail -15
```
Expected: PASS (4 test).

- [ ] **Step 5: Commit**

```bash
cd /mnt/storage/home-mverde/src/Styx
git add push_bridge/src/dispatcher.js push_bridge/test/dispatcher.test.js
git commit -m "feat(bridge): push dispatcher with per-pubkey coalescing and 410 cleanup

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Bridge — parsing evento relay (puro) + listener

**Files:**
- Create: `push_bridge/src/relay-message.js`
- Create: `push_bridge/src/relay-listener.js`
- Test: `push_bridge/test/relay-message.test.js`

**Interfaces:**
- Consumes: `RelayPool` da `../../styx-js/src/transport/nostr-transport.js`.
- Produces: `handleRelayMessage(data, seen, watched) -> { pubkey: string, eventId: string } | null`. `data` è il messaggio relay grezzo (array); `seen` è un `Set` di event id già processati; `watched` è un `Set` di pubkey monitorate. Ritorna il destinatario + eventId per un kind-1059 nuovo indirizzato a una pubkey monitorata, altrimenti `null`.
- Produces: `class RelayListener { constructor({ relays, onEvent }); async start(); watch(pubkey): void }`. `onEvent(pubkey, eventId)` chiamato per ogni evento idoneo.

- [ ] **Step 1: Scrivere il test del parser (fallisce)**

Create `push_bridge/test/relay-message.test.js`:

```js
// test/relay-message.test.js — the bridge only reacts to *new* kind-1059 events
// addressed (p-tag) to a *watched* pubkey. Ephemeral (20000), unwatched, wrong
// kind, non-EVENT, and replayed events must all be ignored.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleRelayMessage } from '../src/relay-message.js';

const watched = new Set(['pkA']);
const ev = (kind, pTag, id) => ['EVENT', 'sub', { id, kind, tags: [['p', pTag]] }];

test('returns recipient + eventId for a new kind-1059 to a watched pubkey', () => {
  const seen = new Set();
  assert.deepEqual(handleRelayMessage(ev(1059, 'pkA', 'e1'), seen, watched), { pubkey: 'pkA', eventId: 'e1' });
});

test('ignores ephemeral kind 20000', () => {
  assert.equal(handleRelayMessage(ev(20000, 'pkA', 'e2'), new Set(), watched), null);
});

test('ignores an event addressed to an unwatched pubkey', () => {
  assert.equal(handleRelayMessage(ev(1059, 'pkZ', 'e3'), new Set(), watched), null);
});

test('ignores a replayed event id (already seen)', () => {
  const seen = new Set(['e4']);
  assert.equal(handleRelayMessage(ev(1059, 'pkA', 'e4'), seen, watched), null);
});

test('marks an event id as seen so the next identical replay is ignored', () => {
  const seen = new Set();
  handleRelayMessage(ev(1059, 'pkA', 'e5'), seen, watched);
  assert.equal(seen.has('e5'), true);
  assert.equal(handleRelayMessage(ev(1059, 'pkA', 'e5'), seen, watched), null);
});

test('ignores non-EVENT relay frames (EOSE/NOTICE)', () => {
  assert.equal(handleRelayMessage(['EOSE', 'sub'], new Set(), watched), null);
  assert.equal(handleRelayMessage(['NOTICE', 'hi'], new Set(), watched), null);
});
```

- [ ] **Step 2: Eseguire → deve fallire**

Run (da `push_bridge`):
```bash
node --test test/relay-message.test.js 2>&1 | tail -15
```
Expected: FAIL — cannot find `../src/relay-message.js`.

- [ ] **Step 3: Implementare il parser puro**

Create `push_bridge/src/relay-message.js`:

```js
// relay-message.js — pure decision over one raw relay frame: is this a new,
// stored (kind 1059) event addressed to a pubkey we watch? Returns the recipient
// and event id to notify, or null. Kept side-effect-free (except marking `seen`)
// so it is trivially unit-testable without any sockets.
const STORED_KIND = 1059; // messages + invites (welcomes); ephemeral 20000 is never notified

/**
 * @param {any} data raw relay message array, e.g. ['EVENT', subId, event]
 * @param {Set<string>} seen event ids already processed (mutated: the id is added)
 * @param {Set<string>} watched pubkeys we have registrations for
 * @returns {{pubkey:string, eventId:string}|null}
 */
export function handleRelayMessage(data, seen, watched) {
  if (!Array.isArray(data) || data[0] !== 'EVENT') return null;
  const ev = data[2];
  if (!ev || ev.kind !== STORED_KIND || !ev.id) return null;
  if (seen.has(ev.id)) return null;
  const recipient = (ev.tags || []).find((t) => t[0] === 'p' && watched.has(t[1]));
  if (!recipient) return null;
  seen.add(ev.id);
  if (seen.size > 5000) seen.clear(); // bound memory on a long-running bridge
  return { pubkey: recipient[1], eventId: ev.id };
}
```

- [ ] **Step 4: Eseguire → deve passare**

Run (da `push_bridge`):
```bash
node --test test/relay-message.test.js 2>&1 | tail -15
```
Expected: PASS (6 test).

- [ ] **Step 5: Implementare il listener (avvolge RelayPool)**

Create `push_bridge/src/relay-listener.js`:

```js
// relay-listener.js — subscribes to the relays for kind-1059 events p-tagged to
// the watched pubkeys, reusing styx-js's RelayPool (auto-reconnect included), and
// calls onEvent(pubkey, eventId) for each new, relevant one. Filtering/dedup is
// delegated to the pure handleRelayMessage.
import { RelayPool } from '../../styx-js/src/transport/nostr-transport.js';
import { handleRelayMessage } from './relay-message.js';

const STORED_KIND = 1059;

export class RelayListener {
  constructor({ relays, onEvent }) {
    this._pool = new RelayPool(relays);
    this._onEvent = onEvent;
    this._watched = new Set();
    this._seen = new Set();
    this._subId = 'push-bridge';
  }

  watch(pubkey) { this._watched.add(pubkey); this._resubscribe(); }

  async start(pubkeys = []) {
    pubkeys.forEach((pk) => this._watched.add(pk));
    const n = await this._pool.connectAll();
    if (n === 0) throw new Error('RelayListener: could not connect to any relay');
    this._pool.messages.on('message', ({ data }) => {
      const hit = handleRelayMessage(data, this._seen, this._watched);
      if (hit) Promise.resolve(this._onEvent(hit.pubkey, hit.eventId)).catch((e) => console.error('[listener] onEvent:', e));
    });
    this._resubscribe();
  }

  /** (Re)issue the subscription with the current watched set. */
  _resubscribe() {
    if (!this._watched.size) return;
    this._pool.subscribe(this._subId, { kinds: [STORED_KIND], '#p': [...this._watched] });
  }
}
```

- [ ] **Step 6: Commit**

```bash
cd /mnt/storage/home-mverde/src/Styx
git add push_bridge/src/relay-message.js push_bridge/src/relay-listener.js push_bridge/test/relay-message.test.js
git commit -m "feat(bridge): relay event filtering (pure) + RelayPool-backed listener

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Bridge — server HTTP + sender + entrypoint

**Files:**
- Create: `push_bridge/src/web-push-sender.js`
- Create: `push_bridge/src/server.js`
- Create: `push_bridge/index.js`
- Test: `push_bridge/test/server.test.js`

**Interfaces:**
- Consumes: `Registry` (Task 2), `verifyRegistration` (Task 3), `Dispatcher` (Task 4), `RelayListener` (Task 5).
- Produces: `createServer({ registry, vapidPublicKey, verify, onRegister }) -> http.Server`. Routes: `GET /vapidPublicKey` → `{ key }`; `POST /register` `{pubkey, subscription, sig}` → 200 se `verify` ok (chiama `onRegister(pubkey)` + `registry.add`), 401 altrimenti; `POST /unregister` `{pubkey, endpoint, sig}` → 200/401.
- Produces: `makeSender({ subject, publicKey, privateKey }) -> (subscription) => Promise<void>`.

- [ ] **Step 1: Scrivere il test del server (fallisce)**

Create `push_bridge/test/server.test.js`:

```js
// test/server.test.js — the HTTP API: hands out the VAPID key, accepts a
// correctly-signed register/unregister, and rejects a bad signature with 401.
// Verify + registry are injected; no real relays or push involved.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { registrationDigest } from '../../styx-js/src/push/registration-digest.js';
import { createServer } from '../src/server.js';

function memRegistry() {
  const m = new Map();
  return {
    add: (pk, sub) => { m.set(pk, [...(m.get(pk) || []), sub]); return true; },
    remove: (pk) => { m.delete(pk); return true; },
    get: (pk) => m.get(pk) || [],
    pubkeys: () => [...m.keys()],
    _m: m,
  };
}
function keypair() {
  const sk = schnorr.utils.randomPrivateKey();
  return { sk, pk: bytesToHex(schnorr.getPublicKey(sk)) };
}
async function listen(server) {
  await new Promise((r) => server.listen(0, r));
  return `http://127.0.0.1:${server.address().port}`;
}

test('GET /vapidPublicKey returns the configured key', async () => {
  const server = createServer({ registry: memRegistry(), vapidPublicKey: 'VKEY', verify: () => true, onRegister: () => {} });
  const base = await listen(server);
  after(() => server.close());
  const res = await fetch(`${base}/vapidPublicKey`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { key: 'VKEY' });
});

test('POST /register stores a validly-signed subscription and watches the pubkey', async () => {
  const registry = memRegistry();
  const watched = [];
  const server = createServer({
    registry, vapidPublicKey: 'V',
    verify: ({ pubkey, action, endpoint, sig }) => {
      try { return schnorr.verify(sig, registrationDigest(action, pubkey, endpoint), pubkey); } catch { return false; }
    },
    onRegister: (pk) => watched.push(pk),
  });
  const base = await listen(server);
  after(() => server.close());

  const { sk, pk } = keypair();
  const endpoint = 'https://push/abc';
  const sig = bytesToHex(schnorr.sign(registrationDigest('register', pk, endpoint), sk));
  const res = await fetch(`${base}/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pubkey: pk, subscription: { endpoint, keys: {} }, sig }),
  });
  assert.equal(res.status, 200);
  assert.deepEqual(registry.get(pk), [{ endpoint, keys: {} }]);
  assert.deepEqual(watched, [pk]);
});

test('POST /register with a bad signature is rejected 401 and stores nothing', async () => {
  const registry = memRegistry();
  const server = createServer({ registry, vapidPublicKey: 'V', verify: () => false, onRegister: () => {} });
  const base = await listen(server);
  after(() => server.close());
  const res = await fetch(`${base}/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pubkey: 'pk', subscription: { endpoint: 'e', keys: {} }, sig: 'bad' }),
  });
  assert.equal(res.status, 401);
  assert.deepEqual(registry.pubkeys(), []);
});

test('POST /unregister removes a validly-signed subscription', async () => {
  const registry = memRegistry();
  registry.add('pk', { endpoint: 'e', keys: {} });
  const server = createServer({ registry, vapidPublicKey: 'V', verify: () => true, onRegister: () => {} });
  const base = await listen(server);
  after(() => server.close());
  const res = await fetch(`${base}/unregister`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pubkey: 'pk', endpoint: 'e', sig: 'ok' }),
  });
  assert.equal(res.status, 200);
  assert.deepEqual(registry.pubkeys(), []);
});
```

- [ ] **Step 2: Eseguire → deve fallire**

Run (da `push_bridge`):
```bash
node --test test/server.test.js 2>&1 | tail -15
```
Expected: FAIL — cannot find `../src/server.js`.

- [ ] **Step 3: Implementare il server**

Create `push_bridge/src/server.js`:

```js
// server.js — the bridge's small HTTP API. Hands out the VAPID public key and
// accepts signed register/unregister requests. All crypto (verify) and state
// (registry) are injected so this stays a thin, testable request router.
import { createServer as httpCreateServer } from 'node:http';

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function send(res, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
  res.end(JSON.stringify(obj));
}

/**
 * @param {object} deps
 * @param {object} deps.registry Registry (add/remove/get/pubkeys)
 * @param {string} deps.vapidPublicKey
 * @param {(r:object)=>boolean} deps.verify verifyRegistration
 * @param {(pubkey:string)=>void} deps.onRegister called after a successful register (e.g. watch it)
 * @returns {import('node:http').Server}
 */
export function createServer({ registry, vapidPublicKey, verify, onRegister }) {
  return httpCreateServer(async (req, res) => {
    try {
      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type',
        });
        return res.end();
      }
      if (req.method === 'GET' && req.url === '/vapidPublicKey') {
        return send(res, 200, { key: vapidPublicKey });
      }
      if (req.method === 'POST' && req.url === '/register') {
        const { pubkey, subscription, sig } = await readJson(req);
        if (!pubkey || !subscription?.endpoint || !sig) return send(res, 400, { error: 'bad request' });
        if (!verify({ pubkey, action: 'register', endpoint: subscription.endpoint, sig })) return send(res, 401, { error: 'bad signature' });
        registry.add(pubkey, subscription);
        onRegister(pubkey);
        return send(res, 200, { ok: true });
      }
      if (req.method === 'POST' && req.url === '/unregister') {
        const { pubkey, endpoint, sig } = await readJson(req);
        if (!pubkey || !endpoint || !sig) return send(res, 400, { error: 'bad request' });
        if (!verify({ pubkey, action: 'unregister', endpoint, sig })) return send(res, 401, { error: 'bad signature' });
        registry.remove(pubkey, endpoint);
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { error: 'not found' });
    } catch (e) {
      return send(res, 500, { error: String(e?.message || e) });
    }
  });
}
```

- [ ] **Step 4: Eseguire → deve passare**

Run (da `push_bridge`):
```bash
node --test test/server.test.js 2>&1 | tail -15
```
Expected: PASS (4 test).

- [ ] **Step 5: Implementare il sender web-push e l'entrypoint**

Create `push_bridge/src/web-push-sender.js`:

```js
// web-push-sender.js — thin wrapper over the `web-push` library. Sends an EMPTY,
// VAPID-signed push (the Web Push encryption still applies) whose only job is to
// wake the device; the content stays E2E and is never here.
import webpush from 'web-push';

export function makeSender({ subject, publicKey, privateKey }) {
  webpush.setVapidDetails(subject, publicKey, privateKey);
  return (subscription) => webpush.sendNotification(subscription, '', { TTL: 60 });
}
```

Create `push_bridge/index.js`:

```js
// index.js — entrypoint. Wires the registry, HTTP API, relay listener and
// dispatcher from environment config, then starts listening. Blind + stateless:
// the only persisted thing is the subscription registry.
import { Registry } from './src/registry.js';
import { verifyRegistration } from './src/signature.js';
import { Dispatcher } from './src/dispatcher.js';
import { RelayListener } from './src/relay-listener.js';
import { makeSender } from './src/web-push-sender.js';
import { createServer } from './src/server.js';

const {
  VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT = 'mailto:admin@styx.local',
  RELAYS = 'wss://relay.damus.io,wss://nos.lol',
  PORT = '8095', REGISTRY_FILE = './registry.json',
} = process.env;

if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  console.error('Set VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY (npx web-push generate-vapid-keys).');
  process.exit(1);
}

const registry = new Registry({ filePath: REGISTRY_FILE });
await registry.load();

const send = makeSender({ subject: VAPID_SUBJECT, publicKey: VAPID_PUBLIC_KEY, privateKey: VAPID_PRIVATE_KEY });
const dispatcher = new Dispatcher({ registry, send, now: () => Date.now() });

const listener = new RelayListener({
  relays: RELAYS.split(',').map((s) => s.trim()).filter(Boolean),
  onEvent: (pubkey) => dispatcher.notify(pubkey),
});
await listener.start(registry.pubkeys());

const server = createServer({
  registry,
  vapidPublicKey: VAPID_PUBLIC_KEY,
  verify: verifyRegistration,
  onRegister: (pubkey) => listener.watch(pubkey),
});
server.listen(Number(PORT), () => console.log(`[push-bridge] http on :${PORT}, watching ${registry.pubkeys().length} pubkeys`));
```

- [ ] **Step 6: Verifica avvio (senza VAPID → esce con messaggio chiaro)**

Run (da `push_bridge`):
```bash
node index.js 2>&1 | head -2
```
Expected: stampa il messaggio "Set VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY..." ed esce (exit 1). Questo prova che l'entrypoint carica senza errori di sintassi/import.

- [ ] **Step 7: Rieseguire tutti i test del bridge**

Run (da `push_bridge`):
```bash
node --test 2>&1 | tail -8
```
Expected: tutti i test del bridge verdi (registry + signature + dispatcher + relay-message + server).

- [ ] **Step 8: Commit**

```bash
cd /mnt/storage/home-mverde/src/Styx
git add push_bridge/src/web-push-sender.js push_bridge/src/server.js push_bridge/index.js push_bridge/test/server.test.js
git commit -m "feat(bridge): HTTP register/unregister API + web-push sender + entrypoint

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Client — PushRegistrar

**Files:**
- Create: `styx-js/src/push/push-registrar.js`
- Modify: `styx-js/src/index.js` (export `PushRegistrar`)
- Test: `styx-js/test/push/push-registrar.test.js`

**Interfaces:**
- Consumes: `chat.signBridgeRegistration(action, endpoint)` (Task 1) come callback `sign`.
- Produces: `class PushRegistrar { constructor({ bridgeUrl, pubkey, sign, fetchImpl, pushManager }); async enable(): Promise<boolean> }`. `sign(action, endpoint) -> Promise<string>` (sig hex). `pushManager.subscribe({...}) -> { toJSON(): {endpoint, keys} }`. Ritorna `false` se `bridgeUrl` è assente (opt-in), altrimenti l'esito del `POST /register`.
- Produces: `urlBase64ToUint8Array(base64: string) -> Uint8Array`.

- [ ] **Step 1: Scrivere il test (fallisce)**

Create `styx-js/test/push/push-registrar.test.js`:

```js
// test/push/push-registrar.test.js — the client fetches the VAPID key, subscribes
// via the browser pushManager, signs the registration with its Nostr key, and
// POSTs it to the bridge. With no bridge URL configured it must be a no-op.
import { describe, test, expect, jest } from '@jest/globals';
import { PushRegistrar, urlBase64ToUint8Array } from '../../src/push/push-registrar.js';

function harness() {
  const calls = [];
  const fetchImpl = jest.fn(async (url, opts) => {
    calls.push({ url, opts });
    if (url.endsWith('/vapidPublicKey')) return { ok: true, json: async () => ({ key: 'BPk_valid-base64url' }) };
    return { ok: true, json: async () => ({ ok: true }) };
  });
  const pushManager = { subscribe: jest.fn(async () => ({ toJSON: () => ({ endpoint: 'https://push/xyz', keys: { p256dh: 'a', auth: 'b' } }) })) };
  const sign = jest.fn(async (action, endpoint) => `sig(${action},${endpoint})`);
  return { calls, fetchImpl, pushManager, sign };
}

describe('PushRegistrar', () => {
  test('is a no-op (returns false) when no bridgeUrl is configured', async () => {
    const { fetchImpl, pushManager, sign } = harness();
    const r = new PushRegistrar({ bridgeUrl: '', pubkey: 'pk', sign, fetchImpl, pushManager });
    expect(await r.enable()).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(pushManager.subscribe).not.toHaveBeenCalled();
  });

  test('subscribes and POSTs a signed registration to the bridge', async () => {
    const { calls, fetchImpl, pushManager, sign } = harness();
    const r = new PushRegistrar({ bridgeUrl: 'https://bridge', pubkey: 'pk', sign, fetchImpl, pushManager });
    expect(await r.enable()).toBe(true);

    expect(pushManager.subscribe).toHaveBeenCalledWith(expect.objectContaining({ userVisibleOnly: true }));
    expect(sign).toHaveBeenCalledWith('register', 'https://push/xyz');

    const post = calls.find((c) => c.url === 'https://bridge/register');
    expect(post).toBeTruthy();
    const body = JSON.parse(post.opts.body);
    expect(body.pubkey).toBe('pk');
    expect(body.subscription.endpoint).toBe('https://push/xyz');
    expect(body.sig).toBe('sig(register,https://push/xyz)');
  });
});

describe('urlBase64ToUint8Array', () => {
  test('decodes a URL-safe base64 VAPID key to bytes', () => {
    const out = urlBase64ToUint8Array('AAAA'); // 3 zero bytes
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.length).toBe(3);
    expect([...out]).toEqual([0, 0, 0]);
  });
});
```

- [ ] **Step 2: Eseguire → deve fallire**

Run (da `styx-js`):
```bash
node --experimental-vm-modules node_modules/.bin/jest test/push/push-registrar.test.js --forceExit
```
Expected: FAIL — cannot find `../../src/push/push-registrar.js`.

- [ ] **Step 3: Implementare il PushRegistrar**

Create `styx-js/src/push/push-registrar.js`:

```js
// push-registrar.js — client side of Web Push. Subscribes via the browser
// pushManager, signs the registration with the Nostr identity (via the injected
// `sign` callback so the secret stays inside StyxChat), and registers with the
// bridge. Opt-in: with no bridgeUrl it does nothing and the app is unaffected.

/** Decode a URL-safe base64 VAPID key into the bytes pushManager wants. */
export function urlBase64ToUint8Array(base64) {
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const b64 = (base64 + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

export class PushRegistrar {
  /**
   * @param {object} deps
   * @param {string} deps.bridgeUrl base URL of the push bridge ('' → disabled)
   * @param {string} deps.pubkey our hex Nostr pubkey
   * @param {(action:string, endpoint:string)=>Promise<string>} deps.sign schnorr signer
   * @param {typeof fetch} deps.fetchImpl
   * @param {PushManager} deps.pushManager
   */
  constructor({ bridgeUrl, pubkey, sign, fetchImpl, pushManager }) {
    this._bridgeUrl = bridgeUrl;
    this._pubkey = pubkey;
    this._sign = sign;
    this._fetch = fetchImpl;
    this._pm = pushManager;
  }

  /** @returns {Promise<boolean>} whether a registration was sent + accepted. */
  async enable() {
    if (!this._bridgeUrl) return false; // opt-in: no bridge configured
    const keyRes = await this._fetch(`${this._bridgeUrl}/vapidPublicKey`);
    const { key } = await keyRes.json();
    const sub = await this._pm.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(key),
    });
    const json = sub.toJSON();
    const sig = await this._sign('register', json.endpoint);
    const res = await this._fetch(`${this._bridgeUrl}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pubkey: this._pubkey, subscription: json, sig }),
    });
    return !!res.ok;
  }
}
```

- [ ] **Step 4: Eseguire → deve passare**

Run (da `styx-js`):
```bash
node --experimental-vm-modules node_modules/.bin/jest test/push/push-registrar.test.js --forceExit
```
Expected: PASS (3 test).

- [ ] **Step 5: Esportare dall'index**

In `styx-js/src/index.js`, add after the `registrationDigest` export:

```js
export { PushRegistrar } from './push/push-registrar.js';
```

- [ ] **Step 6: Commit**

```bash
cd /mnt/storage/home-mverde/src/Styx
git add styx-js/src/push/push-registrar.js styx-js/src/index.js styx-js/test/push/push-registrar.test.js
git commit -m "feat(push): client PushRegistrar (subscribe + signed bridge registration)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: App — SW push handler + config + wiring

**Files:**
- Modify: `styx-js/apps/chat/src/lib/notify.js` (esporta `NOTIFICATION`)
- Modify: `styx-js/apps/chat/src/sw.js` (handler `push`)
- Modify: `styx-js/apps/chat/src/lib/config.js` (`getBridgeUrl`)
- Modify: `styx-js/apps/chat/src/hooks/useStyxChat.js` (`enablePush`)
- Modify: `styx-js/apps/chat/src/components/SettingsPanel.jsx`, `styx-js/apps/chat/src/App.jsx` (invocano `enablePush`)
- Test: `styx-js/apps/chat/test/notify-payload.test.js`, `styx-js/apps/chat/test/config-bridge.test.js`

**Interfaces:**
- Consumes: `PushRegistrar` (Task 7), `chat.signBridgeRegistration` (Task 1).
- Produces: `NOTIFICATION = { title:'Styx Chat', body:'Hai un nuovo messaggio', tag:'styx-new' }` (esportato da `notify.js`).
- Produces: `getBridgeUrl() -> string` ('' se non configurato).
- Produces: hook API `enablePush(): Promise<boolean>`.

- [ ] **Step 1: Scrivere i test (falliscono)**

Create `styx-js/apps/chat/test/notify-payload.test.js`:

```js
// test/notify-payload.test.js — the notification shown (locally AND on a push)
// is the single generic payload; it must never carry content or a sender.
import { describe, test, expect } from '@jest/globals';
import { NOTIFICATION } from '../src/lib/notify.js';

describe('NOTIFICATION payload', () => {
  test('is the generic, content-free notification', () => {
    expect(NOTIFICATION).toEqual({ title: 'Styx Chat', body: 'Hai un nuovo messaggio', tag: 'styx-new' });
  });
});
```

Create `styx-js/apps/chat/test/config-bridge.test.js`:

```js
// test/config-bridge.test.js — the bridge URL is opt-in: read from ?bridge= (or a
// build-time default), '' when absent. Pure parser so it's testable without a DOM.
import { describe, test, expect } from '@jest/globals';
import { parseBridgeUrl } from '../src/lib/config.js';

describe('parseBridgeUrl', () => {
  test('reads the bridge param from a query string', () => {
    expect(parseBridgeUrl('?bridge=https://b.example')).toBe('https://b.example');
  });
  test('strips a trailing slash', () => {
    expect(parseBridgeUrl('?bridge=https://b.example/')).toBe('https://b.example');
  });
  test('returns the fallback when no param is present', () => {
    expect(parseBridgeUrl('', 'https://default.example')).toBe('https://default.example');
    expect(parseBridgeUrl('')).toBe('');
  });
});
```

- [ ] **Step 2: Eseguire → devono fallire**

Run (da `styx-js`):
```bash
node --experimental-vm-modules node_modules/.bin/jest apps/chat/test/notify-payload.test.js apps/chat/test/config-bridge.test.js --forceExit
```
Expected: FAIL — `NOTIFICATION`/`parseBridgeUrl` non esportati.

- [ ] **Step 3: Esportare `NOTIFICATION` da notify.js e usarla**

In `styx-js/apps/chat/src/lib/notify.js`, replace the three private constants
```js
const TITLE = 'Styx Chat';
const BODY = 'Hai un nuovo messaggio'; // generic on purpose — content stays E2E
const TAG = 'styx-new';
```
with a single exported constant:

```js
// Single generic payload for BOTH the local notifier and the service-worker push
// handler. Generic on purpose — content stays E2E, never shown in a notification.
export const NOTIFICATION = { title: 'Styx Chat', body: 'Hai un nuovo messaggio', tag: 'styx-new' };
```

Then in the same file update `createNotifier`'s `show(...)` call to use it:
```js
      show({ title: NOTIFICATION.title, body: NOTIFICATION.body, tag: NOTIFICATION.tag });
```
and in `browserNotifier`, the `show` wrapper already receives `{title, body, tag}` — no change needed there.

- [ ] **Step 4: Aggiungere `parseBridgeUrl` + `getBridgeUrl` a config.js**

In `styx-js/apps/chat/src/lib/config.js`, append:

```js
/**
 * Parse the opt-in bridge URL from a query string. Pure (no window) for testing.
 * @param {string} search e.g. '?bridge=https://b'
 * @param {string} [fallback] build-time default
 * @returns {string} bridge base URL, '' when unset
 */
export function parseBridgeUrl(search, fallback = '') {
  try {
    const v = new URLSearchParams(search).get('bridge');
    return (v || fallback).replace(/\/$/, '');
  } catch {
    return fallback.replace(/\/$/, '');
  }
}

/** The bridge URL for this session: ?bridge=… or the build-time VITE_BRIDGE_URL. */
export function getBridgeUrl() {
  const fallback = (import.meta.env && import.meta.env.VITE_BRIDGE_URL) || '';
  try { return parseBridgeUrl(window.location.search, fallback); } catch { return ''; }
}
```

- [ ] **Step 5: Eseguire i due unit test → devono passare**

Run (da `styx-js`):
```bash
node --experimental-vm-modules node_modules/.bin/jest apps/chat/test/notify-payload.test.js apps/chat/test/config-bridge.test.js --forceExit
```
Expected: PASS (4 test).

- [ ] **Step 6: Riempire l'handler `push` della service worker**

In `styx-js/apps/chat/src/sw.js`, replace the no-op push listener
```js
// Phase 2 fills this in: show a generic notification on a Web Push. No-op for now.
self.addEventListener('push', () => {});
```
with:

```js
// Show the single generic notification on a Web Push wake-up. The payload is
// empty by design (content stays E2E); we never read event.data.
self.addEventListener('push', (event) => {
  event.waitUntil(
    self.registration.showNotification('Styx Chat', { body: 'Hai un nuovo messaggio', tag: 'styx-new' }),
  );
});
```

(The SW is bundled by vite-plugin-pwa but cannot import app modules that pull in the DOM at eval time; the copy is inlined here and unit-covered via `NOTIFICATION` — keep the two in sync: both say "Hai un nuovo messaggio".)

- [ ] **Step 7: Aggiungere `enablePush` all'hook**

In `styx-js/apps/chat/src/hooks/useStyxChat.js`:

(a) add imports after the `browserNotifier` import:
```js
import { PushRegistrar } from 'styx-js';
import { getBridgeUrl } from '../lib/config.js';
```

(b) add an action, defined after the `markRead` callback (around line 157), that builds a registrar and enables push (best-effort, opt-in):
```js
  const enablePush = useCallback(async () => {
    const chat = chatRef.current;
    if (!chat) return false;
    const bridgeUrl = getBridgeUrl();
    if (!bridgeUrl) return false;
    if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return false;
    if (!('serviceWorker' in navigator)) return false;
    try {
      const reg = await navigator.serviceWorker.ready;
      const registrar = new PushRegistrar({
        bridgeUrl,
        pubkey: chat.me.pubkey,
        sign: (action, endpoint) => chat.signBridgeRegistration(action, endpoint),
        fetchImpl: (...a) => fetch(...a),
        pushManager: reg.pushManager,
      });
      return await registrar.enable();
    } catch (e) {
      console.debug('enablePush failed', e);
      return false;
    }
  }, []);
```

(c) enable push automatically right after a successful unlock — inside the `unlock` callback, after `setReady(true);` and before `return chat.me || identity;`, add:
```js
    // Opt-in: if a bridge is configured and permission is already granted, register.
    enablePush();
```
Note on ordering: declare the whole `enablePush` `useCallback` block **immediately before** the `unlock` `useCallback` so the `const` is initialized before `unlock` closes over it. `enablePush` is referentially stable (empty deps) — do NOT add it to `unlock`'s dependency array.

(d) expose it in the returned object — add `enablePush` to the final `return { ... }`:
```js
    setAlias, enablePush, ...pairing,
```

- [ ] **Step 8: Invocare `enablePush` dopo la concessione del permesso in Impostazioni**

In `styx-js/apps/chat/src/App.jsx`, pass the hook action to `SettingsPanel` — add a prop in the `modal === 'settings'` block:
```jsx
          onEnablePush={chat.enablePush}
```

In `styx-js/apps/chat/src/components/SettingsPanel.jsx`:

(a) add `onEnablePush` to the destructured props:
```js
export default function SettingsPanel({ me, contacts, onClose, onSetAlias, onRemoveContact, onLock, onReset, onToast, onEnablePush }) {
```

(b) in `enableNotifications`, after `setNotifPerm(p);`, register with the bridge if granted:
```js
    if (p === 'granted') { try { await onEnablePush?.(); } catch { /* best-effort */ } }
```

- [ ] **Step 9: Verifica build + tutti i test app**

Run (da `styx-js/apps/chat`):
```bash
npm run build
```
Expected: build ok; `dist/sw.js` presente e contiene `showNotification` (grep di controllo):
```bash
grep -c "showNotification" dist/sw.js   # atteso: > 0
```

Run (da `styx-js`):
```bash
node --experimental-vm-modules node_modules/.bin/jest apps/chat/test --forceExit
```
Expected: tutti i test app verdi (manifest, notify, install-hint, notify-payload, config-bridge).

- [ ] **Step 10: Non-regressione e2e (il SW resta valido, l'app carica offline)**

Run (da `styx-js/apps/chat`):
```bash
PW_EXECUTABLE="$(ls ~/.cache/ms-playwright/chromium-*/chrome-linux/chrome 2>/dev/null | head -1)" npm run test:e2e:pwa
```
Expected: 1 test PASS.

- [ ] **Step 11: Commit**

```bash
cd /mnt/storage/home-mverde/src/Styx
git add styx-js/apps/chat/src/lib/notify.js styx-js/apps/chat/src/sw.js styx-js/apps/chat/src/lib/config.js \
  styx-js/apps/chat/src/hooks/useStyxChat.js styx-js/apps/chat/src/components/SettingsPanel.jsx styx-js/apps/chat/src/App.jsx \
  styx-js/apps/chat/test/notify-payload.test.js styx-js/apps/chat/test/config-bridge.test.js
git commit -m "feat(chat): wire Web Push — SW handler, bridge config, opt-in registration

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Verifica finale (Fase 2)

- [ ] **Bridge (da `push_bridge`):** `node --test` → tutti verdi (registry, signature, dispatcher, relay-message, server).
- [ ] **Client push (da `styx-js`):** `node --experimental-vm-modules node_modules/.bin/jest test/push --forceExit` → verdi (digest, sign, registrar).
- [ ] **App (da `styx-js`):** `node --experimental-vm-modules node_modules/.bin/jest apps/chat/test --forceExit` → verdi.
- [ ] **E2E offline (da `styx-js/apps/chat`):** `PW_EXECUTABLE=… npm run test:e2e:pwa` → PASS.
- [ ] **Manuale (dispositivo reale):** generare le chiavi VAPID (`npx web-push generate-vapid-keys`), avviare il bridge dietro un hostname pubblico (tunnel Cloudflare), aprire la PWA installata con `?bridge=https://<bridge-host>`, concedere il permesso da Impostazioni; chiudere l'app; da un secondo device inviare un messaggio → arriva la notifica "Hai un nuovo messaggio"; tap → apre la PWA che decifra E2E. Verificare anche che un invito (welcome) produca la stessa notifica.

## Note

- **Multi-device:** una pubkey può avere più subscription (una per device); il bridge le sveglia tutte (già gestito dal registro + dispatcher).
- **Deploy:** il bridge è un secondo processo sempre-acceso; esporlo via un hostname/tunnel distinto da quello dell'app statica. HTTPS obbligatorio (Web Push lo richiede).
- **Follow-up non in questo piano:** rotazione/scadenza subscription lato bridge oltre il 410; rate-limit per pubkey; interruttore privacy per disattivare le push da UI; `unregister` chiamato al logout/blocco dell'app.
