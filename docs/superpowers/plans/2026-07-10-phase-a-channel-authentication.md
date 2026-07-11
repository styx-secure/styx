# Phase A — Channel Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the channel-authentication vulnerabilities (C1, C2, C3, H3, M1, M2, M3) in `styx-js` so an active network adversary can no longer read messages or impersonate a peer, and any MITM at pairing becomes impossible or detectable.

**Architecture:** The trust anchor is the QR invite (scanned in person), reinforced by a spoken safety number — the Signal model, no new cryptography. Six defences: (A1) verify inbound Nostr signatures so the sender pubkey is *proven* not *relay-suggested*; (A2) bind the `welcome` to a 32-byte nonce that lives only in the QR, via HMAC, single-use; (A3) never let a network message overwrite an existing MLS session; (A4) a valid `welcome` creates a *pending* pairing that only becomes a contact through an explicit `confirmPairing()`, and the alias travels inside MLS instead of in cleartext; (A5) expose a `safetyNumber(pubkey)` derived from the MLS group export key; (A6) refuse to build the unauthenticated `BroadcastChannelTransport` unless an explicit dev opt-in is passed.

**Tech Stack:** Pure ESM JavaScript, `@noble/curves` (schnorr/secp256k1), `@noble/hashes` (sha256, hmac), OpenMLS-WASM (already vendored — no rebuild). Tests: Jest (`node --experimental-vm-modules`). App: React + Vite, Playwright e2e.

## Global Constraints

- Language of code, identifiers, comments, commit messages: **English**. (Conversation with the user is Italian, but that does not apply to source.)
- Node ≥ 18, ESM only (`"type":"module"`); no TypeScript source (JSDoc types only).
- Run the library suite from `styx-js/` with `npm test` (alias for `node --experimental-vm-modules node_modules/.bin/jest --forceExit`). A single file: `npm test -- test/<path>.test.js`.
- Never weaken or delete an existing passing assertion to make a new one pass; if a behaviour legitimately changes (A4 removes auto-roster-add), update the affected test to assert the *new* correct behaviour and say so in the commit.
- Crypto imports follow the existing convention: `import { schnorr } from '@noble/curves/secp256k1';`, `import { sha256 } from '@noble/hashes/sha256';`. Add `import { hmac } from '@noble/hashes/hmac';` where needed.
- Constant-time comparison for any secret/MAC check uses the existing `constantTimeEqual` from `src/utils.js`.
- Conventional Commits. Commit after each task. End every commit message with the `Co-Authored-By` trailer.
- Do NOT rebuild or modify `vendor/openmls-wasm/`. Everything here is JS over the already-exposed WASM surface (`Group.export_key`, `Group.join`, etc.).

---

### Task 1: A1 — Verify inbound Nostr event signatures

**Rationale:** Today `NostrChatTransport._onRelay` passes `ev.pubkey` to the handler without checking that the relay didn't fabricate it. This one change turns `from` from a relay-supplied hint into a cryptographically proven identity — every other defence builds on it.

**Files:**
- Modify: `styx-js/src/transport/nostr-chat-transport.js`
- Test: `styx-js/test/transport/nostr-chat-transport-verify.test.js` (create)

**Interfaces:**
- Consumes: existing `_sign(event)` (NIP-01 id + schnorr sig), `schnorr`, `sha256`, `bytesToHex`, `hexToBytes`, `utf8Encode`.
- Produces: `NostrChatTransport` now drops events that fail id-recompute or schnorr verification before invoking the handler; exposes a read-only `rejectedCount` getter (diagnostic).

- [ ] **Step 1: Write the failing test**

Create `styx-js/test/transport/nostr-chat-transport-verify.test.js`:

```javascript
// test/transport/nostr-chat-transport-verify.test.js
// A1: the transport must verify the NIP-01 id + schnorr signature of every
// inbound event and drop anything that fails, so `from` is a proven identity.
import { describe, test, expect, jest } from '@jest/globals';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { NostrChatTransport } from '../../src/transport/nostr-chat-transport.js';
import { bytesToHex, utf8Encode } from '../../src/utils.js';

function signedEvent(sk, pk, toPk, content) {
  const event = {
    kind: 1059, pubkey: pk, created_at: Math.floor(Date.now() / 1000),
    tags: [['p', toPk]], content,
  };
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  const id = sha256(utf8Encode(serialized));
  event.id = bytesToHex(id);
  event.sig = bytesToHex(schnorr.sign(id, sk));
  return event;
}

function makeTransport(pk) {
  // Bypass the real RelayPool: construct then stub the pool so no sockets open.
  const t = Object.create(NostrChatTransport.prototype);
  t._pk = pk;
  t._seen = new Set();
  t._rejected = 0;
  t._handler = null;
  return t;
}

describe('NostrChatTransport A1 signature verification', () => {
  const meSk = schnorr.utils.randomPrivateKey();
  const mePk = bytesToHex(schnorr.getPublicKey(meSk));
  const senderSk = schnorr.utils.randomPrivateKey();
  const senderPk = bytesToHex(schnorr.getPublicKey(senderSk));

  test('delivers a correctly signed event addressed to us', () => {
    const t = makeTransport(mePk);
    const cb = jest.fn();
    t.onMessage(cb);
    const ev = signedEvent(senderSk, senderPk, mePk, 'aGVsbG8=');
    t._onRelay(['EVENT', 'sub', ev]);
    expect(cb).toHaveBeenCalledTimes(1);
    expect(cb.mock.calls[0][0]).toBe(senderPk);
  });

  test('drops an event whose signature does not match its pubkey (relay forgery)', () => {
    const t = makeTransport(mePk);
    const cb = jest.fn();
    t.onMessage(cb);
    const ev = signedEvent(senderSk, senderPk, mePk, 'aGVsbG8=');
    ev.pubkey = bytesToHex(schnorr.getPublicKey(schnorr.utils.randomPrivateKey())); // claim someone else
    t._onRelay(['EVENT', 'sub', ev]);
    expect(cb).not.toHaveBeenCalled();
    expect(t.rejectedCount).toBe(1);
  });

  test('drops an event whose content was tampered after signing', () => {
    const t = makeTransport(mePk);
    const cb = jest.fn();
    t.onMessage(cb);
    const ev = signedEvent(senderSk, senderPk, mePk, 'aGVsbG8=');
    ev.content = 'dGFtcGVyZWQ='; // id no longer matches
    t._onRelay(['EVENT', 'sub', ev]);
    expect(cb).not.toHaveBeenCalled();
    expect(t.rejectedCount).toBe(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd styx-js && npm test -- test/transport/nostr-chat-transport-verify.test.js`
Expected: FAIL — forged/tampered events are still delivered (`cb` called) and `rejectedCount` is undefined.

- [ ] **Step 3: Implement verification in `_onRelay`**

In `styx-js/src/transport/nostr-chat-transport.js`, add the hmac-free imports already present, then add a private verify helper and call it. Add `hexToBytes` to the utils import line:

```javascript
import { bytesToHex, hexToBytes, bytesToBase64, base64ToBytes, utf8Encode, uuidv4 } from '../utils.js';
```

Initialise the counter in the constructor (after `this._seen = new Set();`):

```javascript
    this._rejected = 0; // events dropped by signature/id verification (A1 diagnostic)
```

Add a getter after the constructor:

```javascript
  /** Number of inbound events dropped by A1 verification (diagnostic). */
  get rejectedCount() { return this._rejected; }

  /**
   * @private Recompute the NIP-01 id and verify the schnorr signature.
   * @param {object} ev a raw Nostr event
   * @returns {boolean} true iff id matches its canonical serialization AND sig verifies
   */
  _verifyEvent(ev) {
    if (!ev || typeof ev.id !== 'string' || typeof ev.sig !== 'string' || typeof ev.pubkey !== 'string') {
      return false;
    }
    let idBytes;
    try {
      const serialized = JSON.stringify([
        0, ev.pubkey, ev.created_at, ev.kind, ev.tags || [], ev.content,
      ]);
      idBytes = sha256(utf8Encode(serialized));
      if (bytesToHex(idBytes) !== ev.id) return false; // id must bind the content
      return schnorr.verify(hexToBytes(ev.sig), idBytes, hexToBytes(ev.pubkey));
    } catch {
      return false; // malformed hex / bad lengths → reject
    }
  }
```

In `_onRelay`, add the verification right after the `addressedToUs` check and before the dedup block:

```javascript
    const addressedToUs = (ev.tags || []).some((t) => t[0] === 'p' && t[1] === this._pk);
    if (!addressedToUs) return;
    // A1: the relay is untrusted. Prove the event is genuinely from ev.pubkey and
    // its content is intact before the handler treats `from` as an identity.
    if (!this._verifyEvent(ev)) { this._rejected += 1; return; }
```

- [ ] **Step 4: Run the new test and the existing transport tests**

Run: `cd styx-js && npm test -- test/transport/nostr-chat-transport-verify.test.js`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add styx-js/src/transport/nostr-chat-transport.js styx-js/test/transport/nostr-chat-transport-verify.test.js
git commit -m "feat(transport): verify inbound Nostr id+signature (Phase A, A1)

Close C1: NostrChatTransport recomputes the NIP-01 id and verifies the
schnorr signature of every event before delivery, dropping forgeries and
tampered payloads. Adds a rejectedCount diagnostic.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: A3 — Never overwrite an established MLS session

**Rationale:** C2 — a `welcome` (or a second one) silently replaces an existing session, enabling an undetectable MITM even mid-conversation. Session replacement must not be reachable from the network; recreating a session must be an explicit local action (`removeContact` then re-pair).

**Files:**
- Modify: `styx-js/src/crypto/mls/mls-engine.js`
- Modify: `styx-js/src/chat/styx-chat.js`
- Test: `styx-js/test/chat/styx-chat-no-overwrite.test.js` (create)

**Interfaces:**
- Consumes: `MlsEngine.joinSession(contactId, welcomeBytes, ratchetTreeBytes)`, `StyxChat._onWire`, `this._groups`.
- Produces: `MlsEngine.joinSession` throws `Error('MlsEngine: session already exists for <id>')` when `this._sessions.has(contactId)`; `StyxChat._onWire` ignores a `welcome` for a `from` that already has a group and never calls `joinSession` twice.

- [ ] **Step 1: Write the failing test**

Create `styx-js/test/chat/styx-chat-no-overwrite.test.js`:

```javascript
// test/chat/styx-chat-no-overwrite.test.js
// A3: a second welcome for an already-established contact must not replace the
// session (that is the C2 silent-MITM vector).
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

describe('MlsEngine A3 no-overwrite', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('joinSession throws if a session for the contact already exists', async () => {
    const inviter = await MlsEngine.create({ name: 'inviter' });
    const joiner = await MlsEngine.create({ name: 'joiner' });
    const kp = joiner.keyPackageBytes();
    const { welcome, ratchetTree } = inviter.startSession('peer', kp);

    joiner.joinSession('peer', welcome, ratchetTree);
    expect(() => joiner.joinSession('peer', welcome, ratchetTree))
      .toThrow(/already exists/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd styx-js && npm test -- test/chat/styx-chat-no-overwrite.test.js`
Expected: FAIL — the second `joinSession` currently succeeds and replaces the session.

- [ ] **Step 3: Guard `joinSession` in the engine**

In `styx-js/src/crypto/mls/mls-engine.js`, at the top of `joinSession`, before `Group.join`:

```javascript
  joinSession(contactId, welcomeBytes, ratchetTreeBytes) {
    if (this._sessions.has(contactId)) {
      throw new Error(`MlsEngine: session already exists for ${contactId}`);
    }
    const group = Group.join(
```

- [ ] **Step 4: Guard the welcome branch in `StyxChat._onWire`**

In `styx-js/src/chat/styx-chat.js`, replace the `welcome` branch body so it refuses when a group already exists (keep the rest of the branch for now; A4 rewrites the roster part):

```javascript
    if (env.t === 'welcome') {
      // A3: a welcome must never replace an established session. Re-pairing is an
      // explicit local action (removeContact + new invite), never network-driven.
      if (this._groups[from] || this._engine.session(from)) return;
      this._engine.joinSession(from, base64ToBytes(env.welcome), base64ToBytes(env.tree));
      if (env.groupId) this._groups[from] = env.groupId;
      await this._persistMls();
      if (!(await this._roster.get(from))) {
        await this._roster.add({ pubkey: from, alias: env.from?.alias || from });
      }
      await this._drainPending(from); // messages that arrived before this Welcome
      return;
    }
```

- [ ] **Step 5: Run the new test plus the full chat suite**

Run: `cd styx-js && npm test -- test/chat/styx-chat-no-overwrite.test.js test/chat/styx-chat.test.js test/chat/styx-chat-assembly.test.js`
Expected: PASS. (Existing pairing tests still pass — the first welcome is unaffected; only a *second* one for the same peer is ignored.)

- [ ] **Step 6: Commit**

```bash
git add styx-js/src/crypto/mls/mls-engine.js styx-js/src/chat/styx-chat.js styx-js/test/chat/styx-chat-no-overwrite.test.js
git commit -m "feat(mls): refuse to overwrite an established session (Phase A, A3)

Close C2 (overwrite path): MlsEngine.joinSession throws if a session for
the contact already exists, and StyxChat ignores a welcome for a peer that
already has a group. Re-pairing must go through removeContact.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: A2 — Bind the welcome to a single-use QR nonce (HMAC)

**Rationale:** M3 + the pairing half of C2 — without proof that the joiner actually saw the inviter's screen, an active adversary can inject a `welcome` during pairing. A 32-byte nonce that exists only in the QR (and the inviter's memory) fixes this: the joiner must MAC the welcome material with it, and the inviter verifies and consumes the nonce.

**Files:**
- Modify: `styx-js/src/chat/styx-chat.js`
- Test: `styx-js/test/chat/styx-chat-invite-nonce.test.js` (create)

**Interfaces:**
- Consumes: `createQrInvite()`, `acceptQrInvite(qr)`, `_onWire` welcome branch, `randomBytes`, `constantTimeEqual`, `concatBytes`, `utf8Encode`, `bytesToBase64`, `base64ToBytes`, `hmac`, `sha256`.
- Produces:
  - The invite payload gains `nonce` (base64 of 32 random bytes). `createQrInvite` stores it as `this._inviteNonce` (single outstanding invite).
  - The `welcome` envelope gains `hmac` = base64 of `HMAC-SHA256(nonce, welcome_bytes ‖ tree_bytes ‖ utf8(groupId))`, computed by the joiner in `acceptQrInvite`.
  - `_onWire` welcome branch rejects (returns without joining) when there is no pending invite nonce or the HMAC does not verify; on success it clears `this._inviteNonce` (single-use).

- [ ] **Step 1: Write the failing test**

Create `styx-js/test/chat/styx-chat-invite-nonce.test.js`:

```javascript
// test/chat/styx-chat-invite-nonce.test.js
// A2: the welcome must carry an HMAC over the nonce embedded in the QR. A
// welcome with a missing/forged HMAC, or arriving when no invite is pending,
// must be rejected; a valid one is single-use.
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';

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

// A bus that lets us capture/replay/mutate the raw frames on the wire.
function makeBus() {
  const handlers = new Map();
  return {
    handlers,
    transportFor(selfPubkey) {
      return {
        async send(toPubkey, bytes) {
          const h = handlers.get(toPubkey);
          if (h) queueMicrotask(() => h(selfPubkey, bytes));
        },
        onMessage(cb) { handlers.set(selfPubkey, cb); return () => handlers.delete(selfPubkey); },
      };
    },
  };
}

const flush = async () => { for (let i = 0; i < 6; i++) await new Promise((r) => setTimeout(r, 0)); };

async function peer(bus, pubkey, alias) {
  const engine = await MlsEngine.create({ name: pubkey });
  const roster = new ContactRoster({ backend: memBackend() });
  await roster.load();
  const chat = new StyxChat({ identity: { pubkey, alias }, engine, roster, transport: bus.transportFor(pubkey) });
  await chat.start();
  return chat;
}

describe('StyxChat A2 invite nonce binding', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('a genuine QR invite still pairs (happy path)', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a2', 'Bob');
    const alice = await peer(bus, 'alice_a2', 'Alice');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();
    expect(bob._engine.session('alice_a2')).toBeTruthy(); // bob joined
  });

  test('a welcome with a stripped HMAC is rejected (no session)', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a2b', 'Bob');
    const alice = await peer(bus, 'alice_a2b', 'Alice');
    const { qr } = await bob.createQrInvite();

    // Intercept the frame Alice sends to Bob and strip the hmac field.
    const realBobHandler = bus.handlers.get('bob_a2b');
    bus.handlers.set('bob_a2b', (from, bytes) => {
      const env = JSON.parse(new TextDecoder().decode(bytes));
      delete env.hmac;
      realBobHandler(from, new TextEncoder().encode(JSON.stringify(env)));
    });

    await alice.acceptQrInvite(qr);
    await flush();
    expect(bob._engine.session('alice_a2b')).toBeFalsy(); // bob refused to join
  });

  test('a welcome arriving with no pending invite is rejected', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a2c', 'Bob');
    const alice = await peer(bus, 'alice_a2c', 'Alice');
    const { qr } = await bob.createQrInvite();
    // Bob consumes his own invite nonce (simulating a prior successful pairing).
    bob._inviteNonce = null;
    await alice.acceptQrInvite(qr);
    await flush();
    expect(bob._engine.session('alice_a2c')).toBeFalsy();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd styx-js && npm test -- test/chat/styx-chat-invite-nonce.test.js`
Expected: FAIL — no nonce/HMAC yet, so the stripped-HMAC and no-pending-invite welcomes are still accepted.

- [ ] **Step 3: Add the imports and generate/store the nonce in `createQrInvite`**

In `styx-js/src/chat/styx-chat.js`, extend the utils import to include `concatBytes`, `constantTimeEqual`, `randomBytes` and add hmac/sha256 imports:

```javascript
import {
  bytesToHex, bytesToBase64, base64ToBytes, utf8Encode, utf8Decode, uuidv4, EventEmitter,
  concatBytes, constantTimeEqual, randomBytes,
} from '../utils.js';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
```

Add a private helper (place it in the `// ---- internals ----` section, near `_send`):

```javascript
  /** @private HMAC-SHA256(nonce, welcome ‖ tree ‖ utf8(groupId)) — the A2 pairing proof. */
  _welcomeMac(nonce, welcomeBytes, treeBytes, groupId) {
    return hmac(sha256, nonce, concatBytes(welcomeBytes, treeBytes, utf8Encode(String(groupId))));
  }
```

Rewrite `createQrInvite` to embed and store the nonce:

```javascript
  async createQrInvite() {
    // A2: a 32-byte nonce lives only in this QR and our memory. The joiner must
    // MAC the welcome with it, proving they actually saw this screen.
    const nonce = randomBytes(32);
    this._inviteNonce = nonce; // single outstanding invite; consumed on a valid welcome
    const payload = {
      pubkey: this._identity.pubkey,
      alias: this._identity.alias,
      kp: bytesToBase64(this._engine.keyPackageBytes()),
      nonce: bytesToBase64(nonce),
    };
    // Generating a KeyPackage stores its private key in the MLS provider; persist
    // it so the invite still works if we reload before the peer joins.
    await this._persistMls();
    return { qr: 'styx://invite/' + bytesToBase64(utf8Encode(JSON.stringify(payload))) };
  }
```

- [ ] **Step 4: Compute the HMAC in `acceptQrInvite`**

Rewrite the `_send` call inside `acceptQrInvite` to include the HMAC over the nonce from the invite:

```javascript
  async acceptQrInvite(qr) {
    const inv = JSON.parse(utf8Decode(base64ToBytes(String(qr).replace('styx://invite/', ''))));
    const { welcome, ratchetTree, groupId } = this._engine.startSession(inv.pubkey, base64ToBytes(inv.kp));
    this._groups[inv.pubkey] = groupId;
    await this._persistMls();
    // A2: prove we saw the inviter's QR by MAC'ing the welcome under its nonce.
    const nonce = inv.nonce ? base64ToBytes(inv.nonce) : new Uint8Array(0);
    const mac = this._welcomeMac(nonce, welcome, ratchetTree, groupId);
    await this._send(inv.pubkey, {
      t: 'welcome',
      from: { pubkey: this._identity.pubkey, alias: this._identity.alias },
      welcome: bytesToBase64(welcome),
      tree: bytesToBase64(ratchetTree),
      groupId,
      hmac: bytesToBase64(mac),
    });
    this._pendingAlias = { [inv.pubkey]: inv.alias };
    return { contactPubkey: inv.pubkey };
  }
```

- [ ] **Step 5: Verify the HMAC in the `_onWire` welcome branch**

Update the welcome branch (built on Task 2) to check the nonce/HMAC before joining and to consume the nonce on success:

```javascript
    if (env.t === 'welcome') {
      // A3: never replace an established session.
      if (this._groups[from] || this._engine.session(from)) return;
      // A2: require a pending invite whose nonce authenticates this welcome.
      if (!this._inviteNonce || !env.hmac) return;
      const welcomeBytes = base64ToBytes(env.welcome);
      const treeBytes = base64ToBytes(env.tree);
      const expected = this._welcomeMac(this._inviteNonce, welcomeBytes, treeBytes, env.groupId);
      if (!constantTimeEqual(expected, base64ToBytes(env.hmac))) return;
      this._inviteNonce = null; // single-use: burn the nonce
      this._engine.joinSession(from, welcomeBytes, treeBytes);
      if (env.groupId) this._groups[from] = env.groupId;
      await this._persistMls();
      if (!(await this._roster.get(from))) {
        await this._roster.add({ pubkey: from, alias: env.from?.alias || from });
      }
      await this._drainPending(from);
      return;
    }
```

- [ ] **Step 6: Run the new test plus the pairing suites**

Run: `cd styx-js && npm test -- test/chat/styx-chat-invite-nonce.test.js test/chat/styx-chat.test.js test/chat/styx-chat-assembly.test.js`
Expected: PASS. The existing happy-path pairing tests now exercise the nonce end-to-end (invite → HMAC → verify).

- [ ] **Step 7: Commit**

```bash
git add styx-js/src/chat/styx-chat.js styx-js/test/chat/styx-chat-invite-nonce.test.js
git commit -m "feat(chat): bind welcome to a single-use QR nonce via HMAC (Phase A, A2)

Close M3 and the pairing half of C2: the invite embeds a 32-byte nonce; the
joiner MACs the welcome under it; the inviter verifies and burns the nonce.
A welcome with no pending invite or a bad/missing HMAC is dropped.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: A4 — Explicit roster add, pending pairing, alias inside MLS

**Rationale:** M1 + M2 — today a valid `welcome` auto-adds the sender to the roster and trusts a cleartext alias. A `welcome` should only create a *pending* pairing surfaced to the user; it becomes a contact solely through `confirmPairing()`. The alias must not ride in cleartext — it travels as the first encrypted app message inside MLS, and is validated on receipt.

**Files:**
- Modify: `styx-js/src/chat/styx-chat.js`
- Test: `styx-js/test/chat/styx-chat-explicit-pairing.test.js` (create)
- Modify (behaviour change): `styx-js/test/chat/styx-chat.test.js`, `styx-js/test/chat/styx-chat-assembly.test.js`

**Interfaces:**
- Consumes: `_onWire` welcome/app branches, `_processApp`, `confirmPairing`, `_send`, the roster.
- Produces:
  - New event `pairing`: `onPairing(cb)` → `cb({ pubkey })` fires when a valid, authenticated welcome creates a pending pairing. Pending pairings live in `this._pending` (Map pubkey→{pubkey, alias?}).
  - The `welcome` envelope no longer carries `from.alias`; the welcome branch no longer calls `_roster.add`.
  - A new app payload type `{ t:'intro', alias }` is sent (encrypted) by both sides once a session exists; on receipt the alias is validated by `sanitizeAlias(raw)` and stored on the pending pairing (or applied to an existing contact).
  - `sanitizeAlias(raw)` (exported helper): trims, caps at 64 chars, strips C0/C1 control chars and Unicode bidi overrides (`‪–‮`, `⁦–⁩`), returns `''` if nothing valid remains.
  - `confirmPairing({ contactPubkey, alias })` unchanged signature; if `alias` is omitted it falls back to the pending pairing's introduced alias, else the pubkey. It also clears the pending entry.

- [ ] **Step 1: Write the failing test**

Create `styx-js/test/chat/styx-chat-explicit-pairing.test.js`:

```javascript
// test/chat/styx-chat-explicit-pairing.test.js
// A4: a welcome creates a pending pairing (not a contact); the contact only
// exists after confirmPairing. The alias arrives encrypted, not in cleartext,
// and is sanitized.
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat, sanitizeAlias } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);
function memBackend() {
  const m = new Map();
  return { async get(k) { return m.has(k) ? m.get(k) : null; }, async set(k, v) { m.set(k, v); }, async delete(k) { m.delete(k); } };
}
function makeBus() {
  const handlers = new Map();
  return { transportFor(pk) { return {
    async send(to, bytes) { const h = handlers.get(to); if (h) queueMicrotask(() => h(pk, bytes)); },
    onMessage(cb) { handlers.set(pk, cb); return () => handlers.delete(pk); },
  }; } };
}
const flush = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0)); };
async function peer(bus, pubkey, alias) {
  const engine = await MlsEngine.create({ name: pubkey });
  const roster = new ContactRoster({ backend: memBackend() });
  await roster.load();
  const chat = new StyxChat({ identity: { pubkey, alias }, engine, roster, transport: bus.transportFor(pubkey) });
  await chat.start();
  return chat;
}

describe('StyxChat A4 explicit pairing + alias in MLS', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('sanitizeAlias strips control chars, bidi overrides, and caps length', () => {
    expect(sanitizeAlias('  Alice  ')).toBe('Alice');
    expect(sanitizeAlias('A‮evil')).toBe('Aevil'); // bidi override removed
    expect(sanitizeAlias('badbell')).toBe('badbell'); // control char removed
    expect(sanitizeAlias('x'.repeat(200)).length).toBe(64);
    expect(sanitizeAlias(' ')).toBe('');
  });

  test('an authenticated welcome does NOT auto-add a contact; it fires a pending pairing', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a4', 'Bob');
    const alice = await peer(bus, 'alice_a4', 'Alice');
    const pendings = [];
    bob.onPairing((p) => pendings.push(p));

    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();

    expect(pendings.map((p) => p.pubkey)).toContain('alice_a4');
    expect((await bob.listContacts()).map((c) => c.pubkey)).not.toContain('alice_a4');

    await bob.confirmPairing({ contactPubkey: 'alice_a4' });
    expect((await bob.listContacts()).map((c) => c.pubkey)).toContain('alice_a4');
  });

  test('the introduced alias arrives encrypted and is used as the default on confirm', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a4b', 'Bob');
    const alice = await peer(bus, 'alice_a4b', 'Alice');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush(); // welcome + intro exchange

    // Bob confirms without specifying an alias → falls back to Alice's introduced alias.
    await bob.confirmPairing({ contactPubkey: 'alice_a4b' });
    const c = (await bob.listContacts()).find((x) => x.pubkey === 'alice_a4b');
    expect(c.alias).toBe('Alice');
  });

  test('the welcome envelope carries no cleartext alias', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a4c', 'Bob');
    const alice = await peer(bus, 'alice_a4c', 'Alice');
    const frames = [];
    const orig = alice._transport.send.bind(alice._transport);
    alice._transport.send = async (to, bytes, opts) => { frames.push(new TextDecoder().decode(bytes)); return orig(to, bytes, opts); };
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();
    const welcomeFrame = frames.map((f) => JSON.parse(f)).find((e) => e.t === 'welcome');
    expect(welcomeFrame).toBeTruthy();
    expect(welcomeFrame.from?.alias).toBeUndefined(); // alias no longer in cleartext
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd styx-js && npm test -- test/chat/styx-chat-explicit-pairing.test.js`
Expected: FAIL — `sanitizeAlias` and `onPairing` do not exist; welcome still auto-adds and carries the alias.

- [ ] **Step 3: Add `sanitizeAlias` and the pending-pairing state**

In `styx-js/src/chat/styx-chat.js`, export a module-level helper (place it above the `StyxChat` class, after `MemoryMessageStore`):

```javascript
/**
 * Normalise an untrusted alias: trim, cap at 64 chars, strip C0/C1 control
 * characters and Unicode bidirectional overrides. Returns '' if empty after.
 * @param {unknown} raw
 * @returns {string}
 */
export function sanitizeAlias(raw) {
  const s = String(raw ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[ --‪-‮⁦-⁩]/g, '')
    .trim();
  return s.slice(0, 64);
}
```

In the constructor, add the pending map (after `this._readSent = new Set();`):

```javascript
    this._pending = new Map(); // pubkey -> { pubkey, alias? } authenticated but not yet a contact
```

Add the subscription accessor next to the other `on*` methods:

```javascript
  onPairing(cb) { return this._emitter.on('pairing', cb); }
```

- [ ] **Step 4: Rewrite the welcome branch to create a pending pairing + send intro**

Replace the welcome branch so it no longer touches the roster and instead records a pending pairing, then sends our own encrypted intro:

```javascript
    if (env.t === 'welcome') {
      if (this._groups[from] || this._engine.session(from)) return; // A3
      if (!this._inviteNonce || !env.hmac) return;                   // A2
      const welcomeBytes = base64ToBytes(env.welcome);
      const treeBytes = base64ToBytes(env.tree);
      const expected = this._welcomeMac(this._inviteNonce, welcomeBytes, treeBytes, env.groupId);
      if (!constantTimeEqual(expected, base64ToBytes(env.hmac))) return;
      this._inviteNonce = null;
      this._engine.joinSession(from, welcomeBytes, treeBytes);
      if (env.groupId) this._groups[from] = env.groupId;
      await this._persistMls();
      // A4: a welcome creates a PENDING pairing, never a contact. The UI shows it
      // and the user confirms explicitly. Send our alias encrypted (M1).
      if (!(await this._roster.get(from))) {
        if (!this._pending.has(from)) this._pending.set(from, { pubkey: from });
        this._emitter.emit('pairing', { pubkey: from });
      }
      await this._sendIntro(from);
      await this._drainPending(from);
      return;
    }
```

Update `acceptQrInvite` to drop the cleartext alias and to send an intro after establishing the session. Change the welcome `from` to carry only the pubkey and add an intro send + pending record:

```javascript
    await this._send(inv.pubkey, {
      t: 'welcome',
      from: { pubkey: this._identity.pubkey },
      welcome: bytesToBase64(welcome),
      tree: bytesToBase64(ratchetTree),
      groupId,
      hmac: bytesToBase64(mac),
    });
    // A4: record a pending pairing for the scanner side too, and introduce our
    // alias encrypted. The inviter's alias (inv.alias) came over the QR — the
    // trusted in-person channel — so it is an acceptable default here.
    this._pending.set(inv.pubkey, { pubkey: inv.pubkey, alias: sanitizeAlias(inv.alias) });
    await this._sendIntro(inv.pubkey);
    return { contactPubkey: inv.pubkey };
```

Add the `_sendIntro` helper in internals:

```javascript
  /** @private Send our alias as an encrypted intro once a session exists. Best-effort. */
  async _sendIntro(toPubkey) {
    const session = this._engine.session(toPubkey);
    if (!session) return;
    try {
      const ct = session.encrypt(utf8Encode(JSON.stringify({ t: 'intro', alias: this._identity.alias })));
      await this._persistMls();
      await this._send(toPubkey, { t: 'app', ct: bytesToBase64(ct) });
    } catch { /* best-effort */ }
  }
```

- [ ] **Step 5: Handle the `intro` payload in `_processApp` and update `confirmPairing`**

In `_processApp`, after the `receipt` branch and before the chat-message handling, add:

```javascript
    if (payload.t === 'intro') {
      const alias = sanitizeAlias(payload.alias);
      if (alias) {
        const existing = await this._roster.get(from);
        if (existing) await this._roster.update(from, { alias });
        else this._pending.set(from, { pubkey: from, alias });
      }
      return true;
    }
```

Update `confirmPairing` to fall back to the introduced alias and clear the pending entry:

```javascript
  async confirmPairing({ contactPubkey, alias }) {
    const pending = this._pending.get(contactPubkey);
    const finalAlias = sanitizeAlias(alias) || pending?.alias || contactPubkey;
    await this._roster.add({ pubkey: contactPubkey, alias: finalAlias });
    this._pending.delete(contactPubkey);
    return { contactPubkey };
  }
```

- [ ] **Step 6: Update the two existing suites for the new (correct) behaviour**

The inviter no longer auto-gets the contact. In `styx-js/test/chat/styx-chat.test.js`, `pairedPeers()` and the first test must confirm on Bob's side. Update `pairedPeers`:

```javascript
  async function pairedPeers() {
    const bus = makeBus();
    const alice = await makePeer(bus, 'a_pk', 'Alice');
    const bob = await makePeer(bus, 'b_pk', 'Bob');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await alice.confirmPairing({ contactPubkey: 'b_pk', alias: 'Bob' });
    await flush();
    await bob.confirmPairing({ contactPubkey: 'a_pk', alias: 'Alice' }); // A4: explicit
    return { alice, bob };
  }
```

And in the first test (`two peers pair via QR invite…`), after `await flush();` add `await bob.confirmPairing({ contactPubkey: 'bob_pk' === undefined ? undefined : 'alice_pk', alias: 'Alice' });` — concretely:

```javascript
    await alice.confirmPairing({ contactPubkey, alias: 'Bob' });
    await flush(); // welcome delivered → Bob has a pending pairing
    await bob.confirmPairing({ contactPubkey: 'alice_pk', alias: 'Alice' }); // A4: explicit
```

In `styx-js/test/chat/styx-chat-assembly.test.js`, the two-peer and reload tests assert Bob's roster contains Alice after `flush()`. Add an explicit confirm on the inviter after each `flush()` that precedes such an assertion. For the `two real peers pair…` test:

```javascript
    await alice.confirmPairing({ contactPubkey, alias: 'Bob' });
    await flush();
    await bob.confirmPairing({ contactPubkey: alice.me.pubkey, alias: 'Alice' }); // A4
```

For `an invite still works if the inviter reloads…`: here A (the inviter, reloaded) receives B's welcome. After `await flush();` add `await a.confirmPairing({ contactPubkey: b.me.pubkey, alias: 'B' });` before the `listContacts` assertion.

For `a peer survives a reload…`: Alice is the scanner (she `acceptQrInvite`s Bob), so Bob is the inviter and must confirm. After the first `await flush();` add `await bob.confirmPairing({ contactPubkey: alice.me.pubkey, alias: 'Alice' });`.

- [ ] **Step 7: Run the A4 suite plus the two updated suites**

Run: `cd styx-js && npm test -- test/chat/styx-chat-explicit-pairing.test.js test/chat/styx-chat.test.js test/chat/styx-chat-assembly.test.js`
Expected: PASS for all. If a reload test still fails on a missing contact, confirm the inviter side in that specific test as above.

- [ ] **Step 8: Commit**

```bash
git add styx-js/src/chat/styx-chat.js styx-js/test/chat/styx-chat-explicit-pairing.test.js styx-js/test/chat/styx-chat.test.js styx-js/test/chat/styx-chat-assembly.test.js
git commit -m "feat(chat): explicit pairing + alias inside MLS (Phase A, A4)

Close M1/M2: a welcome now creates a pending pairing surfaced via onPairing;
a contact exists only after confirmPairing. The alias travels as an encrypted
intro instead of in the cleartext welcome, and is sanitized on receipt.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: A5 — Safety number

**Rationale:** H3 — there is no user-verifiable value to detect a MITM. A safety number derived from the shared MLS group secret is identical on both genuine peers and differs under a MITM; users compare it out loud (Signal ceremony).

**Files:**
- Modify: `styx-js/src/crypto/mls/mls-session.js`
- Modify: `styx-js/src/crypto/mls/mls-engine.js`
- Modify: `styx-js/src/chat/styx-chat.js`
- Modify: `styx-js/src/chat/contact-roster.js`
- Test: `styx-js/test/chat/styx-chat-safety-number.test.js` (create)

**Interfaces:**
- Consumes: `Group.export_key(provider, label, context, key_length)` (already exposed), `MlsEngine.provider`, `bytesToHex`, `utf8Encode`, `concatBytes`.
- Produces:
  - `MlsSession.exportSecret(label, context, length)` → `Uint8Array` (wraps `group.export_key`).
  - `StyxChat.safetyNumber(pubkey)` → `string` of 60 decimal digits grouped in fives (e.g. `"12345 67890 …"`), deterministic and equal on both peers. Throws if there is no session.
  - `ContactRoster.setVerified(pubkey, verified)` → sets `verified` (boolean) and `verifiedAt` (ms timestamp or null) on the contact; `Contact` gains `verified`/`verifiedAt` fields (default `false`/`null`).

- [ ] **Step 1: Write the failing test**

Create `styx-js/test/chat/styx-chat-safety-number.test.js`:

```javascript
// test/chat/styx-chat-safety-number.test.js
// A5: both genuine peers compute the same 60-digit safety number; a third party
// with a different session computes a different one.
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);
function memBackend() {
  const m = new Map();
  return { async get(k) { return m.has(k) ? m.get(k) : null; }, async set(k, v) { m.set(k, v); }, async delete(k) { m.delete(k); } };
}
function makeBus() {
  const handlers = new Map();
  return { transportFor(pk) { return {
    async send(to, bytes) { const h = handlers.get(to); if (h) queueMicrotask(() => h(pk, bytes)); },
    onMessage(cb) { handlers.set(pk, cb); return () => handlers.delete(pk); },
  }; } };
}
const flush = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0)); };
async function peer(bus, pubkey, alias) {
  const engine = await MlsEngine.create({ name: pubkey });
  const roster = new ContactRoster({ backend: memBackend() });
  await roster.load();
  const chat = new StyxChat({ identity: { pubkey, alias }, engine, roster, transport: bus.transportFor(pubkey) });
  await chat.start();
  return chat;
}

describe('StyxChat A5 safety number', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('both peers derive the same 60-digit safety number', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_sn', 'Bob');
    const alice = await peer(bus, 'alice_sn', 'Alice');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();

    const snAlice = alice.safetyNumber('bob_sn');
    const snBob = bob.safetyNumber('alice_sn');
    expect(snAlice).toBe(snBob);
    expect(snAlice.replace(/\s/g, '')).toMatch(/^\d{60}$/);
  });

  test('safetyNumber throws when there is no session', async () => {
    const bus = makeBus();
    const solo = await peer(bus, 'solo_sn', 'Solo');
    expect(() => solo.safetyNumber('ghost')).toThrow(/session/i);
  });

  test('roster records verification state', async () => {
    const backend = memBackend();
    const roster = new ContactRoster({ backend });
    await roster.load();
    await roster.add({ pubkey: 'p1', alias: 'P1' });
    let c = await roster.get('p1');
    expect(c.verified).toBe(false);
    await roster.setVerified('p1', true);
    c = await roster.get('p1');
    expect(c.verified).toBe(true);
    expect(typeof c.verifiedAt).toBe('number');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd styx-js && npm test -- test/chat/styx-chat-safety-number.test.js`
Expected: FAIL — `safetyNumber`, `exportSecret`, and `setVerified` do not exist.

- [ ] **Step 3: Expose `exportSecret` on the session**

In `styx-js/src/crypto/mls/mls-session.js`, add:

```javascript
  /**
   * Derive an exported secret from the group's current epoch key schedule.
   * Identical on all members of the same group at the same epoch.
   * @param {string} label domain-separation label
   * @param {Uint8Array} context binding context
   * @param {number} length output length in bytes
   * @returns {Uint8Array}
   */
  exportSecret(label, context, length) {
    return this._group.export_key(this._engine.provider, label, context, length);
  }
```

- [ ] **Step 4: Add `safetyNumber` to `StyxChat`**

In `styx-js/src/chat/styx-chat.js`, add the method (near the pairing methods) plus a private formatter in internals:

```javascript
  /**
   * A user-verifiable safety number for a contact (Signal-style). Identical on
   * both genuine peers; differs under a MITM. 60 decimal digits, grouped in 5s.
   * @param {string} pubkey
   * @returns {string}
   */
  safetyNumber(pubkey) {
    const session = this._engine.session(pubkey);
    if (!session) throw new Error(`No MLS session for ${pubkey}`);
    const [a, b] = [this._identity.pubkey, pubkey].sort();
    const context = utf8Encode(a + b);
    const secret = session.exportSecret('styx:safety-number:v1', context, 32);
    return StyxChat._formatSafetyNumber(secret);
  }

  /** @private 32 bytes → 60 decimal digits grouped in fives. */
  static _formatSafetyNumber(bytes) {
    let n = 0n;
    for (const byte of bytes) n = (n << 8n) | BigInt(byte);
    let digits = '';
    for (let i = 0; i < 60; i += 1) { digits = String(n % 10n) + digits; n /= 10n; }
    return digits.match(/.{1,5}/g).join(' ');
  }
```

Note: `utf8Encode` and `concatBytes` are already imported (Task 3). If `concatBytes` is unused here, that is fine — it is used elsewhere.

- [ ] **Step 5: Add verification state to the roster**

In `styx-js/src/chat/contact-roster.js`, extend the persisted record in `add` (default fields) and add `setVerified`. Update the `add` record:

```javascript
    const record = {
      pubkey,
      alias,
      unread: existing?.unread ?? 0,
      lastPreview: existing?.lastPreview ?? null,
      lastTs: existing?.lastTs ?? null,
      verified: existing?.verified ?? false,
      verifiedAt: existing?.verifiedAt ?? null,
    };
```

Add the method (after `clearUnread`):

```javascript
  /**
   * Record whether the contact's safety number has been verified out-of-band.
   * @param {string} pubkey
   * @param {boolean} verified
   * @returns {Promise<Contact>}
   */
  async setVerified(pubkey, verified) {
    const record = this._require(pubkey);
    record.verified = !!verified;
    record.verifiedAt = verified ? Date.now() : null;
    await this._persist();
    return this._decorate(record);
  }
```

Update the `Contact` typedef to include the two fields:

```javascript
 * @property {boolean} verified
 * @property {number|null} verifiedAt
```

- [ ] **Step 6: Run the A5 suite and the roster suite**

Run: `cd styx-js && npm test -- test/chat/styx-chat-safety-number.test.js test/chat/contact-roster.test.js`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add styx-js/src/crypto/mls/mls-session.js styx-js/src/chat/styx-chat.js styx-js/src/chat/contact-roster.js styx-js/test/chat/styx-chat-safety-number.test.js
git commit -m "feat(chat): user-verifiable safety number (Phase A, A5)

Close H3: StyxChat.safetyNumber derives a 60-digit code from the shared MLS
group export key — identical on genuine peers, different under a MITM. Roster
persists a verified flag + timestamp.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: A6 — Refuse the unauthenticated transport in production

**Rationale:** C3 — `BroadcastChannelTransport` carries no signatures. It is legitimate for same-origin dev/offline use (`?local=1`), but must not be silently selected in a production build. Require an explicit opt-in.

**Files:**
- Modify: `styx-js/src/transport/broadcast-channel-transport.js`
- Modify: `styx-js/src/chat/styx-chat.js`
- Test: `styx-js/test/transport/broadcast-channel-transport.test.js` (modify)
- Modify: `styx-js/test/chat/styx-chat-assembly.test.js`

**Interfaces:**
- Consumes: `BroadcastChannelTransport` constructor, `StyxChat.init`.
- Produces:
  - `BroadcastChannelTransport(selfPubkey, { channelName, allowInsecure })` throws `Error('BroadcastChannelTransport is unauthenticated — pass { allowInsecure: true } to use it in development')` unless `allowInsecure === true`.
  - `StyxChat.init({ ..., allowInsecureTransport })` passes `allowInsecure: true` to the BroadcastChannel fallback only when `allowInsecureTransport === true`; otherwise, with no relays and no opt-in, it throws `Error('StyxChat: no authenticated transport — pass relays, or allowInsecureTransport:true for dev')`.

- [ ] **Step 1: Write/adjust the failing test**

In `styx-js/test/transport/broadcast-channel-transport.test.js`, update the `mk` helper (line ~8) to pass the opt-in, and add two guard tests. Change the helper:

```javascript
function mk(pubkey, channel) {
  return new BroadcastChannelTransport(pubkey, { channelName: channel, allowInsecure: true });
}
```

Add at the end of the `describe` block:

```javascript
  test('refuses to instantiate without the insecure opt-in', () => {
    expect(() => new BroadcastChannelTransport('pk', { channelName: 'x' }))
      .toThrow(/unauthenticated/);
  });

  test('instantiates with allowInsecure:true', () => {
    const t = new BroadcastChannelTransport('pk', { channelName: 'x2', allowInsecure: true });
    expect(t).toBeTruthy();
    t.close();
  });
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd styx-js && npm test -- test/transport/broadcast-channel-transport.test.js`
Expected: FAIL — constructor does not yet reject the missing opt-in.

- [ ] **Step 3: Guard the transport constructor**

In `styx-js/src/transport/broadcast-channel-transport.js`, change the constructor signature and add the guard:

```javascript
  constructor(selfPubkey, { channelName = 'styx-chat', allowInsecure = false } = {}) {
    if (!allowInsecure) {
      throw new Error(
        'BroadcastChannelTransport is unauthenticated — pass { allowInsecure: true } to use it in development',
      );
    }
    this._self = selfPubkey;
    this._bc = new BroadcastChannel(channelName);
```

- [ ] **Step 4: Thread the opt-in through `StyxChat.init`**

In `styx-js/src/chat/styx-chat.js`, update the transport selection in `init`. Change the signature to accept `allowInsecureTransport` and the fallback:

```javascript
  async init({ password, backend, channelName, alias, ns, relays, allowInsecureTransport = false } = {}) {
```

Replace the transport construction:

```javascript
      if (relays && relays.length) {
        this._transport = new NostrChatTransport({ secretKey: sk, pubkey, relays });
      } else if (allowInsecureTransport) {
        this._transport = new BroadcastChannelTransport(
          pubkey,
          { channelName, allowInsecure: true },
        );
      } else {
        throw new Error('StyxChat: no authenticated transport — pass relays, or allowInsecureTransport:true for dev');
      }
```

- [ ] **Step 5: Update the assembly tests to opt in**

The assembly suite uses BroadcastChannel with no relays. In `styx-js/test/chat/styx-chat-assembly.test.js`, update `realPeer` to pass the flag:

```javascript
async function realPeer({ backend, channelName, alias, password = 'pw' }) {
  const chat = new StyxChat();
  await chat.init({ password, backend, channelName, alias, allowInsecureTransport: true });
  live.push(chat);
  return chat;
}
```

And the two inline `chat.init(...)` calls in that file (the reload tests) must add `allowInsecureTransport: true`:

```javascript
  await a.init({ password: 'pw', backend: aBackend, channelName: ch, allowInsecureTransport: true });
```

```javascript
  await bob.init({ password: 'pw', backend: bobBackend, channelName: ch, allowInsecureTransport: true });
```

And the `wrong password on re-init` test's `chat.init(...)` — it must reach the password check before the transport, so also add `allowInsecureTransport: true` to keep it exercising the password path:

```javascript
    await expect(chat.init({ password: 'wrong', backend, channelName: 'asm-3', allowInsecureTransport: true }))
      .rejects.toThrow('Invalid password');
```

- [ ] **Step 6: Run the transport and assembly suites**

Run: `cd styx-js && npm test -- test/transport/broadcast-channel-transport.test.js test/chat/styx-chat-assembly.test.js`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add styx-js/src/transport/broadcast-channel-transport.js styx-js/src/chat/styx-chat.js styx-js/test/transport/broadcast-channel-transport.test.js styx-js/test/chat/styx-chat-assembly.test.js
git commit -m "feat(transport): gate unauthenticated BroadcastChannel behind dev opt-in (Phase A, A6)

Close C3: BroadcastChannelTransport throws unless { allowInsecure:true }; a
relay-less StyxChat.init requires allowInsecureTransport:true. Production
builds cannot silently select the unauthenticated transport.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: App wiring — pending-pairing UI, safety number, dev opt-in, mock parity

**Rationale:** A4 makes the inviter's side require an explicit confirm, and A5/A6 add user-facing surfaces. The PWA must show incoming pairing requests, expose the safety number with a verify action, pass `allowInsecureTransport` under `?local=1`, and keep the mock lib in parity so the app boots without the real library.

**Files:**
- Modify: `styx-js/apps/chat/src/hooks/useStyxChat.js`
- Modify: `styx-js/apps/chat/src/components/PairingModal.jsx`
- Modify: `styx-js/apps/chat/src/components/ConversationView.jsx`
- Modify: `styx-js/apps/chat/src/App.jsx`
- Modify: `styx-js/apps/chat/src/lib/styx-lib-mock.js`
- Test: `styx-js/apps/chat/e2e/pairing.spec.js` (modify)

**Interfaces:**
- Consumes: `chat.onPairing`, `chat.confirmPairing`, `chat.safetyNumber`, `chat.setVerified` (added below), `getRelays()`.
- Produces:
  - `useStyxChat` exposes `pendingPairings` (array of `{pubkey}`), subscribes to `onPairing`, and passes `allowInsecureTransport` when `getRelays()` is empty.
  - `StyxChat.setVerified(pubkey, verified)` passthrough on the roster (add to `styx-chat.js`).
  - `ConversationView` shows the safety number and a "verified" toggle in the header.
  - The mock lib gains `onPairing`, `safetyNumber`, `setVerified`, and `pendingPairings` parity.

- [ ] **Step 1: Add `setVerified` passthrough to `StyxChat`**

In `styx-js/src/chat/styx-chat.js`, add near `listContacts`:

```javascript
  async setVerified(pubkey, verified) { return this._roster.setVerified(pubkey, verified); }
```

- [ ] **Step 2: Wire pending pairings + dev opt-in in the hook**

In `styx-js/apps/chat/src/hooks/useStyxChat.js`:

Add state near the other `useState` calls:

```javascript
  const [pendingPairings, setPendingPairings] = useState([]);
```

In `unlock`, change the `init` call to pass the opt-in when there are no relays:

```javascript
    const relays = getRelays();
    const identity = await chat.init({
      password, alias: alias?.trim(), ns, relays,
      allowInsecureTransport: relays.length === 0, // ?local=1 → BroadcastChannel dev transport
    });
```

Add an `onPairing` subscription inside the `subsRef.current = [ ... ]` array:

```javascript
      chat.onPairing?.(({ pubkey }) => setPendingPairings((prev) => (prev.some((p) => p.pubkey === pubkey) ? prev : [...prev, { pubkey }]))),
```

Add a `confirmPending` action and a `verifyContact` action (near the other actions):

```javascript
  const confirmPending = useCallback(async (pubkey, alias) => {
    await chatRef.current?.confirmPairing({ contactPubkey: pubkey, alias });
    setPendingPairings((prev) => prev.filter((p) => p.pubkey !== pubkey));
    setContacts(await chatRef.current.listContacts());
  }, []);

  const safetyNumber = useCallback((pubkey) => {
    try { return chatRef.current?.safetyNumber(pubkey) || ''; } catch { return ''; }
  }, []);

  const setVerified = useCallback(async (pubkey, verified) => {
    await chatRef.current?.setVerified(pubkey, verified);
    setContacts(await chatRef.current.listContacts());
  }, []);
```

Clear `pendingPairings` in `lock` (add to the reset block):

```javascript
    setPendingPairings([]);
```

Return the new values (extend the returned object):

```javascript
    ready, me, contacts, messagesByContact, typingByContact, noMore, pendingPairings,
    unlock, lock, openConversation, loadOlder, sendText, markRead, setTyping,
    setAlias, enablePush, confirmPending, safetyNumber, setVerified, ...pairing,
```

- [ ] **Step 3: Surface incoming pairing requests in the UI**

In `styx-js/apps/chat/src/App.jsx`, render a lightweight confirm banner when there are pending pairings. Add, just before the closing `</>`:

```jsx
      {chat.pendingPairings?.length > 0 && (
        <div className="toast sx-badge" role="dialog">
          Richiesta di contatto da {chat.pendingPairings[0].pubkey.slice(0, 12)}…
          <button
            className="btn btn-accent"
            style={{ marginLeft: 8 }}
            onClick={() => chat.confirmPending(chat.pendingPairings[0].pubkey)}
          >
            Aggiungi
          </button>
        </div>
      )}
```

- [ ] **Step 4: Show the safety number in the conversation header**

In `styx-js/apps/chat/src/components/ConversationView.jsx`, accept two new props and render a verify control. Change the signature:

```javascript
export default function ConversationView({
  contact, messages, typing, noMore, isMobile, safetyNumber, onVerify,
  onBack, onSend, onSetTyping, onLoadOlder, onMarkRead, onRetry,
}) {
```

Replace the `e2e-badge` span with a button that reveals the safety number:

```jsx
        <span className="spacer" />
        <button
          className="e2e-badge"
          title="Mostra il numero di sicurezza"
          onClick={() => {
            const sn = safetyNumber?.(contact.pubkey) || '';
            const msg = sn
              ? `Numero di sicurezza:\n\n${sn}\n\nConfermatelo a voce con il contatto. Coincide?`
              : 'Numero di sicurezza non ancora disponibile.';
            if (sn && window.confirm(msg)) onVerify?.(contact.pubkey, true);
          }}
        >
          <Lock size={13} /> {contact.verified ? 'Verificato ✓' : 'E2E'}
        </button>
```

Thread the props from `ChatShell`/`App`. In `styx-js/apps/chat/src/App.jsx`, pass them into `ChatShell` (which forwards to `ConversationView`) — add to the `<ChatShell ... />` props:

```jsx
        safetyNumber={chat.safetyNumber}
        onVerify={chat.setVerified}
```

(If `ChatShell` does not already forward unknown props to `ConversationView`, add `safetyNumber` and `onVerify` to its prop list and pass them through to `<ConversationView ... />`. Verify by reading `styx-js/apps/chat/src/components/ChatShell.jsx` and threading exactly like the existing `onSend`/`onMarkRead` props.)

- [ ] **Step 5: Keep the mock lib in parity**

In `styx-js/apps/chat/src/lib/styx-lib-mock.js`, add the new surface so the app runs on the mock. Add to the subscription setup (where `_subs` is initialised) a `pairing: []` list, and add methods near `confirmPairing`:

```javascript
  onPairing(cb) { this._subs.pairing = this._subs.pairing || []; this._subs.pairing.push(cb); return () => this._off('pairing', cb); }
  safetyNumber(pubkey) {
    // Deterministic 60-digit stand-in for the mock (not cryptographic).
    let h = 0n; for (const ch of String(pubkey)) h = (h * 131n + BigInt(ch.charCodeAt(0))) % (10n ** 60n);
    const digits = h.toString().padStart(60, '0');
    return digits.match(/.{1,5}/g).join(' ');
  }
  async setVerified(pubkey, verified) {
    const c = this._contacts.find((x) => x.pubkey === pubkey);
    if (c) { c.verified = !!verified; c.verifiedAt = verified ? now() : null; this._emit('contacts'); }
    return c;
  }
```

Ensure `confirmPairing` in the mock sets `verified: false, verifiedAt: null` on the created contact record (add those two fields to the pushed object).

- [ ] **Step 6: Update the e2e pairing spec for the explicit inviter confirm**

In `styx-js/apps/chat/e2e/pairing.spec.js`, after Alice adds Bob, Bob now sees a pending pairing banner. Add, before the roster assertions:

```javascript
  // A4: Bob must explicitly accept the incoming pairing request.
  await bob.getByRole('button', { name: /Aggiungi/ }).click();
```

- [ ] **Step 7: Run the app unit tests and the e2e (local transport)**

Run: `cd styx-js/apps/chat && npm test`
Expected: PASS (config/install/notify/manifest suites unaffected).

Run: `cd styx-js/apps/chat && npx playwright test e2e/pairing.spec.js`
Expected: PASS — two peers pair (with the explicit Bob confirm) and exchange an MLS-encrypted message; `errors` is empty.

- [ ] **Step 8: Commit**

```bash
git add styx-js/apps/chat/src styx-js/apps/chat/e2e/pairing.spec.js styx-js/src/chat/styx-chat.js
git commit -m "feat(app): pending-pairing UI, safety number, dev transport opt-in (Phase A, A4/A5/A6)

Surface incoming pairing requests for explicit confirm, expose the safety
number with a verify toggle, pass allowInsecureTransport under ?local=1, and
keep the mock lib in parity.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: Full-suite regression + report

**Files:**
- Modify (if needed): any test broken by the cumulative changes.
- Create: `docs/security/2026-07-10-phase-a-completion-report.md`

- [ ] **Step 1: Run the entire library suite**

Run: `cd styx-js && npm run test:unit`
Expected: PASS. Investigate and fix any regression (the likely candidates are integration tests that pair without an explicit inviter confirm — apply the same A4 fix pattern as Task 4 Step 6).

- [ ] **Step 2: Run the relay integration suite (optional, needs Docker)**

Run: `cd styx-js && npm run test:relay` then `npm run test:relay:down`
Expected: PASS. `nostr-chat-transport.test.js` still delivers because those events are genuinely signed (A1 verifies real signatures). If Docker is unavailable, note it as not run.

- [ ] **Step 3: Write the completion report**

Create `docs/security/2026-07-10-phase-a-completion-report.md` documenting, per vulnerability (C1, C2, C3, H3, M1, M2, M3): what was changed, which file, which test proves it, and what remains out of scope (N2 credential↔pubkey binding needs a WASM rebuild — deferred; metadata privacy is Phase C; at-rest is Phase B). State plainly that after Phase A an active adversary can still delay/reorder/drop (availability) but can no longer read or impersonate, and that the content guarantee to clients is now defensible when pairing is done in person with the safety number verified.

- [ ] **Step 4: Commit**

```bash
git add docs/security/2026-07-10-phase-a-completion-report.md
git commit -m "docs(security): Phase A completion report (channel authentication)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage (Fase A A1–A6):**
- A1 (verify inbound signatures) → Task 1. ✓
- A2 (welcome HMAC over QR nonce, single-use) → Task 3. ✓
- A3 (never overwrite a session) → Task 2. ✓
- A4 (explicit roster add, alias in MLS, alias validation) → Task 4. ✓
- A5 (safety number via export_key + verified flag) → Task 5. ✓
- A6 (ban unauthenticated transport in prod) → Task 6. ✓
- App surfaces for A4/A5/A6 → Task 7. Regression + report → Task 8. ✓

**Deferred (documented, out of Phase A scope):** N2 credential↔pubkey binding at join (needs a `member_credentials()` accessor in the vendored Rust → WASM rebuild); N1 WASM panic hardening (Rust); Phase B at-rest encryption (H1); Phase C metadata privacy / real gift-wrap (H2, M4, M6); Phase D traffic analysis. These are noted in the completion report, not implemented here.

**Type/name consistency:** `_welcomeMac(nonce, welcome, tree, groupId)` defined in Task 3 and used in Tasks 3–4; `sanitizeAlias` exported in Task 4 and reused in `_processApp`/`confirmPairing`; `exportSecret(label, context, length)` (Task 5, session) called by `safetyNumber` (Task 5, chat); `setVerified(pubkey, verified)` defined on the roster (Task 5) and passed through on `StyxChat` (Task 7); `allowInsecure` (transport ctor, Task 6) vs `allowInsecureTransport` (init option, Tasks 6–7) are intentionally distinct names at their two layers.

**Placeholder scan:** none — every code step shows complete code; every run step shows the command and expected result.
