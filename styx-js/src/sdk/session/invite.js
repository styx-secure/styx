/**
 * MLS invitation over Nostr -- PROTOTYPE (branch proto/sdk-demo-2026-10, not for merge).
 *
 * Replaces the out-of-band KeyPackage / Welcome file copy of the M3 demo
 * harness with a relay path:
 *
 *   invitee: publishKeyPackage()  -> kind 4743 event, signed by the invitee's
 *                                    identity port, content = base64 KeyPackage
 *   inviter: invite({ invitee })  -> fetches the newest valid kind-4743 event
 *                                    authored by `invitee`, adds that member
 *                                    (credential must equal `invitee`), and
 *                                    sends the Welcome as a NIP-59 gift wrap
 *                                    (rumor kind 4744 -> seal 13 -> wrap 1059)
 *   invitee: awaitWelcome()       -> unwraps, checks the seal signer, joins
 *                                    (the group's other member must be the
 *                                    seal signer) -- the session port is ready
 *
 * Event kinds. The existing styx-js code has no Marmot (MIP-00/02) encoder,
 * no NIP-44 and no NIP-59, so the Marmot kinds 443/444 are NOT used: our
 * KeyPackage and Welcome encodings (base64 OpenMLS bytes, separate ratchet
 * tree) are not Marmot-compatible, and publishing them under 443/444 would
 * feed malformed data to real Marmot clients. The prototype therefore uses
 * its own EXPERIMENTAL kinds 4743 (KeyPackage, regular, NIP-40 expiration)
 * and 4744 (Welcome rumor, never published bare), next to the delivery
 * layer's 4741/4742. The outer layer is standard NIP-59 (kinds 13 and 1059).
 *
 * The secret key never enters this module: signing goes through
 * `identity.sign`, NIP-59 wrap/unwrap through the identity port's
 * `giftWrap` / `unwrapGift` prototype extensions.
 */

import { sha256 } from '@noble/hashes/sha256';
import { schnorr } from '@noble/curves/secp256k1';
import { createRelaySet } from '../delivery/relay-pool.js';
import { retryDelayMs } from '../delivery/retry.js';
import { bytesToHex, hexToBytes, bytesToBase64, base64ToBytes, utf8Encode, randomBytes } from '../../utils.js';
import { relayUrlAllowed } from '../relay-url.js';

export const PROTO_KIND_KEYPACKAGE = 4743;
export const PROTO_KIND_WELCOME = 4744;
export const NIP59_KIND_WRAP = 1059;
const HEX64 = /^[0-9a-f]{64}$/;
const PROTO_TAG = 'styx-proto';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const eventIdOf = (ev) => bytesToHex(sha256(utf8Encode(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]))));

function verify(ev) {
  try {
    if (!ev || !HEX64.test(ev.pubkey) || !HEX64.test(ev.id) || typeof ev.sig !== 'string') return false;
    if (eventIdOf(ev) !== ev.id) return false;
    return schnorr.verify(hexToBytes(ev.sig), hexToBytes(ev.id), hexToBytes(ev.pubkey));
  } catch {
    return false;
  }
}

const defaultClock = () => ({ now: () => Date.now(), setTimer: (cb, ms) => setTimeout(cb, ms), clearTimer: (h) => clearTimeout(h) });
const defaultRandom = () => ({
  nextUint32: () => { const b = randomBytes(4); return b[0] * 2 ** 24 + b[1] * 2 ** 16 + b[2] * 2 ** 8 + b[3]; },
});

/**
 * @param {object} o
 * @param {string[]} o.relays same rule as the client (loopback or the prototype allowlist)
 * @param {object} o.identity identity port with getPublicKey, sign, giftWrap, unwrapGift
 * @param {object} o.mlsPort the session port of ./mls-port.js
 * @param {number} [o.perRelayTimeoutMs] connection phase and publish timeout of each relay set (default 6000 ms)
 * @param {(step: string, detail?: object) => void} [o.onProgress] demo/log hook; never gets secrets
 */
export function createInviteFlow({ relays, identity, mlsPort, perRelayTimeoutMs = 6000, clock, random, onProgress }) {
  if (!Array.isArray(relays) || relays.length < 1 || !relays.every(relayUrlAllowed)) throw new TypeError('invite: relays not allowed');
  for (const m of ['getPublicKey', 'sign', 'giftWrap', 'unwrapGift']) {
    if (typeof identity?.[m] !== 'function') throw new TypeError(`invite: identity.${m} required`);
  }
  const self = identity.getPublicKey();
  if (!HEX64.test(self)) throw new TypeError('invite: identity key must be lowercase 64-hex');
  const ck = clock ?? defaultClock();
  const rnd = random ?? defaultRandom();
  const progress = (s, d) => { try { onProgress?.(s, d); } catch { /* display only */ } };
  const open = new Set();

  /** One relay set with one subscription; collects verified EVENT frames. */
  async function session(filter) {
    const rs = createRelaySet({
      relays: [...relays], clock: ck, random: rnd, perRelayTimeoutMs,
      subscriptionId: 'i' + bytesToHex(randomBytes(12)), filter, reconnectDelay: retryDelayMs,
    });
    const events = [];
    const eose = new Set();
    const waiters = new Set();
    rs.onFrame((frame) => {
      let m;
      try { m = typeof frame.data === 'string' ? JSON.parse(frame.data) : frame.data; } catch { return; }
      if (!Array.isArray(m)) return;
      if (m[0] === 'EOSE') eose.add(frame.relayIndex ?? 0);
      if (m[0] === 'EVENT' && m[2] && verify(m[2]) && !events.some((e) => e.ev.id === m[2].id)) {
        events.push({ ev: m[2], relayIndex: frame.relayIndex ?? 0 });
      }
      for (const w of [...waiters]) w();
    });
    const handle = { rs, events, eose, changed: () => new Promise((r) => { const f = () => { waiters.delete(f); r(); }; waiters.add(f); }) };
    open.add(handle);
    const started = await rs.start();
    handle.connected = started?.connectedRelays ?? 0;
    if (handle.connected < 1) { await close1(handle); throw new Error('invite: no relay available'); }
    return handle;
  }
  async function close1(h) { open.delete(h); try { await h.rs.dispose(); } catch { /* ignore */ } }

  async function signEvent(ev) {
    const e = { ...ev, pubkey: self, created_at: ev.created_at ?? Math.floor(Date.now() / 1000) };
    e.id = eventIdOf(e);
    const sig = await identity.sign({ digest: hexToBytes(e.id) });
    e.sig = bytesToHex(sig);
    return e;
  }

  /** Publish and wait for the attempt to settle; returns per-relay outcomes. */
  function publishSettled(rs, ev) {
    return new Promise((resolve) => {
      const a = rs.publish(ev);
      a.onSettled(() => resolve([...a.outcomes]));
    });
  }

  async function waitUntil(h, pred, ms) {
    const t0 = Date.now();
    for (;;) {
      if (pred()) return true;
      const left = ms - (Date.now() - t0);
      if (left <= 0) return false;
      await Promise.race([h.changed(), sleep(Math.min(left, 500))]);
    }
  }

  return Object.freeze({
    /** Invitee: publish a fresh KeyPackage (kind 4743, NIP-40 expiration). */
    async publishKeyPackage({ expiresInSec = 3600 } = {}) {
      const kp = mlsPort.keyPackageBytes();
      const now = Math.floor(Date.now() / 1000);
      const ev = await signEvent({
        kind: PROTO_KIND_KEYPACKAGE, created_at: now, content: bytesToBase64(kp),
        tags: [[PROTO_TAG, 'keypackage-v0'], ['encoding', 'base64'], ['expiration', String(now + expiresInSec)]],
      });
      const h = await session({ kinds: [PROTO_KIND_KEYPACKAGE], authors: [self], limit: 1 });
      try {
        const outcomes = await publishSettled(h.rs, ev);
        const accepted = outcomes.filter((o) => o === 'ACCEPTED').length;
        progress('keypackage-published', { eventId: ev.id, bytes: kp.length, outcomes });
        if (accepted < 1) throw new Error('invite: no relay accepted the KeyPackage');
        return { eventId: ev.id, accepted, outcomes };
      } finally { await close1(h); }
    },

    /** Inviter: fetch the invitee's newest KeyPackage, add it, gift-wrap the Welcome. */
    async invite({ invitee, timeoutMs = 60000 }) {
      if (!HEX64.test(invitee) || invitee === self) throw new Error('invite: bad invitee key');
      const h = await session({ kinds: [PROTO_KIND_KEYPACKAGE], authors: [invitee], limit: 5 });
      try {
        const nowS = () => Math.floor(Date.now() / 1000);
        const usable = () => h.events.filter(({ ev }) => ev.pubkey === invitee && ev.kind === PROTO_KIND_KEYPACKAGE
          && ev.tags.some((t) => t[0] === PROTO_TAG && t[1] === 'keypackage-v0')
          && !ev.tags.some((t) => t[0] === 'expiration' && Number(t[1]) <= nowS()));
        // stored events first: wait for EOSE from every connected relay (or any usable one after 3 s)
        const t0 = Date.now();
        await waitUntil(h, () => h.eose.size >= h.connected || (usable().length > 0 && Date.now() - t0 > 3000), Math.min(timeoutMs, 15000));
        if (usable().length === 0) await waitUntil(h, () => usable().length > 0, timeoutMs);
        const list = usable().sort((a, b) => b.ev.created_at - a.ev.created_at);
        if (list.length === 0) throw new Error('invite: no KeyPackage from the invitee on the relays');
        const { ev: kpEv, relayIndex } = list[0];
        progress('keypackage-fetched', { eventId: kpEv.id, relayIndex, candidates: list.length });
        const st = mlsPort.startSession(invitee, base64ToBytes(kpEv.content)); // checks credential == invitee
        progress('member-added', { groupId: st.groupId });
        const rumor = {
          kind: PROTO_KIND_WELCOME, created_at: Math.floor(Date.now() / 1000),
          content: JSON.stringify({ welcome: bytesToBase64(st.welcome), tree: bytesToBase64(st.ratchetTree), groupId: st.groupId }),
          tags: [['e', kpEv.id], [PROTO_TAG, 'welcome-v0']],
        };
        const wrap = await identity.giftWrap({ rumor, recipient: invitee });
        const outcomes = await publishSettled(h.rs, wrap);
        const accepted = outcomes.filter((o) => o === 'ACCEPTED').length;
        progress('welcome-sent', { wrapEventId: wrap.id, wrapAuthor: wrap.pubkey, outcomes });
        if (accepted < 1) throw new Error('invite: no relay accepted the Welcome');
        return { groupId: st.groupId, keyPackageEventId: kpEv.id, wrapEventId: wrap.id, accepted, outcomes };
      } finally { await close1(h); }
    },

    /** Invitee: wait for a gift-wrapped Welcome for `keyPackageEventId`, then join. */
    async awaitWelcome({ keyPackageEventId, timeoutMs = 120000 }) {
      if (!HEX64.test(keyPackageEventId)) throw new Error('invite: keyPackageEventId required');
      const h = await session({ kinds: [NIP59_KIND_WRAP], '#p': [self] });
      try {
        const tried = new Set();
        let joined = null;
        const attempt = () => {
          for (const { ev, relayIndex } of h.events) {
            if (tried.has(ev.id)) continue;
            tried.add(ev.id);
            let u;
            try { u = identity.unwrapGift(ev); } catch { continue; } // not ours / not valid
            const r = u.rumor;
            if (r.kind !== PROTO_KIND_WELCOME || !r.tags.some((t) => t[0] === 'e' && t[1] === keyPackageEventId)) continue;
            let body;
            try { body = JSON.parse(r.content); } catch { continue; }
            try {
              mlsPort.joinSession(u.sealPubkey, base64ToBytes(body.welcome), base64ToBytes(body.tree));
            } catch (e) {
              progress('welcome-rejected', { wrapEventId: ev.id, reason: String(e.message || e) });
              continue;
            }
            joined = { inviter: u.sealPubkey, groupId: body.groupId, wrapEventId: ev.id, relayIndex };
            return true;
          }
          return false;
        };
        const okJoin = await waitUntil(h, attempt, timeoutMs);
        if (!okJoin) throw new Error('invite: no Welcome for our KeyPackage in time');
        progress('joined', joined);
        return joined;
      } finally { await close1(h); }
    },

    async close() { for (const h of [...open]) await close1(h); },
  });
}
