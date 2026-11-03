/**
 * Robustness of the inbound processor (`src/sdk/delivery/receipts.js`): the
 * step-1 bounds of C-DLV section 7.1 and receipt signing beside the inbound
 * queue (C-DLV section 7.2). Ports are fakes with the shapes of C-SDK section 8.
 */

import { describe, expect, test } from '@jest/globals';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

import { bytesToBase64, bytesToHex, hexToBytes, utf8Encode } from '../../../src/utils.js';
import { createReceipts } from '../../../src/sdk/delivery/receipts.js';
import { SDK_WIRE_VERSION as VERSION } from '../../../src/sdk/wire-version.js';

const OWN_CLOCK_MS = 12000;
const CONTENT_MAX = 349528;

async function waitFor(predicate, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) break;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return predicate();
}
const flush = async (rounds = 8) => { for (let i = 0; i < rounds; i += 1) await new Promise((r) => setTimeout(r, 0)); };

function makeKey() {
  const priv = schnorr.utils.randomPrivateKey();
  return { priv, pub: bytesToHex(schnorr.getPublicKey(priv)) };
}
function build({ key, kind = 4741, tags, content, createdAt = OWN_CLOCK_MS / 1000 }) {
  const id = bytesToHex(sha256(utf8Encode(JSON.stringify([0, key.pub, createdAt, kind, tags, content]))));
  return { id, pubkey: key.pub, created_at: createdAt, kind, tags, content,
    sig: bytesToHex(schnorr.sign(hexToBytes(id), key.priv)) };
}
const nonce = (n) => n.toString(16).padStart(32, '0');
function message(sender, owner, { content = bytesToBase64(new Uint8Array([1, 2, 3])), receipt = false, n = 1 } = {}) {
  const tags = [['p', owner.pub], ['v', VERSION], ['n', nonce(n)]];
  if (receipt) tags.push(['r', '1']);
  return build({ key: sender, tags, content });
}
function receiptFor(recipient, owner, eventId) {
  return build({ key: recipient, kind: 4742, tags: [['p', owner.pub], ['e', eventId], ['v', VERSION], ['n', nonce(99)]], content: '' });
}
const eventFrame = (event) => ({ relayIndex: 0, relay: 'relay-0', data: ['EVENT', 'sub', event] });

function harness({ sign } = {}) {
  const owner = makeKey();
  const opens = [], events = [], acks = [], published = [];
  const module = createReceipts({
    identity: { getPublicKey: () => owner.pub, sign: sign ?? (({ digest }) => schnorr.sign(digest, owner.priv)) },
    session: { open: ({ sender, ciphertext }) => { opens.push({ sender, ciphertext }); return { plaintext: new Uint8Array([7]) }; } },
    clock: { now: () => OWN_CLOCK_MS },
    perRelayTimeoutMs: 30000,
    publishReceipt: (event) => { published.push(event); },
    acceptReceipt: ({ eventId, recipient }) => {
      acks.push({ eventId, recipient });
      return Object.freeze({ ok: true, value: Object.freeze({ accepted: true, deliveryId: 'd1' }) });
    },
    onEvent: (event) => { events.push(event); },
  });
  return { module, owner, opens, events, acks, published };
}
const discards = (events) => events.filter((e) => e.kind === 'INBOUND_DISCARDED').map((e) => e.code);

describe('C-DLV section 7.1 step 1 -- inbound content and tag bounds', () => {
  test('content longer than 349 528 characters is discarded before decoding or open', async () => {
    const h = harness(); const sender = makeKey();
    h.module.ingest(eventFrame(message(sender, h.owner, { content: 'A'.repeat(CONTENT_MAX + 4) })));
    expect(await waitFor(() => h.events.length === 1)).toBe(true);
    expect(discards(h.events)).toEqual(['E_SDK_INBOUND_INVALID']);
    expect(h.opens).toHaveLength(0);
  });

  test('a one-mebibyte ciphertext is discarded, and a later valid message is still opened', async () => {
    const h = harness(); const sender = makeKey();
    h.module.ingest(eventFrame(message(sender, h.owner, { content: bytesToBase64(new Uint8Array(1048576)), n: 1 })));
    h.module.ingest(eventFrame(message(sender, h.owner, { n: 2 })));
    expect(await waitFor(() => h.events.length === 2)).toBe(true);
    expect(h.events.map((e) => e.kind)).toEqual(['INBOUND_DISCARDED', 'MESSAGE_RECEIVED']);
    expect(h.opens.map((o) => o.ciphertext.length)).toEqual([3]);
  });

  test('content of exactly 349 528 characters is still opened', async () => {
    const h = harness(); const sender = makeKey();
    h.module.ingest(eventFrame(message(sender, h.owner, { content: 'A'.repeat(CONTENT_MAX) })));
    expect(await waitFor(() => h.events.length === 1)).toBe(true);
    expect(h.events[0].kind).toBe('MESSAGE_RECEIVED');
    expect(h.opens).toHaveLength(1);
    expect(h.opens[0].ciphertext.length).toBe(262146);
  });

  test('the bound is on characters: 262 146 bytes are still opened, 262 147 bytes are refused before open', async () => {
    const h = harness(); const sender = makeKey();
    const fits = bytesToBase64(new Uint8Array(262146));
    const over = bytesToBase64(new Uint8Array(262147));
    expect([fits.length, over.length]).toEqual([CONTENT_MAX, CONTENT_MAX + 4]);
    h.module.ingest(eventFrame(message(sender, h.owner, { content: over, n: 1 })));
    h.module.ingest(eventFrame(message(sender, h.owner, { content: fits, n: 2 })));
    expect(await waitFor(() => h.events.length === 2)).toBe(true);
    expect(h.events.map((e) => e.kind)).toEqual(['INBOUND_DISCARDED', 'MESSAGE_RECEIVED']);
    expect(h.opens.map((o) => o.ciphertext.length)).toEqual([262146]);
  });

  test('a tag list longer than four is refused without reading its later elements', async () => {
    const h = harness(); const sender = makeKey();
    const event = message(sender, h.owner, { receipt: true });
    let reads = 0;
    const tags = [...event.tags];
    expect(tags).toHaveLength(4);
    tags.length = 100000;
    Object.defineProperty(tags, 4, { get: () => { reads += 1; return ['x', 'y']; }, enumerable: true });
    h.module.ingest(eventFrame({ ...event, tags }));
    expect(await waitFor(() => h.events.length === 1)).toBe(true);
    expect(discards(h.events)).toEqual(['E_SDK_INBOUND_INVALID']);
    expect(reads).toBe(0);
    expect(h.opens).toHaveLength(0);
  });

  test('a tag of more than two elements is refused without reading the extra elements', async () => {
    const h = harness(); const sender = makeKey();
    const event = message(sender, h.owner);
    let reads = 0;
    const wide = ['p', h.owner.pub];
    wide.length = 100000;
    Object.defineProperty(wide, 2, { get: () => { reads += 1; return 'x'; }, enumerable: true });
    h.module.ingest(eventFrame({ ...event, tags: [wide, ...event.tags.slice(1)] }));
    expect(await waitFor(() => h.events.length === 1)).toBe(true);
    expect(discards(h.events)).toEqual(['E_SDK_INBOUND_INVALID']);
    expect(reads).toBe(0);
  });
});

describe('C-DLV section 7.2 -- receipt signing does not hold back the inbound queue', () => {
  function held(owner) {
    let release = null; let calls = 0;
    const sign = ({ digest }) => {
      calls += 1;
      const signature = schnorr.sign(digest, owner().priv);
      if (calls !== 1) return signature;
      return new Promise((resolve) => { release = () => resolve(signature); });
    };
    return { sign, released: () => release !== null, release: () => release(), calls: () => calls };
  }

  test('a receipt frame behind a slow receipt signature is acknowledged before the signature settles', async () => {
    let h = null; const slow = held(() => h.owner);
    h = harness({ sign: slow.sign });
    const sender = makeKey();
    h.module.ingest(eventFrame(message(sender, h.owner, { receipt: true, n: 1 })));
    expect(await waitFor(slow.released)).toBe(true);
    const ack = receiptFor(sender, h.owner, 'e'.repeat(64));
    h.module.ingest(eventFrame(ack));
    h.module.ingest(eventFrame(message(sender, h.owner, { n: 2 })));
    // Well inside the 15 s port-call timeout: the held signature is still pending.
    expect(await waitFor(() => h.acks.length === 1, 2000)).toBe(true);
    expect(slow.calls()).toBe(1);
    expect(h.acks).toEqual([{ eventId: 'e'.repeat(64), recipient: sender.pub }]);
    // The next admitted open still follows the held receipt: one unit at a time.
    await flush();
    expect(h.opens).toHaveLength(1);
    expect(h.published).toHaveLength(0);
    slow.release();
    expect(await waitFor(() => h.published.length === 1 && h.opens.length === 2)).toBe(true);
    expect(h.published[0].tags[1]).toEqual(['e', expect.any(String)]);
    expect(h.events.filter((e) => e.kind === 'MESSAGE_RECEIVED')).toHaveLength(2);
  });

  test('shutdown while the signature is held still publishes the owed receipt once within the drain', async () => {
    let h = null; const slow = held(() => h.owner);
    h = harness({ sign: slow.sign });
    const sender = makeKey();
    h.module.ingest(eventFrame(message(sender, h.owner, { receipt: true, n: 3 })));
    expect(await waitFor(slow.released)).toBe(true);
    expect(h.module.shutdown().ok).toBe(true);
    let drained = false; h.module.drained().then(() => { drained = true; });
    await flush();
    expect(drained).toBe(false);
    slow.release();
    expect(await waitFor(() => drained)).toBe(true);
    expect(h.published).toHaveLength(1);
    await h.module.settled();
  });
});
