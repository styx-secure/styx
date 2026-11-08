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

/* ------------------------------------------------------------------------- *
 * M3-RECEIVE-LIMITS (C4): the retained-cost bounds of the inbound queue
 * (C-DLV sections 3 and 7.1), the exact own keys of an event (section 7.1
 * step 1) and the 0.3.1 reading of the five 0.4.0 codes (C-SDK section 5.3).
 * ------------------------------------------------------------------------- */

/** C-DLV section 3: per-frame and retained-total cost bounds. */
const FRAME_COST_MAX = 1048576;
const RETAINED_COST_MAX = 16777216;
/**
 * The cost of one `eventFrame(message(...))` (subscription id `sub`, three
 * tags) with a content of exactly 349 528 characters, by the rule of C-DLV
 * section 7.1: 16 per value, 2 per string character, 8 per array index,
 * 8 + 2 per key character per object key. The largest valid frame, with the
 * `r` tag and a 64-character subscription id, costs 76 + 122 more (700 584).
 */
const MAX_MESSAGE_FRAME_COST = 700386;
const LARGEST_VALID_FRAME_COST = 700584;
const MAX_MESSAGES_RETAINED = Math.floor(RETAINED_COST_MAX / MAX_MESSAGE_FRAME_COST);

function limitsHarness({ audience = true } = {}) {
  const owner = makeKey();
  const opens = [], events = [];
  let releaseKey = null;
  let heldKey = true;
  const state = { audience };
  const module = createReceipts({
    identity: {
      getPublicKey: () => (heldKey ? new Promise((resolve) => { releaseKey = () => resolve(owner.pub); }) : owner.pub),
      sign: ({ digest }) => schnorr.sign(digest, owner.priv),
    },
    session: { open: ({ sender, ciphertext }) => { opens.push({ sender, ciphertext }); return { plaintext: new Uint8Array([7]) }; } },
    clock: { now: () => OWN_CLOCK_MS },
    perRelayTimeoutMs: 30000,
    publishReceipt: () => {},
    acceptReceipt: () => Object.freeze({ ok: true, value: Object.freeze({ accepted: true, deliveryId: 'd1' }) }),
    onEvent: (event) => { events.push(event); },
    reserveMessage: () => (state.audience ? (event) => { events.push(event); return true; } : null),
  });
  return {
    module, owner, opens, events, state,
    held: () => releaseKey !== null,
    release: () => { heldKey = false; if (releaseKey !== null) releaseKey(); },
  };
}
const queued = (envelope) => envelope.ok === true && envelope.value.queued === true;
const received = (events) => events.filter((e) => e.kind === 'MESSAGE_RECEIVED').length;

describe('C-DLV section 7.1 -- retained-cost bounds of the inbound queue', () => {
  test('the documented cost of a maximal valid message frame', () => {
    expect(MAX_MESSAGE_FRAME_COST).toBeLessThan(FRAME_COST_MAX);
    expect(MAX_MESSAGES_RETAINED).toBe(23);
    expect(LARGEST_VALID_FRAME_COST).toBeLessThan(FRAME_COST_MAX);
    expect(Math.floor(RETAINED_COST_MAX / LARGEST_VALID_FRAME_COST)).toBe(23);
  });

  test('a frame over the per-frame bound is not retained: a marker keeps its turn and is E_SDK_INBOUND_INVALID', async () => {
    const h = limitsHarness(); const sender = makeKey();
    expect(queued(h.module.ingest(eventFrame(message(sender, h.owner, { n: 1 }))))).toBe(true);
    expect(await waitFor(h.held)).toBe(true);
    // A valid event whose frame carries a large extra element, and frames whose
    // extra element is deeply nested or self-referencing.
    const frames = [];
    const extra = { relayIndex: 0, relay: 'relay-0', data: ['EVENT', 'sub', message(sender, h.owner, { n: 2 }), 'x'.repeat(600000)] };
    let deep = [];
    for (let i = 0; i < 200000; i += 1) deep = [deep];
    const nested = { relayIndex: 0, relay: 'relay-0', data: ['EVENT', 'sub', message(sender, h.owner, { n: 3 }), deep] };
    const cycle = {}; cycle.self = cycle;
    const cyclic = { relayIndex: 0, relay: 'relay-0', data: ['EVENT', 'sub', message(sender, h.owner, { n: 4 }), cycle] };
    frames.push(extra, nested, cyclic);
    for (const frame of frames) expect(queued(h.module.ingest(frame))).toBe(true);
    // The frames are not kept: replacing their data after ingest changes nothing.
    for (const frame of frames) frame.data = ['EVENT', 'sub', message(sender, h.owner, { n: 5 })];
    expect(queued(h.module.ingest(eventFrame(message(sender, h.owner, { n: 6 }))))).toBe(true);
    h.release();
    expect(await waitFor(() => h.events.length === 5)).toBe(true);
    await flush();
    expect(h.events.map((e) => e.kind === 'MESSAGE_RECEIVED' ? 'M' : e.code)).toEqual([
      'M', 'E_SDK_INBOUND_INVALID', 'E_SDK_INBOUND_INVALID', 'E_SDK_INBOUND_INVALID', 'M',
    ]);
    expect(h.opens).toHaveLength(2);
  });

  test('control: an oversized content is still E_SDK_INBOUND_INVALID in arrival order, also far over the frame bound', async () => {
    const h = limitsHarness(); const sender = makeKey();
    h.release();
    h.module.ingest(eventFrame(message(sender, h.owner, { content: 'A'.repeat(600000), n: 1 })));
    h.module.ingest(eventFrame(message(sender, h.owner, { n: 2 })));
    h.module.ingest(eventFrame(message(sender, h.owner, { content: 'A'.repeat(4000000), n: 3 })));
    expect(await waitFor(() => h.events.length === 3)).toBe(true);
    expect(h.events.map((e) => e.kind === 'MESSAGE_RECEIVED' ? 'M' : e.code)).toEqual([
      'E_SDK_INBOUND_INVALID', 'M', 'E_SDK_INBOUND_INVALID',
    ]);
  });

  test('with the durable receive state an over-bound frame is accounted at once: invalid event, or barrier failure', async () => {
    const owner = makeKey(); const sender = makeKey();
    const accounted = [];
    const module = createReceipts({
      identity: { getPublicKey: () => owner.pub, sign: ({ digest }) => schnorr.sign(digest, owner.priv) },
      session: { open: () => ({ plaintext: new Uint8Array([7]) }) },
      clock: { now: () => OWN_CLOCK_MS },
      perRelayTimeoutMs: 30000,
      publishReceipt: () => {},
      acceptReceipt: () => Object.freeze({ ok: true, value: Object.freeze({ accepted: true, deliveryId: 'd1' }) }),
      onEvent: () => {},
      receiveState: {
        account: (frame, outcome) => { accounted.push([frame.tag, outcome]); },
        admit: async (event, frame) => { accounted.push([frame.tag, 'admitted']); },
      },
    });
    const tagged = (tag, data) => ({ tag, relayIndex: 0, relay: 'relay-0', data });
    module.ingest(tagged('content', ['EVENT', 'sub', message(sender, owner, { content: 'A'.repeat(600000), n: 1 })]));
    module.ingest(tagged('extra', ['EVENT', 'sub', message(sender, owner, { n: 2 }), 'x'.repeat(600000)]));
    expect(accounted).toEqual([['content', 'invalid'], ['extra', 'dropped']]);
    module.ingest(tagged('plain', ['EVENT', 'sub', message(sender, owner, { n: 3 })]));
    expect(await waitFor(() => accounted.length === 3)).toBe(true);
    expect(accounted[2]).toEqual(['plain', 'admitted']);
    module.shutdown();
    await module.settled();
  });

  test('maximal valid messages fill the retained total while validation is held; release lets replays and new frames in', async () => {
    const h = limitsHarness(); const sender = makeKey();
    const content = 'A'.repeat(CONTENT_MAX);
    const events = Array.from({ length: MAX_MESSAGES_RETAINED + 2 }, (_, i) => message(sender, h.owner, { content, n: 10 + i }));
    const first = events.map((event) => queued(h.module.ingest(eventFrame(event))));
    expect(first).toEqual([...Array(MAX_MESSAGES_RETAINED).fill(true), false, false]);
    expect(await waitFor(h.held)).toBe(true);
    // A small frame still fits beside them.
    expect(queued(h.module.ingest(eventFrame(message(sender, h.owner, { n: 99 }))))).toBe(true);
    h.release();
    expect(await waitFor(() => received(h.events) === MAX_MESSAGES_RETAINED + 1)).toBe(true);
    // Every charge was released: the two refused frames are admitted on a replay.
    expect(events.slice(MAX_MESSAGES_RETAINED).map((event) => queued(h.module.ingest(eventFrame(event))))).toEqual([true, true]);
    expect(await waitFor(() => received(h.events) === MAX_MESSAGES_RETAINED + 3)).toBe(true);
    // And a fresh batch fills the bound exactly as the first one did.
    const fresh = Array.from({ length: MAX_MESSAGES_RETAINED + 1 }, (_, i) => message(sender, h.owner, { content, n: 200 + i }));
    expect(fresh.map((event) => queued(h.module.ingest(eventFrame(event)))))
      .toEqual([...Array(MAX_MESSAGES_RETAINED).fill(true), false]);
    expect(await waitFor(() => received(h.events) === 2 * MAX_MESSAGES_RETAINED + 3)).toBe(true);
    expect(discards(h.events)).toEqual([]);
  });

  test('messages waiting for an audience keep their charge until their open starts', async () => {
    const h = limitsHarness({ audience: false }); const sender = makeKey();
    h.release();
    const content = 'A'.repeat(CONTENT_MAX);
    for (let i = 0; i < MAX_MESSAGES_RETAINED; i += 1) {
      expect(queued(h.module.ingest(eventFrame(message(sender, h.owner, { content, n: 300 + i }))))).toBe(true);
    }
    // A small sentinel, processed after them in arrival order, also waits.
    expect(queued(h.module.ingest(eventFrame(message(sender, h.owner, { n: 399 }))))).toBe(true);
    await flush(40);
    expect(h.opens).toHaveLength(0);
    const late = message(sender, h.owner, { content, n: 400 });
    expect(queued(h.module.ingest(eventFrame(late)))).toBe(false);
    h.state.audience = true;
    h.module.wake();
    expect(await waitFor(() => received(h.events) === MAX_MESSAGES_RETAINED + 1)).toBe(true);
    expect(queued(h.module.ingest(eventFrame(late)))).toBe(true);
    expect(await waitFor(() => received(h.events) === MAX_MESSAGES_RETAINED + 2)).toBe(true);
  });

  test('discarded, duplicate and receipt frames release their charge', async () => {
    const h = limitsHarness(); const sender = makeKey();
    h.release();
    const content = 'A'.repeat(CONTENT_MAX);
    const once = message(sender, h.owner, { content, n: 500 });
    // Invalid (wrong p tag), duplicate copies and a receipt, together well past the total.
    const stranger = makeKey();
    for (let i = 0; i < 3 * MAX_MESSAGES_RETAINED; i += 1) {
      expect(queued(h.module.ingest(eventFrame(message(sender, stranger, { content, n: 600 + i }))))).toBe(true);
      expect(queued(h.module.ingest(eventFrame(once)))).toBe(true);
      expect(queued(h.module.ingest(eventFrame(receiptFor(sender, h.owner, 'e'.repeat(64)))))).toBe(true);
      expect(await waitFor(() => discards(h.events).length === i + 1)).toBe(true);
    }
    // A sentinel processed after every earlier frame.
    h.module.ingest(eventFrame(message(sender, h.owner, { n: 699 })));
    expect(await waitFor(() => received(h.events) === 2)).toBe(true);
    expect(discards(h.events)).toHaveLength(3 * MAX_MESSAGES_RETAINED);
    const batch = Array.from({ length: MAX_MESSAGES_RETAINED }, (_, i) => message(sender, h.owner, { content, n: 700 + i }));
    expect(batch.map((event) => queued(h.module.ingest(eventFrame(event))))).toEqual(Array(MAX_MESSAGES_RETAINED).fill(true));
    expect(await waitFor(() => received(h.events) === MAX_MESSAGES_RETAINED + 2)).toBe(true);
  });

  test('shutdown drops everything retained and reports it; nothing is queued after it', async () => {
    const h = limitsHarness(); const sender = makeKey();
    const content = 'A'.repeat(CONTENT_MAX);
    for (let i = 0; i < MAX_MESSAGES_RETAINED; i += 1) h.module.ingest(eventFrame(message(sender, h.owner, { content, n: 800 + i })));
    expect(await waitFor(h.held)).toBe(true);
    const stopped = h.module.shutdown();
    expect(stopped.ok).toBe(true);
    expect(stopped.value.dropped).toBe(MAX_MESSAGES_RETAINED - 1);
    expect(queued(h.module.ingest(eventFrame(message(sender, h.owner, { n: 900 }))))).toBe(false);
    h.release();
    await flush();
    expect(h.opens).toHaveLength(0);
    await h.module.settled();
  });
});

describe('C-DLV section 7.1 step 1 -- exactly the seven own keys', () => {
  test.each([
    ['a non-enumerable eighth key', (event) => Object.defineProperty({ ...event }, 'extra', { value: 1, enumerable: false })],
    ['a symbol key', (event) => ({ ...event, [Symbol('extra')]: 1 })],
    ['one of the seven non-enumerable', (event) => {
      const copy = { ...event }; delete copy.sig;
      return Object.defineProperty(copy, 'sig', { value: event.sig, enumerable: false });
    }],
  ])('an event with %s is E_SDK_INBOUND_INVALID before open', async (_, shape) => {
    const h = harness(); const sender = makeKey();
    h.module.ingest(eventFrame(shape(message(sender, h.owner))));
    expect(await waitFor(() => h.events.length === 1)).toBe(true);
    expect(discards(h.events)).toEqual(['E_SDK_INBOUND_INVALID']);
    expect(h.opens).toHaveLength(0);
  });

  test('control: a plain copy of the same event is opened', async () => {
    const h = harness(); const sender = makeKey();
    h.module.ingest(eventFrame({ ...message(sender, h.owner) }));
    expect(await waitFor(() => h.events.length === 1)).toBe(true);
    expect(h.events[0].kind).toBe('MESSAGE_RECEIVED');
  });
});

describe('C-SDK section 5.3 -- the 0.3.1 inbound path reads the five 0.4.0 codes as unknown (S-08, unchanged)', () => {
  const ADDED = [
    'E_SDK_RECEIVE_STATE_FAILED',
    'E_SDK_RECEIVE_STATE_INCOMPATIBLE',
    'E_SDK_RECEIVE_STATE_CONFLICT',
    'E_SDK_RECEIVE_STATE_CAPACITY',
    'E_SDK_UNKNOWN_MESSAGE',
  ];
  test.each(ADDED)('session.open returning { code: %s } is E_SDK_UNKNOWN_CODE', async (code) => {
    const owner = makeKey(); const events = [];
    const module = createReceipts({
      identity: { getPublicKey: () => owner.pub, sign: ({ digest }) => schnorr.sign(digest, owner.priv) },
      session: { open: () => Object.freeze({ code }) },
      clock: { now: () => OWN_CLOCK_MS },
      perRelayTimeoutMs: 30000,
      publishReceipt: () => {},
      acceptReceipt: () => Object.freeze({ ok: true, value: Object.freeze({ accepted: true, deliveryId: 'd1' }) }),
      onEvent: (event) => { events.push(event); },
    });
    module.ingest(eventFrame(message(makeKey(), owner)));
    expect(await waitFor(() => events.length === 1)).toBe(true);
    expect(events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }]);
  });

  test.each(ADDED)('acceptReceipt failing with %s is E_SDK_UNKNOWN_CODE', async (code) => {
    const owner = makeKey(); const recipient = makeKey(); const events = [];
    const module = createReceipts({
      identity: { getPublicKey: () => owner.pub, sign: ({ digest }) => schnorr.sign(digest, owner.priv) },
      session: { open: () => ({ plaintext: new Uint8Array([7]) }) },
      clock: { now: () => OWN_CLOCK_MS },
      perRelayTimeoutMs: 30000,
      publishReceipt: () => {},
      acceptReceipt: () => Object.freeze({ ok: false, code }),
      onEvent: (event) => { events.push(event); },
    });
    module.ingest(eventFrame(receiptFor(recipient, owner, 'e'.repeat(64))));
    expect(await waitFor(() => events.length === 1)).toBe(true);
    expect(events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }]);
  });
});

describe('M3-RECEIVE-LIMITS review cycle 1 -- the largest valid frame and a stop during the cost walk', () => {
  test('23 of the largest valid frames (r tag, 64-character subscription id) fit while validation is held; the 24th does not', async () => {
    const h = limitsHarness(); const sender = makeKey();
    const content = 'A'.repeat(CONTENT_MAX);
    const subscription = 's'.repeat(64);
    const frames = Array.from({ length: 24 }, (_, i) => ({ relayIndex: 0, relay: 'relay-0',
      data: ['EVENT', subscription, message(sender, h.owner, { content, receipt: true, n: 1000 + i })] }));
    expect(frames.map((frame) => queued(h.module.ingest(frame)))).toEqual([...Array(23).fill(true), false]);
    h.release();
    expect(await waitFor(() => received(h.events) === 23)).toBe(true);
    expect(discards(h.events)).toEqual([]);
  });

  test('a shutdown() re-entered from the cost walk queues nothing, on the ordinary and on the marker path', async () => {
    for (const oversized of [false, true]) {
      const h = limitsHarness(); const sender = makeKey();
      h.release();
      let calls = 0;
      const target = message(sender, h.owner, { n: 1 });
      const event = new Proxy(target, {
        ownKeys: (t) => { calls += 1; h.module.shutdown(); return Reflect.ownKeys(t); },
      });
      const data = oversized ? ['EVENT', 'sub', event, 'x'.repeat(600000)] : ['EVENT', 'sub', event];
      const result = h.module.ingest({ relayIndex: 0, relay: 'relay-0', data });
      expect(calls).toBe(1);
      expect(queued(result)).toBe(false);
      h.module.wake();
      await flush();
      expect(h.events).toEqual([]);
      expect(h.opens).toHaveLength(0);
      await h.module.settled();
    }
  });
});
