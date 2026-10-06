/**
 * I-ACK -- tests for the inbound receipts, acknowledgements and duplicate
 * handling module (`src/sdk/delivery/receipts.js`).
 *
 * Every expectation below is the expectation of C-DLV sections 6.1, 6.3, 7 and
 * 8 and of the C-SDK closed sets; the section is named next to each group.
 * The inbound frames are the `{ relayIndex, relay, data }` records card I-RELAY's
 * `onFrame` emits; the session, clock and identity ports are fakes that carry
 * the shapes of C-SDK section 8; the item-side acknowledgement seam and the
 * inbound publication seam are fakes standing in for card I-QUEUE's
 * `acceptReceipt` and for the client's per-relay publication.
 */

import { describe, expect, test } from '@jest/globals';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

import { bytesToBase64, bytesToHex, hexToBytes, utf8Encode } from '../../../src/utils.js';
import { createReceipts } from '../../../src/sdk/delivery/receipts.js';

const VERSION = 'styx-m3-sdk/0.1.0-experimental';
const FRAME_N = 'a'.repeat(32);
const FRAME_N_2 = 'b'.repeat(32);
const OWN_CLOCK_MS = 12000;
const PORT_CALL_TIMEOUT_MS = 20;

/* ------------------------------------------------------------------------- *
 * Harness
 * ------------------------------------------------------------------------- */

/** Wait for the microtask/macrotask chain of one frame pass to drain. */
async function flush(rounds = 4) {
  for (let index = 0; index < rounds; index += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

/** Wait until a predicate holds, or the budget is spent; never depends on a fixed delay. */
async function waitFor(predicate, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) break;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return predicate();
}

function makeKey() {
  const priv = schnorr.utils.randomPrivateKey();
  return { priv, pub: bytesToHex(schnorr.getPublicKey(priv)) };
}

function eventIdOf(pubkey, createdAt, kind, tags, content) {
  return bytesToHex(sha256(utf8Encode(JSON.stringify([0, pubkey, createdAt, kind, tags, content]))));
}

/** Build one event of section 6.1; every field may be overridden to break it. */
function buildEvent({
  priv,
  pub,
  kind = 4741,
  tags = [['p', pub], ['v', VERSION], ['n', FRAME_N]],
  content = bytesToBase64(new Uint8Array([1, 2, 3])),
  createdAt = OWN_CLOCK_MS / 1000,
  id = null,
  sig = null,
  drop = null,
}) {
  const real = eventIdOf(pub, createdAt, kind, tags, content);
  const event = {
    id: id ?? real,
    pubkey: pub,
    created_at: createdAt,
    kind,
    tags,
    content,
    sig: sig ?? bytesToHex(schnorr.sign(hexToBytes(real), priv)),
  };
  if (drop !== null) delete event[drop];
  return event;
}

/** A kind-4741 message event addressed to `owner`, optionally asking for a receipt. */
function messageEvent({ sender, owner, askReceipt = true, payload = [1, 2, 3], n = FRAME_N, createdAt = OWN_CLOCK_MS / 1000 }) {
  const tags = [['p', owner], ['v', VERSION], ['n', n]];
  if (askReceipt) tags.push(['r', '1']);
  return buildEvent({
    priv: sender.priv,
    pub: sender.pub,
    tags,
    content: bytesToBase64(new Uint8Array(payload)),
    createdAt,
  });
}

/** A kind-4742 acknowledgement event. */
function receiptEvent({ recipient, owner, eventId, n = FRAME_N_2, createdAt = OWN_CLOCK_MS / 1000 }) {
  return buildEvent({
    priv: recipient.priv,
    pub: recipient.pub,
    kind: 4742,
    tags: [['p', owner], ['e', eventId], ['v', VERSION], ['n', n]],
    content: '',
    createdAt,
  });
}

function frame(data, relayIndex = 0) {
  return { relayIndex, relay: `relay-${relayIndex}`, data };
}

function eventFrame(event, relayIndex = 0) {
  return frame(['EVENT', 'sub', event], relayIndex);
}

function makeHarness(overrides = {}) {
  /* A caller may hand in the key it built its frames for, so that a frame whose
   * `p` tag names that key still passes step 3 in this client (owner decision
   * H2: one owner key across both harnesses, or the property is vacuous). */
  const owner = overrides.owner ?? makeKey();
  const other = makeKey();
  const published = [];
  const events = [];
  const acks = [];
  const opens = [];
  const defaults = {
    identity: {
      getPublicKey: () => owner.pub,
      sign: ({ digest }) => schnorr.sign(digest, owner.priv),
    },
    session: {
      open: ({ sender, ciphertext }) => {
        opens.push({ sender, ciphertext });
        return { plaintext: new Uint8Array([7, 8, 9]) };
      },
    },
    clock: { now: () => OWN_CLOCK_MS },
    perRelayTimeoutMs: PORT_CALL_TIMEOUT_MS * 2,
    publishReceipt: (event) => {
      published.push(event);
    },
    acceptReceipt: ({ eventId, recipient }) => {
      acks.push({ eventId, recipient });
      /* C-SDK section 5.1 and C-DLV section 4.5: only the exact frozen envelope
       * of the interface leaves the module silent. */
      return Object.freeze({ ok: true, value: Object.freeze({ accepted: true, deliveryId: 'd1' }) });
    },
    onEvent: (event) => {
      events.push(event);
    },
  };
  for (const key of Object.keys(overrides)) {
    if (key === 'owner') continue;
    if (overrides[key] === undefined) delete defaults[key];
    else defaults[key] = overrides[key];
  }
  const module = createReceipts(defaults);
  return { module, owner, other, published, events, acks, opens, options: defaults };
}

/* ------------------------------------------------------------------------- *
 * The export set and the returned surface
 * ------------------------------------------------------------------------- */

describe('module surface', () => {
  test('the module exports exactly createReceipts', async () => {
    const namespace = await import('../../../src/sdk/delivery/receipts.js');
    expect(Object.keys(namespace)).toEqual(['createReceipts']);
    expect(typeof namespace.createReceipts).toBe('function');
  });

  test('the returned object is frozen and carries exactly ingest and shutdown', () => {
    const { module } = makeHarness();
    expect(Object.isFrozen(module)).toBe(true);
    expect(Object.keys(module).sort()).toEqual(['ingest', 'shutdown']);
    expect(typeof module.ingest).toBe('function');
    expect(typeof module.shutdown).toBe('function');
  });

  test('createReceipts never throws, for any options, and every method answers', async () => {
    const throwing = new Proxy({}, {
      get() {
        throw new Error('port getter throws');
      },
      has() {
        throw new Error('port has throws');
      },
    });
    const values = [
      undefined,
      null,
      0,
      '',
      false,
      [],
      new Map(),
      { identity: throwing, session: throwing, clock: throwing },
      Object.create(null),
    ];
    for (const value of values) {
      let module;
      expect(() => {
        module = createReceipts(value);
      }).not.toThrow();
      expect(Object.isFrozen(module)).toBe(true);
      expect(module.ingest({ relayIndex: 0, relay: 'r', data: ['EVENT', 'sub', {}] })).toEqual({
        ok: true,
        value: { queued: true },
      });
      await flush();
      expect(module.shutdown()).toEqual({ ok: true, value: { dropped: 0 } });
    }
  });

  test('ingest answers the frozen envelope of the contract for every frame shape', () => {
    const { module } = makeHarness();
    const cases = [
      undefined,
      null,
      0,
      'EVENT',
      [],
      {},
      { data: null },
      { data: [] },
      { data: ['NOTICE', 'sub', 'hello'] },
      { data: ['EOSE', 'sub'] },
      { data: ['CLOSED', 'sub', 'reason'] },
      { data: ['OK', 'event-id', true] },
      { data: ['EVENT'] },
      { data: ['EVENT', 'sub'] },
    ];
    for (const record of cases) {
      const result = module.ingest(record);
      expect(result).toEqual({ ok: true, value: { queued: false } });
      expect(Object.isFrozen(result)).toBe(true);
      expect(Object.isFrozen(result.value)).toBe(true);
      expect(() => {
        result.value.queued = true;
      }).toThrow();
    }
  });

  test('an EVENT frame of this subscription is queued and its envelope is frozen', () => {
    const { module, owner, other } = makeHarness();
    const event = messageEvent({ sender: other, owner: owner.pub });
    const result = module.ingest(eventFrame(event, 1));
    expect(result).toEqual({ ok: true, value: { queued: true } });
    expect(Object.isFrozen(result.value)).toBe(true);
  });

  test('shutdown answers the frozen envelope, then E_SDK_CLIENT_STOPPED', () => {
    const { module } = makeHarness();
    const first = module.shutdown();
    expect(first).toEqual({ ok: true, value: { dropped: 0 } });
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.value)).toBe(true);
    const second = module.shutdown();
    expect(second).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    expect(Object.isFrozen(second)).toBe(true);
    expect(() => {
      second.code = 'x';
    }).toThrow();
  });

  test('a record with a throwing getter is dropped without a throw', async () => {
    const { module, events } = makeHarness();
    const record = { relayIndex: 0, relay: 'r' };
    Object.defineProperty(record, 'data', {
      get() {
        throw new Error('frame getter throws');
      },
    });
    expect(module.ingest(record)).toEqual({ ok: true, value: { queued: false } });
    await flush();
    expect(events).toEqual([]);
  });
});

/* ------------------------------------------------------------------------- *
 * C-DLV section 7.1, step 1: a plain object with exactly the seven keys of
 * section 6.1, every field in the form given there.
 * ------------------------------------------------------------------------- */

describe('section 7.1 step 1 -- the structure of section 6.1', () => {
  const invalid = (data) => frame(['EVENT', 'sub', data]);

  test('a non-object, an array, a function, a string and null are all discarded', async () => {
    const { module, events } = makeHarness();
    for (const value of [null, undefined, 7, 'x', true, [], [1, 2], () => {}, new Date()]) {
      module.ingest(invalid(value));
    }
    await flush();
    expect(events).toHaveLength(9);
    for (const event of events) {
      expect(event).toEqual({ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INBOUND_INVALID' });
    }
  });

  test('a missing key, an extra key and a key of another name are all discarded', async () => {
    const { module, owner, other, events } = makeHarness();
    const good = messageEvent({ sender: other, owner: owner.pub });
    for (const drop of ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig']) {
      module.ingest(invalid(buildEvent({ ...good, drop })));
    }
    module.ingest(invalid({ ...good, extra: 1 }));
    module.ingest(invalid({ ...good, id: undefined }));
    await flush();
    expect(events).toHaveLength(9);
    for (const event of events) expect(event.code).toBe('E_SDK_INBOUND_INVALID');
  });

  test('an id that is not 64 lowercase hexadecimal digits is discarded', async () => {
    const { module, owner, other, events } = makeHarness();
    const good = messageEvent({ sender: other, owner: owner.pub });
    for (const id of [
      good.id.toUpperCase(),
      good.id.slice(0, 63),
      `${good.id}0`,
      `0x${good.id}`,
      good.id.replace('0', 'g'),
      'z'.repeat(64),
      '',
      1234,
    ]) {
      module.ingest(invalid({ ...good, id }));
    }
    await flush();
    expect(events).toHaveLength(8);
  });

  test('a sig that is not 128 lowercase hexadecimal digits is discarded', async () => {
    const { module, owner, other, events } = makeHarness();
    const good = messageEvent({ sender: other, owner: owner.pub });
    for (const sig of [
      good.sig.toUpperCase(),
      good.sig.slice(0, 127),
      `${good.sig}0`,
      'f'.repeat(127),
      '',
      null,
    ]) {
      module.ingest(invalid({ ...good, sig }));
    }
    await flush();
    expect(events).toHaveLength(6);
  });

  test('a pubkey that is not 64 lowercase hexadecimal digits is discarded', async () => {
    const { module, owner, other, events } = makeHarness();
    const good = messageEvent({ sender: other, owner: owner.pub });
    for (const pubkey of [
      good.pubkey.toUpperCase(),
      good.pubkey.slice(0, 63),
      `${good.pubkey}0`,
      'g'.repeat(64),
      '',
      42,
    ]) {
      module.ingest(invalid({ ...good, pubkey }));
    }
    await flush();
    expect(events).toHaveLength(6);
  });

  test('a created_at that is not a non-negative safe integer is discarded', async () => {
    const { module, owner, other, events } = makeHarness();
    const good = messageEvent({ sender: other, owner: owner.pub });
    for (const created_at of [
      -1,
      -0.5,
      1.5,
      '12000',
      null,
      undefined,
      Number.MAX_SAFE_INTEGER + 1,
      Infinity,
      NaN,
      true,
    ]) {
      module.ingest(invalid({ ...good, created_at }));
    }
    await flush();
    expect(events).toHaveLength(10);
  });

  test('a kind that is not a safe integer is discarded', async () => {
    const { module, owner, other, events } = makeHarness();
    const good = messageEvent({ sender: other, owner: owner.pub });
    for (const kind of ['4741', 4741.5, null, undefined, true, 1e30]) {
      module.ingest(invalid({ ...good, kind }));
    }
    await flush();
    expect(events).toHaveLength(6);
  });

  test('tags that are not an array of arrays of strings are discarded', async () => {
    const { module, owner, other, events } = makeHarness();
    const good = messageEvent({ sender: other, owner: owner.pub });
    for (const tags of [
      null,
      undefined,
      'p',
      {},
      [[]],
      [['p', owner.pub], ['v', VERSION], 'n'],
      [['p', owner.pub], ['v', VERSION], ['n', 1]],
      [['p', owner.pub], ['v', VERSION], ['n', null]],
      [['p', owner.pub], ['v', VERSION], ['n', []]],
    ]) {
      module.ingest(invalid({ ...good, tags }));
    }
    await flush();
    expect(events).toHaveLength(9);
  });

  test('a content that is not a string is discarded', async () => {
    const { module, owner, other, events } = makeHarness();
    const good = messageEvent({ sender: other, owner: owner.pub });
    for (const content of [null, undefined, 5, [], {}, true]) {
      module.ingest(invalid({ ...good, content }));
    }
    await flush();
    expect(events).toHaveLength(6);
    for (const event of events) expect(event.code).toBe('E_SDK_INBOUND_INVALID');
  });
});

/* ------------------------------------------------------------------------- *
 * C-DLV section 7.1, step 2: kind is 4741 or 4742.
 * ------------------------------------------------------------------------- */

describe('section 7.1 step 2 -- the kind', () => {
  test('a kind other than 4741 and 4742 is discarded', async () => {
    const { module, owner, other, events } = makeHarness();
    for (const kind of [0, 1, 4740, 4743, 4744, 30000, 65535]) {
      const tags = kind === 4742
        ? [['p', owner.pub], ['e', 'a'.repeat(64)], ['v', VERSION], ['n', FRAME_N]]
        : [['p', owner.pub], ['v', VERSION], ['n', FRAME_N]];
      module.ingest(frame(['EVENT', 'sub', buildEvent({
        priv: other.priv, pub: other.pub, kind, tags, content: kind === 4742 ? '' : 'AA==',
      })]));
    }
    await flush();
    expect(events).toHaveLength(7);
    for (const event of events) expect(event.code).toBe('E_SDK_INBOUND_INVALID');
  });
});

/* ------------------------------------------------------------------------- *
 * C-DLV section 7.1, step 3: the tags are exactly the closed tag list of
 * section 6.2 or 6.3, with every value in the form given there, and the p tag
 * equals the client's own public key.
 * ------------------------------------------------------------------------- */

describe('section 7.1 step 3 -- the tag list of kind 4741', () => {
  const withTags = (harness, tags, content) => {
    harness.module.ingest(frame(['EVENT', 'sub', buildEvent({
      priv: harness.other.priv, pub: harness.other.pub, tags, content,
    })]));
  };

  test('the three fixed tags, in order, are accepted', async () => {
    const harness = makeHarness();
    withTags(harness, [['p', harness.owner.pub], ['v', VERSION], ['n', FRAME_N]], 'AA==');
    await flush();
    expect(harness.events).toEqual([{ kind: 'MESSAGE_RECEIVED', sender: harness.other.pub, payload: new Uint8Array([7, 8, 9]) }]);
  });

  test('the three fixed tags plus ["r", "1"] as the fourth are accepted', async () => {
    const harness = makeHarness();
    withTags(harness, [['p', harness.owner.pub], ['v', VERSION], ['n', FRAME_N], ['r', '1']], 'AA==');
    await flush();
    expect(harness.events).toHaveLength(1);
    expect(harness.published).toHaveLength(1);
  });

  test('two tags and five tags are discarded', async () => {
    const harness = makeHarness();
    withTags(harness, [['p', harness.owner.pub], ['v', VERSION]], 'AA==');
    withTags(harness, [
      ['p', harness.owner.pub], ['v', VERSION], ['n', FRAME_N], ['r', '1'], ['r', '1'],
    ], 'AA==');
    await flush();
    expect(harness.events).toHaveLength(2);
    for (const event of harness.events) expect(event.code).toBe('E_SDK_INBOUND_INVALID');
  });

  test('a different tag order is discarded', async () => {
    const harness = makeHarness();
    withTags(harness, [['v', VERSION], ['p', harness.owner.pub], ['n', FRAME_N]], 'AA==');
    withTags(harness, [['p', harness.owner.pub], ['n', FRAME_N], ['v', VERSION]], 'AA==');
    await flush();
    expect(harness.events).toHaveLength(2);
    for (const event of harness.events) expect(event.code).toBe('E_SDK_INBOUND_INVALID');
  });

  test('a p tag naming another key is discarded', async () => {
    const harness = makeHarness();
    withTags(harness, [['p', harness.other.pub], ['v', VERSION], ['n', FRAME_N]], 'AA==');
    await flush();
    expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INBOUND_INVALID' }]);
    expect(harness.opens).toHaveLength(0);
  });

  test('a p tag with one element, three elements or a non-string value is discarded', async () => {
    const harness = makeHarness();
    withTags(harness, [['p'], ['v', VERSION], ['n', FRAME_N]], 'AA==');
    withTags(harness, [['p', harness.owner.pub, 'x'], ['v', VERSION], ['n', FRAME_N]], 'AA==');
    withTags(harness, [['p', 1], ['v', VERSION], ['n', FRAME_N]], 'AA==');
    await flush();
    expect(harness.events).toHaveLength(3);
  });

  test('a v tag of another version is discarded', async () => {
    const harness = makeHarness();
    withTags(harness, [['p', harness.owner.pub], ['v', 'styx-m3-sdk/9'], ['n', FRAME_N]], 'AA==');
    withTags(harness, [['p', harness.owner.pub], ['v', ''], ['n', FRAME_N]], 'AA==');
    await flush();
    expect(harness.events).toHaveLength(2);
    for (const event of harness.events) expect(event.code).toBe('E_SDK_INBOUND_INVALID');
    expect(harness.opens).toHaveLength(0);
  });

  test('an n tag that is not 32 lowercase hex digits is discarded', async () => {
    const harness = makeHarness();
    for (const n of [FRAME_N.toUpperCase(), FRAME_N.slice(0, 31), `${FRAME_N}0`, 'z'.repeat(32), '', 3]) {
      withTags(harness, [['p', harness.owner.pub], ['v', VERSION], ['n', n]], 'AA==');
    }
    await flush();
    expect(harness.events).toHaveLength(6);
  });

  test('a fourth tag other than exactly ["r", "1"] is discarded', async () => {
    const harness = makeHarness();
    for (const fourth of [['r', '0'], ['r', 1], ['r'], ['s', '1'], ['r', '1', 'x'], ['e', '1']]) {
      withTags(harness, [['p', harness.owner.pub], ['v', VERSION], ['n', FRAME_N], fourth], 'AA==');
    }
    await flush();
    expect(harness.events).toHaveLength(6);
    expect(harness.published).toHaveLength(0);
  });
});

describe('section 7.1 step 3 -- the tag list of kind 4742', () => {
  const withTags = (harness, tags, content) => {
    harness.module.ingest(frame(['EVENT', 'sub', buildEvent({
      priv: harness.other.priv, pub: harness.other.pub, kind: 4742, tags, content,
    })]));
  };

  test('the four fixed tags with the empty content are accepted', async () => {
    const harness = makeHarness();
    withTags(harness, [['p', harness.owner.pub], ['e', 'c'.repeat(64)], ['v', VERSION], ['n', FRAME_N]], '');
    await flush();
    expect(harness.acks).toEqual([{ eventId: 'c'.repeat(64), recipient: harness.other.pub }]);
    expect(harness.events).toEqual([]);
  });

  test('a tag count of three or five is discarded', async () => {
    const harness = makeHarness();
    withTags(harness, [['p', harness.owner.pub], ['e', 'c'.repeat(64)], ['v', VERSION]], '');
    withTags(harness, [
      ['p', harness.owner.pub], ['e', 'c'.repeat(64)], ['v', VERSION], ['n', FRAME_N], ['n', FRAME_N],
    ], '');
    await flush();
    expect(harness.events).toHaveLength(2);
    expect(harness.acks).toHaveLength(0);
  });

  test('a different tag order is discarded', async () => {
    const harness = makeHarness();
    withTags(harness, [['p', harness.owner.pub], ['v', VERSION], ['e', 'c'.repeat(64)], ['n', FRAME_N]], '');
    await flush();
    expect(harness.events).toHaveLength(1);
  });

  test('an e tag that is not 64 lowercase hex digits is discarded', async () => {
    const harness = makeHarness();
    for (const e of ['c'.repeat(64).toUpperCase(), 'c'.repeat(63), `${'c'.repeat(64)}c`, '', 7]) {
      withTags(harness, [['p', harness.owner.pub], ['e', e], ['v', VERSION], ['n', FRAME_N]], '');
    }
    await flush();
    expect(harness.events).toHaveLength(5);
    expect(harness.acks).toHaveLength(0);
  });

  test('a non-empty content is discarded', async () => {
    const harness = makeHarness();
    withTags(harness, [['p', harness.owner.pub], ['e', 'c'.repeat(64)], ['v', VERSION], ['n', FRAME_N]], 'AA==');
    await flush();
    expect(harness.events).toHaveLength(1);
    expect(harness.acks).toHaveLength(0);
  });

  test('a p tag naming another key and a v tag of another version are discarded', async () => {
    const harness = makeHarness();
    withTags(harness, [['p', harness.other.pub], ['e', 'c'.repeat(64)], ['v', VERSION], ['n', FRAME_N]], '');
    withTags(harness, [['p', harness.owner.pub], ['e', 'c'.repeat(64)], ['v', 'styx-m3-sdk/9'], ['n', FRAME_N]], '');
    await flush();
    expect(harness.events).toHaveLength(2);
    expect(harness.acks).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------------- *
 * C-DLV section 7.1, steps 4 and 5: the recomputed id and the signature.
 * ------------------------------------------------------------------------- */

describe('section 7.1 steps 4 and 5 -- the id and the signature', () => {
  test('a well-formed id that is not the recomputed one is discarded', async () => {
    const harness = makeHarness();
    const good = messageEvent({ sender: harness.other, owner: harness.owner.pub });
    harness.module.ingest(frame(['EVENT', 'sub', { ...good, id: 'd'.repeat(64) }]));
    await flush();
    expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INBOUND_INVALID' }]);
    expect(harness.opens).toHaveLength(0);
  });

  test('every one of the six signed fields changes the recomputed id', async () => {
    const harness = makeHarness();
    const good = messageEvent({ sender: harness.other, owner: harness.owner.pub });
    const mutated = [
      { ...good, pubkey: harness.owner.pub },
      { ...good, created_at: good.created_at + 1 },
      { ...good, kind: 4742 },
      { ...good, tags: [['p', harness.owner.pub], ['v', VERSION], ['n', FRAME_N_2], ['r', '1']] },
      { ...good, content: bytesToBase64(new Uint8Array([9])) },
    ];
    for (const event of mutated) harness.module.ingest(frame(['EVENT', 'sub', event]));
    await flush();
    expect(harness.events).toHaveLength(5);
    for (const event of harness.events) expect(event.code).toBe('E_SDK_INBOUND_INVALID');
  });

  test('a signature over another digest, another key or with a flipped bit is discarded', async () => {
    const harness = makeHarness();
    const good = messageEvent({ sender: harness.other, owner: harness.owner.pub });
    const wrongKey = bytesToHex(schnorr.sign(hexToBytes(good.id), harness.owner.priv));
    const flipped = bytesToHex(hexToBytes(good.sig).map((byte, index) => (index === 63 ? byte ^ 1 : byte)));
    const otherDigest = bytesToHex(schnorr.sign(new Uint8Array(32).fill(3), harness.other.priv));
    for (const sig of [wrongKey, flipped, otherDigest]) {
      harness.module.ingest(frame(['EVENT', 'sub', { ...good, sig }]));
    }
    await flush();
    expect(harness.events).toHaveLength(3);
    for (const event of harness.events) expect(event.code).toBe('E_SDK_INBOUND_INVALID');
  });

  test('the discard event carries exactly kind and code and is frozen', async () => {
    const harness = makeHarness();
    harness.module.ingest(frame(['EVENT', 'sub', { id: 'x' }]));
    await flush();
    const [event] = harness.events;
    expect(Object.keys(event).sort()).toEqual(['code', 'kind']);
    expect(Object.isFrozen(event)).toBe(true);
    expect(() => {
      event.code = 'other';
    }).toThrow();
  });
});

/* ------------------------------------------------------------------------- *
 * C-DLV section 7.1: the per-client queue, the pending bound and arrival order.
 * ------------------------------------------------------------------------- */

describe('section 7.1 -- the queue, the pending bound and arrival order', () => {
  test('frames are processed one at a time, in arrival order across relays', async () => {
    const senders = [makeKey(), makeKey(), makeKey()];
    const order = [];
    const harness = makeHarness({
      perRelayTimeoutMs: 400,
      session: {
        open: async ({ sender }) => {
          order.push(`start:${sender}`);
          // The first frame is the slowest: a concurrent pipeline would emit
          // the later frames first. The delay stays inside the port-call
          // timeout of floor(400 / 2) ms.
          const delay = sender === senders[0].pub ? 60 : 1;
          await new Promise((resolve) => setTimeout(resolve, delay));
          order.push(`end:${sender}`);
          return { plaintext: new Uint8Array([1]) };
        },
      },
    });
    for (const sender of senders) {
      harness.module.ingest(eventFrame(messageEvent({ sender, owner: harness.owner.pub }), 0));
    }
    await waitFor(() => order.length === 6, 10000);
    expect(order).toHaveLength(6);
    // Every frame ends before the next one starts: one at a time.
    for (let index = 0; index < 3; index += 1) {
      expect(order[index * 2]).toBe(`start:${senders[index].pub}`);
      expect(order[index * 2 + 1]).toBe(`end:${senders[index].pub}`);
    }
    // The messages are the arrival order, not the sending order.
    expect(harness.events.map((event) => event.sender)).toEqual(senders.map((key) => key.pub));
  }, 30000);

  test('the pending bound of 1024 drops a frame before any validation', async () => {
    const harness = makeHarness();
    const senders = makeKey();
    const results = [];
    for (let index = 0; index < 1025; index += 1) {
      results.push(harness.module.ingest(frame(['EVENT', 'sub', { id: `${index}`, pubkey: senders.pub }])));
    }
    const accepted = results.filter((result) => result.value.queued).length;
    expect(accepted).toBe(1024);
    expect(results[1023]).toEqual({ ok: true, value: { queued: true } });
    expect(results[1024]).toEqual({ ok: true, value: { queued: false } });
    expect(await waitFor(() => harness.events.length === 1024, 60000)).toBe(true);
    // Every queued frame was parsed once, and none was lost: 1024 discards.
    for (const event of harness.events) expect(event.code).toBe('E_SDK_INBOUND_INVALID');
  }, 120000);

  test('a frame dropped by the bound was never validated and never opened', async () => {
    const harness = makeHarness();
    const good = messageEvent({ sender: harness.other, owner: harness.owner.pub });
    for (let index = 0; index < 1024; index += 1) {
      harness.module.ingest(frame(['EVENT', 'sub', { id: `${index}` }]));
    }
    expect(harness.module.ingest(eventFrame(good)).value.queued).toBe(false);
    expect(await waitFor(() => harness.events.length === 1024, 60000)).toBe(true);
    expect(harness.opens).toHaveLength(0);
    expect(harness.published).toHaveLength(0);
  }, 120000);

  test('a frame of another frame kind is not queued and emits nothing', async () => {
    const harness = makeHarness();
    for (const data of [
      ['EOSE', 'sub'],
      ['CLOSED', 'sub', 'bye'],
      ['NOTICE', 'sub', 'hi'],
      ['OK', 'event-id', true],
    ]) {
      expect(harness.module.ingest(frame(data)).value.queued).toBe(false);
    }
    await flush();
    expect(harness.events).toEqual([]);
  });
});

/* ------------------------------------------------------------------------- *
 * C-DLV section 8: the duplicate window.
 * ------------------------------------------------------------------------- */

describe('section 8 -- the duplicate window', () => {
  test('a copy of an id already in the window is dropped without an event', async () => {
    const harness = makeHarness();
    const good = messageEvent({ sender: harness.other, owner: harness.owner.pub });
    harness.module.ingest(eventFrame(good, 0));
    harness.module.ingest(eventFrame(good, 1));
    harness.module.ingest(frame(['EVENT', 'other-sub', good], 1));
    await flush(8);
    expect(harness.events).toHaveLength(1);
    expect(harness.published).toHaveLength(1);
    expect(harness.opens).toHaveLength(1);
  });

  test('an id enters the window when the event passes 7.1, before session.open, so a re-delivered copy of an event whose open failed is dropped', async () => {
    const harness = makeHarness({
      session: {
        open: () => {
          throw new Error('session port throws');
        },
      },
    });
    const good = messageEvent({ sender: harness.other, owner: harness.owner.pub });
    harness.module.ingest(eventFrame(good, 0));
    harness.module.ingest(eventFrame(good, 1));
    await flush(8);
    expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' }]);
  });

  test('an invalid event does not enter the window', async () => {
    const harness = makeHarness();
    const good = messageEvent({ sender: harness.other, owner: harness.owner.pub });
    harness.module.ingest(frame(['EVENT', 'sub', { ...good, content: 'AA==' }]));
    harness.module.ingest(eventFrame(good, 1));
    await flush(8);
    expect(harness.events).toHaveLength(2);
    expect(harness.events[0].code).toBe('E_SDK_INBOUND_INVALID');
    expect(harness.events[1].kind).toBe('MESSAGE_RECEIVED');
    expect(harness.published).toHaveLength(1);
  });

  test('the window holds the last 4096 ids, first in first out', async () => {
    const harness = makeHarness();
    const first = messageEvent({ sender: harness.other, owner: harness.owner.pub, n: '0'.repeat(32) });
    const events = [first];
    for (let index = 1; index <= 4096; index += 1) {
      events.push(messageEvent({
        sender: harness.other,
        owner: harness.owner.pub,
        n: index.toString(16).padStart(32, '0'),
        payload: [index & 0xff],
      }));
    }
    expect(new Set(events.map((event) => event.id)).size).toBe(4097);
    // The pending bound of 1 024 admits at most 1 024 frames at a time, so the
    // events are ingested in waves and the queue is allowed to drain between
    // them.
    let expected = 0;
    for (const event of events) {
      harness.module.ingest(eventFrame(event, 0));
      expected += 1;
      if (expected % 256 === 0) {
        expect(await waitFor(() => harness.events.length === expected, 120000)).toBe(true);
      }
    }
    expect(await waitFor(() => harness.events.length === 4097, 120000)).toBe(true);
    expect(harness.published).toHaveLength(4097);
    // The first id has just left the window, so its copy is processed again.
    harness.module.ingest(eventFrame(first, 1));
    expect(await waitFor(() => harness.events.length === 4098, 30000)).toBe(true);
    expect(harness.published).toHaveLength(4098);
    expect(harness.events[4097].sender).toBe(harness.other.pub);
    // An id still inside the window is dropped.
    const last = events[4096];
    harness.module.ingest(eventFrame(last, 1));
    await flush(8);
    expect(harness.events).toHaveLength(4098);
  }, 180000);

  test('both message ids and receipt ids enter the same window of one client', async () => {
    const harness = makeHarness();
    const message = messageEvent({ sender: harness.other, owner: harness.owner.pub, askReceipt: false });
    const receipt = receiptEvent({ recipient: harness.other, owner: harness.owner.pub, eventId: message.id });
    harness.module.ingest(eventFrame(message, 0));
    harness.module.ingest(frame(['EVENT', 'sub', receipt], 1));
    harness.module.ingest(frame(['EVENT', 'sub', receipt], 0));
    await flush(8);
    expect(harness.opens).toHaveLength(1);
    expect(harness.acks).toHaveLength(1);
  });
});

/* ------------------------------------------------------------------------- *
 * C-DLV section 7.2: the message path.
 * ------------------------------------------------------------------------- */

describe('section 7.2 -- a valid kind-4741 event', () => {
  test('a message without the r tag emits MESSAGE_RECEIVED and asks for no receipt', async () => {
    const harness = makeHarness();
    const event = messageEvent({ sender: harness.other, owner: harness.owner.pub, askReceipt: false, payload: [4, 5, 6] });
    harness.module.ingest(eventFrame(event));
    await flush();
    expect(harness.events).toHaveLength(1);
    expect(harness.events[0].kind).toBe('MESSAGE_RECEIVED');
    expect(harness.events[0].sender).toBe(harness.other.pub);
    expect(Array.from(harness.events[0].payload)).toEqual([7, 8, 9]);
    expect(harness.published).toHaveLength(0);
    expect(harness.opens).toHaveLength(1);
  });

  test('the ciphertext handed to session.open is the decoded content, and the sender is the pubkey', async () => {
    const harness = makeHarness();
    const event = messageEvent({ sender: harness.other, owner: harness.owner.pub, payload: [1, 2, 3] });
    harness.module.ingest(eventFrame(event));
    await flush();
    expect(harness.opens).toHaveLength(1);
    expect(harness.opens[0].sender).toBe(harness.other.pub);
    expect(harness.opens[0].ciphertext).toBeInstanceOf(Uint8Array);
    expect(Array.from(harness.opens[0].ciphertext)).toEqual([1, 2, 3]);
  });

  test('the MESSAGE_RECEIVED event carries exactly kind, sender and payload and is frozen', async () => {
    const harness = makeHarness();
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    const [event] = harness.events;
    expect(Object.keys(event).sort()).toEqual(['kind', 'payload', 'sender']);
    expect(Object.isFrozen(event)).toBe(true);
    expect(() => {
      event.sender = 'x';
    }).toThrow();
  });

  test('the payload is a fresh copy of the plaintext, not the port\'s own array', async () => {
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    const harness = makeHarness({ session: { open: () => ({ plaintext }) } });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    const [event] = harness.events;
    expect(event.payload).not.toBe(plaintext);
    expect(Array.from(event.payload)).toEqual([1, 2, 3, 4]);
    plaintext[0] = 99;
    expect(event.payload[0]).toBe(1);
  });

  test('an empty plaintext is still a message', async () => {
    const harness = makeHarness({ session: { open: () => ({ plaintext: new Uint8Array(0) }) } });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    expect(harness.events).toHaveLength(1);
    expect(harness.events[0].payload.length).toBe(0);
  });

  test('the message is emitted even when the identity port cannot sign a receipt', async () => {
    const harness = makeHarness({ identity: { getPublicKey: () => undefined, sign: undefined } });
    const owner = makeKey();
    const local = makeHarness({ identity: { getPublicKey: () => owner.pub, sign: undefined } });
    local.module.ingest(eventFrame(messageEvent({ sender: local.other, owner: owner.pub })));
    await flush();
    expect(local.events).toHaveLength(1);
    expect(local.events[0].kind).toBe('MESSAGE_RECEIVED');
    expect(local.published).toHaveLength(0);
    expect(harness.module).toBeDefined();
  });
});

describe('section 7.2 -- decoding and session faults', () => {
  test('a content that does not decode to at least one byte is E_SDK_INBOUND_INVALID', async () => {
    const harness = makeHarness();
    const sender = harness.other;
    for (const content of ['', '!!not base64!!', 'AAAA=====']) {
      harness.module.ingest(eventFrame(buildEvent({
        priv: sender.priv,
        pub: sender.pub,
        tags: [['p', harness.owner.pub], ['v', VERSION], ['n', FRAME_N], ['r', '1']],
        content,
      })));
    }
    await flush(8);
    expect(harness.opens).toHaveLength(0);
    expect(harness.published).toHaveLength(0);
    for (const event of harness.events) expect(event).toEqual({ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INBOUND_INVALID' });
  });

  test('an absent session port, a non-function and a throwing method are E_SDK_SESSION_FAILED', async () => {
    const cases = [
      {},
      { open: null },
      { open: 5 },
      { open: () => { throw new Error('boom'); } },
    ];
    for (const session of cases) {
      const harness = makeHarness({ session });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush(8);
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' }]);
      expect(harness.published).toHaveLength(0);
    }
  });

  test('a return that is not { plaintext: Uint8Array } is E_SDK_SESSION_FAILED', async () => {
    const returns = [null, undefined, 0, 'plaintext', [], new Uint8Array([1]), {}, { plaintext: [1, 2] }, { plaintext: 'x' }];
    for (const value of returns) {
      const harness = makeHarness({ session: { open: () => value } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush(8);
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' }]);
      expect(harness.published).toHaveLength(0);
    }
  });

  test('a session port that rejects is E_SDK_SESSION_FAILED', async () => {
    const harness = makeHarness({ session: { open: () => Promise.reject(new Error('nope')) } });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(8);
    expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' }]);
  });

  test('a session port that does not settle within the port-call timeout is E_SDK_SESSION_FAILED', async () => {
    const harness = makeHarness({ session: { open: () => new Promise(() => {}) } });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(2);
    expect(harness.events).toEqual([]);
    await new Promise((resolve) => setTimeout(resolve, PORT_CALL_TIMEOUT_MS + 60));
    expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' }]);
  });

  test('a session port whose getter throws is E_SDK_SESSION_FAILED', async () => {
    const session = {};
    Object.defineProperty(session, 'open', {
      get() {
        throw new Error('getter');
      },
    });
    const harness = makeHarness({ session });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' }]);
  });
});

/* ------------------------------------------------------------------------- *
 * C-DLV section 6.3 and section 7.2: the receipt.
 * ------------------------------------------------------------------------- */

describe('section 6.3 -- the receipt structure and its publication', () => {
  test('the receipt carries exactly the seven keys of section 6.1, the four tags of 6.3 and the empty content', async () => {
    const harness = makeHarness();
    const message = messageEvent({ sender: harness.other, owner: harness.owner.pub, payload: [1, 2, 3] });
    harness.module.ingest(eventFrame(message));
    await flush();
    expect(harness.published).toHaveLength(1);
    const receipt = harness.published[0];
    expect(Object.keys(receipt).sort()).toEqual(
      ['content', 'created_at', 'id', 'kind', 'pubkey', 'sig', 'tags'],
    );
    expect(receipt.kind).toBe(4742);
    expect(receipt.pubkey).toBe(harness.owner.pub);
    expect(receipt.content).toBe('');
    expect(receipt.tags.map((tag) => tag[0])).toEqual(['p', 'e', 'v', 'n']);
    expect(receipt.tags[0][1]).toBe(harness.other.pub);
    expect(receipt.tags[1][1]).toBe(message.id);
    expect(receipt.tags[2][1]).toBe(VERSION);
    expect(receipt.tags[3][1]).toMatch(/^[0-9a-f]{32}$/);
    expect(receipt.created_at).toBe(Math.floor(OWN_CLOCK_MS / 1000));
    expect(Object.isFrozen(receipt)).toBe(true);
  });

  test('the receipt id is the recomputed id of section 6.1 and its signature verifies with the client key', async () => {
    const harness = makeHarness();
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    const receipt = harness.published[0];
    const recomputed = eventIdOf(receipt.pubkey, receipt.created_at, receipt.kind, receipt.tags, receipt.content);
    expect(receipt.id).toBe(recomputed);
    expect(schnorr.verify(hexToBytes(receipt.sig), hexToBytes(receipt.id), hexToBytes(receipt.pubkey))).toBe(true);
    expect(receipt.sig).toMatch(/^[0-9a-f]{128}$/);
  });

  test('the digest handed to identity.sign is the 32 bytes of the receipt id', async () => {
    const digests = [];
    const harness = makeHarness({
      identity: {
        getPublicKey: () => harness.owner.pub,
        sign: ({ digest }) => {
          digests.push(digest);
          return schnorr.sign(digest, harness.owner.priv);
        },
      },
    });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    expect(digests).toHaveLength(1);
    expect(digests[0]).toBeInstanceOf(Uint8Array);
    expect(digests[0].length).toBe(32);
    expect(bytesToHex(digests[0])).toBe(harness.published[0].id);
  });

  test('created_at is floor(clock.now() / 1000) at signing', async () => {
    for (const [now, expected] of [[0, 0], [999, 0], [1000, 1], [12999, 12], [13000, 13]]) {
      const harness = makeHarness({ clock: { now: () => now } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.published[0].created_at).toBe(expected);
    }
  });

  test('two receipts for two message ids differ in their e tag and in their drawn n tag', async () => {
    const harness = makeHarness();
    const first = messageEvent({ sender: harness.other, owner: harness.owner.pub, n: '1'.repeat(32), payload: [1] });
    const second = messageEvent({ sender: harness.other, owner: harness.owner.pub, n: '2'.repeat(32), payload: [2] });
    harness.module.ingest(eventFrame(first));
    harness.module.ingest(eventFrame(second));
    await flush(8);
    expect(harness.published).toHaveLength(2);
    expect(harness.published[0].id).not.toBe(harness.published[1].id);
    expect(harness.published[0].tags[1][1]).toBe(first.id);
    expect(harness.published[1].tags[1][1]).toBe(second.id);
    expect(harness.published[0].tags[3][1]).toMatch(/^[0-9a-f]{32}$/);
    expect(harness.published[1].tags[3][1]).toMatch(/^[0-9a-f]{32}$/);
  });

  test('a receipt is sent at most once per message event id', async () => {
    const harness = makeHarness();
    const message = messageEvent({ sender: harness.other, owner: harness.owner.pub });
    harness.module.ingest(eventFrame(message, 0));
    harness.module.ingest(eventFrame(message, 1));
    harness.module.ingest(eventFrame(message, 0));
    await flush(8);
    expect(harness.published).toHaveLength(1);
    expect(harness.opens).toHaveLength(1);
  });

  test('a throwing publishReceipt seam changes nothing already emitted', async () => {
    const harness = makeHarness({
      publishReceipt: () => {
        throw new Error('publication seam throws');
      },
    });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    expect(harness.events).toHaveLength(1);
    expect(harness.events[0].kind).toBe('MESSAGE_RECEIVED');
  });

  test('an absent publishReceipt seam is tolerable', async () => {
    const harness = makeHarness({ publishReceipt: undefined });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    expect(harness.events).toHaveLength(1);
  });
});

describe('section 6.3 and section 7.2 -- a receipt that cannot be built means no receipt', () => {
  const expectNoReceipt = async (harness) => {
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(8);
    expect(harness.events).toHaveLength(1);
    expect(harness.events[0].kind).toBe('MESSAGE_RECEIVED');
    expect(harness.published).toHaveLength(0);
  };

  test('an absent, non-function, throwing or non-settling clock gives no receipt', async () => {
    await expectNoReceipt(makeHarness({ clock: undefined }));
    await expectNoReceipt(makeHarness({ clock: {} }));
    await expectNoReceipt(makeHarness({ clock: { now: 5 } }));
    await expectNoReceipt(makeHarness({ clock: { now: () => { throw new Error('clock'); } } }));
    await expectNoReceipt(makeHarness({ clock: { now: () => new Promise(() => {}) } }));
    await expectNoReceipt(makeHarness({ clock: { now: () => new Promise((resolve) => resolve(1000)) } }));
  });

  test('a clock reading whose second is negative or not a safe integer gives no receipt', async () => {
    await expectNoReceipt(makeHarness({ clock: { now: () => -1 } }));
    await expectNoReceipt(makeHarness({ clock: { now: () => -999 } }));
    await expectNoReceipt(makeHarness({ clock: { now: () => Infinity } }));
    await expectNoReceipt(makeHarness({ clock: { now: () => NaN } }));
    await expectNoReceipt(makeHarness({ clock: { now: () => 9.1e18 } }));
    await expectNoReceipt(makeHarness({ clock: { now: () => '1000' } }));
    await expectNoReceipt(makeHarness({ clock: { now: () => null } }));
  });

  test('an absent, non-function, throwing, short or non-settling identity.sign gives no receipt', async () => {
    const cases = [
      undefined,
      {},
      { sign: 5 },
      { sign: () => { throw new Error('sign'); } },
      { sign: () => new Uint8Array(63) },
      { sign: () => new Uint8Array(0) },
      { sign: () => 'a'.repeat(128) },
      { sign: () => new Promise(() => {}) },
    ];
    for (const identity of cases) {
      const harness = makeHarness({
        identity: identity === undefined
          ? undefined
          : { getPublicKey: () => harness.owner.pub, ...identity },
      });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush(8);
      expect(harness.published).toHaveLength(0);
    }
  });

  test('an identity port whose sign never settles stops the receipt at the port-call timeout', async () => {
    const harness = makeHarness({
      identity: { getPublicKey: () => harness.owner.pub, sign: () => new Promise(() => {}) },
    });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await new Promise((resolve) => setTimeout(resolve, PORT_CALL_TIMEOUT_MS + 60));
    expect(harness.events).toHaveLength(1);
    expect(harness.published).toHaveLength(0);
  });
});

describe('the identity key reading', () => {
  test('getPublicKey is read at most once for the module lifetime and shared', async () => {
    let reads = 0;
    const harness = makeHarness({
      identity: {
        getPublicKey: () => {
          reads += 1;
          return harness.owner.pub;
        },
        sign: ({ digest }) => schnorr.sign(digest, harness.owner.priv),
      },
    });
    for (let index = 0; index < 20; index += 1) {
      harness.module.ingest(eventFrame(messageEvent({
        sender: harness.other, owner: harness.owner.pub, n: index.toString(16).padStart(32, '0'), payload: [index],
      })));
    }
    await waitFor(() => harness.events.length === 20, 30000);
    expect(reads).toBe(1);
    expect(harness.events).toHaveLength(20);
  });

  test('a faulting or malformed key reading makes every frame fail step 3 with E_SDK_INBOUND_INVALID', async () => {
    for (const getPublicKey of [
      undefined,
      () => { throw new Error('key'); },
      () => Promise.resolve(''),
      () => 12,
      () => 'z'.repeat(64),
      () => new Promise(() => {}),
    ]) {
      const harness = makeHarness({ identity: { getPublicKey, sign: () => new Uint8Array(64) } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await new Promise((resolve) => setTimeout(resolve, PORT_CALL_TIMEOUT_MS + 40));
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INBOUND_INVALID' }]);
    }
  });
});

/* ------------------------------------------------------------------------- *
 * C-DLV section 7.3: the acknowledgement, through the item-side seam.
 * ------------------------------------------------------------------------- */

describe('section 7.3 -- the acknowledgement seam', () => {
  test('a valid kind-4742 event is handed to the seam once, with the e tag and the signer', async () => {
    const harness = makeHarness();
    const eventId = 'e'.repeat(64);
    harness.module.ingest(frame(['EVENT', 'sub', receiptEvent({
      recipient: harness.other, owner: harness.owner.pub, eventId,
    })]));
    await flush();
    expect(harness.acks).toEqual([{ eventId, recipient: harness.other.pub }]);
    expect(harness.events).toEqual([]);
  });

  test('a duplicate acknowledgement is dropped before the seam', async () => {
    const harness = makeHarness();
    const receipt = receiptEvent({ recipient: harness.other, owner: harness.owner.pub, eventId: 'f'.repeat(64) });
    harness.module.ingest(frame(['EVENT', 'sub', receipt], 0));
    harness.module.ingest(frame(['EVENT', 'sub', receipt], 1));
    await flush(8);
    expect(harness.acks).toHaveLength(1);
  });

  test('a refusal whose code is inside the closed set of C-SDK section 5.2 is ignored without an event', async () => {
    for (const code of ['E_SDK_STORAGE_FAILED', 'E_SDK_INTERNAL', 'E_SDK_UNKNOWN_DELIVERY', 'E_SDK_DELIVERY_TERMINAL', 'E_SDK_UNKNOWN_CODE']) {
      const harness = makeHarness({ acceptReceipt: () => Object.freeze({ ok: false, code }) });
      harness.module.ingest(frame(['EVENT', 'sub', receiptEvent({
        recipient: harness.other, owner: harness.owner.pub, eventId: 'a'.repeat(64),
      })]));
      await flush();
      expect(harness.events).toEqual([]);
    }
  });

  test('a code outside the closed set and a malformed envelope are E_SDK_UNKNOWN_CODE', async () => {
    const returns = [
      { ok: false, code: 'E_NOT_A_CLOSED_CODE' },
      { ok: false, code: 42 },
      { ok: false },
      { ok: 'yes' },
      {},
      null,
      undefined,
      0,
      'envelope',
      [],
      { code: 'E_SDK_INBOUND_INVALID' },
    ];
    for (const value of returns) {
      const harness = makeHarness({ acceptReceipt: () => value });
      harness.module.ingest(frame(['EVENT', 'sub', receiptEvent({
        recipient: harness.other, owner: harness.owner.pub, eventId: 'b'.repeat(64),
      })]));
      await flush();
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }]);
    }
  });

  test('an absent, non-function, throwing or non-settling seam is E_SDK_UNKNOWN_CODE', async () => {
    const seams = [
      undefined,
      null,
      5,
      'seam',
      () => { throw new Error('seam'); },
      () => Promise.reject(new Error('seam')),
      () => new Promise(() => {}),
    ];
    for (const acceptReceipt of seams) {
      const harness = makeHarness({ acceptReceipt });
      harness.module.ingest(frame(['EVENT', 'sub', receiptEvent({
        recipient: harness.other, owner: harness.owner.pub, eventId: 'c'.repeat(64),
      })]));
      await new Promise((resolve) => setTimeout(resolve, PORT_CALL_TIMEOUT_MS + 60));
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }]);
    }
  });

  test('an accepting seam leaves the module silent', async () => {
    for (const value of [
      Object.freeze({ ok: true, value: Object.freeze({ accepted: true, deliveryId: 'd1' }) }),
      Object.freeze({ ok: true, value: Object.freeze({ accepted: false, deliveryId: null }) }),
    ]) {
      const harness = makeHarness({ acceptReceipt: () => value });
      harness.module.ingest(frame(['EVENT', 'sub', receiptEvent({
        recipient: harness.other, owner: harness.owner.pub, eventId: 'd'.repeat(64),
      })]));
      await flush();
      expect(harness.events).toEqual([]);
    }
  });

  test('a receipt for an item no seam recognises is ignored without an event', async () => {
    const harness = makeHarness({
      acceptReceipt: () => Object.freeze({ ok: true, value: Object.freeze({ accepted: false, deliveryId: null }) }),
    });
    harness.module.ingest(frame(['EVENT', 'sub', receiptEvent({
      recipient: harness.other, owner: harness.owner.pub, eventId: 'e'.repeat(64),
    })]));
    await flush();
    expect(harness.events).toEqual([]);
    expect(harness.published).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------------- *
 * C-DLV section 4.6 step (1): the inbound queue is dropped at the stop.
 * ------------------------------------------------------------------------- */

describe('the stop', () => {
  test('shutdown drops the queued frames and counts them', async () => {
    const harness = makeHarness();
    const sender = harness.other;
    for (let index = 0; index < 5; index += 1) {
      harness.module.ingest(eventFrame(messageEvent({
        sender, owner: harness.owner.pub, n: index.toString(16).padStart(32, '0'), payload: [index],
      })));
    }
    const result = harness.module.shutdown();
    expect(result).toEqual({ ok: true, value: { dropped: 5 } });
    await flush(8);
    expect(harness.opens).toHaveLength(0);
    expect(harness.events).toEqual([]);
    expect(harness.published).toHaveLength(0);
  });

  test('no frame ingested after the stop is queued or processed', async () => {
    const harness = makeHarness();
    harness.module.shutdown();
    const result = harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    expect(result).toEqual({ ok: true, value: { queued: false } });
    await flush(8);
    expect(harness.events).toEqual([]);
    expect(harness.opens).toHaveLength(0);
  });

  test('a stop during an open does not start a receipt afterwards', async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const harness = makeHarness({
      session: { open: () => gate.then(() => ({ plaintext: new Uint8Array([1]) })) },
    });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(2);
    harness.module.shutdown();
    release();
    await flush(8);
    /* C-DLV section 4.6 step (1): the stop is terminal, so the message event
     * of the frame that was waiting on the port call is not emitted either. */
    expect(harness.events).toHaveLength(0);
    expect(harness.published).toHaveLength(0);
  });

  test('the second stop is E_SDK_CLIENT_STOPPED and the first is idempotent in its answer', () => {
    const harness = makeHarness();
    expect(harness.module.shutdown().ok).toBe(true);
    expect(harness.module.shutdown()).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    expect(harness.module.shutdown()).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
  });
});

/* ------------------------------------------------------------------------- *
 * A generative property over a deterministic draw stream (owner decision R4,
 * H-1 and G1: the acceptance criterion of the contract applied literally).
 * ------------------------------------------------------------------------- */

/**
 * A small deterministic generator, so "fixed seed" means exactly that. Every
 * draw takes the HIGH bits of the linear congruential state: the low bits of
 * `state * 1664525 + 1013904223` modulo 2^32 have short periods (bit 0 simply
 * alternates), so two consecutive low-bit draws are correlated, which is what
 * made the receipt dimension unreachable at the round-3 head.
 */
function makeGenerator(seed) {
  let state = seed >>> 0;
  const high16 = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state >>> 16;
  };
  return {
    below(bound) {
      if (bound <= 0x10000) return high16() % bound;
      return (high16() * 0x10000 + high16()) % bound;
    },
    between(min, max) {
      return min + this.below(max - min + 1);
    },
    pick(list) {
      return list[this.below(list.length)];
    },
    shuffle(list) {
      for (let index = list.length - 1; index > 0; index -= 1) {
        const other = this.below(index + 1);
        [list[index], list[other]] = [list[other], list[index]];
      }
      return list;
    },
  };
}

/** A key derived from a label, so every generated timeline is reproducible. */
function deterministicKey(label) {
  const priv = sha256(utf8Encode(label));
  return { priv, pub: bytesToHex(schnorr.getPublicKey(priv)) };
}

/** C-SDK section 7's closed event-kind set and section 5.2's INBOUND_DISCARDED codes. */
const CLOSED_EVENT_KINDS = new Set([
  'CLIENT_STATE_CHANGED', 'DELIVERY_STATE_CHANGED', 'MESSAGE_RECEIVED', 'INBOUND_DISCARDED',
]);
const INBOUND_DISCARD_CODES = new Set(['E_SDK_INBOUND_INVALID', 'E_SDK_SESSION_FAILED', 'E_SDK_UNKNOWN_CODE']);
/** C-SDK section 4.1's two receipt modes; the sender's mode decides the `r` tag. */
const GENERATED_RECEIPT_MODES = ['RECIPIENT_RECEIPT', 'RELAY_ACCEPTANCE_ONLY'];
/** The single-field mutations; each one fails a step of C-DLV section 7.1. */
const GENERATED_MUTATIONS = {
  id: () => ({ id: 'f'.repeat(64) }),
  sig: () => ({ sig: 'f'.repeat(128) }),
  pubkey: (owner) => ({ pubkey: owner.pub }),
  createdAtNegative: () => ({ created_at: -1 }),
  createdAtFraction: () => ({ created_at: 1.5 }),
  kind: () => ({ kind: 4740 }),
  content: () => ({ content: null }),
  tags: () => ({ tags: null }),
};
const GENERATED_VALIDITY = ['valid', ...Object.keys(GENERATED_MUTATIONS)];

describe('generative invariants over a deterministic draw stream', () => {
  test('300 drawn timelines over timeout, relay count, receipt mode, kind, validity and duplicate pattern', async () => {
    const TIMELINES = 300;
    const generator = makeGenerator(0x1acc2026);
    const coverage = {
      relayCounts: new Set(),
      timeoutMin: Infinity,
      timeoutMax: -Infinity,
      receiptModes: new Map(),
      kindCases: new Map(),
      validKindCases: new Map(),
      validity: new Map(),
      copies: new Map(),
    };
    const bump = (map, key) => map.set(key, (map.get(key) ?? 0) + 1);
    const totals = { messages: 0, receipts: 0, acks: 0, discards: 0, droppedCopies: 0, accepted: 0 };

    for (let timeline = 0; timeline < TIMELINES; timeline += 1) {
      /* The six dimensions of the criterion, each drawn from the stream. */
      const relayCount = generator.between(1, 16);
      const perRelayTimeoutMs = generator.between(11000, 30000);
      const receiptMode = generator.pick(GENERATED_RECEIPT_MODES);
      const clockMs = generator.below(2 ** 31);
      coverage.relayCounts.add(relayCount);
      coverage.timeoutMin = Math.min(coverage.timeoutMin, perRelayTimeoutMs);
      coverage.timeoutMax = Math.max(coverage.timeoutMax, perRelayTimeoutMs);
      bump(coverage.receiptModes, receiptMode);
      expect(Number.isSafeInteger(perRelayTimeoutMs)).toBe(true);
      expect(perRelayTimeoutMs).toBeGreaterThanOrEqual(11000);
      expect(perRelayTimeoutMs).toBeLessThanOrEqual(30000);
      expect(relayCount).toBeGreaterThanOrEqual(1);
      expect(relayCount).toBeLessThanOrEqual(16);

      /* Every frame of the timeline is addressed to the key its own client
       * reads, so a well-formed frame passes step 3 and a mutation reaches the
       * step it targets. */
      const owner = deterministicKey(`i-ack-generative-owner-${timeline}`);
      const sender = deterministicKey(`i-ack-generative-sender-${timeline}`);
      const harness = makeHarness({
        owner,
        perRelayTimeoutMs,
        clock: { now: () => clockMs },
        session: { open: ({ ciphertext }) => ({ plaintext: Uint8Array.from(ciphertext) }) },
      });

      const plan = [];
      const eventCount = generator.between(1, 3);
      for (let index = 0; index < eventCount; index += 1) {
        const kind = generator.pick([4741, 4742]);
        const validity = generator.below(2) === 0 ? 'valid' : generator.pick(GENERATED_VALIDITY.slice(1));
        const copies = generator.between(1, 3);
        const n = (timeline * 4 + index).toString(16).padStart(32, '0');
        const askReceipt = kind === 4741 && receiptMode === 'RECIPIENT_RECEIPT';
        const payload = [generator.below(256), generator.below(256), index + 1];
        const base = kind === 4741
          ? messageEvent({ sender, owner: owner.pub, askReceipt, payload, n })
          : receiptEvent({
            recipient: sender,
            owner: owner.pub,
            eventId: bytesToHex(sha256(utf8Encode(`i-ack-generative-target-${timeline}-${index}`))),
            n,
          });
        const event = validity === 'valid' ? base : { ...base, ...GENERATED_MUTATIONS[validity](owner) };
        const kindCase = kind === 4742 ? '4742' : (askReceipt ? '4741-r' : '4741-no-r');
        bump(coverage.kindCases, kindCase);
        if (validity === 'valid') bump(coverage.validKindCases, kindCase);
        bump(coverage.validity, validity);
        bump(coverage.copies, copies);
        for (let copy = 0; copy < copies; copy += 1) {
          plan.push({ event, base, kind, validity, askReceipt, payload, relayIndex: generator.below(relayCount) });
        }
      }
      /* The duplicate pattern: copies, their relays and their interleaving. */
      generator.shuffle(plan);

      /* The model of C-DLV sections 7.1, 7.2, 7.3 and 8, in arrival order. */
      const seen = new Set();
      const expectedEvents = [];
      const expectedReceiptsFor = [];
      const expectedAcks = [];
      let droppedCopies = 0;
      for (const step of plan) {
        if (step.validity !== 'valid') {
          expectedEvents.push({ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INBOUND_INVALID' });
          continue;
        }
        if (seen.has(step.event.id)) {
          droppedCopies += 1;
          continue;
        }
        seen.add(step.event.id);
        if (step.kind === 4741) {
          expectedEvents.push({ kind: 'MESSAGE_RECEIVED', sender: sender.pub, payload: new Uint8Array(step.payload) });
          if (step.askReceipt) expectedReceiptsFor.push(step.event.id);
        } else {
          expectedAcks.push({ eventId: step.event.tags[1][1], recipient: sender.pub });
        }
      }

      for (const step of plan) {
        expect(harness.module.ingest(eventFrame(step.event, step.relayIndex))).toEqual({ ok: true, value: { queued: true } });
      }
      await waitFor(() => harness.events.length >= expectedEvents.length
        && harness.acks.length >= expectedAcks.length
        && harness.published.length >= expectedReceiptsFor.length);
      await flush(8);

      /* The closed sets. */
      for (const event of harness.events) {
        expect(CLOSED_EVENT_KINDS.has(event.kind)).toBe(true);
        if (event.kind === 'INBOUND_DISCARDED') expect(INBOUND_DISCARD_CODES.has(event.code)).toBe(true);
      }
      /* Exactly the modelled events, in arrival order: one MESSAGE_RECEIVED per
       * distinct valid kind-4 741 id that opens, one discard per invalid copy. */
      expect(harness.events).toEqual(expectedEvents);
      /* One receipt per such event that carries the `r` tag, and no other. */
      expect(harness.published.map((receipt) => receipt.tags[1][1])).toEqual(expectedReceiptsFor);
      for (const receipt of harness.published) {
        expect(receipt.pubkey).toBe(owner.pub);
        expect(receipt.created_at).toBe(Math.floor(clockMs / 1000));
        expect(receipt.tags[0]).toEqual(['p', sender.pub]);
        expect(receipt.id).toBe(eventIdOf(receipt.pubkey, receipt.created_at, receipt.kind, receipt.tags, receipt.content));
        expect(schnorr.verify(hexToBytes(receipt.sig), hexToBytes(receipt.id), hexToBytes(receipt.pubkey))).toBe(true);
      }
      /* One acknowledgement per distinct valid kind-4 742 id, before the seam. */
      expect(harness.acks).toEqual(expectedAcks);

      /* The terminal state: nothing is emitted, published or routed after the stop. */
      const stop = harness.module.shutdown();
      expect(stop).toEqual({ ok: true, value: { dropped: 0 } });
      const late = generator.pick(plan);
      expect(harness.module.ingest(eventFrame(late.base, late.relayIndex))).toEqual({ ok: true, value: { queued: false } });
      await flush(3);
      expect(harness.events).toHaveLength(expectedEvents.length);
      expect(harness.published).toHaveLength(expectedReceiptsFor.length);
      expect(harness.acks).toHaveLength(expectedAcks.length);

      const messages = expectedEvents.filter((event) => event.kind === 'MESSAGE_RECEIVED').length;
      totals.messages += messages;
      totals.receipts += expectedReceiptsFor.length;
      totals.acks += expectedAcks.length;
      totals.discards += expectedEvents.length - messages;
      totals.droppedCopies += droppedCopies;
      totals.accepted += messages + expectedAcks.length;
    }

    /* Per-dimension coverage: every drawn dimension took more than one value
     * and every kind / receipt case was seen, valid, at least once. */
    expect(coverage.relayCounts.size).toBe(16);
    expect(coverage.timeoutMin).toBeLessThan(13000);
    expect(coverage.timeoutMax).toBeGreaterThan(28000);
    for (const mode of GENERATED_RECEIPT_MODES) expect(coverage.receiptModes.get(mode) ?? 0).toBeGreaterThan(0);
    for (const kindCase of ['4741-r', '4741-no-r', '4742']) {
      expect(coverage.kindCases.get(kindCase) ?? 0).toBeGreaterThan(0);
      expect(coverage.validKindCases.get(kindCase) ?? 0).toBeGreaterThan(0);
    }
    for (const validity of GENERATED_VALIDITY) expect(coverage.validity.get(validity) ?? 0).toBeGreaterThan(0);
    for (const copies of [1, 2, 3]) expect(coverage.copies.get(copies) ?? 0).toBeGreaterThan(0);
    /* The property is not vacuous: messages were delivered, receipts were
     * published, acknowledgements were routed, mutations were discarded and
     * duplicate copies were dropped. */
    expect(totals.messages).toBeGreaterThan(0);
    expect(totals.receipts).toBeGreaterThan(0);
    expect(totals.acks).toBeGreaterThan(0);
    expect(totals.discards).toBeGreaterThan(0);
    expect(totals.droppedCopies).toBeGreaterThan(0);
    console.log(`generative: ${totals.accepted} generated well-formed frames accepted over ${TIMELINES} timelines; `
      + `${totals.messages} messages, ${totals.receipts} receipts, ${totals.acks} acknowledgements, `
      + `${totals.discards} discards, ${totals.droppedCopies} duplicate copies dropped; relay counts `
      + `${coverage.relayCounts.size}/16, timeouts ${coverage.timeoutMin}..${coverage.timeoutMax} ms; kind cases `
      + `${JSON.stringify(Object.fromEntries(coverage.validKindCases))} valid of `
      + `${JSON.stringify(Object.fromEntries(coverage.kindCases))}`);
  }, 600000);

  test('the window bound over a drawn stream: 4 096 ids are held and the 4 097th distinct insertion evicts the oldest', async () => {
    const generator = makeGenerator(0x4096);
    const owner = deterministicKey('i-ack-generative-window-owner');
    const sender = deterministicKey('i-ack-generative-window-sender');
    const relayCount = generator.between(1, 16);
    const harness = makeHarness({ owner, perRelayTimeoutMs: generator.between(11000, 30000) });
    const processed = () => harness.events.length + harness.acks.length;
    const stream = [];
    for (let index = 0; index < 4097; index += 1) {
      const n = index.toString(16).padStart(32, '0');
      stream.push(generator.below(2) === 0
        ? messageEvent({ sender, owner: owner.pub, askReceipt: generator.below(2) === 0, n, payload: [index & 0xff] })
        : receiptEvent({ recipient: sender, owner: owner.pub, eventId: 'c'.repeat(64), n }));
    }
    expect(new Set(stream.map((event) => event.id)).size).toBe(4097);
    const ingestWave = async (events, expected) => {
      for (const event of events) harness.module.ingest(eventFrame(event, generator.below(relayCount)));
      expect(await waitFor(() => processed() === expected, 120000)).toBe(true);
    };
    const [first, ...rest] = stream;
    let expected = 1;
    await ingestWave([first], expected);
    for (let start = 0; start < 4095; start += 256) {
      const wave = rest.slice(start, Math.min(start + 256, 4095));
      expected += wave.length;
      await ingestWave(wave, expected);
    }
    /* 4 096 distinct ids are in the window: a copy of the oldest is dropped. */
    harness.module.ingest(eventFrame(first, generator.below(relayCount)));
    await flush(8);
    expect(processed()).toBe(4096);
    /* The 4 097th distinct insertion evicts it, and only it: the id inserted
     * right after it is still held, and the oldest one's copy is processed
     * again. */
    await ingestWave([rest[4095]], 4097);
    harness.module.ingest(eventFrame(rest[0], generator.below(relayCount)));
    await flush(8);
    expect(processed()).toBe(4097);
    harness.module.ingest(eventFrame(first, generator.below(relayCount)));
    expect(await waitFor(() => processed() === 4098, 30000)).toBe(true);
    await flush(8);
    expect(processed()).toBe(4098);
  }, 600000);
});

/* ------------------------------------------------------------------------- *
 * O-SCEN3 replays (owner decision R4, S1). Each test below replays exactly the
 * inbound frames that the record's own client receives, from the relay the
 * record names, at the instant the record fixes (the clock port reads that
 * instant when the frame is processed). The session double returns the
 * ciphertext bytes as the plaintext, so distinct payloads stay distinct, and the
 * sender client ingests the very receipts the recipient client published.
 * ------------------------------------------------------------------------- */

/** One client of a replay: a harness whose clock reads the replay's instant. */
function replayClient(label, overrides = {}) {
  const at = { now: 0 };
  const opened = [];
  const harness = makeHarness({
    owner: deterministicKey(label),
    clock: { now: () => at.now },
    session: {
      open: ({ sender, ciphertext }) => {
        opened.push({ sender, ciphertext });
        return { plaintext: Uint8Array.from(ciphertext) };
      },
    },
    perRelayTimeoutMs: 12000,
    ...overrides,
  });
  harness.opens = opened;
  /** Deliver one frame at its record instant and let it be processed there. */
  const deliver = async (instant, event, relayIndex) => {
    at.now = instant;
    const answer = harness.module.ingest(eventFrame(event, relayIndex));
    await flush(8);
    return answer;
  };
  return { harness, deliver };
}

describe('O-SCEN3 duplicateAndReordered / inboundDuplicateReordered -- exact replay', () => {
  test('the recipient and the sender receive the frames of the record at its instants', async () => {
    const recipient = replayClient('i-ack-replay-dup-recipient');
    const sender = replayClient('i-ack-replay-dup-sender');
    const senderKey = sender.harness.owner;
    const recipientKey = recipient.harness.owner;
    /* 12 000: the sender sends P1 then P2 in RECIPIENT_RECEIPT mode; the two n
     * tags differ, so the event ids differ. */
    const e1 = messageEvent({ sender: senderKey, owner: recipientKey.pub, askReceipt: true, payload: [0x50, 0x31], n: '1'.repeat(32), createdAt: 12 });
    const e2 = messageEvent({ sender: senderKey, owner: recipientKey.pub, askReceipt: true, payload: [0x50, 0x32], n: '2'.repeat(32), createdAt: 12 });
    expect(e1.id).not.toBe(e2.id);

    /* The recipient: relay1 replays in reverse insertion order, each twice. */
    await recipient.deliver(21105, e2, 1);
    expect(recipient.harness.events).toEqual([
      { kind: 'MESSAGE_RECEIVED', sender: senderKey.pub, payload: new Uint8Array([0x50, 0x32]) },
    ]);
    expect(recipient.harness.published.map((receipt) => receipt.tags[1][1])).toEqual([e2.id]);
    await recipient.deliver(21115, e2, 1);
    await recipient.deliver(21125, e1, 1);
    expect(recipient.harness.events).toHaveLength(2);
    expect(recipient.harness.events[1]).toEqual(
      { kind: 'MESSAGE_RECEIVED', sender: senderKey.pub, payload: new Uint8Array([0x50, 0x31]) },
    );
    await recipient.deliver(21135, e1, 1);
    /* 21 205: relay0's insertion-order replay, e1 then e2, both dropped. */
    await recipient.deliver(21205, e1, 0);
    await recipient.deliver(21205, e2, 0);
    expect(recipient.harness.events).toHaveLength(2);
    expect(recipient.harness.opens).toHaveLength(2);
    /* Exactly two receipts, one per event id, in processing order e2 then e1. */
    const [r2, r1] = recipient.harness.published;
    expect(recipient.harness.published).toHaveLength(2);
    expect(r2.tags[1][1]).toBe(e2.id);
    expect(r1.tags[1][1]).toBe(e1.id);
    expect(r2.id).not.toBe(r1.id);
    expect(r2.created_at).toBe(21);
    expect(r1.created_at).toBe(21);
    for (const receipt of [r2, r1]) {
      expect(receipt.pubkey).toBe(recipientKey.pub);
      expect(receipt.tags[0]).toEqual(['p', senderKey.pub]);
      expect(schnorr.verify(hexToBytes(receipt.sig), hexToBytes(receipt.id), hexToBytes(receipt.pubkey))).toBe(true);
    }

    /* The sender ingests the receipts the recipient published, as the record
     * delivers them: relay1 twice each, then relay0's copies of both. */
    await sender.deliver(21200, r2, 1);
    expect(sender.harness.acks).toEqual([{ eventId: e2.id, recipient: recipientKey.pub }]);
    await sender.deliver(21210, r2, 1);
    await sender.deliver(21220, r1, 1);
    await sender.deliver(21230, r1, 1);
    await sender.deliver(21305, r2, 0);
    await sender.deliver(21305, r1, 0);
    expect(sender.harness.acks).toEqual([
      { eventId: e2.id, recipient: recipientKey.pub },
      { eventId: e1.id, recipient: recipientKey.pub },
    ]);
    expect(sender.harness.events).toEqual([]);
    expect(sender.harness.opens).toHaveLength(0);
    expect(sender.harness.published).toHaveLength(0);
  });
});

describe('O-SCEN3 offlineRecipient -- exact replays', () => {
  /** The real item-side seam's refusal shape (card I-QUEUE `acceptReceipt`). */
  const refusing = (routed) => ({ eventId, recipient }) => {
    routed.push({ eventId, recipient });
    return Object.freeze({ ok: true, value: Object.freeze({ accepted: false, deliveryId: 'd1' }) });
  };

  test('receiptBeforeDeadline: 61 105 / 61 250 at the recipient, 61 200 / 61 260 at the sender', async () => {
    const recipient = replayClient('i-ack-replay-before-recipient');
    const sender = replayClient('i-ack-replay-before-sender');
    const message = messageEvent({
      sender: sender.harness.owner, owner: recipient.harness.owner.pub, askReceipt: true, payload: [0x50], createdAt: 12,
    });
    await recipient.deliver(61105, message, 0);
    expect(recipient.harness.events).toEqual([
      { kind: 'MESSAGE_RECEIVED', sender: sender.harness.owner.pub, payload: new Uint8Array([0x50]) },
    ]);
    expect(recipient.harness.published).toHaveLength(1);
    const receipt = recipient.harness.published[0];
    expect(receipt.created_at).toBe(61);
    expect(receipt.tags[1][1]).toBe(message.id);

    await sender.deliver(61200, receipt, 0);
    expect(sender.harness.acks).toEqual([{ eventId: message.id, recipient: recipient.harness.owner.pub }]);
    await recipient.deliver(61250, message, 1);
    expect(recipient.harness.events).toHaveLength(1);
    expect(recipient.harness.published).toHaveLength(1);
    await sender.deliver(61260, receipt, 1);
    expect(sender.harness.acks).toHaveLength(1);
    expect(sender.harness.events).toEqual([]);
  });

  test('receiptAfterDeadline: 134 105 / 134 250 at the recipient, 135 000 at the sender, refused without an event', async () => {
    const routed = [];
    const recipient = replayClient('i-ack-replay-after-recipient');
    const sender = replayClient('i-ack-replay-after-sender', { acceptReceipt: refusing(routed) });
    const message = messageEvent({
      sender: sender.harness.owner, owner: recipient.harness.owner.pub, askReceipt: true, payload: [0x50], createdAt: 12,
    });
    await recipient.deliver(134105, message, 0);
    await recipient.deliver(134250, message, 1);
    expect(recipient.harness.events).toHaveLength(1);
    expect(recipient.harness.published).toHaveLength(1);
    const receipt = recipient.harness.published[0];
    expect(receipt.created_at).toBe(134);

    await sender.deliver(135000, receipt, 0);
    expect(routed).toEqual([{ eventId: message.id, recipient: recipient.harness.owner.pub }]);
    expect(sender.harness.events).toEqual([]);
    expect(sender.harness.published).toHaveLength(0);
  });

  test('receiptExactlyAtDeadline: 122 105 / 122 250 at the recipient, both receipt copies at 132 000 at the sender', async () => {
    const routed = [];
    const recipient = replayClient('i-ack-replay-boundary-recipient');
    const sender = replayClient('i-ack-replay-boundary-sender', { acceptReceipt: refusing(routed) });
    const message = messageEvent({
      sender: sender.harness.owner, owner: recipient.harness.owner.pub, askReceipt: true, payload: [0x50], createdAt: 12,
    });
    await recipient.deliver(122105, message, 0);
    await recipient.deliver(122250, message, 1);
    expect(recipient.harness.events).toHaveLength(1);
    expect(recipient.harness.published).toHaveLength(1);
    const receipt = recipient.harness.published[0];
    expect(receipt.created_at).toBe(122);

    await sender.deliver(132000, receipt, 0);
    await sender.deliver(132000, receipt, 1);
    expect(routed).toEqual([{ eventId: message.id, recipient: recipient.harness.owner.pub }]);
    expect(sender.harness.events).toEqual([]);
  });
});

/* ------------------------------------------------------------------------- *
 * Round-1 counterexamples. Each test replays a counterexample of the first
 * review round: the closed-slot precedence of C-DLV section 4.5, the exact
 * success shapes of C-SDK section 8, the exact acknowledgement envelopes of
 * C-SDK section 5.1, the fractional clock of C-SDK section 8.4, the terminal
 * stop of C-DLV section 4.6 and the eviction of section 8's window.
 * ------------------------------------------------------------------------- */
describe('round-1 counterexamples', () => {
  test('a session return carrying a closed slot outside its set is E_SDK_UNKNOWN_CODE', async () => {
    const extras = [
      { code: 'E_FUTURE_RESULT' },
      { state: 'FUTURE_STATE' },
      { outcome: 'FUTURE_OUTCOME' },
      { lastCode: 'E_FUTURE_RESULT' },
      { receiptMode: 'FUTURE_MODE' },
    ];
    for (const extra of extras) {
      const harness = makeHarness({
        session: { open: () => ({ plaintext: new Uint8Array([1]), ...extra }) },
      });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }]);
      expect(harness.published).toHaveLength(0);
    }
  });

  test('a closed slot value does not take precedence: the success shape decides', async () => {
    const extras = [
      { lastCode: null },
      { code: 'E_SDK_SESSION_FAILED' },
      { code: 'E_SDK_UNKNOWN_CODE' },
      { state: 'IN_FLIGHT' },
      { outcome: 'ACCEPTED' },
      { receiptMode: 'RECIPIENT_RECEIPT' },
    ];
    for (const extra of extras) {
      const harness = makeHarness({
        session: { open: () => ({ plaintext: new Uint8Array([1]), ...extra }) },
      });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' }]);
    }
  });

  test('the session success shape is exactly the one key plaintext', async () => {
    const values = [
      { plaintext: new Uint8Array([1]), extra: 1 },
      {},
      { ciphertext: new Uint8Array([1]) },
      { plaintext: 'AA==' },
      [],
      new Uint8Array([1]),
      'plaintext',
      null,
    ];
    for (const value of values) {
      const harness = makeHarness({ session: { open: () => value } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' }]);
      expect(harness.published).toHaveLength(0);
    }
  });

  test('a signature return carrying an unknown closed slot is E_SDK_UNKNOWN_CODE after the message', async () => {
    const harness = makeHarness();
    harness.options.identity.sign = () => Object.assign(new Uint8Array(64), { code: 'E_FUTURE_RESULT' });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    expect(harness.events).toEqual([
      { kind: 'MESSAGE_RECEIVED', sender: harness.other.pub, payload: new Uint8Array([7, 8, 9]) },
      { kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' },
    ]);
    expect(harness.published).toHaveLength(0);
  });

  test('a signature return carrying a closed code keeps the 64-byte rule', async () => {
    const harness = makeHarness();
    harness.options.identity.sign = () => Object.assign(new Uint8Array(63), { code: 'E_SDK_IDENTITY_FAILED' });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    expect(harness.events).toHaveLength(1);
    expect(harness.events[0].kind).toBe('MESSAGE_RECEIVED');
    expect(harness.published).toHaveLength(0);
  });

  test('a fractional millisecond clock reading is accepted and floored', async () => {
    for (const [reading, second] of [[12000.75, 12], [999.999, 0], [0.5, 0]]) {
      const harness = makeHarness({ clock: { now: () => reading } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.published).toHaveLength(1);
      expect(harness.published[0].created_at).toBe(second);
    }
  });

  test('a clock reading that is not finite still gives no receipt', async () => {
    for (const reading of [Infinity, -Infinity, NaN]) {
      const harness = makeHarness({ clock: { now: () => reading } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.published).toHaveLength(0);
      expect(harness.events).toHaveLength(1);
    }
  });

  test('the acknowledgement envelope is exactly { ok: true, value } or { ok: false, code }', async () => {
    const malformed = [
      { ok: true },
      { ok: true, code: 'E_FUTURE_RESULT' },
      { ok: true, state: 'FUTURE_STATE' },
      { ok: true, extra: 1 },
      { ok: false },
      { ok: false, value: 1 },
      { ok: false, code: 'E_FUTURE_RESULT' },
      { ok: false, code: 42 },
      { ok: 1, value: 1 },
      { ok: 'true', value: 1 },
      { value: 1 },
      { code: 'E_SDK_SESSION_FAILED' },
      [],
      new Uint8Array([1]),
      'ok',
      null,
    ];
    for (const value of malformed) {
      const harness = makeHarness({ acceptReceipt: () => value });
      harness.module.ingest(eventFrame(receiptEvent({
        recipient: harness.other, owner: harness.owner.pub, eventId: 'a'.repeat(64),
      })));
      await flush();
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }]);
    }
  });

  test('a well-formed refusal with a closed code is silent, and so is a well-formed acceptance', async () => {
    const silent = [
      Object.freeze({ ok: true, value: Object.freeze({ accepted: true, deliveryId: 'd1' }) }),
      Object.freeze({ ok: true, value: null }),
      Object.freeze({ ok: false, code: 'E_SDK_QUEUE_FULL' }),
      Object.freeze({ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' }),
      Object.freeze({ ok: false, code: 'E_SDK_DELIVERY_TERMINAL' }),
    ];
    for (const value of silent) {
      const harness = makeHarness({ acceptReceipt: () => value });
      harness.module.ingest(eventFrame(receiptEvent({
        recipient: harness.other, owner: harness.owner.pub, eventId: 'b'.repeat(64),
      })));
      await flush();
      expect(harness.events).toEqual([]);
    }
  });

  test('a rejected promise from the sink or from a seam does not surface', async () => {
    const rejections = [];
    const onUnhandled = (reason) => rejections.push(reason);
    process.on('unhandledRejection', onUnhandled);
    try {
      const harness = makeHarness({
        onEvent: () => Promise.reject(new Error('sink')),
        publishReceipt: () => Promise.reject(new Error('seam')),
        acceptReceipt: () => Promise.reject(new Error('ack seam')),
        /* C-SDK section 8.4: a promise from the synchronous clock port is an
         * invalid return, and its rejection is consumed, not left unhandled. */
        clock: { now: () => Promise.reject(new Error('clock')) },
      });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      harness.module.ingest(eventFrame(receiptEvent({
        recipient: harness.other, owner: harness.owner.pub, eventId: 'c'.repeat(64),
      })));
      await flush(8);
      await new Promise((resolve) => setTimeout(resolve, 40));
      expect(rejections).toHaveLength(0);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });

  test('the oldest id leaves the window only at the 4 097th distinct insertion', async () => {
    const harness = makeHarness();
    const first = messageEvent({ sender: harness.other, owner: harness.owner.pub, n: '0'.repeat(32) });
    harness.module.ingest(eventFrame(first));
    for (let index = 1; index <= 4095; index += 1) {
      harness.module.ingest(eventFrame(messageEvent({
        sender: harness.other, owner: harness.owner.pub, n: index.toString(16).padStart(32, '0'),
      })));
      if (index % 512 === 0) {
        expect(await waitFor(() => harness.events.length === index + 1, 60000)).toBe(true);
      }
    }
    expect(await waitFor(() => harness.events.length === 4096, 60000)).toBe(true);
    /* 4 096 ids are retained, so the first is still a duplicate. */
    harness.module.ingest(eventFrame(first));
    await flush();
    expect(harness.events).toHaveLength(4096);
    /* The 4 097th distinct id evicts the first, which is then processed again. */
    harness.module.ingest(eventFrame(messageEvent({
      sender: harness.other, owner: harness.owner.pub, n: 'f'.repeat(32),
    })));
    expect(await waitFor(() => harness.events.length === 4097, 60000)).toBe(true);
    harness.module.ingest(eventFrame(first));
    expect(await waitFor(() => harness.events.length === 4098, 60000)).toBe(true);
  }, 300000);

  test('no event follows the terminal state of the pipeline', async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const opens = [];
    const harness = makeHarness({
      session: {
        open: ({ sender, ciphertext }) => {
          opens.push({ sender, ciphertext });
          return gate.then(() => ({ plaintext: new Uint8Array([1]) }));
        },
      },
    });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(2);
    harness.module.shutdown();
    release();
    await flush(8);
    expect(harness.events).toEqual([]);
    expect(harness.published).toHaveLength(0);
    expect(opens).toHaveLength(1);
  });
});

/* ------------------------------------------------------------------------- *
 * The terminal stop of C-DLV section 4.6 step (1). No port call, seam call,
 * emission or signature may begin once `shutdown()` has returned, whatever
 * awaited boundary the pipeline is parked on.
 * ------------------------------------------------------------------------- */
describe('the terminal stop at every awaited boundary', () => {
  test('a stop while the identity key is pending starts no port call and emits nothing', async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const harness = makeHarness();
    harness.options.identity.getPublicKey = () => gate.then(() => harness.owner.pub);
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    harness.module.ingest(eventFrame(receiptEvent({
      recipient: harness.other, owner: harness.owner.pub, eventId: 'a'.repeat(64),
    })));
    await flush(2);
    harness.module.shutdown();
    release();
    await flush(16);
    expect(harness.events).toEqual([]);
    expect(harness.opens).toEqual([]);
    expect(harness.acks).toEqual([]);
    expect(harness.published).toEqual([]);
  });

  test('a stop during an open that then rejects emits nothing', async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const harness = makeHarness();
    harness.options.session.open = () => gate.then(() => {
      throw new Error('open rejects after the stop');
    });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(2);
    harness.module.shutdown();
    release();
    await flush(16);
    expect(harness.events).toEqual([]);
  });

  test('a stop during an open that then times out emits nothing', async () => {
    const harness = makeHarness({ perRelayTimeoutMs: 400 });
    harness.options.session.open = () => new Promise(() => {});
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(2);
    harness.module.shutdown();
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(harness.events).toEqual([]);
  });

  test('a stop during the signature leaves the message event that preceded it and no discard', async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const harness = makeHarness();
    harness.options.identity.sign = () => gate.then(
      () => Object.assign(new Uint8Array(64), { code: 'E_FUTURE_RESULT' }),
    );
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(2);
    /* The message event was emitted before the stop; the signature is pending. */
    expect(harness.events).toHaveLength(1);
    expect(harness.events[0].kind).toBe('MESSAGE_RECEIVED');
    harness.module.shutdown();
    release();
    await flush(16);
    expect(harness.events).toHaveLength(1);
    expect(harness.published).toEqual([]);
  });

  test('a stop during an open starts no signature afterwards', async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const harness = makeHarness();
    let signs = 0;
    harness.options.identity.sign = ({ digest }) => {
      signs += 1;
      return schnorr.sign(digest, harness.owner.priv);
    };
    harness.options.session.open = () => gate.then(() => ({ plaintext: new Uint8Array([1]) }));
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(2);
    harness.module.shutdown();
    release();
    await flush(16);
    expect(signs).toBe(0);
    expect(harness.events).toEqual([]);
    expect(harness.published).toEqual([]);
  });
});


/* ------------------------------------------------------------------------- *
 * Owner decision R2 -- the round-3 corrections.
 *
 * A1: C-DLV section 4.5 runs first on the return of `getPublicKey()`, so an
 * unknown closed slot there is `E_SDK_UNKNOWN_CODE` and only a well-formed but
 * non-64-hex key is the step-3 failure of `E_SDK_INBOUND_INVALID`. (c)1: the
 * five closed slots the contract names are read on any object return. (c)4: the
 * acknowledgement envelope is checked with `Object.isFrozen`. The O-SCEN3
 * replays are the exact replays above; `relayLoss` and `hungRelay` carry no
 * inbound frame and are checked below as C-DLV section 7.1 properties, with
 * C1, the clock return under C-DLV section 4.5. The remaining tests
 * are the MEDIUM findings of the round-3 review that are inside the two-file
 * allowlist and change no contract text.
 * ------------------------------------------------------------------------- */

describe('A1 -- unknown-value precedence on the identity-key return', () => {
  test('a getPublicKey return carrying a closed slot outside its set is E_SDK_UNKNOWN_CODE, ahead of the step-3 failure', async () => {
    for (const reading of [
      { code: 'E_FUTURE_RESULT' },
      { state: 'FUTURE_STATE' },
      { outcome: 'FUTURE_OUTCOME' },
      { lastCode: 'E_FUTURE_RESULT' },
      { receiptMode: 'FUTURE_MODE' },
    ]) {
      const harness = makeHarness({ identity: { getPublicKey: () => reading, sign: () => new Uint8Array(64) } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }]);
      expect(harness.published).toHaveLength(0);
      expect(harness.opens).toHaveLength(0);
    }
  });

  test('a well-formed but non-64-hex key return is still the step-3 failure of E_SDK_INBOUND_INVALID', async () => {
    for (const reading of ['', 'z'.repeat(64), 'A'.repeat(64), 12, true, { key: 'a'.repeat(64) }]) {
      const harness = makeHarness({ identity: { getPublicKey: () => reading, sign: () => new Uint8Array(64) } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INBOUND_INVALID' }]);
      expect(harness.published).toHaveLength(0);
    }
  });

  test('a getPublicKey return carrying a closed slot that is INSIDE its set still fails step 3 the plain way', async () => {
    for (const reading of [{ lastCode: null }, { state: 'IN_FLIGHT' }, { code: 'E_SDK_UNKNOWN_CODE' }]) {
      const harness = makeHarness({ identity: { getPublicKey: () => reading, sign: () => new Uint8Array(64) } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INBOUND_INVALID' }]);
    }
  });
});

describe('(c)1 -- the five closed slots are read on any object return', () => {
  test('a typed-array return that carries a closed slot outside its set is E_SDK_UNKNOWN_CODE', async () => {
    const sign = makeHarness();
    sign.options.identity.sign = () => Object.assign(new Uint8Array(64), { state: 'FUTURE_STATE' });
    sign.module.ingest(eventFrame(messageEvent({ sender: sign.other, owner: sign.owner.pub })));
    await flush();
    expect(sign.events).toEqual([
      { kind: 'MESSAGE_RECEIVED', sender: sign.other.pub, payload: new Uint8Array([7, 8, 9]) },
      { kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' },
    ]);
    expect(sign.published).toHaveLength(0);

    const open = makeHarness({
      session: { open: () => Object.assign(new Uint8Array(1), { outcome: 'FUTURE_OUTCOME' }) },
    });
    open.module.ingest(eventFrame(messageEvent({ sender: open.other, owner: open.owner.pub })));
    await flush();
    expect(open.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }]);
  });
});

describe('(c)4 -- the acknowledgement envelope is checked with Object.isFrozen', () => {
  test('an unfrozen acceptance or refusal is E_SDK_UNKNOWN_CODE, and the frozen envelope is silent', async () => {
    const unfrozen = [
      { ok: true, value: { accepted: true, deliveryId: 'd1' } },
      { ok: false, code: 'E_SDK_QUEUE_FULL' },
      { ok: true, value: null },
    ];
    for (const value of unfrozen) {
      const harness = makeHarness({ acceptReceipt: () => value });
      harness.module.ingest(frame(['EVENT', 'sub', receiptEvent({
        recipient: harness.other, owner: harness.owner.pub, eventId: 'a'.repeat(64),
      })]));
      await flush();
      expect(harness.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }]);
    }
    const frozen = makeHarness({
      acceptReceipt: () => Object.freeze({ ok: true, value: Object.freeze({ accepted: true }) }),
    });
    frozen.module.ingest(frame(['EVENT', 'sub', receiptEvent({
      recipient: frozen.other, owner: frozen.owner.pub, eventId: 'b'.repeat(64),
    })]));
    await flush();
    expect(frozen.events).toEqual([]);
  });
});

/* ------------------------------------------------------------------------- *
 * C-DLV section 7.1 properties (owner decision R4, S1: relabelled). The O-SCEN3
 * records `relayLoss` (`relayLossAndReplacement`) and `hungRelay`
 * (`hungRelayAlongsideNormal`) have one sender client and carry no inbound
 * kind-4 741 or kind-4 742 frame, so there is nothing of theirs for this module
 * to replay; the contract cites them transitively for the inbound rule below,
 * which these two tests check as properties of C-DLV section 7.1, not as replays.
 * ------------------------------------------------------------------------- */

describe('C-DLV section 7.1 -- arrival order across relays, without waiting on a relay', () => {
  test('frames delivered by two relays before the client is RUNNING are queued and processed in arrival order', async () => {
    const harness = makeHarness();
    const first = messageEvent({ sender: harness.other, owner: harness.owner.pub, n: '1'.repeat(32), payload: [1] });
    const second = messageEvent({ sender: harness.other, owner: harness.owner.pub, n: '2'.repeat(32), payload: [2] });
    harness.module.ingest(eventFrame(first, 1));
    harness.module.ingest(eventFrame(second, 0));
    await flush(8);
    expect(harness.events.map((event) => event.kind)).toEqual(['MESSAGE_RECEIVED', 'MESSAGE_RECEIVED']);
    expect(harness.published.map((receipt) => receipt.tags[1][1])).toEqual([first.id, second.id]);
    expect(harness.opens).toHaveLength(2);
  });

  test("one relay's frame is processed at once and another relay's later frame at its own arrival, in arrival order", async () => {
    const harness = makeHarness();
    const early = messageEvent({ sender: harness.other, owner: harness.owner.pub, n: '3'.repeat(32), payload: [3] });
    const late = messageEvent({ sender: harness.other, owner: harness.owner.pub, n: '4'.repeat(32), payload: [4] });
    harness.module.ingest(eventFrame(early, 0));
    await flush(8);
    expect(harness.events).toHaveLength(1);
    harness.module.ingest(eventFrame(late, 1));
    await flush(8);
    expect(harness.events).toHaveLength(2);
    expect(harness.published.map((receipt) => receipt.tags[1][1])).toEqual([early.id, late.id]);
  });
});

describe('C1 -- C-DLV section 4.5 on the clock return (owner decision R4)', () => {
  test('a clock return carrying a closed slot outside its set is E_SDK_UNKNOWN_CODE after the message event, with no receipt', async () => {
    for (const reading of [
      { code: 'E_FUTURE_RESULT' },
      { state: 'FUTURE_STATE' },
      { outcome: 'FUTURE_OUTCOME' },
      { lastCode: 'E_FUTURE_RESULT' },
      { receiptMode: 'FUTURE_MODE' },
      Object.assign(new Number(12000), { code: 'E_FUTURE_RESULT' }),
    ]) {
      const harness = makeHarness({ clock: { now: () => reading } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.events).toEqual([
        { kind: 'MESSAGE_RECEIVED', sender: harness.other.pub, payload: new Uint8Array([7, 8, 9]) },
        { kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' },
      ]);
      expect(harness.published).toHaveLength(0);
    }
  });

  test('the closed-slot check runs before the number checks, and the rest of the clock clause is unchanged', async () => {
    /* A slot inside its closed set is not unknown: the reading is then a
     * non-number and means no receipt and no event, as before. */
    for (const reading of [{ code: 'E_SDK_INTERNAL' }, { state: 'QUEUED' }, { lastCode: null }, {}, '1000', null]) {
      const harness = makeHarness({ clock: { now: () => reading } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.events).toHaveLength(1);
      expect(harness.events[0].kind).toBe('MESSAGE_RECEIVED');
      expect(harness.published).toHaveLength(0);
    }
    /* A throwing clock and a promise are still faults with no event. */
    for (const now of [() => { throw new Error('clock'); }, () => Promise.resolve({ code: 'E_FUTURE_RESULT' })]) {
      const harness = makeHarness({ clock: { now } });
      harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
      await flush();
      expect(harness.events).toHaveLength(1);
      expect(harness.published).toHaveLength(0);
    }
    /* A legal reading still builds and publishes the receipt. */
    const harness = makeHarness({ clock: { now: () => 12000.5 } });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    expect(harness.events).toHaveLength(1);
    expect(harness.published).toHaveLength(1);
    expect(harness.published[0].created_at).toBe(12);
  });

  test('a stop that lands while the clock return is screened emits no discard', async () => {
    let module = null;
    const value = {};
    Object.defineProperty(value, 'state', {
      enumerable: true,
      get() {
        module.shutdown();
        return 'FUTURE_STATE';
      },
    });
    const harness = makeHarness({ clock: { now: () => value } });
    module = harness.module;
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(8);
    expect(harness.events).toHaveLength(1);
    expect(harness.events[0].kind).toBe('MESSAGE_RECEIVED');
    expect(harness.published).toEqual([]);
  });
});

describe('the remaining in-allowlist findings of the round-3 review', () => {
  test('a negative clock reading builds no receipt and emits no event (B8)', async () => {
    const harness = makeHarness({ clock: { now: () => -12000 } });
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush();
    expect(harness.events).toHaveLength(1);
    expect(harness.events[0].kind).toBe('MESSAGE_RECEIVED');
    expect(harness.published).toHaveLength(0);
  });

  test('a port getter that stops the client during the lookup starts no call and emits nothing (B3)', async () => {
    const calls = [];
    let module = null;
    const harness = makeHarness({
      session: {
        get open() {
          module.shutdown();
          return () => {
            calls.push('open');
            return { plaintext: new Uint8Array([1]) };
          };
        },
      },
    });
    module = harness.module;
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(8);
    expect(calls).toEqual([]);
    expect(harness.events).toEqual([]);
    expect(harness.published).toEqual([]);
  });

  test('a closed-slot getter that stops the client emits no discard after the stop (B3)', async () => {
    const calls = [];
    let module = null;
    const value = {};
    Object.defineProperty(value, 'state', {
      enumerable: true,
      get() {
        module.shutdown();
        return 'FUTURE_STATE';
      },
    });
    const harness = makeHarness({ session: { open: () => value } });
    module = harness.module;
    harness.module.ingest(eventFrame(messageEvent({ sender: harness.other, owner: harness.owner.pub })));
    await flush(8);
    expect(calls).toEqual([]);
    expect(harness.events).toEqual([]);
    expect(harness.published).toEqual([]);
  });

  test('a frame array whose index getter throws is never queued, and never processed (B5)', async () => {
    const hostileIngest = makeHarness();
    const unreadable = ['EVENT', 'sub', null];
    Object.defineProperty(unreadable, 0, {
      get() {
        throw new Error('hostile frame');
      },
    });
    expect(hostileIngest.module.ingest({ relayIndex: 0, relay: 'relay-0', data: unreadable }))
      .toEqual({ ok: true, value: { queued: false } });
    await flush(4);
    expect(hostileIngest.events).toEqual([]);
    expect(hostileIngest.published).toEqual([]);

    const hostileProcess = makeHarness();
    const unreadableEvent = ['EVENT', 'sub', null];
    Object.defineProperty(unreadableEvent, 2, {
      get() {
        throw new Error('hostile frame');
      },
    });
    expect(hostileProcess.module.ingest({ relayIndex: 0, relay: 'relay-0', data: unreadableEvent }))
      .toEqual({ ok: true, value: { queued: true } });
    await flush(8);
    expect(hostileProcess.events).toEqual([]);
    expect(hostileProcess.published).toEqual([]);
  });
});
