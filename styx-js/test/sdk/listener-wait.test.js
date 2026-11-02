import { describe, test, expect } from '@jest/globals';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, bytesToBase64, utf8Encode, hexToBytes } from '../../src/utils.js';
import { createReceipts } from '../../src/sdk/delivery/receipts.js';
import { SDK_WIRE_VERSION } from '../../src/sdk/index.js';

const sleep = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate) {
  const deadline = Date.now() + 15000;
  while (!predicate() && Date.now() < deadline) await sleep(2);
  expect(predicate()).toBe(true);
}
function key() {
  const secret = schnorr.utils.randomPrivateKey();
  return { secret, publicKey: bytesToHex(schnorr.getPublicKey(secret)) };
}
function harness({ session: replacementSession = null } = {}) {
  const own = key();
  const sender = key();
  const calls = [];
  const messages = [];
  const published = [];
  const receipts = [];
  const discarded = [];
  let audience = null;
  let opening = null;
  let openingHook = null;
  const module = createReceipts({
    publicKey: own.publicKey, identity: {
      getPublicKey: () => own.publicKey,
      sign: ({ digest }) => { calls.push('sign'); return schnorr.sign(digest, own.secret); },
    },
    session: replacementSession ?? { open: async ({ ciphertext }) => {
      calls.push('open');
      if (openingHook !== null) openingHook();
      if (opening !== null) await opening;
      return { plaintext: new Uint8Array(ciphertext) };
    } },
    clock: { now: () => 12000 }, perRelayTimeoutMs: 2000,
    reserveMessage: () => {
      const reserved = audience;
      if (reserved === null) return null;
      return (event) => { calls.push('invoke'); reserved(event); return true; };
    },
    onEvent: (event) => discarded.push(event),
    publishReceipt: (event) => { calls.push('publish'); published.push(event); },
    acceptReceipt: (event) => { receipts.push(event); return Object.freeze({ ok: true, value: Object.freeze({ accepted: false }) }); },
  });
  function event(index, kind = 4741, request = true) {
    const tags = kind === 4741
      ? [['p', own.publicKey], ['v', SDK_WIRE_VERSION], ['n', index.toString(16).padStart(32, '0')]]
      : [['p', own.publicKey], ['e', 'd'.repeat(64)], ['v', SDK_WIRE_VERSION], ['n', index.toString(16).padStart(32, '0')]];
    if (kind === 4741 && request) tags.push(['r', '1']);
    const content = kind === 4741 ? bytesToBase64(new Uint8Array([index % 256])) : '';
    const id = bytesToHex(sha256(utf8Encode(JSON.stringify([0, sender.publicKey, 12, kind, tags, content]))));
    return { id, pubkey: sender.publicKey, created_at: 12, kind, tags, content,
      sig: bytesToHex(schnorr.sign(hexToBytes(id), sender.secret)) };
  }
  const ingest = (value) => module.ingest({ relayIndex: 0, relay: 'injected', data: ['EVENT', 'sub', value] });
  return { module, calls, messages, published, receipts, discarded, event, ingest,
    listen: (callback = (event) => messages.push(event)) => { audience = callback; module.wake(); },
    unlisten: () => { audience = null; },
    hold: (promise) => { opening = promise; },
    onOpen: (hook) => { openingHook = hook; },
  };
}

describe('M3-LISTENER bounded encrypted waiting', () => {
  test.each(['method-getter', 'closed-slot-getter'])('Kimi R1 HIGH: reserved delivery emits no discard after stop from %s', async (fault) => {
    let h;
    let invoked = false;
    const session = fault === 'method-getter' ? {
      get open() {
        h.module.shutdown();
        return () => { invoked = true; return { plaintext: new Uint8Array([1]) }; };
      },
    } : {
      open: () => {
        invoked = true;
        return { plaintext: new Uint8Array([1]), get state() { h.module.shutdown(); return 'OUTSIDE'; } };
      },
    };
    h = harness({ session });
    h.listen(); h.ingest(h.event(1));
    await sleep(25);
    await Promise.all([h.module.settled(), h.module.drained()]);
    expect(invoked).toBe(fault !== 'method-getter');
    expect(h.messages).toEqual([]);
    expect(h.discarded).toEqual([]);
    expect(h.published).toEqual([]);
  });

  test('Kimi R1 LOW: a validated acknowledgement does not occupy a raw pending slot', async () => {
    // Surface capacity is already covered by the 1,024-message test below.
    // This case covers the receipt-side async continuation specifically.
    const own = key(), sender = key();
    let release;
    const blocked = new Promise((resolve) => { release = resolve; });
    let accepting = false;
    const processor = createReceipts({ publicKey: own.publicKey, perRelayTimeoutMs: 2000,
      acceptReceipt: () => { accepting = true; return blocked; }, onEvent: () => {} });
    const tags = [['p', own.publicKey], ['e', 'd'.repeat(64)], ['v', SDK_WIRE_VERSION], ['n', '1'.repeat(32)]];
    const id = bytesToHex(sha256(utf8Encode(JSON.stringify([0, sender.publicKey, 12, 4742, tags, '']))));
    const receipt = { id, pubkey: sender.publicKey, created_at: 12, kind: 4742, tags, content: '',
      sig: bytesToHex(schnorr.sign(hexToBytes(id), sender.secret)) };
    const frame = { data: ['EVENT', 'sub', receipt] };
    processor.ingest(frame);
    await until(() => accepting);
    try {
      for (let i = 0; i < 1024; i += 1) expect(processor.ingest(frame).value.queued).toBe(true);
      expect(processor.ingest(frame).value.queued).toBe(false);
    } finally {
      processor.shutdown(); release({ ok: true, value: {} }); await processor.settled();
    }
  });

  test('no listener through shutdown: no open, no callback, no receipt', async () => {
    const h = harness();
    h.ingest(h.event(1));
    await sleep(25);
    expect(h.calls).toEqual([]);
    expect(h.module.shutdown()).toEqual({ ok: true, value: { dropped: 1 } });
    h.listen();
    await h.module.settled();
    expect(h.calls).toEqual([]);
  });

  test('waiting ids are deduplicated separately, in admission order; receipts pass while waiting', async () => {
    const h = harness();
    const first = h.event(1);
    h.ingest(first); h.ingest(first); h.ingest(h.event(2)); h.ingest(h.event(3, 4742));
    await until(() => h.receipts.length === 1);
    expect(h.calls).toEqual([]);
    h.listen();
    await until(() => h.published.length === 2);
    expect(h.messages.map((event) => [...event.payload])).toEqual([[1], [2]]);
    expect(h.calls).toEqual(['open', 'invoke', 'sign', 'publish', 'open', 'invoke', 'sign', 'publish']);
    h.ingest(first);
    await sleep(20);
    expect(h.messages).toHaveLength(2);
    h.module.shutdown(); await h.module.settled();
  });

  test('last unsubscribe pauses, registration wakes; a self-unsubscribe stops the next open', async () => {
    const h = harness();
    h.ingest(h.event(1)); h.ingest(h.event(2));
    h.listen((event) => { h.messages.push(event); h.unlisten(); });
    await until(() => h.published.length === 1);
    await sleep(20);
    expect(h.calls.filter((x) => x === 'open')).toHaveLength(1);
    h.listen();
    await until(() => h.published.length === 2);
    expect(h.messages.map((event) => [...event.payload])).toEqual([[1], [2]]);
    h.module.shutdown(); await h.module.settled();
  });

  test('in-flight reserved listener survives unsubscribe, receipt follows callback', async () => {
    const h = harness();
    let release;
    h.hold(new Promise((resolve) => { release = resolve; }));
    h.listen(); h.ingest(h.event(1));
    await until(() => h.calls.includes('open'));
    h.unlisten();
    expect(h.published).toEqual([]);
    release();
    await until(() => h.published.length === 1);
    expect(h.calls).toEqual(['open', 'invoke', 'sign', 'publish']);
    h.module.shutdown(); await h.module.settled();
  });

  test('shutdown during reserved open settles delivery before receipt, never opens the queued message', async () => {
    const h = harness();
    let release;
    h.hold(new Promise((resolve) => { release = resolve; }));
    h.listen(); h.ingest(h.event(1)); h.ingest(h.event(2));
    await until(() => h.calls.includes('open'));
    h.module.shutdown();
    release();
    await Promise.all([h.module.settled(), h.module.drained()]);
    expect(h.calls).toEqual(['open', 'invoke', 'sign', 'publish']);
    expect(h.messages).toHaveLength(1);
  });

  test('shutdown from the callback drains the receipt only after callback invocation', async () => {
    const h = harness();
    h.listen((event) => { h.messages.push(event); h.module.shutdown(); });
    h.ingest(h.event(1));
    await until(() => h.published.length === 1);
    await h.module.settled();
    expect(h.calls).toEqual(['open', 'invoke', 'sign', 'publish']);
  });

  test('full ciphertext queue drops without a seen mark; replay after capacity frees is delivered', async () => {
    const h = harness();
    // Repeated identical ids occupy one validated waiting slot, not 1,024.
    const first = h.event(1, 4741, false);
    for (let i = 0; i < 50; i += 1) { h.ingest(first); await sleep(); }
    const entries = [first];
    for (let i = 2; i <= 1024; i += 1) {
      const event = h.event(i, 4741, false); entries.push(event); h.ingest(event);
      // Let validation move the frame to ciphertext waiting on every batch.
      if (i % 32 === 0) await sleep();
    }
    await sleep(25);
    const overflow = h.event(1025, 4741, false);
    expect(h.ingest(overflow)).toEqual({ ok: true, value: { queued: false } });
    expect(h.calls).toEqual([]);
    h.listen();
    await until(() => h.messages.length === 1024);
    h.ingest(overflow);
    await until(() => h.messages.length === 1025);
    expect([...h.messages.at(-1).payload]).toEqual([1]);
    expect(h.published).toEqual([]);
    h.module.shutdown(); await h.module.settled();
  }, 30000);
});
