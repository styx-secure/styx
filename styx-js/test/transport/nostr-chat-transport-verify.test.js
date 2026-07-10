// test/transport/nostr-chat-transport-verify.test.js
// A1: the transport must verify the NIP-01 id + schnorr signature of every
// inbound event and drop anything that fails, so `from` is a proven identity.
import { describe, test, expect, jest } from '@jest/globals';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { NostrChatTransport } from '../../src/transport/nostr-chat-transport.js';
import { bytesToHex, utf8Encode } from '../../src/utils.js';

const KIND = 1059;

function signedEvent(sk, pk, toPk, content, kind = KIND) {
  const event = {
    kind, pubkey: pk, created_at: Math.floor(Date.now() / 1000),
    tags: [['p', toPk]], content,
  };
  const serialized = JSON.stringify([
    0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
  ]);
  const id = sha256(utf8Encode(serialized));
  event.id = bytesToHex(id);
  event.sig = bytesToHex(schnorr.sign(id, sk));
  return event;
}

/** A transport instance without opening any socket (RelayPool is not constructed). */
function makeTransport(pk) {
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
    t._onRelay(['EVENT', 'sub', signedEvent(senderSk, senderPk, mePk, 'aGVsbG8=')]);
    expect(cb).toHaveBeenCalledTimes(1);
    expect(cb.mock.calls[0][0]).toBe(senderPk);
    expect(t.rejectedCount).toBe(0);
  });

  test('drops an event whose signature does not match its pubkey (relay forgery)', () => {
    const t = makeTransport(mePk);
    const cb = jest.fn();
    t.onMessage(cb);
    const ev = signedEvent(senderSk, senderPk, mePk, 'aGVsbG8=');
    // The relay claims the event came from someone else, keeping the valid-looking sig.
    ev.pubkey = bytesToHex(schnorr.getPublicKey(schnorr.utils.randomPrivateKey()));
    t._onRelay(['EVENT', 'sub', ev]);
    expect(cb).not.toHaveBeenCalled();
    expect(t.rejectedCount).toBe(1);
  });

  test('drops an event whose content was tampered after signing', () => {
    const t = makeTransport(mePk);
    const cb = jest.fn();
    t.onMessage(cb);
    const ev = signedEvent(senderSk, senderPk, mePk, 'aGVsbG8=');
    ev.content = 'dGFtcGVyZWQ='; // id no longer binds the content
    t._onRelay(['EVENT', 'sub', ev]);
    expect(cb).not.toHaveBeenCalled();
    expect(t.rejectedCount).toBe(1);
  });

  test('drops an event with a valid id but a signature from another key', () => {
    const t = makeTransport(mePk);
    const cb = jest.fn();
    t.onMessage(cb);
    const ev = signedEvent(senderSk, senderPk, mePk, 'aGVsbG8=');
    const otherSk = schnorr.utils.randomPrivateKey();
    ev.sig = bytesToHex(schnorr.sign(sha256(utf8Encode('anything')), otherSk));
    t._onRelay(['EVENT', 'sub', ev]);
    expect(cb).not.toHaveBeenCalled();
    expect(t.rejectedCount).toBe(1);
  });

  test('drops a malformed event (missing sig / bad hex) without throwing', () => {
    const t = makeTransport(mePk);
    const cb = jest.fn();
    t.onMessage(cb);
    const noSig = signedEvent(senderSk, senderPk, mePk, 'aGVsbG8=');
    delete noSig.sig;
    expect(() => t._onRelay(['EVENT', 'sub', noSig])).not.toThrow();

    const badHex = signedEvent(senderSk, senderPk, mePk, 'aGVsbG8=');
    badHex.sig = 'zz';
    expect(() => t._onRelay(['EVENT', 'sub', badHex])).not.toThrow();

    expect(cb).not.toHaveBeenCalled();
    expect(t.rejectedCount).toBe(2);
  });

  test('a forged event does not poison the dedup set (a later genuine one still arrives)', () => {
    const t = makeTransport(mePk);
    const cb = jest.fn();
    t.onMessage(cb);
    const genuine = signedEvent(senderSk, senderPk, mePk, 'aGVsbG8=');
    // A relay replays the same id with tampered content first.
    const forged = { ...genuine, content: 'dGFtcGVyZWQ=' };
    t._onRelay(['EVENT', 'sub', forged]);
    t._onRelay(['EVENT', 'sub', genuine]);
    expect(cb).toHaveBeenCalledTimes(1);
    expect(cb.mock.calls[0][0]).toBe(senderPk);
  });
});
