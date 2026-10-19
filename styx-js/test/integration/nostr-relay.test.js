/**
 * Integration tests using a real strfry Nostr relay via Docker.
 *
 * Prerequisites:
 *   cd styx-js && docker compose -f docker-compose.test.yml up -d
 *
 * Run:
 *   npm test -- test/integration/nostr-relay.test.js
 */

import { describe, test, expect, beforeAll, afterAll, afterEach } from '@jest/globals';
import WebSocket from 'ws';
import { RelayPool, NostrTransport } from '../../src/transport/nostr-transport.js';
import { TransportMessage, TransportState } from '../../src/transport/transport-interface.js';
import {
  TransportFailover,
  TransportPriority,
} from '../../src/transport/failover.js';
import { StyxEncryptor } from '../../src/crypto/encryption.js';
import { schnorr } from '@noble/curves/secp256k1';
import { IdentityManager } from '../../src/crypto/identity.js';
import { SovereignLedger, StyxState, LedgerConfig, LogLevel } from '../../src/facade/sovereign-ledger.js';
import {
  MemoryLedgerStore,
  MemoryPeerStore,
  MemoryKeyStore,
  MemoryOutboxStore,
} from '../../src/storage/memory-store.js';
import { loadTestWordlist } from '../setup.js';
import { randomBytes, bytesToHex } from '../../src/utils.js';

const RELAY_URL = process.env.NOSTR_RELAY || 'ws://localhost:17777';
const REQUIRE_RELAY = process.env.REQUIRE_RELAY === '1';

// Polyfill WebSocket for Node.js
globalThis.WebSocket = WebSocket;

// Condition wait with a bounded deadline: poll `cond()` until it holds instead
// of sleeping a fixed number of milliseconds. `deadline` is an absolute
// Date.now() value shared by every wait of one test, so the test as a whole
// stays bounded. On expiry it throws, naming what was awaited and the observed
// state (`detail()`), so a slow or absent relay fails loudly, never as a pass.
async function waitUntil(what, cond, deadline, detail = () => '') {
  for (;;) {
    if (await cond()) return;
    if (Date.now() >= deadline) {
      const d = detail();
      throw new Error('timed out waiting for ' + what + ' on ' + RELAY_URL + (d ? ' (' + d + ')' : ''));
    }
    await new Promise((r) => setTimeout(r, 20));
  }
}

// Record the relay's NIP-01 answers (EOSE per subscription, OK per event id)
// on a pool, so tests wait on what the relay actually said.
function relayAnswers(pool) {
  const eose = new Set();
  const ok = new Map();
  pool.messages.on('message', ({ data }) => {
    if (!Array.isArray(data)) return;
    if (data[0] === 'EOSE') eose.add(data[1]);
    if (data[0] === 'OK') ok.set(data[1], { accepted: data[2], reason: data[3] });
  });
  return { eose, ok };
}

let relayAvailable = false;

beforeAll(async () => {
  loadTestWordlist();
  relayAvailable = await new Promise((resolve) => {
    const ws = new WebSocket(RELAY_URL);
    const timeout = setTimeout(() => { try { ws.close(); } catch {} resolve(false); }, 2000);
    ws.on('open', () => { clearTimeout(timeout); ws.close(); resolve(true); });
    ws.on('error', () => { clearTimeout(timeout); resolve(false); });
  });
  if (!relayAvailable) {
    if (REQUIRE_RELAY) {
      throw new Error('required relay unavailable: ' + RELAY_URL);
    }
    console.warn(
      '\n⚠ Nostr relay not available at ' + RELAY_URL +
      '\n  Run: cd styx-js && docker compose -f docker-compose.test.yml up -d\n' +
      '  Skipping relay integration tests.\n'
    );
  }
}, 10000);

function skipIfNoRelay() {
  if (!relayAvailable) {
    return true;
  }
  return false;
}

describe('RelayPool (real relay)', () => {
  let pool;

  afterEach(async () => {
    if (pool) { await pool.dispose(); pool = null; }
  });

  test('connectAll connects to real relay', async () => {
    if (skipIfNoRelay()) return;
    pool = new RelayPool([RELAY_URL]);
    const count = await pool.connectAll();
    expect(count).toBe(1);
    expect(pool.connectedCount).toBe(1);
  });

  test('healthCheck shows connected relay', async () => {
    if (skipIfNoRelay()) return;
    pool = new RelayPool([RELAY_URL]);
    await pool.connectAll();
    const health = pool.healthCheck();
    expect(health[0].isConnected).toBe(true);
  });

  test('publish sends event to relay', async () => {
    if (skipIfNoRelay()) return;
    pool = new RelayPool([RELAY_URL]);
    await pool.connectAll();
    const sent = pool.publish({
      id: bytesToHex(randomBytes(32)),
      pubkey: bytesToHex(randomBytes(32)),
      created_at: Math.floor(Date.now() / 1000),
      kind: 30078,
      tags: [],
      content: 'test-content',
      sig: bytesToHex(randomBytes(64)),
    });
    expect(sent).toBe(1);
  });

  test('subscribe receives EOSE from relay', async () => {
    if (skipIfNoRelay()) return;
    pool = new RelayPool([RELAY_URL]);
    await pool.connectAll();

    const messages = [];
    pool.messages.on('message', (msg) => messages.push(msg));
    const subId = 'sub-' + Date.now();
    pool.subscribe(subId, { kinds: [30078], limit: 1 });

    // strfry sends EOSE after subscription: wait for it instead of sleeping.
    const deadline = Date.now() + 4000;
    await waitUntil('EOSE for ' + subId,
      () => messages.some((m) => m.data[0] === 'EOSE' && m.data[1] === subId), deadline,
      () => messages.length + ' relay messages seen');
    expect(messages.length).toBeGreaterThanOrEqual(0);
  });

  test('publishAndVerify confirms persistence on real relay', async () => {
    if (skipIfNoRelay()) return;
    const deadline = Date.now() + 8000;
    pool = new RelayPool([RELAY_URL]);
    const answers = relayAnswers(pool);
    await pool.connectAll();

    // Create and sign a valid event
    const nostrPriv = randomBytes(32);
    const nostrPub = bytesToHex(schnorr.getPublicKey(nostrPriv));
    const { sha256 } = await import('@noble/hashes/sha256');

    // The pinned relay runs with rejectEventsOlderThanSeconds = 0: it answers
    // ["OK", id, false, "invalid: created_at too early"] to any event whose
    // created_at second has already ended when the relay ingests it. Stamping
    // late in a second on a loaded runner therefore loses the event, and no
    // verification budget can recover it. Wait (bounded) until the clock is in
    // the first half of a second, then stamp, sign and publish with no await
    // in between, leaving >= 500 ms for ingestion.
    await waitUntil('the first half of a wall-clock second', () => Date.now() % 1000 < 500, deadline);
    const event = {
      pubkey: nostrPub,
      created_at: Math.floor(Date.now() / 1000),
      kind: 30078,
      tags: [['t', 'verify-test']],
      content: 'publishAndVerify test',
    };
    const ser = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
    const idBytes = sha256(new TextEncoder().encode(ser));
    event.id = bytesToHex(idBytes);
    event.sig = bytesToHex(schnorr.sign(idBytes, nostrPriv));

    // Verification budget = whatever is left of this test's deadline; it ends
    // as soon as the relay returns the stored event. The relay's own OK verdict
    // is checked first, so a rejection fails at once and prints its reason.
    const verifying = pool.publishAndVerify(event, Math.max(0, deadline - Date.now()));
    await waitUntil('the relay OK for event ' + event.id, () => answers.ok.has(event.id), deadline);
    expect(answers.ok.get(event.id)).toEqual({ accepted: true, reason: '' });
    const result = await verifying;
    expect(result.sent).toBe(1);
    expect(result.verified).toBe(true);
  }, 10000);

  test('disconnectAll closes all connections', async () => {
    if (skipIfNoRelay()) return;
    pool = new RelayPool([RELAY_URL]);
    await pool.connectAll();
    await pool.disconnectAll();
    // Wait (bounded) until no connection of the pool is open any more.
    await waitUntil('all relay connections to close', () => pool.connectedCount === 0,
      Date.now() + 4000, () => pool.connectedCount + ' still open');
    expect(pool.connectedCount).toBe(0);
  });

  test('connectAll with mixed valid/invalid relays', async () => {
    if (skipIfNoRelay()) return;
    pool = new RelayPool([RELAY_URL, 'ws://localhost:19999']);
    const count = await pool.connectAll();
    expect(count).toBe(1);
  });
});

describe('NostrTransport (real relay)', () => {
  let transportA, transportB;

  afterEach(async () => {
    if (transportA) { await transportA.dispose(); transportA = null; }
    if (transportB) { await transportB.dispose(); transportB = null; }
  });

  test('connect to real relay sets CONNECTED state', async () => {
    if (skipIfNoRelay()) return;
    const nostrPriv = randomBytes(32);
    const nostrPub = bytesToHex(schnorr.getPublicKey(nostrPriv));
    const pool = new RelayPool([RELAY_URL]);
    transportA = new NostrTransport(pool, new StyxEncryptor(randomBytes(32), randomBytes(32)), nostrPub, 'bb', nostrPriv, nostrPub);

    const states = [];
    transportA.onStateChange((s) => states.push(s));
    await transportA.connect();

    expect(transportA.currentState).toBe(TransportState.CONNECTED);
    expect(states).toContain(TransportState.CONNECTING);
    expect(states).toContain(TransportState.CONNECTED);
  });

  test('send and receive message round-trip', async () => {
    if (skipIfNoRelay()) return;

    // Generate secp256k1 keys for NIP-01 signing
    const nostrPrivA = randomBytes(32);
    const nostrPubA = bytesToHex(schnorr.getPublicKey(nostrPrivA));
    const nostrPrivB = randomBytes(32);
    const nostrPubB = bytesToHex(schnorr.getPublicKey(nostrPrivB));

    // Shared encryption key (both sides same for this test)
    const encKey = randomBytes(32);

    // A sends with p-tag = tagB, B subscribes to tagB
    const tagB = bytesToHex(randomBytes(32)); // opaque subscription tag

    const poolA = new RelayPool([RELAY_URL]);
    const poolB = new RelayPool([RELAY_URL]);
    const answersA = relayAnswers(poolA);
    const answersB = relayAnswers(poolB);
    transportA = new NostrTransport(poolA, new StyxEncryptor(encKey, encKey), nostrPubA, tagB, nostrPrivA);
    transportB = new NostrTransport(poolB, new StyxEncryptor(encKey, encKey), nostrPubB, nostrPubA, nostrPrivB, tagB);

    const deadline = Date.now() + 12000;
    // B's subscription is live once the relay has answered it with EOSE.
    await transportB.connect();
    await waitUntil("EOSE for B's subscription", () => answersB.eose.size > 0, deadline);
    await transportA.connect();

    const receivedByB = [];
    transportB.onMessage((msg) => receivedByB.push(msg));

    const msg = new TransportMessage({
      id: 'rt-' + Date.now(),
      senderPubkey: nostrPubA,
      recipientPubkey: nostrPubB,
      payload: new Uint8Array([42, 99, 7]),
    });

    // send() stamps created_at and publishes synchronously; the pinned relay
    // rejects an event whose created_at second has ended before ingestion
    // (see the publishAndVerify test), so send early in a second.
    await waitUntil('the first half of a wall-clock second', () => Date.now() % 1000 < 500, deadline);
    await transportA.send(msg);
    await waitUntil('B to receive ' + msg.id, () => receivedByB.length >= 1, deadline,
      () => 'relay OK answers to A: ' + JSON.stringify([...answersA.ok.values()]));

    expect(receivedByB.length).toBeGreaterThanOrEqual(1);
    expect(receivedByB[0].id).toBe(msg.id);
    expect(receivedByB[0].payload).toEqual(new Uint8Array([42, 99, 7]));
  }, 15000);

  test('disconnect emits DISCONNECTED', async () => {
    if (skipIfNoRelay()) return;
    const dPriv = randomBytes(32);
    const dPub = bytesToHex(schnorr.getPublicKey(dPriv));
    const dk = randomBytes(32);
    const pool = new RelayPool([RELAY_URL]);
    transportA = new NostrTransport(pool, new StyxEncryptor(dk, dk), dPub, 'bb', dPriv, dPub);
    await transportA.connect();

    const states = [];
    transportA.onStateChange((s) => states.push(s));
    await transportA.disconnect();

    expect(states).toContain(TransportState.DISCONNECTED);
  });
});

describe('TransportFailover (real relay)', () => {
  let failover;

  afterEach(async () => {
    if (failover) { await failover.dispose(); failover = null; }
  });

  test('connect succeeds through failover', async () => {
    if (skipIfNoRelay()) return;
    const fPriv = randomBytes(32);
    const fPub = bytesToHex(schnorr.getPublicKey(fPriv));
    const fk = randomBytes(32);
    const pool = new RelayPool([RELAY_URL]);
    const nostr = new NostrTransport(pool, new StyxEncryptor(fk, fk), fPub, 'bb', fPriv, fPub);

    failover = new TransportFailover([
      new TransportPriority(nostr, 3, 5000),
    ]);
    await failover.connect();
    expect(failover.currentState).toBe(TransportState.CONNECTED);
  });
});

describe('SovereignLedger with real relay', () => {
  test('paired ledger transitions to READY', async () => {
    if (skipIfNoRelay()) return;
    const im = new IdentityManager();
    const kpA = await im.generate();
    const kpB = await im.generate();

    const keyStore = new MemoryKeyStore();
    await keyStore.storeKeyPair({ keyId: 'primary', keyPair: kpA });

    const ledger = new SovereignLedger({
      config: new LedgerConfig({ relayUrls: [RELAY_URL], logLevel: LogLevel.NONE }),
      ledgerStore: new MemoryLedgerStore(),
      peerStore: new MemoryPeerStore(),
      keyStore,
      outboxStore: new MemoryOutboxStore(),
    });

    await ledger.initialize();
    expect(ledger.state).toBe(StyxState.UNPAIRED);

    await ledger.confirmPairing({ peerPublicKey: kpB.publicKey, peerAlias: 'B' });
    expect(ledger.state).toBe(StyxState.READY);

    const event = await ledger.sendTransaction({
      payload: new TextEncoder().encode('real-relay-tx'),
    });
    expect(event.eventType).toBe('transaction');

    const history = await ledger.getHistory();
    expect(history.length).toBeGreaterThanOrEqual(2);

    expect(await ledger.validateChain()).toBeNull();

    await ledger.shutdown();
    expect(ledger.state).toBe(StyxState.UNINITIALIZED);
  }, 15000);

  test('blessNewDevice creates REKEY event', async () => {
    if (skipIfNoRelay()) return;
    const im = new IdentityManager();
    const kpA = await im.generate();
    const kpB = await im.generate();
    const kpNew = await im.generate();

    const keyStore = new MemoryKeyStore();
    await keyStore.storeKeyPair({ keyId: 'primary', keyPair: kpA });

    const ledger = new SovereignLedger({
      config: new LedgerConfig({ relayUrls: [RELAY_URL], logLevel: LogLevel.NONE }),
      ledgerStore: new MemoryLedgerStore(),
      peerStore: new MemoryPeerStore(),
      keyStore,
      outboxStore: new MemoryOutboxStore(),
    });

    await ledger.initialize();
    await ledger.confirmPairing({ peerPublicKey: kpB.publicKey, peerAlias: 'B' });

    const rekeyEvent = await ledger.blessNewDevice({ newPublicKey: kpNew.publicKey });
    expect(rekeyEvent.eventType).toBe('rekey');

    const payload = JSON.parse(new TextDecoder().decode(rekeyEvent.payload));
    expect(payload.newPublicKey).toBe(kpNew.publicKey.toHex());

    await ledger.shutdown();
  }, 15000);

  test('two paired peers both reach READY', async () => {
    if (skipIfNoRelay()) return;
    const im = new IdentityManager();
    const kpA = await im.generate();
    const kpB = await im.generate();

    const ksA = new MemoryKeyStore();
    const ksB = new MemoryKeyStore();
    await ksA.storeKeyPair({ keyId: 'primary', keyPair: kpA });
    await ksB.storeKeyPair({ keyId: 'primary', keyPair: kpB });

    const mkLedger = (ks) => new SovereignLedger({
      config: new LedgerConfig({ relayUrls: [RELAY_URL], logLevel: LogLevel.NONE }),
      ledgerStore: new MemoryLedgerStore(),
      peerStore: new MemoryPeerStore(),
      keyStore: ks,
      outboxStore: new MemoryOutboxStore(),
    });

    const ledgerA = mkLedger(ksA);
    const ledgerB = mkLedger(ksB);

    await ledgerA.initialize();
    await ledgerB.initialize();

    await ledgerA.confirmPairing({ peerPublicKey: kpB.publicKey, peerAlias: 'B' });
    await ledgerB.confirmPairing({ peerPublicKey: kpA.publicKey, peerAlias: 'A' });

    expect(ledgerA.state).toBe(StyxState.READY);
    expect(ledgerB.state).toBe(StyxState.READY);
    expect(ledgerA.identity.peerRole).not.toBe(ledgerB.identity.peerRole);

    await ledgerA.sendMessage({ payload: new TextEncoder().encode('hello') });
    await ledgerB.sendTransaction({ payload: new TextEncoder().encode('tx') });

    expect(await ledgerA.validateChain()).toBeNull();
    expect(await ledgerB.validateChain()).toBeNull();

    await ledgerA.shutdown();
    await ledgerB.shutdown();
  }, 15000);
});
