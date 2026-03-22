import { describe, test, expect, beforeAll } from '@jest/globals';
import { SovereignLedger, StyxState, LedgerConfig, LogLevel } from '../../src/facade/sovereign-ledger.js';
import {
  MemoryLedgerStore,
  MemoryPeerStore,
  MemoryKeyStore,
  MemoryOutboxStore,
} from '../../src/storage/memory-store.js';
import { IdentityManager } from '../../src/crypto/identity.js';
import { ShamirSplitter, ShamirReconstructor, ShamirShare, KeyBackup } from '../../src/crypto/shamir.js';
import { Hasher } from '../../src/crypto/hasher.js';
import { Signer, Verifier } from '../../src/crypto/signer.js';
import { EventFactory } from '../../src/ledger/event-factory.js';
import { ChainValidator } from '../../src/ledger/chain-validator.js';
import { LedgerService } from '../../src/ledger/ledger-service.js';
import { VectorClock } from '../../src/ledger/vector-clock.js';
import { EventType } from '../../src/ledger/event.js';
import { loadTestWordlist, createTestKeyPair } from '../setup.js';

beforeAll(() => {
  loadTestWordlist();
});

function createConfig() {
  return new LedgerConfig({ logLevel: LogLevel.NONE });
}

function createLedger(overrides = {}) {
  return new SovereignLedger({
    config: createConfig(),
    ledgerStore: overrides.ledgerStore || new MemoryLedgerStore(),
    peerStore: overrides.peerStore || new MemoryPeerStore(),
    keyStore: overrides.keyStore || new MemoryKeyStore(),
    outboxStore: overrides.outboxStore || new MemoryOutboxStore(),
  });
}

describe('E2E Integration', () => {
  test('two peers: initialize, pair via QR, exchange events, validate chains', async () => {
    const ledgerA = createLedger();
    const ledgerB = createLedger();

    await ledgerA.initialize();
    await ledgerB.initialize();

    expect(ledgerA.state).toBe(StyxState.UNPAIRED);
    expect(ledgerB.state).toBe(StyxState.UNPAIRED);

    // A generates QR, B processes it
    const qrData = await ledgerA.generatePairingQr();
    const result = await ledgerB.processPairingQr(qrData.toQrPayload());
    expect(result.isValid).toBe(true);

    // Both confirm pairing
    await ledgerA.confirmPairing({
      peerPublicKey: ledgerB.identity.publicKey,
      peerAlias: 'PeerB',
    });

    await ledgerB.confirmPairing({
      peerPublicKey: ledgerA.identity.publicKey,
      peerAlias: 'PeerA',
    });

    // Both should be DEGRADED (no real relay) or READY
    expect([StyxState.READY, StyxState.DEGRADED]).toContain(ledgerA.state);
    expect([StyxState.READY, StyxState.DEGRADED]).toContain(ledgerB.state);

    // Peer roles should be complementary
    expect(ledgerA.identity.peerRole).toMatch(/^[AB]$/);
    expect(ledgerB.identity.peerRole).toMatch(/^[AB]$/);
    expect(ledgerA.identity.peerRole).not.toBe(ledgerB.identity.peerRole);

    // A sends events
    const event1 = await ledgerA.sendTransaction({
      payload: new TextEncoder().encode('tx-1'),
    });
    const event2 = await ledgerA.sendMessage({
      payload: new TextEncoder().encode('msg-1'),
    });

    expect(event1.eventType).toBe('transaction');
    expect(event2.eventType).toBe('message');

    // A's chain should be valid
    const validationA = await ledgerA.validateChain();
    expect(validationA).toBeNull();

    // A's history should include genesis + events
    const historyA = await ledgerA.getHistory();
    expect(historyA.length).toBeGreaterThanOrEqual(3);

    // Peers should be accessible
    const peerA = await ledgerA.getPeer();
    expect(peerA.alias).toBe('PeerB');
    const peerB = await ledgerB.getPeer();
    expect(peerB.alias).toBe('PeerA');

    // Shutdown
    await ledgerA.shutdown();
    await ledgerB.shutdown();
    expect(ledgerA.state).toBe(StyxState.UNINITIALIZED);
    expect(ledgerB.state).toBe(StyxState.UNINITIALIZED);
  });

  test('Shamir backup and restore preserves identity', async () => {
    const ledger = createLedger();
    await ledger.initialize();
    const originalPubHex = ledger.identity.publicKey.toHex();

    // Create backup with 2-of-3 scheme
    const shares = await ledger.createIdentityBackup({ threshold: 2, totalShares: 3 });
    expect(shares).toHaveLength(3);

    // Restore using any 2 shares
    const newLedger = createLedger();
    await newLedger.initialize();

    await newLedger.restoreIdentity({ shares: [shares[0], shares[2]] });
    expect(newLedger.identity.publicKey.toHex()).toBe(originalPubHex);

    await ledger.shutdown();
    await newLedger.shutdown();
  });

  test('chain validation detects integrity across multiple events', async () => {
    const ledger = createLedger();
    await ledger.initialize();
    const peerKp = await createTestKeyPair();
    await ledger.confirmPairing({
      peerPublicKey: peerKp.publicKey,
      peerAlias: 'Peer',
    });

    // Send multiple events of different types
    await ledger.sendTransaction({ payload: new TextEncoder().encode('tx') });
    await ledger.sendMessage({ payload: new TextEncoder().encode('msg') });
    await ledger.sendSOS({ payload: new TextEncoder().encode('help') });
    await ledger.sendConfig({ payload: new TextEncoder().encode('cfg') });

    // Chain should be valid
    const error = await ledger.validateChain();
    expect(error).toBeNull();

    // History should have genesis + 4 events
    const history = await ledger.getHistory();
    expect(history.length).toBeGreaterThanOrEqual(5);

    // All hashes should be unique
    const hashes = history.map((e) => e.eventHash);
    expect(new Set(hashes).size).toBe(hashes.length);

    // Chain linkage: each event's previousHash should match prior event's hash
    for (let i = 1; i < history.length; i++) {
      expect(history[i].previousHash).toBe(history[i - 1].eventHash);
    }

    await ledger.shutdown();
  });

  test('identity persistence across sessions', async () => {
    const keyStore = new MemoryKeyStore();

    // Session 1: create identity
    const ledger1 = createLedger({ keyStore });
    await ledger1.initialize();
    const pubHex = ledger1.identity.publicKey.toHex();
    await ledger1.shutdown();

    // Session 2: same keyStore, identity should be loaded
    const ledger2 = createLedger({ keyStore });
    await ledger2.initialize();
    expect(ledger2.identity.publicKey.toHex()).toBe(pubHex);
    await ledger2.shutdown();
  });

  test('low-level Shamir split/reconstruct with various thresholds', () => {
    const splitter = new ShamirSplitter();
    const reconstructor = new ShamirReconstructor();
    const secret = new Uint8Array([42, 137, 255, 0, 100, 200, 50, 75]);

    // 2-of-3
    const shares3 = splitter.split(secret, 2, 3);
    expect(reconstructor.reconstruct([shares3[0], shares3[1]])).toEqual(secret);
    expect(reconstructor.reconstruct([shares3[0], shares3[2]])).toEqual(secret);
    expect(reconstructor.reconstruct([shares3[1], shares3[2]])).toEqual(secret);

    // 3-of-5
    const shares5 = splitter.split(secret, 3, 5);
    expect(reconstructor.reconstruct([shares5[0], shares5[2], shares5[4]])).toEqual(secret);

    // Serialize/deserialize roundtrip
    const serialized = shares3.map((s) => s.serialize());
    const deserialized = serialized.map((s) => ShamirShare.deserialize(s));
    expect(reconstructor.reconstruct([deserialized[0], deserialized[1]])).toEqual(secret);
  });

  test('event stream subscriptions work', async () => {
    const ledger = createLedger();
    await ledger.initialize();
    const peerKp = await createTestKeyPair();
    await ledger.confirmPairing({
      peerPublicKey: peerKp.publicKey,
      peerAlias: 'Peer',
    });

    const allEvents = [];
    ledger.eventStream.onAllEvents((e) => allEvents.push(e));

    await ledger.sendMessage({ payload: new TextEncoder().encode('test') });
    expect(allEvents.length).toBeGreaterThanOrEqual(1);
    expect(allEvents[allEvents.length - 1].eventType).toBe('message');

    await ledger.shutdown();
  });
});
