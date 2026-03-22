import { describe, test, expect, beforeEach, beforeAll } from '@jest/globals';
import { SovereignLedger, StyxState, LedgerConfig, LogLevel } from '../../src/facade/sovereign-ledger.js';
import {
  MemoryLedgerStore,
  MemoryPeerStore,
  MemoryKeyStore,
  MemoryOutboxStore,
} from '../../src/storage/memory-store.js';
import { StyxPublicKey } from '../../src/crypto/identity.js';
import { loadTestWordlist, createTestKeyPair } from '../setup.js';

beforeAll(() => {
  loadTestWordlist();
});

function createLedger(overrides = {}) {
  return new SovereignLedger({
    config: new LedgerConfig({ logLevel: LogLevel.NONE, ...overrides.config }),
    ledgerStore: overrides.ledgerStore || new MemoryLedgerStore(),
    peerStore: overrides.peerStore || new MemoryPeerStore(),
    keyStore: overrides.keyStore || new MemoryKeyStore(),
    outboxStore: overrides.outboxStore || new MemoryOutboxStore(),
  });
}

describe('SovereignLedger', () => {
  describe('State and Config', () => {
    test('StyxState has all required values', () => {
      expect(StyxState.UNINITIALIZED).toBe('uninitialized');
      expect(StyxState.INITIALIZING).toBe('initializing');
      expect(StyxState.UNPAIRED).toBe('unpaired');
      expect(StyxState.READY).toBe('ready');
      expect(StyxState.DEGRADED).toBe('degraded');
      expect(StyxState.PAIRING).toBe('pairing');
      expect(StyxState.ERROR).toBe('error');
      expect(StyxState.SHUTTING_DOWN).toBe('shuttingDown');
    });

    test('LedgerConfig defaults and freeze', () => {
      const config = new LedgerConfig();
      expect(config.privacyProfile).toBe('balanced');
      expect(config.persistence).toBe('memory');
      expect(config.relayUrls).toHaveLength(3);
      expect(Object.isFrozen(config)).toBe(true);
    });

    test('initial state is UNINITIALIZED', () => {
      const ledger = createLedger();
      expect(ledger.state).toBe(StyxState.UNINITIALIZED);
      expect(ledger.identity).toBeNull();
    });
  });

  describe('Lifecycle', () => {
    test('initialize generates new identity and transitions to UNPAIRED', async () => {
      const ledger = createLedger();
      await ledger.initialize();
      expect(ledger.state).toBe(StyxState.UNPAIRED);
      expect(ledger.identity).not.toBeNull();
      expect(ledger.identity.publicKey).toBeDefined();
      expect(ledger.identity.nodeId).toHaveLength(8);
    });

    test('initialize loads existing identity', async () => {
      const keyStore = new MemoryKeyStore();
      const kp = await createTestKeyPair();
      await keyStore.storeKeyPair({ keyId: 'primary', keyPair: kp });

      const ledger = createLedger({ keyStore });
      await ledger.initialize();
      expect(ledger.identity.publicKey.toHex()).toBe(kp.publicKey.toHex());
    });

    test('shutdown transitions to UNINITIALIZED', async () => {
      const ledger = createLedger();
      await ledger.initialize();
      await ledger.shutdown();
      expect(ledger.state).toBe(StyxState.UNINITIALIZED);
    });

    test('onStateChange tracks transitions', async () => {
      const ledger = createLedger();
      const states = [];
      ledger.onStateChange((s) => states.push(s));

      await ledger.initialize();
      expect(states).toContain(StyxState.INITIALIZING);
      expect(states).toContain(StyxState.UNPAIRED);

      await ledger.shutdown();
      expect(states).toContain(StyxState.SHUTTING_DOWN);
      // UNINITIALIZED is set after removeAllListeners(), so it won't be captured
      expect(ledger.state).toBe(StyxState.UNINITIALIZED);
    });
  });

  describe('Pairing', () => {
    test('generatePairingQr returns QR data', async () => {
      const ledger = createLedger();
      await ledger.initialize();
      const qrData = await ledger.generatePairingQr();
      expect(qrData.publicKey.toHex()).toBe(ledger.identity.publicKey.toHex());
      expect(qrData.nonce.length).toBe(16);
    });

    test('generatePairingQr throws in wrong state', async () => {
      const ledger = createLedger();
      await expect(ledger.generatePairingQr()).rejects.toThrow('Invalid state');
    });

    test('confirmPairing transitions to DEGRADED (no relay)', async () => {
      const ledger = createLedger();
      await ledger.initialize();
      const peerKp = await createTestKeyPair();

      await ledger.confirmPairing({
        peerPublicKey: peerKp.publicKey,
        peerAlias: 'Alice',
      });

      // Without real relays, connect fails → DEGRADED
      expect([StyxState.READY, StyxState.DEGRADED]).toContain(ledger.state);
      expect(ledger.identity.peerRole).toMatch(/^[AB]$/);
    });

    test('getPeer returns paired peer', async () => {
      const ledger = createLedger();
      await ledger.initialize();
      const peerKp = await createTestKeyPair();

      await ledger.confirmPairing({
        peerPublicKey: peerKp.publicKey,
        peerAlias: 'Alice',
      });

      const peer = await ledger.getPeer();
      expect(peer).not.toBeNull();
      expect(peer.alias).toBe('Alice');
    });

    test('confirmPairing with hex string pubkey', async () => {
      const ledger = createLedger();
      await ledger.initialize();
      const peerKp = await createTestKeyPair();

      await ledger.confirmPairing({
        peerPublicKey: peerKp.publicKey.toHex(),
        peerAlias: 'Bob',
      });

      const peer = await ledger.getPeer();
      expect(peer).not.toBeNull();
    });
  });

  describe('Events', () => {
    let ledger;

    beforeEach(async () => {
      ledger = createLedger();
      await ledger.initialize();
      const peerKp = await createTestKeyPair();
      await ledger.confirmPairing({
        peerPublicKey: peerKp.publicKey,
        peerAlias: 'Peer',
      });
    });

    test('sendTransaction creates event', async () => {
      const event = await ledger.sendTransaction({
        payload: new TextEncoder().encode('test tx'),
      });
      expect(event).toBeDefined();
      expect(event.eventType).toBe('transaction');
      expect(event.eventHash).toBeDefined();
    });

    test('sendMessage creates event', async () => {
      const event = await ledger.sendMessage({
        payload: new TextEncoder().encode('hello'),
      });
      expect(event.eventType).toBe('message');
    });

    test('sendSOS creates event', async () => {
      const event = await ledger.sendSOS({
        payload: new TextEncoder().encode('help'),
      });
      expect(event.eventType).toBe('sos');
    });

    test('sendConfig creates event', async () => {
      const event = await ledger.sendConfig({
        payload: new TextEncoder().encode('{}'),
      });
      expect(event.eventType).toBe('config');
    });

    test('sendEvent in UNPAIRED state throws', async () => {
      const unpaired = createLedger();
      await unpaired.initialize();
      await expect(
        unpaired.sendMessage({ payload: new TextEncoder().encode('hi') })
      ).rejects.toThrow('Invalid state');
    });
  });

  describe('History', () => {
    let ledger;

    beforeEach(async () => {
      ledger = createLedger();
      await ledger.initialize();
      const peerKp = await createTestKeyPair();
      await ledger.confirmPairing({
        peerPublicKey: peerKp.publicKey,
        peerAlias: 'Peer',
      });
    });

    test('getHistory returns all events', async () => {
      await ledger.sendMessage({ payload: new TextEncoder().encode('msg1') });
      await ledger.sendMessage({ payload: new TextEncoder().encode('msg2') });
      const history = await ledger.getHistory();
      // genesis + 2 messages
      expect(history.length).toBeGreaterThanOrEqual(3);
    });

    test('validateChain returns null for valid chain', async () => {
      await ledger.sendMessage({ payload: new TextEncoder().encode('test') });
      const error = await ledger.validateChain();
      expect(error).toBeNull();
    });
  });

  describe('Backup and Restore', () => {
    test('createIdentityBackup and restoreIdentity roundtrip', async () => {
      const ledger = createLedger();
      await ledger.initialize();
      const originalPubHex = ledger.identity.publicKey.toHex();

      const shares = await ledger.createIdentityBackup({ threshold: 2, totalShares: 3 });
      expect(shares).toHaveLength(3);
      expect(typeof shares[0]).toBe('string');

      // Use only 2 shares to restore
      await ledger.restoreIdentity({ shares: shares.slice(0, 2) });
      expect(ledger.identity.publicKey.toHex()).toBe(originalPubHex);
    });
  });

  describe('Pruning', () => {
    let ledger;

    beforeEach(async () => {
      ledger = createLedger();
      await ledger.initialize();
      const peerKp = await createTestKeyPair();
      await ledger.confirmPairing({
        peerPublicKey: peerKp.publicKey,
        peerAlias: 'Peer',
      });
    });

    test('getExpiredEvents returns empty with no retention policy', async () => {
      const expired = await ledger.getExpiredEvents();
      expect(expired).toEqual([]);
    });
  });

  describe('Remote Pairing', () => {
    test('startRemotePairing generates mnemonic', async () => {
      const ledger = createLedger();
      await ledger.initialize();
      const mnemonic = await ledger.startRemotePairing();
      expect(mnemonic.split(' ').length).toBeGreaterThanOrEqual(6);
      expect(ledger.state).toBe(StyxState.PAIRING);
    });

    test('startRemotePairing as responder returns existing mnemonic', async () => {
      const ledger = createLedger();
      await ledger.initialize();
      const result = await ledger.startRemotePairing('abandon ability able about above absent');
      expect(result).toBe('abandon ability able about above absent');
    });
  });
});
