import { describe, test, expect, beforeEach, beforeAll, jest } from '@jest/globals';
import { SovereignLedger, StyxState, LedgerConfig, LogLevel } from '../../src/facade/sovereign-ledger.js';
import {
  MemoryLedgerStore,
  MemoryPeerStore,
  MemoryKeyStore,
  MemoryOutboxStore,
} from '../../src/storage/memory-store.js';
import { StyxPublicKey } from '../../src/crypto/identity.js';
import { EventType } from '../../src/ledger/event.js';
import {
  V1PruningDisabledError,
  V1_PRUNING_DISABLED_CODE,
  V1_PRUNING_DISABLED_RESULT,
} from '../../src/ledger/pruning.js';
import { loadTestWordlist, createTestEvent, createTestKeyPair } from '../setup.js';

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
    let ledgerStore;
    let outboxStore;
    let peerKp;

    beforeEach(async () => {
      ledgerStore = new MemoryLedgerStore();
      outboxStore = new MemoryOutboxStore();
      ledger = createLedger({ ledgerStore, outboxStore });
      await ledger.initialize();
      peerKp = await createTestKeyPair();
      await ledger.confirmPairing({
        peerPublicKey: peerKp.publicKey,
        peerAlias: 'Peer',
      });
    });

    test('getExpiredEvents returns empty with no retention policy', async () => {
      const expired = await ledger.getExpiredEvents();
      expect(expired).toEqual([]);
    });

    test.each([
      'userRequest',
      'retentionExpired',
      'gdprArticle17',
      'unknownReason',
      null,
      undefined,
    ])(
      'requestPrune(%s) fails closed before every local side effect',
      async (reason) => {
        const target = await createTestEvent({
          previousEvent: await ledgerStore.getLatestEvent(),
          vectorClock: await ledgerStore.getCurrentVectorClock(),
          peerRole: ledger.identity.peerRole,
          type: EventType.MESSAGE,
          payload: new TextEncoder().encode('must remain readable'),
        });
        await ledgerStore.appendEvent(target);
        const appendSpy = jest.spyOn(ledgerStore, 'appendEvent');
        const pruneSpy = jest.spyOn(ledgerStore, 'pruneEvent');
        const outboxSpy = jest.spyOn(outboxStore, 'addEntry');
        const transportSpy = jest.spyOn(ledger._transport, 'send');
        const beforeEvents = (await ledgerStore.getAllEvents()).map((event) =>
          event.toJSON()
        );
        const beforeHeadId = (await ledgerStore.getLatestEvent()).eventId;
        const beforeClock = (await ledgerStore.getCurrentVectorClock()).toJSON();
        const beforeOutboxCount = await outboxStore.pendingCount();
        const applicationEvents = [];
        const securityEvents = [];
        ledger.eventStream.onAllEvents((event) => applicationEvents.push(event));
        ledger.onSecurityEvent((event) => securityEvents.push(event));

        await expect(
          ledger.requestPrune({ targetEventId: target.eventId, reason })
        ).rejects.toBeInstanceOf(V1PruningDisabledError);

        expect(appendSpy).not.toHaveBeenCalled();
        expect(pruneSpy).not.toHaveBeenCalled();
        expect(outboxSpy).not.toHaveBeenCalled();
        expect(transportSpy).not.toHaveBeenCalled();
        expect((await ledgerStore.getEventById(target.eventId)).payload).toEqual(
          target.payload
        );
        expect((await ledgerStore.getAllEvents()).map((event) => event.toJSON())).toEqual(
          beforeEvents
        );
        expect((await ledgerStore.getLatestEvent()).eventId).toBe(beforeHeadId);
        expect((await ledgerStore.getCurrentVectorClock()).toJSON()).toEqual(beforeClock);
        expect(await outboxStore.pendingCount()).toBe(beforeOutboxCount);
        expect(applicationEvents).toEqual([]);
        expect(securityEvents).toEqual([V1_PRUNING_DISABLED_RESULT]);
      }
    );

    test('requestPrune rejects with the containment error before state validation', async () => {
      const unpaired = createLedger();
      await unpaired.initialize();

      await expect(unpaired.requestPrune()).rejects.toMatchObject({
        name: 'V1PruningDisabledError',
        code: V1_PRUNING_DISABLED_CODE,
      });
      expect(unpaired.state).toBe(StyxState.UNPAIRED);
    });

    test.each([
      ['well-formed request with false hash targeting genesis', EventType.PRUNE_REQUEST, true],
      ['malformed request payload', EventType.PRUNE_REQUEST, false],
      ['well-formed acknowledgement', EventType.PRUNE_ACK, true],
    ])(
      'rejects inbound %s before fork detection, persistence, or application emission',
      async (_label, eventType, wellFormed) => {
        const localHead = await ledgerStore.getLatestEvent();
        const controlPayload = wellFormed
          ? JSON.stringify({
              type: eventType === EventType.PRUNE_REQUEST ? 'prune_request' : 'prune_ack',
              targetEventId: localHead.eventId,
              targetEventHash: '00'.repeat(32),
              reason: 'userRequest',
            })
          : '{ malformed v1 control payload';
        const inbound = await createTestEvent({
          keyPair: peerKp,
          previousEvent: localHead,
          vectorClock: await ledgerStore.getCurrentVectorClock(),
          peerRole: ledger.identity.peerRole === 'A' ? 'B' : 'A',
          type: eventType,
          payload: new TextEncoder().encode(controlPayload),
        });
        const message = {
          payload: new TextEncoder().encode(JSON.stringify(inbound.toJSON())),
        };
        const beforeEvents = (await ledgerStore.getAllEvents()).map((event) =>
          event.toJSON()
        );
        const beforeHeadId = (await ledgerStore.getLatestEvent()).eventId;
        const beforeClock = (await ledgerStore.getCurrentVectorClock()).toJSON();
        const beforeOutboxCount = await outboxStore.pendingCount();
        const appendSpy = jest.spyOn(ledgerStore, 'appendEvent');
        const pruneSpy = jest.spyOn(ledgerStore, 'pruneEvent');
        const receiveSpy = jest.spyOn(ledger._ledgerService, 'receiveRemoteEvent');
        const outboxSpy = jest.spyOn(outboxStore, 'addEntry');
        const transportSpy = jest.spyOn(ledger._transport, 'send');
        const applicationEvents = [];
        const securityEvents = [];
        ledger.eventStream.onAllEvents((event) => applicationEvents.push(event));
        ledger.onSecurityEvent((event) => securityEvents.push(event));

        for (let i = 0; i < 100; i++) {
          await expect(ledger._handleIncomingMessage(message)).resolves.toBe(
            V1_PRUNING_DISABLED_RESULT
          );
        }

        expect(appendSpy).not.toHaveBeenCalled();
        expect(pruneSpy).not.toHaveBeenCalled();
        expect(receiveSpy).not.toHaveBeenCalled();
        expect(await ledgerStore.getEventsByType(EventType.PRUNE_ACK)).toEqual([]);
        expect(outboxSpy).not.toHaveBeenCalled();
        expect(transportSpy).not.toHaveBeenCalled();
        expect(applicationEvents).toEqual([]);
        expect(securityEvents).toHaveLength(100);
        expect(securityEvents.every((event) => event.accepted === false)).toBe(true);
        expect(await ledgerStore.getAllEvents()).toEqual(
          expect.arrayContaining(
            beforeEvents.map((json) => expect.objectContaining({ eventId: json.eventId }))
          )
        );
        expect((await ledgerStore.getAllEvents()).map((event) => event.toJSON())).toEqual(
          beforeEvents
        );
        expect(await ledgerStore.count()).toBe(beforeEvents.length);
        expect((await ledgerStore.getLatestEvent()).eventId).toBe(beforeHeadId);
        expect((await ledgerStore.getCurrentVectorClock()).toJSON()).toEqual(beforeClock);
        expect(await outboxStore.pendingCount()).toBe(beforeOutboxCount);
      }
    );

    test('drops an incomplete raw prune envelope before LedgerEvent construction', async () => {
      const beforeEvents = (await ledgerStore.getAllEvents()).map((event) =>
        event.toJSON()
      );
      const securityEvents = [];
      ledger.onSecurityEvent((event) => securityEvents.push(event));
      const message = {
        payload: new TextEncoder().encode(
          JSON.stringify({ eventType: EventType.PRUNE_REQUEST })
        ),
      };

      await expect(ledger._handleIncomingMessage(message)).resolves.toBe(
        V1_PRUNING_DISABLED_RESULT
      );
      expect((await ledgerStore.getAllEvents()).map((event) => event.toJSON())).toEqual(
        beforeEvents
      );
      expect(securityEvents).toEqual([V1_PRUNING_DISABLED_RESULT]);
    });

    test.each([
      ['missing payload', {}],
      ['empty payload', { payload: new Uint8Array() }],
      ['non-JSON bytes', { payload: new TextEncoder().encode('not JSON') }],
      ['JSON null', { payload: new TextEncoder().encode('null') }],
      ['JSON array', { payload: new TextEncoder().encode('[]') }],
      ['JSON string', { payload: new TextEncoder().encode('"pruneRequest"') }],
      ['JSON number', { payload: new TextEncoder().encode('3') }],
    ])('leaves a malformed non-prune envelope inert: %s', async (_label, message) => {
      const beforeEvents = (await ledgerStore.getAllEvents()).map((event) =>
        event.toJSON()
      );
      const beforeOutboxCount = await outboxStore.pendingCount();
      const appendSpy = jest.spyOn(ledgerStore, 'appendEvent');
      const pruneSpy = jest.spyOn(ledgerStore, 'pruneEvent');
      const receiveSpy = jest.spyOn(ledger._ledgerService, 'receiveRemoteEvent');
      const applicationEvents = [];
      const securityEvents = [];
      ledger.eventStream.onAllEvents((event) => applicationEvents.push(event));
      ledger.onSecurityEvent((event) => securityEvents.push(event));

      await expect(ledger._handleIncomingMessage(message)).resolves.toBeUndefined();

      expect(appendSpy).not.toHaveBeenCalled();
      expect(pruneSpy).not.toHaveBeenCalled();
      expect(receiveSpy).not.toHaveBeenCalled();
      expect(applicationEvents).toEqual([]);
      expect(securityEvents).toEqual([]);
      expect((await ledgerStore.getAllEvents()).map((event) => event.toJSON())).toEqual(
        beforeEvents
      );
      expect(await outboxStore.pendingCount()).toBe(beforeOutboxCount);
    });

    test('keeps ordinary inbound message behavior unchanged as a positive control', async () => {
      const localHead = await ledgerStore.getLatestEvent();
      const inbound = await createTestEvent({
        keyPair: peerKp,
        previousEvent: localHead,
        vectorClock: await ledgerStore.getCurrentVectorClock(),
        peerRole: ledger.identity.peerRole === 'A' ? 'B' : 'A',
        type: EventType.MESSAGE,
        payload: new TextEncoder().encode('ordinary remote event'),
      });
      const message = {
        payload: new TextEncoder().encode(JSON.stringify(inbound.toJSON())),
      };
      const allEvents = [];
      const remoteEvents = [];
      ledger.eventStream.onAllEvents((event) => allEvents.push(event));
      ledger.eventStream.onRemoteEvents((event) => remoteEvents.push(event));

      await ledger._handleIncomingMessage(message);

      expect(await ledgerStore.getEventById(inbound.eventId)).not.toBeNull();
      expect(allEvents).toEqual([inbound]);
      expect(remoteEvents).toEqual([inbound]);
    });

    test('logger and telemetry failures cannot turn rejection into acceptance', async () => {
      const localHead = await ledgerStore.getLatestEvent();
      const inbound = await createTestEvent({
        keyPair: peerKp,
        previousEvent: localHead,
        vectorClock: await ledgerStore.getCurrentVectorClock(),
        peerRole: ledger.identity.peerRole === 'A' ? 'B' : 'A',
        type: EventType.PRUNE_REQUEST,
      });
      const message = {
        payload: new TextEncoder().encode(JSON.stringify(inbound.toJSON())),
      };
      const receiveSpy = jest.spyOn(ledger._ledgerService, 'receiveRemoteEvent');
      const pruneSpy = jest.spyOn(ledgerStore, 'pruneEvent');
      ledger._log = () => {
        throw new Error('injected logger failure');
      };
      ledger.onSecurityEvent(() => {
        throw new Error('injected telemetry failure');
      });

      await expect(ledger._handleIncomingMessage(message)).resolves.toMatchObject({
        accepted: false,
        code: V1_PRUNING_DISABLED_CODE,
      });
      expect(receiveSpy).not.toHaveBeenCalled();
      expect(pruneSpy).not.toHaveBeenCalled();
    });

    test('local rejection survives hostile logger and telemetry consumers', async () => {
      const appendSpy = jest.spyOn(ledgerStore, 'appendEvent');
      const pruneSpy = jest.spyOn(ledgerStore, 'pruneEvent');
      const outboxSpy = jest.spyOn(outboxStore, 'addEntry');
      ledger._log = () => {
        throw new Error('injected logger failure');
      };
      ledger.onSecurityEvent(() => {
        throw new Error('injected telemetry failure');
      });

      await expect(
        ledger.requestPrune({ targetEventId: 'irrelevant', reason: 'userRequest' })
      ).rejects.toBeInstanceOf(V1PruningDisabledError);

      expect(appendSpy).not.toHaveBeenCalled();
      expect(pruneSpy).not.toHaveBeenCalled();
      expect(outboxSpy).not.toHaveBeenCalled();
    });

    test('requestPrune rejects before initialize()', async () => {
      const fresh = createLedger();
      expect(fresh.state).toBe(StyxState.UNINITIALIZED);

      await expect(fresh.requestPrune()).rejects.toBeInstanceOf(
        V1PruningDisabledError
      );
      expect(fresh.state).toBe(StyxState.UNINITIALIZED);
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
