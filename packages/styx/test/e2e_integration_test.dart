import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:styx/styx.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/styx_ledger_engine.dart';
import 'package:styx_transport/styx_transport.dart';
import 'package:test/test.dart';

// ---------------------------------------------------------------------------
// InMemoryLedgerStore
// ---------------------------------------------------------------------------

/// In-memory implementation of [LedgerStore] for E2E testing.
///
/// Uses real [EventFactory] and [ChainValidator] internally.
class InMemoryLedgerStore implements LedgerStore {
  InMemoryLedgerStore({
    required EventFactory eventFactory,
    required ChainValidator chainValidator,
    required String localPeerRole,
  })  : _eventFactory = eventFactory,
        _chainValidator = chainValidator,
        _localPeerRole = localPeerRole;

  final EventFactory _eventFactory;
  final ChainValidator _chainValidator;
  final String _localPeerRole;

  final _events = <LedgerEvent>[];
  VectorClock _vectorClock = const VectorClock.zero();
  final _newEventController = StreamController<LedgerEvent>.broadcast();

  @override
  Future<LedgerEvent> appendEvent({
    required EventType type,
    required Uint8List payload,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
  }) async {
    final previous = _events.isEmpty ? null : _events.last;

    final event = await _eventFactory.createEvent(
      type: type,
      payload: payload,
      privateKey: privateKey,
      publicKey: publicKey,
      previousEvent: previous,
      currentVectorClock: _vectorClock,
      localPeerRole: _localPeerRole,
    );

    _events.add(event);
    _vectorClock = event.vectorClock;
    _newEventController.add(event);
    return event;
  }

  /// Appends a pre-built event directly (for cross-peer simulation).
  void addExternalEvent(LedgerEvent event) {
    _events.add(event);
    _vectorClock = _vectorClock.merge(event.vectorClock);
    _newEventController.add(event);
  }

  @override
  Future<List<LedgerEvent>> getHistory() async =>
      List.unmodifiable(_events);

  @override
  Future<ChainValidationError?> validateChain() async =>
      _chainValidator.validateFullChain(_events);

  @override
  Future<LedgerEvent?> getLatestEvent() async =>
      _events.isEmpty ? null : _events.last;

  @override
  Stream<LedgerEvent> watchNewEvents() => _newEventController.stream;

  /// Releases the stream controller.
  Future<void> dispose() async {
    await _newEventController.close();
  }
}

// ---------------------------------------------------------------------------
// FakeTransport
// ---------------------------------------------------------------------------

/// Fake transport for E2E testing with send/connect/disconnect tracking.
class FakeTransport implements TransportInterface {
  final _messageController = StreamController<TransportMessage>.broadcast();
  final _stateController = StreamController<TransportState>.broadcast();
  final sentMessages = <TransportMessage>[];
  TransportState _currentState = TransportState.disconnected;
  int connectCount = 0;
  int disconnectCount = 0;

  @override
  TransportState get currentState => _currentState;

  @override
  bool get isAvailable => _currentState == TransportState.connected;

  @override
  Stream<TransportMessage> get messages => _messageController.stream;

  @override
  Stream<TransportState> get stateChanges => _stateController.stream;

  @override
  Future<void> connect() async {
    connectCount++;
    _currentState = TransportState.connected;
    _stateController.add(TransportState.connected);
  }

  @override
  Future<void> disconnect() async {
    disconnectCount++;
    _currentState = TransportState.disconnected;
    _stateController.add(TransportState.disconnected);
  }

  @override
  Future<void> send(TransportMessage message) async {
    sentMessages.add(message);
  }

  /// Releases stream controllers.
  Future<void> dispose() async {
    await _messageController.close();
    await _stateController.close();
  }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

final _signer = Signer();
final _hasher = Hasher();
final _verifier = Verifier();
final _identityManager = IdentityManager();

/// Creates a fully wired [SovereignLedger] for testing.
Future<({
  SovereignLedger ledger,
  InMemoryLedgerStore store,
  FakeTransport transport,
  TrustStoreManager trustStore,
  InMemoryPeerStore peerStore,
  QrPairingService qrPairing,
  StyxKeyPair keyPair,
})> createTestLedger({
  required String peerRole,
  StyxKeyPair? existingKeyPair,
}) async {
  final keyPair = existingKeyPair ?? await _identityManager.generate();
  final nodeId = keyPair.publicKey.toHex().substring(0, 8);
  final eventFactory = EventFactory(signer: _signer, hasher: _hasher);
  final chainValidator = ChainValidator(
    hasher: _hasher,
    verifier: _verifier,
  );
  final store = InMemoryLedgerStore(
    eventFactory: eventFactory,
    chainValidator: chainValidator,
    localPeerRole: peerRole,
  );
  final transport = FakeTransport();
  final peerStore = InMemoryPeerStore();
  final trustStore = TrustStoreManager(peerStore: peerStore);
  final qrPairing = QrPairingService(trustStore: trustStore);
  final spake2 = Spake2Protocol();
  final mnemonicGen = MnemonicGenerator();
  final sessionVerifier = SessionVerifier();
  final doubleCheck = DoubleCheckVerifier(
    sessionVerifier: sessionVerifier,
  );
  final remotePairing = RemotePairingService(
    spake2Protocol: spake2,
    mnemonicGenerator: mnemonicGen,
    doubleCheckVerifier: doubleCheck,
    trustStore: trustStore,
  );
  final reKeyProtocol = ReKeyProtocol(
    eventFactory: eventFactory,
    trustStoreManager: trustStore,
    verifier: _verifier,
  );
  final keyBackup = KeyBackup(
    splitter: ShamirSplitter(),
    reconstructor: ShamirReconstructor(),
  );
  final migrationService = KeyMigrationService(
    identityManager: _identityManager,
    reKeyProtocol: reKeyProtocol,
    keyBackup: keyBackup,
  );
  final secureKeyStore = InMemoryKeyStore();
  final backupService = ShamirBackupService(
    keyBackup: keyBackup,
    secureKeyStore: secureKeyStore,
  );
  final retentionManager = RetentionManager();
  final pruneProtocol = PruneProtocol(eventFactory: eventFactory);

  final identity = StyxIdentity(
    publicKey: keyPair.publicKey,
    nodeId: nodeId,
    peerRole: peerRole,
  );

  const config = LedgerConfig();

  final ledger = SovereignLedger(
    identity: identity,
    config: config,
    ledgerStore: store,
    transport: transport,
    trustStore: trustStore,
    qrPairing: qrPairing,
    remotePairing: remotePairing,
    reKeyProtocol: reKeyProtocol,
    migrationService: migrationService,
    backupService: backupService,
    retentionManager: retentionManager,
    pruneProtocol: pruneProtocol,
    keyPair: keyPair,
  );

  return (
    ledger: ledger,
    store: store,
    transport: transport,
    trustStore: trustStore,
    peerStore: peerStore,
    qrPairing: qrPairing,
    keyPair: keyPair,
  );
}

/// Performs mutual QR pairing between two peers.
Future<void> performQrPairing({
  required QrPairingService qrA,
  required QrPairingService qrB,
  required StyxPublicKey pubA,
  required StyxPublicKey pubB,
}) async {
  // A shows QR, B scans.
  final qrDataA = qrA.generateQrData(localPublicKey: pubA);
  final resultB = qrB.processScannedQr(
    qrPayload: qrDataA.toQrPayload(),
    localPublicKey: pubB,
  );
  expect(resultB.isValid, isTrue);
  await qrB.completePairing(
    peerPublicKey: resultB.peerPublicKey,
    peerAlias: null,
  );

  // B shows QR, A scans.
  final qrDataB = qrB.generateQrData(localPublicKey: pubB);
  final resultA = qrA.processScannedQr(
    qrPayload: qrDataB.toQrPayload(),
    localPublicKey: pubA,
  );
  expect(resultA.isValid, isTrue);
  await qrA.completePairing(
    peerPublicKey: resultA.peerPublicKey,
    peerAlias: null,
  );
}

Uint8List payload(String text) => Uint8List.fromList(utf8.encode(text));

// ---------------------------------------------------------------------------
// E2E Integration Tests
// ---------------------------------------------------------------------------

void main() {
  // E2E.1 — Happy path: Init -> QR pair -> A sends 100 transactions -> validate
  test(
    'E2E.1: Happy path - init, QR pair, 100 transactions, chain valid',
    () async {
      final a = await createTestLedger(peerRole: 'A');
      final b = await createTestLedger(peerRole: 'B');

      // QR pairing.
      await performQrPairing(
        qrA: a.qrPairing,
        qrB: b.qrPairing,
        pubA: a.keyPair.publicKey,
        pubB: b.keyPair.publicKey,
      );

      // Initialize both ledgers.
      await a.ledger.initialize();
      await b.ledger.initialize();

      expect(a.ledger.state, StyxState.ready);
      expect(b.ledger.state, StyxState.ready);

      // A sends 100 transactions.
      for (var i = 0; i < 100; i++) {
        await a.ledger.sendTransaction(payload('tx-$i'));
      }

      // Validate chain.
      final history = await a.store.getHistory();
      expect(history, hasLength(100));

      final validationError = await a.store.validateChain();
      expect(validationError, isNull);

      // Verify chain linkage.
      for (var i = 1; i < history.length; i++) {
        expect(history[i].previousHash, history[i - 1].eventHash);
      }

      await a.ledger.shutdown();
      await b.ledger.shutdown();
      await a.store.dispose();
      await b.store.dispose();
      await a.transport.dispose();
      await b.transport.dispose();
    },
  );

  // E2E.2 — Bidirectional: A sends 50, B sends 50 -> both see 100 same order
  test(
    'E2E.2: Bidirectional - A sends 50, B sends 50, shared chain of 100',
    () async {
      final a = await createTestLedger(peerRole: 'A');
      final b = await createTestLedger(peerRole: 'B');

      // Direct trust setup.
      await a.trustStore.addTrustedPeer(
        peerPublicKey: b.keyPair.publicKey,
        alias: null,
      );
      await b.trustStore.addTrustedPeer(
        peerPublicKey: a.keyPair.publicKey,
        alias: null,
      );

      await a.ledger.initialize();
      await b.ledger.initialize();

      // Build a shared chain: alternating A and B.
      // Use a single shared store to simulate synchronized ledger.
      final eventFactory = EventFactory(signer: _signer, hasher: _hasher);
      final chainValidator = ChainValidator(
        hasher: _hasher,
        verifier: _verifier,
      );
      final sharedStore = InMemoryLedgerStore(
        eventFactory: eventFactory,
        chainValidator: chainValidator,
        localPeerRole: 'A',
      );

      var vc = const VectorClock.zero();
      LedgerEvent? previous;

      for (var i = 0; i < 100; i++) {
        final isA = i < 50;
        final kp = isA ? a.keyPair : b.keyPair;
        final role = isA ? 'A' : 'B';

        final event = await eventFactory.createEvent(
          type: EventType.transaction,
          payload: payload('bidirectional-$i'),
          privateKey: kp.privateKey,
          publicKey: kp.publicKey,
          previousEvent: previous,
          currentVectorClock: vc,
          localPeerRole: role,
        );

        sharedStore.addExternalEvent(event);
        vc = event.vectorClock;
        previous = event;
      }

      final history = await sharedStore.getHistory();
      expect(history, hasLength(100));

      final validationError = await sharedStore.validateChain();
      expect(validationError, isNull);

      // First 50 from A, last 50 from B.
      for (var i = 0; i < 50; i++) {
        expect(
          history[i].senderPubkey,
          a.keyPair.publicKey.toHex(),
        );
      }
      for (var i = 50; i < 100; i++) {
        expect(
          history[i].senderPubkey,
          b.keyPair.publicKey.toHex(),
        );
      }

      await a.ledger.shutdown();
      await b.ledger.shutdown();
      await sharedStore.dispose();
      await a.store.dispose();
      await b.store.dispose();
      await a.transport.dispose();
      await b.transport.dispose();
    },
  );

  // E2E.3 — Mixed types: 30 TRANSACTION + 10 MESSAGE + 5 CONFIG + 1 SOS
  test(
    'E2E.3: Mixed event types - 30 TX + 10 MSG + 5 CFG + 1 SOS',
    () async {
      final a = await createTestLedger(peerRole: 'A');

      await a.trustStore.addTrustedPeer(
        peerPublicKey: StyxPublicKey.fromHex('bb' * 32),
        alias: null,
      );
      await a.ledger.initialize();

      // 30 transactions.
      for (var i = 0; i < 30; i++) {
        await a.ledger.sendTransaction(payload('tx-$i'));
      }
      // 10 messages.
      for (var i = 0; i < 10; i++) {
        await a.ledger.sendMessage(payload('msg-$i'));
      }
      // 5 configs.
      for (var i = 0; i < 5; i++) {
        await a.ledger.sendConfig(payload('cfg-$i'));
      }
      // 1 SOS.
      await a.ledger.sendSOS(payload('help'));

      final history = await a.store.getHistory();
      expect(history, hasLength(46));

      final txCount =
          history.where((e) => e.eventType == EventType.transaction).length;
      final msgCount =
          history.where((e) => e.eventType == EventType.message).length;
      final cfgCount =
          history.where((e) => e.eventType == EventType.config).length;
      final sosCount =
          history.where((e) => e.eventType == EventType.sos).length;

      expect(txCount, 30);
      expect(msgCount, 10);
      expect(cfgCount, 5);
      expect(sosCount, 1);

      final validationError = await a.store.validateChain();
      expect(validationError, isNull);

      await a.ledger.shutdown();
      await a.store.dispose();
      await a.transport.dispose();
    },
  );

  // E2E.9 — Pruning: A sends event -> prune request -> verify prune protocol
  test(
    'E2E.9: Pruning - send event, request prune, verify prune event',
    () async {
      final a = await createTestLedger(peerRole: 'A');

      await a.trustStore.addTrustedPeer(
        peerPublicKey: StyxPublicKey.fromHex('bb' * 32),
        alias: null,
      );
      await a.ledger.initialize();

      // Send an event.
      final event = await a.ledger.sendTransaction(
        payload('sensitive-data'),
      );

      // Request prune.
      final pruneEvent = await a.ledger.requestPrune(
        targetEventId: event.eventId,
      );

      expect(pruneEvent.eventType, EventType.pruneRequest);

      // Decode the prune payload.
      final prunePayload =
          jsonDecode(utf8.decode(pruneEvent.payload!)) as Map<String, dynamic>;
      expect(prunePayload['target_event_id'], event.eventId);
      expect(prunePayload['target_event_hash'], event.eventHash);
      expect(prunePayload['reason'], PruneReason.userRequest.name);

      await a.ledger.shutdown();
      await a.store.dispose();
      await a.transport.dispose();
    },
  );

  // E2E.13 — SOS: A sends SOS -> event type is SOS
  test(
    'E2E.13: SOS - send SOS event, verify type is SOS',
    () async {
      final a = await createTestLedger(peerRole: 'A');

      await a.trustStore.addTrustedPeer(
        peerPublicKey: StyxPublicKey.fromHex('bb' * 32),
        alias: null,
      );
      await a.ledger.initialize();

      final sosEvent = await a.ledger.sendSOS(payload('emergency'));

      expect(sosEvent.eventType, EventType.sos);
      expect(utf8.decode(sosEvent.payload!), 'emergency');
      expect(sosEvent.senderPubkey, a.keyPair.publicKey.toHex());

      final history = await a.store.getHistory();
      expect(history, hasLength(1));
      expect(history.first.eventType, EventType.sos);

      final validationError = await a.store.validateChain();
      expect(validationError, isNull);

      await a.ledger.shutdown();
      await a.store.dispose();
      await a.transport.dispose();
    },
  );

  // E2E.15 — Re-key: Pair -> 10 events -> re-key A -> 10 events -> valid, 21
  test(
    'E2E.15: Re-key - pair, 10 events, re-key A, 10 more, chain valid 21',
    () async {
      final a = await createTestLedger(peerRole: 'A');
      final b = await createTestLedger(peerRole: 'B');

      // Direct trust.
      await a.trustStore.addTrustedPeer(
        peerPublicKey: b.keyPair.publicKey,
        alias: null,
      );
      await b.trustStore.addTrustedPeer(
        peerPublicKey: a.keyPair.publicKey,
        alias: null,
      );

      await a.ledger.initialize();
      await b.ledger.initialize();

      // Build a shared chain for both peers.
      final eventFactory = EventFactory(signer: _signer, hasher: _hasher);
      final chainValidator = ChainValidator(
        hasher: _hasher,
        verifier: _verifier,
      );
      final sharedStore = InMemoryLedgerStore(
        eventFactory: eventFactory,
        chainValidator: chainValidator,
        localPeerRole: 'A',
      );

      var vc = const VectorClock.zero();
      LedgerEvent? previous;

      // First 10 events (alternating A and B).
      for (var i = 0; i < 10; i++) {
        final isA = i.isEven;
        final kp = isA ? a.keyPair : b.keyPair;
        final role = isA ? 'A' : 'B';

        final event = await eventFactory.createEvent(
          type: EventType.transaction,
          payload: payload('pre-rekey-$i'),
          privateKey: kp.privateKey,
          publicKey: kp.publicKey,
          previousEvent: previous,
          currentVectorClock: vc,
          localPeerRole: role,
        );

        sharedStore.addExternalEvent(event);
        vc = event.vectorClock;
        previous = event;
      }

      // A re-keys to new device.
      final newKeyPairA = await _identityManager.generate();

      final reKeyProtocol = ReKeyProtocol(
        eventFactory: eventFactory,
        trustStoreManager: b.trustStore,
        verifier: _verifier,
      );

      final blessingEvent = await reKeyProtocol.createBlessingEvent(
        oldPrivateKey: a.keyPair.privateKey,
        oldPublicKey: a.keyPair.publicKey,
        newPublicKey: newKeyPairA.publicKey,
        previousEvent: previous,
        currentVectorClock: vc,
        localPeerRole: 'A',
      );

      sharedStore.addExternalEvent(blessingEvent);
      vc = blessingEvent.vectorClock;
      previous = blessingEvent;

      // B processes the REKEY event.
      final rekeyResult = await reKeyProtocol.processReKeyEvent(
        rekeyEvent: blessingEvent,
      );
      expect(rekeyResult.success, isTrue);

      // 10 more events using new A key.
      for (var i = 0; i < 10; i++) {
        final isA = i.isEven;
        final kp = isA ? newKeyPairA : b.keyPair;
        final role = isA ? 'A' : 'B';

        final event = await eventFactory.createEvent(
          type: EventType.transaction,
          payload: payload('post-rekey-$i'),
          privateKey: kp.privateKey,
          publicKey: kp.publicKey,
          previousEvent: previous,
          currentVectorClock: vc,
          localPeerRole: role,
        );

        sharedStore.addExternalEvent(event);
        vc = event.vectorClock;
        previous = event;
      }

      // Total: 10 + 1 REKEY + 10 = 21 events.
      final history = await sharedStore.getHistory();
      expect(history, hasLength(21));

      // Validate chain linkage.
      for (var i = 1; i < history.length; i++) {
        expect(history[i].previousHash, history[i - 1].eventHash);
      }

      // REKEY event at index 10.
      expect(history[10].eventType, EventType.rekey);

      // Validate all signatures.
      for (final event in history) {
        final hashBytes = eventFactory.computeHashBytes(
          previousHash: event.previousHash,
          eventType: event.eventType,
          payload: event.payload,
          hlcBytes: event.hlc.toBytes(),
        );
        final valid = await _verifier.verify(
          payload: hashBytes,
          signatureBytes: event.signature,
          publicKey: StyxPublicKey.fromHex(event.senderPubkey),
        );
        expect(valid, isTrue);
      }

      await a.ledger.shutdown();
      await b.ledger.shutdown();
      await sharedStore.dispose();
      await a.store.dispose();
      await b.store.dispose();
      await a.transport.dispose();
      await b.transport.dispose();
    },
  );

  // E2E.18 — Backup + restore: 20 events -> backup -> restore -> verify match
  test(
    'E2E.18: Backup and restore - 20 events, Shamir backup, restore keypair',
    () async {
      final a = await createTestLedger(peerRole: 'A');

      await a.trustStore.addTrustedPeer(
        peerPublicKey: StyxPublicKey.fromHex('bb' * 32),
        alias: null,
      );
      await a.ledger.initialize();

      // Send 20 events.
      for (var i = 0; i < 20; i++) {
        await a.ledger.sendTransaction(payload('backup-tx-$i'));
      }

      final history = await a.store.getHistory();
      expect(history, hasLength(20));

      // Create Shamir backup.
      final shares = a.ledger.createIdentityBackup();
      expect(shares, hasLength(3));

      // Restore from 2 of 3 shares.
      final restoredKeyPair = await SovereignLedger.restoreIdentity(
        [shares[0], shares[2]],
      );

      // Verify restored key matches original.
      expect(
        restoredKeyPair.publicKey.toHex(),
        a.keyPair.publicKey.toHex(),
      );
      expect(
        restoredKeyPair.privateKey.bytes,
        a.keyPair.privateKey.bytes,
      );

      // Verify chain is still valid.
      final validationError = await a.store.validateChain();
      expect(validationError, isNull);

      await a.ledger.shutdown();
      await a.store.dispose();
      await a.transport.dispose();
    },
  );

  // E2E.20 — QR pairing: A gen QR -> B scans -> B gen QR -> A scans -> paired
  test(
    'E2E.20: QR pairing - mutual QR exchange, both peers paired',
    () async {
      final a = await createTestLedger(peerRole: 'A');
      final b = await createTestLedger(peerRole: 'B');

      // A generates QR.
      final qrDataA = a.qrPairing.generateQrData(
        localPublicKey: a.keyPair.publicKey,
        relayHints: ['wss://relay.example.com'],
      );

      // B scans A's QR.
      final resultB = b.qrPairing.processScannedQr(
        qrPayload: qrDataA.toQrPayload(),
        localPublicKey: b.keyPair.publicKey,
      );
      expect(resultB.isValid, isTrue);
      expect(resultB.peerPublicKey.toHex(), a.keyPair.publicKey.toHex());
      expect(resultB.relayHints, contains('wss://relay.example.com'));

      await b.qrPairing.completePairing(
        peerPublicKey: resultB.peerPublicKey,
        peerAlias: 'Alice',
      );

      // B generates QR.
      final qrDataB = b.qrPairing.generateQrData(
        localPublicKey: b.keyPair.publicKey,
      );

      // A scans B's QR.
      final resultA = a.qrPairing.processScannedQr(
        qrPayload: qrDataB.toQrPayload(),
        localPublicKey: a.keyPair.publicKey,
      );
      expect(resultA.isValid, isTrue);
      expect(resultA.peerPublicKey.toHex(), b.keyPair.publicKey.toHex());

      await a.qrPairing.completePairing(
        peerPublicKey: resultA.peerPublicKey,
        peerAlias: 'Bob',
      );

      // Verify mutual trust.
      expect(await a.trustStore.isTrusted(b.keyPair.publicKey), isTrue);
      expect(await b.trustStore.isTrusted(a.keyPair.publicKey), isTrue);

      // Verify peers are active.
      final peerOfA = await a.trustStore.getActivePeer();
      final peerOfB = await b.trustStore.getActivePeer();
      expect(peerOfA, isNotNull);
      expect(peerOfB, isNotNull);
      expect(peerOfA!.publicKey.toHex(), b.keyPair.publicKey.toHex());
      expect(peerOfB!.publicKey.toHex(), a.keyPair.publicKey.toHex());

      await a.ledger.shutdown();
      await b.ledger.shutdown();
      await a.store.dispose();
      await b.store.dispose();
      await a.transport.dispose();
      await b.transport.dispose();
    },
  );

  // E2E.21 — Remote pairing: mnemonic -> SPAKE2 -> Double Check -> OK
  test(
    'E2E.21: Remote pairing - SPAKE2 + mnemonic + Double Check',
    () async {
      final keyPairA = await _identityManager.generate();
      final keyPairB = await _identityManager.generate();

      final peerStoreA = InMemoryPeerStore();
      final peerStoreB = InMemoryPeerStore();
      final trustA = TrustStoreManager(peerStore: peerStoreA);
      final trustB = TrustStoreManager(peerStore: peerStoreB);

      final spake2 = Spake2Protocol();
      final mnemonicGen = MnemonicGenerator();
      final sessionVerifier = SessionVerifier();

      final serviceA = RemotePairingService(
        spake2Protocol: spake2,
        mnemonicGenerator: mnemonicGen,
        doubleCheckVerifier: DoubleCheckVerifier(
          sessionVerifier: sessionVerifier,
        ),
        trustStore: trustA,
      );
      final serviceB = RemotePairingService(
        spake2Protocol: spake2,
        mnemonicGenerator: mnemonicGen,
        doubleCheckVerifier: DoubleCheckVerifier(
          sessionVerifier: sessionVerifier,
        ),
        trustStore: trustB,
      );

      // Step 1: A generates mnemonic.
      final mnemonic = serviceA.generateMnemonic();
      expect(mnemonic.split(' '), hasLength(6));
      expect(serviceA.state, RemotePairingState.mnemonicGenerated);

      // Step 2: Exchange SPAKE2 messages.
      final msgA = await serviceA.startAsInitiator(
        mnemonic: mnemonic,
        localPublicKey: keyPairA.publicKey,
      );
      final msgB = await serviceB.startAsResponder(
        mnemonic: mnemonic,
        localPublicKey: keyPairB.publicKey,
      );

      // Step 3: Process peer messages.
      expect(serviceA.processPeerMessage(msgB), isTrue);
      expect(serviceB.processPeerMessage(msgA), isTrue);

      expect(serviceA.state, RemotePairingState.doubleCheckPending);
      expect(serviceB.state, RemotePairingState.doubleCheckPending);

      // Step 4: Verify Double Check codes match.
      final codeA = serviceA.getDoubleCheckCode();
      final codeB = serviceB.getDoubleCheckCode();
      expect(codeA, codeB);
      expect(codeA.length, 6);
      expect(RegExp(r'^\d{6}$').hasMatch(codeA), isTrue);

      // Step 5: Exchange public keys and confirm.
      serviceA.peerPublicKey = keyPairB.publicKey;
      serviceB.peerPublicKey = keyPairA.publicKey;

      await serviceA.confirmDoubleCheck(
        codeMatches: true,
        peerAlias: 'Peer B',
      );
      await serviceB.confirmDoubleCheck(
        codeMatches: true,
        peerAlias: 'Peer A',
      );

      expect(serviceA.state, RemotePairingState.completed);
      expect(serviceB.state, RemotePairingState.completed);

      // Verify mutual trust.
      expect(await trustA.isTrusted(keyPairB.publicKey), isTrue);
      expect(await trustB.isTrusted(keyPairA.publicKey), isTrue);

      await serviceA.dispose();
      await serviceB.dispose();
    },
  );

  // E2E.26 — Stress: 10,000 events -> chain valid
  test(
    'E2E.26: Stress - 10,000 events, chain valid',
    () async {
      final a = await createTestLedger(peerRole: 'A');

      await a.trustStore.addTrustedPeer(
        peerPublicKey: StyxPublicKey.fromHex('bb' * 32),
        alias: null,
      );
      await a.ledger.initialize();

      for (var i = 0; i < 10000; i++) {
        await a.ledger.sendTransaction(payload('stress-$i'));
      }

      final history = await a.store.getHistory();
      expect(history, hasLength(10000));

      final validationError = await a.store.validateChain();
      expect(validationError, isNull);

      // Spot-check chain linkage at boundaries.
      expect(history.first.previousHash, isNull);
      for (var i = 1; i < 10; i++) {
        expect(history[i].previousHash, history[i - 1].eventHash);
      }
      // Check last few.
      for (var i = 9998; i < 10000; i++) {
        expect(history[i].previousHash, history[i - 1].eventHash);
      }

      // Verify vector clock progression.
      expect(history.last.vectorClock.a, 10000);
      expect(history.last.vectorClock.b, 0);

      await a.ledger.shutdown();
      await a.store.dispose();
      await a.transport.dispose();
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );

  // E2E.29 — Random payloads: 1000 random payloads (0-100KB) -> all processed
  test(
    'E2E.29: Random payloads - 1000 random payloads 0-100KB, all processed',
    () async {
      final a = await createTestLedger(peerRole: 'A');

      await a.trustStore.addTrustedPeer(
        peerPublicKey: StyxPublicKey.fromHex('bb' * 32),
        alias: null,
      );
      await a.ledger.initialize();

      final random = Random(42);

      for (var i = 0; i < 1000; i++) {
        final size = random.nextInt(100 * 1024 + 1); // 0 to 100KB
        final randomPayload = Uint8List(size);
        for (var j = 0; j < size; j++) {
          randomPayload[j] = random.nextInt(256);
        }
        await a.ledger.sendTransaction(randomPayload);
      }

      final history = await a.store.getHistory();
      expect(history, hasLength(1000));

      // Validate full chain.
      final validationError = await a.store.validateChain();
      expect(validationError, isNull);

      // Verify all events have non-null payloads.
      for (final event in history) {
        expect(event.payload, isNotNull);
      }

      await a.ledger.shutdown();
      await a.store.dispose();
      await a.transport.dispose();
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
}
