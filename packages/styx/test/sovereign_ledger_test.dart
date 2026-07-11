import 'dart:async';
import 'dart:typed_data';

import 'package:styx/styx.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/styx_ledger_engine.dart';
import 'package:styx_push_bridge_client/styx_push_bridge_client.dart';
import 'package:styx_transport/styx_transport.dart';
import 'package:test/test.dart';

// ---------------------------------------------------------------------------
// Fake LedgerStore
// ---------------------------------------------------------------------------

class FakeLedgerStore implements LedgerStore {
  FakeLedgerStore({
    this.events = const [],
    this.chainError,
  });

  List<LedgerEvent> events;
  ChainValidationError? chainError;
  final appendedEvents = <LedgerEvent>[];
  final newEventController = StreamController<LedgerEvent>.broadcast();

  @override
  Future<LedgerEvent> appendEvent({
    required EventType type,
    required Uint8List payload,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
  }) async {
    final signer = Signer();
    final hasher = Hasher();
    final factory = EventFactory(signer: signer, hasher: hasher);
    final previous = events.isEmpty ? null : events.last;
    final vc = previous?.vectorClock ?? const VectorClock.zero();

    final event = await factory.createEvent(
      type: type,
      payload: payload,
      privateKey: privateKey,
      publicKey: publicKey,
      previousEvent: previous,
      currentVectorClock: vc,
      localPeerRole: 'A',
    );

    events = [...events, event];
    appendedEvents.add(event);
    newEventController.add(event);
    return event;
  }

  @override
  Future<List<LedgerEvent>> getHistory() async => events;

  @override
  Future<ChainValidationError?> validateChain() async => chainError;

  @override
  Future<LedgerEvent?> getLatestEvent() async =>
      events.isEmpty ? null : events.last;

  @override
  Stream<LedgerEvent> watchNewEvents() => newEventController.stream;
}

// ---------------------------------------------------------------------------
// Fake TransportInterface
// ---------------------------------------------------------------------------

class FakeTransport implements TransportInterface {
  bool connected = false;
  bool disconnected = false;
  final messageController = StreamController<TransportMessage>.broadcast();
  final stateController = StreamController<TransportState>.broadcast();

  @override
  Future<void> connect() async {
    connected = true;
  }

  @override
  Future<void> disconnect() async {
    disconnected = true;
    connected = false;
  }

  @override
  bool get isAvailable => connected;

  @override
  TransportState get currentState =>
      connected ? TransportState.connected : TransportState.disconnected;

  @override
  Stream<TransportMessage> get messages => messageController.stream;

  @override
  Future<void> send(TransportMessage message) async {}

  @override
  Stream<TransportState> get stateChanges => stateController.stream;
}

// ---------------------------------------------------------------------------
// Fake PushBridgeRegistrar
// ---------------------------------------------------------------------------

class FakePushBridge implements PushBridgeRegistrar {
  final registerCalls = <Map<String, dynamic>>[];
  final unregisterCalls = <String>[];

  @override
  Future<void> register({
    required String pushBridgeUrl,
    required String token,
    required String pubkey,
    required PrivacyProfile profile,
    required List<String> relayUrls,
  }) async {
    registerCalls.add({
      'pushBridgeUrl': pushBridgeUrl,
      'token': token,
      'pubkey': pubkey,
      'profile': profile,
      'relayUrls': relayUrls,
    });
  }

  @override
  Future<void> unregister({required String token}) async {
    unregisterCalls.add(token);
  }
}

// ---------------------------------------------------------------------------
// Helper to build a SovereignLedger with all dependencies
// ---------------------------------------------------------------------------

Future<StyxKeyPair> makeKeyPair() => IdentityManager().generate();

StyxIdentity makeIdentity(StyxKeyPair keyPair) {
  return StyxIdentity(
    publicKey: keyPair.publicKey,
    nodeId: keyPair.publicKey.toHex().substring(0, 8),
    peerRole: 'A',
  );
}

({
  SovereignLedger ledger,
  FakeLedgerStore store,
  FakeTransport transport,
  FakePushBridge pushBridge,
  InMemoryPeerStore peerStore,
  TrustStoreManager trustStore,
  LedgerEventStream? eventStream,
})
buildLedger({
  required StyxKeyPair keyPair,
  FakeLedgerStore? store,
  FakeTransport? transport,
  FakePushBridge? pushBridge,
  InMemoryPeerStore? peerStore,
  LedgerConfig? config,
  LedgerEventStream? eventStream,
}) {
  final identity = makeIdentity(keyPair);
  final ledgerStore = store ?? FakeLedgerStore();
  final fakeTransport = transport ?? FakeTransport();
  final fakePushBridge = pushBridge ?? FakePushBridge();
  final fakePeerStore = peerStore ?? InMemoryPeerStore();
  final trustStore = TrustStoreManager(peerStore: fakePeerStore);

  final signer = Signer();
  final hasher = Hasher();
  final verifier = Verifier();
  final eventFactory = EventFactory(signer: signer, hasher: hasher);

  final qrPairing = QrPairingService(trustStore: trustStore);
  final remotePairing = RemotePairingService(
    spake2Protocol: Spake2Protocol(),
    mnemonicGenerator: MnemonicGenerator(),
    doubleCheckVerifier: DoubleCheckVerifier(
      sessionVerifier: SessionVerifier(),
    ),
    trustStore: trustStore,
  );
  final reKeyProtocol = ReKeyProtocol(
    eventFactory: eventFactory,
    trustStoreManager: trustStore,
    verifier: verifier,
  );
  final keyBackup = KeyBackup(
    splitter: ShamirSplitter(),
    reconstructor: ShamirReconstructor(),
  );
  final migrationService = KeyMigrationService(
    identityManager: IdentityManager(),
    reKeyProtocol: reKeyProtocol,
    keyBackup: keyBackup,
  );
  final backupService = ShamirBackupService(
    keyBackup: keyBackup,
    secureKeyStore: InMemoryKeyStore(),
  );
  final retentionManager = RetentionManager();
  final pruneProtocol = PruneProtocol(eventFactory: eventFactory);

  final ledgerConfig =
      config ??
      const LedgerConfig(
        relayUrls: ['wss://relay.example.com'],
      );

  final ledger = SovereignLedger(
    identity: identity,
    config: ledgerConfig,
    ledgerStore: ledgerStore,
    transport: fakeTransport,
    trustStore: trustStore,
    qrPairing: qrPairing,
    remotePairing: remotePairing,
    reKeyProtocol: reKeyProtocol,
    migrationService: migrationService,
    backupService: backupService,
    retentionManager: retentionManager,
    pruneProtocol: pruneProtocol,
    keyPair: keyPair,
    pushBridge: fakePushBridge,
    eventStream: eventStream,
  );

  return (
    ledger: ledger,
    store: ledgerStore,
    transport: fakeTransport,
    pushBridge: fakePushBridge,
    peerStore: fakePeerStore,
    trustStore: trustStore,
    eventStream: eventStream,
  );
}

Future<LedgerEvent> makeEvent({
  required StyxKeyPair keyPair,
  LedgerEvent? previous,
  VectorClock vc = const VectorClock.zero(),
  EventType type = EventType.transaction,
  Uint8List? payload,
}) async {
  final signer = Signer();
  final hasher = Hasher();
  final factory = EventFactory(signer: signer, hasher: hasher);
  return factory.createEvent(
    type: type,
    payload: payload ?? Uint8List.fromList([1, 2, 3]),
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    previousEvent: previous,
    currentVectorClock: vc,
    localPeerRole: 'A',
  );
}

void main() {
  group('SovereignLedger facade', () {
    // T12.1: Init with minimal config — only relayUrls.
    //        State -> unpaired.
    test(
      'T12.1: initialize with minimal config sets state to unpaired',
      () async {
        final keyPair = await makeKeyPair();
        final result = buildLedger(keyPair: keyPair);

        await result.ledger.initialize();

        expect(result.ledger.state, equals(StyxState.unpaired));
      },
    );

    // T12.2: Init with existing keypair — identity loaded, not generated.
    test(
      'T12.2: initialize with existing keypair loads that identity',
      () async {
        final existingKeyPair = await makeKeyPair();
        final result = buildLedger(keyPair: existingKeyPair);

        expect(
          result.ledger.identity.publicKey,
          equals(existingKeyPair.publicKey),
        );

        await result.ledger.initialize();

        expect(result.ledger.state, equals(StyxState.unpaired));
        expect(
          result.ledger.identity.publicKey,
          equals(existingKeyPair.publicKey),
        );
      },
    );

    // T12.3: Init + chain validation — DB with valid events.
    //        State -> ready (if paired) or unpaired.
    test(
      'T12.3: initialize with valid chain and paired peer sets state to ready',
      () async {
        final keyPair = await makeKeyPair();
        final peerKeyPair = await makeKeyPair();
        final peerStore = InMemoryPeerStore();

        // Pre-add a trusted peer.
        await peerStore.addPeer(
          pubkey: peerKeyPair.publicKey.toHex(),
          alias: 'peer',
          pairedAt: DateTime.now().toUtc(),
        );

        final event = await makeEvent(keyPair: keyPair);
        final store = FakeLedgerStore(events: [event]);
        final result = buildLedger(
          keyPair: keyPair,
          store: store,
          peerStore: peerStore,
        );

        await result.ledger.initialize();

        expect(result.ledger.state, equals(StyxState.ready));
        expect(result.transport.connected, isTrue);
      },
    );

    // T12.4: Init with corrupted DB — broken hash chain.
    //        State -> error.
    test(
      'T12.4: initialize with corrupted DB sets state to error',
      () async {
        final keyPair = await makeKeyPair();
        final store = FakeLedgerStore(
          chainError: const ChainValidationError(
            eventId: 'evt-corrupted',
            errorType: ChainErrorType.hashMismatch,
            message: 'Computed hash does not match eventHash',
          ),
        );
        final result = buildLedger(
          keyPair: keyPair,
          store: store,
        );

        await result.ledger.initialize();

        expect(result.ledger.state, equals(StyxState.error));
      },
    );

    // T12.5: Shutdown — active Styx.
    //        State -> shuttingDown, resources released.
    test(
      'T12.5: shutdown sets state to shuttingDown and disconnects transport',
      () async {
        final keyPair = await makeKeyPair();
        final result = buildLedger(keyPair: keyPair);
        await result.ledger.initialize();

        await result.ledger.shutdown();

        expect(result.ledger.state, equals(StyxState.shuttingDown));
        expect(result.transport.disconnected, isTrue);
      },
    );

    // T12.6: SendTransaction without peer — unpaired.
    //        StateError exception.
    test(
      'T12.6: sendTransaction when unpaired throws StateError',
      () async {
        final keyPair = await makeKeyPair();
        final result = buildLedger(keyPair: keyPair);
        await result.ledger.initialize();

        expect(result.ledger.state, equals(StyxState.unpaired));
        expect(
          () => result.ledger.sendTransaction(
            Uint8List.fromList([1, 2, 3]),
          ),
          throwsA(isA<StateError>()),
        );
      },
    );

    // T12.7: SendTransaction with peer — paired.
    //        Event created.
    test(
      'T12.7: sendTransaction when paired creates an event',
      () async {
        final keyPair = await makeKeyPair();
        final peerKeyPair = await makeKeyPair();
        final peerStore = InMemoryPeerStore();
        await peerStore.addPeer(
          pubkey: peerKeyPair.publicKey.toHex(),
          alias: 'peer',
          pairedAt: DateTime.now().toUtc(),
        );

        final result = buildLedger(
          keyPair: keyPair,
          peerStore: peerStore,
        );
        await result.ledger.initialize();
        expect(result.ledger.state, equals(StyxState.ready));

        final payload = Uint8List.fromList([10, 20, 30]);
        final event = await result.ledger.sendTransaction(payload);

        expect(event.eventType, equals(EventType.transaction));
        expect(event.senderPubkey, equals(keyPair.publicKey.toHex()));
        expect(result.store.appendedEvents, hasLength(1));
      },
    );

    // T12.8: GetHistory empty — no events.
    //        Empty list.
    test(
      'T12.8: getHistory returns empty list when no events exist',
      () async {
        final keyPair = await makeKeyPair();
        final result = buildLedger(keyPair: keyPair);
        await result.ledger.initialize();

        final history = await result.ledger.getHistory();

        expect(history, isEmpty);
      },
    );

    // T12.9: GetHistory with events — 10 events.
    //        10 events ordered by HLC.
    test(
      'T12.9: getHistory returns 10 events ordered by HLC',
      () async {
        final keyPair = await makeKeyPair();
        final events = <LedgerEvent>[];
        LedgerEvent? previous;
        var vc = const VectorClock.zero();

        for (var i = 0; i < 10; i++) {
          final event = await makeEvent(
            keyPair: keyPair,
            previous: previous,
            vc: vc,
          );
          events.add(event);
          previous = event;
          vc = event.vectorClock;
        }

        final store = FakeLedgerStore(events: events);
        final result = buildLedger(
          keyPair: keyPair,
          store: store,
        );
        await result.ledger.initialize();

        final history = await result.ledger.getHistory();

        expect(history, hasLength(10));

        // Verify HLC ordering is non-decreasing.
        for (var i = 1; i < history.length; i++) {
          expect(
            history[i].hlc.compareTo(history[i - 1].hlc),
            greaterThan(0),
            reason: 'Event $i should have HLC after event ${i - 1}',
          );
        }
      },
    );

    // T12.10: EventStream — 5 events inserted.
    //         Stream emits 5 events.
    test(
      'T12.10: eventStream emits 5 events when 5 events are inserted',
      () async {
        final keyPair = await makeKeyPair();
        final peerKeyPair = await makeKeyPair();
        final peerStore = InMemoryPeerStore();
        await peerStore.addPeer(
          pubkey: peerKeyPair.publicKey.toHex(),
          alias: 'peer',
          pairedAt: DateTime.now().toUtc(),
        );

        final localController = StreamController<LedgerEvent>.broadcast();
        final remoteController = StreamController<LedgerEvent>.broadcast();
        final eventStreamObj = LedgerEventStream(
          localEventSource: localController.stream,
          remoteEventSource: remoteController.stream,
        );

        final result = buildLedger(
          keyPair: keyPair,
          peerStore: peerStore,
          eventStream: eventStreamObj,
        );
        await result.ledger.initialize();

        final collectedEvents = <LedgerEvent>[];
        final subscription = result.ledger.eventStream.listen(
          collectedEvents.add,
        );

        // Create and emit 5 events via the local source.
        LedgerEvent? previous;
        var vc = const VectorClock.zero();
        for (var i = 0; i < 5; i++) {
          final event = await makeEvent(
            keyPair: keyPair,
            previous: previous,
            vc: vc,
          );
          previous = event;
          vc = event.vectorClock;
          localController.add(event);
        }

        // Allow the stream to deliver events.
        await Future<void>.delayed(const Duration(milliseconds: 50));

        expect(collectedEvents, hasLength(5));

        await subscription.cancel();
        await localController.close();
        await remoteController.close();
        await eventStreamObj.dispose();
      },
    );

    // T12.11: SetPrivacyProfile — change to Paranoid.
    //         Profile updated.
    test(
      'T12.11: setPrivacyProfile updates the profile to paranoid',
      () async {
        final keyPair = await makeKeyPair();
        final result = buildLedger(
          keyPair: keyPair,
          config: const LedgerConfig(
            relayUrls: ['wss://relay.example.com'],
            pushBridgeUrl: 'https://push.example.com',
          ),
        );
        await result.ledger.initialize();

        expect(
          result.ledger.privacyProfile,
          equals(PrivacyProfile.balanced),
        );

        await result.ledger.setPrivacyProfile(PrivacyProfile.paranoid);

        expect(
          result.ledger.privacyProfile,
          equals(PrivacyProfile.paranoid),
        );

        // Verify push bridge was re-registered.
        expect(result.pushBridge.registerCalls, hasLength(1));
        expect(
          result.pushBridge.registerCalls.first['profile'],
          equals(PrivacyProfile.paranoid),
        );
      },
    );

    // T12.12: SetRetentionPolicy — 30 days, only TRANSACTION.
    //         Config saved.
    test(
      'T12.12: setRetentionPolicy saves the retention configuration',
      () async {
        final keyPair = await makeKeyPair();
        final result = buildLedger(keyPair: keyPair);
        await result.ledger.initialize();

        await result.ledger.setRetentionPolicy(
          retentionPeriod: const Duration(days: 30),
          applicableTypes: [EventType.transaction],
        );

        // Verify by checking getExpiredEvents with old events.
        final oldEvent = await makeEvent(keyPair: keyPair);
        // The event was just created so it should NOT be expired
        // with a 30-day policy.
        final expired = result.ledger.getExpiredEvents([oldEvent]);
        expect(expired, isEmpty);
      },
    );

    // T12.13: CreateIdentityBackup — threshold=2, total=3.
    //         3 serialized shares.
    test(
      'T12.13: createIdentityBackup produces 3 serialized shares',
      () async {
        final keyPair = await makeKeyPair();
        final result = buildLedger(keyPair: keyPair);

        final shares = result.ledger.createIdentityBackup();

        expect(shares, hasLength(3));
        for (final share in shares) {
          expect(share, startsWith('styx-share-v1:'));
        }
      },
    );

    // T12.14: RestoreIdentity — 2 valid shares.
    //         Keypair reconstructed.
    test(
      'T12.14: restoreIdentity from 2 valid shares reconstructs keypair',
      () async {
        final keyPair = await makeKeyPair();
        final result = buildLedger(keyPair: keyPair);

        final shares = result.ledger.createIdentityBackup();

        // Restore using only 2 of 3 shares.
        final restoredKeyPair = await SovereignLedger.restoreIdentity(
          shares.sublist(0, 2),
        );

        expect(
          restoredKeyPair.publicKey,
          equals(keyPair.publicKey),
        );
        expect(
          restoredKeyPair.privateKey.bytes,
          equals(keyPair.privateKey.bytes),
        );
      },
    );

    // T12.15: State stream — Init -> pair -> ready.
    //         States emitted in correct order.
    test(
      'T12.15: state stream emits states in correct order during init',
      () async {
        final keyPair = await makeKeyPair();
        final peerKeyPair = await makeKeyPair();
        final peerStore = InMemoryPeerStore();
        await peerStore.addPeer(
          pubkey: peerKeyPair.publicKey.toHex(),
          alias: 'peer',
          pairedAt: DateTime.now().toUtc(),
        );

        final result = buildLedger(
          keyPair: keyPair,
          peerStore: peerStore,
        );

        final states = <StyxState>[];
        final subscription = result.ledger.stateStream.listen(states.add);

        expect(result.ledger.state, equals(StyxState.uninitialized));

        await result.ledger.initialize();

        // Allow all events to propagate.
        await Future<void>.delayed(const Duration(milliseconds: 50));

        // Expect: initializing -> ready (because peer is present).
        expect(states, contains(StyxState.initializing));
        expect(states, contains(StyxState.ready));
        expect(
          states.indexOf(StyxState.initializing),
          lessThan(states.indexOf(StyxState.ready)),
        );

        await subscription.cancel();
        await result.ledger.shutdown();
      },
    );
  });
}
