import 'dart:convert';
import 'dart:typed_data';

import 'package:styx/styx.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/styx_ledger_engine.dart';
import 'package:test/test.dart';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

final _signer = Signer();
final _hasher = Hasher();
final _verifier = Verifier();
final _identityManager = IdentityManager();

Future<LedgerEvent> _createEvent({
  required EventFactory factory,
  required EventType type,
  required Uint8List payload,
  required StyxKeyPair keyPair,
  required LedgerEvent? previous,
  required VectorClock vc,
  required String role,
}) async {
  return factory.createEvent(
    type: type,
    payload: payload,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    previousEvent: previous,
    currentVectorClock: vc,
    localPeerRole: role,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  // T11.37 — Full QR pairing → 10 events → validate
  test(
    'T11.37: QR pairing then 10 events validate on both',
    () async {
      // Setup two peers.
      final peerA = await _identityManager.generate();
      final peerB = await _identityManager.generate();

      final storeA = InMemoryPeerStore();
      final storeB = InMemoryPeerStore();
      final trustA = TrustStoreManager(peerStore: storeA);
      final trustB = TrustStoreManager(peerStore: storeB);

      // QR pairing: A shows QR, B scans it.
      final qrServiceA = QrPairingService(trustStore: trustA);
      final qrServiceB = QrPairingService(trustStore: trustB);

      final qrData = qrServiceA.generateQrData(
        localPublicKey: peerA.publicKey,
        relayHints: ['wss://relay.example.com'],
      );

      final resultB = qrServiceB.processScannedQr(
        qrPayload: qrData.toQrPayload(),
        localPublicKey: peerB.publicKey,
      );
      expect(resultB.isValid, isTrue);

      // B completes pairing with A.
      await qrServiceB.completePairing(
        peerPublicKey: resultB.peerPublicKey,
        peerAlias: 'Peer A',
      );

      // A also needs B's key — simulate B showing QR to A.
      final qrDataB = qrServiceB.generateQrData(
        localPublicKey: peerB.publicKey,
      );
      final resultA = qrServiceA.processScannedQr(
        qrPayload: qrDataB.toQrPayload(),
        localPublicKey: peerA.publicKey,
      );
      expect(resultA.isValid, isTrue);

      await qrServiceA.completePairing(
        peerPublicKey: resultA.peerPublicKey,
        peerAlias: 'Peer B',
      );

      // Verify both trust each other.
      expect(await trustA.isTrusted(peerB.publicKey), isTrue);
      expect(await trustB.isTrusted(peerA.publicKey), isTrue);

      // Create 10 events (5 from A, 5 from B).
      final eventFactory = EventFactory(signer: _signer, hasher: _hasher);
      final events = <LedgerEvent>[];
      var vc = const VectorClock.zero();

      for (var i = 0; i < 10; i++) {
        final isA = i.isEven;
        final kp = isA ? peerA : peerB;
        final role = isA ? 'A' : 'B';

        final event = await _createEvent(
          factory: eventFactory,
          type: EventType.message,
          payload: Uint8List.fromList(
            utf8.encode('event-$i'),
          ),
          keyPair: kp,
          previous: events.isEmpty ? null : events.last,
          vc: vc,
          role: role,
        );
        events.add(event);
        vc = event.vectorClock;
      }

      expect(events, hasLength(10));

      // Validate chain: each event's previousHash matches
      // the prior event's hash.
      for (var i = 1; i < events.length; i++) {
        expect(
          events[i].previousHash,
          events[i - 1].eventHash,
        );
      }

      // Validate all signatures.
      for (final event in events) {
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
    },
  );

  // T11.38 — Full remote pairing → 10 events → validate
  test(
    'T11.38: remote SPAKE2 pairing then 10 events validate',
    () async {
      final peerA = await _identityManager.generate();
      final peerB = await _identityManager.generate();

      final storeA = InMemoryPeerStore();
      final storeB = InMemoryPeerStore();
      final trustA = TrustStoreManager(peerStore: storeA);
      final trustB = TrustStoreManager(peerStore: storeB);

      final spake2 = Spake2Protocol();
      final mnemonicGen = MnemonicGenerator();
      final sessionVerifier = SessionVerifier();
      final dcvA = DoubleCheckVerifier(
        sessionVerifier: sessionVerifier,
      );
      final dcvB = DoubleCheckVerifier(
        sessionVerifier: sessionVerifier,
      );

      final serviceA = RemotePairingService(
        spake2Protocol: spake2,
        mnemonicGenerator: mnemonicGen,
        doubleCheckVerifier: dcvA,
        trustStore: trustA,
      );
      final serviceB = RemotePairingService(
        spake2Protocol: spake2,
        mnemonicGenerator: mnemonicGen,
        doubleCheckVerifier: dcvB,
        trustStore: trustB,
      );

      // Step 1: A generates mnemonic, communicates to B.
      final mnemonic = serviceA.generateMnemonic();

      // Step 2: Exchange SPAKE2 messages.
      final msgA = await serviceA.startAsInitiator(
        mnemonic: mnemonic,
        localPublicKey: peerA.publicKey,
      );
      final msgB = await serviceB.startAsResponder(
        mnemonic: mnemonic,
        localPublicKey: peerB.publicKey,
      );

      expect(serviceA.processPeerMessage(msgB), isTrue);
      expect(serviceB.processPeerMessage(msgA), isTrue);

      // Step 3: Verify Double Check codes match.
      final codeA = serviceA.getDoubleCheckCode();
      final codeB = serviceB.getDoubleCheckCode();
      expect(codeA, codeB);

      // Step 4: Exchange pubkeys and confirm.
      serviceA.peerPublicKey = peerB.publicKey;
      serviceB.peerPublicKey = peerA.publicKey;

      await serviceA.confirmDoubleCheck(
        codeMatches: true,
        peerAlias: 'Peer B',
      );
      await serviceB.confirmDoubleCheck(
        codeMatches: true,
        peerAlias: 'Peer A',
      );

      expect(
        serviceA.state,
        RemotePairingState.completed,
      );
      expect(
        serviceB.state,
        RemotePairingState.completed,
      );
      expect(await trustA.isTrusted(peerB.publicKey), isTrue);
      expect(await trustB.isTrusted(peerA.publicKey), isTrue);

      // Create 10 events and validate.
      final eventFactory = EventFactory(signer: _signer, hasher: _hasher);
      final events = <LedgerEvent>[];
      var vc = const VectorClock.zero();

      for (var i = 0; i < 10; i++) {
        final isA = i.isEven;
        final kp = isA ? peerA : peerB;
        final role = isA ? 'A' : 'B';

        final event = await _createEvent(
          factory: eventFactory,
          type: EventType.message,
          payload: Uint8List.fromList(
            utf8.encode('event-$i'),
          ),
          keyPair: kp,
          previous: events.isEmpty ? null : events.last,
          vc: vc,
          role: role,
        );
        events.add(event);
        vc = event.vectorClock;
      }

      expect(events, hasLength(10));

      for (var i = 1; i < events.length; i++) {
        expect(
          events[i].previousHash,
          events[i - 1].eventHash,
        );
      }

      await serviceA.dispose();
      await serviceB.dispose();
    },
  );

  // T11.39 — Pairing → 10 events → re-key → 10 events → validate
  test(
    'T11.39: pairing, 10 events, re-key, 10 more events',
    () async {
      final peerA = await _identityManager.generate();
      final peerB = await _identityManager.generate();

      final storeA = InMemoryPeerStore();
      final storeB = InMemoryPeerStore();
      final trustA = TrustStoreManager(peerStore: storeA);
      final trustB = TrustStoreManager(peerStore: storeB);

      // QR pairing (simplified).
      await trustA.addTrustedPeer(
        peerPublicKey: peerB.publicKey,
        alias: 'Peer B',
      );
      await trustB.addTrustedPeer(
        peerPublicKey: peerA.publicKey,
        alias: 'Peer A',
      );

      final eventFactory = EventFactory(signer: _signer, hasher: _hasher);
      final events = <LedgerEvent>[];
      var vc = const VectorClock.zero();

      // First 10 events.
      for (var i = 0; i < 10; i++) {
        final isA = i.isEven;
        final kp = isA ? peerA : peerB;
        final role = isA ? 'A' : 'B';

        final event = await _createEvent(
          factory: eventFactory,
          type: EventType.message,
          payload: Uint8List.fromList(
            utf8.encode('pre-rekey-$i'),
          ),
          keyPair: kp,
          previous: events.isEmpty ? null : events.last,
          vc: vc,
          role: role,
        );
        events.add(event);
        vc = event.vectorClock;
      }

      // A re-keys to a new device.
      final newPeerA = await _identityManager.generate();
      final rekeyProtocol = ReKeyProtocol(
        eventFactory: eventFactory,
        trustStoreManager: trustB,
        verifier: _verifier,
      );

      // Create blessing event (old A signs new A's key).
      final blessingEvent = await rekeyProtocol.createBlessingEvent(
        oldPrivateKey: peerA.privateKey,
        oldPublicKey: peerA.publicKey,
        newPublicKey: newPeerA.publicKey,
        previousEvent: events.last,
        currentVectorClock: vc,
        localPeerRole: 'A',
      );
      events.add(blessingEvent);
      vc = blessingEvent.vectorClock;

      // B processes the REKEY event.
      final result = await rekeyProtocol.processReKeyEvent(
        rekeyEvent: blessingEvent,
      );
      expect(result.success, isTrue);
      expect(
        await trustB.isTrusted(newPeerA.publicKey),
        isTrue,
      );
      expect(
        await trustB.isTrusted(peerA.publicKey),
        isFalse,
      );

      // 10 more events using new A key.
      for (var i = 0; i < 10; i++) {
        final isA = i.isEven;
        final kp = isA ? newPeerA : peerB;
        final role = isA ? 'A' : 'B';

        final event = await _createEvent(
          factory: eventFactory,
          type: EventType.message,
          payload: Uint8List.fromList(
            utf8.encode('post-rekey-$i'),
          ),
          keyPair: kp,
          previous: events.last,
          vc: vc,
          role: role,
        );
        events.add(event);
        vc = event.vectorClock;
      }

      // Total: 10 + 1 REKEY + 10 = 21 events.
      expect(events, hasLength(21));

      // Validate chain.
      for (var i = 1; i < events.length; i++) {
        expect(
          events[i].previousHash,
          events[i - 1].eventHash,
        );
      }

      // Verify REKEY event is at index 10.
      expect(
        events[10].eventType,
        EventType.rekey,
      );
    },
  );

  // T11.40 — Backup → delete identity → restore → resume
  test(
    'T11.40: Shamir backup, delete, restore, resume chain',
    () async {
      final originalKP = await _identityManager.generate();

      // Create Shamir backup (2-of-3).
      final keyBackup = KeyBackup(
        splitter: ShamirSplitter(),
        reconstructor: ShamirReconstructor(),
      );
      final shares = keyBackup.backupPrivateKey(
        privateKey: originalKP.privateKey,
      );
      final serialized = shares.map((s) => s.serialize()).toList();
      expect(serialized, hasLength(3));

      // Build a short chain with the original key.
      final eventFactory = EventFactory(signer: _signer, hasher: _hasher);
      final events = <LedgerEvent>[];
      var vc = const VectorClock.zero();

      for (var i = 0; i < 5; i++) {
        final event = await _createEvent(
          factory: eventFactory,
          type: EventType.message,
          payload: Uint8List.fromList(
            utf8.encode('before-restore-$i'),
          ),
          keyPair: originalKP,
          previous: events.isEmpty ? null : events.last,
          vc: vc,
          role: 'A',
        );
        events.add(event);
        vc = event.vectorClock;
      }

      // Simulate key loss — destroy private key.
      originalKP.privateKey.destroy();

      // Restore from 2 of 3 shares.
      final restoredShares = [
        ShamirShare.deserialize(serialized[0]),
        ShamirShare.deserialize(serialized[2]),
      ];
      final restoredKP = await keyBackup.restoreFromShares(restoredShares);

      // Verify restored key matches original public key.
      expect(
        restoredKP.publicKey.toHex(),
        originalKP.publicKey.toHex(),
      );

      // Continue the chain with restored key.
      for (var i = 0; i < 5; i++) {
        final event = await _createEvent(
          factory: eventFactory,
          type: EventType.message,
          payload: Uint8List.fromList(
            utf8.encode('after-restore-$i'),
          ),
          keyPair: restoredKP,
          previous: events.last,
          vc: vc,
          role: 'A',
        );
        events.add(event);
        vc = event.vectorClock;
      }

      expect(events, hasLength(10));

      // Validate full chain.
      for (var i = 1; i < events.length; i++) {
        expect(
          events[i].previousHash,
          events[i - 1].eventHash,
        );
      }

      // All events signed by same pubkey.
      for (final event in events) {
        expect(
          event.senderPubkey,
          originalKP.publicKey.toHex(),
        );
      }
    },
  );
}
