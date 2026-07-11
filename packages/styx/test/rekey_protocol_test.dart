import 'dart:convert';
import 'dart:typed_data';

import 'package:styx/styx.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/styx_ledger_engine.dart';
import 'package:test/test.dart';

void main() {
  late InMemoryPeerStore peerStore;
  late TrustStoreManager trustStore;
  late Signer signer;
  late Hasher hasher;
  late Verifier verifier;
  late EventFactory eventFactory;
  late ReKeyProtocol protocol;
  late IdentityManager identityManager;

  setUp(() {
    peerStore = InMemoryPeerStore();
    trustStore = TrustStoreManager(peerStore: peerStore);
    signer = Signer();
    hasher = Hasher();
    verifier = Verifier();
    eventFactory = EventFactory(
      signer: signer,
      hasher: hasher,
    );
    protocol = ReKeyProtocol(
      eventFactory: eventFactory,
      trustStoreManager: trustStore,
      verifier: verifier,
    );
    identityManager = IdentityManager();
  });

  group('ReKeyProtocol', () {
    // T11.23: CreateBlessingEvent -> REKEY event with correct
    //         payload, signed with old key.
    test(
      'T11.23: createBlessingEvent produces REKEY event '
      'with correct payload',
      () async {
        final oldKp = await identityManager.generate();
        final newKp = await identityManager.generate();

        final event = await protocol.createBlessingEvent(
          oldPrivateKey: oldKp.privateKey,
          oldPublicKey: oldKp.publicKey,
          newPublicKey: newKp.publicKey,
          previousEvent: null,
          currentVectorClock: const VectorClock.zero(),
          localPeerRole: 'A',
        );

        expect(event.eventType, equals(EventType.rekey));
        expect(
          event.senderPubkey,
          equals(oldKp.publicKey.toHex()),
        );

        // Parse payload JSON to verify old_key and new_key.
        final payloadJson =
            jsonDecode(
                  utf8.decode(event.payload!),
                )
                as Map<String, dynamic>;

        expect(
          payloadJson['old_key'],
          equals(oldKp.publicKey.toHex()),
        );
        expect(
          payloadJson['new_key'],
          equals(newKp.publicKey.toHex()),
        );

        // Verify the signature is valid.
        final hashBytes = eventFactory.computeHashBytes(
          previousHash: event.previousHash,
          eventType: event.eventType,
          payload: event.payload,
          hlcBytes: event.hlc.toBytes(),
        );
        final sigValid = await verifier.verify(
          payload: hashBytes,
          signatureBytes: event.signature,
          publicKey: oldKp.publicKey,
        );
        expect(sigValid, isTrue);
      },
    );

    // T11.24: ProcessReKeyEvent valid -> trust store updated,
    //         success==true.
    test(
      'T11.24: processReKeyEvent succeeds for valid '
      'blessing event',
      () async {
        final oldKp = await identityManager.generate();
        final newKp = await identityManager.generate();

        // Add old key as trusted.
        await trustStore.addTrustedPeer(
          peerPublicKey: oldKp.publicKey,
          alias: 'OldDevice',
        );

        final event = await protocol.createBlessingEvent(
          oldPrivateKey: oldKp.privateKey,
          oldPublicKey: oldKp.publicKey,
          newPublicKey: newKp.publicKey,
          previousEvent: null,
          currentVectorClock: const VectorClock.zero(),
          localPeerRole: 'A',
        );

        final result = await protocol.processReKeyEvent(
          rekeyEvent: event,
        );

        expect(result.success, isTrue);
        expect(result.oldKey, equals(oldKp.publicKey));
        expect(result.newKey, equals(newKp.publicKey));
        expect(result.errorMessage, isNull);
      },
    );

    // T11.25: ProcessReKeyEvent invalid signature ->
    //         success==false, trust store unchanged.
    test(
      'T11.25: processReKeyEvent fails with tampered '
      'signature',
      () async {
        final oldKp = await identityManager.generate();
        final newKp = await identityManager.generate();

        await trustStore.addTrustedPeer(
          peerPublicKey: oldKp.publicKey,
          alias: 'OldDevice',
        );

        final event = await protocol.createBlessingEvent(
          oldPrivateKey: oldKp.privateKey,
          oldPublicKey: oldKp.publicKey,
          newPublicKey: newKp.publicKey,
          previousEvent: null,
          currentVectorClock: const VectorClock.zero(),
          localPeerRole: 'A',
        );

        // Tamper with the signature.
        final tamperedSig = Uint8List.fromList(
          event.signature,
        );
        tamperedSig[0] = (tamperedSig[0] + 1) % 256;

        final tamperedEvent = LedgerEvent(
          eventId: event.eventId,
          eventType: event.eventType,
          payload: event.payload,
          previousHash: event.previousHash,
          eventHash: event.eventHash,
          hlc: event.hlc,
          vectorClock: event.vectorClock,
          senderPubkey: event.senderPubkey,
          signature: tamperedSig,
          createdAt: event.createdAt,
        );

        final result = await protocol.processReKeyEvent(
          rekeyEvent: tamperedEvent,
        );

        expect(result.success, isFalse);
        expect(
          result.errorMessage,
          contains('Invalid signature'),
        );

        // Trust store unchanged: old key still trusted.
        expect(
          await trustStore.isTrusted(oldKp.publicKey),
          isTrue,
        );
      },
    );

    // T11.26: ProcessReKeyEvent untrusted key ->
    //         success==false.
    test(
      'T11.26: processReKeyEvent fails for untrusted '
      'sender key',
      () async {
        final oldKp = await identityManager.generate();
        final newKp = await identityManager.generate();

        // Do NOT add old key as trusted.
        final event = await protocol.createBlessingEvent(
          oldPrivateKey: oldKp.privateKey,
          oldPublicKey: oldKp.publicKey,
          newPublicKey: newKp.publicKey,
          previousEvent: null,
          currentVectorClock: const VectorClock.zero(),
          localPeerRole: 'A',
        );

        final result = await protocol.processReKeyEvent(
          rekeyEvent: event,
        );

        expect(result.success, isFalse);
        expect(
          result.errorMessage,
          contains('not trusted'),
        );
      },
    );

    // T11.27: Post-rekey events with new key accepted.
    test(
      'T11.27: after processReKeyEvent, new key is trusted',
      () async {
        final oldKp = await identityManager.generate();
        final newKp = await identityManager.generate();

        await trustStore.addTrustedPeer(
          peerPublicKey: oldKp.publicKey,
          alias: 'OldDevice',
        );

        final event = await protocol.createBlessingEvent(
          oldPrivateKey: oldKp.privateKey,
          oldPublicKey: oldKp.publicKey,
          newPublicKey: newKp.publicKey,
          previousEvent: null,
          currentVectorClock: const VectorClock.zero(),
          localPeerRole: 'A',
        );

        await protocol.processReKeyEvent(
          rekeyEvent: event,
        );

        expect(
          await trustStore.isTrusted(newKp.publicKey),
          isTrue,
        );
      },
    );

    // T11.28: Post-rekey events with old key rejected.
    test(
      'T11.28: after processReKeyEvent, old key is '
      'no longer trusted',
      () async {
        final oldKp = await identityManager.generate();
        final newKp = await identityManager.generate();

        await trustStore.addTrustedPeer(
          peerPublicKey: oldKp.publicKey,
          alias: 'OldDevice',
        );

        final event = await protocol.createBlessingEvent(
          oldPrivateKey: oldKp.privateKey,
          oldPublicKey: oldKp.publicKey,
          newPublicKey: newKp.publicKey,
          previousEvent: null,
          currentVectorClock: const VectorClock.zero(),
          localPeerRole: 'A',
        );

        await protocol.processReKeyEvent(
          rekeyEvent: event,
        );

        expect(
          await trustStore.isTrusted(oldKp.publicKey),
          isFalse,
        );
      },
    );
  });
}
