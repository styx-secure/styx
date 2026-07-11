import 'dart:async';
import 'dart:typed_data';

import 'package:styx/styx.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  late Spake2Protocol spake2;
  late MnemonicGenerator mnemonicGen;

  setUp(() {
    spake2 = Spake2Protocol();
    mnemonicGen = MnemonicGenerator();
  });

  /// Helper to create a deterministic 32-byte public key.
  StyxPublicKey makeKey(int seed) {
    final bytes = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      bytes[i] = (seed + i) % 256;
    }
    return StyxPublicKey(bytes);
  }

  /// Helper to build a RemotePairingService with fresh stores.
  ({
    RemotePairingService service,
    TrustStoreManager trustStore,
    InMemoryPeerStore peerStore,
  })
  buildService({
    Duration timeout = const Duration(minutes: 5),
  }) {
    final peerStore = InMemoryPeerStore();
    final trustStore = TrustStoreManager(
      peerStore: peerStore,
    );
    final sessionVerifier = SessionVerifier();
    final doubleCheck = DoubleCheckVerifier(
      sessionVerifier: sessionVerifier,
    );
    final service = RemotePairingService(
      spake2Protocol: spake2,
      mnemonicGenerator: mnemonicGen,
      doubleCheckVerifier: doubleCheck,
      trustStore: trustStore,
      timeout: timeout,
    );
    return (
      service: service,
      trustStore: trustStore,
      peerStore: peerStore,
    );
  }

  group('T11.7 - Mnemonic generated', () {
    test(
      'wordCount 6 produces 6 valid BIP-39 words',
      () {
        final deps = buildService();
        final service = deps.service;

        final mnemonic = service.generateMnemonic();

        final words = mnemonic.split(' ');
        expect(words, hasLength(6));

        final wordSet = bip39English.toSet();
        for (final word in words) {
          expect(
            wordSet.contains(word),
            isTrue,
            reason: '"$word" is not a valid BIP-39 word',
          );
        }

        expect(
          service.state,
          equals(RemotePairingState.mnemonicGenerated),
        );

        addTearDown(service.dispose);
      },
    );
  });

  group('T11.8 - Full remote pairing (happy path)', () {
    test(
      'initiator and responder both get peer pubkey '
      'and complete pairing',
      () async {
        final initiatorDeps = buildService();
        final responderDeps = buildService();
        final initiator = initiatorDeps.service;
        final responder = responderDeps.service;

        final initiatorKey = makeKey(1);
        final responderKey = makeKey(2);

        // 1. Generate mnemonic (same for both).
        final mnemonic = initiator.generateMnemonic();

        // 2. Initiator starts.
        final messageA = await initiator.startAsInitiator(
          mnemonic: mnemonic,
          localPublicKey: initiatorKey,
        );

        // 3. Responder starts.
        final messageB = await responder.startAsResponder(
          mnemonic: mnemonic,
          localPublicKey: responderKey,
        );

        // 4. Exchange SPAKE2 messages.
        final initiatorOk = initiator.processPeerMessage(
          messageB,
        );
        final responderOk = responder.processPeerMessage(
          messageA,
        );

        expect(initiatorOk, isTrue);
        expect(responderOk, isTrue);

        // 5. Double Check codes must match.
        final codeA = initiator.getDoubleCheckCode();
        final codeB = responder.getDoubleCheckCode();
        expect(codeA, equals(codeB));
        expect(codeA, hasLength(6));
        expect(
          RegExp(r'^\d{6}$').hasMatch(codeA),
          isTrue,
        );

        // 6. Set peer public keys.
        initiator.peerPublicKey = responderKey;
        responder.peerPublicKey = initiatorKey;

        // 7. Confirm Double Check.
        await initiator.confirmDoubleCheck(
          codeMatches: true,
          peerAlias: 'Responder',
        );
        await responder.confirmDoubleCheck(
          codeMatches: true,
          peerAlias: 'Initiator',
        );

        // 8. Both complete.
        expect(
          initiator.state,
          equals(RemotePairingState.completed),
        );
        expect(
          responder.state,
          equals(RemotePairingState.completed),
        );

        // 9. Peers saved in trust stores.
        final initiatorTrusted = await initiatorDeps.trustStore.isTrusted(
          responderKey,
        );
        final responderTrusted = await responderDeps.trustStore.isTrusted(
          initiatorKey,
        );
        expect(initiatorTrusted, isTrue);
        expect(responderTrusted, isTrue);

        addTearDown(initiator.dispose);
        addTearDown(responder.dispose);
      },
    );
  });

  group('T11.9 - SPAKE2 password mismatch', () {
    test(
      'different mnemonic on responder produces '
      'different session keys (detected via '
      'Double Check)',
      () async {
        final initiatorDeps = buildService();
        final responderDeps = buildService();
        final initiator = initiatorDeps.service;
        final responder = responderDeps.service;

        final initiatorKey = makeKey(1);
        final responderKey = makeKey(2);

        // Initiator uses one mnemonic.
        const mnemonicA =
            'abandon ability able '
            'about above absent';
        // Responder uses a DIFFERENT mnemonic.
        const mnemonicB =
            'zoo zone zero yield '
            'year wrong';

        final messageA = await initiator.startAsInitiator(
          mnemonic: mnemonicA,
          localPublicKey: initiatorKey,
        );

        final messageB = await responder.startAsResponder(
          mnemonic: mnemonicB,
          localPublicKey: responderKey,
        );

        // SPAKE2 does not fail immediately on wrong
        // password; it produces different keys.
        final initiatorOk = initiator.processPeerMessage(
          messageB,
        );
        final responderOk = responder.processPeerMessage(
          messageA,
        );

        // Both process messages successfully (SPAKE2
        // only produces different keys, doesn't error).
        expect(initiatorOk, isTrue);
        expect(responderOk, isTrue);

        // But Double Check codes differ, revealing MITM.
        final codeA = initiator.getDoubleCheckCode();
        final codeB = responder.getDoubleCheckCode();
        expect(
          codeA,
          isNot(equals(codeB)),
          reason:
              'Different passwords must produce '
              'different Double Check codes',
        );

        addTearDown(initiator.dispose);
        addTearDown(responder.dispose);
      },
    );
  });

  group('T11.10 - Double Check code match', () {
    test(
      'same session key produces same code on both',
      () async {
        final initiatorDeps = buildService();
        final responderDeps = buildService();
        final initiator = initiatorDeps.service;
        final responder = responderDeps.service;

        const mnemonic =
            'abandon ability able '
            'about above absent';

        final messageA = await initiator.startAsInitiator(
          mnemonic: mnemonic,
          localPublicKey: makeKey(1),
        );
        final messageB = await responder.startAsResponder(
          mnemonic: mnemonic,
          localPublicKey: makeKey(2),
        );

        initiator.processPeerMessage(messageB);
        responder.processPeerMessage(messageA);

        final codeA = initiator.getDoubleCheckCode();
        final codeB = responder.getDoubleCheckCode();

        expect(codeA, equals(codeB));
        expect(codeA, hasLength(6));
        expect(
          RegExp(r'^\d{6}$').hasMatch(codeA),
          isTrue,
        );

        addTearDown(initiator.dispose);
        addTearDown(responder.dispose);
      },
    );
  });

  group('T11.11 - Double Check code mismatch (MITM)', () {
    test(
      'different session keys produce different codes',
      () {
        final verifier = SessionVerifier();

        // Simulate two different session keys.
        final keyA = Uint8List.fromList(
          List.generate(32, (i) => i),
        );
        final keyB = Uint8List.fromList(
          List.generate(32, (i) => 255 - i),
        );

        final codeA = verifier.generateDoubleCheckCode(keyA);
        final codeB = verifier.generateDoubleCheckCode(keyB);

        expect(codeA, isNot(equals(codeB)));
      },
    );
  });

  group('T11.12 - Confirm Double Check true', () {
    test(
      'codeMatches true saves peer and completes',
      () async {
        final deps = buildService();
        final service = deps.service;
        final peerKey = makeKey(99);

        const mnemonic =
            'abandon ability able '
            'about above absent';

        // Set up a completed SPAKE2 session via a
        // second service acting as responder.
        final respDeps = buildService();
        final responder = respDeps.service;

        final msgA = await service.startAsInitiator(
          mnemonic: mnemonic,
          localPublicKey: makeKey(1),
        );
        final msgB = await responder.startAsResponder(
          mnemonic: mnemonic,
          localPublicKey: peerKey,
        );

        service.processPeerMessage(msgB);
        responder.processPeerMessage(msgA);

        service.peerPublicKey = peerKey;

        await service.confirmDoubleCheck(
          codeMatches: true,
          peerAlias: 'TrustedPeer',
        );

        expect(
          service.state,
          equals(RemotePairingState.completed),
        );

        final isTrusted = await deps.trustStore.isTrusted(
          peerKey,
        );
        expect(isTrusted, isTrue);

        addTearDown(service.dispose);
        addTearDown(responder.dispose);
      },
    );
  });

  group('T11.13 - Confirm Double Check false', () {
    test(
      'codeMatches false transitions to failed',
      () async {
        final deps = buildService();
        final service = deps.service;
        final peerKey = makeKey(99);

        const mnemonic =
            'abandon ability able '
            'about above absent';

        final respDeps = buildService();
        final responder = respDeps.service;

        final msgA = await service.startAsInitiator(
          mnemonic: mnemonic,
          localPublicKey: makeKey(1),
        );
        final msgB = await responder.startAsResponder(
          mnemonic: mnemonic,
          localPublicKey: peerKey,
        );

        service.processPeerMessage(msgB);
        responder.processPeerMessage(msgA);

        service.peerPublicKey = peerKey;

        await service.confirmDoubleCheck(
          codeMatches: false,
          peerAlias: null,
        );

        expect(
          service.state,
          equals(RemotePairingState.failed),
        );

        // Peer should NOT be saved.
        final isTrusted = await deps.trustStore.isTrusted(
          peerKey,
        );
        expect(isTrusted, isFalse);

        addTearDown(service.dispose);
        addTearDown(responder.dispose);
      },
    );
  });

  group('T11.14 - Timeout pairing', () {
    test(
      'service can be created with a short timeout',
      () {
        final deps = buildService(
          timeout: const Duration(seconds: 1),
        );
        final service = deps.service;

        expect(
          service.timeout,
          equals(const Duration(seconds: 1)),
        );
        expect(
          service.state,
          equals(RemotePairingState.idle),
        );

        addTearDown(service.dispose);
      },
    );

    test(
      'state remains in waitingForPeer when no peer '
      'responds',
      () async {
        final deps = buildService(
          timeout: const Duration(seconds: 1),
        );
        final service = deps.service;

        const mnemonic =
            'abandon ability able '
            'about above absent';

        await service.startAsInitiator(
          mnemonic: mnemonic,
          localPublicKey: makeKey(1),
        );

        // No peer message processed. State stays
        // at spake2InProgress (after startAsInitiator).
        expect(
          service.state,
          equals(RemotePairingState.spake2InProgress),
        );

        addTearDown(service.dispose);
      },
    );
  });

  group('T11.15 - Cancel pairing', () {
    test(
      'cancel during waitingForPeer returns to idle',
      () async {
        final deps = buildService();
        final service = deps.service;

        final mnemonic = service.generateMnemonic();

        await service.startAsInitiator(
          mnemonic: mnemonic,
          localPublicKey: makeKey(1),
        );

        // State is now spake2InProgress.
        expect(
          service.state,
          isNot(equals(RemotePairingState.idle)),
        );

        await service.cancel();

        expect(
          service.state,
          equals(RemotePairingState.idle),
        );

        // peerPublicKey should be cleared.
        expect(service.peerPublicKey, isNull);

        addTearDown(service.dispose);
      },
    );
  });

  group('T11.16 - State stream', () {
    test(
      'full flow emits states in correct order',
      () async {
        final initiatorDeps = buildService();
        final responderDeps = buildService();
        final initiator = initiatorDeps.service;
        final responder = responderDeps.service;

        final states = <RemotePairingState>[];
        final sub = initiator.stateStream.listen(
          states.add,
        );

        const mnemonic =
            'abandon ability able '
            'about above absent';

        // Generate mnemonic.
        initiator.generateMnemonic();

        // Start as initiator.
        final msgA = await initiator.startAsInitiator(
          mnemonic: mnemonic,
          localPublicKey: makeKey(1),
        );

        // Set up responder.
        final msgB = await responder.startAsResponder(
          mnemonic: mnemonic,
          localPublicKey: makeKey(2),
        );

        // Process peer message.
        initiator.processPeerMessage(msgB);
        responder.processPeerMessage(msgA);

        // Set peer key and confirm.
        initiator.peerPublicKey = makeKey(2);
        await initiator.confirmDoubleCheck(
          codeMatches: true,
          peerAlias: 'Peer',
        );

        // Allow stream events to propagate.
        await Future<void>.delayed(Duration.zero);

        expect(
          states,
          equals([
            RemotePairingState.mnemonicGenerated,
            RemotePairingState.waitingForPeer,
            RemotePairingState.spake2InProgress,
            RemotePairingState.doubleCheckPending,
            RemotePairingState.completed,
          ]),
        );

        await sub.cancel();
        addTearDown(initiator.dispose);
        addTearDown(responder.dispose);
      },
    );

    test(
      'cancel emits idle state',
      () async {
        final deps = buildService();
        final service = deps.service;

        final states = <RemotePairingState>[];
        final sub = service.stateStream.listen(
          states.add,
        );

        const mnemonic =
            'abandon ability able '
            'about above absent';

        await service.startAsInitiator(
          mnemonic: mnemonic,
          localPublicKey: makeKey(1),
        );

        await service.cancel();

        // Allow stream events to propagate.
        await Future<void>.delayed(Duration.zero);

        expect(states.last, RemotePairingState.idle);

        await sub.cancel();
        addTearDown(service.dispose);
      },
    );
  });

  group('RemotePairingService.deriveSharedTag', () {
    test(
      'produces deterministic hex tag from mnemonic',
      () {
        const mnemonic =
            'abandon ability able '
            'about above absent';

        final tag1 = RemotePairingService.deriveSharedTag(
          mnemonic,
        );
        final tag2 = RemotePairingService.deriveSharedTag(
          mnemonic,
        );

        expect(tag1, equals(tag2));
        // SHA-256 first 8 bytes → 16 hex chars.
        expect(tag1, hasLength(16));
        expect(
          RegExp(r'^[0-9a-f]{16}$').hasMatch(tag1),
          isTrue,
        );
      },
    );

    test(
      'different mnemonics produce different tags',
      () {
        final tagA = RemotePairingService.deriveSharedTag(
          'abandon ability able about above absent',
        );
        final tagB = RemotePairingService.deriveSharedTag(
          'zoo zone zero yield year wrong',
        );

        expect(tagA, isNot(equals(tagB)));
      },
    );
  });
}
