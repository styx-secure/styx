import 'dart:convert';
import 'dart:typed_data';

import 'package:styx/styx.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  late QrPairingService service;
  late TrustStoreManager trustStore;
  late InMemoryPeerStore peerStore;

  setUp(() {
    peerStore = InMemoryPeerStore();
    trustStore = TrustStoreManager(peerStore: peerStore);
    service = QrPairingService(trustStore: trustStore);
  });

  /// Helper to create a deterministic 32-byte public key.
  StyxPublicKey makeKey(int seed) {
    final bytes = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      bytes[i] = (seed + i) % 256;
    }
    return StyxPublicKey(bytes);
  }

  group('T11.1 - GenerateQrData format', () {
    test(
      'pubkey + relay hints produce valid QR payload JSON '
      'with pk, n, r fields',
      () {
        final localKey = makeKey(1);
        final relays = [
          'wss://relay1.example.com',
          'wss://relay2.example.com',
        ];

        final qrData = service.generateQrData(
          localPublicKey: localKey,
          relayHints: relays,
        );

        final payload = qrData.toQrPayload();
        final json = jsonDecode(payload) as Map<String, dynamic>;

        expect(json, contains('pk'));
        expect(json, contains('n'));
        expect(json, contains('r'));

        expect(json['pk'], equals(localKey.toHex()));
        expect(json['n'], isA<String>());
        expect(json['n'], isNotEmpty);

        final decodedNonce = base64Decode(json['n'] as String);
        expect(decodedNonce, hasLength(16));

        final decodedRelays = (json['r'] as List<dynamic>).cast<String>();
        expect(decodedRelays, equals(relays));
      },
    );

    test(
      'QR payload without relay hints omits r field',
      () {
        final localKey = makeKey(2);

        final qrData = service.generateQrData(
          localPublicKey: localKey,
        );

        final payload = qrData.toQrPayload();
        final json = jsonDecode(payload) as Map<String, dynamic>;

        expect(json, contains('pk'));
        expect(json, contains('n'));
        expect(json, isNot(contains('r')));
      },
    );
  });

  group('T11.2 - QrPairingData round-trip', () {
    test(
      'generate, serialize, deserialize produces '
      'identical data',
      () {
        final localKey = makeKey(3);
        final relays = ['wss://relay.example.com'];

        final original = service.generateQrData(
          localPublicKey: localKey,
          relayHints: relays,
        );

        final payload = original.toQrPayload();
        final restored = QrPairingData.fromQrPayload(
          payload,
        );

        expect(
          restored.publicKey.toHex(),
          equals(original.publicKey.toHex()),
        );
        expect(
          restored.nonce,
          equals(original.nonce),
        );
        expect(
          restored.relayHints,
          equals(original.relayHints),
        );
      },
    );

    test(
      'round-trip without relay hints preserves null',
      () {
        final localKey = makeKey(4);

        final original = service.generateQrData(
          localPublicKey: localKey,
        );

        final payload = original.toQrPayload();
        final restored = QrPairingData.fromQrPayload(
          payload,
        );

        expect(
          restored.publicKey.toHex(),
          equals(original.publicKey.toHex()),
        );
        expect(restored.relayHints, isNull);
      },
    );
  });

  group('T11.3 - ProcessScannedQr valid', () {
    test(
      'correct QR payload returns isValid true '
      'and extracts pubkey',
      () {
        final peerKey = makeKey(10);
        final nonce = Uint8List.fromList(
          List.generate(16, (i) => i + 100),
        );

        final qrData = QrPairingData(
          publicKey: peerKey,
          nonce: nonce,
          relayHints: const ['wss://relay.example.com'],
        );
        final payload = qrData.toQrPayload();

        final localKey = makeKey(20);
        final result = service.processScannedQr(
          qrPayload: payload,
          localPublicKey: localKey,
        );

        expect(result.isValid, isTrue);
        expect(result.errorMessage, isNull);
        expect(
          result.peerPublicKey.toHex(),
          equals(peerKey.toHex()),
        );
        expect(
          result.relayHints,
          equals(['wss://relay.example.com']),
        );
      },
    );
  });

  group('T11.4 - ProcessScannedQr invalid', () {
    test(
      'malformed JSON returns isValid false '
      'with errorMessage',
      () {
        final localKey = makeKey(20);

        final result = service.processScannedQr(
          qrPayload: 'not valid json!!!',
          localPublicKey: localKey,
        );

        expect(result.isValid, isFalse);
        expect(result.errorMessage, isNotNull);
        expect(result.errorMessage, isNotEmpty);
      },
    );

    test(
      'JSON missing pk field returns isValid false',
      () {
        final localKey = makeKey(20);
        final payload = jsonEncode({
          'n': base64Encode(Uint8List(16)),
        });

        final result = service.processScannedQr(
          qrPayload: payload,
          localPublicKey: localKey,
        );

        expect(result.isValid, isFalse);
        expect(result.errorMessage, isNotNull);
      },
    );

    test(
      'JSON missing n field returns isValid false',
      () {
        final localKey = makeKey(20);
        final payload = jsonEncode({
          'pk': makeKey(30).toHex(),
        });

        final result = service.processScannedQr(
          qrPayload: payload,
          localPublicKey: localKey,
        );

        expect(result.isValid, isFalse);
        expect(result.errorMessage, isNotNull);
      },
    );
  });

  group('T11.5 - ProcessScannedQr replay', () {
    test(
      'same nonce used twice results in '
      'second attempt rejected',
      () {
        final peerKey = makeKey(10);
        final nonce = Uint8List.fromList(
          List.generate(16, (i) => i + 50),
        );

        final qrData = QrPairingData(
          publicKey: peerKey,
          nonce: nonce,
        );
        final payload = qrData.toQrPayload();

        final localKey = makeKey(20);

        // First scan succeeds.
        final first = service.processScannedQr(
          qrPayload: payload,
          localPublicKey: localKey,
        );
        expect(first.isValid, isTrue);

        // Second scan with same nonce is rejected.
        final second = service.processScannedQr(
          qrPayload: payload,
          localPublicKey: localKey,
        );
        expect(second.isValid, isFalse);
        expect(
          second.errorMessage,
          contains('replay'),
        );
      },
    );
  });

  group('T11.6 - CompletePairing', () {
    test(
      'valid pubkey saves peer in trust store',
      () async {
        final peerKey = makeKey(42);

        await service.completePairing(
          peerPublicKey: peerKey,
          peerAlias: 'Alice',
        );

        final isTrusted = await trustStore.isTrusted(
          peerKey,
        );
        expect(isTrusted, isTrue);

        final activePeer = await trustStore.getActivePeer();
        expect(activePeer, isNotNull);
        expect(
          activePeer!.publicKey.toHex(),
          equals(peerKey.toHex()),
        );
        expect(activePeer.alias, equals('Alice'));
      },
    );

    test(
      'completePairing with null alias saves peer',
      () async {
        final peerKey = makeKey(43);

        await service.completePairing(
          peerPublicKey: peerKey,
          peerAlias: null,
        );

        final isTrusted = await trustStore.isTrusted(
          peerKey,
        );
        expect(isTrusted, isTrue);
      },
    );
  });
}
